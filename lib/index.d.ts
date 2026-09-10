import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { MemoryIntegrityStore, type IntegrityResult, type MemoryVerdict } from './memory.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { isAgentContextFile, AGENT_CONTEXT_PATTERNS, MEMORY_RULES, scanMemoryContent, worstAction, guardMemoryWrite, MemoryIntegrityStore, type MemoryRule, type MemoryHit, type MemoryVerdict, type IntegrityResult, type IntegrityStatus, } from './memory.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'memory';
    tool?: string;
    ruleId?: string;
    reason?: string;
    snippet?: string;
}
export interface Interception {
    intercepted: true;
    reason: string;
    ruleId: string;
    action: Rule['action'];
    engine: AuditEntry['engine'];
}
declare module 'cordis' {
    interface Context {
        guardian: GuardianService;
    }
}
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 三个检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private enableMemory;
    private allowedRoots;
    /** 认知完整性基线（TOFU 哈希 pin） */
    readonly integrity: MemoryIntegrityStore;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 认知写入判定：非受保护文件直接放行；受保护文件按投毒规则判，干净则顺带 TOFU 建基线 */
    checkMemoryWrite(target: string, content: string): MemoryVerdict;
    /** 启动自检：校验受保护上下文文件是否偏离 TOFU 基线（宿主会话启动时逐个调用） */
    verifyContextFile(target: string): IntegrityResult;
    /**
     * 识别"写 Agent 认知上下文文件"的工具调用：
     *  1. 写入类工具名 + payload 中出现受保护路径（write_file/edit 等结构化调用）
     *  2. shell 写入动词（重定向/tee/cp/mv/append）指向受保护文件（绕过结构化工具的逃逸路径）
     */
    private looksLikeContextWrite;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    private handleRule;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
}
export declare namespace GuardianService {
    interface Config {
        logFile?: string;
        rules?: Rule[];
        /** 是否启用密钥泄露扫描（默认 true） */
        scanSecrets?: boolean;
        /** 是否启用 SSRF/内网访问扫描（默认 true） */
        scanSSRF?: boolean;
        /** 是否启用路径沙箱校验（默认 true） */
        checkPaths?: boolean;
        /** 是否启用认知完整性引擎：Agent 上下文文件投毒检测（默认 true） */
        guardMemory?: boolean;
        /** 认知完整性 TOFU 基线存放路径（默认 ~/.dsh-guardian.memory.json） */
        integrityFile?: string;
        /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
        allowedRoots?: string[];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
