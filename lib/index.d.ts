import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type ManifestVerdict, type ToolSpec } from './integrity.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { canonicalJson, diffManifests, hashToolSpec, manifestFingerprint, normalizeName, diceSimilarity, pinManifest, toBaseline, type BaselineEntry, type IntegrityOptions, type ManifestFinding, type ManifestFindingKind, type ManifestVerdict, type ToolSpec, } from './integrity.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'integrity';
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
 * 另有独立通道：guardian/path 路径沙箱、guardian/tools 工具清单完整性（rug-pull 检测）
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private allowedRoots;
    /** 引擎 6：工具清单完整性（rug-pull 检测） */
    private enableIntegrity;
    private newToolPolicy;
    /** 配置 pin 的锁基线（name → hash），类似 package-lock；设置后配置即权威 */
    private pinnedTools?;
    /** 会话级基线：sessionId → (name → BaselineEntry)，首次观察即 pin */
    private toolBaselines;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /**
     * 引擎 6：工具清单完整性校验（rug-pull 检测）。
     * 宿主在会话开始与每次收到 tools/list 刷新时调用（或经 guardian/tools 通道）。
     * 语义：首次观察即 pin 基线（或用配置 manifestBaseline pin）；之后任何
     * 描述/schema 变更、中途新增工具、同名仿冒都要求重新授权，deny 级直接拒绝。
     */
    checkToolManifest(sessionId: string, tools: ToolSpec[]): ManifestVerdict;
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
        /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
        allowedRoots?: string[];
        /** 是否启用工具清单完整性校验（默认 true） */
        checkToolIntegrity?: boolean;
        /** 会话中途新增工具的处置：'block'（默认，人工确认）| 'deny' | 'log' | 'allow' */
        newToolPolicy?: 'deny' | 'block' | 'log' | 'allow';
        /**
         * 工具清单 pin 锁基线（类似 package-lock 的角色）。
         * 传 ToolSpec[] 会自动计算 hash；或直接传 pinManifest() 生成的 name→hash 映射。
         * 设置后配置即权威，任何漂移都要求重新授权。
         */
        manifestBaseline?: ToolSpec[] | Record<string, string>;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
