import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type TrifectaStatus } from './trifecta.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { TrifectaTracker, classifyCapabilities, CAPABILITIES, type Capability, type CapabilityObservation, type TrifectaEvent, type TrifectaStatus, type TrifectaTrackerOptions } from './trifecta.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'trifecta';
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
 * 检测引擎（前六个是「空间维度」：单次调用无状态判定；第七个补「时间维度」）：
 *  1. rule     —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret   —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf     —— 内网/元数据地址访问
 *  7. trifecta —— 时空致命三角：会话滑动窗口内 私有数据+不可信内容+外部通道 三者齐备即拦
 *    （单看每次调用可能都合法，组合才暴露攻击 —— Lethal Trifecta / Rule of Two）
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private allowedRoots;
    private trifecta;
    private enableTrifecta;
    private trifectaAction;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 查询当前会话致命三角状态（可观测性，供 UI/审计用） */
    trifectaStatus(): TrifectaStatus;
    /**
     * 时空观测：复用既有检测器输出，把本次调用投影到能力维度并记录进滑动窗口。
     * 触发即返回拦截：①本次调用补全了三角；②三角已热时再次出现外部数据通道。
     */
    private observeTrifecta;
    /** 生成该能力归类的简短证据说明 */
    private capEvidence;
    /** 生成致命三角的可读拦截理由 */
    private describeTrifecta;
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
        /** 是否启用致命三角时空关联引擎（默认 true） */
        scanTrifecta?: boolean;
        /** 致命三角会话滑动窗口时长 ms（默认 10 分钟） */
        trifectaWindowMs?: number;
        /** 致命三角处置动作（默认 block=人工确认；deny=直接拒；log=仅记录） */
        trifectaAction?: Rule['action'];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
