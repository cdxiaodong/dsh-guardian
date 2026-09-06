import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type CanaryRecord } from './canary.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { generateCanary, generateDecoyCanary, scanForCanary, redactCanary, canaryFingerprint, CANARY_PREFIX, DECOY_PREFIX, type CanaryRecord, type CanaryHit, type CanaryVariant, } from './canary.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'canary';
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
    private enableCanary;
    private allowedRoots;
    /** 蜜罐信标注册表：per-session 内存态，绝不落盘 */
    private canaries;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /**
     * 植入蜜罐信标：把外部内容（网页/邮件/文档）喂给 Agent 前调用。
     * 返回带 canary 的上下文；此后 canary 一旦出现在任何出境通道即被 deny。
     *  - 默认中性形态：`[internal-tracking-ref: GUARDIAN-CANARY-…]`，不惊动注入指令
     *  - decoy: true 蜜饵形态：伪装成 API key 裸 token，诱惑注入「优先偷它」
     */
    plantCanary(context: string, opts?: {
        label?: string;
        decoy?: boolean;
    }): {
        context: string;
        token: string;
    };
    /** 撤销信标：轮次结束 / token 疑似已泄露时调用，之后不再据此拦截 */
    revokeCanary(token: string): void;
    /** 列出信标指纹（前 4 后 4），全文不离开内存 */
    listCanaries(): Array<Omit<CanaryRecord, 'token'> & {
        fingerprint: string;
    }>;
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
        /** 是否启用蜜罐信标出境检测（默认 true；无注册信标时零开销） */
        canaryTrap?: boolean;
        /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
        allowedRoots?: string[];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
