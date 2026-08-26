import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { AttackMemory } from './attack-memory.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { AttackMemory, normalizePayload, strictNormalize, fingerprint, strictFingerprint, tokenSet, jaccard, type AttackRecord, type MemoryHit } from './attack-memory.js';
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
    /** 记忆引擎命中时，指向被记忆的原始攻击所命中的规则 ID */
    sourceRuleId?: string;
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
 * 检测引擎（guardian/check 通道内依次执行）：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. memory —— 攻击记忆（历史攻击指纹/变种的最后一道网，自学习）
 * 另有独立通道：guardian/path —— 路径沙箱（realpath + 白名单）
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private allowedRoots;
    /** 攻击记忆库（attackMemory:false 时为 undefined） */
    private memory?;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 各引擎依次判定（check 负责记忆学习，此处纯判定） */
    private runChecks;
    /**
     * 从审计日志自举攻击记忆：历史 deny 与"未被批准的 block"即攻击语料库。
     * block 条目若紧随 approved:<id> 的补偿 allow 条目（同 ruleId+snippet），说明用户已批准，不学习。
     */
    private bootstrapMemoryFromAudit;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    private handleRule;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
    /** 攻击记忆库（attackMemory:false 时为 undefined），可查 size()/forget(fp) 等 */
    get attackMemory(): AttackMemory | undefined;
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
        /**
         * 攻击记忆引擎（默认开启）：true=默认配置；对象=细配（file/threshold/maxRecords/minTokens）；false=关闭。
         * 被拦截的攻击自动进入记忆库，换 IP/路径/措辞的重复与变种攻击会被 MEMORY-EXACT / MEMORY-VARIANT 命中。
         */
        attackMemory?: boolean | AttackMemory.Config;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
