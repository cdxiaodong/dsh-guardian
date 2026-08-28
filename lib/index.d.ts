import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { EgressBudget } from './egress.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { EgressBudget, isEgressTool, estimateBytes, fmtBytes, EGRESS_TOOL_RE, type BudgetDimension, type BudgetUsage, type BudgetViolation } from './egress.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'budget';
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
 * 检测引擎（guardian/check 通道内依次执行）：
 *  0. budget —— 出境预算：调用频次滑窗（在内容引擎之前——被拦的尝试也是行为信号）
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. budget —— 出境体积记账：内容引擎全放行后，出境类工具的 payload 记账（累计/峰值）
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
    /** 出境预算记账器（egressBudget:false 时为 undefined） */
    private budget?;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 预算违规处理：block 走人工确认；批准即重置该维度窗口（合法大上传只打扰一次） */
    private handleBudget;
    /** 内容检测引擎（纯判定；预算逻辑在 check 中环绕） */
    private runContentChecks;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    private handleRule;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
    /** 出境预算记账器（egressBudget:false 时为 undefined），可查 usage()/reset(dim) 等 */
    get egressBudget(): EgressBudget | undefined;
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
         * 出境预算引擎（默认开启）：true=默认配置；对象=细配（windowMs/maxEgressBytes/
         * maxPayloadBytes/maxCalls）；false=关闭。
         * 内容无关的量化防线：滑窗累计出境字节（分块渗出）、单次峰值（批量外传）、
         * 调用频次（失控循环）。超限走人工确认，批准即重置窗口。
         */
        egressBudget?: boolean | EgressBudget.Config;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
