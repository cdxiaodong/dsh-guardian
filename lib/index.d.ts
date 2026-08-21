import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type PolicyRule, type PolicyLoadResult } from './policy.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { parsePolicyYaml, compilePolicies, evaluatePolicies, globToRegExp, type PolicyRule, type PolicyFile, type PolicyAction, type CompiledPolicy, type PolicyLoadResult } from './policy.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'policy';
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
 * 检测引擎（按顺序）：
 *  0. policy —— YAML 声明式策略（工具名通配 + 参数正则 + allow 白名单豁免，支持热加载）
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入 / RCE 反序列化正则规则
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
    private allowedRoots;
    /** 已编译策略（按 priority 升序），来自 YAML 策略文件 */
    private policies;
    private policyPath;
    private unwatchPolicy;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    private handleRule;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
    /** 加载 YAML 策略文件（解析+校验+立即生效）。失败保留旧策略并返回 errors——热加载安全回退 */
    loadPolicyFile(file: string): PolicyLoadResult;
    /** 重新加载当前策略文件 */
    reloadPolicy(): PolicyLoadResult;
    /** 当前生效的策略列表（已按 priority 排序） */
    listPolicies(): PolicyRule[];
    /** 监听策略文件变化自动热加载；每次重载结果经 'guardian/policy-loaded' 事件广播（时空可组合-空间维度） */
    private watchPolicyFile;
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
        /** YAML 声明式策略文件路径（提供即启用策略引擎，优先于内置规则） */
        policyFile?: string;
        /** 是否热加载策略文件变化（默认 true；加载失败自动回退旧策略） */
        watchPolicy?: boolean;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
