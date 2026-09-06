import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { TrustLedger, type IngestResult, type ToolCategory } from './capability.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { TrustLedger, classifyTool, detectDirectives, DIRECTIVE_RULES, PROTECTED_CATEGORIES, TOOL_CATEGORY_PATTERNS, type IngestResult, type ToolCategory, type DirectiveRule, type DirectiveHit, type AttenuationInfo } from './capability.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny' | 'flag';
    engine: 'rule' | 'secret' | 'ssrf' | 'cap';
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
 * 四个检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. cap    —— 能力衰减（confused deputy 防护）：跨调用信任状态机，
 *               不可信内容摄入后，影响窗口内的副作用工具自动降权为人工确认
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private allowedRoots;
    private enableAttenuation;
    private protectedCategories;
    private toolCategoryOverrides;
    readonly ledger: TrustLedger;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 外部内容摄入申报：携带指令性话术 → 会话进入衰减态（confused deputy 防护） */
    ingestContent(source: string, content: string): IngestResult;
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
        /** 是否启用能力衰减引擎（confused deputy 防护，默认 true） */
        attenuateConfusedDeputy?: boolean;
        /** 衰减影响窗口步数：不可信内容摄入后，多少次工具调用内的副作用操作被降权（默认 3） */
        influenceSteps?: number;
        /** 衰减保护的副作用类别（默认全部：exec/write/delete/network/credential） */
        protectedCategories?: ToolCategory[];
        /** 工具名 → 副作用类别的精确覆盖映射（内置分类靠子串启发式，宿主可精确指定） */
        toolCategories?: Record<string, ToolCategory>;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
