import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type RenderOptions, type RenderVerdict } from './render.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { scanMarkdown, sanitizeMarkdown, scanAndJudge, verdictOf as renderVerdictOf, segmentMarkdown, parseUrl, decodeEntities, developTags as developRenderTags, type RenderSeverity, type RenderFinding, type RenderVerdict, type RenderOptions, type Segment } from './render.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'render';
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
 *
 * 独立通道：guardian/path 路径沙箱；guardian/render 渲染层外泄
 * （Markdown 注入 / 图片信标 / 链接显示欺骗，宿主渲染 Agent 输出前调用）。
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private enableRender;
    private trustedImageHosts;
    private allowedRoots;
    constructor(ctx: Context, config?: GuardianService.Config);
    /**
     * 渲染层外泄校验（Markdown 注入 / 图片信标 / 链接显示欺骗）。
     * poison → 审计 deny 并返回 sanitized 替代版本；suspect → 审计 allow 仅告警。
     */
    checkRender(md: string, opts?: RenderOptions): RenderVerdict;
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
        /** 是否启用渲染层外泄扫描（默认 true） */
        scanRender?: boolean;
        /** 可信图片域名：其图片 URL 带普通 query 不告警（精确/后缀匹配） */
        trustedImageHosts?: string[];
        /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
        allowedRoots?: string[];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
