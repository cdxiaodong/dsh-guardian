import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type TransformKind } from './deobfuscate.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, obfuscationSignal, collectSignalsDeep, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { normalizeText, expandTexts, findBase64Segments, TRANSFORM_LABELS, type TransformKind, type NormalizedText, type TextVariant } from './deobfuscate.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'deob';
    tool?: string;
    ruleId?: string;
    reason?: string;
    snippet?: string;
    /** 命中变体经过的混淆消解变换链（原文直接命中时无此字段） */
    via?: TransformKind[];
}
export interface Interception {
    intercepted: true;
    reason: string;
    ruleId: string;
    action: Rule['action'];
    engine: AuditEntry['engine'];
    /** 命中变体经过的混淆消解变换链（原文直接命中时无此字段） */
    via?: TransformKind[];
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
 * 检测管线（混淆消解前置）：
 *  原文/归一化变体 →  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *                      2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *                      3. ssrf   —— 内网/元数据地址访问
 *  变体由 deobfuscate 引擎展开：零宽/Unicode Tags/bidi 剥离解码、NFKC、
 *  HTML 实体/百分号/base64/leetspeak 解码还原（decode-before-scan）。
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private enableDeobfuscation;
    private escalateObfuscated;
    private auditObfuscation;
    private allowedRoots;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 对单个文本变体跑全部引擎。via 非空表示这是混淆消解后的变体 */
    private checkText;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认；混淆变体命中 log 级规则升级为 block */
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
        /** 是否启用混淆消解（零宽/Unicode Tags/base64/实体等解码后再扫，默认 true） */
        deobfuscate?: boolean;
        /** 混淆变形命中 log 级规则时升级为人工确认 block（默认 true） */
        escalateObfuscated?: boolean;
        /** 检测到混淆但未命中规则时是否记录审计（默认 true） */
        auditObfuscation?: boolean;
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
