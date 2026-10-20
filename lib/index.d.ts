import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf';
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
 * Agent security guardrail service (cordis Service, name='guardian').
 *
 * Workflow: the host calls `ctx.bail('guardian/check', tool, payload)` before every tool call.
 *  - Returns an Interception object → intercept (deny rejects directly; block first goes through guardian/approve for manual confirmation)
 *  - Returns false → allow
 *
 * Three detection engines:
 *  1. rule   —— dangerous commands / destructive operations / prompt-injection regex rules
 *  2. secret —— secret/credential leakage (gitleaks style)
 *  3. ssrf   —— access to internal network / metadata addresses
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private allowedRoots;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** Path sandbox check: realpath + allowlist, returns PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** Core decision. Returns Interception = intercept; false = allow (cordis bail semantics) */
    check(toolName: string, payload: unknown): Interception | false;
    /** Handle a single matched rule: deny is blocked directly; block goes through manual confirmation */
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
        /** Whether to enable secret leakage scanning (default true) */
        scanSecrets?: boolean;
        /** Whether to enable SSRF/internal network access scanning (default true) */
        scanSSRF?: boolean;
        /** Whether to enable path sandbox checks (default true) */
        checkPaths?: boolean;
        /** Sandbox allowlist root directories (when set, paths must fall within one of them) */
        allowedRoots?: string[];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
