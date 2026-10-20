/** SSRF / internal target detection: identifies internal and metadata addresses an agent attempts to access */
export interface SSRFRule {
    id: string;
    pattern: RegExp;
    reason: string;
}
/** Internal/dangerous target addresses (raises an alert when they appear in URL/IP parameters) */
export declare const SSRF_RULES: SSRFRule[];
export declare function scanNetworkTarget(text: string): Array<{
    ruleId: string;
    reason: string;
}>;
