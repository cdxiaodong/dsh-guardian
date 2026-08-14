/** SSRF / 内网目标检测：识别 Agent 试图访问的内网/元数据地址 */
export interface SSRFRule {
    id: string;
    pattern: RegExp;
    reason: string;
}
/** 内网/危险目标地址（出现在 URL/IP 参数里即告警） */
export declare const SSRF_RULES: SSRFRule[];
export declare function scanNetworkTarget(text: string): Array<{
    ruleId: string;
    reason: string;
}>;
