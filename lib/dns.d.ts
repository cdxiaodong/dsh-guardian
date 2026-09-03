/**
 * DNS 隐蔽信道检测（engine-19：DNS Covert Channel / Tunneling Guard）。
 *
 * 威胁模型：沙箱/出站策略通常只封 HTTP，DNS 查询仍然畅通。被注入的 Agent
 * 可以把敏感数据编码进域名标签（hex/base32），用一条 dig/nslookup 或
 * DoH 请求送出去——既绕过 HTTP 层的字节出境预算，也不触达任何"内网 IP"。
 * （参考：Cloud Security Alliance 研究笔记 "AI Agent Trust Boundaries:
 * DNS Escape and Exfiltration"；经典工具 dnscat2 / iodine 均以 base32 分块。）
 *
 * 检测面全部是确定性的协议结构特征，不依赖网络行为：
 *  1. 标签编码特征 —— hex / base32（DNS 大小写不敏感，隧道工具首选 base32）
 *  2. 标签长度逼近协议上限（单标签 ≤63 字节；正常业务域名几乎不超 24）
 *  3. 分块特征 —— 连续多个等长长标签（iodine/dnscat2 的 chunked 编码）
 *  4. 高熵 DGA 特征 —— 随机字符分布（block 级，人工确认兜底）
 *  5. DoH 编码查询 —— 公共 DoH 端点 + name 参数里带编码子域
 */
export interface DnsVerdict {
    safe: boolean;
    reason?: string;
    evidence?: string[];
    domain?: string;
}
export interface DnsHit {
    ruleId: string;
    reason: string;
    domain: string;
    label: string;
    /** 命中特征明细（audit 用） */
    evidence: string[];
}
/** 公共 DoH / DNS-over-HTTPS 端点（Agent 借它把解析流量伪装成普通 HTTPS） */
export declare const DOH_ENDPOINTS: string[];
/**
 * 分析单个域名的标签结构，返回命中的隧道特征。
 */
export declare function inspectDomain(domain: string): DnsHit[];
/** 扫描工具调用文本：提取全部候选域名/DoH URL 并逐一分析 */
export declare function scanDnsCovert(text: string): DnsHit[];
/** deny 级命中（确定性隧道特征：编码/超长/分块/DoH 编码查询）；其余 block 级走人工确认 */
export declare const DNS_DENY_RULES: Set<string>;
/** 独立校验入口（guardian/dns 事件通道用）：给定域名/查询文本，返回 verdict */
export declare function checkDns(target: string): DnsVerdict;
