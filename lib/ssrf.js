/** 内网/危险目标地址（出现在 URL/IP 参数里即告警） */
export const SSRF_RULES = [
    { id: 'cloud-metadata-aws', pattern: /169\.254\.169\.254/, reason: 'AWS/云 metadata 服务（SSRF 经典目标）' },
    { id: 'cloud-metadata-gcp', pattern: /metadata\.google\.internal|169\.254\.169\.254.*computeMetadata/i, reason: 'GCP metadata 服务' },
    { id: 'cloud-metadata-aliyun', pattern: /100\.100\.100\.200/, reason: '阿里云 metadata 服务' },
    { id: 'loopback', pattern: /\b(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\b/, reason: '访问回环地址' },
    { id: 'rfc1918-10', pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, reason: '访问 10.x 内网' },
    { id: 'rfc1918-192', pattern: /\b192\.168\.\d{1,3}\.\d{1,3}\b/, reason: '访问 192.168 内网' },
    { id: 'rfc1918-172', pattern: /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/, reason: '访问 172.16-31 内网' },
    { id: 'link-local', pattern: /\b169\.254\.\d{1,3}\.\d{1,3}\b/, reason: '访问链路本地地址' },
    { id: 'internal-suffix', pattern: /https?:\/\/[^/\s]*\.(internal|local|lan|corp|intranet)\b/i, reason: '访问内网域名后缀' },
    { id: 'file-scheme', pattern: /\bfile:\/\/\//i, reason: 'file:// 协议读取本地文件' },
    { id: 'gopher-scheme', pattern: /\bgopher:\/\//i, reason: 'gopher:// 协议（SSRF 利用）' },
    { id: 'dict-scheme', pattern: /\bdict:\/\//i, reason: 'dict:// 协议（SSRF 利用）' },
];
export function scanNetworkTarget(text) {
    const hits = [];
    for (const rule of SSRF_RULES) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(text))
            hits.push({ ruleId: rule.id, reason: rule.reason });
    }
    return hits;
}
