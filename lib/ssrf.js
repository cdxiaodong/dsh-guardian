/** Internal/dangerous target addresses (raises an alert when they appear in URL/IP parameters) */
export const SSRF_RULES = [
    { id: 'cloud-metadata-aws', pattern: /169\.254\.169\.254/, reason: 'AWS/cloud metadata service (classic SSRF target)' },
    { id: 'cloud-metadata-gcp', pattern: /metadata\.google\.internal|169\.254\.169\.254.*computeMetadata/i, reason: 'GCP metadata service' },
    { id: 'cloud-metadata-aliyun', pattern: /100\.100\.100\.200/, reason: 'Alibaba Cloud metadata service' },
    { id: 'loopback', pattern: /\b(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\b/, reason: 'Access to loopback address' },
    { id: 'rfc1918-10', pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, reason: 'Access to 10.x internal network' },
    { id: 'rfc1918-192', pattern: /\b192\.168\.\d{1,3}\.\d{1,3}\b/, reason: 'Access to 192.168 internal network' },
    { id: 'rfc1918-172', pattern: /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/, reason: 'Access to 172.16-31 internal network' },
    { id: 'link-local', pattern: /\b169\.254\.\d{1,3}\.\d{1,3}\b/, reason: 'Access to link-local address' },
    { id: 'internal-suffix', pattern: /https?:\/\/[^/\s]*\.(internal|local|lan|corp|intranet)\b/i, reason: 'Access to internal domain suffix' },
    { id: 'file-scheme', pattern: /\bfile:\/\/\//i, reason: 'file:// scheme reads local files' },
    { id: 'gopher-scheme', pattern: /\bgopher:\/\//i, reason: 'gopher:// scheme (SSRF exploitation)' },
    { id: 'dict-scheme', pattern: /\bdict:\/\//i, reason: 'dict:// scheme (SSRF exploitation)' },
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
