export const SECRET_RULES = [
    // AWS
    { id: 'aws-akid', secretType: 'AWS Access Key', description: 'AWS Access Key ID', pattern: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z2-7]{16})\b/ },
    { id: 'aws-secret', secretType: 'AWS Secret', description: 'AWS Secret Access Key 赋值', pattern: /aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}/i },
    // GitHub 全家桶
    { id: 'github-pat', secretType: 'GitHub Token', description: 'GitHub PAT', pattern: /\bghp_[0-9a-zA-Z]{36}\b/ },
    { id: 'github-oauth', secretType: 'GitHub Token', description: 'GitHub OAuth Token', pattern: /\bgho_[0-9a-zA-Z]{36}\b/ },
    { id: 'github-app', secretType: 'GitHub Token', description: 'GitHub App/Refresh Token', pattern: /\b(ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b/ },
    { id: 'github-fine', secretType: 'GitHub Token', description: 'GitHub fine-grained PAT', pattern: /\bgithub_pat_\w{82}\b/ },
    { id: 'gitlab-pat', secretType: 'GitLab Token', description: 'GitLab PAT', pattern: /\bglpat-[0-9a-zA-Z_\-]{20}\b/ },
    // OpenAI（新旧格式）
    { id: 'openai-key', secretType: 'OpenAI Key', description: 'OpenAI API Key', pattern: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}|sk-[A-Za-z0-9_-]{32,})\b/ },
    // Anthropic
    { id: 'anthropic-key', secretType: 'Anthropic Key', description: 'Anthropic API Key', pattern: /\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b|\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
    // 云与平台
    { id: 'google-api', secretType: 'Google Key', description: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    { id: 'gcp-oauth', secretType: 'GCP OAuth', description: 'GCP OAuth access token', pattern: /\bya29\.[0-9A-Za-z_-]{20,}\b/ },
    { id: 'slack-bot', secretType: 'Slack Token', description: 'Slack Bot Token', pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/ },
    { id: 'slack-user', secretType: 'Slack Token', description: 'Slack User Token', pattern: /\bxox[pe](-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}/ },
    { id: 'slack-app', secretType: 'Slack Token', description: 'Slack App Token', pattern: /\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b/ },
    { id: 'stripe-live', secretType: 'Stripe Key', description: 'Stripe Live Secret Key', pattern: /\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b/ },
    { id: 'stripe-test', secretType: 'Stripe Key', description: 'Stripe Test Key', pattern: /\b(sk|rk)_test_[0-9a-zA-Z]{24,}\b/ },
    { id: 'npm-token', secretType: 'npm', description: 'npm Access Token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
    { id: 'pypi-token', secretType: 'PyPI', description: 'PyPI Upload Token', pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/ },
    { id: 'telegram', secretType: 'Telegram', description: 'Telegram Bot Token', pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/ },
    { id: 'twilio', secretType: 'Twilio', description: 'Twilio API Key', pattern: /\bSK[0-9a-fA-F]{32}\b/ },
    { id: 'sendgrid', secretType: 'SendGrid', description: 'SendGrid API Key', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
    { id: 'huggingface', secretType: 'HuggingFace', description: 'HuggingFace Token', pattern: /\bhf_[A-Za-z0-9]{30,}\b/ },
    // 通用
    { id: 'private-key', secretType: 'Private Key', description: '私钥头', pattern: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----/i },
    { id: 'jwt', secretType: 'JWT', description: 'JWT Token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
    { id: 'bearer', secretType: 'Bearer', description: 'Bearer Token', pattern: /\bBearer\s+[A-Za-z0-9_\-.~+/]{20,}={0,2}\b/ },
    { id: 'generic-secret', secretType: 'Generic', description: '通用 secret 赋值', pattern: /[\w.-]{0,50}?(?:access|auth|api|credential|key|passw(?:or)?d|secret|token)[ \t\w.-]{0,20}[\s'"]{0,3}(?:=|:{1,3}=|:|\?=)[\x60'"\s=]{0,5}([\w.=-]{16,150})/i },
];
/** 计算字符串 Shannon 熵（trufflehog/gitleaks 用它过滤低熵误报，如 'aaaaaaaa'） */
export function shannonEntropy(s) {
    if (!s)
        return 0;
    const freq = new Map();
    for (const ch of s)
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
/** 在文本中扫描密钥，返回命中列表（含熵值，低熵命中可信度低） */
export function scanSecrets(text, minEntropy = 0) {
    const hits = [];
    for (const rule of SECRET_RULES) {
        rule.pattern.lastIndex = 0;
        const m = rule.pattern.exec(text);
        if (m) {
            const raw = m[0];
            const entropy = shannonEntropy(raw);
            if (entropy >= minEntropy) {
                hits.push({ ruleId: rule.id, secretType: rule.secretType, description: rule.description, match: mask(raw), entropy });
            }
        }
    }
    return hits;
}
/** 脱敏：保留前 4 后 2，其余打码 */
function mask(s) {
    if (s.length <= 8)
        return '***';
    return s.slice(0, 4) + '*'.repeat(Math.min(s.length - 6, 24)) + s.slice(-2);
}
