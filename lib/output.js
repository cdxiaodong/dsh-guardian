/**
 * 输出侧扫描 —— 检测 Agent 响应中的密钥泄露、Canary Token 或敏感信息。
 *
 * 设计理念：
 * - 输入侧扫描已在 check() 中实现（扫描工具调用参数）
 * - 输出侧扫描在 Agent 生成响应后、发送给用户前执行
 * - 借鉴 ClawShield AI Agent Security Proxy 的双向扫描思路
 * - Canary Token 格式参考：高熵字符串 + 标记前缀（如 canary_、test_token_）
 *
 * 资料来源：
 * - Bidirectional Response Scanning - Intelligent Nexus Security
 *   https://ins.security/features/response-scanning
 * - Canary Tokens for Prompt Injection Detection
 *   https://www.toxsec.com/p/canary-tokens-for-prompt-injection
 * - tracebit-com/tracebit-canaries-skill
 *   https://github.com/tracebit-com/tracebit-canaries-skill
 * - ClawShield AI Agent Security Proxy
 *   https://www.linkedin.com/posts/alan-ross-4a21662_release-clawshield-v100-sleuthcoclawshield-public-activity-7434039270509645824-zqGw
 */
import { scanSecrets } from './secrets.js';
/**
 * Canary Token 规则集。
 *
 * Canary Token 是埋入系统中的虚假凭据，当它们出现在 Agent 输出中时，
 * 表明存在泄露或数据外泄。格式包括：
 * - 标准前缀（canary_、test_token_、honeytoken_）
 * - 高熵随机字符串（模拟真实密钥）
 * - 特定格式（UUID、Base64）
 */
export const CANARY_RULES = [
    // 通用 Canary 前缀
    { id: 'canary-generic', description: '通用 Canary Token（canary_ 前缀）', pattern: /\bcanary_[A-Za-z0-9_-]{16,}\b/gi },
    { id: 'canary-test', description: '测试 Canary Token（test_token_ 前缀）', pattern: /\btest_token_[A-Za-z0-9_-]{16,}\b/gi },
    { id: 'canary-honey', description: 'Honeytoken（honeytoken_ 前缀）', pattern: /\bhoneytoken_[A-Za-z0-9_-]{16,}\b/gi },
    // UUID 格式 Canary（常用于追踪泄露）
    { id: 'canary-uuid', description: 'UUID 格式 Canary', pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi },
    // Base64 格式高熵字符串
    { id: 'canary-base64', description: 'Base64 高熵字符串（可能为编码的 Canary）', pattern: /\b[A-Za-z0-9+/]{32,}={0,2}\b/g },
    // 特定平台 Canary
    { id: 'canary-aws', description: 'AWS 格式 Canary（假 AKIA 开头）', pattern: /\bAKIACANARY[A-Z0-9]{16}\b/g },
    { id: 'canary-github', description: 'GitHub 格式 Canary（假 ghp_ 开头）', pattern: /\bghp_canary_[A-Za-z0-9_-]{29}\b/gi },
];
/**
 * 扫描输出文本中的敏感信息。
 *
 * 检测两类：
 * 1. Canary Token（优先检测）—— 标记为 sensitive=false（警报但不拦截）
 * 2. 真实密钥泄露—— 标记为 sensitive=true
 *
 * 策略：先移除文本中的 Canary Token，再检测密钥，避免 Canary 被通用密钥规则误报。
 *
 * @param text 要扫描的输出文本
 * @param minEntropy 密钥熵阈值（默认 3.0，降低误报）
 * @returns 命中列表
 */
export function scanOutput(text, minEntropy = 3.0) {
    const hits = [];
    // 1. 优先检测 Canary Token
    for (const rule of CANARY_RULES) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
            hits.push({
                type: 'canary',
                ruleId: rule.id,
                description: rule.description,
                match: mask(match[0]),
                sensitive: false,
            });
        }
    }
    // 2. 清理文本：移除已识别的 Canary Token（替换为占位符）
    let cleanText = text;
    for (const rule of CANARY_RULES) {
        rule.pattern.lastIndex = 0;
        cleanText = cleanText.replace(rule.pattern, '[REDACTED-CANARY]');
    }
    // 3. 密钥泄露检测（在清理后的文本上）
    const secretHits = scanSecrets(cleanText, minEntropy);
    for (const hit of secretHits) {
        hits.push({
            type: 'secret',
            ruleId: hit.ruleId,
            description: `输出含明文密钥：${hit.description}`,
            match: hit.match,
            sensitive: true,
        });
    }
    return hits;
}
/**
 * 判定输出安全性。
 *
 * @param text 要判定的输出文本
 * @returns 判定结果
 */
export function judgeOutput(text) {
    const hits = scanOutput(text);
    const sensitiveHits = hits.filter((h) => h.sensitive);
    if (sensitiveHits.length > 0) {
        const first = sensitiveHits[0];
        return {
            safe: false,
            reason: first.description,
            hits,
        };
    }
    return { safe: true, hits };
}
/** 脱敏显示 */
function mask(s) {
    if (s.length <= 8)
        return '***';
    return s.slice(0, 4) + '*'.repeat(Math.min(s.length - 6, 24)) + s.slice(-2);
}
