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
/** Canary Token 规则 */
export interface CanaryRule {
    id: string;
    pattern: RegExp;
    description: string;
}
/**
 * Canary Token 规则集。
 *
 * Canary Token 是埋入系统中的虚假凭据，当它们出现在 Agent 输出中时，
 * 表明存在泄露或数据外泄。格式包括：
 * - 标准前缀（canary_、test_token_、honeytoken_）
 * - 高熵随机字符串（模拟真实密钥）
 * - 特定格式（UUID、Base64）
 */
export declare const CANARY_RULES: CanaryRule[];
/** 输出扫描命中结果 */
export interface OutputHit {
    type: 'secret' | 'canary';
    ruleId: string;
    description: string;
    match: string;
    /** 是否为敏感内容（需拦截） */
    sensitive: boolean;
}
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
export declare function scanOutput(text: string, minEntropy?: number): OutputHit[];
/**
 * 输出安全判定结果。
 *
 * - unsafe=true: 命中真实密钥，建议拦截
 * - unsafe=false: 安全或仅命中 Canary（仅需警报）
 */
export interface OutputVerdict {
    safe: boolean;
    /** 不安全原因（仅 unsafe=true 时有值） */
    reason?: string;
    /** 命中列表（含 Canary，用于审计） */
    hits: OutputHit[];
}
/**
 * 判定输出安全性。
 *
 * @param text 要判定的输出文本
 * @returns 判定结果
 */
export declare function judgeOutput(text: string): OutputVerdict;
