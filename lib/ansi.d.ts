/**
 * 终端转义序列防御引擎（ANSI Deception Guard）
 *
 * 攻击面：Trail of Bits《Deceiving users with ANSI terminal codes in MCP》(2025-04)
 * 揭示的一类攻击——攻击者在 MCP 工具输出 / 文件内容 / 命令输出中嵌入 ANSI 转义序列，
 * 让「人工审核员在终端看到的」与「LLM 实际收到的」不一致：
 *   - SGR 8（conceal）隐藏文本：人眼不可见，LLM 可读
 *   - 行擦除 + 回车覆盖：先打印无害内容骗过审核，再擦掉换成恶意指令
 *   - 光标上跳（line-jumping）：把恶意行覆盖到批准提示上方
 *   - OSC 8 伪装超链接：显示无害文本，实际指向恶意地址
 *   - DSR/DA 探测序列：诱导终端回传数据（侧信道）
 *   - C1 单字节 CSI（\x9b）：等价于 ESC+[ 的绕过形式，常用于绕过只查 \x1b 的过滤器
 *
 * 正常 CLI 输出（git diff / ls --color）带大量安全 SGR 色码，因此引擎只对
 * 「改变可见性 / 覆盖已有内容 / 与终端双向通信」的序列告警，纯颜色码放行。
 */
export interface AnsiRule {
    id: string;
    pattern: RegExp;
    description: string;
    /** deny=直接拒绝；block=人工确认；log=仅记录 */
    action: 'block' | 'deny' | 'log';
    /** 风险权重 0~1（供风险评分信号使用） */
    weight: number;
}
export interface AnsiHit {
    ruleId: string;
    description: string;
    action: AnsiRule['action'];
    /** 命中的原始序列（审计证据，写入审计前会被可见化） */
    match: string;
    /** 在原文中的起始位置；-1 表示来自 JSON 字面量解码后的文本 */
    index: number;
}
/**
 * 危险转义序列规则集（ID 前缀 ANSI-）。
 * 安全 SGR 色码（颜色/粗体/下划线等）不在此列，由 isSafeSgr 单独放行。
 */
export declare const ANSI_RULES: AnsiRule[];
export interface ScanAnsiOptions {
    /** 先解码 JSON 字面量（ESC 等）再复扫。guardian/check 集成路径应开启 */
    unescapeLiterals?: boolean;
}
/**
 * 扫描文本中的危险终端转义序列，按规则顺序返回全部命中。
 * 安全 SGR 色码（git diff / ls --color 等正常输出）不产生命中。
 */
export declare function scanAnsi(text: string, opts?: ScanAnsiOptions): AnsiHit[];
export type SanitizeMode = 'escape' | 'strip' | 'redact';
/**
 * 净化文本中的终端转义序列，保证「审核员看到的 = LLM 收到的」。
 *  - escape：控制字符可见化（␛ 等），长度不变、证据保真 —— 审计日志固定用此模式
 *  - strip ：删除所有转义序列，得到终端安全的纯文本
 *  - redact：危险序列替换为 <ANSI:id> 占位，保留可读的攻击证据链
 */
export declare function sanitizeAnsi(text: string, mode?: SanitizeMode): string;
export interface RenderReport {
    /** 参与统计的可打印字符数 */
    totalChars: number;
    /** conceal 隐藏的字符数（LLM 可读、人眼不可见） */
    hiddenChars: number;
    /** 隐藏字符占比 0~1 */
    hiddenRatio: number;
    /** 被擦除/覆盖替换掉的字符数 */
    overwrittenChars: number;
    /** 触发的一致性异常信号（ANSI-xxx） */
    signals: string[];
    /** hiddenRatio≥0.05 或 overwrittenChars≥24 时为 true */
    suspicious: boolean;
}
/**
 * 渲染一致性审计（简化终端模型）：模拟文本在终端渲染后，量化
 * 「LLM 收到的原文」与「人眼最终看到的」之间的差异。
 * 这是给人工审核 UI 的核心信号：suspicious=true 意味着你看到的可能不是全部。
 */
export declare function renderConsistency(text: string): RenderReport;
