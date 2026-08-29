/**
 * 工具定义毒性扫描引擎（Tool-Definition Poisoning Scanner / 确定性版 mcp-scan）。
 *
 * 威胁模型（Invariant Labs 2025-04「Tool Poisoning Attacks」披露）：
 * **工具描述就是 prompt** —— MCP 客户端把所有已连接 server 的工具描述、参数
 * schema 说明以全信任注入模型上下文，工具元数据与指令流之间没有沙箱；一个恶意
 * server 可以借描述里的隐藏指令毒化其他合法 server 工具的行为（跨 server 注入）。
 * 典型载体：描述中藏「ignore previous instructions」、Unicode Tags 区隐形指令、
 * HTML 注释、双向文本（RLO）视觉伪装、inputSchema 嵌套字段的说明文本。
 *
 * 与工具清单完整性引擎（feat/2026-08-24）互补，二者拼成完整防线：
 *  - 完整性 = 定义「变没变」（批准时刻 pin hash，运行时校验漂移）
 *  - 本引擎 = 定义「有没有毒」（首次接触即扫内容，零基线依赖）
 *
 * mcp-scan（Invariant Labs）用 LLM 做离线扫描；本引擎做**确定性、无 LLM、可单测**
 * 的运行时常驻版本，并附带 Unicode Tags「显影」——把隐形注入还原成可读明文供审计。
 *
 * 借鉴：Invariant Labs mcp-scan 与 Tool Poisoning PoC、OWASP MCP03:2025
 * (Tool Poisoning)、arXiv:2503.24652（ARTMS Tags-poisoning 提示注入）。
 */
/** 宿主上报的最小工具定义（MCP tools/list 条目 / Cordis 指令声明子集） */
export interface ToolDefInput {
    name: string;
    description?: string;
    /** JSON Schema 形态参数定义：递归扫描其中 description/title/default 字符串字段 */
    inputSchema?: unknown;
}
export type PoisonSeverity = 'poison' | 'suspect';
export interface PoisonFinding {
    ruleId: string;
    severity: PoisonSeverity;
    /** 命中位置：name / description / schema 字段路径（如 schema:properties.token.description） */
    where: string;
    reason: string;
    /** 命中片段（截断；隐形字符已显影为可读明文） */
    excerpt: string;
}
export interface ToolDefVerdict {
    /** false = 存在 poison 级命中，宿主应拒绝注册该工具 */
    safe: boolean;
    findings: PoisonFinding[];
    /** 存在 suspect 级命中（可疑但可能合法），建议人工复核 */
    requiresReview: boolean;
}
export interface ScanOptions {
    /** 宿主内置/保留工具名清单：新工具与之同名或同形异码即视为抢注（TPD-006） */
    reservedNames?: string[];
}
/**
 * Unicode Tags「显影」：U+E0020–U+E007E 映射回可见 ASCII（code − 0xE0000），
 * 语言标签（U+E0001）与取消符（U+E007F）丢弃。把隐形注入变成人眼可读明文。
 */
export declare function developTags(s: string): string;
/** 提取文本中所有 Tags 区字符并显影为 ASCII（判定「藏了什么」用） */
export declare function tagsPayload(s: string): string;
/** 工具名规范化：NFKC（全角→半角）+ 去零宽/双向控制 + 同形折叠 + 小写 */
export declare function normalizeToolName(name: string): string;
interface TextRule {
    id: string;
    severity: PoisonSeverity;
    reason: string;
    /** 命中判定（字符串或函数：返回 true 即命中） */
    test: RegExp | ((developedText: string, rawText: string) => boolean);
}
/**
 * 描述文本毒性规则。所有正则不带 /g，避免 lastIndex 状态污染。
 * 分级原则：确定性恶意模式（指令覆盖/角色伪装/隐形载体/瞒用户）= poison；
 * 可疑但存在合法用例（指令头措辞、敏感源引用）= suspect 走人工确认。
 */
export declare const TOOLPOISON_RULES: TextRule[];
interface TextField {
    path: string;
    text: string;
}
/** 深度遍历 schema，收集会进入模型上下文的字符串字段（description/title/default） */
export declare function collectSchemaTexts(schema: unknown, base?: string, out?: TextField[], depth?: number): TextField[];
/** 扫描单个工具定义：name 抢注 + description + schema 嵌套字段 */
export declare function scanToolDefinition(def: ToolDefInput, opts?: ScanOptions): PoisonFinding[];
/** findings → 判定：poison 存在即 unsafe；suspect 存在则要求人工复核 */
export declare function verdictOf(findings: PoisonFinding[]): ToolDefVerdict;
export {};
