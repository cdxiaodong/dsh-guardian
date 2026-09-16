/**
 * 参数结构走私守卫（Arg-Smuggling Guard）—— engine-26
 *
 * 威胁模型：既有 25 个引擎全部扫描「解析后的值的内容语义」——命令字符串危不危险、
 * 密钥格式像不像、地址在内网吗。但工具调用的 args 是 JSON，JSON 自身的「结构」
 * 就能走私：两个值单独看都无害，组合成歧义结构即可让验证器看到 A、执行器执行 B。
 *
 *   - 重复键（parser differential）：{"path":"/safe/dir","path":"/etc/passwd"}
 *     Go encoding/json 取第一个值、JS JSON.parse 取最后一个值、MySQL 8 又是一套
 *     （Bishop Fox《JSON Interoperability Vulnerabilities》系统梳理）。MCP 攻击学院
 *     Genbounty 已把「duplicate key validation bypass」课程化——攻击面成熟。
 *     MCP Go SDK 官方 advisory GHSA-q382-vc8q-7jhj：null Unicode + 重复键 last-wins
 *     覆盖 MCP 消息。
 *   - 原型污染键：{"__proto__":{"isAdmin":true}} 经 defu/merge 类库合并即穿透
 *     （GHSA-737v-mqg7-c878 / CVE-2026-35209；mcp-server-fetch 原型污染
 *     SNYK-MINIMOSLATEST-MCPSERVERFETCH-17663748）。JSON.parse 会把它做成 own
 *     property，Object.entries 可见——但下游 merge 库把它当原型赋值处理。
 *   - 标识符欺骗：西里尔 а 冒充拉丁 a 的 "pаth" 键——deny 规则按键名匹配时对不上，
 *     渲染/日志层 NFKC 归一后又变回 "path"（anthropics/claude-code#29489：confusable
 *     绕过 permission 规则匹配，closed as not planned 未修复）。
 *   - 非标数字字面量：NaN/Infinity/undefined 是 JS eval/Python json.loads 的方言，
 *     严格 JSON.parse 直接抛错——跨语言语义分歧（Trail of Bits《Unexpected
 *     Security Footguns in Go's Parsers》）。>2^53 整数静默舍入（雪花 ID/纳秒时间戳
 *     在 JS 执行器里精度丢失，google/adk-python#3592 生产 bug）。
 *
 * 本仓库自身的失明点（main src/index.ts check()）：
 *   const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {})
 *   ——字符串原样传给内容引擎（内容正则可被无害值骗过）；对象形态直接 stringify，
 *   重复键被 last-wins 折叠、NaN 变 null、大数已舍入：结构证据不可逆丢失。
 *   本引擎直接消费原始 payload：字符串形态跑 tokenizer（在 JSON.parse 固化 last-wins
 *   之前——parse 之后谁也看不见第一个值），对象形态走降级路径（键名三查 +
 *   NaN/Infinity 值 + 超精度数值仍可检测，重复键/裸字面量已丢失，诚实声明见下）。
 *
 * fail-safe 设计原则（对抗审查驱动修正，教训：检测器静默跳过 = 给攻击者发绕过指南）：
 *   - 任何「扫不完」的情形（语法垃圾/未闭合/根后内容/非法定数字/超深嵌套）一律上报
 *     ARG-007 block 级命中交人工确认，绝不静默放行——下游 jsonrepair 类修复解析器
 *     恰好会复活这些语法瑕疵里的结构歧义
 *   - 命中截断 deny 优先：50 条 block 噪声挤不掉 deny 级证据（防审计炸弹的截断
 *     不能反过来变成掩埋工具）
 *
 * 与既有引擎的分工：
 *   - deobfuscation（engine-9）解码的是「值的编码」，无 JSON 结构意识——不区分键/值/
 *     层级，无法回答「这个 JSON 本身有没有两义」
 *   - tool-integrity（engine-11）pin 的是工具 schema 定义指纹，不管单次调用的参数
 *   - tool-poisoning（engine-15）验毒对象是工具描述文本，不管 args
 *   - squat-guard（engine-22）的同形字归一只用于包名（且各引擎分支互相独立，本引擎
 *     自带 UTS#39-lite 映射表）
 *   - rule 引擎的全文正则查不到「两个值单独看都无害」的结构歧义
 *
 * 诚实边界：
 *   1. 宿主若已 JSON.parse 再传对象，重复键/裸 NaN 字面量/大整数原始精度已在对象化
 *      时丢失（JSON.stringify(NaN)→null）——对象形态是降级路径。满血检测要求宿主传
 *      原始字符串（MCP 2025-06 规范后 arguments 以原始 JSON 文本传输，卡位现成）。
 *   2. 同形字映射是 UTS#39 精简子集（NFKC + 高频混淆对静态表），完整性不及官方
 *      skeleton 算法，未覆盖的冷门混淆对会漏报——但已知攻击字符（西里尔/希腊/全角）
 *      全覆盖。
 *   3. tokenizer 对部分语法垃圾宽容消费（如尾逗号），但所有「无法继续可靠扫描」的
 *      情形都以 ARG-007 上报而非静默——本引擎是检测器不是校验器，但绝不假装扫过。
 *   4. 以 { 或 [ 开头的非 JSON 文本（如 bash 花括号命令组 "{ ls; }"）会进入结构扫描
 *      并命中 ARG-007——这是 fail-safe 的代价（block 人工确认），换取的是结构走私
 *      无法借「假装不是 JSON」蒙混过关。
 */
/** 检出处置级别：deny=直接拒；block=人工确认 */
export type ArgAction = 'deny' | 'block';
export interface ArgHit {
    ruleId: string;
    reason: string;
    action: ArgAction;
    /** 命中证据（截断，避免审计日志膨胀） */
    match: string;
}
export interface ArgScanOptions {
    /** 嵌套深度关注阈值（默认 512：远高于常规合法 JSON，超限上报 ARG-007 继续扫） */
    maxDepth?: number;
    /** 追加的敏感键名（小写；折叠后命中即升级 block） */
    sensitiveKeys?: string[];
    /** 是否对键名做 URI 解码变体检查（默认 true，捕获 %5F%5Fproto%5F%5F 类变形） */
    uriDecode?: boolean;
}
/**
 * 敏感参数名基线（全部小写比较）。键名经同形字折叠后落入该集合 = 键名冒充。
 * 含三类：原型污染键、HiddenLayer《Beyond MCP》实证的提示词劫持键名
 * （system_prompt/chain_of_thought 等作参数名窃取系统提示词）、
 * 常见安全决策参数（deny 规则/审批/权限常用键名，冒充即可绕过按名匹配的防线）。
 */
export declare const SENSITIVE_PARAM_KEYS: string[];
/**
 * UTS#39-lite 同形字映射（在小写化之后做单字符替换；NFKC 已覆盖全角/连字，
 * 此表补 NFKC 不做跨脚本折叠的西里尔/希腊混淆对；表按小写键存储，大写输入
 * 先 toLowerCase 再查——防大小写不对称绕过，如西里尔大写 Ѕ(U+0405)）。
 */
export declare const CONFUSABLE_MAP: Record<string, string>;
/** 键名骨架折叠：NFKC 归一（全角/连字/兼容形）→ 小写化 → 同形字替换。
 *  小写化必须在映射之前（大写西里尔 Ѕ 先变 ѕ 再映射 s）——顺序反了即产生
 *  大小写不对称绕过。 */
export declare function skeletonFold(key: string): string;
/**
 * 参数结构走私扫描入口。消费「原始 payload」而非序列化文本：
 *  - string：tokenizer 路径（满血——重复键/裸字面量/原始精度全可检）
 *  - object：降级路径（键名三查 + 非有限数值 + 超精度数值；重复键证据已不可逆丢失）
 *  - 其他（number/boolean/null/undefined）：无结构，不命中
 * 纯函数、零网络零模型、无状态可并发。
 */
export declare function scanArgs(payload: unknown, opts?: ArgScanOptions): ArgHit[];
