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
export type ArgAction = 'deny' | 'block'

export interface ArgHit {
  ruleId: string
  reason: string
  action: ArgAction
  /** 命中证据（截断，避免审计日志膨胀） */
  match: string
}

export interface ArgScanOptions {
  /** 嵌套深度关注阈值（默认 512：远高于常规合法 JSON，超限上报 ARG-007 继续扫） */
  maxDepth?: number
  /** 追加的敏感键名（小写；折叠后命中即升级 block） */
  sensitiveKeys?: string[]
  /** 是否对键名做 URI 解码变体检查（默认 true，捕获 %5F%5Fproto%5F%5F 类变形） */
  uriDecode?: boolean
}

// ── 常量：危险键名 / 敏感参数名 / 同形字映射 / 不可见字符 ──────────────

/** 原型污染键（CWE-1321）：任意深度出现即 deny */
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * 敏感参数名基线（全部小写比较）。键名经同形字折叠后落入该集合 = 键名冒充。
 * 含三类：原型污染键、HiddenLayer《Beyond MCP》实证的提示词劫持键名
 * （system_prompt/chain_of_thought 等作参数名窃取系统提示词）、
 * 常见安全决策参数（deny 规则/审批/权限常用键名，冒充即可绕过按名匹配的防线）。
 */
export const SENSITIVE_PARAM_KEYS: string[] = [
  '__proto__', 'constructor', 'prototype',
  'system', 'system_prompt', 'systemprompt', 'developer_message',
  'instructions', 'chain_of_thought', 'prompt', 'context',
  'credentials', 'password', 'passwd', 'secret', 'secrets',
  'token', 'tokens', 'api_key', 'apikey', 'access_token',
  'allowed_tools', 'permissions', 'permission', 'approved', 'approval',
  'guardian', 'rules', 'rule', 'action', 'policy',
  'cmd', 'command', 'exec', 'run',
  'path', 'file_path', 'filepath', 'file', 'url', 'uri', 'host', 'target',
]

/**
 * UTS#39-lite 同形字映射（在小写化之后做单字符替换；NFKC 已覆盖全角/连字，
 * 此表补 NFKC 不做跨脚本折叠的西里尔/希腊混淆对；表按小写键存储，大写输入
 * 先 toLowerCase 再查——防大小写不对称绕过，如西里尔大写 Ѕ(U+0405)）。
 */
export const CONFUSABLE_MAP: Record<string, string> = {
  // 西里尔小写 → 拉丁
  'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѕ': 's',
  // 西里尔大写 → 拉丁大写（skeletonFold 已先小写化，此组为直接调用者兜底）
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
  // 希腊小写 → 拉丁
  'ο': 'o', 'α': 'a', 'ν': 'n', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'κ': 'k',
  'ι': 'i', 'ε': 'e',
  // 希腊大写 → 拉丁大写（同上兜底）
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Κ': 'K', 'Μ': 'M',
  'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
  // 拉丁扩展形近字
  'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'l',
}

/** 键名中的不可见字符：C0/C1 控制 / DEL / 软连字符 / ALM(U+061C) / 蒙古 vowel sep(U+180E) /
 *  零宽 / 行段分隔(U+2028-9) / 双向控制与隔离符(RLO/LRI/RLI/FSI/PDI, U+202A-E/U+2066-9) /
 *  BOM / deprecated U+2065 —— 覆盖完整 bidi 家族，不只 RLO */
const INVISIBLE_KEY_RE = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2069\uFEFF]/u
/** Unicode Tags 区（U+E0000–U+E007F，engine-15 显影过的隐形注入载体） */
const TAG_CHARS_RE = /[\u{E0000}-\u{E007F}]/u
/** 键名归一预览时要转义的不可见字符（C0/C1/DEL） */
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F-\u009F]/g
/** 键名归一预览时标记的零宽/双向类字符 */
const ZERO_WIDTH_RE = /[\u00AD\u061C\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2069\uFEFF]/g
/** UTF-8 BOM */
const BOM_RE = /^\uFEFF/
/** 严格 JSON 数字格式（上溢/精度判定只对合法数字做——畸形 token 走 ARG-007，防假报） */
const STRICT_NUMBER_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/

/** 键名骨架折叠：NFKC 归一（全角/连字/兼容形）→ 小写化 → 同形字替换。
 *  小写化必须在映射之前（大写西里尔 Ѕ 先变 ѕ 再映射 s）——顺序反了即产生
 *  大小写不对称绕过。 */
export function skeletonFold(key: string): string {
  const out = key.normalize('NFKC').toLowerCase()
  let folded = ''
  for (const ch of out) folded += CONFUSABLE_MAP[ch] ?? ch
  return folded
}

/** 数值安全边界：2^53-1，纯整数字面量超过它即精确性损失（BigInt 精确比对源文本） */
const MAX_SAFE_BIGINT = 9007199254740991n
/** 对象形态数值检查边界 */
const MAX_SAFE = Number.MAX_SAFE_INTEGER

// ── 键名三查：不可见字符(deny) / 原型污染键(deny) / 同形字冒充(block) ──

interface ResolvedOptions {
  maxDepth: number
  sensitiveKeys: Set<string>
  uriDecode: boolean
}

function resolveOptions(opts: ArgScanOptions = {}): ResolvedOptions {
  return {
    maxDepth: opts.maxDepth ?? 512,
    sensitiveKeys: new Set([
      ...SENSITIVE_PARAM_KEYS,
      ...(opts.sensitiveKeys ?? []).map((k) => k.toLowerCase()),
    ]),
    uriDecode: opts.uriDecode ?? true,
  }
}

/** 单个键名检查，返回命中（无命中返回 null）。检查顺序按确定性从高到低 */
function checkKey(key: string, opts: ResolvedOptions): ArgHit | null {
  // ARG-006：键名内嵌不可见字符——标识符里的隐形字符没有任何合法用途，
  // 唯一效果是骗过按名匹配的规则与肉眼审计（日志里"看起来一样"的键）
  if (INVISIBLE_KEY_RE.test(key) || TAG_CHARS_RE.test(key)) {
    return {
      ruleId: 'ARG-006',
      reason: `结构走私：键名内嵌不可见字符（零宽/双向控制/C0/Tags）："${escapePreview(key)}"`,
      action: 'deny',
      match: escapePreview(key).slice(0, 160),
    }
  }
  // ARG-002：原型污染键（精确 / URI 解码变形 / NFKC+同形字折叠变形）
  if (isProtoKey(key, opts)) {
    return {
      ruleId: 'ARG-002',
      reason: `结构走私：原型污染键 "${escapePreview(key)}"（CWE-1321，defu/merge 类库即穿透）`,
      action: 'deny',
      match: escapePreview(key).slice(0, 160),
    }
  }
  // ARG-005：同形字键名冒充——折叠前后不一致且折叠后命中敏感参数名
  const folded = skeletonFold(key)
  if (folded !== key.toLowerCase() && opts.sensitiveKeys.has(folded)) {
    return {
      ruleId: 'ARG-005',
      reason: `结构走私：同形字键名冒充 "${escapePreview(key)}" → 折叠后为敏感参数名 "${folded}"（绕过按键名匹配的 deny 规则）`,
      action: 'block',
      match: escapePreview(key).slice(0, 160),
    }
  }
  return null
}

/** 原型污染键判定：精确匹配 / 最多 2 轮 URI 解码后 / NFKC+同形字折叠后 */
function isProtoKey(key: string, opts: ResolvedOptions): boolean {
  const variants = new Set<string>([key.toLowerCase(), skeletonFold(key)])
  if (opts.uriDecode) {
    let cur = key
    for (let round = 0; round < 2; round++) {
      let next: string
      try { next = decodeURIComponent(cur) } catch { break }
      if (next === cur) break
      cur = next
      variants.add(cur.toLowerCase())
      variants.add(skeletonFold(cur))
    }
  }
  for (const v of variants) if (PROTO_KEYS.has(v)) return true
  return false
}

/** ARG-007：结构异常（fail-safe 兜底）。任何「无法完整可靠扫描」的情形都上报，
 *  绝不静默——下游修复型解析器（jsonrepair 等）恰好会复活语法瑕疵里的结构歧义 */
function structureAnomaly(reason: string, match: string): ArgHit {
  return {
    ruleId: 'ARG-007',
    reason: `结构异常：${reason}（无法完整验证结构，走人工确认——修复型解析器可能复活其中歧义）`,
    action: 'block',
    match: match.slice(0, 160),
  }
}

/** 数值字面量检查：非标字面量(block) / 上溢与超精度整数(block) / 非法定数(ARG-007) */
function checkNumberToken(tok: string, hits: ArgHit[]): void {
  // ARG-003：非标字面量（严格 JSON 不存在，Python json.loads / JS eval 方言）
  if (tok === 'NaN' || tok === 'Infinity' || tok === '-Infinity' || tok === 'undefined') {
    hits.push({
      ruleId: 'ARG-003',
      reason: `结构走私：非标 JSON 字面量 ${tok}（跨语言解析分歧：Python 可解析 / JS JSON.parse 抛错或 eval 语义）`,
      action: 'block',
      match: tok.slice(0, 160),
    })
    return
  }
  if (!/^-?[0-9]/.test(tok)) return
  // 非法定数字面量：Number() 会得 NaN，绝不能当「上溢」误报（未加引号的日期是
  // LLM 生成 JSON 最高频缺陷——上报结构异常而非编造理由）
  if (!STRICT_NUMBER_RE.test(tok)) {
    hits.push(structureAnomaly(`非法定数字字面量 ${tok}（严格 JSON 拒绝；未加引号的日期/版本号高发）`, tok))
    return
  }
  // ARG-004a：指数上溢（1e999 在 JS 执行器里静默变 Infinity）——显式判 ±Infinity
  const v = Number(tok)
  if (v === Infinity || v === -Infinity) {
    hits.push({
      ruleId: 'ARG-004',
      reason: `结构走私：数值上溢为 Infinity（${tok} 在 JS 执行器里静默变 Infinity）`,
      action: 'block',
      match: tok.slice(0, 160),
    })
    return
  }
  // ARG-004b：纯整数字面量超出 2^53——源文本承诺精确整数，JS parse 静默舍入
  // （只查纯数字形式：1e308/6.02e23 是浮点形态、本就按浮点语义理解，不算误报源）
  if (/^-?[0-9]+$/.test(tok)) {
    try {
      const bi = BigInt(tok)
      const abs = bi < 0n ? -bi : bi
      if (abs > MAX_SAFE_BIGINT) {
        hits.push({
          ruleId: 'ARG-004',
          reason: `结构走私：整数超出 2^53 安全精度（${tok} 在 JS 执行器里静默舍入为 ${v}）`,
          action: 'block',
          match: tok.slice(0, 160),
        })
      }
    } catch { /* 不可达：纯数字必可 BigInt */ }
  }
}

/** 证据预览：控制字符转义 + 零宽类字符标记 + 截断，保证审计日志可读 */
function escapePreview(s: string): string {
  return s
    .replace(CONTROL_CHARS_RE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
    .replace(ZERO_WIDTH_RE, '　')
    .slice(0, 60)
}

// ── 字符串形态：手写零依赖 JSON tokenizer（parse 前唯一卡位）──────────

interface ObjCtx {
  kind: 'obj'
  /** 已见键 → 首次值的预览（重复键证据并排展示） */
  keys: Map<string, string>
  phase: 'key-or-end' | 'colon' | 'value' | 'comma-or-end'
  pendingKey: string | null
}
interface ArrCtx {
  kind: 'arr'
  phase: 'value-or-end' | 'comma-or-end'
}
type Ctx = ObjCtx | ArrCtx

const PREVIEW_PLACEHOLDER = '(值未读取)'
const preview = (raw: string) => (raw.length > 40 ? raw.slice(0, 37) + '…' : raw) || '""'

/**
 * 结构扫描：单遍 tokenizer，维护对象栈逐层记录键名集合。
 * fail-safe：不设扫描深度硬停（tokenizer 是显式栈、无调用栈风险，合法深嵌套
 * JSON 必须扫完——深度只作为 ARG-007 关注阈值）；所有无法继续可靠扫描的情形
 * （语法相位错位/未闭合/根后内容/无法归类字符）都上报 ARG-007 后停止。
 */
function scanStructure(text: string, opts: ResolvedOptions, hits: ArgHit[]): void {
  const s = text.replace(BOM_RE, '')
  const n = s.length
  const stack: Ctx[] = []
  let rootDone = false
  let depthFlagged = false
  let i = 0

  /** 读取带转义的 JSON 字符串，返回解码值与结束位置；未闭合/非法转义返回 null */
  const readString = (start: number): { raw: string; decoded: string; end: number } | null => {
    let raw = ''
    let decoded = ''
    let j = start + 1
    while (j < n) {
      const c = s[j]
      if (c === '\\') {
        const e = s[j + 1]
        if (e === undefined) return null
        if (e === 'u') {
          const hex = s.slice(j + 2, j + 6)
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return null
          decoded += String.fromCharCode(parseInt(hex, 16))
          raw += s.slice(j, j + 6)
          j += 6
        } else {
          const unescaped: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
          if (!(e in unescaped)) return null
          decoded += unescaped[e]
          raw += s.slice(j, j + 2)
          j += 2
        }
      } else if (c === '"') {
        return { raw, decoded, end: j + 1 }
      } else {
        decoded += c
        raw += c
        j++
      }
    }
    return null
  }

  /** 读取数字或字面量词（含可选负号），返回 token 文本与结束位置 */
  const readNumberOrWord = (start: number): { tok: string; end: number } | null => {
    let j = start
    let tok = ''
    if (s[j] === '-') { tok += '-'; j++ }
    if (/[0-9]/.test(s[j] ?? '')) {
      while (j < n && /[0-9+.\-eE]/.test(s[j])) { tok += s[j]; j++ }
      return { tok, end: j }
    }
    const m = /^[A-Za-z]+/.exec(s.slice(j))
    if (m) return { tok: tok + m[0], end: j + m[0].length }
    return null
  }

  /** 记录「pendingKey 的首次值」预览（重复键并排证据用） */
  const noteValuePreview = (raw: string) => {
    const top = stack[stack.length - 1]
    if (top && top.kind === 'obj' && top.phase === 'value' && top.pendingKey !== null
      && top.keys.get(top.pendingKey) === PREVIEW_PLACEHOLDER) {
      top.keys.set(top.pendingKey, preview(raw))
    }
  }

  /** 终结符值或结构值结束后推进相位 */
  const afterValue = () => {
    const top = stack[stack.length - 1]
    if (!top) return
    if (top.kind === 'obj' && top.phase === 'value') top.phase = 'comma-or-end'
    else if (top.kind === 'arr' && top.phase === 'value-or-end') top.phase = 'comma-or-end'
  }

  /** fail-safe 退出：上报结构异常（每次扫描至多一条 007 类降级标记由调用方截断兜底） */
  const fail = (reason: string, match: string) => {
    hits.push(structureAnomaly(reason, match))
  }

  while (i < n) {
    const c = s[i]
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue }
    // 根值已完整：其后只允许空白，出现任何内容 = 根后垃圾（修复型解析器分歧面）
    if (rootDone) {
      fail('根值后存在额外内容', s.slice(Math.max(0, i - 20), i + 40))
      return
    }
    const top = stack[stack.length - 1]

    if (c === '{' || c === '[') {
      // 深度关注阈值：继续扫描（不静默截停——深嵌套是合法 JSON），透明上报一次
      if (!depthFlagged && stack.length === opts.maxDepth) {
        depthFlagged = true
        fail(`嵌套深度达 ${opts.maxDepth}（远超常规合法 JSON；继续扫描，此结构本身可疑）`, `depth=${stack.length}`)
      }
      noteValuePreview(c)
      if (c === '{') stack.push({ kind: 'obj', keys: new Map(), phase: 'key-or-end', pendingKey: null })
      else stack.push({ kind: 'arr', phase: 'value-or-end' })
      i++; continue
    }
    if (c === '"') {
      const str = readString(i)
      if (!str) {
        fail('字符串未闭合或非法转义，扫描中断', s.slice(i, i + 60))
        return
      }
      if (top && top.kind === 'obj' && top.phase === 'key-or-end') {
        const key = str.decoded
        // 键名三查（每个键都查，包括重复出现的）
        const keyHit = checkKey(key, opts)
        if (keyHit) hits.push(keyHit)
        // ARG-001：同层重复键——first-wins 校验器 vs last-wins 执行器的语义分歧
        if (top.keys.has(key)) {
          const first = top.keys.get(key) ?? PREVIEW_PLACEHOLDER
          hits.push({
            ruleId: 'ARG-001',
            reason: `结构走私：重复键 "${escapePreview(key)}"（同层第 2 次出现：first-wins 校验器看到 ${escapePreview(first)}，last-wins 执行器用后面的值）`,
            action: 'deny',
            match: `键 "${escapePreview(key)}"：首次值 ${escapePreview(first)} ↔ 第 2 次出现`.slice(0, 160),
          })
        } else {
          top.keys.set(key, PREVIEW_PLACEHOLDER)
        }
        top.pendingKey = key
        top.phase = 'colon'
      } else {
        noteValuePreview(str.raw)
        afterValue()
      }
      i = str.end; continue
    }
    if (c === ':') {
      if (top && top.kind === 'obj' && top.phase === 'colon') { top.phase = 'value'; i++; continue }
      fail('冒号相位错位（值位置出现 ":"）', s.slice(Math.max(0, i - 20), i + 40))
      return
    }
    if (c === ',') {
      if (top && top.kind === 'obj' && top.phase === 'comma-or-end') { top.phase = 'key-or-end'; i++; continue }
      if (top && top.kind === 'arr' && top.phase === 'comma-or-end') { top.phase = 'value-or-end'; i++; continue }
      fail('逗号相位错位', s.slice(Math.max(0, i - 20), i + 40))
      return
    }
    if (c === '}') {
      if (top && top.kind === 'obj' && (top.phase === 'key-or-end' || top.phase === 'comma-or-end')) {
        stack.pop(); afterValue(); if (!stack.length) rootDone = true; i++; continue
      }
      fail('闭括号相位错位（"}" 无匹配对象）', s.slice(Math.max(0, i - 20), i + 40))
      return
    }
    if (c === ']') {
      if (top && top.kind === 'arr' && (top.phase === 'value-or-end' || top.phase === 'comma-or-end')) {
        stack.pop(); afterValue(); if (!stack.length) rootDone = true; i++; continue
      }
      fail('闭括号相位错位（"]" 无匹配数组）', s.slice(Math.max(0, i - 20), i + 40))
      return
    }
    if (c === '-' || (c >= '0' && c <= '9') || /[A-Za-z]/.test(c)) {
      const t = readNumberOrWord(i)
      if (!t) {
        fail('数值/字面量 token 异常，扫描中断', s.slice(i, i + 30))
        return
      }
      checkNumberToken(t.tok, hits)
      noteValuePreview(t.tok)
      afterValue()
      i = t.end; continue
    }
    // 无法归类的字符：结构破坏——上报后停止（保留已检出证据）
    fail(`无法归类字符 ${JSON.stringify(c)}`, s.slice(Math.max(0, i - 20), i + 40))
    return
  }

  // 自然耗尽但结构未闭合：截断载荷（修复型解析器会补全——歧义复活面）
  if (!rootDone && stack.length > 0) {
    fail('结构未闭合（载荷截断）', s.slice(-40))
  }
}

// ── 对象形态：降级路径（键名三查 + NaN/Infinity 值 + 超精度数值）──────

function scanValue(v: unknown, opts: ResolvedOptions, hits: ArgHit[], depth: number, seen: Set<unknown>): void {
  // 对象路径是真递归（受调用栈约束）：到阈值上报降级并停止下探——fail-safe
  if (depth === opts.maxDepth) {
    hits.push(structureAnomaly(`对象嵌套深度达 ${opts.maxDepth}，检测降级`, `depth=${depth}`))
    return
  }
  if (depth > opts.maxDepth) return
  if (typeof v === 'number') {
    // NaN/±Infinity 只能来自宿主 JS 构造（JSON.parse 产不出）——同样是跨语言分歧信号
    if (Number.isNaN(v) || !Number.isFinite(v)) {
      hits.push({
        ruleId: 'ARG-003',
        reason: `结构走私：非有限数值 ${String(v)}（JSON 无法表示，宿主侧已发生语义分歧）`,
        action: 'block',
        match: String(v).slice(0, 160),
      })
    } else if (Number.isInteger(v) && Math.abs(v) > MAX_SAFE) {
      hits.push({
        ruleId: 'ARG-004',
        reason: `结构走私：整数超出 2^53 安全精度（${v} 在 JS 执行器里已/将被舍入）`,
        action: 'block',
        match: String(v).slice(0, 160),
      })
    }
    return
  }
  if (v !== null && typeof v === 'object') {
    if (seen.has(v)) return // 循环引用防护
    seen.add(v)
    // Map/Set 载荷：键与成员同样过三查/数值检查（Object.entries 对它们是空转）
    if (v instanceof Map) {
      for (const [mk, mv] of v) {
        const keyHit = checkKey(typeof mk === 'string' ? mk : String(mk), opts)
        if (keyHit) hits.push(keyHit)
        scanValue(mv, opts, hits, depth + 1, seen)
      }
      return
    }
    if (v instanceof Set) {
      for (const sv of v) scanValue(sv, opts, hits, depth + 1, seen)
      return
    }
    for (const [k, val] of Object.entries(v)) {
      // JSON.parse 把 "__proto__" 做成 own enumerable key，Object.entries 可见
      const keyHit = checkKey(k, opts)
      if (keyHit) hits.push(keyHit)
      scanValue(val, opts, hits, depth + 1, seen)
    }
  }
}

/**
 * 参数结构走私扫描入口。消费「原始 payload」而非序列化文本：
 *  - string：tokenizer 路径（满血——重复键/裸字面量/原始精度全可检）
 *  - object：降级路径（键名三查 + 非有限数值 + 超精度数值；重复键证据已不可逆丢失）
 *  - 其他（number/boolean/null/undefined）：无结构，不命中
 * 纯函数、零网络零模型、无状态可并发。
 */
export function scanArgs(payload: unknown, opts: ArgScanOptions = {}): ArgHit[] {
  const resolved = resolveOptions(opts)
  const hits: ArgHit[] = []
  if (typeof payload === 'string') {
    const trimmed = payload.replace(BOM_RE, '').trimStart()
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) scanStructure(payload, resolved, hits)
  } else if (payload !== null && typeof payload === 'object') {
    scanValue(payload, resolved, hits, 0, new Set())
  }
  // 截断防审计炸弹，但 deny 优先——block 噪声挤不掉 deny 证据（对抗审查实测过
  // 「50 条同形字噪声把 __proto__ 挤出结果」的掩埋攻击）
  const denies = hits.filter((h) => h.action === 'deny').slice(0, 25)
  const blocks = hits.filter((h) => h.action === 'block').slice(0, 25)
  return [...denies, ...blocks]
}
