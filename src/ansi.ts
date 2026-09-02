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
  id: string
  pattern: RegExp
  description: string
  /** deny=直接拒绝；block=人工确认；log=仅记录 */
  action: 'block' | 'deny' | 'log'
  /** 风险权重 0~1（供风险评分信号使用） */
  weight: number
}

export interface AnsiHit {
  ruleId: string
  description: string
  action: AnsiRule['action']
  /** 命中的原始序列（审计证据，写入审计前会被可见化） */
  match: string
  /** 在原文中的起始位置；-1 表示来自 JSON 字面量解码后的文本 */
  index: number
}

/**
 * 危险转义序列规则集（ID 前缀 ANSI-）。
 * 安全 SGR 色码（颜色/粗体/下划线等）不在此列，由 isSafeSgr 单独放行。
 */
export const ANSI_RULES: AnsiRule[] = [
  // 感知不对称：对人隐藏、对 LLM 可读 —— 正常输出没有任何理由使用
  { id: 'ANSI-001', description: 'SGR 8 隐藏文本（conceal，人眼不可见 LLM 可读）', pattern: /\x1b\[(?:\d+;)*8(?:;\d*)*m/, action: 'deny', weight: 0.95 },
  // C1 单字节控制符（U+009B=CSI 等）：与 ESC 序列等价，只查 \x1b 的过滤器会被绕过
  { id: 'ANSI-002', description: 'C1 单字节控制符（U+0085-U+009D/U+009F，转义绕过形式）', pattern: /[\x85-\x9d\x9f]/, action: 'deny', weight: 0.8 },
  // 覆盖已有内容：时间差欺骗（先显示无害内容，审核后擦除重写）
  { id: 'ANSI-003', description: '行擦除序列（EL，擦除本行内容用于覆盖重写）', pattern: /\x1b\[(?:0?|2)K/, action: 'block', weight: 0.7 },
  { id: 'ANSI-004', description: '光标上移（line-jumping，覆盖之前显示的内容）', pattern: /\x1b\[\d*A/, action: 'block', weight: 0.75 },
  { id: 'ANSI-005', description: '清屏/光标归位（ED/CUP，抹掉屏幕历史输出）', pattern: /\x1b\[(?:2|3)J|\x1b\[H/, action: 'block', weight: 0.7 },
  // 与终端双向通信：伪装链接 / 改标题钓鱼 / 探测回传
  { id: 'ANSI-006', description: 'OSC 8 伪装超链接（显示文本与实际地址不一致）', pattern: /\x1b\]8;[^\x07\x1b]*(?:\x07|\x1b\\)/, action: 'block', weight: 0.8 },
  { id: 'ANSI-007', description: 'OSC 终端标题修改（伪装窗口/进程名钓鱼）', pattern: /\x1b\](?:0|1|2);/, action: 'block', weight: 0.6 },
  { id: 'ANSI-008', description: '终端状态探测（DSR/DA，诱导终端回传数据）', pattern: /\x1b\[\??(?:6n|c)/, action: 'block', weight: 0.7 },
  // 字符集切换：内容显示为替代图形，人眼与 LLM 感知再次分裂
  { id: 'ANSI-009', description: '备选字符集切换（SO/SI，G0/G1 字符集替换）', pattern: /[\x0e\x0f]/, action: 'block', weight: 0.6 },
  // 回车不换行：覆盖本行先前内容（\r\n 正常换行不含此模式）
  { id: 'ANSI-010', description: '孤立回车 CR（不换行，配合输出覆盖本行内容）', pattern: /\r(?!\n)/, action: 'log', weight: 0.4 },
]

/** 完整 ANSI 转义序列（CSI/OSC/独立 ESC），strip 净化与 token 化共用 */
const CSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/
const OSC = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/
const ESC = /\x1b[@-Z\\-_]/
const ANY_ESCAPE = new RegExp(`${CSI.source}|${OSC.source}|${ESC.source}`, 'g')
/** SGR 序列（含参数），用于解析 conceal/reveal 状态与安全色码识别 */
const SGR = /\x1b\[([0-9;]*)m/g
/** JSON.stringify 会把控制字符转成 \uXXXX 字面量；宿主 UI 一旦 unescape 渲染，攻击即成立 */
const ESCAPE_LITERAL = /\\u00(1b|07|0e|0f|85|8d|9b|9c|9d|9f)|\\x1b|\\x9[b-f]/gi

/** SGR 参数中属于「安全渲染属性」的集合：粗体/斜体/下划线/闪烁/反色/删除线/默认色等 */
const SAFE_SGR_PARAMS = new Set(['0', '1', '2', '3', '4', '5', '7', '9', '21', '22', '23', '24', '25', '27', '29', '39', '49', '53', '54', '59'])

/** 判断 SGR 序列是否为安全色码（不含 conceal=8 与未知控制属性） */
function isSafeSgr(params: string): boolean {
  return params.split(';').every((p) => {
    if (p === '') return true // 空参数等价于 0（重置）
    const n = Number(p)
    if (SAFE_SGR_PARAMS.has(p)) return true
    // 256 色 / 24 位色参数（38;5;n、38;2;r;g;b、48;…）
    if (n === 38 || n === 48 || n === 5 || n === 2) return true
    // 标准/亮色前景背景
    if ((n >= 30 && n <= 37) || (n >= 40 && n <= 47) || (n >= 90 && n <= 107)) return true
    return false
  })
}

export interface ScanAnsiOptions {
  /** 先解码 JSON 字面量（ESC 等）再复扫。guardian/check 集成路径应开启 */
  unescapeLiterals?: boolean
}

/**
 * 扫描文本中的危险终端转义序列，按规则顺序返回全部命中。
 * 安全 SGR 色码（git diff / ls --color 等正常输出）不产生命中。
 */
export function scanAnsi(text: string, opts: ScanAnsiOptions = {}): AnsiHit[] {
  const targets: Array<{ text: string; indexBase: number }> = [{ text, indexBase: 0 }]
  if (opts.unescapeLiterals && ESCAPE_LITERAL.test(text)) {
    ESCAPE_LITERAL.lastIndex = 0
    targets.push({ text: text.replace(ESCAPE_LITERAL, (lit) => {
      const hex = /(?:\\u00|\\x)([0-9a-f]{1,2})$/i.exec(lit)?.[1]
      return hex ? String.fromCharCode(parseInt(hex, 16)) : lit
    }), indexBase: -1 })
  }

  // 预收集安全 SGR 区间：完全落在其中的命中视为误报丢弃
  const safeRanges: Array<[number, number]> = []
  for (const m of text.matchAll(SGR)) {
    if (isSafeSgr(m[1] ?? '')) safeRanges.push([m.index!, m.index! + m[0].length])
  }

  const hits: AnsiHit[] = []
  for (const rule of ANSI_RULES) {
    for (const target of targets) {
      const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g')
      for (const m of target.text.matchAll(re)) {
        const idx = target.indexBase < 0 ? -1 : m.index! + target.indexBase
        if (idx >= 0 && safeRanges.some(([s, e]) => m.index! >= s && m.index! < e)) continue
        hits.push({ ruleId: rule.id, description: rule.description, action: rule.action, match: m[0], index: idx })
      }
    }
  }
  return hits.sort((a, b) => a.index - b.index)
}

export type SanitizeMode = 'escape' | 'strip' | 'redact'

/**
 * 净化文本中的终端转义序列，保证「审核员看到的 = LLM 收到的」。
 *  - escape：控制字符可见化（␛ 等），长度不变、证据保真 —— 审计日志固定用此模式
 *  - strip ：删除所有转义序列，得到终端安全的纯文本
 *  - redact：危险序列替换为 <ANSI:id> 占位，保留可读的攻击证据链
 */
export function sanitizeAnsi(text: string, mode: SanitizeMode = 'escape'): string {
  if (mode === 'strip') {
    return text
      .replace(ANY_ESCAPE, '')
      .replace(/[\x85-\x9d\x9f]/g, '')
      .replace(/[\x00-\x08\x0b\x0c\x0e\x0f]/g, '')
      .replace(/\r(?!\n)/g, '')
  }
  if (mode === 'redact') {
    let out = text
    for (const rule of ANSI_RULES) {
      out = out.replace(new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g'), `<${rule.id}>`)
    }
    return out
  }
  // escape：可见化，长度不变。孤立 CR 可见化，\r\n 中的 CR 保留
  return text
    .replace(/\x1b/g, '␛')
    .replace(/[\x85-\x9d\x9f]/g, (c) => `⍾${c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()}`)
    .replace(/[\x00-\x08\x0b\x0c\x0e\x0f]/g, (c) => `⍾${c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()}`)
    .replace(/\r(?!\n)/g, '␍')
}

export interface RenderReport {
  /** 参与统计的可打印字符数 */
  totalChars: number
  /** conceal 隐藏的字符数（LLM 可读、人眼不可见） */
  hiddenChars: number
  /** 隐藏字符占比 0~1 */
  hiddenRatio: number
  /** 被擦除/覆盖替换掉的字符数 */
  overwrittenChars: number
  /** 触发的一致性异常信号（ANSI-xxx） */
  signals: string[]
  /** hiddenRatio≥0.05 或 overwrittenChars≥24 时为 true */
  suspicious: boolean
}

/**
 * 渲染一致性审计（简化终端模型）：模拟文本在终端渲染后，量化
 * 「LLM 收到的原文」与「人眼最终看到的」之间的差异。
 * 这是给人工审核 UI 的核心信号：suspicious=true 意味着你看到的可能不是全部。
 */
export function renderConsistency(text: string): RenderReport {
  const TOKEN = new RegExp(`${CSI.source}|${OSC.source}|${ESC.source}|\\r|\\n|[^\\x1b\\r\\n]+`, 'g')
  let total = 0
  let hidden = 0
  let overwritten = 0
  let concealed = false
  const signals = new Set<string>()
  const lines: string[] = ['']
  let cur = 0
  let col = 0

  for (const m of text.matchAll(TOKEN)) {
    const tok = m[0]
    if (tok === '\n') { cur++; col = 0; lines[cur] ??= ''; continue }
    if (tok === '\r') { col = 0; continue }              // 回行首，后续输出覆盖本行
    if (!tok.startsWith('\x1b')) {                        // 普通文本
      const line = lines[cur] ?? ''
      if (col < line.length) overwritten += Math.min(tok.length, line.length - col) // 覆盖已有内容
      lines[cur] = line.slice(0, col) + tok + line.slice(col + tok.length)
      col += tok.length
      total += tok.length
      if (concealed) hidden += tok.length
      continue
    }
    const sgr = /^\x1b\[([0-9;]*)m$/.exec(tok)
    if (sgr) {
      const params = (sgr[1] ?? '').split(';').filter(Boolean)
      if (params.includes('8')) { concealed = true; signals.add('ANSI-001') }
      else if (params.includes('28') || params.includes('0')) concealed = false
      continue
    }
    if (/^\x1b\[(?:0?|2)K$/.test(tok)) {                  // 行擦除
      overwritten += (lines[cur] ?? '').length
      lines[cur] = ''; col = 0
      signals.add('ANSI-003')
      continue
    }
    const cuu = /^\x1b\[(\d*)A$/.exec(tok)                // 光标上移：之后写入覆盖旧行
    if (cuu) {
      cur = Math.max(0, cur - (Number(cuu[1] || '1')))
      col = 0
      lines[cur] ??= ''
      signals.add('ANSI-004')
      continue
    }
  }
  const hiddenRatio = total === 0 ? 0 : hidden / total
  const suspicious = hiddenRatio >= 0.05 || overwritten >= 24
  return { totalChars: total, hiddenChars: hidden, hiddenRatio, overwrittenChars: overwritten, signals: [...signals], suspicious }
}
