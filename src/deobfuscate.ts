/**
 * 混淆消解引擎（decode-before-scan）。
 *
 * 背景：正则规则引擎只看原文，攻击者可以把 payload 编码/隐藏后绕过：
 *  - Unicode Tags block（U+E0000 区）：隐形编码 ASCII 指令，肉眼与正则均不可见
 *    （CSA Research Note 2026「Hidden Unicode Instruction Injection in AI Agent Skills」）
 *  - 零宽字符 / Hangul filler：拆散关键词（arXiv:2508.14070 实测零宽注入 ASR 54.2%）
 *  - 双向覆盖控制符：Trojan Source（CVE-2021-42574）的 LLM 变体
 *  - Base64 / HTML 实体 / 百分号编码 / 全角同形字 / leetspeak
 *    （F5 DevCentral、SecureLayer7 对 prompt obfuscation 攻击面的分类）
 *
 * 防御思路（业界共识 decode-before-scan）：先把文本归一化折叠成 canonical，
 * 再连同 base64 解码、leetspeak 还原等附加变体一起交给既有检测引擎
 * （rule / secret / ssrf）复扫，使所有引擎的检出率同时提升——
 * 不需要为每种混淆手法单独写一套规则（类比 WAF 的请求归一化层）。
 */

/** 归一化管线中实际发生作用的变换种类 */
export type TransformKind =
  | 'zero-width'    // 零宽字符 / Hangul filler 剥离
  | 'tags-block'    // Unicode Tags block（U+E0000）隐形指令解码
  | 'bidi'          // 双向覆盖控制符剥离（Trojan Source）
  | 'nfkc'          // NFKC 归一化（全角同形字 → 半角）
  | 'html-entity'   // HTML 实体解码（&#x72; → r，迭代到固定点）
  | 'percent'       // 百分号编码解码（%72 → r，迭代到固定点）
  | 'base64'        // base64 候选段解码（附加变体）
  | 'leet'          // leetspeak 还原（附加变体）

export interface NormalizedText {
  /** 折叠后的规范文本（原文无混淆时 === 原文，零成本短路） */
  canonical: string
  /** canonical 相对原文应用过的变换链（仅记录实际产生变化的步骤） */
  transforms: TransformKind[]
}

/** 一个待扫描文本变体：text + 它由哪些变换得到 */
export interface TextVariant {
  text: string
  via: TransformKind[]
}

// ── 隐形字符表（一律用 \u 转义，避免源码里混入不可见字符）──────────
// 零宽类：ZWSP U+200B / ZWNJ U+200C / ZWJ U+200D / WORD JOINER U+2060 /
//        BOM(零宽不换行空格) U+FEFF / 蒙古语元音分隔符 U+180E
// 填充类：HANGUL FILLER U+3164 / 半角 HANGUL FILLER U+FFA0
const INVISIBLE_RE = /[\u200B\u200C\u200D\u2060\uFEFF\u180E\u3164\uFFA0]/g
// 双向覆盖：LRE/RLE/PDF/LRO/RLO U+202A-E、LRI/RLI/FSI/PDI U+2066-9、LRM/RLM U+200E/F
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g
// Unicode Tags block 整区检测（U+E0001-U+E007F）
const TAGS_ANY_RE = /[\uE0001-\uE007F]/

// ── HTML 实体 ───────────────────────────────────────────
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  colon: ':', semi: ';', sol: '/', bsol: '\\', period: '.', comma: ',',
  hyphen: '-', dash: '-', minus: '-', num: '#', excl: '!', quest: '?',
}
const ENTITY_RE = /&(?:#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]{1,10});/g

// ── base64 ──────────────────────────────────────────────
const B64_SEGMENT_RE = /[A-Za-z0-9+/]{24,}={0,2}/g

// ── leetspeak ───────────────────────────────────────────
const LEET_MAP: Record<string, string> = {
  '3': 'e', '@': 'a', '1': 'i', '0': 'o', '$': 's',
  '4': 'a', '5': 's', '7': 't', '!': 'i',
}

/**
 * leetspeak 还原：只处理"字母词内部混数字/符号"的词（1gn0r3 → ignore）。
 * 纯数字 token（v2、12345）与纯字母词都不受影响——误还原只产生一个
 * 额外扫描变体，不命中规则即无副作用。
 */
function applyLeet(s: string): string {
  // 词中含 leet 字符且首尾含字母的混合词，或 leet 字符开头后跟字母的词
  const LEET_WORD_RE = /[A-Za-z][A-Za-z0-9@$!]*[0-9@$!][A-Za-z0-9@$!]*[A-Za-z]|[0-9@$!]+[A-Za-z][A-Za-z0-9@$!]*/g
  if (!LEET_WORD_RE.test(s)) return s
  LEET_WORD_RE.lastIndex = 0
  return s.replace(LEET_WORD_RE, (word) => [...word].map((c) => LEET_MAP[c] ?? c).join(''))
}

/** 单次 HTML 实体解码（数字十/十六进制 + 常用命名子集；控制字符不解出） */
function decodeEntitiesOnce(s: string): string {
  return s.replace(ENTITY_RE, (m) => {
    const body = m.slice(1, -1)
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10)
      // 拒绝控制字符（保留 \t\n\r）与越界码点
      if (!Number.isFinite(cp) || cp > 0x10ffff || (cp < 0x20 && cp !== 9 && cp !== 10 && cp !== 13)) return m
      try { return String.fromCodePoint(cp) } catch { return m }
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? m
  })
}

/** 单次百分号解码（连续 %XX 段，无效 UTF-8 序列保留原文） */
function decodePercentOnce(s: string): string {
  return s.replace(/(?:%[0-9A-Fa-f]{2})+/g, (seq) => {
    try { return decodeURIComponent(seq) } catch { return seq }
  })
}

/** Unicode Tags block 解码：U+E0020-U+E007E → 可见 ASCII，tag 控制符剥除 */
function decodeTagsBlock(s: string): string {
  if (!TAGS_ANY_RE.test(s)) return s
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0)!
    if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000)
    else if (cp === 0xE0001 || cp === 0xE007F) continue   // LANGUAGE TAG / CANCEL TAG
    else out += ch
  }
  return out
}

/** base64 候选段：按长度降序取前 maxSegments 个可解码段（解码结果须为可打印文本） */
export function findBase64Segments(text: string, maxSegments = 2): { segment: string; decoded: string }[] {
  const hits: { segment: string; decoded: string }[] = []
  const segments = (text.match(B64_SEGMENT_RE) ?? []).sort((a, b) => b.length - a.length)
  for (const segment of segments) {
    const buf = Buffer.from(segment, 'base64')
    if (buf.length < 12) continue
    const decoded = buf.toString('utf8')
    // 解码失败（无效 UTF-8 → U+FFFD）或二进制内容（低可打印率）直接放弃——
    // 图片 data URI、加密 blob 等正常数据不会产生变体
    if (decoded.includes('�')) continue
    let printable = 0
    for (const ch of decoded) if (/[ -~\t\n\r]/.test(ch)) printable++
    if (printable / decoded.length < 0.9) continue
    hits.push({ segment, decoded })
    if (hits.length >= maxSegments) break
  }
  return hits
}

/**
 * 归一化：隐形字符剥离 → Tags block 解码 → bidi 剥离 → NFKC →
 * 实体/百分号交替迭代到固定点（≤3 轮，防 &amp;#x72; 双层编码）。
 */
export function normalizeText(input: string): NormalizedText {
  const transforms: TransformKind[] = []
  let s = input

  const step = (kind: TransformKind, fn: (x: string) => string) => {
    const next = fn(s)
    if (next !== s) { transforms.push(kind); s = next }
  }

  step('zero-width', (x) => x.replace(INVISIBLE_RE, ''))
  step('tags-block', decodeTagsBlock)
  step('bidi', (x) => x.replace(BIDI_RE, ''))
  step('nfkc', (x) => x.normalize('NFKC'))

  // 实体与百分号交替迭代到固定点（上限 3 轮）
  for (let round = 0; round < 3; round++) {
    const before = s
    step('html-entity', decodeEntitiesOnce)
    step('percent', decodePercentOnce)
    if (s === before) break
  }

  return { canonical: s, transforms }
}

/**
 * 展开扫描变体集：[原文, canonical, base64 段解码变体(≤2), leet 变体]，上限 5。
 * 原文始终排第一（保证原文命中的行为与未启用本引擎时完全一致）；
 * 纯净文本 canonical === 原文时只剩一个变体，零额外开销。
 */
export function expandTexts(input: string): TextVariant[] {
  const { canonical, transforms } = normalizeText(input)
  const variants: TextVariant[] = [{ text: input, via: [] }]
  if (canonical !== input) variants.push({ text: canonical, via: transforms })

  for (const { segment, decoded } of findBase64Segments(canonical)) {
    if (decoded === canonical) continue
    variants.push({
      text: canonical.split(segment).join(decoded),
      via: transforms.includes('base64') ? transforms : [...transforms, 'base64'],
    })
  }

  const leeted = applyLeet(canonical)
  if (leeted !== canonical) {
    variants.push({ text: leeted, via: [...transforms, 'leet'] })
  }

  return variants.slice(0, 5)
}

/** 变换种类的中文名（审计展示用） */
export const TRANSFORM_LABELS: Record<TransformKind, string> = {
  'zero-width': '零宽/填充字符',
  'tags-block': 'Unicode Tags 隐形指令',
  bidi: '双向覆盖控制符',
  nfkc: '全角/兼容字符归一化',
  'html-entity': 'HTML 实体编码',
  percent: '百分号编码',
  base64: 'Base64 编码',
  leet: 'Leetspeak 混淆',
}
