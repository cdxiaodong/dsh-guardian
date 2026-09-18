/**
 * 工具结果消毒引擎（Tool-Result Sanitizer）
 *
 * 威胁模型：间接提示注入的主载体不是用户输入，而是工具返回值——
 * 网页正文、文件内容、命令输出在写入模型上下文前不受任何检查，
 * 恶意指令可借数据通道进入上下文（Invariant Labs Tool Poisoning /
 * arXiv:2606.20922 所述"传统注入发生在工具输出与外部内容中"）。
 *
 * 与 guardian/check（入参侧）互补：入参侧扫"Agent 想做什么"，
 * 本引擎扫"世界塞给 Agent 什么"。借鉴 CaMeL（DeepMind 2025）的
 * 通道分离思想：工具结果=数据通道，数据中出现指令即违规，
 * 因此规则比输入侧更严；处置借鉴 llm-guard Output Scanner 的
 * sanitize 模式——不全拦（正文往往是用户要的），就地剥除指令段落，
 * 数据继续流动（消毒的误报成本只是一行文本，远低于拦截整个结果）。
 *
 * 独有检测：延迟引信（deferred trigger）——注入不要求立即执行，
 * 而是埋下"当用户下次问起 X 时做 Y"的休眠条件（TRP-003），
 * 今日读入、明日触发，绕过针对即时指令的防线。
 */

export interface TRPRule {
  id: string
  pattern: RegExp
  reason: string
  /** redact=就地剥除（数据继续流动）；deny=拒绝该结果 */
  action: 'redact' | 'deny'
  weight: number
}

/** 被移除内容的审计条目 */
export interface RemovedSpan {
  ruleId: string
  reason: string
  /** 被移除内容的预览（隐形载体为显影后的明文） */
  preview: string
}

export interface ResultVerdict {
  /** false=deny 级命中，宿主不应把该结果写入模型上下文 */
  safe: boolean
  ruleId?: string
  reason?: string
  /** safe 时：消毒后的文本（无命中即原文） */
  sanitized: string
  removed: RemovedSpan[]
}

/**
 * 结果侧规则集。与输入侧 PI-* 分离：数据通道里出现这些形态
 * 几乎必为注入（合法数据不携带对 Agent 的指令），全部从严。
 * 正则不带 /g 标志（逐行扫描时逐次 test，避免 lastIndex 状态污染）。
 */
export const TRP_RULES: TRPRule[] = [
  // TRP-001 指令覆盖注入：数据里指挥模型抛弃既有指令
  { id: 'TRP-001', action: 'redact', weight: 0.9,
    pattern: /\b(ignore|disregard|forget|override|bypass|neglect|stop\s+following)\b[^.\n]{0,50}\b(previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,40}\b(instruction|prompt|rule|direction|message|constraint|guardrail|policy|system)s?\b/i,
    reason: '工具结果中的指令覆盖注入' },

  // TRP-002 系统角色伪装：伪造特权消息头 / chat 模板 token / 角色切换
  { id: 'TRP-002', action: 'redact', weight: 0.9,
    pattern: /\[(system|assistant|developer|operator|admin|installed|important)\]|(?<!\w)(system|developer)\s+(prompt|message|instruction)s?\s*:|<\|(im_start|im_end|system|endoftext)\|>|\b(you\s+are\s+now|from\s+now\s+on)\s+(a|an|the)?\s*\w{0,20}\b(unrestricted|developer|admin|root|dan|jailbroken|uncensored|different)\b/i,
    reason: '工具结果中的系统角色伪装' },

  // TRP-003 延迟引信：休眠条件触发——"当用户问到 X 时做 Y"、跨会话触发
  { id: 'TRP-003', action: 'redact', weight: 0.85,
    pattern: /\b(when|if|once|until|after)\b[^.\n]{0,50}\b(user|human|they|victim|target)\b[^.\n]{0,60}\b(asks?|says?|requests?|mentions?|queries?|types?|instructs?)\b[^.\n]{0,80}\b(respond|reply|answer|say|tell|act|execute|run|send|delete|install|reveal)\b|\b(in|during|at)\s+the\s+(next|following|later)\s+(session|conversation|turn|task|run)\b[^.\n]{0,80}\b(respond|reply|act|execute|send|delete|reveal)\b|\b(sleep|stay|remain)\b[^.\n]{0,30}\b(dormant|silent|inactive|hidden)\b[^.\n]{0,50}\b(until|until\s+the)\b/i,
    reason: '工具结果中的延迟引信（休眠条件触发指令）' },

  // TRP-004 隐形载体：HTML 注释藏指令（网页经典载体）
  { id: 'TRP-004', action: 'redact', weight: 0.8,
    pattern: /<!--[^>]{0,400}?[^.\n]{0,60}\b(ignore|disregard|forget|instructions?|system\s+prompt|you\s+are|act\s+as|send|exfiltrate)\b[^>]{0,400}?-->/i,
    reason: 'HTML 注释中隐藏的注入指令' },

  // TRP-005 结果内外传指使：教唆把上下文/数据发往外部端点
  { id: 'TRP-005', action: 'deny', weight: 1.0,
    pattern: /\b(send|post|upload|transmit|exfiltrate|email|deliver|forward)\b[^.\n]{0,60}\b(this|the|all|these|that)\b[^.\n]{0,30}\b(data|content|file|credentials?|tokens?|keys?|secrets?|information|conversation|history|context)\b[^.\n]{0,80}\b(to|at|via|on|using)\b[^.\n]{0,60}(\bhttps?:\/\/|\b[a-z0-9][a-z0-9-]{1,30}\.(com|net|io|xyz|org|me|dev|cn|cc|top)\b|webhook|discord|telegram|pastebin)/i,
    reason: '工具结果教唆将数据外传至外部端点' },
]

/** Unicode Tags 区（U+E0000–U+E007F）显影为可读明文（arXiv:2503.24652 载体） */
export function revealTagChars(text: string): string {
  let out = ''
  for (const ch of text) {
    const c = ch.codePointAt(0)!
    if (c >= 0xE0000 && c <= 0xE007F) out += String.fromCharCode(c - 0xE0000)
  }
  return out
}

/** 零宽字符与双向文本控制符（视觉伪装载体） */
const INVISIBLE_CHARS = /[​-‏‪-‮⁠⁦-⁩﻿]/gu
/** Unicode Tags 区字符（含空格终止符 U+E0020）；星面码点必须用 /u 码点转义，否则 0 会被解析成 +"0" */
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu

/** 单行内命中区间向两侧扩展到的安全边界（字符） */
const LINE_REDACT_CONTEXT = 160
/** 超过该长度的行不做整行替换，改用窗口替换以保护合法长文 */
const WHOLE_LINE_MAX = 400

interface RedactRange {
  start: number
  end: number
  rule: TRPRule
  preview: string
}

/**
 * 核心消毒：扫描工具结果文本，deny 级命中返回 safe:false；
 * redact 级命中就地剥除指令段落（短行整行替换、长行窗口替换，
 * 避免误伤合法长文），数据继续流动。
 */
export function sanitizeToolResult(text: string): ResultVerdict {
  const removed: RemovedSpan[] = []
  let working = text

  // ── 第一遍：字符级隐形载体。不可见字符直接删除（对合法内容无损），
  //    Tags 区显影后入审计，让"隐形注入"留下可读证据。
  if (TAG_CHARS.test(working)) {
    TAG_CHARS.lastIndex = 0
    const revealed = revealTagChars(working)
    if (revealed.trim()) {
      removed.push({ ruleId: 'TRP-006', reason: 'Unicode Tags 区隐形载体已剥离（显影见 preview）', preview: revealed.slice(0, 200) })
    }
    working = working.replace(TAG_CHARS, '')
  }
  TAG_CHARS.lastIndex = 0
  if (INVISIBLE_CHARS.test(working)) {
    INVISIBLE_CHARS.lastIndex = 0
    working = working.replace(INVISIBLE_CHARS, '')
    removed.push({ ruleId: 'TRP-006', reason: '零宽/双向文本控制符已剥离', preview: '(不可见字符)' })
  }
  INVISIBLE_CHARS.lastIndex = 0

  // ── 第二遍：逐行规则扫描。deny 优先短路；redact 收集区间后统一替换。
  const lines = working.split('\n')
  const outLines: string[] = []
  for (const line of lines) {
    const ranges: RedactRange[] = []
    let denyHit: TRPRule | null = null
    for (const rule of TRP_RULES) {
      rule.pattern.lastIndex = 0
      const m = rule.pattern.exec(line)
      if (!m) continue
      if (rule.action === 'deny') { denyHit = rule; break }
      const start = Math.max(0, Math.min(m.index, Math.max(0, m.index - LINE_REDACT_CONTEXT)))
      const end = line.length <= WHOLE_LINE_MAX ? line.length : Math.min(line.length, m.index + m[0].length + LINE_REDACT_CONTEXT)
      ranges.push({ start, end, rule, preview: line.slice(start, Math.min(end, start + 200)) })
    }
    if (denyHit) {
      return { safe: false, ruleId: denyHit.id, reason: denyHit.reason, sanitized: '', removed: [...removed, { ruleId: denyHit.id, reason: denyHit.reason, preview: line.slice(0, 200) }] }
    }
    if (!ranges.length) { outLines.push(line); continue }
    // 合并重叠区间后替换为占位标记
    ranges.sort((a, b) => a.start - b.start)
    let merged: RedactRange[] = []
    for (const r of ranges) {
      const last = merged[merged.length - 1]
      if (last && r.start <= last.end) {
        last.end = Math.max(last.end, r.end)
        last.preview = line.slice(last.start, Math.min(last.end, last.start + 200))
      } else {
        merged.push({ ...r })
      }
    }
    let out = ''
    let cursor = 0
    for (const r of merged) {
      out += line.slice(cursor, r.start)
      out += `[dsh-guardian:已移除疑似注入内容 ${r.rule.id}]`
      cursor = r.end
      removed.push({ ruleId: r.rule.id, reason: r.rule.reason, preview: r.preview })
    }
    out += line.slice(cursor)
    outLines.push(out)
  }

  return { safe: true, sanitized: outLines.join('\n'), removed }
}
