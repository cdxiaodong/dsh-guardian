/**
 * 攻击记忆引擎（engine-13）：自学习攻击向量库。
 *
 * 灵感来自 Rebuff 的 self-hardening 架构（把历史攻击写入向量库，相似攻击再现即报警），
 * 但去掉外部 LLM 与向量库依赖，改为确定性本地算法：
 *   - 归一化指纹（sha256）：把 IP / URL / 路径 / 数字 / UUID / 长 hex / 长 base64 等
 *     易变要素折叠为占位符后哈希 —— 换 IP 换路径换时间的"重复攻击"直接同指纹
 *   - token 集 Jaccard 相似度：词序无关的结构相似 —— 改写措辞的"变种攻击"按阈值捕获
 *   - 磁盘持久化 + 审计日志自举：重启后记忆仍在，历史审计日志即攻击语料库
 *   - 人工批准补偿：被用户 approve 放行的操作不进入（或被遗忘出）记忆，避免"批一次、永远拦"
 */
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { createHash } from 'node:crypto'

/** 一条攻击记忆（归一化后的攻击指纹） */
export interface AttackRecord {
  /** 宽松指纹（sha256 前 16 位）：记忆去重合并的键 */
  fp: string
  /** 严格指纹（sha256 前 16 位）：完全重复攻击的判定键 */
  strictFp: string
  /** 归一化后的去重 token 集（供 Jaccard 比对） */
  tokens: string[]
  /** 首次记住该攻击的时间（ISO） */
  ts: string
  /** 命中的原始规则 ID（MEMORY-* 表示由记忆引擎自身的变种命中学习而来） */
  ruleId: string
  /** 原始处置级别：deny 级攻击的精确重复仍 deny；block 级仍走人工确认 */
  severity: 'deny' | 'block'
  tool?: string
  reason?: string
}

/** 记忆命中结果 */
export interface MemoryHit {
  kind: 'exact' | 'similar'
  /** 相似度 0~1；exact 恒为 1 */
  similarity: number
  record: AttackRecord
}

/**
 * 宽松归一化（折叠 URL host 与路径）：同一攻击模板换目标/换路径后收敛到同一形态。
 * 用于"同形状"判定（similar 级）与记忆去重合并。
 * 顺序敏感：UUID → URL(先于 IP，让 IP 型 URL 整体折叠) → IP → 长 hex → 长 base64 → 路径 → 数字 → 空白。
 */
export function normalizePayload(text: string): string {
  return strictNormalize(text)
    // 带协议的 URL 折叠 host（含已被严格归一化折叠成 <ip>/<hex> 的 host）+ 端口
    .replace(/\bhttps?:\/\/(?:<ip>|<hex>|<b64>|[a-z0-9.-]+)(:<num>)?/g, '<url>')
    // Unix 路径（至少一段 /xxx）：/etc/passwd、~/.ssh/id_rsa、/home/u/a.ts
    .replace(/(?:~|\.{1,2})?(?:\/[\w.-]+){1,}/g, '<path>')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * 严格归一化：只折叠真正易变的原子要素（UUID/IP/长 hex/长 base64/裸数字/大小写/空白），
 * 保留 URL 与路径原样 —— 严格指纹一致才算"精确重复攻击"（deny 级语义）。
 */
export function strictNormalize(text: string): string {
  return text
    .toLowerCase()
    // UUID
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '<uuid>')
    // IPv4
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '<ip>')
    // 长 hex 串（时间戳摘要/哈希等）
    .replace(/\b[0-9a-f]{16,}\b/g, '<hex>')
    // 长 base64 串
    .replace(/\b[a-z0-9+/]{24,}={0,2}\b/g, '<b64>')
    // 裸数字（端口号、行号、日期数字等）
    .replace(/\b\d+\b/g, '<num>')
    .replace(/\s+/g, ' ')
    .trim()
}

/** 宽松指纹（sha256 前 16 位）：记忆去重合并的键 */
export function fingerprint(text: string): string {
  return createHash('sha256').update(normalizePayload(text)).digest('hex').slice(0, 16)
}

/** 严格指纹（sha256 前 16 位）：完全重复攻击的判定键 */
export function strictFingerprint(text: string): string {
  return createHash('sha256').update(strictNormalize(text)).digest('hex').slice(0, 16)
}

/** 归一化后按空白切分并去重的 token 集 */
export function tokenSet(text: string): string[] {
  return [...new Set(normalizePayload(text).split(/\s+/).filter(Boolean))]
}

/** Jaccard 相似度：|A∩B| / |A∪B|；任一侧为空返回 0 */
export function jaccard(a: string[], b: string[]): number {
  if (!a.length || !b.length) return 0
  const sa = new Set(a)
  const sb = new Set(b)
  let inter = 0
  for (const t of sa) if (sb.has(t)) inter++
  return inter / (sa.size + sb.size - inter)
}

export namespace AttackMemory {
  export interface Config {
    /** 记忆文件路径；设为 '' 关闭持久化（仅内存态）。默认 ~/.dsh-guardian.memory.json */
    file?: string
    /** 变种判定阈值 0~1，默认 0.55 */
    threshold?: number
    /** 记忆容量上限（LRU 淘汰），默认 500 */
    maxRecords?: number
    /** token 数低于该值的文本只做精确指纹匹配（避免 "rm -rf <path>" 之类短命令误报），默认 4 */
    minTokens?: number
  }
}

/** 攻击记忆库：remember 落库，lookup 查询（精确指纹优先，其次相似度） */
export class AttackMemory {
  /** fp → record；Map 插入序即 LRU 序（重新 remember 会刷新到末尾） */
  private records = new Map<string, AttackRecord>()
  private readonly file: string
  readonly threshold: number
  private readonly maxRecords: number
  private readonly minTokens: number

  constructor(config: AttackMemory.Config = {}) {
    this.file = config.file ?? path.join(os.homedir(), '.dsh-guardian.memory.json')
    this.threshold = config.threshold ?? 0.55
    this.maxRecords = config.maxRecords ?? 500
    this.minTokens = config.minTokens ?? 4
  }

  /** 从磁盘载入记忆，返回载入条数（文件不存在/损坏时返回 0，不抛错） */
  load(): number {
    if (!this.file || !fs.existsSync(this.file)) return 0
    try {
      const arr = JSON.parse(fs.readFileSync(this.file, 'utf8'))
      if (!Array.isArray(arr)) return 0
      for (const r of arr) {
        if (r && typeof r.fp === 'string' && typeof r.strictFp === 'string' && Array.isArray(r.tokens)) {
          this.records.set(r.fp, r)
        }
      }
    } catch { /* 损坏文件按空处理 */ }
    return this.records.size
  }

  size(): number { return this.records.size }

  clear() {
    this.records.clear()
    this.persist()
  }

  /** 遗忘指定指纹（用户人工批准了记忆命中的攻击时调用） */
  forget(fp: string) {
    if (this.records.delete(fp)) this.persist()
  }

  /**
   * 记住一次攻击。宽松指纹相同视为同一条记忆（合并：刷新时间与 LRU 位、severity 就高不就低）。
   * 返回落库记录；文本归一化后无 token 时返回 null。
   */
  remember(text: string, meta: { ruleId: string; severity: 'deny' | 'block'; tool?: string; reason?: string }): AttackRecord | null {
    const tokens = tokenSet(text)
    if (!tokens.length) return null
    const fp = fingerprint(text)
    const strictFp = strictFingerprint(text)
    const prev = this.records.get(fp)
    if (prev) {
      this.records.delete(fp)
      prev.ts = new Date().toISOString()
      if (meta.severity === 'deny') prev.severity = 'deny'   // 就高：曾判 deny 则永远 deny
      this.records.set(fp, prev)
      this.persist()
      return prev
    }
    const rec: AttackRecord = {
      fp, strictFp, tokens,
      ts: new Date().toISOString(),
      ruleId: meta.ruleId,
      severity: meta.severity,
      ...(meta.tool ? { tool: meta.tool } : {}),
      ...(meta.reason ? { reason: meta.reason } : {}),
    }
    this.records.set(fp, rec)
    // LRU 淘汰：超出容量删最旧（Map 首键）
    while (this.records.size > this.maxRecords) {
      const oldest = this.records.keys().next().value as string
      this.records.delete(oldest)
    }
    this.persist()
    return rec
  }

  /**
   * 查询文本是否命中记忆（严格 → 宽松 → 相似度，逐级放松）：
   *  - exact：严格指纹一致（仅 UUID/IP/hex/base64/数字/大小写/空白差异）→ 完全重复攻击
   *  - similar(形状)：宽松指纹一致（换了路径/URL host 的同形状攻击）
   *  - similar(措辞)：token Jaccard ≥ threshold（改写措辞的变种）
   * token 过少的文本跳过宽松与相似度两级（避免 "rm -rf <path>" 类短命令泛化误报）。
   * 未命中返回 null。
   */
  lookup(text: string): MemoryHit | null {
    const sfp = strictFingerprint(text)
    for (const rec of this.records.values()) {
      if (rec.strictFp === sfp) return { kind: 'exact', similarity: 1, record: rec }
    }

    const tokens = tokenSet(text)
    if (tokens.length < this.minTokens) return null
    const loose = this.records.get(fingerprint(text))
    if (loose && loose.strictFp !== sfp) {
      return { kind: 'similar', similarity: 1, record: loose }
    }

    let best: AttackRecord | undefined
    let bestSim = 0
    for (const rec of this.records.values()) {
      const sim = jaccard(tokens, rec.tokens)
      if (sim > bestSim) { bestSim = sim; best = rec }
    }
    if (best && bestSim >= this.threshold) {
      return { kind: 'similar', similarity: bestSim, record: best }
    }
    return null
  }

  private persist() {
    if (!this.file) return
    try {
      fs.writeFileSync(this.file, JSON.stringify([...this.records.values()], null, 2))
    } catch { /* 持久化失败不阻断主流程 */ }
  }
}
