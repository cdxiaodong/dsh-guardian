/**
 * Engine 40: Relay Provenance Guard（跨会话接力污点引擎）
 *
 * 缝合 SkillRelayGuard（arXiv:2610.13227，2026-10-09，SkillRelayBench 作者）：
 * agent skill 在执行中产出/修改的持久化工件（文件、配置、缓存）会被后续会话
 * 的其他 skill 复用，恶意效果经由持久化工件在会话之间"接力"传播。论文刻画
 * 三种攻击机制：
 *   IP  Instruction Propagation     恶意指令写进工件 → 后续会话当作指令执行
 *   DBV Data Boundary Violation     跨信任边界的数据搬运（A 的私有数据被 B 读走）
 *   EP  Evidence Poisoning          污染"证据"工件（被审计/验证器引用的数据源）
 *
 * SkillRelayGuard 的防御是「恢复工件来源上下文 + 执行前咨询审查」；本引擎把它
 * 确定性化为**污点传播追踪**：
 *
 *   ingest（标记来源） → persist（污染判定） → relay（污染工件再消费） → revoke（复核）
 *
 * 四条规则（与现有引擎的分工：其他引擎盯单次调用的 payload 内容，本引擎盯
 * "内容在会话间带来源流动"——同一段文本在会话 1 是注入、在会话 2 被当技能
 * 指令消费，单会话视角永远看不见这条链）：
 *   RLY-001 deny  污染标记出口——带 PI 命中史的文本被写入持久化目标
 *   RLY-002 block 污染工件消费——读取已被标记的工件（新会话接力起点）
 *   RLY-003 block DBV——跨边界搬运：origin ≠ persist 会话的数据流
 *   RLY-004 deny  EP——伪装成"验证结果/证据"的工件包含未复核污点
 *
 * 审计通道 engine='relay'。所有状态在内存（影子库持久化是另一个 PR 的活）。
 */

import { DEFAULT_RULES, type Rule } from './rules.js'

/** 来源信任级别：ingest 时的初始标记 */
export type ProvenanceClass =
  | 'trusted'    // 宿主注入的系统指令 / 内置规则
  | 'user'       // 用户亲自输入
  | 'external'   // 外部世界内容：网页/工具结果/文件（注入的主入口）
  | 'agent'      // agent 自产内容（无命中史时视为干净）

/** 污点条目：一段文本的传播记录 */
export interface TaintRecord {
  /** 污点体（FNV-1a 64bit 内容指纹，避免存全文） */
  fp: string
  /** 源头信任级别 */
  origin: ProvenanceClass
  /** 首次标记的会话 */
  originSession: string
  /** 被写出的会话（RLY-003 用） */
  persistSessions: string[]
  /** 标记时刻携带的 PI 命中规则 id */
  piRules: string[]
  /** 首次标记时间戳（ms，注入时钟） */
  firstSeen: number
}

/** 污染工件注册表条目（RLY-002/004 消费侧） */
export interface ArtifactRecord {
  /** 工件路径（规范化后作 key） */
  path: string
  fp: string
  taints: string[]
  session: string
  ts: number
}

export interface RelayVerdict {
  intercepted: boolean
  ruleId: 'RLY-001' | 'RLY-002' | 'RLY-003' | 'RLY-004' | null
  action: 'deny' | 'block' | null
  reason?: string
  /** 触发判定的污点指纹列表 */
  taints?: string[]
}

export interface RelayConfig {
  enabled?: boolean
  /** 污点指纹上限（防内存膨胀；默认 4096，LRU 淘汰） */
  maxTaints?: number
  /** 污点有效期（ms；默认 7 天） */
  ttl?: number
  now?: () => number
}

// ── PI 判定：复用主规则库的注入类规则（零新正则，规则演化引擎管它）──
const PI_CATEGORIES = new Set(['prompt-injection', 'tool-poisoning', 'injection'])

/** 注入类规则（eval 惰性缓存，避免 import 环） */
function piRules(): Rule[] {
  return DEFAULT_RULES.filter((r) => r.category && PI_CATEGORIES.has(r.category))
}

// ── FNV-1a 64bit 指纹（与 egress-escrow 同款，一致性）──────────
export function fnv1a64(text: string): string {
  let h = 0xcbf29ce484222325n
  for (let i = 0; i < text.length; i++) {
    h ^= BigInt(text.charCodeAt(i) & 0xff)
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn
  }
  return h.toString(16)
}

/** 文本 → 指纹（空串/undefined 指纹为 null，不追踪） */
function taintFp(text: unknown): string | null {
  if (typeof text !== 'string' || text.length < 8) return null
  return fnv1a64(text)
}

/** 归一化工件路径（去引号/展开 ~）作注册表 key */
export function normalizeArtifactPath(p: string): string {
  return p.replace(/^['"]|['"]$/g, '').replace(/^~/, '/home/u')
}

// ── 证据伪装面（RLY-004）：被审计/验证器信任的数据源文件名模式 ─────
const EVIDENCE_PATH_RE = [/result/i, /evidence/i, /verdict/i, /verified/i, /report/i]
const EVIDENCE_HEAD_RE = [
  /^###?\s*(?:test|scan|check|verif)[a-z]*\s*(?:report|result|summary)/i,
  /\bVERIFIED\b|\bPASSED\b(?=.{0,40}(?:scan|check|test))/i,
]

export class RelayTracker {
  private taints = new Map<string, TaintRecord>()
  private artifacts = new Map<string, ArtifactRecord>()
  private maxTaints: number
  private ttl: number
  private now: () => number

  constructor(cfg: RelayConfig = {}) {
    this.maxTaints = cfg.maxTaints ?? 4096
    this.ttl = cfg.ttl ?? 7 * 24 * 3600 * 1000
    this.now = cfg.now ?? (() => Date.now())
  }

  private sweep() {
    const t = this.now()
    for (const [fp, rec] of this.taints) {
      if (t - rec.firstSeen > this.ttl) this.taints.delete(fp)
    }
  }

  /**
   * ingest：宿主把外部内容喂给 agent 前登记来源。
   * PI 命中的文本自动获得 external 级污点（DBV/RLY-003 的 origin）。
   * @returns 该文本的污点指纹（null=不追踪）
   */
  ingest(text: string, origin: ProvenanceClass, session: string): string | null {
    if (origin === 'trusted') return null    // 系统注入的内容不追踪
    const fp = taintFp(text)
    if (!fp) return null
    this.sweep()
    const existing = this.taints.get(fp)
    if (existing) {
      // 已有污点：合并 PI 规则、扩大 persist 会话集
      const rules = piHitIds(text)
      for (const r of rules) if (!existing.piRules.includes(r)) existing.piRules.push(r)
      return fp
    }
    const rules = piHitIds(text)
    this.taints.set(fp, {
      fp, origin, originSession: session, persistSessions: [],
      piRules: rules, firstSeen: this.now(),
    })
    this.evictIfNeeded()
    return fp
  }

  private evictIfNeeded() {
    if (this.taints.size <= this.maxTaints) return
    // LRU：删 firstSeen 最老的
    let oldestKey: string | null = null
    let oldest = Infinity
    for (const [fp, rec] of this.taints) {
      if (rec.firstSeen < oldest) { oldest = rec.firstSeen; oldestKey = fp }
    }
    if (oldestKey) this.taints.delete(oldestKey)
  }

  /** 查询某文本的污点（无则 null） */
  taintOf(text: string): TaintRecord | null {
    this.sweep()
    const fp = taintFp(text)
    if (!fp) return null
    return this.taints.get(fp) ?? null
  }

  taintByFp(fp: string): TaintRecord | null {
    return this.taints.get(fp) ?? null
  }

  /**
   * persist 判定：把文本写入 artifactPath（write 语义工具调用）。
   * - RLY-001：污点带 PI 命中史 → deny
   * - RLY-003：origin 会话 ≠ 当前会话 → block（DBV 跨边界）
   * - 干净文本 → 落注册表（后续 RLY-002 消费侧判定的基准）
   */
  persist(session: string, text: string, artifactPath: string): RelayVerdict {
    const fp = taintFp(text) ?? ''
    const rec = fp ? this.taints.get(fp) : undefined
    if (rec && rec.piRules.length) {
      this.registerArtifact(session, fp, artifactPath, rec)
      return {
        intercepted: true, ruleId: 'RLY-001', action: 'deny',
        reason: `跨会话接力污点：带提示注入命中史（${rec.piRules.join(',')}，源于 ${rec.origin}/${rec.originSession}）的文本被写入持久化工件 ${artifactPath}`,
        taints: [fp],
      }
    }
    if (rec && rec.originSession !== session) {
      this.registerArtifact(session, fp, artifactPath, rec)
      return {
        intercepted: true, ruleId: 'RLY-003', action: 'block',
        reason: `数据边界违规：会话 ${rec.originSession} 的 ${rec.origin} 内容被会话 ${session} 写入工件 ${artifactPath}`,
        taints: [fp],
      }
    }
    // 干净文本：登记污点 + 工件（agent 产出落盘 = 可接力面，标记为 agent 级）
    if (fp) {
      this.taints.set(fp, {
        fp, origin: 'agent', originSession: session,
        persistSessions: [session], piRules: [], firstSeen: this.now(),
      })
      this.registerArtifact(session, fp, artifactPath, this.taints.get(fp)!)
    }
    return { intercepted: false, ruleId: null, action: null }
  }

  /**
   * relay 判定：从 artifactPath 读取内容（read 语义工具调用）。
   * - RLY-002：读取已标记工件 → block（新会话接力起点，人工确认）
   * - RLY-004：工件路径/内容伪装成证据类 → deny
   */
  relay(session: string, artifactPath: string): RelayVerdict {
    const key = normalizeArtifactPath(artifactPath)
    const art = this.artifacts.get(key)
    if (!art) return { intercepted: false, ruleId: null, action: null }
    // 证据伪装面：路径或内容声称"验证结果"，但包含未复核污点
    if (looksLikeEvidence(artifactPath) && art.taints.length) {
      return {
        intercepted: true, ruleId: 'RLY-004', action: 'deny',
        reason: `证据污染：工件 ${artifactPath} 声称验证结果但携带未复核污点（${art.taints.join(',')}）`,
        taints: [...art.taints],
      }
    }
    if (art.session !== session) {
      return {
        intercepted: true, ruleId: 'RLY-002', action: 'block',
        reason: `污点工件接力：${artifactPath} 由会话 ${art.session} 写入（带污点），会话 ${session} 正在消费`,
        taints: [...art.taints],
      }
    }
    return { intercepted: false, ruleId: null, action: null }
  }

  private registerArtifact(session: string, fp: string, artifactPath: string, rec: TaintRecord) {
    const key = normalizeArtifactPath(artifactPath)
    const existing = this.artifacts.get(key)
    if (existing) {
      if (!existing.taints.includes(fp)) existing.taints.push(fp)
      return
    }
    if (!rec.persistSessions.includes(session)) rec.persistSessions.push(session)
    this.artifacts.set(key, { path: key, fp, taints: [fp], session, ts: this.now() })
  }

  /** 人工复核放行：把工件的污点标记清除（RLY-002/004 的出口） */
  revoke(artifactPath: string): boolean {
    const key = normalizeArtifactPath(artifactPath)
    const art = this.artifacts.get(key)
    if (!art) return false
    // 把工件污点的 persist 会话扩充到当前会话 = 允许接力
    for (const fp of art.taints) {
      const rec = this.taints.get(fp)
      if (rec) rec.piRules = []    // 复核确认 = 清 PI 史（防再触发 RLY-001）
    }
    this.artifacts.delete(key)
    return true
  }

  snapshot(): { taints: number; artifacts: number } {
    this.sweep()
    return { taints: this.taints.size, artifacts: this.artifacts.size }
  }
}

/** 文本命中的 PI 类规则 id 列表 */
function piHitIds(text: string): string[] {
  const ids: string[] = []
  for (const rule of piRules()) {
    rule.pattern.lastIndex = 0
    if (rule.pattern.test(text)) ids.push(rule.id)
  }
  return ids
}

/** 证据伪装判定：路径像证据文件，或内容开头声称验证报告 */
export function looksLikeEvidence(artifactPath: string, content?: string): boolean {
  if (EVIDENCE_PATH_RE.some((re) => re.test(artifactPath))) return true
  if (typeof content === 'string') {
    for (const re of EVIDENCE_HEAD_RE) {
      re.lastIndex = 0
      if (re.test(content)) return true
    }
  }
  return false
}
