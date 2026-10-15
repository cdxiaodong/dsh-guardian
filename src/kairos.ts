import type { Rule } from './rules.js'
import { scoreSignals, type RiskSignal } from './risk.js'

/**
 * Kairos 延迟判定门（Deferred-Adjudication Gate）
 *
 * 缝合 Kairos（arXiv:2610.18457）的事务化执法思想：
 * 合法动作与攻击第一步在单点观测上往往不可分，区分证据出现在后续 trace 里。
 * 只会 allow/deny 的监视器被迫在证据积累前裁决——本引擎引入第三态 defer（扣留）：
 *
 *   defer（扣留，Agent 继续投机执行）→ 证据累积 / oracle 裁决 / 任务结算 → release | refuse
 *
 * 事务语义映射：defer=BEGIN，release=COMMIT，refuse=ROLLBACK。
 *
 * 有界权威原则（fail-safe）：确定性层只能 refuse（证据过阈 / TTL 过期 / 预算驱逐），
 * release 权只属于 oracle（guardian/adjudicate 监听器）与任务结算 commit——
 * 无人裁决时宁可错拒不可错放（借鉴 LLMSentinel 的 deterministic fail-safe policy layer）。
 */

/** 规则分类即证据分类（与 Rule['category'] 同域） */
export type DeferCategory = NonNullable<Rule['category']>

/** 一条 trace 证据：后续工具调用中命中的信号 */
export interface TraceEvidence {
  ts: number
  category: DeferCategory
  weight: number
  detail: string
}

/** 被扣留的效应（尚未执行，等待裁决） */
export interface DeferredEffect {
  id: string
  tool: string
  snippet: string
  category: DeferCategory
  /** 扣留时刻的灰区风险分（仅 log 级信号构成） */
  score: number
  reason: string
  deferredAt: number
  expiresAt: number
  evidence: TraceEvidence[]
}

/** 账本轮转事件：确定性层产生的 refuse / release，供宿主审计 */
export interface LedgerEvent {
  id: string
  tool: string
  ruleId: 'KAI-002' | 'KAI-003' | 'KAI-004' | 'KAI-ORACLE'
  level: 'deny' | 'allow'
  reason: string
}

export interface DeferConfig {
  /** 灰区下界：log 级信号并集分 ≥ 此值才扣留（默认 0.3） */
  deferLo?: number
  /** 证据累积拒绝阈：并集证据分 ≥ 此值自动 refuse（默认 0.75） */
  refuseAt?: number
  /** 扣留 TTL，过期 fail-safe 拒绝（默认 60s） */
  ttlMs?: number
  /** 扣留预算，超出驱逐最旧项（默认 16） */
  maxPending?: number
}

/**
 * 类别亲和度：扣留项类别 × 后续证据类别 → 该证据对其裁决的相关度。
 * 凭据读取 ↔ 外泄/网络 是经典攻击链的两半，亲和度最高。
 */
export function affinity(pending: DeferCategory, incoming: DeferCategory): number {
  if (pending === incoming) return 0.4
  const pair = [pending, incoming].sort().join('+')
  switch (pair) {
    case 'credential+exfil': return 0.9
    case 'credential+network': return 0.8
    case 'exfil+injection':
    case 'credential+injection': return 0.7
    case 'exfil+prompt-injection':
    case 'credential+prompt-injection':
    case 'network+prompt-injection': return 0.6
    case 'exfil+tool-poisoning':
    case 'credential+tool-poisoning':
    case 'network+tool-poisoning': return 0.6
    case 'exfil+network': return 0.5
    default: return 0.1
  }
}

/** 灰区信号：只收集 log 级规则的命中（deny/block 级由既有引擎裁决，不重复 gating） */
export interface GraySignal {
  ruleId: string
  reason: string
  category: DeferCategory
  weight: number
}

export function graySignals(rules: Rule[], text: string): GraySignal[] {
  const out: GraySignal[] = []
  for (const rule of rules) {
    if (rule.action !== 'log') continue
    rule.pattern.lastIndex = 0
    if (rule.pattern.test(text)) {
      out.push({ ruleId: rule.id, reason: rule.reason, category: rule.category ?? 'destructive', weight: rule.weight ?? 0.3 })
    }
  }
  return out
}

function clamp01(n: number) { return Math.max(0, Math.min(1, n)) }

/**
 * 扣留账本：defer/observe/sweep/settle 的纯逻辑容器（无 IO，时钟可注入）。
 * 证据分沿用风险引擎的并集概率式累加：1 - Π(1 - affinity × weight)。
 */
export class DeferralLedger {
  private pending: DeferredEffect[] = []
  private seq = 0
  readonly deferLo: number
  readonly refuseAt: number
  readonly ttlMs: number
  readonly maxPending: number
  private readonly now: () => number

  constructor(config: DeferConfig & { now?: () => number } = {}) {
    this.deferLo = config.deferLo ?? 0.3
    this.refuseAt = config.refuseAt ?? 0.75
    this.ttlMs = config.ttlMs ?? 60_000
    this.maxPending = config.maxPending ?? 16
    this.now = config.now ?? Date.now
  }

  /** 灰区分（log 级信号并集）是否落在扣留带 [deferLo, 1) */
  shouldDefer(signals: GraySignal[]): boolean {
    return scoreSignals(signals as RiskSignal[]).score >= this.deferLo
  }

  /**
   * 扣留一个效应。预算超限时驱逐最旧项（fail-safe 拒绝，KAI-004）。
   */
  defer(tool: string, snippet: string, signals: GraySignal[]): { effect: DeferredEffect; evicted: LedgerEvent | null } {
    const top = [...signals].sort((a, b) => b.weight - a.weight)[0]
    const t = this.now()
    let evicted: LedgerEvent | null = null
    while (this.pending.length >= this.maxPending) {
      const oldest = this.pending.shift()!
      evicted = { id: oldest.id, tool: oldest.tool, ruleId: 'KAI-004', level: 'deny', reason: `扣留预算超限（max=${this.maxPending}），驱逐最旧效应` }
    }
    const effect: DeferredEffect = {
      id: `K${++this.seq}`,
      tool,
      snippet,
      category: top?.category ?? 'destructive',
      score: scoreSignals(signals as RiskSignal[]).score,
      reason: top?.reason ?? '灰区信号',
      deferredAt: t,
      expiresAt: t + this.ttlMs,
      evidence: [],
    }
    this.pending.push(effect)
    return { effect, evicted }
  }

  /** 喂入一批 trace 证据：先清 TTL，再按亲和度累积，过阈自动 refuse（KAI-002） */
  observe(evs: Array<Omit<TraceEvidence, 'ts'>>): LedgerEvent[] {
    const events = this.sweep()
    const t = this.now()
    for (const ev of evs) {
      for (const item of [...this.pending]) {
        item.evidence.push({ ts: t, ...ev })
      }
    }
    // 累积过阈的扣留项确定性拒绝（有界权威：确定性层只 refuse 不 release）
    for (const item of [...this.pending]) {
      if (this.evidenceScore(item) >= this.refuseAt) {
        events.push(...this.refuse(item.id, `KAI-002`, `trace 证据累积 ${this.evidenceScore(item).toFixed(2)} ≥ 拒绝阈 ${this.refuseAt}（${item.evidence.map((e) => e.detail).join('、')}）`))
      }
    }
    return events
  }

  /** TTL 清点：过期效应 fail-safe 拒绝（KAI-004）。每次 observe/裁决前调用。 */
  sweep(): LedgerEvent[] {
    const t = this.now()
    const events: LedgerEvent[] = []
    for (const item of [...this.pending]) {
      if (t >= item.expiresAt) {
        events.push(...this.refuse(item.id, 'KAI-004', `扣留 TTL ${this.ttlMs}ms 过期，fail-safe 拒绝`))
      }
    }
    return events
  }

  /** 证据并集分：1 - Π(1 - affinity × weight) */
  evidenceScore(item: DeferredEffect): number {
    const s = 1 - item.evidence.reduce((acc, e) => acc * (1 - clamp01(affinity(item.category, e.category) * clamp01(e.weight))), 1)
    return Math.round(s * 100) / 100
  }

  /** oracle / 结算的正向裁决：释放（放行执行） */
  release(ids: string[], reason: string): LedgerEvent[] {
    const events: LedgerEvent[] = []
    for (const id of ids) {
      const item = this.pending.find((p) => p.id === id)
      if (!item) continue
      this.pending = this.pending.filter((p) => p.id !== id)
      events.push({ id, tool: item.tool, ruleId: 'KAI-ORACLE', level: 'allow', reason: `oracle 释放：${reason}` })
    }
    return events
  }

  /** 拒绝单个扣留项 */
  refuse(id: string, ruleId: LedgerEvent['ruleId'], reason: string): LedgerEvent[] {
    const item = this.pending.find((p) => p.id === id)
    if (!item) return []
    this.pending = this.pending.filter((p) => p.id !== id)
    return [{ id, tool: item.tool, ruleId, level: 'deny', reason }]
  }

  /** 任务结算（事务边界）：commit 释放全部剩余扣留；abort 全部拒绝（KAI-003） */
  settle(outcome: 'commit' | 'abort'): LedgerEvent[] {
    const events: LedgerEvent[] = []
    for (const item of [...this.pending]) {
      if (outcome === 'commit') {
        this.pending = this.pending.filter((p) => p.id !== item.id)
        events.push({ id: item.id, tool: item.tool, ruleId: 'KAI-003', level: 'allow', reason: '任务提交（COMMIT）：释放扣留效应' })
      } else {
        events.push(...this.refuse(item.id, 'KAI-003', '任务中止（ROLLBACK）：拒绝扣留效应'))
      }
    }
    return events
  }

  /** 全量拒绝（无 oracle 时的 fail-safe 兜底） */
  refuseAll(reason: string): LedgerEvent[] {
    const events: LedgerEvent[] = []
    for (const item of [...this.pending]) {
      events.push(...this.refuse(item.id, 'KAI-ORACLE', reason))
    }
    return events
  }

  pendingEffects(): readonly DeferredEffect[] { return [...this.pending] }
  size(): number { return this.pending.length }
}
