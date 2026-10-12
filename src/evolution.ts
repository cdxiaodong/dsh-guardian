/**
 * Engine 39: Policy Evolution Guard（规则演化验证引擎）——缝合 VEPA
 *
 * VEPA (arXiv:2610.12813, 2026-10-08) 的核心洞察：护栏策略需要随部署持续进化，
 * 但 LLM/自动化提议的策略补丁不能直接生效——"uncertain updates cannot directly
 * affect guardrail decisions"。VEPA 用三层机制守住进化安全：
 *   1. 结构验证器：确定性检查补丁结构合法且冲突自由
 *   2. 证据感知激活：新规则只有积累足够部署证据才被激活
 *   3. 权威层：验证过的规则才进入可执行策略
 *
 * 本引擎是 VEPA 三层机制的确定性本地实现，防守 main 上 addRule() 的盲区：
 * 攻击者注入一条永真 deny 规则 → 护栏武器化（拦死一切工具调用）；
 * 注入永真 log 规则 → 审计稀释（审计流被垃圾条目淹没，真实告警被淹没）。
 *
 * 三道门（规则进化必须全部通过才能生效）：
 *   Gate 1 验证器（validateRuleChange）：结构 + 语义 + 防武器化
 *     - EVL-001 结构合法：ID 非空唯一、正则可编译且非永真、action 枚举、reason 非空
 *     - EVL-002 防武器化：超宽 pattern（. / .* / [\s\S]* / 空白裸量词）拦截
 *     - EVL-003 防降级：deny→log/block 的处置降级必须显式声明
 *   Gate 2 影子模式（shadow）：新规则先以 log-only 观察，不实际拦截
 *   Gate 3 证据感知激活（promote）：积累 ≥minHits 次命中后才晋升为声明的 action
 *
 * 与 main 现有引擎的分工：其他引擎盯"工具调用 payload"，本引擎盯"护栏自身的
 * 规则库变化"——规则的来源不可信（可能是注入诱导的），规则库必须守卫自身。
 */

import type { Rule } from './rules.js'

/** 规则进化提案的类型 */
export type RuleProposalType = 'add' | 'update' | 'remove'

/** 进化提案：对规则库的一次原子变更 */
export interface RuleProposal {
  type: RuleProposalType
  /** add/update 时为完整规则；remove 时只需 id */
  rule?: Rule
  /** 仅 update：目标规则 id */
  targetId?: string
  /** 仅降级场景：显式声明处置降级的原因（EVL-003 要求） */
  downgradeAck?: string
}

/** 验证结果：code 为 null 表示通过 */
export interface ValidationVerdict {
  ok: boolean
  /** EVL-001/002/003 规则号；ok=true 时为 null */
  code: 'EVL-001' | 'EVL-002' | 'EVL-003' | null
  reason: string
}

/** 影子规则：已通过验证、进入观察期的规则 */
export interface ShadowRule {
  /** 本地生成的影子 id（与正式规则区分） */
  shadowId: string
  proposal: RuleProposal
  /** 验证通过的时间戳（ms） */
  since: number
  /** 影子观察期内命中次数 */
  hits: number
  /** 观察到的不同工具名（独立证据维度：跨工具命中比单工具重复命中证据强） */
  tools: Set<string>
  /** 证据样本（最多保留 maxSamples 条，供宿主复核） */
  samples: Array<{ tool: string; snippet: string; ts: number }>
}

/** 证据感知激活的配置 */
export interface EvolutionConfig {
  /** 是否启用规则演化验证（默认 true） */
  enabled?: boolean
  /** 影子规则晋升所需最小命中次数（默认 3） */
  minHits?: number
  /** 影子规则晋升所需最小独立工具数（默认 1） */
  minTools?: number
  /** 影子窗口最长存活毫秒数，超时未晋升自动退役（默认 7 天） */
  shadowTtl?: number
  /** 每条影子规则保留的样本上限（默认 8） */
  maxSamples?: number
  /** 影子观察用时钟（测试注入用）；默认 () => Date.now() */
  now?: () => number
}

/** 永真/超宽正则的确定性黑名单（按 source 精确匹配，大小写不敏感） */
const OVERWIDE_SOURCES = new Set([
  '.',
  '.*',
  '.+',
  '[\\s\\S]',
  '[\\s\\S]*',
  '[\\s\\S]+',
  '[\\s\\s]*',
  '[\\S\\s]*',
  '.{0,}',
  '.{1,}',
  '^',
  '$',
  '^$',
  '',
])

/** 判断 pattern source 是否为永真/超宽（结构分析而非试错，避免 ReDoS 面） */
function isOverwide(pattern: RegExp): boolean {
  const src = pattern.source.replace(/\s+/g, '')
  if (OVERWIDE_SOURCES.has(src)) return true
  // 去锚后纯通配序列（如 .*.*.*）同样永真
  if (/^(\.\*|\.\+|\{\d*,\})+$/.test(src)) return true
  return false
}

/** 结构校验：字段齐备且类型正确（EVL-001 的结构面） */
function isStructurallyValid(rule: Rule | undefined): rule is Rule {
  if (!rule || typeof rule !== 'object') return false
  if (typeof rule.id !== 'string' || rule.id.length === 0) return false
  if (!(rule.pattern instanceof RegExp)) return false
  if (!['block', 'deny', 'log'].includes(rule.action)) return false
  if (typeof rule.reason !== 'string' || rule.reason.length === 0) return false
  return true
}

/** 计算处置严重度序：deny > block > log */
function severityOf(action: Rule['action']): number {
  return action === 'deny' ? 2 : action === 'block' ? 1 : 0
}

/**
 * 规则进化验证器（Gate 1）。
 *
 * 输入：提案 + 当前规则库（判断 ID 冲突与降级）。
 * 判定全部是确定性结构分析，无 LLM 参与——这是与"LLM 提议补丁"场景的
 * 分工：本引擎不生成规则，只验证规则。
 */
export function validateRuleChange(
  proposal: RuleProposal,
  existing: ReadonlyArray<Rule>,
): ValidationVerdict {
  if (proposal.type === 'remove') {
    // remove 提案要求目标存在；移除 SECURITY 类内置规则同样需要显式确认
    const target = existing.find(r => r.id === (proposal.targetId ?? proposal.rule?.id))
    if (!target) {
      return { ok: false, code: 'EVL-001', reason: `移除目标规则不存在：${proposal.targetId ?? proposal.rule?.id}` }
    }
    return { ok: true, code: null, reason: '移除提案结构合法' }
  }

  const rule = proposal.rule
  if (!isStructurallyValid(rule)) {
    return { ok: false, code: 'EVL-001', reason: '规则结构不合法（id/pattern/action/reason）' }
  }

  // add：ID 不得与现有重复
  if (proposal.type === 'add' && existing.some(r => r.id === rule.id)) {
    return { ok: false, code: 'EVL-001', reason: `规则 ID 已存在：${rule.id}` }
  }
  // update：目标必须存在且是同一条
  if (proposal.type === 'update') {
    if (!proposal.targetId || !existing.some(r => r.id === proposal.targetId)) {
      return { ok: false, code: 'EVL-001', reason: `更新目标规则不存在：${proposal.targetId}` }
    }
    if (rule.id !== proposal.targetId && existing.some(r => r.id === rule.id)) {
      return { ok: false, code: 'EVL-001', reason: `更新改 ID 且新 ID 已被占用：${rule.id}` }
    }
  }

  // EVL-002：防武器化——永真/超宽正则
  if (isOverwide(rule.pattern)) {
    return { ok: false, code: 'EVL-002', reason: `超宽/永真正则（${rule.pattern.source}）会把护栏武器化或稀释审计` }
  }

  // EVL-003：防降级——update 场景下处置严重度下降必须显式声明
  if (proposal.type === 'update') {
    const target = existing.find(r => r.id === proposal.targetId)!
    if (severityOf(rule.action) < severityOf(target.action)) {
      if (!proposal.downgradeAck || proposal.downgradeAck.trim().length === 0) {
        return {
          ok: false,
          code: 'EVL-003',
          reason: `处置降级（${target.action}→${rule.action}）未声明 downgradeAck——这是渐进解除防线的特征`,
        }
      }
    }
  }

  return { ok: true, code: null, reason: '提案通过验证' }
}

/** 影子规则库（引擎核心状态） */
export class EvolutionTracker {
  private shadows = new Map<string, ShadowRule>()
  private counter = 0
  private readonly cfg: Required<EvolutionConfig>
  /** 晋升历史：[[shadowId, ruleId]]，供宿主审计 */
  readonly promotions: Array<{ shadowId: string; ruleId: string; at: number; hits: number; tools: number }> = []
  /** 退役历史（TTL 过期未晋升） */
  readonly retirements: Array<{ shadowId: string; ruleId: string; at: number; hits: number }> = []

  constructor(cfg: EvolutionConfig = {}) {
    this.cfg = {
      enabled: cfg.enabled ?? true,
      minHits: cfg.minHits ?? 3,
      minTools: cfg.minTools ?? 1,
      shadowTtl: cfg.shadowTtl ?? 7 * 24 * 3600 * 1000,
      maxSamples: cfg.maxSamples ?? 8,
      now: cfg.now ?? (() => Date.now()),
    }
  }

  /**
   * Gate 1 + Gate 2：验证提案，通过则入影子库（返回影子条目），
   * 不通过返回 ValidationVerdict（ok=false）。
   */
  submit(
    proposal: RuleProposal,
    existing: ReadonlyArray<Rule>,
  ): ShadowRule | ValidationVerdict {
    if (!this.cfg.enabled) {
      return { ok: false, code: 'EVL-001', reason: '规则演化验证未启用' }
    }
    const verdict = validateRuleChange(proposal, existing)
    if (!verdict.ok) return verdict
    const shadowId = `shadow-${++this.counter}-${Math.random().toString(36).slice(2, 8)}`
    const entry: ShadowRule = {
      shadowId,
      proposal,
      since: this.cfg.now(),
      hits: 0,
      tools: new Set(),
      samples: [],
    }
    this.shadows.set(shadowId, entry)
    return entry
  }

  /**
   * 影子观察：工具调用 payload 喂给全部影子规则（log-only，不拦截）。
   * 返回命中了该 payload 的影子规则（供宿主记录观察数据）。
   */
  observe(tool: string, payloadText: string): ShadowRule[] {
    const now = this.cfg.now()
    const hitShadows: ShadowRule[] = []
    for (const entry of this.shadows.values()) {
      const rule = entry.proposal.rule
      if (!rule) continue
      rule.pattern.lastIndex = 0
      if (!rule.pattern.test(payloadText)) continue
      entry.hits += 1
      entry.tools.add(tool)
      if (entry.samples.length < this.cfg.maxSamples) {
        entry.samples.push({ tool, snippet: payloadText.slice(0, 300), ts: now })
      }
      hitShadows.push(entry)
    }
    return hitShadows
  }

  /**
   * Gate 3：证据感知晋升检查。命中数与独立工具数均达标即晋升
   * （返回被晋升的完整提案，从影子库摘除）；证据不足返回 null。
   * remove 型提案不参与自动晋升——移除防线必须人工 forcePromote。
   */
  promoteIfReady(shadowId: string): RuleProposal | null {
    const entry = this.shadows.get(shadowId)
    if (!entry || entry.proposal.type === 'remove') return null
    if (entry.hits < this.cfg.minHits) return null
    if (entry.tools.size < this.cfg.minTools) return null
    const proposal = entry.proposal
    this.shadows.delete(shadowId)
    this.recordPromotion(entry)
    return proposal
  }

  /** 主动晋升（宿主人工复核后强制转正，跳过证据门槛，remove 提案走这里） */
  forcePromote(shadowId: string): RuleProposal | null {
    const entry = this.shadows.get(shadowId)
    if (!entry) return null
    const proposal = entry.proposal
    this.shadows.delete(shadowId)
    this.recordPromotion(entry)
    return proposal
  }

  private recordPromotion(entry: ShadowRule): void {
    this.promotions.push({
      shadowId: entry.shadowId,
      ruleId: entry.proposal.rule?.id ?? entry.proposal.targetId ?? '(remove)',
      at: this.cfg.now(),
      hits: entry.hits,
      tools: entry.tools.size,
    })
  }

  /** TTL 清理：影子窗口超时未晋升自动退役（返回退役的规则 id 列表） */
  sweepExpired(): string[] {
    const now = this.cfg.now()
    const retired: string[] = []
    for (const [shadowId, entry] of this.shadows) {
      if (now - entry.since > this.cfg.shadowTtl) {
        const ruleId = entry.proposal.rule?.id ?? '(remove)'
        this.shadows.delete(shadowId)
        this.retirements.push({ shadowId, ruleId, at: now, hits: entry.hits })
        retired.push(ruleId)
      }
    }
    return retired
  }

  /** 当前影子库快照（宿主 API） */
  shadowRules(): ShadowRule[] {
    return [...this.shadows.values()]
  }

  /** 单条影子规则证据读数 */
  evidenceOf(shadowId: string): { hits: number; tools: number; ageMs: number } | null {
    const e = this.shadows.get(shadowId)
    if (!e) return null
    return { hits: e.hits, tools: e.tools.size, ageMs: this.cfg.now() - e.since }
  }
}
