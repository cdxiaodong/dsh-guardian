import type { Rule } from './rules.js'
import { shannonEntropy } from './secrets.js'

/**
 * 风险评分引擎（调研 takeaway：多信号加权 → 阈值分级处置）。
 * 不只会一刀切，把命中的所有信号累加成 0~1 风险分，再按阈值决定动作。
 */
export interface RiskSignal {
  ruleId: string
  reason: string
  weight: number
  category?: string
}

export interface RiskScore {
  /** 0~1 综合风险分（1 - Π(1-w)，多信号并集概率式累加，避免线性爆分） */
  score: number
  signals: RiskSignal[]
  /** 建议处置 */
  verdict: 'deny' | 'block' | 'warn' | 'allow'
}

export interface RiskThresholds {
  /** ≥ 此分直接拒绝（默认 0.9） */
  deny: number
  /** ≥ 此分需人工确认（默认 0.5） */
  block: number
  /** ≥ 此分告警记录（默认 0.25） */
  warn: number
}

export const DEFAULT_THRESHOLDS: RiskThresholds = { deny: 0.9, block: 0.5, warn: 0.25 }

/** 把命中规则集转成风险评分 */
export function scoreSignals(signals: RiskSignal[], thresholds: RiskThresholds = DEFAULT_THRESHOLDS): RiskScore {
  if (!signals.length) return { score: 0, signals: [], verdict: 'allow' }
  // 并集概率式累加：1 - Π(1 - w)，天然封顶 1，多信号越叠越高但不溢出
  const score = 1 - signals.reduce((acc, s) => acc * (1 - clamp01(s.weight)), 1)
  let verdict: RiskScore['verdict'] = 'allow'
  if (score >= thresholds.deny) verdict = 'deny'
  else if (score >= thresholds.block) verdict = 'block'
  else if (score >= thresholds.warn) verdict = 'warn'
  return { score: round2(score), signals, verdict }
}

/** 从规则列表收集一次文本命中的所有信号 */
export function collectSignals(rules: Rule[], text: string): RiskSignal[] {
  const signals: RiskSignal[] = []
  for (const rule of rules) {
    rule.pattern.lastIndex = 0
    if (rule.pattern.test(text)) {
      signals.push({ ruleId: rule.id, reason: rule.reason, weight: rule.weight ?? actionWeight(rule.action), category: rule.category })
    }
  }
  return signals
}

/** 动作到默认权重的映射（无显式 weight 时用） */
function actionWeight(action: Rule['action']): number {
  return action === 'deny' ? 0.95 : action === 'block' ? 0.6 : 0.3
}

/** 密钥熵越高越可疑：把熵映射成 0~1 权重信号 */
export function secretEntropySignal(ruleId: string, description: string, raw: string): RiskSignal {
  const e = shannonEntropy(raw)
  // 熵 >3.5 典型真密钥；<2.5 多为占位符
  const weight = e >= 3.5 ? 0.95 : e >= 2.5 ? 0.6 : 0.2
  return { ruleId, reason: `明文密钥：${description}（熵 ${round2(e)}）`, weight, category: 'credential' }
}

function clamp01(n: number) { return Math.max(0, Math.min(1, n)) }
function round2(n: number) { return Math.round(n * 100) / 100 }
