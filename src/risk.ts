import type { Rule } from './rules.js'
import { shannonEntropy } from './secrets.js'

/**
 * Risk scoring engine (research takeaway: weighted multi-signal scoring, then threshold-based actions).
 * Rather than blocking across the board, sums all matched signals into a 0~1 risk score, then picks an action by threshold.
 */
export interface RiskSignal {
  ruleId: string
  reason: string
  weight: number
  category?: string
}

export interface RiskScore {
  /** 0~1 combined risk score (1 - Π(1-w), probabilistic union of signals, avoids linear blow-up) */
  score: number
  signals: RiskSignal[]
  /** Suggested action */
  verdict: 'deny' | 'block' | 'warn' | 'allow'
}

export interface RiskThresholds {
  /** Score ≥ this is denied outright (default 0.9) */
  deny: number
  /** Score ≥ this requires manual confirmation (default 0.5) */
  block: number
  /** Score ≥ this is logged as a warning (default 0.25) */
  warn: number
}

export const DEFAULT_THRESHOLDS: RiskThresholds = { deny: 0.9, block: 0.5, warn: 0.25 }

/** Converts the matched rule set into a risk score */
export function scoreSignals(signals: RiskSignal[], thresholds: RiskThresholds = DEFAULT_THRESHOLDS): RiskScore {
  if (!signals.length) return { score: 0, signals: [], verdict: 'allow' }
  // Probabilistic union: 1 - Π(1 - w), naturally capped at 1; more signals raise the score without overflowing
  const score = 1 - signals.reduce((acc, s) => acc * (1 - clamp01(s.weight)), 1)
  let verdict: RiskScore['verdict'] = 'allow'
  if (score >= thresholds.deny) verdict = 'deny'
  else if (score >= thresholds.block) verdict = 'block'
  else if (score >= thresholds.warn) verdict = 'warn'
  return { score: round2(score), signals, verdict }
}

/** Collects all signals matched by a text from the rule list */
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

/** Maps action to default weight (used when no explicit weight is set) */
function actionWeight(action: Rule['action']): number {
  return action === 'deny' ? 0.95 : action === 'block' ? 0.6 : 0.3
}

/** Higher key entropy is more suspicious: maps entropy to a 0~1 weight signal */
export function secretEntropySignal(ruleId: string, description: string, raw: string): RiskSignal {
  const e = shannonEntropy(raw)
  // Entropy >3.5 is typical of real keys; <2.5 is mostly placeholders
  const weight = e >= 3.5 ? 0.95 : e >= 2.5 ? 0.6 : 0.2
  return { ruleId, reason: `Plaintext secret: ${description} (entropy ${round2(e)})`, weight, category: 'credential' }
}

function clamp01(n: number) { return Math.max(0, Math.min(1, n)) }
function round2(n: number) { return Math.round(n * 100) / 100 }
