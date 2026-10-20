import type { Rule } from './rules.js';
/**
 * Risk scoring engine (research takeaway: weighted multi-signal scoring, then threshold-based actions).
 * Rather than blocking across the board, sums all matched signals into a 0~1 risk score, then picks an action by threshold.
 */
export interface RiskSignal {
    ruleId: string;
    reason: string;
    weight: number;
    category?: string;
}
export interface RiskScore {
    /** 0~1 combined risk score (1 - Π(1-w), probabilistic union of signals, avoids linear blow-up) */
    score: number;
    signals: RiskSignal[];
    /** Suggested action */
    verdict: 'deny' | 'block' | 'warn' | 'allow';
}
export interface RiskThresholds {
    /** Score ≥ this is denied outright (default 0.9) */
    deny: number;
    /** Score ≥ this requires manual confirmation (default 0.5) */
    block: number;
    /** Score ≥ this is logged as a warning (default 0.25) */
    warn: number;
}
export declare const DEFAULT_THRESHOLDS: RiskThresholds;
/** Converts the matched rule set into a risk score */
export declare function scoreSignals(signals: RiskSignal[], thresholds?: RiskThresholds): RiskScore;
/** Collects all signals matched by a text from the rule list */
export declare function collectSignals(rules: Rule[], text: string): RiskSignal[];
/** Higher key entropy is more suspicious: maps entropy to a 0~1 weight signal */
export declare function secretEntropySignal(ruleId: string, description: string, raw: string): RiskSignal;
