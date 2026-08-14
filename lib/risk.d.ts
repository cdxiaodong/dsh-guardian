import type { Rule } from './rules.js';
/**
 * 风险评分引擎（调研 takeaway：多信号加权 → 阈值分级处置）。
 * 不只会一刀切，把命中的所有信号累加成 0~1 风险分，再按阈值决定动作。
 */
export interface RiskSignal {
    ruleId: string;
    reason: string;
    weight: number;
    category?: string;
}
export interface RiskScore {
    /** 0~1 综合风险分（1 - Π(1-w)，多信号并集概率式累加，避免线性爆分） */
    score: number;
    signals: RiskSignal[];
    /** 建议处置 */
    verdict: 'deny' | 'block' | 'warn' | 'allow';
}
export interface RiskThresholds {
    /** ≥ 此分直接拒绝（默认 0.9） */
    deny: number;
    /** ≥ 此分需人工确认（默认 0.5） */
    block: number;
    /** ≥ 此分告警记录（默认 0.25） */
    warn: number;
}
export declare const DEFAULT_THRESHOLDS: RiskThresholds;
/** 把命中规则集转成风险评分 */
export declare function scoreSignals(signals: RiskSignal[], thresholds?: RiskThresholds): RiskScore;
/** 从规则列表收集一次文本命中的所有信号 */
export declare function collectSignals(rules: Rule[], text: string): RiskSignal[];
/** 密钥熵越高越可疑：把熵映射成 0~1 权重信号 */
export declare function secretEntropySignal(ruleId: string, description: string, raw: string): RiskSignal;
