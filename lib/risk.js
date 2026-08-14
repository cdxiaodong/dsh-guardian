import { shannonEntropy } from './secrets.js';
export const DEFAULT_THRESHOLDS = { deny: 0.9, block: 0.5, warn: 0.25 };
/** 把命中规则集转成风险评分 */
export function scoreSignals(signals, thresholds = DEFAULT_THRESHOLDS) {
    if (!signals.length)
        return { score: 0, signals: [], verdict: 'allow' };
    // 并集概率式累加：1 - Π(1 - w)，天然封顶 1，多信号越叠越高但不溢出
    const score = 1 - signals.reduce((acc, s) => acc * (1 - clamp01(s.weight)), 1);
    let verdict = 'allow';
    if (score >= thresholds.deny)
        verdict = 'deny';
    else if (score >= thresholds.block)
        verdict = 'block';
    else if (score >= thresholds.warn)
        verdict = 'warn';
    return { score: round2(score), signals, verdict };
}
/** 从规则列表收集一次文本命中的所有信号 */
export function collectSignals(rules, text) {
    const signals = [];
    for (const rule of rules) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(text)) {
            signals.push({ ruleId: rule.id, reason: rule.reason, weight: rule.weight ?? actionWeight(rule.action), category: rule.category });
        }
    }
    return signals;
}
/** 动作到默认权重的映射（无显式 weight 时用） */
function actionWeight(action) {
    return action === 'deny' ? 0.95 : action === 'block' ? 0.6 : 0.3;
}
/** 密钥熵越高越可疑：把熵映射成 0~1 权重信号 */
export function secretEntropySignal(ruleId, description, raw) {
    const e = shannonEntropy(raw);
    // 熵 >3.5 典型真密钥；<2.5 多为占位符
    const weight = e >= 3.5 ? 0.95 : e >= 2.5 ? 0.6 : 0.2;
    return { ruleId, reason: `明文密钥：${description}（熵 ${round2(e)}）`, weight, category: 'credential' };
}
function clamp01(n) { return Math.max(0, Math.min(1, n)); }
function round2(n) { return Math.round(n * 100) / 100; }
