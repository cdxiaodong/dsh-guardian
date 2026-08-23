/**
 * 攻击链时序检测引擎（Engine 10：Kill-Chain / 跨调用状态机）。
 *
 * 灵感与借鉴：
 *  - MITRE ATLAS™（https://atlas.mitre.org/）—— kill chain 战术序列知识库
 *    （16 tactics / 84 techniques），攻击按 Reconnaissance → Credential Access →
 *    Collection → Exfiltration 的阶段序列推进；
 *  - ARMO "assemble signals into an attack story" —— 把离散的单次告警组装成
 *    完整攻击叙事，而不是孤立地看每次工具调用；
 *  - Promptfoo 红队的多步攻击插件（context poisoning / memory manipulation）——
 *    验证了针对有状态 Agent 的攻击天然是跨调用、多步骤的。
 *
 * 核心创新：现有引擎全部是"单次调用"视角——读 .env（block）、base64 编码（放行）、
 * curl 上传（block）每一步单独看都有各自处置，但序列组合起来是完整的凭据外传链。
 * 本引擎为每条内置链维护一个有限状态机，按序消费工具调用事件，链达成时输出
 * 高置信度攻击叙事并升级处置（deny / 人工确认）。
 */
import { DEFAULT_RULES } from './rules.js';
/**
 * 内置攻击链库（编号沿用 mcp-safeguard 风格前缀 CHAIN-）。
 * 阶段信号尽量复用现有五引擎的规则 ID / 类别，跨引擎组装叙事。
 */
export const KILL_CHAINS = [
    {
        id: 'CHAIN-EXFIL',
        name: '凭据窃取→编码→外传',
        tactics: 'Credential Access → Collection → Exfiltration',
        severity: 'critical',
        action: 'deny',
        windowMs: 15 * 60_000,
        stages: [
            { label: '凭据获取', anyCategories: ['credential'], anyRuleIds: ['CRED-001', 'CRED-002', 'CRED-004', 'CRED-005', 'CRED-006', 'CRED-007', 'PATH-002'] },
            { label: '打包/编码', anyRuleIds: ['INJ-006', 'INJ-007'], where: (e) => /\b(base64|openssl\s+enc|g?zip|tar\s|gpg\s|--encode)\b/i.test(e.text ?? '') },
            { label: '数据外传', anyCategories: ['exfil', 'network'], anyRuleIds: ['EXFIL-001', 'EXFIL-002', 'EXFIL-003', 'EXFIL-004', 'EXFIL-005'] },
        ],
    },
    {
        id: 'CHAIN-PERSIST',
        name: '提权→持久化→后门',
        tactics: 'Privilege Escalation → Persistence → Backdoor',
        severity: 'critical',
        action: 'deny',
        windowMs: 30 * 60_000,
        stages: [
            { label: '提权/关闭防护', anyCategories: ['privesc'], anyRuleIds: ['PRIV-001', 'PRIV-002', 'PRIV-003', 'PRIV-004'] },
            { label: '持久化写入', anyRuleIds: ['PATH-003', 'PATH-004', 'PATH-005', 'PATH-006'] },
            { label: '植入后门', anyRuleIds: ['PATH-007'], where: (e) => /authorized_keys|useradd|adduser|chattr\s+\+i/i.test(e.text ?? '') },
        ],
    },
    {
        id: 'CHAIN-DESTROY',
        name: '侦察→批量删除→痕迹清理',
        tactics: 'Reconnaissance → Destroy → Cover Tracks',
        severity: 'high',
        action: 'deny',
        windowMs: 15 * 60_000,
        stages: [
            { label: '大范围侦察', where: (e) => /(\bfind\s+\/|\bls\s+-[a-z]*R[a-z]*\s+\/|\bdu\s+-[a-z]*h?\s+\/|\bcat\s+\/etc\/passwd)/i.test(e.text ?? '') },
            { label: '批量删除', anyCategories: ['destructive'], anyRuleIds: ['CMD-002', 'CMD-007', 'CMD-009'] },
            { label: '痕迹清理/覆写', anyRuleIds: ['CMD-003'], where: (e) => /(\bshred\b|\bdd\b|>\s*\/dev\/(sd|nvme|hd)|history\s+-c)/i.test(e.text ?? '') },
        ],
    },
    {
        id: 'CHAIN-HIJACK',
        name: '提示注入→覆盖护栏→危险执行',
        tactics: 'Prompt Injection → Defense Evasion → Execution',
        severity: 'high',
        action: 'block',
        windowMs: 15 * 60_000,
        stages: [
            { label: '提示注入', anyCategories: ['prompt-injection'], anyRuleIds: ['PI-001', 'PI-003', 'PI-005'] },
            { label: '覆盖安全机制/瞒用户', anyCategories: ['tool-poisoning'], anyRuleIds: ['TP-001', 'TP-002', 'TP-003', 'TP-004'] },
            { label: '危险执行', anyCategories: ['destructive', 'privesc'], anyRuleIds: ['CMD-002', 'CMD-006', 'PATH-007'] },
        ],
    },
];
/** 规则 ID → category 索引（解析自定义规则的类别） */
function buildCategoryIndex(rules) {
    const index = new Map();
    for (const rule of rules) {
        if (rule.category)
            index.set(rule.id, rule.category);
    }
    return index;
}
const DEFAULT_WINDOW_MS = 15 * 60_000;
/**
 * 攻击链状态机引擎。
 * 每条 ChainPattern 一个独立状态机；同一事件可同时推进多条链；
 * 阶段必须按序匹配（kill-chain 语义），乱序事件忽略。
 */
export class ChainEngine {
    patterns;
    categoryIndex;
    active = new Map();
    constructor(patterns = KILL_CHAINS, rules = DEFAULT_RULES) {
        this.patterns = patterns;
        this.categoryIndex = buildCategoryIndex(rules);
    }
    /** 消费一次工具调用事件，返回本次达成的链 verdict（可能多条，也可能为空） */
    observe(event) {
        const ts = event.ts ?? Date.now();
        const verdicts = [];
        for (const chain of this.patterns) {
            const windowMs = chain.windowMs ?? DEFAULT_WINDOW_MS;
            let state = this.active.get(chain.id);
            // 相邻阶段间隔超窗 → 整链重置（防慢速攻击跨小时累积误报）
            if (state && ts - state.lastAdvancedAt > windowMs) {
                this.active.delete(chain.id);
                state = undefined;
            }
            const stageIndex = state ? state.stageIndex : 0;
            const matcher = chain.stages[stageIndex];
            if (!matcher || !this.matchStage(matcher, event))
                continue;
            if (!state) {
                state = { chainId: chain.id, stageIndex: 0, startedAt: ts, lastAdvancedAt: ts, events: [] };
                this.active.set(chain.id, state);
            }
            state.stageIndex = stageIndex + 1;
            state.lastAdvancedAt = ts;
            state.events.push({
                stage: stageIndex,
                ts,
                tool: event.tool,
                signals: [...event.ruleIds],
                snippet: (event.text ?? '').slice(0, 120),
            });
            const progress = state.stageIndex / chain.stages.length;
            if (progress >= (chain.triggerAt ?? 1)) {
                verdicts.push({
                    chainId: chain.id,
                    name: chain.name,
                    trigger: progress >= 1 ? 'complete' : 'threshold',
                    progress: round2(progress),
                    action: chain.action,
                    severity: chain.severity,
                    story: buildStory(chain, state),
                });
                // 触发即重置，避免同一条链反复报（后续重新开始跟踪）
                this.active.delete(chain.id);
            }
        }
        return verdicts;
    }
    /** 阶段匹配：anyRuleIds / anyCategories / anyTools / where 任一满足即可 */
    matchStage(matcher, event) {
        if (matcher.anyRuleIds?.some((id) => event.ruleIds.includes(id)))
            return true;
        // 类别匹配：显式 categories + 通过规则 ID 反查（覆盖 addRule 加进来的自定义规则）
        if (matcher.anyCategories) {
            const eventCategories = new Set([
                ...event.categories,
                ...event.ruleIds.flatMap((id) => { const c = this.categoryIndex.get(id); return c ? [c] : []; }),
            ]);
            if (matcher.anyCategories.some((c) => eventCategories.has(c)))
                return true;
        }
        if (matcher.anyTools?.some((t) => (t.endsWith('*') ? event.tool.startsWith(t.slice(0, -1)) : event.tool === t)))
            return true;
        if (matcher.where?.(event))
            return true;
        return false;
    }
    /** 所有进行中的链进度快照（宿主可查询做态势展示） */
    progress() {
        return [...this.active.values()].map((s) => ({ ...s, events: s.events.map((e) => ({ ...e })) }));
    }
    /** 重置状态（全部或指定链） */
    reset(chainId) {
        if (chainId === undefined)
            this.active.clear();
        else
            this.active.delete(chainId);
    }
}
/** 组装攻击叙事：每个已完成阶段一行 */
function buildStory(chain, state) {
    return state.events.map((e) => {
        const label = chain.stages[e.stage]?.label ?? `阶段${e.stage + 1}`;
        const detail = e.snippet ? `“${e.snippet}”` : '';
        return `[${e.stage + 1}/${chain.stages.length}] ${label} —— ${e.tool}${e.signals.length ? `（信号: ${e.signals.join(', ')}）` : ''} ${detail}`.trim();
    });
}
function round2(n) { return Math.round(n * 100) / 100; }
