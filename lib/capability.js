/**
 * 能力衰减引擎（Engine 21）：混淆代理人（Confused Deputy）防护 —— 完整性侧防线。
 *
 * 借鉴来源：
 *  - Cloud Security Alliance《Confused Deputy Attacks on Autonomous AI Agents》(2026)：
 *    经典 confused deputy 是访问控制漏洞——低权限攻击者借高权限 Agent 之手越权行动；
 *    修复思路是"绑定身份 + 传播授权"，而非继续打磨提示词。
 *  - Stack Overflow Blog (2026-06)《AI agents are a confused deputy with the keys to your kingdom》：
 *    Agent 暴露的缺失控制正是"调用者身份绑定"。
 *  - Quarkslab《Agentic AI: the confused deputy problem》：这是授权问题，不是模型质量问题。
 *  - 对象能力模型（object-capability, Mark Miller）的 attenuation 原则：
 *    权威可以衰减传播、绝不自动增强——LLM 上下文恰是反例：一段网页文本就能"免费"获得
 *    与用户本人等价的工具调度权。本引擎把这条被打破的定律装回去。
 *
 * 与既有引擎的正交性：
 *  - Engine 12（污点追踪）管机密性：敏感数据**流出**要授权；
 *  - Engine 7（致命三角）管外泄三角**成形**告警；
 *  - 本引擎管完整性：不可信**指令流入**决策后，特权副作用操作自动降权。
 *    判定不看本次 payload 说了什么（其余引擎都盯 payload），只看"此刻谁在说话"——
 *    会话信任状态 + 工具副作用类别。
 *
 * 核心机制：
 *  ① 指令性语言检测（data vs. code 的 LLM 翻版）：外部内容是"数据"还是"指令"？
 *     数据可以进上下文；携带指令性话术的内容 = 潜在 confused deputy 载荷。
 *  ② 信任账本（TrustLedger）：跨调用状态机。ingest 污染内容 → 会话进入衰减态，
 *     影响窗口（默认 3 步）内的副作用类工具（exec/write/delete/network/credential）
 *     一律降为人工确认。
 *  ③ 委托凭证（delegation voucher）：人工确认后按 (来源, 类别) 发放、次数受限——
 *     授权可传播但可衰减、可撤销，绝不无中生有。
 */
/** 衰减态默认保护的副作用类别 */
export const PROTECTED_CATEGORIES = ['exec', 'write', 'delete', 'network', 'credential'];
/** 工具名 → 副作用类别的内置映射（子串匹配，大小写不敏感；宿主可用 config 覆盖） */
export const TOOL_CATEGORY_PATTERNS = [
    { category: 'exec', pattern: /bash|shell|\bsh\b|\bzsh\b|exec|run[_\s-]?command|terminal|process\.spawn|code[_\s-]?interpreter|subprocess|powershell|cmd\.exe/i },
    { category: 'delete', pattern: /delete|remove|\brm\b|unlink|drop\b|truncate|destroy|shred/i },
    { category: 'write', pattern: /write|create[_\s-]?file|save|apply[_\s-]?patch|edit\b|modify|update\b|append|mkdir|touch\b|insert|patch\b/i },
    { category: 'network', pattern: /fetch|http|curl|wget|request|webhook|url\b|browser\.navigate|navigate|download|upload|\bsend\b|email|smtp|post\b/i },
    { category: 'credential', pattern: /auth|login|oauth|\btoken\b|\bkey\b|sudo|\bssh\b|credential|secret|password|api[_\s-]?key/i },
];
export const DIRECTIVE_RULES = [
    { id: 'ILK-001', pattern: /(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+)?(previous|prior|above|earlier|initial|original)\s+(instructions?|prompts?|rules?|directions?|guardrails?)/i, description: '覆盖既有指令' },
    { id: 'ILK-002', pattern: /忽略(之前|以上|先前|上面)(的)?(所有|全部)?(指令|指示|提示|规则|约束)/, description: '覆盖既有指令（中文）' },
    { id: 'ILK-003', pattern: /(you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you\s+are|假设你现在是|你现在扮演|你现在是)/i, description: '身份重定义' },
    { id: 'ILK-004', pattern: /(you\s+(must|should|need\s+to|are\s+required\s+to|have\s+to)|你必须|你需要|请务必)[^.\n]{0,40}(execute|run|call|create|delete|write|send|modify|install|download|invoke|执行|调用|删除|写入|发送|安装|下载)/i, description: '强制工具动作' },
    { id: 'ILK-005', pattern: /(send|post|upload|transmit|exfiltrate|email|提交|上传|发送)[^.\n]{0,60}(to|at|via|到|至)[^.\n]{0,60}(https?:\/\/|[a-z0-9-]+\.(com|net|io|xyz|dev|cn)|webhook|api)/i, description: '指名外传目的地' },
    { id: 'ILK-006', pattern: /(reveal|show|print|repeat|output|dump|泄露|输出|打印)[^.\n]{0,30}(your|the)\s+(system\s+)?(prompt|instructions?|rules?|configuration|初始提示|系统提示|系统指令)/i, description: '套取系统提示' },
    { id: 'ILK-007', pattern: /(call|invoke|execute|使用|调用)[^.\n]{0,40}(tool|function|command|工具|函数|命令)/i, description: '直接点名调用工具' },
    { id: 'ILK-008', pattern: /(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|alert|notify)[^.\n]{0,30}(user|the\s+user|human|operator|不要告诉|瞒着|不要通知)/i, description: '对用户隐瞒' },
];
/** 扫描外部内容中的指令性话术。携带指令的内容视为潜在 confused deputy 载荷 */
export function detectDirectives(content) {
    if (!content)
        return [];
    const hits = [];
    for (const rule of DIRECTIVE_RULES) {
        rule.pattern.lastIndex = 0;
        const m = rule.pattern.exec(content);
        if (m)
            hits.push({ ruleId: rule.id, description: rule.description, match: m[0].slice(0, 120) });
    }
    return hits;
}
/** 工具名 → 副作用类别（benign = 无需衰减保护） */
export function classifyTool(toolName, overrides) {
    if (overrides) {
        const exact = overrides[toolName];
        if (exact)
            return exact;
    }
    for (const { category, pattern } of TOOL_CATEGORY_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(toolName))
            return category;
    }
    return 'benign';
}
/**
 * 信任账本：跨调用的会话信任状态机。
 * - ingest / pollute 建立污染；step 随每次工具调用衰减；窗口关闭自动恢复。
 * - attenuatedFor(category) 查询副作用类别是否被衰减（有凭证则消费凭证并放行）。
 */
export class TrustLedger {
    pollutions = [];
    vouchers = [];
    influenceSteps;
    constructor(opts = {}) {
        this.influenceSteps = Math.max(1, opts.influenceSteps ?? 3);
    }
    /** 申报外部内容摄入：携带指令性话术即建立污染 */
    ingest(source, content) {
        const directives = detectDirectives(content);
        if (directives.length) {
            this.pollute(source, `来源 "${source}" 的内容携带指令性话术`, directives);
        }
        return { source, polluted: directives.length > 0, directives };
    }
    /** 手动建立污染（宿主明确知道某来源不可信时） */
    pollute(source, reason, directives = []) {
        // 同来源已污染则刷新窗口并合并指令证据，不重复堆积
        const existing = this.pollutions.find(p => p.source === source);
        if (existing) {
            existing.remaining = this.influenceSteps;
            existing.reason = reason;
            for (const d of directives) {
                if (!existing.directives.some(x => x.ruleId === d.ruleId))
                    existing.directives.push(d);
            }
            return;
        }
        this.pollutions.push({ source, reason, directives: [...directives], remaining: this.influenceSteps });
    }
    /**
     * 查询副作用类别是否被衰减。命中有效凭证 → 消费一次并返回 null（授权可传播，但次数受限）。
     * 判定即消费：guardian/check 每次只查一次，语义为"凭证兑换放行"。
     */
    attenuatedFor(category) {
        const active = this.pollutions.filter(p => p.remaining > 0);
        if (!active.length)
            return null;
        const vi = this.vouchers.findIndex(v => v.category === category && active.some(p => p.source === v.source));
        if (vi >= 0) {
            const v = this.vouchers[vi];
            v.uses -= 1;
            if (v.uses <= 0)
                this.vouchers.splice(vi, 1);
            return null;
        }
        const sources = [...new Set(active.map(p => p.source))];
        const directives = active.flatMap(p => p.directives);
        const remaining = Math.max(...active.map(p => p.remaining));
        return {
            sources,
            directives,
            remaining,
            reason: `混淆代理人风险：不可信来源 [${sources.join(', ')}] 携带指令性内容进入上下文，其影响窗口（剩 ${remaining} 步）内的 ${category} 类副作用操作已降权`,
        };
    }
    /** 人工确认通过后发放委托凭证：限定来源 + 类别 + 次数 */
    grant(source, category, uses = 1) {
        this.vouchers.push({ source, category, uses });
    }
    /** 每次工具调用消耗一步影响窗口；窗口关闭的污染事件自动出清 */
    step() {
        this.pollutions = this.pollutions.filter(p => --p.remaining > 0);
    }
    /** 清除污染（新会话 / 人工复核整批内容后），可指定单一来源 */
    clear(source) {
        if (source === undefined) {
            this.pollutions = [];
            this.vouchers = [];
        }
        else {
            this.pollutions = this.pollutions.filter(p => p.source !== source);
            this.vouchers = this.vouchers.filter(v => v.source !== source);
        }
    }
    /** 当前状态（审计 / 调试） */
    status() {
        return {
            polluted: this.pollutions.some(p => p.remaining > 0),
            sources: this.pollutions
                .filter(p => p.remaining > 0)
                .map(p => ({ source: p.source, reason: p.reason, remaining: p.remaining, directives: p.directives.map(d => d.ruleId) })),
            vouchers: this.vouchers.map(v => ({ ...v })),
        };
    }
}
