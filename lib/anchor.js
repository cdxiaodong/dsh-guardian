/**
 * 会话锚定引擎（Context Anchoring / Session Anchor Drift Detection）
 *
 * 灵感来源：Unit 42《Agent Session Smuggling in Agent2Agent Systems》(2025-10)
 * 提出的"上下文锚定"防御——基于原始用户意图建立任务锚点，持续验证后续
 * agent 行为是否与锚点一致，偏离即标记。本文件把它做成**确定性、本地、
 * 无 LLM** 的实现：
 *
 *  1. 会话开始时从用户原始意图提取"锚点实体"（合法出站主机集合）
 *  2. 每次工具调用提取"出站目标"（URL / curl|wget 目标主机）
 *  3. 出站目标 ∉ 锚点 ∪ 已确认 ∪ 环境中性 → 意图漂移（foreign）
 *
 * 与 kill-chain（匹配已知攻击序列）、taint（跟踪数据流）正交：
 * 锚定引擎捕获的是**意图偏离**——即使注入 payload 不匹配任何已知模式，
 * 一个凭空出现的出站主机也逃不出锚点比对。适合抓 0day 注入向量。
 */
/**
 * 环境中性主机：开发基础设施与本地回环。
 * 访问它们与"用户意图"无关（任何会话都可能合法发生），不计为漂移。
 * 注意：内网段/云 metadata 由 ssrf.ts 引擎负责，这里不重复。
 */
export const AMBIENT_HOSTS = new Set([
    'localhost', '127.0.0.1', '0.0.0.0', '::1',
    'registry.npmjs.org', 'registry.npmmirror.com',
]);
/** 意图文本中认可的 TLD 白名单——避免把 "file.md"、"v1.2" 误判为域名 */
const HOST_TLDS = new Set([
    'com', 'org', 'net', 'io', 'ai', 'dev', 'cn', 'app', 'co', 'me', 'sh',
    'edu', 'gov', 'uk', 'jp', 'de', 'fr', 'ru', 'info', 'xyz', 'site', 'top',
    'online', 'tech', 'cloud', 'live', 'pro', 'zip', 'link', 'cc', 'tv', 'gg',
]);
/** URL（含端口/路径），用于提取 host */
const URL_RE = /https?:\/\/([a-z0-9][a-z0-9.-]*[a-z0-9]|\[[0-9a-f:]+\]|[0-9.]+)(?::\d+)?/gi;
/** 裸域名（至少两段标签 + 白名单 TLD） */
const BARE_HOST_RE = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,}))\b/gi;
/** IPv4 */
const IPV4_RE = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
/** curl/wget 的目标参数（支持 URL 或裸域名形式） */
const CURL_TARGET_RE = /\b(?:curl|wget)\b[^|;&\n]*?['"\s=]((?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s'"]*)?)/gi;
/** 主机名规范化：小写、去端口、去 www. 前缀 */
export function normalizeHost(raw) {
    let h = raw.trim().toLowerCase();
    if (h.startsWith('[') && h.endsWith(']'))
        h = h.slice(1, -1); // [IPv6]
    h = h.replace(/:\d+$/, ''); // 去端口
    if (h.startsWith('www.'))
        h = h.slice(4); // www 统一
    return h;
}
function pushHost(set, raw) {
    const h = normalizeHost(raw);
    // 含点（域名/IP）或已知单标签环境主机（localhost 等）才有效
    if (h && (h.includes('.') || AMBIENT_HOSTS.has(h)))
        set.add(h);
}
/**
 * 从用户原始意图提取锚点实体。
 * 用户明确提到的主机 = 本会话的合法出站目的地。
 */
export function extractIntentHosts(intent) {
    const hosts = new Set();
    if (typeof intent !== 'string')
        return [];
    const text = intent.slice(0, 10_000);
    for (const m of text.matchAll(URL_RE))
        pushHost(hosts, m[1]);
    for (const m of text.matchAll(IPV4_RE))
        pushHost(hosts, m[0]);
    for (const m of text.matchAll(BARE_HOST_RE)) {
        const tld = m[2].toLowerCase();
        if (HOST_TLDS.has(tld))
            pushHost(hosts, m[1]);
    }
    return [...hosts].map((value) => ({ kind: 'host', value }));
}
/**
 * 从工具调用 payload 提取"出站目标"主机。
 * 只认显式出站语义（URL / curl|wget 目标），裸域名不计——压误报。
 */
export function extractEgressHosts(text) {
    const hosts = new Set();
    if (typeof text !== 'string' || !text)
        return [];
    const clipped = text.slice(0, 20_000);
    for (const m of clipped.matchAll(URL_RE))
        pushHost(hosts, m[1]);
    for (const m of clipped.matchAll(CURL_TARGET_RE)) {
        const target = m[1].replace(/^https?:\/\//, '');
        pushHost(hosts, target.split('/')[0]);
    }
    return [...hosts].map((value) => ({ kind: 'host', value }));
}
/**
 * 会话锚点。生命周期由宿主驱动：
 *   begin → judge（每次工具调用）→ confirm（人工批准动态扩展）→ end
 */
export class SessionAnchor {
    id;
    createdAt;
    intent;
    anchorHosts;
    confirmedHosts = new Set();
    foreignEvents = 0;
    constructor(intent) {
        this.id = `anchor-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
        this.createdAt = new Date().toISOString();
        this.intent = typeof intent === 'string' ? intent.slice(0, 500) : '';
        this.anchorHosts = new Set(extractIntentHosts(this.intent).map((e) => e.value));
    }
    /** 判定一次工具调用的出站目标是否漂移。纯函数式：不修改 confirmed，只累计观察计数 */
    judge(payloadText) {
        const egress = extractEgressHosts(payloadText);
        if (!egress.length)
            return { safe: true, drift: 'none', foreignHosts: [] };
        const foreign = [];
        let sawAnchored = false; // 存在锚点内/已确认的出站（非漂移的实质出站）
        for (const { value } of egress) {
            if (this.anchorHosts.has(value) || this.confirmedHosts.has(value)) {
                sawAnchored = true;
                continue;
            }
            if (AMBIENT_HOSTS.has(value))
                continue;
            foreign.push(value);
        }
        if (foreign.length) {
            this.foreignEvents += foreign.length;
            return {
                safe: false,
                drift: 'high',
                foreignHosts: foreign,
                reason: `出站目标 ${foreign.join('、')} 不在会话锚点内（用户意图未授权该目的地）`,
            };
        }
        // 仅环境中性出站（localhost/registry）→ 弱信号；有锚点内出站 → 完全正常
        return { safe: true, drift: sawAnchored ? 'none' : 'ambient', foreignHosts: [] };
    }
    /** 人工确认后把主机纳入锚点（动态扩展：一次批准，本会话不再打扰） */
    confirm(host) {
        const h = normalizeHost(host);
        if (h)
            this.confirmedHosts.add(h);
    }
    /** 本会话是否已授权该主机（锚点原生或事后确认） */
    allows(host) {
        const h = normalizeHost(host);
        return this.anchorHosts.has(h) || this.confirmedHosts.has(h);
    }
    stats() {
        return {
            intent: this.intent,
            anchorHosts: [...this.anchorHosts],
            confirmedHosts: [...this.confirmedHosts],
            foreignEvents: this.foreignEvents,
        };
    }
}
