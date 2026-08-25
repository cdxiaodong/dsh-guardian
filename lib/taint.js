/**
 * 污点追踪引擎（Engine 12）：跨调用的信息流控制（IFC）。
 *
 * 思想借鉴 Google DeepMind 的 CaMeL（Capabilities for Machine Learning, 2025-04）：
 * 提示注入无法被 100% 检测，但可以追踪"不可信/敏感数据"在系统里的流动，
 * 让污点值流向高危 sink（外传/exec）时必须显式获得能力（capability）授权。
 *
 * 与其他引擎的本质区别：其余引擎做"单点检测"（每次工具调用独立扫描内容），
 * 本引擎做"跨调用数据流检测"——
 *   ① 敏感内容进入上下文（读 .env / 私钥 / 用户 PII）→ 注册污点源，提取内容指纹
 *   ② 后续任何工具调用参数携带该内容（原文 / base64 / hex / URL 编码 / ROT13 变体）
 *      → 视为污点外传，拦截并要求人工授权
 *
 * 攻击场景：单看每次调用都无害（"读配置文件"放行、"POST 到合法 API"放行），
 * 但数据流构成泄露——只有污点追踪能抓到。
 *
 * 指纹方案：规范化（小写+去空白）后切固定宽度字符窗口（shingle），
 * FNV-1a 哈希入池；匹配时对 payload 的各解码变体切窗口求交集，
 * 交集 ≥ minHits（默认 3，要求 ~10+ 连续字符相同）即判定携带污点。
 */
/** FNV-1a 32bit 哈希：短串指纹，快且分布均匀 */
export function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
}
/** 规范化：小写 + 去所有空白。让 "sk-AbC" / "sk-Ab C" / "sk-abc\n" 指纹一致 */
export function normalizeText(s) {
    return s.toLowerCase().replace(/\s+/g, '');
}
/** 滚动字符窗口（shingle）切分 + 哈希。内容过长时均匀采样，封顶防膨胀 */
export function shingles(s, windowSize = 8, cap = 512) {
    const n = s.length - windowSize + 1;
    if (n <= 0)
        return s.length > 0 ? [fnv1a(s)] : [];
    if (n <= cap) {
        const out = new Array(n);
        for (let i = 0; i < n; i++)
            out[i] = fnv1a(s.slice(i, i + windowSize));
        return out;
    }
    const step = n / cap;
    const out = new Array(cap);
    for (let i = 0; i < cap; i++) {
        const start = Math.floor(i * step);
        out[i] = fnv1a(s.slice(start, start + windowSize));
    }
    return out;
}
/** 判断解码产物是否"可读"（可打印字符占比），过滤把普通单词误当 base64 解出的乱码 */
function printableRatio(s) {
    if (!s.length)
        return false;
    let printable = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126))
            printable++;
    }
    return printable / s.length >= 0.85;
}
function tryBase64(seg) {
    const padded = seg.length % 4 === 0 ? seg : seg + '='.repeat(4 - (seg.length % 4));
    try {
        const decoded = Buffer.from(padded, 'base64').toString('utf8');
        return decoded.length >= 8 && printableRatio(decoded) ? decoded : null;
    }
    catch {
        return null;
    }
}
function tryHex(seg) {
    if (seg.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(seg))
        return null;
    try {
        const decoded = Buffer.from(seg, 'hex').toString('utf8');
        return decoded.length >= 8 && printableRatio(decoded) ? decoded : null;
    }
    catch {
        return null;
    }
}
const ROT13 = (s) => s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
});
/**
 * 对 payload 生成解码变体候选集：
 *  - plain：原文
 *  - base64：所有 ≥16 字符的 base64 片段各自解码（对抗"编码后塞 URL/body"）
 *  - hex：所有 ≥32 字符的 hex 片段解码
 *  - url：整体 decodeURIComponent + 所有 %XX 密集片段解码
 *  - rot13：整体 ROT13（对抗字母替换混淆外传）
 */
export function decodeVariants(payload) {
    const out = [{ variant: 'plain', text: payload }];
    const seen = new Set([payload]);
    const push = (variant, text) => {
        if (text && !seen.has(text)) {
            seen.add(text);
            out.push({ variant, text });
        }
    };
    for (const m of payload.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g))
        push('base64', tryBase64(m[0]));
    for (const m of payload.matchAll(/\b[0-9a-fA-F]{32,}\b/g))
        push('hex', tryHex(m[0]));
    for (const m of payload.matchAll(/(?:%[0-9A-Fa-f]{2}){8,}/g)) {
        try {
            push('url', decodeURIComponent(m[0]));
        }
        catch { /* 非法转义，跳过 */ }
    }
    try {
        push('url', decodeURIComponent(payload));
    }
    catch { /* 整体非法则忽略 */ }
    push('rot13', ROT13(payload));
    return out;
}
export const DEFAULT_TAINT_CONFIG = {
    enable: true,
    windowSize: 8,
    minHits: 3,
    ttlMs: 30 * 60 * 1000,
    maxSources: 64,
    maxShinglesPerSource: 512,
    action: 'block',
    sweepIntervalMs: 60_000,
};
/**
 * 污点池：源注册 / 过期清扫（惰性 + 定时）/ 变体感知匹配。
 * 纯内存状态，随插件实例生命周期销毁（时间维度：宿主 dispose 即整池清空）。
 */
export class TaintPool {
    sources = new Map(); // Map 保持插入序，便于 FIFO 淘汰
    cfg;
    constructor(cfg = {}) {
        this.cfg = { ...DEFAULT_TAINT_CONFIG, ...cfg };
    }
    get config() { return this.cfg; }
    get size() { return this.sources.size; }
    /** 注册污点源（同 id 重复注册 = 刷新指纹与 TTL） */
    register(src) {
        const now = Date.now();
        this.sweep(now);
        const fp = shingles(normalizeText(src.content), this.cfg.windowSize, this.cfg.maxShinglesPerSource);
        const rec = {
            id: src.id,
            description: src.description,
            fingerprint: new Set(fp),
            registeredAt: now,
            expiresAt: now + (src.ttlMs ?? this.cfg.ttlMs),
        };
        this.sources.set(src.id, rec);
        // FIFO 淘汰：超过上限时删最旧（Map 迭代序 = 插入序）
        while (this.sources.size > this.cfg.maxSources) {
            const oldest = this.sources.keys().next().value;
            if (oldest === undefined)
                break;
            this.sources.delete(oldest);
        }
        return rec;
    }
    /** 清除过期源。返回被清除的 id 列表 */
    sweep(now = Date.now()) {
        const expired = [];
        for (const [id, rec] of this.sources) {
            if (rec.expiresAt <= now) {
                this.sources.delete(id);
                expired.push(id);
            }
        }
        return expired;
    }
    /**
     * 匹配：对 text 的所有解码变体切指纹，与每个存活源求交集。
     * 命中即返回证据（含变体归因）——同一个源只报最强命中（plain 优先保留）。
     */
    match(text) {
        const now = Date.now();
        const variants = decodeVariants(text);
        const hits = [];
        const variantOrder = ['plain', 'base64', 'hex', 'url', 'rot13'];
        for (const rec of this.sources.values()) {
            if (rec.expiresAt <= now)
                continue;
            let best = null;
            for (const { variant, text: vText } of variants) {
                const cand = shingles(normalizeText(vText), this.cfg.windowSize, this.cfg.maxShinglesPerSource);
                let matched = 0;
                for (const h of cand)
                    if (rec.fingerprint.has(h))
                        matched++;
                if (matched >= this.cfg.minHits) {
                    // plain 命中比编码命中更强；同变体取交集更大者
                    if (!best || (variant === 'plain' && best.variant !== 'plain') || (variant === best.variant && matched > best.matched) || (best.variant !== 'plain' && variantOrder.indexOf(variant) < variantOrder.indexOf(best.variant))) {
                        best = { sourceId: rec.id, description: rec.description, matched, variant };
                    }
                }
            }
            if (best)
                hits.push(best);
        }
        return hits;
    }
    clear() { this.sources.clear(); }
}
