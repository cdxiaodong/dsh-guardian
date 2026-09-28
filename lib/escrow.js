/**
 * 出境滞留引擎（Egress Escrow Guard）——"先扣货、后放行"的延迟出境闸门。
 *
 * 借鉴 Provisional Reachability（arXiv:2609.18741, 2026-09-18）的核心思想：
 * 防御者每周期要拦的不是"次数"而是"比特数"；把每次携带敏感数据的出境
 * 调用先押入 escrow（滞留/托管）一个观察窗口，窗口内审计若发现风险信号
 * 即可撤销（rollback 那次调用），从而把"秘密可在任一时刻组装完成"降级为
 * "秘密必须在整个窗口内持续未被发现才能组装"。
 *
 * 本引擎是该论文 escrow+revoke 机制的确定性本地实现（LLM Agent 工具调用层）：
 *  - ESC-001：payload 命中敏感内容（凭据路径/密钥/PII 关键段）的出境外呼
 *              → hold（block 变体：需人工批准，且即便批准也计入滞留配额）
 *  - ESC-002：滞留配额 —— 观察窗口内出境比特数（去重脱敏后的内容指纹数）
 *              超过 bitBudget 即升级 deny（速率维度，逆限流）
 *  - ESC-003：自愈 —— 敏感指纹滑出窗口后自动释放，配额恢复
 *  - 撤销语义：宿主调用 release/rollback 时输出审计事件，供外部联动
 *
 * 与 engine-9（Egress Budget）的区别：budget 是"即时字节守恒"，本引擎是
 * "时间维度上的可撤销出境"—— 每次敏感出境都先扣为 escrow，观察期是宽限
 * 而非放行；审计信号在窗口内出现则整批撤销。
 */
/** 敏感内容探针：凭据路径 / 密钥形态 / PII 片段（确定性正则，无外部依赖） */
const SENSITIVE_PROBES = [
    { id: 'cred-path', pattern: /\.(ssh|aws|gnupg|kube|netrc)\b|id_rsa|id_ed25519|authorized_keys|\.env\b|credentials\.json/i, label: '凭据路径' },
    { id: 'secret-shape', pattern: /\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|ghp_[0-9a-zA-Z]{36}|-----BEGIN[ A-Z0-9_-]*PRIVATE KEY)/, label: '密钥形态' },
    { id: 'pii', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]?){13,16}\b/, label: 'PII' },
];
/** FNV-1a 64 位哈希（BigInt），内容指纹用 */
export function fnv1a64(s) {
    let h = 0xcbf29ce484222325n;
    for (let i = 0; i < s.length; i++) {
        h ^= BigInt(s.charCodeAt(i));
        h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
    }
    return h.toString(16).padStart(16, '0');
}
/**
 * 估算一个指纹承载的"比特数"。
 * 去重后每个独立内容指纹记 64 比特（哈希宽度）——同一内容反复出境
 * 不增记，这就是"秘密重组需要的是多样性而非次数"的量化表达。
 */
export function bitsOf(fingerprint) {
    return fingerprint.length >= 16 ? 64 : 32;
}
/** 判定 payload 是否携带敏感内容（返回首个命中探针，供审计展示） */
export function probeSensitive(text) {
    for (const p of SENSITIVE_PROBES) {
        p.pattern.lastIndex = 0;
        const m = p.pattern.exec(text);
        if (m)
            return { id: p.id, label: p.label, snippet: m[0].slice(0, 120) };
    }
    return null;
}
/** 脱敏采样：取前 8 后 4 + 中段 16 字符做指纹原料（足以区分多样性，不足以还原内容） */
function sampleForFingerprint(text) {
    const flat = text.replace(/\s+/g, ' ').trim();
    if (flat.length <= 28)
        return flat;
    return flat.slice(0, 8) + flat.slice(Math.floor(flat.length / 2) - 8, Math.floor(flat.length / 2) + 8) + flat.slice(-4);
}
/**
 * 出境滞留账本。所有携带敏感内容的出境调用（含被拦的）都入账——
 * 记账无条件先于判定，同 engine-29/30/31 惯例。
 */
export class EscrowTracker {
    config;
    entries = [];
    seq = 0;
    constructor(config) {
        this.config = config;
    }
    prune(now) {
        const cutoff = now - this.config.windowMs;
        if (this.entries.length && this.entries[0].at < cutoff) {
            this.entries = this.entries.filter((e) => e.at >= cutoff);
        }
    }
    /**
     * 记账并判定。返回 verdict；counted=true 表示本条已入滞留账。
     * 记账无条件：即使 deny 也入账（逆限流：被拦的尝试照样消耗注意力预算）。
     */
    record(tool, payload, now = Date.now()) {
        const probe = probeSensitive(payload);
        // 无敏感内容：不滞留、不拦（普通出境外呼不本引擎管辖）
        if (!probe) {
            return { intercepted: false, ruleId: null, reason: 'payload 无敏感内容，不滞留', heldBits: this.heldBits(now), counted: false };
        }
        this.seq += 1;
        const fingerprint = fnv1a64(sampleForFingerprint(payload));
        const entry = { seq: this.seq, tool, fingerprint, at: now };
        this.entries.push(entry);
        this.prune(now);
        const heldBits = this.heldBits(now);
        // ESC-002：窗口内去重比特数超预算 → 升级 deny（速率维度）
        if (heldBits > this.config.bitBudget) {
            return {
                intercepted: true, ruleId: 'ESC-002',
                reason: `出境滞留配额耗尽：窗口 ${this.config.windowMs}ms 内已滞留 ${heldBits} bits（配额 ${this.config.bitBudget}）`,
                heldBits, counted: true,
            };
        }
        // ESC-001：敏感内容首次滞留 → hold（人工批准可过，但账已记）
        return {
            intercepted: true, ruleId: 'ESC-001',
            reason: `出境内容含${probe.label}（${probe.snippet}），已押入滞留窗口 ${this.config.windowMs}ms`,
            heldBits, counted: true,
        };
    }
    /** 当前窗口滞留比特数（去重） */
    heldBits(now = Date.now()) {
        this.prune(now);
        const unique = new Set(this.entries.map((e) => e.fingerprint));
        return [...unique].reduce((acc, fp) => acc + bitsOf(fp), 0);
    }
    /** 撤销：清空滞留账（审计信号命中时宿主调用，对应论文的 revoke） */
    revoke() {
        const n = this.entries.length;
        this.entries = [];
        return n;
    }
    /** 窗口内明细（审计用） */
    snapshot() {
        return this.entries.map((e) => ({ ...e }));
    }
}
export function createEscrowTracker(config = {}) {
    const merged = {
        windowMs: config.windowMs ?? 10 * 60 * 1000,
        bitBudget: config.bitBudget ?? 2048,
        scanContent: config.scanContent ?? true,
    };
    return new EscrowTracker(merged);
}
