/**
 * 工具清单完整性引擎（Runtime Tool-Manifest Integrity / Rug-Pull Detection）。
 *
 * 威胁模型：MCP/工具服务端在 Agent 已经审查并信任某工具之后，静默修改其描述或参数
 * schema（rug pull，OWASP MCP03:2025 Tool Poisoning 的子技术），把"干净过审"的工具
 * 翻转为恶意——描述里藏注入指令、schema 里塞危险参数。
 *
 * 业界共识防御：**批准时刻 pin 住工具定义（hash），运行时每次 tools/list 重校验，
 * 任何变更必须重新人工授权**。mcp-scan（Invariant Labs）做的是静态/离线扫描，
 * 本引擎把这套语义搬进 Agent 运行时，作为 cordis 插件常驻检测。
 *
 * 借鉴：OWASP MCP Top 10 (MCP03:2025)、Invariant Labs mcp-scan 与 2025-04 PoC、
 * arXiv:2506.01333（Tool Squatting and Rug Pull Attacks in MCP）。
 */
import { createHash } from 'node:crypto';
// ── 规范化与指纹 ─────────────────────────────────────────
/** 稳定序列化：对象键排序，保证同内容不同键序 → 同 hash */
export function canonicalJson(v) {
    if (v === undefined)
        return 'null';
    if (v === null || typeof v !== 'object')
        return JSON.stringify(v);
    if (Array.isArray(v))
        return '[' + v.map(canonicalJson).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}
/** 单个工具的指纹：sha256(name + description + inputSchema) */
export function hashToolSpec(spec) {
    return createHash('sha256').update(canonicalJson({
        name: spec.name,
        description: spec.description ?? '',
        inputSchema: spec.inputSchema ?? null,
    })).digest('hex');
}
/** 整份清单的指纹：按工具名排序后级联，用于快速比对/审计引用 */
export function manifestFingerprint(specs) {
    const joined = [...specs]
        .map((s) => s.name + ':' + hashToolSpec(s))
        .sort()
        .join('\n');
    return createHash('sha256').update(joined).digest('hex').slice(0, 16);
}
/** 工具清单 → 基线（批准时刻 pin） */
export function toBaseline(tools) {
    return new Map(tools.map((t) => [t.name, { hash: hashToolSpec(t), description: t.description }]));
}
/**
 * 生成 pin 锁文件（name → hash 映射，类似 package-lock 的角色）。
 * 宿主在受控环境下生成一次，写进配置 manifestBaseline，之后任何漂移都会被拒绝。
 */
export function pinManifest(tools) {
    return Object.fromEntries(tools.map((t) => [t.name, hashToolSpec(t)]));
}
// ── 同形异码（homoglyph）工具名检测 ─────────────────────
/** 常见西里尔/希腊同形字符 → ASCII（防 seаrch 抢注 search 这类攻击） */
const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'Ԍ': 'g', 'Ь': 'b', '№': 'no',
    'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ϲ': 'c', 'υ': 'u', 'χ': 'x', 'ι': 'i', 'κ': 'k', 'ν': 'n', 'τ': 't', 'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p', 'Τ': 't', 'Υ': 'u', 'Χ': 'x',
};
/** 工具名规范化：NFKC（全角→半角）+ 去零宽 + 同形字符折叠 + 小写 */
export function normalizeName(name) {
    let s = name.normalize('NFKC').replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, '').toLowerCase();
    s = s.replace(/[Ѐ-ӿͰ-Ͽ]/g, (ch) => CONFUSABLES[ch] ?? ch);
    return s;
}
/** Dice 双字符相似度（0~1），识别重命名/仿冒名 */
export function diceSimilarity(a, b) {
    if (a === b)
        return 1;
    if (a.length < 2 || b.length < 2)
        return a === b ? 1 : 0;
    const grams = (s) => {
        const m = new Map();
        for (let i = 0; i < s.length - 1; i++) {
            const g = s.slice(i, i + 2);
            m.set(g, (m.get(g) ?? 0) + 1);
        }
        return m;
    };
    const ga = grams(a), gb = grams(b);
    let overlap = 0, totalA = 0, totalB = 0;
    for (const n of ga.values())
        totalA += n;
    for (const n of gb.values())
        totalB += n;
    for (const [g, n] of ga)
        overlap += Math.min(n, gb.get(g) ?? 0);
    return (2 * overlap) / (totalA + totalB);
}
// ── 核心差分：基线 vs 当前清单 ──────────────────────────
/**
 * 比对当前工具清单与授权基线，产出 findings（纯函数，无副作用，便于测试）。
 * - 描述被改 → rugpull（deny）
 * - 仅 schema 被改 → schema-drift（block，人工重授权）
 * - 新增工具 → new-tool（默认 block，按 newToolPolicy）
 * - 工具消失 → removed-tool（log）
 * - 同形异码/高相似仿冒名 → squat（deny）
 */
export function diffManifests(baseline, current, opts = {}) {
    const findings = [];
    const curNames = new Set(current.map((t) => t.name));
    const policy = opts.newToolPolicy ?? 'block';
    for (const cur of current) {
        const base = baseline.get(cur.name);
        if (!base) {
            if (policy === 'allow')
                continue;
            let reason = `会话中途新增工具「${cur.name}」（未在授权基线中）`;
            const lookalike = [...baseline.keys()].find((n) => n !== cur.name && diceSimilarity(normalizeName(n), normalizeName(cur.name)) >= 0.75);
            if (lookalike)
                reason += `，且与已授权工具「${lookalike}」名称高度相似，疑似抢注/重命名`;
            findings.push({ kind: 'new-tool', ruleId: 'TI-003', tool: cur.name, reason, severity: policy, detail: (cur.description ?? '').slice(0, 200) });
            continue;
        }
        const curHash = hashToolSpec(cur);
        if (curHash === base.hash)
            continue;
        if ((cur.description ?? '') !== (base.description ?? '')) {
            findings.push({
                kind: 'rugpull', ruleId: 'TI-001', tool: cur.name, severity: 'deny',
                reason: `工具「${cur.name}」描述在授权后被修改（rug-pull）`,
                detail: `旧:「${(base.description ?? '').slice(0, 120)}」→ 新:「${(cur.description ?? '').slice(0, 120)}」`,
            });
        }
        else {
            findings.push({
                kind: 'schema-drift', ruleId: 'TI-002', tool: cur.name, severity: 'block',
                reason: `工具「${cur.name}」参数 schema 在授权后被修改`,
                detail: `hash ${base.hash.slice(0, 8)} → ${curHash.slice(0, 8)}`,
            });
        }
    }
    for (const [name] of baseline) {
        if (!curNames.has(name)) {
            findings.push({ kind: 'removed-tool', ruleId: 'TI-004', tool: name, reason: `工具「${name}」已从清单移除（可能被重命名或替换）`, severity: 'log' });
        }
    }
    // 同形异码抢注：当前清单内部归一化碰撞，以及与基线名的归一化碰撞
    const normSeen = new Map();
    for (const cur of current) {
        const norm = normalizeName(cur.name);
        const prev = normSeen.get(norm);
        if (prev && prev !== cur.name) {
            findings.push({ kind: 'squat', ruleId: 'TI-005', tool: cur.name, severity: 'deny', reason: `工具名「${cur.name}」与「${prev}」同形异码（homoglyph 抢注）` });
        }
        else {
            normSeen.set(norm, cur.name);
        }
        for (const [baseName] of baseline) {
            if (baseName !== cur.name && normalizeName(baseName) === norm) {
                findings.push({ kind: 'squat', ruleId: 'TI-005', tool: cur.name, severity: 'deny', reason: `工具名「${cur.name}」归一化后与基线工具「${baseName}」重合（仿冒）` });
            }
        }
    }
    return findings;
}
