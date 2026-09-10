/**
 * 认知完整性引擎（Memory Poisoning Guard）—— engine-24
 *
 * 威胁模型（2026 顶级威胁 memory poisoning / CBSE 配置型沙箱逃逸）：
 *   攻击者通过间接提示注入诱导 Agent 把恶意指令写进自己的"认知上下文文件"
 *   （CLAUDE.md / AGENTS.md / .cursorrules / memory 目录……）。写入动作本身
 *   人畜无害（就是写个 markdown），OS 级持久化检测（cron/rc/launchd）管不到；
 *   但下次会话这些文件会被加载进 system prompt，恶意指令以最高权限复活——
 *   注入的"跨会话持久化"形态。
 *
 *   借鉴：Rules File Backdoor（Cursor/Windsurf 2025 公开演示的同型攻击）、
 *   Invariant Labs tool-poisoning 的描述扫描思路（扫工具描述 → 扫记忆内容）、
 *   Claude Code 对 CLAUDE.md 的权限边界设计。
 *
 * 两层防线：
 *   1. 写时拦截：写入目标命中受保护上下文文件 → 对写入内容做注入扫描
 *   2. 完整性校验：TOFU（trust-on-first-write）哈希基线，启动时验篡改
 *
 * 与 persistence-guard（engine-23，另一分支）的分工：
 *   那个盯 OS 持久化机制（cron/systemd/rc/authorized_keys）；
 *   本引擎盯 Agent 认知层文件——模型自己下次会话会当指令读的文件。
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
/** 受保护的 Agent 认知上下文文件模式（对路径末段做全小写匹配） */
export const AGENT_CONTEXT_PATTERNS = [
    // 指令文件：会被整份加载进 system prompt
    /(^|[\/\\])(claude|agents|gemini|copilot-instructions|codex)[.\-_]?(local|md|txt)?\.md$/i,
    /(^|[\/\\])\.?claude[.\-_]local\.md$/i,
    /(^|[\/\\])\.cursorrules$/i,
    /(^|[\/\\])\.?clinerules([.\-_].*)?$/i,
    /(^|[\/\\])\.cursor\/rules([\/\\].*|)$/i,
    /(^|[\/\\])\.windsurfrules$/i,
    /(^|[\/\\])\.github\/copilot-instructions\.md$/i,
    // 记忆目录：持久化记忆条目
    /(^|[\/\\])memory[\/\\].+\.(md|json|txt)$/i,
    /(^|[\/\\])\.claude[\/\\].*(memory|plans)[\/\\].+\.(md|json)$/i,
    /(^|[\/\\])(memories|agent-memory)[\/\\].+\.(md|json)$/i,
    // 宿主运行时配置：Agent 行为开关与权限（CBSE 面）
    /(^|[\/\\])\.claude[\/\\]settings(\.local)?\.json$/i,
    /(^|[\/\\])\.codex[\/\\](config|rules)\.(json|toml|md)$/i,
    /(^|[\/\\])\.aionui[\/\\].*(rules|memory|persona).*\.(json|md)$/i,
    /(^|[\/\\])dsh[-_]?guardian\.ya?ml$/i,
];
/** 判定一个路径是否是受保护的 Agent 认知上下文文件 */
export function isAgentContextFile(target) {
    if (!target || typeof target !== 'string')
        return false;
    const normalized = target.replace(/\\/g, '/').toLowerCase();
    return AGENT_CONTEXT_PATTERNS.some((p) => p.test(normalized));
}
/**
 * 内置记忆投毒规则集（MEM-xxx）。所有正则不带 /g 标志。
 * 这些内容将被持久化并在下次会话以高权限加载——"现在只是可疑"
 * 持久化之后就是"每会话都执行的恶意指令"。
 */
export const MEMORY_RULES = [
    // 指令劫持：覆盖/替换既有指令体系
    { id: 'MEM-001', action: 'block', pattern: /\b(ignore|disregard|forget|override|bypass|supersede)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|existing|current)?\s*(instructions?|rules?|guidelines?|directives?|policies?)\b/i, reason: '记忆投毒：劫持/覆盖既有指令体系' },
    { id: 'MEM-002', action: 'deny', pattern: /\b(new|updated?|real|actual|true)\s+(instructions?|rules?|directives?)\s*[:：]/i, reason: '记忆投毒：植入替代指令集' },
    // 静默性：要求对用户隐瞒
    { id: 'MEM-003', action: 'deny', pattern: /\b(without|don'?t|do\s+not)\s+(telling|informing|notifying|alerting|mentioning\s+to|letting\s+know)\s+(the\s+)?user\b|(?<!\w)secretly\b|silent(ly)?\s+(execute|run|send|upload|exfiltrate)/i, reason: '记忆投毒：要求对用户隐瞒行为' },
    // 强制行为挂钩：把恶意动作绑到每个任务上（动词带词干弹性：completing/finishes/…）
    { id: 'MEM-004', action: 'deny', pattern: /\b(before|after|when(ever)?|every\s+time|each\s+time)\s+(you\s+)?(complet|finish|start|begin|respond|reply|answer|are\s+asked)\w*[^.\n]{0,100}\b(run|execut|curl|wget|send|upload|post|fetch|includ|attach|read)\w*\b/i, reason: '记忆投毒：把恶意动作绑定到每个任务' },
    // 数据外泄：指令本体就在教 Agent 外泄（候选词以 . 开头时前置 \b 不成立，故单词型候选项自带边界）
    { id: 'MEM-005', action: 'deny', pattern: /\b(send|upload|post|exfiltrate|transmit|deliver|email|includ)\w*[^.\n]{0,50}(\.env\b|\.ssh\b|\.(bash|zsh)rc|credentials?\b|secrets?\b|id_rsa|id_ed25519|api[_\-]?keys?\b|access[_\-]?tokens?\b|cookies?\b|passwords?\b|private\s+keys?\b)/i, reason: '记忆投毒：外泄凭据/密钥的持久指令' },
    // 护栏禁用：教 Agent 卸掉自己的安全机制
    { id: 'MEM-006', action: 'deny', pattern: /\b(disable|remove|turn\s+off|bypass|uninstall|deactivate|skip)\b[^.\n]{0,40}\b(guardian|dsh-guardian|guardrails?|protections?|sandbox|approvals?|confirmations?|security\s+checks?|permission\s+checks?|safe\s+mode)/i, reason: '记忆投毒：禁用安全护栏的持久指令' },
    // 执行链：远程脚本/编码执行写进记忆
    { id: 'MEM-007', action: 'deny', pattern: /(curl|wget)[^|\n]{0,120}\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b|\beval\s*\(\s*(atob|base64|Buffer)/i, reason: '记忆投毒：持久化远程代码执行链' },
    // 权限自扩：指示自动批准一切
    { id: 'MEM-008', action: 'deny', pattern: /\b(auto-?approve|always\s+approve|approve\s+all|allow\s+all|never\s+(ask|confirm|require\s+confirmation)|YOLO\s+mode)\b/i, reason: '记忆投毒：自动批准一切危险操作' },
    // 隐蔽载体：零宽/双向控制字符（人不可见，模型可读）
    { id: 'MEM-009', action: 'deny', pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/, reason: '记忆投毒：零宽/双向控制字符隐写' },
    // Unicode 私有区（Tags 区段常用于隐形指令走私）
    { id: 'MEM-010', action: 'deny', pattern: /[\uE000-\uF8FF]/, reason: '记忆投毒：Unicode 私用区/Tags 隐形字符' },
    // 注释藏指令：HTML 注释/代码注释中夹带指令
    { id: 'MEM-011', action: 'block', pattern: /(?:<!--|\/\*|#|\/\/)[^\n>]{0,200}?\b(ignore|disregard|forget|secretly|exfiltrate|disable|curl|wget|system\s+prompt|developer\s+(message|instruction))\b/i, reason: '记忆投毒：注释中夹带隐藏指令' },
];
/** 对将被写入 Agent 认知上下文文件的内容做投毒扫描 */
export function scanMemoryContent(text) {
    if (!text)
        return [];
    const hits = [];
    for (const rule of MEMORY_RULES) {
        rule.pattern.lastIndex = 0;
        const m = rule.pattern.exec(text);
        if (m) {
            hits.push({ ruleId: rule.id, reason: rule.reason, action: rule.action, match: m[0].slice(0, 120) });
        }
    }
    return hits;
}
/** 命中集合中最严动作：deny > block > log */
export function worstAction(hits) {
    if (hits.some((h) => h.action === 'deny'))
        return 'deny';
    if (hits.some((h) => h.action === 'block'))
        return 'block';
    if (hits.length)
        return 'log';
    return null;
}
/**
 * 写时判定：目标是否受保护 + 内容是否带毒。
 * TOFU 语义：内容干净时顺带刷新该文件的哈希基线（首次信任，之后验篡改）。
 */
export function guardMemoryWrite(target, content, store) {
    if (!isAgentContextFile(target)) {
        return { safe: true, target, isContextFile: false, hits: [] };
    }
    const hits = scanMemoryContent(content ?? '');
    const worst = worstAction(hits);
    if (worst === 'deny' || worst === 'block') {
        return { safe: false, target, isContextFile: true, hits, reason: hits.map((h) => h.reason).join('；') };
    }
    if (worst === 'log') {
        // log 级：可疑但不确定——放行并记录，基线不刷新（下次仍会重扫）
        return { safe: true, target, isContextFile: true, hits, reason: hits.map((h) => h.reason).join('；') };
    }
    if (store)
        store.pin(target, content ?? '');
    return { safe: true, target, isContextFile: true, hits: [] };
}
/**
 * 认知上下文文件哈希基线库。TOFU：首次写入干净内容即建基线；
 * 之后每次校验，内容哈希变化 = 记忆被篡改（boot-time integrity check）。
 * 基线持久化为 JSON，宿主会话启动时调用 verify() 做启动自检。
 */
export class MemoryIntegrityStore {
    file;
    baseline = new Map();
    dirty = false;
    constructor(file) {
        this.file = file;
        if (file && fs.existsSync(file)) {
            try {
                const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
                for (const [k, v] of Object.entries(raw))
                    this.baseline.set(k, v);
            }
            catch { /* 基线文件损坏视为空库，重新 TOFU */ }
        }
    }
    hash(content) {
        return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    }
    /** 建立/刷新某文件的基线（仅干净内容应调用） */
    pin(target, content) {
        const key = path.resolve(target);
        this.baseline.set(key, this.hash(content));
        this.dirty = true;
        this.flush();
    }
    /** 校验当前内容是否偏离基线 */
    verify(target, content) {
        const key = path.resolve(target);
        const expected = this.baseline.get(key);
        const actual = this.hash(content);
        if (expected === undefined)
            return { status: 'untracked', target };
        if (expected !== actual)
            return { status: 'modified', target, expected, actual };
        return { status: 'ok', target };
    }
    /** 便捷：直接从磁盘读取并校验受保护文件（启动自检用） */
    verifyOnDisk(target) {
        if (!isAgentContextFile(target))
            return { status: 'untracked', target };
        if (!fs.existsSync(target))
            return { status: 'missing', target };
        return this.verify(target, fs.readFileSync(target, 'utf8'));
    }
    /** 撤销某文件基线（宿主主动确认变更后重新信任） */
    unpin(target) {
        const key = path.resolve(target);
        const had = this.baseline.delete(key);
        if (had) {
            this.dirty = true;
            this.flush();
        }
        return had;
    }
    list() { return [...this.baseline.keys()]; }
    flush() {
        if (!this.file || !this.dirty)
            return;
        try {
            fs.mkdirSync(path.dirname(this.file), { recursive: true });
            fs.writeFileSync(this.file, JSON.stringify(Object.fromEntries(this.baseline), null, 2));
            this.dirty = false;
        }
        catch { /* 持久化失败不阻断主流程，内存基线仍有效 */ }
    }
}
