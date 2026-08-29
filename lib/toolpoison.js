/**
 * 工具定义毒性扫描引擎（Tool-Definition Poisoning Scanner / 确定性版 mcp-scan）。
 *
 * 威胁模型（Invariant Labs 2025-04「Tool Poisoning Attacks」披露）：
 * **工具描述就是 prompt** —— MCP 客户端把所有已连接 server 的工具描述、参数
 * schema 说明以全信任注入模型上下文，工具元数据与指令流之间没有沙箱；一个恶意
 * server 可以借描述里的隐藏指令毒化其他合法 server 工具的行为（跨 server 注入）。
 * 典型载体：描述中藏「ignore previous instructions」、Unicode Tags 区隐形指令、
 * HTML 注释、双向文本（RLO）视觉伪装、inputSchema 嵌套字段的说明文本。
 *
 * 与工具清单完整性引擎（feat/2026-08-24）互补，二者拼成完整防线：
 *  - 完整性 = 定义「变没变」（批准时刻 pin hash，运行时校验漂移）
 *  - 本引擎 = 定义「有没有毒」（首次接触即扫内容，零基线依赖）
 *
 * mcp-scan（Invariant Labs）用 LLM 做离线扫描；本引擎做**确定性、无 LLM、可单测**
 * 的运行时常驻版本，并附带 Unicode Tags「显影」——把隐形注入还原成可读明文供审计。
 *
 * 借鉴：Invariant Labs mcp-scan 与 Tool Poisoning PoC、OWASP MCP03:2025
 * (Tool Poisoning)、arXiv:2503.24652（ARTMS Tags-poisoning 提示注入）。
 */
// ── 隐形字符显影 ────────────────────────────────────────
/** 零宽与不可见控制字符（ZWSP/ZWNJ/ZWJ/LRM/RLM/WJ/BOM 等）*/
const INVISIBLE_CTRL = /[\u200B-\u200F\u2060-\u2064\uFEFF]/;
/** 双向覆盖字符（RLO/LRO/RLI/LRI…）：视觉伪装专用，合法描述零理由出现 */
const BIDI_CTRL = /[\u202A-\u202E\u2066-\u2069]/;
/** Unicode Tags 区（U+E0000–U+E007F）：ASCII 标签编码，渲染不可见但模型可读 */
const TAGS_RANGE = /[\u{E0000}-\u{E007F}]/u;
/**
 * Unicode Tags「显影」：U+E0020–U+E007E 映射回可见 ASCII（code − 0xE0000），
 * 语言标签（U+E0001）与取消符（U+E007F）丢弃。把隐形注入变成人眼可读明文。
 */
export function developTags(s) {
    let out = '';
    for (const ch of s) {
        const c = ch.codePointAt(0);
        if (c >= 0xE0020 && c <= 0xE007E)
            out += String.fromCharCode(c - 0xE0000);
        else if (c === 0xE0001 || c === 0xE007F)
            continue;
        else
            out += ch;
    }
    return out;
}
/** 提取文本中所有 Tags 区字符并显影为 ASCII（判定「藏了什么」用） */
export function tagsPayload(s) {
    let out = '';
    for (const ch of s) {
        const c = ch.codePointAt(0);
        if (c >= 0xE0020 && c <= 0xE007E)
            out += String.fromCharCode(c - 0xE0000);
    }
    return out;
}
/** 截断片段（显影后再截，保证审计里看到的是可读内容） */
function excerptOf(s, max = 160) {
    const t = s.replace(/\s+/g, ' ').trim();
    return t.length > max ? t.slice(0, max) + '…' : t;
}
// ── 工具名规范化（同形异码抢注检测）─────────────────────
/** 常见西里尔/希腊同形字符 → ASCII（防 seаrch 抢注 search 这类攻击） */
const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'Ь': 'b',
    'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ϲ': 'c', 'υ': 'u', 'χ': 'x', 'ι': 'i', 'κ': 'k', 'ν': 'n',
};
/** 工具名规范化：NFKC（全角→半角）+ 去零宽/双向控制 + 同形折叠 + 小写 */
export function normalizeToolName(name) {
    let s = name.normalize('NFKC')
        .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, '')
        .toLowerCase();
    s = s.replace(/[а-яА-Яα-ωϲ]/g, (ch) => CONFUSABLES[ch] ?? ch);
    return s;
}
/**
 * 描述文本毒性规则。所有正则不带 /g，避免 lastIndex 状态污染。
 * 分级原则：确定性恶意模式（指令覆盖/角色伪装/隐形载体/瞒用户）= poison；
 * 可疑但存在合法用例（指令头措辞、敏感源引用）= suspect 走人工确认。
 */
export const TOOLPOISON_RULES = [
    // TPD-001 指令覆盖注入 —— Invariant PoC 原文模式
    { id: 'TPD-001', severity: 'poison', reason: '指令覆盖注入（ignore/disregard previous instructions）',
        test: /\b(ignore|disregard|forget|override|bypass)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|preceding|all|your|system|developer|safety)\b[^.!?\n]{0,30}\b(instruction|prompt|rule|directive|message|guideline|training)s?\b/i },
    { id: 'TPD-001', severity: 'poison', reason: '指令覆盖注入（重设任务/真实指令）',
        test: /(new|your\s+real|actual|true|updated)\s+(instructions?|task|objective|system\s+prompt)\s*[:：]/i },
    // TPD-002 系统角色伪装 —— 冒充系统/开发者消息
    { id: 'TPD-002', severity: 'poison', reason: '系统角色伪装（行首方括号权限头）',
        test: /^\s*\[(SYSTEM|ADMIN|DEVELOPER|OVERRIDE|INTERNAL|SECRET)\]\s*[:：]?/im },
    { id: 'TPD-002', severity: 'poison', reason: '系统角色伪装（system prompt / developer message 声明）',
        test: /\b(system\s+prompt|developer\s+message|admin\s+note|internal\s+instructions?)\s*[:：]/i },
    { id: 'TPD-002', severity: 'poison', reason: '系统角色伪装（chat 模板 token 越权）',
        test: /<\|(im_start|im_end|system|endoftext|assistant)\|>|\b(BEGIN|END)\s+(SYSTEM|INSTRUCTION|ADMIN|OVERRIDE)\s+(PROMPT|MESSAGE|BLOCK)/i },
    { id: 'TPD-002', severity: 'poison', reason: '越狱/角色逃逸（DAN、developer mode 等）',
        test: /(you\s+are\s+now|act\s+as|enter|enable|activate)\s+[^.\n]{0,20}(DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|jailbreak|unrestricted|unfiltered|uncensored)/i },
    // TPD-003 敏感源外传指使 —— 读取敏感数据并放入响应/外发
    { id: 'TPD-003', severity: 'poison', reason: '指使读取敏感数据并放入响应（外传指使）',
        test: (dev) => SENSITIVE_SOURCE.test(dev) && /(\bresponse\b|\breply\b|\banswer\b|\boutput\b|\bresult\b|\binclude\b|\bappend\b|\battach\b|\bsend\b|\bpost\b|\bupload\b|\bwebhook\b|\bcurl\b|\bhttp)/i.test(dev.slice(Math.max(0, firstMatchIndex(dev, SENSITIVE_SOURCE) - 40), firstMatchIndex(dev, SENSITIVE_SOURCE) + 120)) },
    { id: 'TPD-003', severity: 'suspect', reason: '描述中含敏感路径/凭据读取指令（可能是合法安全工具，需人工确认）',
        test: (dev) => SENSITIVE_SOURCE.test(dev) },
    // TPD-004 隐形指令载体 —— Tags 区 / 零宽 / 双向覆盖 / HTML 注释
    { id: 'TPD-004', severity: 'poison', reason: 'Unicode Tags 区隐形字符，显影出可读指令（渲染不可见但模型可读）',
        test: (_dev, raw) => /[a-zA-Z]{3,}/.test(tagsPayload(raw)) },
    { id: 'TPD-004', severity: 'suspect', reason: '含 Unicode Tags 区字符（显影未见可读内容，仍属异常）',
        test: (_dev, raw) => TAGS_RANGE.test(raw) },
    { id: 'TPD-004', severity: 'suspect', reason: '含零宽/不可见控制字符',
        test: (_dev, raw) => INVISIBLE_CTRL.test(raw) },
    { id: 'TPD-004', severity: 'poison', reason: '双向文本控制字符（RLO 等），视觉伪装专用',
        test: (_dev, raw) => BIDI_CTRL.test(raw) },
    { id: 'TPD-004', severity: 'poison', reason: 'HTML 注释藏指令（渲染不可见但进入模型上下文）',
        test: (dev) => /<!--[\s\S]*?(ignore|instruction|system|assistant|must|do\s+not|note\s+to|secret|hidden)[\s\S]*?-->/i.test(dev) },
    { id: 'TPD-004', severity: 'suspect', reason: '含 HTML 注释（内容未见指令词，建议人工查看）',
        test: /<!--[\s\S]+-->/ },
    // TPD-005 指令头伪装 —— 换行后新起“指令块”（合法文档也用 IMPORTANT，须绑定第二人称祈使）
    { id: 'TPD-005', severity: 'suspect', reason: '指令头伪装（IMPORTANT/NOTE 后跟针对模型的祈使句）',
        test: /(^|\n)\s*(IMPORTANT|NOTE|WARNING|CAUTION|INSTRUCTIONS?|CONTEXT|ADDENDUM|P\.S\.?|SYSTEM)\s*[:：][^\n]{0,200}\b(you\s+(must|should|always|never|need|are|now)|do\s+not\s+(tell|mention|show|reveal|inform|disclose)|don'?t\s+(tell|mention|show|reveal))/i },
    // TPD-007 瞒用户指令 —— 「不要告诉用户」是投毒描述的签名特征
    { id: 'TPD-007', severity: 'poison', reason: '瞒用户指令（do not tell the user / conceal from user）',
        test: /(do\s+not|don'?t)\s+(tell|mention|show|reveal|inform|disclose|alert)\b[^.!?\n]{0,40}\b(user|human|owner|caller|person)\b|conceal\w*\b[^.!?\n]{0,40}\bfrom\s+the\s+user|without\s+(telling|informing|alerting)\s+the\s+user/i },
];
/** 敏感源锚点：SSH/AWS 凭据、环境文件、密钥与秘密的读取指向 */
const SENSITIVE_SOURCE = /(~\/\.ssh|\/\.ssh|\.env\b|\.aws\/credentials|\/etc\/shadow|\bid_rsa\b|\bid_ed25519\b|authorized_keys|\.bash_history|\.netrc|\.kube\/config|api[_ -]?keys?\b|private\s+keys?\b|environment\s+variables?\b|os\.environ)/i;
/** 找到正则首个命中位置（无 g 标志下用 search） */
function firstMatchIndex(s, re) {
    const m = s.search(re);
    return m === -1 ? s.length : m;
}
/** 深度遍历 schema，收集会进入模型上下文的字符串字段（description/title/default） */
export function collectSchemaTexts(schema, base = 'schema', out = [], depth = 0) {
    if (depth > 8 || schema == null || typeof schema !== 'object')
        return out;
    if (Array.isArray(schema)) {
        schema.forEach((v, i) => collectSchemaTexts(v, `${base}[${i}]`, out, depth + 1));
        return out;
    }
    for (const [k, v] of Object.entries(schema)) {
        const p = `${base}.${k}`;
        if ((k === 'description' || k === 'title' || k === 'default') && typeof v === 'string') {
            out.push({ path: p, text: v });
        }
        else {
            collectSchemaTexts(v, p, out, depth + 1);
        }
    }
    return out;
}
// ── 主扫描入口 ──────────────────────────────────────────
function scanText(rawText, where, findings) {
    const developed = developTags(rawText);
    for (const rule of TOOLPOISON_RULES) {
        const hit = typeof rule.test === 'function' ? rule.test(developed, rawText) : rule.test.test(developed);
        if (!hit)
            continue;
        // 同一规则在同一段文本只记一次；TPD-003 poison 命中时不再重复记 suspect 条目
        if (findings.some((f) => f.ruleId === rule.id && f.where === where))
            continue;
        if (rule.id === 'TPD-003' && rule.severity === 'suspect'
            && findings.some((f) => f.ruleId === 'TPD-003' && f.severity === 'poison' && f.where === where))
            continue;
        findings.push({ ruleId: rule.id, severity: rule.severity, where, reason: rule.reason, excerpt: excerptOf(developed) });
    }
}
/** 扫描单个工具定义：name 抢注 + description + schema 嵌套字段 */
export function scanToolDefinition(def, opts = {}) {
    const findings = [];
    // 名称维度（TPD-006）：抢注/同形异码/隐形字符
    if (INVISIBLE_CTRL.test(def.name) || TAGS_RANGE.test(def.name)) {
        findings.push({ ruleId: 'TPD-006', severity: 'poison', where: 'name', reason: '工具名含隐形字符（零宽/Tags/双向控制）', excerpt: excerptOf(developTags(JSON.stringify(def.name))) });
    }
    if (opts.reservedNames?.length) {
        const incoming = normalizeToolName(def.name);
        for (const reserved of opts.reservedNames) {
            if (incoming && incoming === normalizeToolName(reserved)) {
                findings.push({ ruleId: 'TPD-006', severity: 'poison', where: 'name', reason: `工具名抢注：与保留工具「${reserved}」同名（含同形异码折叠后）`, excerpt: def.name });
                break;
            }
        }
    }
    // 描述维度
    if (def.description)
        scanText(def.description, 'description', findings);
    // schema 嵌套字段维度（Invariant PoC 把指令藏在 inputSchema.properties.x.description）
    for (const field of collectSchemaTexts(def.inputSchema)) {
        scanText(field.text, field.path, findings);
    }
    return findings;
}
/** findings → 判定：poison 存在即 unsafe；suspect 存在则要求人工复核 */
export function verdictOf(findings) {
    return {
        safe: !findings.some((f) => f.severity === 'poison'),
        requiresReview: findings.some((f) => f.severity === 'suspect'),
        findings,
    };
}
