import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { guardSkillWrite, scanShellSkillWrite, scanSkillPayload, scanSkillContent, collectSkillTargets, unescapeJsonText, worstSkillAction, mergeSkillHits } from './skills.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS } from './risk.js';
export { isSkillSurface, SKILL_SURFACES, SKILL_RULES, scanSkillContent, guardSkillWrite, scanShellSkillWrite, extractSkillTargets, worstSkillAction, scanSkillPayload, mergeSkillHits, collectSkillTargets, unescapeJsonText, } from './skills.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 四个检测引擎：
 *  1. skill  —— 技能面投毒（skills/commands/agents 树写入时扫描：动态上下文
 *     预执行标记、凭据外泄配对、frontmatter 元数据投毒、隐形字符）
 *  2. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  3. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  4. ssrf   —— 内网/元数据地址访问
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    enableSkills;
    allowedRoots;
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.enableSkills = config.guardSkills ?? true;
        this.allowedRoots = config.allowedRoots ?? [];
        this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log');
        this.stream = fs.createWriteStream(this.logFile, { flags: 'a' });
        // 可逆效应：插件卸载时自动关闭文件流（时空可组合-时间维度）
        ctx.effect(() => () => this.stream.end());
        // 护栏最先执行（prepend）
        ctx.on('guardian/check', (toolName, payload) => {
            return this.check(toolName, payload);
        }, true);
        // 独立的路径沙箱校验通道：宿主读写文件前调用
        // 用法：const v = ctx.bail('guardian/path', targetPath)；v.safe===false 即拦截
        ctx.on('guardian/path', (target) => {
            return this.checkPathAccess(target);
        }, true);
        // 独立的技能面写入通道：宿主写技能/命令/子代理定义文件前调用
        // 用法：const v = ctx.bail('guardian/skill', targetPath, content)；v.safe===false 即拦截
        ctx.on('guardian/skill', (target, content) => {
            return this.checkSkillWriteAccess(target, content);
        }, true);
    }
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target) {
        const verdict = checkPath(target, this.allowedRoots);
        if (!verdict.safe) {
            this.audit({ level: 'deny', engine: 'rule', tool: 'fs', ruleId: 'PATH-SANDBOX', reason: verdict.reason, snippet: target.slice(0, 300) });
        }
        return verdict;
    }
    /** 技能面写入判定：非技能面直接放行；技能面内容带毒则拦截并落审计 */
    checkSkillWriteAccess(target, content) {
        const verdict = guardSkillWrite(target, content);
        if (!verdict.safe) {
            const worst = worstSkillAction(verdict.hits);
            this.audit({ level: worst, engine: 'skill', tool: 'write', ruleId: verdict.hits[0].ruleId, reason: verdict.reason, snippet: (content ?? '').slice(0, 300) });
        }
        return verdict;
    }
    /**
     * 识别「写技能面」的工具调用并判定（guardian/check 通道内用）——两条卡位
     * 并联而非互斥（工具名像写工具 ≠ payload 不是 shell 命令，对抗审查：互斥
     * 曾让 sed -i 经 run_command 工具名整体绕过）：
     *  - 路径 A：写入类工具 + 载荷中出现技能面路径 → 对载荷做内容判定
     *    （对象形态先逐字段取解码后的字符串原值——stringify 会把换行转义，
     *    frontmatter 定界与同行配对窗口在转义文本上失明；兜底扫描前先做
     *    JSON 反转义）
     *  - 路径 B：shell 写入/变更动词或内容载体指向技能面（echo 重定向/tee/cp/
     *    heredoc/sed -i/rm/git clone/tar/unzip/解释器 -c——绕过结构化写工具
     *    的路径路由）→ SKL-012 + 命令串内嵌内容扫描
     * 闸门用 collectSkillTargets：对载荷解码后的字段原值提取目标（对抗审查：
     * \uXXXX 转义路径与 Windows 反斜杠路径在原始文本上曾整体失明）。
     */
    checkSkillSurface(toolName, payload, text) {
        const targets = collectSkillTargets(payload, text);
        if (!targets.length)
            return false;
        const snippet = text.slice(0, 300);
        const hits = [];
        if (SKILL_WRITE_TOOL_RE.test(toolName)) {
            const decoded = scanSkillPayload(payload);
            const rawText = typeof payload === 'string' ? [] : scanSkillContent(unescapeJsonText(text));
            hits.push(...decoded, ...rawText);
        }
        const shellHits = scanShellSkillWrite(text);
        hits.push(...shellHits);
        const merged = mergeSkillHits(hits);
        if (merged.length) {
            return this.interceptSkillHits(toolName, merged, snippet);
        }
        return false;
    }
    /** 技能命中 → Interception：deny 直接拦；block 走人工确认（透出全部命中 ruleId） */
    interceptSkillHits(toolName, hits, snippet) {
        const first = hits.find((h) => h.action === 'deny') ?? hits[0];
        const rest = hits.filter((h) => h !== first);
        const extra = rest.length ? `（另检出 ${rest.map((h) => h.ruleId).join('、')}，共 ${hits.length} 条）` : '';
        return this.handleRule(toolName, { id: first.ruleId, reason: first.reason + extra, action: first.action }, snippet, 'skill');
    }
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName, payload) {
        const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
        // 引擎 1：技能面投毒（skill poisoning）——置于通用规则引擎之前：恶意技能
        // 入库那一刻拦截（技能专用理由优先于通用「危险命令」理由）。写入时点的
        // 内容判定 + shell 绕过路由双卡位；载入/预执行时点已无工具调用事件可拦
        // （Datadog：`!`+反引号在 harness 渲染时预执行，模型看不到命令本体）
        if (this.enableSkills) {
            const skillHit = this.checkSkillSurface(toolName, payload, text);
            if (skillHit)
                return skillHit;
        }
        // 引擎 2：危险规则
        for (const rule of this.rules) {
            rule.pattern.lastIndex = 0;
            if (!rule.pattern.test(text))
                continue;
            const snippet = text.slice(0, 300);
            const hit = this.handleRule(toolName, rule, snippet, 'rule');
            if (hit)
                return hit;
        }
        // 引擎 3：密钥泄露（deny 级，含明文密钥绝不放行）
        if (this.enableSecret) {
            const secretHits = scanSecrets(text);
            if (secretHits.length) {
                const first = secretHits[0];
                this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet: text.slice(0, 300) });
                return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' };
            }
        }
        // 引擎 4：SSRF / 内网访问（block 级，走人工确认）
        if (this.enableSSRF) {
            const ssrfHits = scanNetworkTarget(text);
            if (ssrfHits.length) {
                const first = ssrfHits[0];
                const snippet = text.slice(0, 300);
                const hit = this.handleRule(toolName, { id: first.ruleId, reason: first.reason, action: 'block' }, snippet, 'ssrf');
                if (hit)
                    return hit;
            }
        }
        return false;
    }
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    handleRule(toolName, rule, snippet, engine) {
        if (rule.action === 'deny') {
            this.audit({ level: 'deny', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet });
            return { intercepted: true, reason: rule.reason, ruleId: rule.id, action: 'deny', engine };
        }
        if (rule.action === 'block') {
            this.audit({ level: 'block', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet });
            // 宿主提供 'guardian/approve' 监听器做人工确认，约定返回 { approved: boolean }
            const res = this.ctx.bail('guardian/approve', { tool: toolName, rule, snippet });
            const approved = typeof res === 'object' && res !== null && res.approved === true;
            if (!approved) {
                return { intercepted: true, reason: `${rule.reason}（未获批准）`, ruleId: rule.id, action: 'block', engine };
            }
            return false; // 已批准 → 放行本条，继续后续引擎
        }
        // log：仅记录，放行
        this.audit({ level: 'allow', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet });
        return false;
    }
    audit(entry) {
        const full = { ts: new Date().toISOString(), ...entry };
        this.stream.write(JSON.stringify(full) + '\n');
    }
    readAudit(limit = 20) {
        if (!fs.existsSync(this.logFile))
            return [];
        const lines = fs.readFileSync(this.logFile, 'utf8').trim().split('\n').filter(Boolean);
        return lines.slice(-limit)
            .map((l) => { try {
            return JSON.parse(l);
        }
        catch {
            return null;
        } })
            .filter(Boolean);
    }
    addRule(rule) { this.rules.push(rule); }
    listRules() { return [...this.rules]; }
}
export const provide = ['guardian'];
export function apply(ctx, config) {
    ctx.plugin(GuardianService, config);
}
// ── 技能写入识别辅助 ─────────────────────────────────────────
/** 写入/安装类工具名识别（结构化写路径 A 的门卫） */
const SKILL_WRITE_TOOL_RE = /write|edit|patch|create|save|update|store|append|install|sync|skill|command|agent/i;
