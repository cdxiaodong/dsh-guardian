import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { scanAnsi, sanitizeAnsi, renderConsistency } from './ansi.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scanAnsi, sanitizeAnsi, renderConsistency, ANSI_RULES } from './ansi.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS } from './risk.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 四个检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. ansi   —— 终端转义序列欺骗（隐藏文本/行覆盖/伪装链接，防审核链路被渲染欺骗）
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    enableAnsi;
    sanitizeMode;
    allowedRoots;
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.enableAnsi = config.scanTerminalEscape ?? true;
        this.sanitizeMode = config.sanitizeMode ?? 'escape';
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
        // 终端净化通道：宿主把任何要「显示给人」的文本（approve 对话框、终端回显）先过这里，
        // 保证审核员看到的与 LLM 收到的一致。用法：const safe = ctx.bail('guardian/sanitize', text)
        ctx.on('guardian/sanitize', (text) => {
            return this.sanitize(text);
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
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName, payload) {
        const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
        // 引擎 1：危险规则
        for (const rule of this.rules) {
            rule.pattern.lastIndex = 0;
            if (!rule.pattern.test(text))
                continue;
            const snippet = text.slice(0, 300);
            const hit = this.handleRule(toolName, rule, snippet, 'rule');
            if (hit)
                return hit;
        }
        // 引擎 2：密钥泄露（deny 级，含明文密钥绝不放行）
        if (this.enableSecret) {
            const secretHits = scanSecrets(text);
            if (secretHits.length) {
                const first = secretHits[0];
                this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet: text.slice(0, 300) });
                return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' };
            }
        }
        // 引擎 3：SSRF / 内网访问（block 级，走人工确认）
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
        // 引擎 4：终端转义序列欺骗（ANSI Deception Guard）。
        // 字符串 payload 优先扫原文（JSON.stringify 会把控制字符转成字面量，导致漏扫）
        if (this.enableAnsi) {
            const scanText = typeof payload === 'string' ? payload : text;
            const ansiHits = scanAnsi(scanText, { unescapeLiterals: true });
            if (ansiHits.length) {
                // 取最严重级别的第一个命中（deny > block > log）
                const order = { deny: 0, block: 1, log: 2 };
                const worst = ansiHits.reduce((a, b) => (order[a.action] <= order[b.action] ? a : b));
                const report = renderConsistency(scanText);
                const hit = this.handleRule(toolName, { id: worst.ruleId, reason: worst.description, action: worst.action }, text.slice(0, 300), 'ansi', 
                // 审核附加上下文：净化后内容 + 渲染一致性报告（隐藏比例/覆盖量）
                { hiddenRatio: report.hiddenRatio, overwrittenChars: report.overwrittenChars });
                if (hit)
                    return hit;
            }
        }
        return false;
    }
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    handleRule(toolName, rule, snippet, engine, extra) {
        if (rule.action === 'deny') {
            this.audit({ level: 'deny', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet });
            return { intercepted: true, reason: rule.reason, ruleId: rule.id, action: 'deny', engine };
        }
        if (rule.action === 'block') {
            this.audit({ level: 'block', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet });
            // 宿主提供 'guardian/approve' 监听器做人工确认，约定返回 { approved: boolean }。
            // payload 附净化后 snippet 与渲染一致性指标，防审核 UI 被终端渲染欺骗
            const res = this.ctx.bail('guardian/approve', { tool: toolName, rule, snippet, sanitized: sanitizeAnsi(snippet, 'escape'), ...extra });
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
    /** 按配置模式净化文本（guardian/sanitize 通道的实现） */
    sanitize(text) {
        return sanitizeAnsi(text, this.sanitizeMode);
    }
    audit(entry) {
        // snippet 固定 escape 可见化：审计日志被 cat/回显时，原始转义序列不会再欺骗终端
        const snippet = entry.snippet !== undefined ? sanitizeAnsi(entry.snippet, 'escape') : undefined;
        const full = { ts: new Date().toISOString(), ...entry, ...(snippet !== undefined ? { snippet } : {}) };
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
