import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { expandTexts, TRANSFORM_LABELS } from './deobfuscate.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, obfuscationSignal, collectSignalsDeep, DEFAULT_THRESHOLDS } from './risk.js';
export { normalizeText, expandTexts, findBase64Segments, TRANSFORM_LABELS } from './deobfuscate.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 检测管线（混淆消解前置）：
 *  原文/归一化变体 →  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *                      2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *                      3. ssrf   —— 内网/元数据地址访问
 *  变体由 deobfuscate 引擎展开：零宽/Unicode Tags/bidi 剥离解码、NFKC、
 *  HTML 实体/百分号/base64/leetspeak 解码还原（decode-before-scan）。
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    enableDeobfuscation;
    escalateObfuscated;
    auditObfuscation;
    allowedRoots;
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.enableDeobfuscation = config.deobfuscate ?? true;
        this.escalateObfuscated = config.escalateObfuscated ?? true;
        this.auditObfuscation = config.auditObfuscation ?? true;
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
        const raw = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
        // 混淆消解（decode-before-scan）：原文 + 归一化/解码变体依次过引擎。
        // 原文始终第一（原文命中行为与旧版完全一致），纯净文本仅 1 个变体，零额外开销。
        const variants = this.enableDeobfuscation
            ? expandTexts(raw)
            : [{ text: raw, via: [] }];
        for (const variant of variants) {
            const hit = this.checkText(toolName, variant.text, raw, variant.via);
            if (hit)
                return hit;
        }
        // 未命中规则，但检测到了混淆变形 → 记一条审计供事后追溯（不拦截）
        if (this.enableDeobfuscation && this.auditObfuscation && variants.length > 1) {
            const via = variants[1].via;
            this.audit({
                level: 'allow', engine: 'deob', tool: toolName, ruleId: 'DEOB-INFO',
                reason: `检测到混淆变形（${via.map((t) => TRANSFORM_LABELS[t]).join('→')}），归一化后未命中规则`,
                snippet: raw.slice(0, 300), via,
            });
        }
        return false;
    }
    /** 对单个文本变体跑全部引擎。via 非空表示这是混淆消解后的变体 */
    checkText(toolName, text, raw, via) {
        // 引擎 1：危险规则
        for (const rule of this.rules) {
            rule.pattern.lastIndex = 0;
            if (!rule.pattern.test(text))
                continue;
            const snippet = raw.slice(0, 300);
            const hit = this.handleRule(toolName, rule, snippet, 'rule', via);
            if (hit)
                return hit;
        }
        // 引擎 2：密钥泄露（deny 级，含明文密钥绝不放行）
        if (this.enableSecret) {
            const secretHits = scanSecrets(text);
            if (secretHits.length) {
                const first = secretHits[0];
                this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet: raw.slice(0, 300), ...(via.length ? { via } : {}) });
                return { intercepted: true, reason: `检测到明文密钥：${first.description}${via.length ? '（混淆变形后检出）' : ''}`, ruleId: first.ruleId, action: 'deny', engine: 'secret', ...(via.length ? { via } : {}) };
            }
        }
        // 引擎 3：SSRF / 内网访问（block 级，走人工确认）
        if (this.enableSSRF) {
            const ssrfHits = scanNetworkTarget(text);
            if (ssrfHits.length) {
                const first = ssrfHits[0];
                const snippet = raw.slice(0, 300);
                const hit = this.handleRule(toolName, { id: first.ruleId, reason: first.reason, action: 'block' }, snippet, 'ssrf', via);
                if (hit)
                    return hit;
            }
        }
        return false;
    }
    /** 处理单条命中规则：deny 直接拦；block 走人工确认；混淆变体命中 log 级规则升级为 block */
    handleRule(toolName, rule, snippet, engine, via = []) {
        let action = rule.action;
        let reason = rule.reason;
        if (via.length) {
            reason = `混淆变形后命中（${via.map((t) => TRANSFORM_LABELS[t]).join('→')}）：${rule.reason}`;
            // 混淆 = 刻意规避检测的意图证据：log 升级为人工确认；
            // block/deny 保持原级（deny 已是顶，block 保留人在环），误伤可控
            if (this.escalateObfuscated && action === 'log')
                action = 'block';
        }
        const extra = via.length ? { via } : {};
        if (action === 'deny') {
            this.audit({ level: 'deny', engine, tool: toolName, ruleId: rule.id, reason, snippet, ...extra });
            return { intercepted: true, reason, ruleId: rule.id, action: 'deny', engine, ...extra };
        }
        if (action === 'block') {
            this.audit({ level: 'block', engine, tool: toolName, ruleId: rule.id, reason, snippet, ...extra });
            // 宿主提供 'guardian/approve' 监听器做人工确认，约定返回 { approved: boolean }
            const res = this.ctx.bail('guardian/approve', { tool: toolName, rule, snippet });
            const approved = typeof res === 'object' && res !== null && res.approved === true;
            if (!approved) {
                return { intercepted: true, reason: `${reason}（未获批准）`, ruleId: rule.id, action: 'block', engine, ...extra };
            }
            return false; // 已批准 → 放行本条，继续后续引擎
        }
        // log：仅记录，放行
        this.audit({ level: 'allow', engine, tool: toolName, ruleId: rule.id, reason, snippet, ...extra });
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
