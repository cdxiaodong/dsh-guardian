import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { ChainEngine, KILL_CHAINS } from './chain.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS } from './risk.js';
export { ChainEngine, KILL_CHAINS } from './chain.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  10. chain —— 攻击链时序检测（跨调用 kill-chain 状态机，单步放行 ≠ 序列无害）
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    enableChain;
    allowedRoots;
    chainEngine;
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.enableChain = config.trackChains ?? true;
        this.allowedRoots = config.allowedRoots ?? [];
        this.chainEngine = new ChainEngine(config.chains ?? KILL_CHAINS, this.rules);
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
        const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
        // 一遍收集全部信号（正则均无 /g 标志，无 lastIndex 状态污染）
        const ruleHits = this.rules.filter((rule) => { rule.pattern.lastIndex = 0; return rule.pattern.test(text); });
        const secretHits = this.enableSecret ? scanSecrets(text) : [];
        const ssrfHits = this.enableSSRF ? scanNetworkTarget(text) : [];
        // 引擎 1~3：单次调用静态检测
        const result = this.runStaticEngines(toolName, text, ruleHits, secretHits, ssrfHits);
        // 引擎 10：攻击链时序检测——无论单步是否拦截都推进状态机
        // （被拦截的尝试同样暴露攻击意图序列：单步放行 ≠ 序列无害）
        if (this.enableChain) {
            const categories = new Set();
            for (const rule of ruleHits)
                if (rule.category)
                    categories.add(rule.category);
            if (secretHits.length)
                categories.add('credential');
            if (ssrfHits.length)
                categories.add('network');
            const verdicts = this.chainEngine.observe({
                tool: toolName,
                text: text.slice(0, 500),
                ruleIds: [...ruleHits.map((r) => r.id), ...secretHits.map((s) => s.ruleId), ...ssrfHits.map((s) => s.ruleId)],
                categories: [...categories],
                intercepted: result !== false,
            });
            if (verdicts.length)
                return this.handleChainVerdicts(toolName, verdicts, result);
        }
        return result;
    }
    /** 引擎 1~3：危险规则 / 密钥泄露 / SSRF（行为与旧版逐引擎判定一致） */
    runStaticEngines(toolName, text, ruleHits, secretHits, ssrfHits) {
        const snippet = text.slice(0, 300);
        // 引擎 1：危险规则
        for (const rule of ruleHits) {
            const hit = this.handleRule(toolName, rule, snippet, 'rule');
            if (hit)
                return hit;
        }
        // 引擎 2：密钥泄露（deny 级，含明文密钥绝不放行）
        if (secretHits.length) {
            const first = secretHits[0];
            this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet });
            return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' };
        }
        // 引擎 3：SSRF / 内网访问（block 级，走人工确认）
        if (ssrfHits.length) {
            const first = ssrfHits[0];
            const hit = this.handleRule(toolName, { id: first.ruleId, reason: first.reason, action: 'block' }, snippet, 'ssrf');
            if (hit)
                return hit;
        }
        return false;
    }
    /** 引擎 10 达成后的处置：链 deny 覆盖一切；链 block 在单步放行时走人工确认 */
    handleChainVerdicts(toolName, verdicts, result) {
        for (const v of verdicts) {
            this.audit({
                level: v.action === 'deny' ? 'deny' : 'block',
                engine: 'chain',
                tool: toolName,
                ruleId: v.chainId,
                reason: `攻击链${v.trigger === 'complete' ? '完整达成' : `达升级阈值（${Math.round(v.progress * 100)}%）`}: ${v.name}`,
                snippet: v.story.join(' → ').slice(0, 300),
            });
        }
        // 决策取最严 verdict：deny 优先，其次 severity
        const top = [...verdicts].sort((a, b) => rankChain(b) - rankChain(a))[0];
        if (top.action === 'deny' && (result === false || result.action !== 'deny')) {
            return { intercepted: true, reason: `攻击链完整达成：${top.name}。${top.story.join(' → ')}`, ruleId: top.chainId, action: 'deny', engine: 'chain' };
        }
        if (!result) {
            // 链 block：走 guardian/approve，审批者可看到完整攻击叙事
            const res = this.ctx.bail('guardian/approve', { tool: toolName, chain: top, snippet: top.story.join(' → ') });
            const approved = typeof res === 'object' && res !== null && res.approved === true;
            if (!approved) {
                return { intercepted: true, reason: `攻击链达成（需人工确认）：${top.name}。${top.story.join(' → ')}`, ruleId: top.chainId, action: 'block', engine: 'chain' };
            }
        }
        return result;
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
    /** 攻击链进度快照（态势查询） */
    chainProgress() { return this.chainEngine.progress(); }
    /** 重置攻击链状态机（全部或指定链） */
    resetChain(chainId) { this.chainEngine.reset(chainId); }
}
/** 链 verdict 严重度排序：deny > block-critical > block-high */
function rankChain(v) {
    return v.action === 'deny' ? 2 : v.severity === 'critical' ? 1 : 0;
}
export const provide = ['guardian'];
export function apply(ctx, config) {
    ctx.plugin(GuardianService, config);
}
