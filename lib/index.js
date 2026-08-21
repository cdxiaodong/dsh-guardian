import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { parsePolicyYaml, evaluatePolicies } from './policy.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS } from './risk.js';
export { parsePolicyYaml, compilePolicies, evaluatePolicies, globToRegExp } from './policy.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 检测引擎（按顺序）：
 *  0. policy —— YAML 声明式策略（工具名通配 + 参数正则 + allow 白名单豁免，支持热加载）
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入 / RCE 反序列化正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    allowedRoots;
    /** 已编译策略（按 priority 升序），来自 YAML 策略文件 */
    policies = [];
    policyPath;
    unwatchPolicy;
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.allowedRoots = config.allowedRoots ?? [];
        this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log');
        this.stream = fs.createWriteStream(this.logFile, { flags: 'a' });
        // 可逆效应：插件卸载时自动关闭文件流、停掉策略热加载监听（时空可组合-时间维度）
        ctx.effect(() => () => {
            this.stream.end();
            this.unwatchPolicy?.();
        });
        // YAML 策略文件：提供即加载，默认开启热加载（fs.watchFile 轮询，跨编辑器保存可靠）
        if (config.policyFile) {
            this.loadPolicyFile(config.policyFile);
            if (config.watchPolicy !== false)
                this.watchPolicyFile(config.policyFile);
        }
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
        // 引擎 0：YAML 声明式策略（Edictum 式工具契约，优先于内置规则）
        if (this.policies.length) {
            const policy = evaluatePolicies(this.policies, toolName, text);
            if (policy) {
                const snippet = text.slice(0, 300);
                if (policy.action === 'allow') {
                    // 显式白名单：豁免内置规则引擎，但保留密钥扫描（明文凭据任何场景都不该外泄）
                    this.audit({ level: 'allow', engine: 'policy', tool: toolName, ruleId: policy.id, reason: policy.reason ?? '策略白名单放行', snippet });
                    if (this.enableSecret) {
                        const secretHits = scanSecrets(text);
                        if (secretHits.length) {
                            const first = secretHits[0];
                            this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet });
                            return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' };
                        }
                    }
                    return false;
                }
                // allow 已在上面单独处理，此处只剩 deny/block/log
                const hit = this.handleRule(toolName, { id: policy.id, reason: policy.reason ?? `策略 ${policy.id} 命中`, action: policy.action }, snippet, 'policy');
                if (hit)
                    return hit;
            }
        }
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
    /** 加载 YAML 策略文件（解析+校验+立即生效）。失败保留旧策略并返回 errors——热加载安全回退 */
    loadPolicyFile(file) {
        this.policyPath = file;
        let text;
        try {
            text = fs.readFileSync(file, 'utf8');
        }
        catch (e) {
            this.audit({ level: 'deny', engine: 'policy', reason: `策略文件读取失败：${e.message}，保留当前 ${this.policies.length} 条策略`, ruleId: 'POLICY-LOAD' });
            return { ok: false, count: this.policies.length, errors: [`读取失败：${e.message}`] };
        }
        const { policies, errors } = parsePolicyYaml(text);
        if (errors.length) {
            this.audit({ level: 'deny', engine: 'policy', reason: `策略文件校验失败（${errors.length} 处），保留当前 ${this.policies.length} 条旧策略`, ruleId: 'POLICY-LOAD', snippet: errors.join('；').slice(0, 300) });
            return { ok: false, count: this.policies.length, errors };
        }
        this.policies = policies;
        return { ok: true, count: policies.length, errors: [] };
    }
    /** 重新加载当前策略文件 */
    reloadPolicy() {
        if (!this.policyPath)
            return { ok: false, count: 0, errors: ['未配置策略文件'] };
        return this.loadPolicyFile(this.policyPath);
    }
    /** 当前生效的策略列表（已按 priority 排序） */
    listPolicies() { return [...this.policies]; }
    /** 监听策略文件变化自动热加载；每次重载结果经 'guardian/policy-loaded' 事件广播（时空可组合-空间维度） */
    watchPolicyFile(file) {
        const listener = (curr, prev) => {
            if (curr.mtimeMs === prev.mtimeMs)
                return;
            const result = this.loadPolicyFile(file);
            this.ctx.emit('guardian/policy-loaded', result);
        };
        fs.watchFile(file, { interval: 1000 }, listener);
        this.unwatchPolicy = () => fs.unwatchFile(file, listener);
    }
}
export const provide = ['guardian'];
export function apply(ctx, config) {
    ctx.plugin(GuardianService, config);
}
