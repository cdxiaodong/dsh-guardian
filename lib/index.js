import { Service } from 'cordis';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { DEFAULT_RULES } from './rules.js';
import { scanSecrets } from './secrets.js';
import { scanNetworkTarget } from './ssrf.js';
import { checkPath } from './path.js';
import { diffManifests, manifestFingerprint, pinManifest, toBaseline, } from './integrity.js';
export const name = 'dsh-guardian';
export { DEFAULT_RULES };
export { scanSecrets, SECRET_RULES, shannonEntropy } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS } from './risk.js';
export { canonicalJson, diffManifests, hashToolSpec, manifestFingerprint, normalizeName, diceSimilarity, pinManifest, toBaseline, } from './integrity.js';
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 三个检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 * 另有独立通道：guardian/path 路径沙箱、guardian/tools 工具清单完整性（rug-pull 检测）
 */
export class GuardianService extends Service {
    stream;
    logFile;
    rules;
    enableSecret;
    enableSSRF;
    enablePath;
    allowedRoots;
    /** 引擎 6：工具清单完整性（rug-pull 检测） */
    enableIntegrity;
    newToolPolicy;
    /** 配置 pin 的锁基线（name → hash），类似 package-lock；设置后配置即权威 */
    pinnedTools;
    /** 会话级基线：sessionId → (name → BaselineEntry)，首次观察即 pin */
    toolBaselines = new Map();
    constructor(ctx, config = {}) {
        super(ctx, 'guardian');
        this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])];
        this.enableSecret = config.scanSecrets ?? true;
        this.enableSSRF = config.scanSSRF ?? true;
        this.enablePath = config.checkPaths ?? true;
        this.allowedRoots = config.allowedRoots ?? [];
        this.enableIntegrity = config.checkToolIntegrity ?? true;
        this.newToolPolicy = config.newToolPolicy ?? 'block';
        if (config.manifestBaseline) {
            this.pinnedTools = new Map(Object.entries(Array.isArray(config.manifestBaseline)
                ? pinManifest(config.manifestBaseline)
                : config.manifestBaseline).map(([name, hash]) => [name, { hash }]));
        }
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
        // 独立的工具清单完整性通道：宿主在会话开始/收到 tools/list 刷新时调用
        // 用法：const v = ctx.bail('guardian/tools', sessionId, toolSpecs)；v.safe===false 即拒绝加载该清单
        ctx.on('guardian/tools', (sessionId, tools) => {
            return this.checkToolManifest(sessionId, tools);
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
    /**
     * 引擎 6：工具清单完整性校验（rug-pull 检测）。
     * 宿主在会话开始与每次收到 tools/list 刷新时调用（或经 guardian/tools 通道）。
     * 语义：首次观察即 pin 基线（或用配置 manifestBaseline pin）；之后任何
     * 描述/schema 变更、中途新增工具、同名仿冒都要求重新授权，deny 级直接拒绝。
     */
    checkToolManifest(sessionId, tools) {
        const fingerprint = manifestFingerprint(tools);
        if (!this.enableIntegrity)
            return { safe: true, findings: [], fingerprint };
        const state = this.toolBaselines.get(sessionId);
        if (!state && !this.pinnedTools) {
            // 首次观察：建立会话基线（"批准时刻 pin"）
            this.toolBaselines.set(sessionId, toBaseline(tools));
            this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: 'TI-000', reason: `工具清单基线已建立（${tools.length} 个工具，指纹 ${fingerprint}）` });
            return { safe: true, findings: [], fingerprint };
        }
        const baseline = this.pinnedTools ?? state;
        const findings = diffManifests(baseline, tools, { newToolPolicy: this.newToolPolicy });
        const effective = toBaseline(tools);
        const reported = [];
        let safe = true;
        for (const f of findings) {
            if (f.severity === 'deny') {
                this.audit({ level: 'deny', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: f.reason, snippet: f.detail });
                reported.push(f);
                safe = false;
            }
            else if (f.severity === 'block') {
                // 复用 guardian/approve 人工确认通道：批准即"重新授权"，基线更新为新定义
                const res = this.ctx.bail('guardian/approve', { tool: 'manifest', rule: { id: f.ruleId, reason: f.reason, action: 'block' }, snippet: f.detail ?? '' });
                const approved = typeof res === 'object' && res !== null && res.approved === true;
                if (!approved) {
                    this.audit({ level: 'block', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: `${f.reason}（未获批准）`, snippet: f.detail });
                    reported.push(f);
                    safe = false;
                    effective.delete(f.tool); // 未授权的变更不进新基线，下轮继续报警
                }
                else {
                    this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: `${f.reason}（已人工重授权）`, snippet: f.detail });
                }
            }
            else {
                this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: f.reason, snippet: f.detail });
                reported.push(f);
            }
        }
        // 会话基线更新（pin 模式下配置即权威，不改）
        if (!this.pinnedTools && safe)
            this.toolBaselines.set(sessionId, effective);
        return { safe, findings: reported, fingerprint };
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
