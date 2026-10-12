import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { EvolutionTracker, validateRuleChange, type RuleProposal, type ShadowRule, type ValidationVerdict, type EvolutionConfig } from './evolution.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { EvolutionTracker, validateRuleChange, type RuleProposal, type RuleProposalType, type ShadowRule, type ValidationVerdict, type EvolutionConfig } from './evolution.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'evolution'
  tool?: string
  ruleId?: string
  reason?: string
  snippet?: string
}

export interface Interception {
  intercepted: true
  reason: string
  ruleId: string
  action: Rule['action']
  engine: AuditEntry['engine']
}

declare module 'cordis' {
  interface Context {
    guardian: GuardianService
  }
}

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
 *
 * 引擎 6（evolution）—— 规则演化验证（VEPA）：守卫规则库自身，
 * addRule 必须过三道门（结构验证 → 影子观察 → 证据感知晋升）。
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  private evolution: EvolutionTracker
  private evolutionCfg: EvolutionConfig

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.evolution = new EvolutionTracker(config.evolution)
    this.evolutionCfg = config.evolution ?? {}
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })

    // 可逆效应：插件卸载时自动关闭文件流（时空可组合-时间维度）
    ctx.effect(() => () => this.stream.end())

    // 护栏最先执行（prepend）
    ctx.on('guardian/check' as any, (toolName: string, payload: unknown) => {
      return this.check(toolName, payload)
    }, true)

    // 独立的路径沙箱校验通道：宿主读写文件前调用
    // 用法：const v = ctx.bail('guardian/path', targetPath)；v.safe===false 即拦截
    ctx.on('guardian/path' as any, (target: string) => {
      return this.checkPathAccess(target)
    }, true)
  }

  /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
  checkPathAccess(target: string) {
    const verdict = checkPath(target, this.allowedRoots)
    if (!verdict.safe) {
      this.audit({ level: 'deny', engine: 'rule', tool: 'fs', ruleId: 'PATH-SANDBOX', reason: verdict.reason, snippet: target.slice(0, 300) })
    }
    return verdict
  }

  /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
  check(toolName: string, payload: unknown): Interception | false {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {})

    // 引擎 6（VEPA 权威层）：影子观察 + 证据感知自动晋升，先于静态判定。
    // 记账无条件原则：无论本次判定结果如何，影子规则都积累部署证据。
    // 证据凑齐的当下晋升并生效（本次调用即被新规则判定）——晋升只发生
    // 一次（影子条目随晋升摘除），不存在 observe→promote→apply 的循环。
    this.autoPromote(toolName, text)

    // 引擎 1：危险规则
    for (const rule of this.rules) {
      rule.pattern.lastIndex = 0
      if (!rule.pattern.test(text)) continue
      const snippet = text.slice(0, 300)
      const hit = this.handleRule(toolName, rule, snippet, 'rule')
      if (hit) return hit
    }

    // 引擎 2：密钥泄露（deny 级，含明文密钥绝不放行）
    if (this.enableSecret) {
      const secretHits = scanSecrets(text)
      if (secretHits.length) {
        const first = secretHits[0]
        this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet: text.slice(0, 300) })
        return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' }
      }
    }

    // 引擎 3：SSRF / 内网访问（block 级，走人工确认）
    if (this.enableSSRF) {
      const ssrfHits = scanNetworkTarget(text)
      if (ssrfHits.length) {
        const first = ssrfHits[0]
        const snippet = text.slice(0, 300)
        const hit = this.handleRule(toolName, { id: first.ruleId, reason: first.reason, action: 'block' }, snippet, 'ssrf')
        if (hit) return hit
      }
    }

    return false
  }

  /** 影子观察 + 证据达标的自动晋升（VEPA authority layer 的本地实现） */
  private autoPromote(toolName: string, text: string): void {
    if (this.evolutionCfg.enabled === false) return
    const hits = this.evolution.observe(toolName, text)
    for (const shadow of hits) {
      const promoted = this.evolution.promoteIfReady(shadow.shadowId)
      if (promoted) {
        const applied = this.applyPromotion(promoted)
        this.audit({
          level: promoted.type === 'remove' ? 'block' : 'allow',
          engine: 'evolution',
          ruleId: 'EVL-004',
          reason: `影子规则证据达标自动晋升（applied=${applied}）：${promoted.rule?.id ?? promoted.targetId}`,
          snippet: `hits=${shadow.hits} tools=${shadow.tools.size}`,
        })
      }
    }
  }

  /**
   * 规则进化提案（Gate 1+2）：验证 + 入影子库。
   * 返回 ShadowRule=通过验证进入观察；ValidationVerdict(ok=false)=被拒。
   */
  submitRuleProposal(proposal: RuleProposal): ShadowRule | ValidationVerdict {
    const result = this.evolution.submit(proposal, this.rules)
    if ('ok' in result && 'code' in result) {
      const verdict = result as ValidationVerdict
      this.audit({
        level: 'block',
        engine: 'evolution',
        ruleId: verdict.code ?? 'EVL-001',
        reason: verdict.reason,
        snippet: proposal.rule?.id ?? proposal.targetId ?? '',
      })
      return verdict
    }
    const shadow = result as ShadowRule
    this.audit({
      level: 'allow',
      engine: 'evolution',
      ruleId: 'EVL-000',
      reason: `提案通过验证进入影子观察：${shadow.proposal.rule?.id ?? shadow.proposal.targetId ?? '(remove)'}`,
      snippet: shadow.shadowId,
    })
    return shadow
  }

  /**
   * 证据感知晋升（Gate 3）：达标返回提案并由宿主决定应用；
   * remove 型提案永不被自动晋升，须 forcePromote 人工转正。
   */
  promoteShadowRule(shadowId: string): RuleProposal | null {
    return this.evolution.promoteIfReady(shadowId)
  }

  /** 人工强制转正（跳过证据门槛；remove 提案的唯一通道） */
  forcePromoteShadowRule(shadowId: string): RuleProposal | null {
    return this.evolution.forcePromote(shadowId)
  }

  /**
   * 应用已晋升的提案到正式规则库。
   * 这是唯一改写 this.rules 的进化出口——所有变更都过了三道门。
   */
  applyPromotion(proposal: RuleProposal): boolean {
    if (proposal.type === 'add' && proposal.rule) {
      this.rules.push(proposal.rule)
      return true
    }
    if (proposal.type === 'update' && proposal.rule && proposal.targetId) {
      const idx = this.rules.findIndex(r => r.id === proposal.targetId)
      if (idx >= 0) { this.rules[idx] = proposal.rule; return true }
      return false
    }
    if (proposal.type === 'remove') {
      const targetId = proposal.targetId ?? proposal.rule?.id
      if (!targetId) return false
      const idx = this.rules.findIndex(r => r.id === targetId)
      if (idx >= 0) { this.rules.splice(idx, 1); return true }
      return false
    }
    return false
  }

  /** 影子库快照（宿主观察 API） */
  shadowRules(): ShadowRule[] { return this.evolution.shadowRules() }

  /** 影子规则证据读数（宿主观察 API） */
  shadowEvidence(shadowId: string): { hits: number; tools: number; ageMs: number } | null {
    return this.evolution.evidenceOf(shadowId)
  }

  /** 影子 TTL 清理（宿主可定期调用；返回退役规则 id） */
  sweepShadowRules(): string[] { return this.evolution.sweepExpired() }

  /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
  private handleRule(toolName: string, rule: { id: string; reason: string; action: Rule['action'] }, snippet: string, engine: AuditEntry['engine']): Interception | false {
    if (rule.action === 'deny') {
      this.audit({ level: 'deny', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
      return { intercepted: true, reason: rule.reason, ruleId: rule.id, action: 'deny', engine }
    }
    if (rule.action === 'block') {
      this.audit({ level: 'block', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
      // 宿主提供 'guardian/approve' 监听器做人工确认，约定返回 { approved: boolean }
      const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, rule, snippet } as any)
      const approved = typeof res === 'object' && res !== null && (res as any).approved === true
      if (!approved) {
        return { intercepted: true, reason: `${rule.reason}（未获批准）`, ruleId: rule.id, action: 'block', engine }
      }
      return false   // 已批准 → 放行本条，继续后续引擎
    }
    // log：仅记录，放行
    this.audit({ level: 'allow', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
    return false
  }

  audit(entry: Omit<AuditEntry, 'ts'>) {
    const full: AuditEntry = { ts: new Date().toISOString(), ...entry }
    this.stream.write(JSON.stringify(full) + '\n')
  }

  readAudit(limit = 20): AuditEntry[] {
    if (!fs.existsSync(this.logFile)) return []
    const lines = fs.readFileSync(this.logFile, 'utf8').trim().split('\n').filter(Boolean)
    return lines.slice(-limit)
      .map((l) => { try { return JSON.parse(l) } catch { return null } })
      .filter(Boolean) as AuditEntry[]
  }

  /**
   * 运行时加规则（保持 main 兼容签名，但加 Gate-1 验证）。
   * 结构/武器化检查失败时抛错——addRule 是宿主的同步可信通道，
   * 坏规则必须立刻炸出来而不是悄悄生效。
   * 注意：addRule 走的是"宿主显式添加"语义（等同声明式配置），不进影子
   * 观察期——影子门槛只约束"来源不可信的进化提案"（submitRuleProposal）。
   */
  addRule(rule: Rule): this {
    const verdict = validateRuleChange({ type: 'add', rule }, this.rules)
    if (!verdict.ok) {
      throw new Error(`[dsh-guardian] addRule 被演化验证器拒绝（${verdict.code}）：${verdict.reason}`)
    }
    this.rules.push(rule)
    return this
  }
  listRules(): Rule[] { return [...this.rules] }
}

export namespace GuardianService {
  export interface Config {
    logFile?: string
    rules?: Rule[]
    /** 是否启用密钥泄露扫描（默认 true） */
    scanSecrets?: boolean
    /** 是否启用 SSRF/内网访问扫描（默认 true） */
    scanSSRF?: boolean
    /** 是否启用路径沙箱校验（默认 true） */
    checkPaths?: boolean
    /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
    allowedRoots?: string[]
    /** 规则演化验证（VEPA 三道门）配置 */
    evolution?: EvolutionConfig
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
