import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { scoreSignals, collectSignals } from './risk.js'
import { DeferralLedger, graySignals, affinity, type DeferConfig, type DeferredEffect, type GraySignal, type LedgerEvent, type TraceEvidence, type DeferCategory } from './kairos.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { DeferralLedger, graySignals, affinity, type DeferConfig, type DeferredEffect, type GraySignal, type LedgerEvent, type TraceEvidence, type DeferCategory } from './kairos.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny' | 'defer'
  engine: 'rule' | 'secret' | 'ssrf' | 'kairos'
  tool?: string
  ruleId?: string
  reason?: string
  snippet?: string
}

export interface Interception {
  intercepted: true
  reason: string
  ruleId: string
  action: Rule['action'] | 'defer'
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
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  /** Kairos 延迟判定门（默认 null = 关闭，既有行为不变） */
  readonly kairos: DeferralLedger | null

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })
    this.kairos = config.kairos?.enabled === true ? new DeferralLedger(config.kairos) : null

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

    // 任务结算通道（Kairos 事务边界）：宿主在任务成功/失败时调用
    // 用法：ctx.bail('guardian/settle', 'commit' | 'abort') → { released, refused }
    if (this.kairos) {
      ctx.on('guardian/settle' as any, (outcome: 'commit' | 'abort') => {
        return this.settleTask(outcome)
      }, true)
    }
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

    // 引擎 6（Kairos）：把本次调用作为 trace 证据喂入扣留账本。
    // Kairos 的核心洞察：区分合法/攻击的证据出现在后续 trace 里——
    // 每次调用（无论自身是否被拦）都可能让先前扣留的灰区效应证据过阈 → 确定性 refuse。
    if (this.kairos) {
      const events = this.kairos.observe(this.collectTraceEvidence(toolName, text))
      for (const e of events) this.auditLedgerEvent(e)
    }

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

    // 引擎 6（Kairos）：灰区扣留门。deny/block 级已由上述引擎裁决（含 approve 批准的——
    // 用户批准语义优先，不重复 gating）；剩下 log 级信号正是"单点观测不可分"的灰区，
    // 并集风险分 ≥ deferLo 时不立即放行，而是扣留（defer）待后续证据/oracle/结算裁决。
    if (this.kairos) {
      const signals = graySignals(this.rules, text)
      if (signals.length && this.kairos.shouldDefer(signals)) {
        const { effect, evicted } = this.kairos.defer(toolName, text.slice(0, 300), signals)
        if (evicted) this.auditLedgerEvent(evicted)
        const score = scoreSignals(signals as any).score
        this.audit({ level: 'defer', engine: 'kairos', tool: toolName, ruleId: 'KAI-001', reason: `灰区扣留（风险分 ${score}）：${effect.reason}——证据未足，暂缓执行待裁决`, snippet: text.slice(0, 300) })
        return { intercepted: true, reason: `灰区扣留（${effect.reason}）：单点证据不足，效应已暂缓，等待 oracle 裁决或任务结算`, ruleId: 'KAI-001', action: 'defer', engine: 'kairos' }
      }
    }

    return false
  }

  /** 从一次调用文本提取 trace 证据（全部规则的命中 + 密钥/SSRF 信号） */
  private collectTraceEvidence(toolName: string, text: string): Array<Omit<TraceEvidence, 'ts'>> {
    const evs: Array<Omit<TraceEvidence, 'ts'>> = []
    for (const s of collectSignals(this.rules, text)) {
      evs.push({ category: (s.category as DeferCategory | undefined) ?? 'destructive', weight: s.weight, detail: s.ruleId })
    }
    if (this.enableSecret) {
      for (const hit of scanSecrets(text)) {
        evs.push({ category: 'credential', weight: 0.95, detail: hit.ruleId })
      }
    }
    if (this.enableSSRF) {
      for (const hit of scanNetworkTarget(text)) {
        evs.push({ category: 'network', weight: 0.8, detail: hit.ruleId })
      }
    }
    return evs
  }

  /** 账本事件落审计 */
  private auditLedgerEvent(e: LedgerEvent) {
    this.audit({ level: e.level, engine: 'kairos', tool: e.tool, ruleId: e.ruleId, reason: e.reason })
  }

  /**
   * oracle 裁决：向宿主的 'guardian/adjudicate' 监听器查询每个扣留效应的 release/refuse。
   * 约定监听器返回 { verdicts: [{ id, verdict }] }。
   * 无监听器（bail 返回 undefined）→ fail-safe 全部拒绝（有界权威：无人裁决不释放）。
   */
  adjudicate(): LedgerEvent[] {
    if (!this.kairos) return []
    this.sweepToAudit()
    const pending = this.kairos.pendingEffects()
    if (!pending.length) return []
    const res = this.ctx.bail('guardian/adjudicate' as any, pending as any)
    const events: LedgerEvent[] = []
    if (res && typeof res === 'object' && Array.isArray((res as any).verdicts)) {
      for (const v of (res as any).verdicts) {
        if (!v || typeof v.id !== 'string') continue
        if (v.verdict === 'release') events.push(...this.kairos.release([v.id], 'oracle 裁决'))
        else if (v.verdict === 'refuse') events.push(...this.kairos.refuse(v.id, 'KAI-ORACLE', 'oracle 裁决：拒绝'))
      }
    } else {
      events.push(...this.kairos.refuseAll('无 oracle 监听器，fail-safe 全部拒绝'))
    }
    for (const e of events) this.auditLedgerEvent(e)
    return events
  }

  /** 任务结算（事务边界）：commit=释放全部剩余扣留；abort=全部拒绝 */
  settleTask(outcome: 'commit' | 'abort'): { released: number; refused: number } {
    if (!this.kairos) return { released: 0, refused: 0 }
    const events = this.kairos.settle(outcome)
    for (const e of events) this.auditLedgerEvent(e)
    return {
      released: events.filter((e) => e.level === 'allow').length,
      refused: events.filter((e) => e.level === 'deny').length,
    }
  }

  /** TTL 清点并审计 */
  private sweepToAudit() {
    if (!this.kairos) return
    for (const e of this.kairos.sweep()) this.auditLedgerEvent(e)
  }

  pendingEffects(): readonly DeferredEffect[] {
    return this.kairos ? this.kairos.pendingEffects() : []
  }

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

  addRule(rule: Rule) { this.rules.push(rule) }
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
    /** Kairos 延迟判定门（默认关闭；enabled=true 后灰区效应扣留待裁决） */
    kairos?: DeferConfig & { enabled?: boolean }
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
