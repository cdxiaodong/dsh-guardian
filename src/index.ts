import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { ChainEngine, KILL_CHAINS, type ChainEvent, type ChainPattern, type ChainVerdict } from './chain.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { ChainEngine, KILL_CHAINS, type ChainEvent, type ChainPattern, type ChainProgress, type ChainVerdict, type StageMatcher } from './chain.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'chain'
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
 * 检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  10. chain —— 攻击链时序检测（跨调用 kill-chain 状态机，单步放行 ≠ 序列无害）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private enableChain: boolean
  private allowedRoots: string[]
  private chainEngine: ChainEngine

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.enableChain = config.trackChains ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.chainEngine = new ChainEngine(config.chains ?? KILL_CHAINS, this.rules)
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
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

    // 一遍收集全部信号（正则均无 /g 标志，无 lastIndex 状态污染）
    const ruleHits = this.rules.filter((rule) => { rule.pattern.lastIndex = 0; return rule.pattern.test(text) })
    const secretHits = this.enableSecret ? scanSecrets(text) : []
    const ssrfHits = this.enableSSRF ? scanNetworkTarget(text) : []

    // 引擎 1~3：单次调用静态检测
    const result = this.runStaticEngines(toolName, text, ruleHits, secretHits, ssrfHits)

    // 引擎 10：攻击链时序检测——无论单步是否拦截都推进状态机
    // （被拦截的尝试同样暴露攻击意图序列：单步放行 ≠ 序列无害）
    if (this.enableChain) {
      const categories = new Set<string>()
      for (const rule of ruleHits) if (rule.category) categories.add(rule.category)
      if (secretHits.length) categories.add('credential')
      if (ssrfHits.length) categories.add('network')
      const verdicts = this.chainEngine.observe({
        tool: toolName,
        text: text.slice(0, 500),
        ruleIds: [...ruleHits.map((r) => r.id), ...secretHits.map((s) => s.ruleId), ...ssrfHits.map((s) => s.ruleId)],
        categories: [...categories],
        intercepted: result !== false,
      })
      if (verdicts.length) return this.handleChainVerdicts(toolName, verdicts, result)
    }

    return result
  }

  /** 引擎 1~3：危险规则 / 密钥泄露 / SSRF（行为与旧版逐引擎判定一致） */
  private runStaticEngines(toolName: string, text: string, ruleHits: Rule[], secretHits: SecretHit[], ssrfHits: Array<{ ruleId: string; reason: string }>): Interception | false {
    const snippet = text.slice(0, 300)

    // 引擎 1：危险规则
    for (const rule of ruleHits) {
      const hit = this.handleRule(toolName, rule, snippet, 'rule')
      if (hit) return hit
    }

    // 引擎 2：密钥泄露（deny 级，含明文密钥绝不放行）
    if (secretHits.length) {
      const first = secretHits[0]
      this.audit({ level: 'deny', engine: 'secret', tool: toolName, ruleId: first.ruleId, reason: `检测到明文密钥：${first.description}（${first.match}）`, snippet })
      return { intercepted: true, reason: `检测到明文密钥：${first.description}`, ruleId: first.ruleId, action: 'deny', engine: 'secret' }
    }

    // 引擎 3：SSRF / 内网访问（block 级，走人工确认）
    if (ssrfHits.length) {
      const first = ssrfHits[0]
      const hit = this.handleRule(toolName, { id: first.ruleId, reason: first.reason, action: 'block' }, snippet, 'ssrf')
      if (hit) return hit
    }

    return false
  }

  /** 引擎 10 达成后的处置：链 deny 覆盖一切；链 block 在单步放行时走人工确认 */
  private handleChainVerdicts(toolName: string, verdicts: ChainVerdict[], result: Interception | false): Interception | false {
    for (const v of verdicts) {
      this.audit({
        level: v.action === 'deny' ? 'deny' : 'block',
        engine: 'chain',
        tool: toolName,
        ruleId: v.chainId,
        reason: `攻击链${v.trigger === 'complete' ? '完整达成' : `达升级阈值（${Math.round(v.progress * 100)}%）`}: ${v.name}`,
        snippet: v.story.join(' → ').slice(0, 300),
      })
    }
    // 决策取最严 verdict：deny 优先，其次 severity
    const top = [...verdicts].sort((a, b) => rankChain(b) - rankChain(a))[0]
    if (top.action === 'deny' && (result === false || result.action !== 'deny')) {
      return { intercepted: true, reason: `攻击链完整达成：${top.name}。${top.story.join(' → ')}`, ruleId: top.chainId, action: 'deny', engine: 'chain' }
    }
    if (!result) {
      // 链 block：走 guardian/approve，审批者可看到完整攻击叙事
      const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, chain: top, snippet: top.story.join(' → ') } as any)
      const approved = typeof res === 'object' && res !== null && (res as any).approved === true
      if (!approved) {
        return { intercepted: true, reason: `攻击链达成（需人工确认）：${top.name}。${top.story.join(' → ')}`, ruleId: top.chainId, action: 'block', engine: 'chain' }
      }
    }
    return result
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
  /** 攻击链进度快照（态势查询） */
  chainProgress() { return this.chainEngine.progress() }
  /** 重置攻击链状态机（全部或指定链） */
  resetChain(chainId?: string) { this.chainEngine.reset(chainId) }
}

/** 链 verdict 严重度排序：deny > block-critical > block-high */
function rankChain(v: ChainVerdict): number {
  return v.action === 'deny' ? 2 : v.severity === 'critical' ? 1 : 0
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
    /** 是否启用攻击链时序检测（默认 true） */
    trackChains?: boolean
    /** 自定义攻击链模式（默认内置 KILL_CHAINS 四条） */
    chains?: ChainPattern[]
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
