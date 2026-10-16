import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { DelegationLedger, classifyOperations, extractSinks, inferLabels, sinkCovered, purposeOverlap, type DelegationConfig, type GrantRequest, type Capability, type OperationClass, type DataLabel, type DelegationVerdict, type AuthorizeResult } from './delegation.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { DelegationLedger, classifyOperations, extractSinks, inferLabels, sinkCovered, purposeOverlap, type DelegationConfig, type GrantRequest, type Capability, type OperationClass, type DataLabel, type DelegationVerdict, type AuthorizeResult } from './delegation.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'delegation'
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
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  /** 授权衰减账本（默认 null = 关闭，既有行为不变） */
  readonly delegation: DelegationLedger | null

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })
    this.delegation = config.delegation?.enabled === true ? new DelegationLedger(config.delegation) : null

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

    // 授权编译通道（DelegateGuard）：宿主拿到用户批准后把授权铸成五维能力
    // 用法：ctx.bail('guardian/grant', { purpose, ... }) → { ok: true, capability }
    if (this.delegation) {
      ctx.on('guardian/grant' as any, (req: GrantRequest) => {
        const capability = this.delegation!.grant(req)
        this.audit({ level: 'allow', engine: 'delegation', tool: 'grant', ruleId: 'DLG-GRANT', reason: `授权编译：${capability.purpose.slice(0, 80)}（ops=${capability.operations.join('|')} depth=${capability.depth} uses=${capability.maxUses}）` })
        return { ok: true as const, capability }
      }, true)

      // 委派衰减通道：子 agent / 子工具继承授权，逐维只减不增
      // 用法：ctx.bail('guardian/delegate', parentId, req) → DelegationVerdict
      ctx.on('guardian/delegate' as any, (parentId: string, req: GrantRequest) => {
        const verdict = this.delegation!.delegate(parentId, req)
        if (!verdict.ok) {
          this.audit({ level: 'deny', engine: 'delegation', tool: 'delegate', ruleId: verdict.ruleId, reason: verdict.reason })
        } else {
          this.audit({ level: 'allow', engine: 'delegation', tool: 'delegate', ruleId: 'DLG-DELEGATE', reason: `合法衰减委派 ${verdict.capability.id}（父 ${parentId}，depth ${verdict.capability.depth}）` })
        }
        return verdict
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
        // 引擎（delegation）：本次人工未批准，但用户既往批准编译成的能力可能仍覆盖——
        // 授权复用（reference monitor 语义：同类操作不再打扰用户）；
        // 与已失效授权维度匹配的重放则升级 deny（DLG-002）；从未覆盖维持原拦截走人工。
        if (this.delegation) {
          const verdict = this.delegation.authorize({
            operations: classifyOperations(snippet),
            sinks: (() => { const s = extractSinks(snippet); return [...s.paths, ...s.domains] })(),
            labels: inferLabels(snippet),
          })
          if (verdict.decision === 'allow') {
            this.audit({ level: 'allow', engine: 'delegation', tool: toolName, ruleId: 'DLG-REUSE', reason: `授权复用：能力 ${verdict.capability!.id} 覆盖本次操作（剩余预算 ${verdict.capability!.maxUses - verdict.capability!.uses}）`, snippet })
            return false
          }
          if (verdict.decision === 'deny') {
            this.audit({ level: 'deny', engine: 'delegation', tool: toolName, ruleId: verdict.ruleId, reason: verdict.reason!, snippet })
            return { intercepted: true, reason: `${rule.reason}；${verdict.reason}`, ruleId: verdict.ruleId!, action: 'deny', engine: 'delegation' }
          }
        }
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
    /** 授权衰减引擎（DelegateGuard）：默认关闭 */
    delegation?: DelegationConfig & { enabled?: boolean }
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
