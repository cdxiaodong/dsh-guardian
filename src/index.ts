import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { collectSignals } from './risk.js'
import { TrifectaTracker, classifyCapabilities, CAPABILITIES, type Capability, type TrifectaStatus } from './trifecta.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { TrifectaTracker, classifyCapabilities, CAPABILITIES, type Capability, type CapabilityObservation, type TrifectaEvent, type TrifectaStatus, type TrifectaTrackerOptions } from './trifecta.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'trifecta'
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
 * 检测引擎（前六个是「空间维度」：单次调用无状态判定；第七个补「时间维度」）：
 *  1. rule     —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret   —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf     —— 内网/元数据地址访问
 *  7. trifecta —— 时空致命三角：会话滑动窗口内 私有数据+不可信内容+外部通道 三者齐备即拦
 *    （单看每次调用可能都合法，组合才暴露攻击 —— Lethal Trifecta / Rule of Two）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  private trifecta: TrifectaTracker
  private enableTrifecta: boolean
  private trifectaAction: Rule['action']

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.enableTrifecta = config.scanTrifecta ?? true
    this.trifectaAction = config.trifectaAction ?? 'block'
    this.trifecta = new TrifectaTracker({ windowMs: config.trifectaWindowMs })
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })

    // 可逆效应：插件卸载时自动关闭文件流（时空可组合-时间维度）
    ctx.effect(() => () => this.stream.end())
    // 可逆效应：插件卸载时清空致命三角滑动窗口（时空可组合-时间维度）
    ctx.effect(() => () => this.trifecta.reset())

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

    // 引擎 7（时空维度·最先观测）：把本次调用投影到三类能力并记入会话滑动窗口，
    // 致命三角齐备即拦。observe-first：即使本次随后被单引擎拦下，"尝试"也已入窗。
    if (this.enableTrifecta) {
      const tri = this.observeTrifecta(toolName, text)
      if (tri) return tri
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

    return false
  }

  /** 查询当前会话致命三角状态（可观测性，供 UI/审计用） */
  trifectaStatus(): TrifectaStatus {
    return this.trifecta.status()
  }

  /**
   * 时空观测：复用既有检测器输出，把本次调用投影到能力维度并记录进滑动窗口。
   * 触发即返回拦截：①本次调用补全了三角；②三角已热时再次出现外部数据通道。
   */
  private observeTrifecta(toolName: string, text: string): Interception | false {
    const categories = collectSignals(this.rules, text)
      .map((s) => s.category)
      .filter((c): c is string => Boolean(c))
    const secret = this.enableSecret && scanSecrets(text).length > 0
    const network = this.enableSSRF && scanNetworkTarget(text).length > 0
    const caps = classifyCapabilities({ tool: toolName, categories, secret, network })

    const wasAssembled = this.trifecta.assembled()
    for (const cap of caps) {
      this.trifecta.record(cap, toolName, this.capEvidence(cap, secret, network))
    }
    const st = this.trifecta.status()

    const closedNow = !wasAssembled && st.assembled
    const egressWhileHot = wasAssembled && st.assembled && caps.includes('external-egress')
    if (!closedNow && !egressWhileHot) return false

    const reason = this.describeTrifecta(st, closedNow)
    return this.handleRule(toolName, { id: 'TRIFECTA-001', reason, action: this.trifectaAction }, text.slice(0, 300), 'trifecta')
  }

  /** 生成该能力归类的简短证据说明 */
  private capEvidence(cap: Capability, secret: boolean, network: boolean): string {
    if (cap === 'private-data') return secret ? '检出明文密钥/凭据' : '私有数据/凭据访问'
    if (cap === 'external-egress') return network ? '命中网络外联目标' : '外部通信/数据出站'
    return '摄入不可信外部内容'
  }

  /** 生成致命三角的可读拦截理由 */
  private describeTrifecta(st: TrifectaStatus, closedNow: boolean): string {
    const label: Record<Capability, string> = {
      'private-data': '私有数据访问',
      'untrusted-content': '不可信内容摄入',
      'external-egress': '外部通信通道',
    }
    const parts = CAPABILITIES.map((c) => `${label[c]}[${st.latest[c]?.tool ?? '-'}]`).join(' + ')
    const head = closedNow ? '致命三角成形' : '致命三角持续，再次出现外部数据通道'
    return `${head}：本会话滑动窗口内同时具备 ${parts}（Lethal Trifecta / Rule-of-Two），存在数据外泄风险`
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
    /** 是否启用致命三角时空关联引擎（默认 true） */
    scanTrifecta?: boolean
    /** 致命三角会话滑动窗口时长 ms（默认 10 分钟） */
    trifectaWindowMs?: number
    /** 致命三角处置动作（默认 block=人工确认；deny=直接拒；log=仅记录） */
    trifectaAction?: Rule['action']
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
