import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { DutyLedger, DEFAULT_DUTY_DEFS, EGRESS_SHAPE, EGRESS_TOOL, type DutyDef, type DutyRecord, type DutyView } from './duty.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { DutyLedger, DEFAULT_DUTY_DEFS, EGRESS_SHAPE, EGRESS_TOOL, pathMatchesArtifact, type DutyDef, type DutyRecord, type DutyView } from './duty.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'duty'
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
 * 四个检测引擎：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. duty   —— 义务账本（获取敏感残留 → 期限内必须清理，逾期冻结出境）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  private enableDuties: boolean
  private dutyDefs: DutyDef[]
  private dutyClock: () => number
  private ledger: DutyLedger

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.enableDuties = config.enforceDuties ?? true
    this.dutyDefs = [...DEFAULT_DUTY_DEFS, ...(config.dutyDefs ?? [])]
    this.dutyClock = config.dutyClock ?? (() => Date.now())
    this.ledger = new DutyLedger(this.dutyDefs, this.dutyClock)
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

    // 引擎 4：义务账本（acquire → F[0,d] dispose 的有界最终性义务 + 逾期遏制）
    if (this.enableDuties) {
      const hit = this.runDutyEngine(toolName, text)
      if (hit) return hit
    }

    return false
  }

  /**
   * 义务账本引擎：三段式判定。
   *  1) 销账优先——补救动作（清理残留）永远先于遏制执行，不能把"赎罪之路"堵死
   *  2) 违约遏制——存在逾期未清义务时冻结出境通道（deny），但本地操作不受影响
   *  3) 获取记账——产生敏感残留的调用本身放行，代价是背上期限义务
   */
  private runDutyEngine(toolName: string, text: string): Interception | false {
    const now = this.dutyClock()

    // 1) 销账扫描（须在任何遏制判定之前）
    for (const rec of this.ledger.settleFrom(text)) {
      this.audit({ level: 'allow', engine: 'duty', tool: toolName, ruleId: rec.defId, reason: `义务已履行：清理 ${rec.binding}`, snippet: text.slice(0, 300) })
    }

    // 2) 违约遏制：逾期未清 → 冻结出境
    const overdue = this.ledger.overdue(now)
    if (overdue.length && (EGRESS_SHAPE.test(text) || EGRESS_TOOL.test(toolName))) {
      const worst = overdue[overdue.length - 1]
      this.audit({ level: 'deny', engine: 'duty', tool: toolName, ruleId: 'DUTY-900', reason: `存在 ${overdue.length} 条逾期未清理的敏感残留义务（如 ${worst.binding}），出境通道已冻结直至销账`, snippet: text.slice(0, 300) })
      return { intercepted: true, reason: `敏感残留清理义务逾期（${overdue.length} 条，最早涉及 ${worst.binding}），已冻结出境通道；请先清理残留再外传数据`, ruleId: 'DUTY-900', action: 'deny', engine: 'duty' }
    }

    // 3) 获取记账（不拦截：义务是获取的代价，不是禁令）
    for (const rec of this.ledger.recordFrom(text)) {
      this.audit({ level: 'allow', engine: 'duty', tool: toolName, ruleId: rec.defId, reason: `产生清理义务：${rec.binding} 须在 ${Math.round((rec.deadlineAt - rec.acquiredAt) / 1000)}s 内清理`, snippet: text.slice(0, 300) })
    }

    return false
  }

  /** 未清义务清单（含 overdue 计算位），宿主可在会话收尾前检查"未尽事项" */
  pendingDuties(): DutyView[] {
    return this.ledger.open(this.dutyClock())
  }

  /** 人工销账：宿主在带外完成清理后手动清偿义务 */
  fulfillDuty(defId: string, binding?: string): DutyRecord[] {
    return this.ledger.manualFulfill(defId, binding)
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
    /** 是否启用义务账本引擎（默认 true） */
    enforceDuties?: boolean
    /** 追加自定义义务定义（signal→artifact→dispose + 期限） */
    dutyDefs?: DutyDef[]
    /** 义务账本时钟注入（默认真实时钟；测试/宿主可时间旅行） */
    dutyClock?: () => number
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
