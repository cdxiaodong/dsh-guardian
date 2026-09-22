import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { TamperEvidence, verifyChain, GENESIS_HASH, computeRecordHash, canonicalizeEvent, type ChainEntry, type ChainHead, type VerifyResult } from './chain.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { TamperEvidence, verifyChain, GENESIS_HASH, computeRecordHash, canonicalizeEvent, type ChainEntry, type ChainHead, type VerifyResult } from './chain.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf'
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
  /** 防篡改模式开关：审计串接哈希链 */
  readonly tamperEvidence: boolean
  /** 链式写入器（tamperEvidence=false 时为 null） */
  private chain: TamperEvidence | null

  /** 初始化链写入器：磁盘已有合法链 → 从链尾续写（跨进程持久）；否则新链 */
  private initChain(): TamperEvidence {
    let head: ChainHead | undefined
    if (fs.existsSync(this.logFile)) {
      const lines = fs.readFileSync(this.logFile, 'utf8').trim().split('\n').filter(Boolean)
      const res = verifyChain(lines)
      if (res.ok && res.head && res.head.seq > 0) head = res.head
      // 验证失败 → 从新链重开（旧文件已被篡改，保留现场由宿主处置）
    }
    return new TamperEvidence(this.logFile, head)
  }

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    // 防篡改模式：审计日志串接哈希链（tamper-evidence chain）
    // 注意 append 模式：initChain 已读磁盘验证旧链，从链尾续写；验链失败则从创世重开（先 truncate 清掉坏链）
    this.tamperEvidence = config.tamperEvidence ?? false
    this.chain = this.tamperEvidence ? this.initChain() : null
    const startFresh = this.tamperEvidence && this.chain && this.chain.chainHead().seq === 0
    if (startFresh && fs.existsSync(this.logFile)) fs.writeFileSync(this.logFile, '')
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
    if (this.chain) {
      // 链式模式：事件先 canonical 序列化再串链，写盘的是含链字段的 JSON 行
      this.stream.write(this.chain.append(full as unknown as Record<string, unknown>) + '\n')
    } else {
      this.stream.write(JSON.stringify(full) + '\n')
    }
  }

  /** 验证审计日志完整性：链模式查哈希链；普通模式查 JSON 可解析性 */
  verifyAudit(): VerifyResult & { mode: 'chain' | 'plain' } {
    const lines = this.readAuditLines()
    if (this.chain) {
      const res = this.chain.checkAgainstDisk(() => lines)
      return { ...res, mode: 'chain' }
    }
    // 普通模式兜底：至少能解析出所有行（无防篡改保证，只防意外损坏）
    for (let i = 0; i < lines.length; i++) {
      try { JSON.parse(lines[i]) } catch { return { ok: false, problem: 'parse', line: i + 1, verifiedCount: i, head: null, lastGood: null, mode: 'plain' } }
    }
    return { ok: true, problem: null, line: 0, verifiedCount: lines.length, head: null, lastGood: null, mode: 'plain' }
  }

  /** 读取审计链头（普通模式返回 null）——供宿主外部备份 / 告警联动 */
  auditChainHead(): ChainHead | null {
    return this.chain ? this.chain.chainHead() : null
  }

  private readAuditLines(): string[] {
    if (!fs.existsSync(this.logFile)) return []
    return fs.readFileSync(this.logFile, 'utf8').trim().split('\n').filter(Boolean)
  }

  readAudit(limit = 20): AuditEntry[] {
    return this.readAuditLines()
      .slice(-limit)
      .map((l) => {
        try {
          const rec = JSON.parse(l)
          // 链模式：还原出业务事件（entry 字段）；普通模式：整行即事件
          return rec && typeof rec.entry === 'string' ? parseCanonicalEntry(rec.entry) : rec
        } catch { return null }
      })
      .filter(Boolean) as AuditEntry[]
  }

  addRule(rule: Rule) { this.rules.push(rule) }
  listRules(): Rule[] { return [...this.rules] }
}

/** 链模式 entry 是 canonical（\u0001 分隔的 k=v）格式，还原成对象 */
function parseCanonicalEntry(entry: string): AuditEntry | null {
  const out: Record<string, string> = {}
  for (const part of entry.split('\u0001')) {
    const eq = part.indexOf('=')
    if (eq === -1) return null
    out[part.slice(0, eq)] = part.slice(eq + 1)
  }
  return out as unknown as AuditEntry
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
    /** 审计日志防篡改哈希链：每条记录串接前条哈希，事后篡改可离线检出（默认 false） */
    tamperEvidence?: boolean
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
