import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import {
  diffManifests, manifestFingerprint, pinManifest, toBaseline,
  type BaselineEntry, type IntegrityOptions, type ManifestFinding, type ManifestVerdict, type ToolSpec,
} from './integrity.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export {
  canonicalJson, diffManifests, hashToolSpec, manifestFingerprint, normalizeName, diceSimilarity, pinManifest, toBaseline,
  type BaselineEntry, type IntegrityOptions, type ManifestFinding, type ManifestFindingKind, type ManifestVerdict, type ToolSpec,
} from './integrity.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'integrity'
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
 * 另有独立通道：guardian/path 路径沙箱、guardian/tools 工具清单完整性（rug-pull 检测）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  /** 引擎 6：工具清单完整性（rug-pull 检测） */
  private enableIntegrity: boolean
  private newToolPolicy: NonNullable<IntegrityOptions['newToolPolicy']>
  /** 配置 pin 的锁基线（name → hash），类似 package-lock；设置后配置即权威 */
  private pinnedTools?: Map<string, BaselineEntry>
  /** 会话级基线：sessionId → (name → BaselineEntry)，首次观察即 pin */
  private toolBaselines = new Map<string, Map<string, BaselineEntry>>()

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.enableIntegrity = config.checkToolIntegrity ?? true
    this.newToolPolicy = config.newToolPolicy ?? 'block'
    if (config.manifestBaseline) {
      this.pinnedTools = new Map(
        Object.entries(Array.isArray(config.manifestBaseline)
          ? pinManifest(config.manifestBaseline)
          : config.manifestBaseline,
        ).map(([name, hash]) => [name, { hash }]),
      )
    }
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

    // 独立的工具清单完整性通道：宿主在会话开始/收到 tools/list 刷新时调用
    // 用法：const v = ctx.bail('guardian/tools', sessionId, toolSpecs)；v.safe===false 即拒绝加载该清单
    ctx.on('guardian/tools' as any, (sessionId: string, tools: ToolSpec[]) => {
      return this.checkToolManifest(sessionId, tools)
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

  /**
   * 引擎 6：工具清单完整性校验（rug-pull 检测）。
   * 宿主在会话开始与每次收到 tools/list 刷新时调用（或经 guardian/tools 通道）。
   * 语义：首次观察即 pin 基线（或用配置 manifestBaseline pin）；之后任何
   * 描述/schema 变更、中途新增工具、同名仿冒都要求重新授权，deny 级直接拒绝。
   */
  checkToolManifest(sessionId: string, tools: ToolSpec[]): ManifestVerdict {
    const fingerprint = manifestFingerprint(tools)
    if (!this.enableIntegrity) return { safe: true, findings: [], fingerprint }

    const state = this.toolBaselines.get(sessionId)
    if (!state && !this.pinnedTools) {
      // 首次观察：建立会话基线（"批准时刻 pin"）
      this.toolBaselines.set(sessionId, toBaseline(tools))
      this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: 'TI-000', reason: `工具清单基线已建立（${tools.length} 个工具，指纹 ${fingerprint}）` })
      return { safe: true, findings: [], fingerprint }
    }
    const baseline = this.pinnedTools ?? state!

    const findings = diffManifests(baseline, tools, { newToolPolicy: this.newToolPolicy })
    const effective = toBaseline(tools)
    const reported: ManifestFinding[] = []
    let safe = true

    for (const f of findings) {
      if (f.severity === 'deny') {
        this.audit({ level: 'deny', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: f.reason, snippet: f.detail })
        reported.push(f)
        safe = false
      } else if (f.severity === 'block') {
        // 复用 guardian/approve 人工确认通道：批准即"重新授权"，基线更新为新定义
        const res = this.ctx.bail('guardian/approve' as any, { tool: 'manifest', rule: { id: f.ruleId, reason: f.reason, action: 'block' }, snippet: f.detail ?? '' } as any)
        const approved = typeof res === 'object' && res !== null && (res as any).approved === true
        if (!approved) {
          this.audit({ level: 'block', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: `${f.reason}（未获批准）`, snippet: f.detail })
          reported.push(f)
          safe = false
          effective.delete(f.tool)   // 未授权的变更不进新基线，下轮继续报警
        } else {
          this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: `${f.reason}（已人工重授权）`, snippet: f.detail })
        }
      } else {
        this.audit({ level: 'allow', engine: 'integrity', tool: 'manifest', ruleId: f.ruleId, reason: f.reason, snippet: f.detail })
        reported.push(f)
      }
    }

    // 会话基线更新（pin 模式下配置即权威，不改）
    if (!this.pinnedTools && safe) this.toolBaselines.set(sessionId, effective)
    return { safe, findings: reported, fingerprint }
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
    /** 是否启用工具清单完整性校验（默认 true） */
    checkToolIntegrity?: boolean
    /** 会话中途新增工具的处置：'block'（默认，人工确认）| 'deny' | 'log' | 'allow' */
    newToolPolicy?: 'deny' | 'block' | 'log' | 'allow'
    /**
     * 工具清单 pin 锁基线（类似 package-lock 的角色）。
     * 传 ToolSpec[] 会自动计算 hash；或直接传 pinManifest() 生成的 name→hash 映射。
     * 设置后配置即权威，任何漂移都要求重新授权。
     */
    manifestBaseline?: ToolSpec[] | Record<string, string>
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
