import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { TrustLedger, classifyTool, detectDirectives, PROTECTED_CATEGORIES, type IngestResult, type ToolCategory, type DirectiveHit, type AttenuationInfo } from './capability.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { TrustLedger, classifyTool, detectDirectives, DIRECTIVE_RULES, PROTECTED_CATEGORIES, TOOL_CATEGORY_PATTERNS, type IngestResult, type ToolCategory, type DirectiveRule, type DirectiveHit, type AttenuationInfo } from './capability.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny' | 'flag'
  engine: 'rule' | 'secret' | 'ssrf' | 'cap'
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
 *  4. cap    —— 能力衰减（confused deputy 防护）：跨调用信任状态机，
 *               不可信内容摄入后，影响窗口内的副作用工具自动降权为人工确认
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  private enableAttenuation: boolean
  private protectedCategories: ToolCategory[]
  private toolCategoryOverrides: Record<string, ToolCategory> | undefined
  readonly ledger: TrustLedger

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.enableAttenuation = config.attenuateConfusedDeputy ?? true
    this.protectedCategories = config.protectedCategories ?? [...PROTECTED_CATEGORIES]
    this.toolCategoryOverrides = config.toolCategories
    this.ledger = new TrustLedger({ influenceSteps: config.influenceSteps })
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

    // 外部内容摄入申报通道：宿主把网页/工具结果/外部文件放进 LLM 上下文前调用。
    // 用法：const r = ctx.bail('guardian/ingest', source, content)；r.polluted 即进入衰减态
    ctx.on('guardian/ingest' as any, (source: string, content: string) => {
      return this.ingestContent(source, content)
    }, true)
  }

  /** 外部内容摄入申报：携带指令性话术 → 会话进入衰减态（confused deputy 防护） */
  ingestContent(source: string, content: string): IngestResult {
    const result = this.ledger.ingest(source, content)
    if (result.polluted) {
      this.audit({
        level: 'flag', engine: 'cap', ruleId: 'CAP-INGEST',
        reason: `不可信来源 "${source}" 携带指令性内容（${result.directives.map(d => d.ruleId).join(', ')}），会话进入能力衰减态`,
        snippet: content.slice(0, 300),
      })
    }
    return result
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

    // 引擎 4：能力衰减（confused deputy）—— 状态型拦截，先于所有内容型引擎。
    // 判定依据不是本次 payload，而是会话信任状态：不可信内容的影响窗口内，
    // 副作用类工具一律降为人工确认（借鉴 oCap attenuation：权威绝不自动增强）
    if (this.enableAttenuation) {
      const category = classifyTool(toolName, this.toolCategoryOverrides)
      if (this.protectedCategories.includes(category)) {
        const info = this.ledger.attenuatedFor(category)
        if (info) {
          const snippet = text.slice(0, 300)
          this.audit({ level: 'block', engine: 'cap', tool: toolName, ruleId: 'CAP-ATTENUATE', reason: info.reason, snippet })
          const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, rule: { id: 'CAP-ATTENUATE', reason: info.reason, action: 'block' }, snippet } as any)
          const approved = typeof res === 'object' && res !== null && (res as any).approved === true
          if (!approved) {
            this.ledger.step()
            return { intercepted: true, reason: `${info.reason}（未获批准）`, ruleId: 'CAP-ATTENUATE', action: 'block', engine: 'cap' }
          }
          // 人工确认 → 发放委托凭证：授权可传播，但限定来源+类别+次数（默认 1 次）
          for (const src of info.sources) this.ledger.grant(src, category)
        }
      }
    }
    this.ledger.step()

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
    /** 是否启用能力衰减引擎（confused deputy 防护，默认 true） */
    attenuateConfusedDeputy?: boolean
    /** 衰减影响窗口步数：不可信内容摄入后，多少次工具调用内的副作用操作被降权（默认 3） */
    influenceSteps?: number
    /** 衰减保护的副作用类别（默认全部：exec/write/delete/network/credential） */
    protectedCategories?: ToolCategory[]
    /** 工具名 → 副作用类别的精确覆盖映射（内置分类靠子串启发式，宿主可精确指定） */
    toolCategories?: Record<string, ToolCategory>
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
