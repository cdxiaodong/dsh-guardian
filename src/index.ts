import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import {
  AtrScanner, loadAtrRules as loadAtrRulesImpl, exportAtrYaml, ATR_EXPORT_SET,
  type AtrEvent, type AtrEventType, type AtrLoadOptions, type AtrLoadResult, type AtrMatch, type AtrSeverity,
} from './atr.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export {
  loadAtrRules, exportAtrYaml, ATR_EXPORT_SET, AtrScanner, RateMeter, parseYaml,
  compileAtrRegex, parseCombineExpr,
  type AtrEvent, type AtrEventType, type AtrLoadOptions, type AtrLoadResult, type AtrMatch,
  type AtrSeverity, type AtrStatus, type AtrScanTarget, type CompiledAtrRule, type AtrExportEntry,
} from './atr.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'atr'
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
 *  4. atr    —— ATR 开放标准社区规则（engine-44 互操作层，按需装载）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  /** engine-44：ATR 兼容扫描器（未装载规则时为 undefined，引擎静默关闭） */
  private atr?: AtrScanner
  private atrStatus: AtrLoadResult = { rules: [], errors: [], skipped: [] }
  private atrSeverityAction: Partial<Record<AtrSeverity, Rule['action']>>

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.atrSeverityAction = {
      critical: 'block', high: 'block', medium: 'block', low: 'log', informational: 'log',
      ...config.atrSeverityAction,
    }
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })

    // engine-44：装载 ATR 标准规则（内联字符串或文件；社区语料库直接喂进来即用）
    const atrYaml = config.atrRules
      ?? (config.atrRulesFile ? fs.readFileSync(config.atrRulesFile, 'utf8') : undefined)
    if (atrYaml) this.loadAtrRules(atrYaml, { includeDraft: config.atrIncludeDraft })

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

    // engine-44：独立的 ATR 扫描通道——工具调用之外的事件（skill 文件内容、LLM I/O、
    // 工具返回文本）交给宿主在合适的时机喂进来。用法：
    //   const hits = ctx.bail('guardian/atr', { type: 'skill', content: skillMd })
    //   返回 AtrMatch[]（空则 false），命中条目含 rule_id/severity（SPEC §7）
    ctx.on('guardian/atr' as any, (event: AtrEvent) => {
      if (!this.atr || !event || typeof event.content !== 'string') return false
      const hits = this.atr.scan(event)
      return hits.length ? hits : false
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

    // 引擎 4：ATR 社区规则（engine-44 互操作层；置于内置引擎之后——
    // 内置引擎精确优先，社区正则覆盖面广但误报率高于内置，最后兜底）
    if (this.atr) {
      this.atr.recordCall() // 供 tool_calls_per_minute 等 behavioral 指标
      const matches = this.atr.scanText('tool_call', text, { toolDescription: toolName })
      if (matches.length) {
        const first = matches[0]
        const action = this.atrSeverityAction[first.severity] ?? 'log'
        const hit = this.handleRule(toolName, {
          id: first.rule_id,
          reason: `ATR[${first.severity}] ${first.title}（${first.matched_conditions[0] ?? first.rule_id}）`,
          action,
        }, text.slice(0, 300), 'atr')
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

  /** engine-44：运行时装载 ATR 标准规则（可多次调用累积） */
  loadAtrRules(yamlText: string, opts?: AtrLoadOptions): AtrLoadResult {
    const result = loadAtrRulesImpl(yamlText, opts)
    if (result.rules.length) {
      if (this.atr) this.atr.rules.push(...result.rules)
      else this.atr = new AtrScanner(result.rules)
    }
    this.atrStatus = {
      rules: [...this.atrStatus.rules, ...result.rules],
      errors: [...this.atrStatus.errors, ...result.errors],
      skipped: [...this.atrStatus.skipped, ...result.skipped],
    }
    return result
  }

  /** engine-44：ATR 装载状态（规则数/被拒规则/被跳过规则） */
  getAtrStatus(): AtrLoadResult { return this.atrStatus }

  /** engine-44：独立扫描（等价于 guardian/atr 通道；skill/llm_io 等非工具调用事件） */
  scanAtr(event: AtrEvent): AtrMatch[] { return this.atr ? this.atr.scan(event) : [] }

  /** engine-44：导出内置 PI/TP 规则为 ATR YAML 多文档字符串（可回馈上游语料库） */
  exportAtrYaml(): string { return exportAtrYaml(this.rules) }
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
    /** engine-44：内联 ATR 标准规则 YAML（与 atrRulesFile 二选一） */
    atrRules?: string
    /** engine-44：ATR 规则文件路径（如 clone 的 Agent-Threat-Rule 语料库单文件） */
    atrRulesFile?: string
    /** engine-44：是否装载 status: draft 规则（默认 false，ATR conformance #4） */
    atrIncludeDraft?: boolean
    /** engine-44：ATR severity → 处置级别覆盖（默认 critical/high/medium→block，low/informational→log） */
    atrSeverityAction?: Partial<Record<AtrSeverity, Rule['action']>>
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
