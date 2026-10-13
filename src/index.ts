import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { RelayTracker, type ProvenanceClass, type RelayConfig, type RelayVerdict, type TaintRecord, type ArtifactRecord } from './relay.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { RelayTracker, fnv1a64, normalizeArtifactPath, looksLikeEvidence, type ProvenanceClass, type RelayConfig, type RelayVerdict, type TaintRecord, type ArtifactRecord } from './relay.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'relay'
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
  private relay: RelayTracker
  private relayCfg: RelayConfig
  /** 当前会话标识（跨会话接力判定的基线；宿主可用 setSession 切换） */
  private session: string

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.relayCfg = config.relay ?? {}
    this.relay = new RelayTracker(this.relayCfg)
    this.session = config.session ?? 'default'
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

    // 引擎 40：跨会话接力污点通道。
    // 宿主在把外部内容喂给 agent 前（爬虫结果/工具结果/文件读取）调
    //   ctx.bail('guardian/ingest', text, origin, session)
    // 文本携带的注入命中史会登记为污点；后续 persist/relay 判定靠它。
    ctx.on('guardian/ingest' as any, (text: string, origin: ProvenanceClass, session?: string) => {
      if (this.relayCfg.enabled === false) return false
      return this.ingest(text, origin, session ?? this.session)
    }, true)
  }

  /** 登记外部内容来源：返回污点指纹（null=不追踪） */
  ingest(text: string, origin: ProvenanceClass, session?: string): string | null {
    return this.relay.ingest(text, origin, session ?? this.session)
  }

  /** 切换当前会话（跨会话判定基线） */
  setSession(session: string) { this.session = session }

  /** 污点查询（宿主调试/展示用） */
  taintOf(text: string): TaintRecord | null { return this.relay.taintOf(text) }

  /** 人工复核放行：清除工件的污点标记（RLY-002/004 的出口） */
  revokeArtifact(artifactPath: string): boolean { return this.relay.revoke(artifactPath) }

  /** 接力引擎状态快照 */
  relaySnapshot(): { taints: number; artifacts: number } { return this.relay.snapshot() }

  /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
  checkPathAccess(target: string) {
    const verdict = checkPath(target, this.allowedRoots)
    if (!verdict.safe) {
      this.audit({ level: 'deny', engine: 'rule', tool: 'fs', ruleId: 'PATH-SANDBOX', reason: verdict.reason, snippet: target.slice(0, 300) })
    }
    return verdict
  }

  /**
   * 引擎 40：写/读语义工具调用的接力判定。
   * 约定 payload 结构（宿主按工具语义传）：
   *   write 语义：{ path: string, content: string } 或 { file_path, content }
   *   read  语义：{ path: string } 或字符串路径
   * 其他工具（bash 等）返回 false 交给后续引擎。
   */
  private relayCheck(toolName: string, payload: unknown, text: string): Interception | false {
    let artifactPath: string | undefined
    let content: string | undefined
    if (typeof payload === 'object' && payload !== null) {
      const p = payload as Record<string, unknown>
      artifactPath = typeof p.path === 'string' ? p.path : typeof p.file_path === 'string' ? p.file_path : undefined
      content = typeof p.content === 'string' ? p.content : undefined
    }
    const isWriteTool = typeof content === 'string' && artifactPath !== undefined
    const isReadTool = !isWriteTool && artifactPath !== undefined && /read|load|source|import|open/i.test(toolName)
    if (!isWriteTool && !isReadTool) return false

    let verdict: RelayVerdict
    if (isWriteTool) {
      verdict = this.relay.persist(this.session, content!, artifactPath!)
    } else {
      verdict = this.relay.relay(this.session, artifactPath!)
    }
    if (!verdict.intercepted) return false

    // block 级走人工确认（与其他引擎一致）
    if (verdict.action === 'block') {
      const hit = this.handleRule(toolName, { id: verdict.ruleId!, reason: verdict.reason!, action: 'block' }, text.slice(0, 300), 'relay')
      if (hit) return hit
      return false
    }
    this.audit({ level: 'deny', engine: 'relay', tool: toolName, ruleId: verdict.ruleId!, reason: verdict.reason, snippet: text.slice(0, 300) })
    return { intercepted: true, reason: verdict.reason!, ruleId: verdict.ruleId!, action: 'deny', engine: 'relay' }
  }

  /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
  check(toolName: string, payload: unknown): Interception | false {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {})

    // 引擎 40：跨会话接力污点（写/读语义工具调用交给 relay 判定）
    if (this.relayCfg.enabled !== false && this.relay) {
      const relayVerdict = this.relayCheck(toolName, payload, text)
      if (relayVerdict) return relayVerdict
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
    /** 跨会话接力污点引擎配置（默认启用） */
    relay?: RelayConfig
    /** 当前会话标识（跨会话判定基线，宿主可用 guardian.setSession 切换） */
    session?: string
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
