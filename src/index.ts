import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { AttackMemory } from './attack-memory.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export { AttackMemory, normalizePayload, strictNormalize, fingerprint, strictFingerprint, tokenSet, jaccard, type AttackRecord, type MemoryHit } from './attack-memory.js'

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  engine: 'rule' | 'secret' | 'ssrf' | 'memory'
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
  /** 记忆引擎命中时，指向被记忆的原始攻击所命中的规则 ID */
  sourceRuleId?: string
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
 * 检测引擎（guardian/check 通道内依次执行）：
 *  1. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  2. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  3. ssrf   —— 内网/元数据地址访问
 *  4. memory —— 攻击记忆（历史攻击指纹/变种的最后一道网，自学习）
 * 另有独立通道：guardian/path —— 路径沙箱（realpath + 白名单）
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]
  private enableSecret: boolean
  private enableSSRF: boolean
  private enablePath: boolean
  private allowedRoots: string[]
  /** 攻击记忆库（attackMemory:false 时为 undefined） */
  private memory?: AttackMemory

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })

    // 可逆效应：插件卸载时自动关闭文件流（时空可组合-时间维度）
    ctx.effect(() => () => this.stream.end())

    // 攻击记忆引擎：载入磁盘记忆 + 从审计日志自举（历史 deny/未批准 block 即攻击语料）
    if (config.attackMemory !== false) {
      this.memory = new AttackMemory(
        typeof config.attackMemory === 'object' ? config.attackMemory : {},
      )
      const fromDisk = this.memory.load()
      this.bootstrapMemoryFromAudit()
      if (this.memory.size()) {
        this.audit({ level: 'allow', engine: 'memory', reason: `攻击记忆就绪：${this.memory.size()} 条（磁盘 ${fromDisk} + 审计自举）` })
      }
    }

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
    const result = this.runChecks(toolName, text)
    // 自学习：真正被拦截（deny / block 未获批准）的攻击写入记忆，下次变种也逃不掉
    if (result && this.memory) {
      this.memory.remember(text, {
        ruleId: result.sourceRuleId ?? result.ruleId,
        severity: result.action === 'deny' ? 'deny' : 'block',
        tool: toolName,
      })
    }
    return result
  }

  /** 各引擎依次判定（check 负责记忆学习，此处纯判定） */
  private runChecks(toolName: string, text: string): Interception | false {
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

    // 引擎 4：攻击记忆（规则全 miss 后的最后一道网——历史攻击的指纹/变种仍在库）
    if (this.memory) {
      const hit = this.memory.lookup(text)
      if (hit) {
        const ruleId = hit.kind === 'exact' ? 'MEMORY-EXACT' : 'MEMORY-VARIANT'
        const reason = hit.kind === 'exact'
          ? `攻击记忆：与 ${hit.record.ts} 被拦截的「${hit.record.ruleId}」指纹完全一致（重复攻击）`
          : `攻击记忆：与已知攻击「${hit.record.ruleId}」相似度 ${(hit.similarity * 100).toFixed(0)}%（疑似变种）`
        // 精确重复沿用原判级别（deny 的永远 deny）；变种一律人工确认
        const action: Rule['action'] = hit.kind === 'exact' ? hit.record.severity : 'block'
        const res = this.handleRule(toolName, { id: ruleId, reason, action }, text.slice(0, 300), 'memory', hit.record.ruleId)
        if (res) return res
        // 用户人工批准了"精确重复"命中 → 遗忘该指纹（批准一次不再反复打扰）
        if (hit.kind === 'exact') this.memory.forget(hit.record.fp)
        return false
      }
    }

    return false
  }

  /**
   * 从审计日志自举攻击记忆：历史 deny 与"未被批准的 block"即攻击语料库。
   * block 条目若紧随 approved:<id> 的补偿 allow 条目（同 ruleId+snippet），说明用户已批准，不学习。
   */
  private bootstrapMemoryFromAudit() {
    if (!this.memory) return
    const entries = this.readAudit(1000)
    const approved = new Set(entries
      .filter((e) => e.level === 'allow' && e.reason?.startsWith('approved:') && e.ruleId && e.snippet)
      .map((e) => `${e.ruleId} ${e.snippet}`))
    for (const e of entries) {
      if (!e.snippet) continue
      if (e.level === 'deny') {
        this.memory.remember(e.snippet, { ruleId: e.ruleId ?? 'AUDIT', severity: 'deny', tool: e.tool })
      } else if (e.level === 'block' && !approved.has(`${e.ruleId} ${e.snippet}`)) {
        // 记忆引擎自身产生的 block 不重复学习（其来源已在落库时传播）
        if (e.ruleId?.startsWith('MEMORY-')) continue
        this.memory.remember(e.snippet, { ruleId: e.ruleId ?? 'AUDIT', severity: 'block', tool: e.tool })
      }
    }
  }

  /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
  private handleRule(toolName: string, rule: { id: string; reason: string; action: Rule['action'] }, snippet: string, engine: AuditEntry['engine'], sourceRuleId?: string): Interception | false {
    if (rule.action === 'deny') {
      this.audit({ level: 'deny', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
      return { intercepted: true, reason: rule.reason, ruleId: rule.id, action: 'deny', engine, ...(sourceRuleId ? { sourceRuleId } : {}) }
    }
    if (rule.action === 'block') {
      this.audit({ level: 'block', engine, tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
      // 宿主提供 'guardian/approve' 监听器做人工确认，约定返回 { approved: boolean }
      const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, rule, snippet } as any)
      const approved = typeof res === 'object' && res !== null && (res as any).approved === true
      if (!approved) {
        return { intercepted: true, reason: `${rule.reason}（未获批准）`, ruleId: rule.id, action: 'block', engine, ...(sourceRuleId ? { sourceRuleId } : {}) }
      }
      // 补偿条目：供攻击记忆自举时识别"该 block 已被人工批准，不学习"
      this.audit({ level: 'allow', engine, tool: toolName, ruleId: rule.id, reason: `approved:${rule.id}`, snippet })
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

  /** 攻击记忆库（attackMemory:false 时为 undefined），可查 size()/forget(fp) 等 */
  get attackMemory(): AttackMemory | undefined { return this.memory }
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
    /**
     * 攻击记忆引擎（默认开启）：true=默认配置；对象=细配（file/threshold/maxRecords/minTokens）；false=关闭。
     * 被拦截的攻击自动进入记忆库，换 IP/路径/措辞的重复与变种攻击会被 MEMORY-EXACT / MEMORY-VARIANT 命中。
     */
    attackMemory?: boolean | AttackMemory.Config
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
