import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { DEFAULT_RULES, type Rule } from './rules.js'
import { scanSecrets, type SecretHit } from './secrets.js'
import { scanNetworkTarget } from './ssrf.js'
import { checkPath } from './path.js'
import { guardMemoryWrite, isAgentContextFile, MemoryIntegrityStore, scanMemoryContent, worstAction, type IntegrityResult, type MemoryVerdict } from './memory.js'

export const name = 'dsh-guardian'
export { DEFAULT_RULES, type Rule }
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js'
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js'
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js'
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js'
export {
  isAgentContextFile, AGENT_CONTEXT_PATTERNS, MEMORY_RULES, scanMemoryContent, worstAction,
  guardMemoryWrite, MemoryIntegrityStore,
  type MemoryRule, type MemoryHit, type MemoryVerdict, type IntegrityResult, type IntegrityStatus,
} from './memory.js'

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
  private enableMemory: boolean
  private allowedRoots: string[]
  /** 认知完整性基线（TOFU 哈希 pin） */
  readonly integrity: MemoryIntegrityStore

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.enableSecret = config.scanSecrets ?? true
    this.enableSSRF = config.scanSSRF ?? true
    this.enablePath = config.checkPaths ?? true
    this.enableMemory = config.guardMemory ?? true
    this.allowedRoots = config.allowedRoots ?? []
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })
    this.integrity = new MemoryIntegrityStore(config.integrityFile ?? path.join(os.homedir(), '.dsh-guardian.memory.json'))

    // 可逆效应：插件卸载时自动关闭文件流、落盘完整性基线（时空可组合-时间维度）
    ctx.effect(() => () => {
      this.integrity.flush()
      this.stream.end()
    })

    // 护栏最先执行（prepend）
    ctx.on('guardian/check' as any, (toolName: string, payload: unknown) => {
      return this.check(toolName, payload)
    }, true)

    // 独立的路径沙箱校验通道：宿主读写文件前调用
    // 用法：const v = ctx.bail('guardian/path', targetPath)；v.safe===false 即拦截
    ctx.on('guardian/path' as any, (target: string) => {
      return this.checkPathAccess(target)
    }, true)

    // 独立的认知完整性通道：宿主写 Agent 上下文文件（CLAUDE.md/记忆等）前调用
    // 用法：const v = ctx.bail('guardian/memory', targetPath, content)；v.safe===false 即拦截
    ctx.on('guardian/memory' as any, (target: string, content: string) => {
      return this.checkMemoryWrite(target, content)
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

  /** 认知写入判定：非受保护文件直接放行；受保护文件按投毒规则判，干净则顺带 TOFU 建基线 */
  checkMemoryWrite(target: string, content: string): MemoryVerdict {
    const verdict = guardMemoryWrite(target, content, this.integrity)
    if (!verdict.safe) {
      this.audit({ level: 'deny', engine: 'memory', tool: 'write', ruleId: verdict.hits[0]?.ruleId ?? 'MEM-000', reason: verdict.reason, snippet: (content ?? '').slice(0, 300) })
    } else if (verdict.isContextFile && verdict.hits.length) {
      // log 级可疑内容：放行但留痕（不刷新基线，下次写入仍会重扫）
      this.audit({ level: 'allow', engine: 'memory', tool: 'write', ruleId: verdict.hits[0].ruleId, reason: verdict.reason })
    }
    return verdict
  }

  /** 启动自检：校验受保护上下文文件是否偏离 TOFU 基线（宿主会话启动时逐个调用） */
  verifyContextFile(target: string): IntegrityResult {
    const result = this.integrity.verifyOnDisk(target)
    if (result.status === 'modified') {
      this.audit({ level: 'deny', engine: 'memory', tool: 'boot', ruleId: 'MEM-INTEGRITY', reason: `认知上下文文件偏离基线（疑被篡改）：${target}` })
    }
    return result
  }

  /**
   * 识别"写 Agent 认知上下文文件"的工具调用：
   *  1. 写入类工具名 + payload 中出现受保护路径（write_file/edit 等结构化调用）
   *  2. shell 写入动词（重定向/tee/cp/mv/append）指向受保护文件（绕过结构化工具的逃逸路径）
   */
  private looksLikeContextWrite(toolName: string, text: string): boolean {
    const tokens = extractPathTokens(text)
    if (/write|edit|patch|create|save|update|store|remember|append|memo/i.test(toolName)) {
      if (tokens.some((t) => isAgentContextFile(t))) return true
    }
    // 写入动词后 60 字符内出现受保护文件 token
    for (const t of tokens) {
      if (!isAgentContextFile(t)) continue
      const esc = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      if (new RegExp(`(>>?|\\btee\\b|\\bcp\\b|\\bmv\\b|\\bappend\\b|\\bln\\s+-s\\b)[^;\\n]{0,60}${esc}`, 'i').test(text)) return true
    }
    return false
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

    // 引擎 4：认知完整性（memory poisoning）——写 Agent 上下文文件的动作本身
    // 人畜无害，OS 级持久化检测管不到，必须在工具调用层识别并扫描写入内容
    if (this.enableMemory && this.looksLikeContextWrite(toolName, text)) {
      const verdict = this.checkMemoryWrite(extractContextTarget(text), text)
      if (!verdict.safe) {
        const worst = worstAction(verdict.hits)!
        if (worst === 'deny') {
          this.audit({ level: 'deny', engine: 'memory', tool: toolName, ruleId: verdict.hits[0].ruleId, reason: verdict.reason!, snippet: text.slice(0, 300) })
          return { intercepted: true, reason: verdict.reason!, ruleId: verdict.hits[0].ruleId, action: 'deny', engine: 'memory' }
        }
        // block 级投毒嫌疑：走人工确认（管理员可能确实在手改自己的 CLAUDE.md）
        this.audit({ level: 'block', engine: 'memory', tool: toolName, ruleId: verdict.hits[0].ruleId, reason: verdict.reason!, snippet: text.slice(0, 300) })
        const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, rule: { id: verdict.hits[0].ruleId, reason: verdict.reason, action: 'block' }, snippet: text.slice(0, 300) } as any)
        const approved = typeof res === 'object' && res !== null && (res as any).approved === true
        if (!approved) {
          return { intercepted: true, reason: `${verdict.reason}（未获批准）`, ruleId: verdict.hits[0].ruleId, action: 'block', engine: 'memory' }
        }
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
    /** 是否启用认知完整性引擎：Agent 上下文文件投毒检测（默认 true） */
    guardMemory?: boolean
    /** 认知完整性 TOFU 基线存放路径（默认 ~/.dsh-guardian.memory.json） */
    integrityFile?: string
    /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
    allowedRoots?: string[]
  }
}

export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}

// ── 认知写入识别辅助 ─────────────────────────────────────────

/** 从工具调用文本中提取文件路径样式的 token（含裸 dotfile 规则文件名） */
function extractPathTokens(text: string): string[] {
  const matches = text.match(/[\w~./\\-]*\w\.(?:md|json|toml|ya?ml|txt)|\.cursorrules|\.clinerules[\w.-]*|\.windsurfrules/gi) ?? []
  return [...new Set(matches)]
}

/** 从文本中提取第一个受保护的上下文文件路径（guardian/check 通道内用） */
function extractContextTarget(text: string): string {
  return extractPathTokens(text).find((t) => isAgentContextFile(t)) ?? ''
}
