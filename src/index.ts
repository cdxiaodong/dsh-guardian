import { Context, Service } from 'cordis'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'

export const name = 'dsh-guardian'

/** 危险规则 */
export interface Rule {
  id: string
  pattern: RegExp
  reason: string
  /** block=需人工确认；deny=直接拒绝；log=仅记录 */
  action: 'block' | 'deny' | 'log'
}

/** 内置规则集（命令注入 / 破坏操作 / 凭据读取 / 反弹shell / 外泄） */
export const DEFAULT_RULES: Rule[] = [
  { id: 'rm-rf', pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+[~/]/i, reason: '递归强制删除目录', action: 'block' },
  { id: 'dd-disk', pattern: /\bdd\s+if=.*of=\/dev\//i, reason: 'dd 覆写磁盘设备', action: 'deny' },
  { id: 'mkfs', pattern: /\bmkfs\b/i, reason: '格式化文件系统', action: 'deny' },
  { id: 'fork-bomb', pattern: /:\(\)\s*\{\s*:\s*\|\s*:.*\}\s*;\s*:/, reason: 'fork 炸弹', action: 'deny' },
  { id: 'pipe-shell', pattern: /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, reason: '远程脚本管道执行', action: 'block' },
  { id: 'chmod-777-root', pattern: /chmod\s+(-R\s+)?777\s+\//i, reason: '放开系统目录权限', action: 'block' },
  { id: 'read-cred', pattern: /\.ssh\/|id_rsa|id_ed25519|\.aws\/|\.env\b|\/etc\/shadow/i, reason: '读取凭据/密钥文件', action: 'block' },
  { id: 'reverse-shell', pattern: /\/dev\/tcp\/|nc\s+-[a-z]*e\s|bash\s+-i\s+>&/i, reason: '反弹 shell', action: 'deny' },
  { id: 'git-push-force', pattern: /git\s+push\s+.*--force|git\s+push\s+-f\b/i, reason: 'git 强推', action: 'block' },
  { id: 'env-exfil', pattern: /\bprintenv\b[^|]*\|\s*(curl|wget|nc)\b|^\s*env\s*\|\s*(curl|wget|nc)\b/i, reason: '环境变量外泄', action: 'block' },
]

export interface AuditEntry {
  ts: string
  level: 'allow' | 'block' | 'deny'
  tool?: string
  ruleId?: string
  reason?: string
  snippet?: string
}

declare module 'cordis' {
  interface Context {
    guardian: GuardianService
  }
}

/**
 * 护栏服务：继承 cordis Service，name='guardian' 即对外提供的服务标识。
 * 宿主/上层在每次工具调用前触发 'guardian/check' 事件即可完成拦截。
 */
export class GuardianService extends Service {
  private stream: fs.WriteStream
  readonly logFile: string
  private rules: Rule[]

  constructor(ctx: Context, config: GuardianService.Config = {}) {
    super(ctx, 'guardian')
    this.rules = [...DEFAULT_RULES, ...(config.rules ?? [])]
    this.logFile = config.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
    this.stream = fs.createWriteStream(this.logFile, { flags: 'a' })

    // 可逆效应：插件卸载时自动关闭文件流
    ctx.effect(() => () => this.stream.end())

    // 护栏最先执行（prepend）。
    // cordis bail 语义：isBailed(v)= v!==null && v!==false && v!==undefined。
    // 因此 check 返回【拦截原因对象】=拦截；返回 false=放行（让后续监听器/宿主继续）。
    ctx.on('guardian/check' as any, (toolName: string, payload: unknown) => {
      return this.check(toolName, payload)
    }, true)
  }

  /**
   * 核心判定（适配 cordis bail 语义）：
   *  - 返回 { intercepted, reason, ruleId } 对象 → 命中规则，bail 短路返回该对象 = 拦截
   *  - 返回 false → 放行
   * 宿主用法：`const r = ctx.bail('guardian/check', tool, payload)`；r 为对象即被拦截。
   */
  check(toolName: string, payload: unknown): { intercepted: true; reason: string; ruleId: string; action: Rule['action'] } | false {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {})
    for (const rule of this.rules) {
      if (!rule.pattern.test(text)) continue
      const snippet = text.slice(0, 300)
      if (rule.action === 'deny') {
        this.audit({ level: 'deny', tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
        return { intercepted: true, reason: rule.reason, ruleId: rule.id, action: 'deny' }
      }
      if (rule.action === 'block') {
        this.audit({ level: 'block', tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
        // 宿主提供 'guardian/approve' 监听器做人工确认。
        // cordis bail 语义：truthy 会被当作 bail 结果短路返回，无法区分"批准true"。
        // 约定：approve 监听器返回 { approved: boolean } 对象；无监听器或 approved!==true 即拒绝。
        const res = this.ctx.bail('guardian/approve' as any, { tool: toolName, rule, snippet } as any)
        const approved = typeof res === 'object' && res !== null && (res as any).approved === true
        if (!approved) {
          return { intercepted: true, reason: `${rule.reason}（未获批准）`, ruleId: rule.id, action: 'block' }
        }
        // 已批准 → 继续检查后续规则
      } else {
        this.audit({ level: 'allow', tool: toolName, ruleId: rule.id, reason: rule.reason, snippet })
      }
    }
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
  }
}

/** cordis 插件入口（Function 形式），provide 声明对外提供 'guardian' 服务 */
export const provide = ['guardian']
export function apply(ctx: Context, config?: GuardianService.Config) {
  ctx.plugin(GuardianService, config)
}
