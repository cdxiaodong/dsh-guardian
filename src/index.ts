import type { Context } from '@deepseek-ai/cordis'

export const name = 'dsh-guardian'

// 声明依赖：等 tools 服务就绪才加载（响应式协效应）
export const inject = ['tools']

/** 敏感操作规则：命中即要求人工确认 */
const DANGER_RULES: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /rm\s+-rf\s+[~/]/, reason: '递归删除目录' },
  { pattern: />\s*\/dev\/sd/, reason: '覆写磁盘设备' },
  { pattern: /:\(\)\{.*:\|:.*\}/, reason: 'fork 炸弹' },
  { pattern: /curl[^|]*\|\s*(ba)?sh/, reason: '远程脚本管道执行' },
  { pattern: /(mkfs|dd\s+if=)/, reason: '格式化/写盘' },
  { pattern: /chmod\s+777\s+\//, reason: '放开系统目录权限' },
  { pattern: /\.ssh|id_rsa|\.aws|\.env\b/i, reason: '读取凭据/密钥' },
]

export function apply(ctx: Context) {
  // ── 1. 审计日志（写本地文件，随插件卸载自动关闭句柄）──────────────
  const logFile = `${process.env.HOME}/.dsh-guardian.audit.log`
  const fs = require('node:fs')
  const stream = fs.createWriteStream(logFile, { flags: 'a' })

  // ctx.effect：我们持有需要显式释放的资源（文件流），返回撤销函数
  ctx.effect(() => {
    return () => stream.close()   // 插件卸载时自动执行
  })

  function audit(entry: object) {
    stream.write(JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n')
  }

  // ── 2. 工具调用拦截（核心：在真正执行前检查）──────────────────────
  // Cordis 拦截机制：挂到 tools 服务上，对所有工具调用做前置审查
  ctx.tools.intercept(async (call, next) => {
    const text = JSON.stringify(call.args ?? {})

    for (const rule of DANGER_RULES) {
      if (rule.pattern.test(text)) {
        audit({ level: 'block', tool: call.name, reason: rule.reason, args: call.args })

        // 要求人工确认（approval policy）
        const ok = await ctx.approval.ask({
          title: `⚠️ 危险操作：${rule.reason}`,
          detail: `工具 ${call.name} 命中规则，参数：${text.slice(0, 200)}`,
        })
        if (!ok) {
          throw new Error(`[dsh-guardian] 已阻止：${rule.reason}`)
        }
      }
    }

    audit({ level: 'allow', tool: call.name })
    return next()   // 放行，继续执行真正的工具
  })

  // ── 3. 暴露一个查询工具：让 Agent/用户能查审计日志 ─────────────────
  ctx.tools.register({
    name: 'guardian_audit_query',
    description: '查询 dsh-guardian 的安全审计日志（最近 N 条）',
    parameters: {
      type: 'object',
      properties: { limit: { type: 'number', default: 20 } },
    },
    async execute({ limit }: { limit: number }) {
      const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n')
      return lines.slice(-limit).map((l: string) => JSON.parse(l))
    },
  })
}
