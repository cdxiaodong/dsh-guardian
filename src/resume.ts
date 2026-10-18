/**
 * Engine 45: Resume Integrity Guard（恢复/回滚完整性守卫）
 *
 * 缝合 "Safe to Resume? Breaking Execution Continuity of Agent Execution via
 * Rollback"（arXiv:2608.29381，2026-08-29）：Agent 的检查点/回滚（C/R）被当作
 * 可靠性机制，但"正确的回滚 ≠ 安全的恢复"——忠实还原的检查点可能续上一段
 * "状态、前提、外部效应从未在任何合法历史中共存过"的执行。论文归纳的失效
 * 类别：内部状态不完整/不一致、外部依赖过期、非确定性重放、外部效应未记录；
 * 并在 Hermes / Cline / LangGraph 上打通了恶意软件校验绕过、越权转发邮件、
 * 重复扣款三条端到端攻击。
 *
 * 本引擎的关键架构点：**恢复账本活在守卫进程里，不在 Agent 的检查点里**。
 * 回滚能把 Agent 的内存/对话/状态图倒回去，但倒不回守卫的账本——账本是
 * 回滚免疫的见证者（rollback-immune witness），每次"续上"都要先对账：
 *
 *   ① 登记：宿主为每个有副作用的动作传 resumeToken（幂等/续传标识），
 *      首次出现记为基线：规范化内容指纹 + 授权过期时间 + 外部依赖指纹 +
 *      是否天然幂等。基线字段**只在登记时采信**——恢复路径不能自报。
 *   ② 结算：宿主在效应确认落地后调 guardian/resume-commit；确认没落地
 *      （调用失败/已回滚）调 guardian/resume-abort。
 *   ③ 恢复：同 token 再来，按"效应已落地 > 授权过期 > 内容偷换 > 依赖漂移 >
 *      结果未知"逐级对账，任一前提不成立就拦。
 *
 * 规则表（审计通道 engine='resume'）：
 *   RSM-001 deny  重复落地——效应已 committed，同 token 再触发（重复扣款）
 *   RSM-002 block 内容偷换——同 token 内容/工具与基线不符（非确定性重放）
 *   RSM-003 deny  授权失效——基线授权已过期，不能跨中断缺口静默延用
 *   RSM-004 block 冒领恢复——isResume=true 但账本无基线（内部状态不一致）
 *   RSM-005 block 依赖漂移——批准时依赖的外部事实已变（恶意软件校验绕过）
 *   RSM-006 block 结果未知——上次尝试既未 commit 也未 abort 就恢复，
 *                效应可能已落地但没被记录（未记录外部效应 → 重复扣款）
 *
 * 与相邻引擎的分工：compensation（engine-41）管"后果撤得销吗"；Kairos
 * （engine-42）管"要不要现在批"；Delegation（engine-43）管"批准还剩多少"；
 * 本引擎管"批准过的动作被中断后，还能不能原样续上"。
 */

import * as crypto from 'node:crypto'

export type ResumeRuleId = 'RSM-001' | 'RSM-002' | 'RSM-003' | 'RSM-004' | 'RSM-005' | 'RSM-006'
export type ResumeStatus = 'inflight' | 'committed' | 'aborted'

export interface ResumeCheckOptions {
  /** 宿主显式声明：本次调用是否为中断/回滚后的恢复重试（而非首次执行） */
  isResume?: boolean
  /** 本次调用背书的授权票据过期时间（ms epoch）。仅在基线登记时采信 */
  authExpiresAt?: number
  /**
   * 外部依赖指纹：批准该动作时依赖的外部事实（如已扫描文件的 sha256、
   * 收件人白名单版本、账户余额快照）。登记时存为基线；恢复时宿主重新计算
   * 后传入，任一键缺失或不一致即 RSM-005。
   */
  deps?: Record<string, string>
  /** 该动作是否天然幂等（重复执行无额外效应）。仅在基线登记时采信 */
  idempotent?: boolean
  now?: number
}

export interface ResumeVerdict {
  intercepted: boolean
  ruleId: ResumeRuleId | null
  action: 'deny' | 'block' | null
  reason?: string
}

export interface ResumeEntry {
  token: string
  tool: string
  contentHash: string
  firstSeenTs: number
  lastTs: number
  attempts: number
  status: ResumeStatus
  authExpiresAt?: number
  deps?: Record<string, string>
  idempotent: boolean
  snippet: string
}

export interface ResumeSnapshot {
  total: number
  inflight: number
  committed: number
  aborted: number
  byTool: Record<string, number>
}

export interface ResumeConfig {
  enabled?: boolean
  /** 账本容量上限（防内存膨胀；默认 1024，优先淘汰非 committed 的最旧条目） */
  maxEntries?: number
  /** 条目有效期（ms；默认 7 天） */
  ttl?: number
  now?: () => number
}

/**
 * 规范化 JSON：对象键按字典序排列后再序列化。LLM 恢复时重新生成的调用参数
 * 常常键序不同但语义相同——直接 JSON.stringify 会把它误判成内容偷换。
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(v).sort()) sorted[k] = (v as Record<string, unknown>)[k]
      return sorted
    }
    return v
  }) ?? 'null'
}

/** 内容指纹：同 token 的两次调用内容是否一致（偷换检测） */
export function contentHash(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex')
}

/** 依赖漂移：返回基线中缺失或值已变的依赖键 */
export function depDrift(baseline: Record<string, string> | undefined, current: Record<string, string> | undefined): string[] {
  if (!baseline) return []
  const drifted: string[] = []
  for (const [k, v] of Object.entries(baseline)) {
    if (current?.[k] !== v) drifted.push(k)
  }
  return drifted
}

const PASS: ResumeVerdict = { intercepted: false, ruleId: null, action: null }

export class ResumeLedger {
  private entries = new Map<string, ResumeEntry>()
  private maxEntries: number
  private ttl: number
  private now: () => number

  constructor(cfg: ResumeConfig = {}) {
    this.maxEntries = cfg.maxEntries ?? 1024
    this.ttl = cfg.ttl ?? 7 * 24 * 3600 * 1000
    this.now = cfg.now ?? (() => Date.now())
  }

  private sweep(t: number) {
    if (this.ttl >= Infinity) return
    for (const [token, e] of this.entries) {
      if (t - e.lastTs > this.ttl) this.entries.delete(token)
    }
  }

  private evictIfNeeded() {
    if (this.entries.size <= this.maxEntries) return
    // 优先淘汰非 committed 的最旧条目——已落地的效应要保留，否则 RSM-001 失效
    let victim: string | undefined
    for (const [token, e] of this.entries) {
      if (e.status === 'committed') continue
      if (!victim || e.lastTs < this.entries.get(victim)!.lastTs) victim = token
    }
    if (!victim) victim = this.entries.keys().next().value
    if (victim !== undefined) this.entries.delete(victim)
  }

  private register(tool: string, token: string, text: string, opts: ResumeCheckOptions, t: number) {
    this.entries.set(token, {
      token, tool, contentHash: contentHash(text), firstSeenTs: t, lastTs: t,
      attempts: 1, status: 'inflight', authExpiresAt: opts.authExpiresAt,
      deps: opts.deps ? { ...opts.deps } : undefined, idempotent: opts.idempotent === true,
      snippet: text.slice(0, 300),
    })
    this.evictIfNeeded()
  }

  /** 核心判定：延续性是否成立（放行前） */
  check(tool: string, token: string, text: string, opts: ResumeCheckOptions = {}): ResumeVerdict {
    const t = opts.now ?? this.now()
    this.sweep(t)

    const e = this.entries.get(token)
    if (!e) {
      if (opts.isResume) {
        return { intercepted: true, ruleId: 'RSM-004', action: 'block', reason: `声称是恢复重试（resumeToken=${token}），但账本中找不到对应的原始尝试记录——Agent 的内部状态与守卫账本不一致` }
      }
      if (opts.authExpiresAt !== undefined && t > opts.authExpiresAt) {
        return { intercepted: true, ruleId: 'RSM-003', action: 'deny', reason: `resumeToken=${token} 登记时背书的授权已于 ${new Date(opts.authExpiresAt).toISOString()} 过期` }
      }
      this.register(tool, token, text, opts, t)
      return PASS
    }

    if (e.status === 'committed') {
      return { intercepted: true, ruleId: 'RSM-001', action: 'deny', reason: `resumeToken=${token} 对应的效应已落地（committed），同 token 再次触发属于重复执行（重复扣款/重复消费类风险）` }
    }

    if (e.authExpiresAt !== undefined && t > e.authExpiresAt) {
      return { intercepted: true, ruleId: 'RSM-003', action: 'deny', reason: `resumeToken=${token} 的原始授权已于 ${new Date(e.authExpiresAt).toISOString()} 过期，不能跨中断缺口静默延用` }
    }

    if (contentHash(text) !== e.contentHash || tool !== e.tool) {
      return { intercepted: true, ruleId: 'RSM-002', action: 'block', reason: `resumeToken=${token} 声称延续同一动作，但调用内容与原始基线不一致——非确定性重放：重新生成的请求被当作已批准动作的延续` }
    }

    const drifted = depDrift(e.deps, opts.deps)
    if (drifted.length) {
      return { intercepted: true, ruleId: 'RSM-005', action: 'block', reason: `resumeToken=${token} 批准时依赖的外部事实已失效或未重新校验：${drifted.join(', ')}——不能沿用回滚前的校验结论` }
    }

    if (opts.isResume && e.status === 'inflight' && !e.idempotent) {
      return { intercepted: true, ruleId: 'RSM-006', action: 'block', reason: `resumeToken=${token} 的上一次尝试（第 ${e.attempts} 次）既未确认落地也未确认失败就被恢复——效应可能已落地但未被记录，需先对账（guardian/resume-commit 或 guardian/resume-abort）` }
    }

    this.touch(e, t)
    return PASS
  }

  /**
   * 人工批准了一条 block 级拦截后调用：批准的内容/依赖成为新基线，本次
   * 尝试记为新的在途尝试。deny 级（RSM-001/003）没有批准路径，不会走到这里。
   */
  accept(tool: string, token: string, text: string, opts: ResumeCheckOptions = {}): void {
    const t = opts.now ?? this.now()
    const e = this.entries.get(token)
    if (!e) {
      this.register(tool, token, text, opts, t)
      return
    }
    e.tool = tool
    e.contentHash = contentHash(text)
    e.snippet = text.slice(0, 300)
    if (opts.deps) e.deps = { ...opts.deps }
    this.touch(e, t)
  }

  private touch(e: ResumeEntry, t: number) {
    e.attempts += 1
    e.lastTs = t
    e.status = 'inflight'
  }

  /** 宿主确认效应已成功落地。未知 token 返回 false */
  commit(token: string): boolean {
    const e = this.entries.get(token)
    if (!e) return false
    e.status = 'committed'
    return true
  }

  /**
   * 宿主确认上一次尝试的效应没有落地（调用失败/对端已回滚），允许重试。
   * 已 committed 的效应不能 abort——撤销已落地效应是补偿引擎的事。
   */
  abort(token: string): boolean {
    const e = this.entries.get(token)
    if (!e || e.status === 'committed') return false
    e.status = 'aborted'
    return true
  }

  get(token: string): ResumeEntry | undefined {
    const e = this.entries.get(token)
    return e ? { ...e, deps: e.deps ? { ...e.deps } : undefined } : undefined
  }

  snapshot(): ResumeSnapshot {
    const snap: ResumeSnapshot = { total: this.entries.size, inflight: 0, committed: 0, aborted: 0, byTool: {} }
    for (const e of this.entries.values()) {
      snap.byTool[e.tool] = (snap.byTool[e.tool] ?? 0) + 1
      snap[e.status] += 1
    }
    return snap
  }
}
