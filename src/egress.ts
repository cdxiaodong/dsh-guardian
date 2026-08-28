/**
 * 出境预算引擎（engine-14）：Egress Budget / 量化行为画像。
 *
 * 核心思想：内容检测的尽头是物理量。现有全部引擎（正则/熵/指纹/数据流/状态机）
 * 都是"内容语义检测"——攻击者可以加密、编码、分块、变形绕过任何内容分析，
 * 但有一件事绕不过去：**字节守恒**。数据要离开本机，就必然占用字节数与调用次数。
 * 本引擎不看内容，只数数：
 *   - 窗口内累计出境字节  → 分块渗出（low-and-slow exfiltration）检测
 *   - 单次出境字节峰值    → 一次性批量外传检测
 *   - 窗口内调用频次      → 失控循环 / 自动化扫描行为检测
 *
 * 业界依据（为什么 egress 控制是内容检测的必要补充）：
 *  - arXiv:2604.05432（Data Exfiltration via Backdoored Tool Use, 2026）——
 *    防御建议明确包含 per-tool quotas on request volume（按工具的请求量配额）；
 *  - Sophos《Inside the Lethal Trifecta》——blast-radius reduction 的关键模式
 *    即 egress restriction：被攻陷的 Agent 就是持有活凭据的外传通道，出口设防收窄爆炸半径；
 *  - Appinventiv/Prompt Injection Defense —— "egress control catches what the payload
 *    was *trying to accomplish*: it doesn't need to recognize the attack itself to work"
 *    （出境控制抓的是攻击意图，不需要识别攻击本身）；
 *  - Cloudflare WAF rate limiting —— 滑动时间窗算法的经典工程实现。
 *
 * 与其他引擎的正交性：rule/secret/ssrf=单次内容，deobfuscate=解码后内容，
 * chain=定性序列，taint=语义数据流，memory=攻击指纹 —— 本引擎是唯一的
 * **定量维度**（体积/频次），内容加密后照样命中。
 *
 * 交互语义："批准即重置"——用户人工批准一次预算超限后，该维度窗口清零重新记账
 * （合法大上传只打扰一次），与攻击记忆引擎的"批准即遗忘"哲学一致。
 */

/** 出境类工具名启发式（前缀匹配，小写化后比对）。命中才记出境字节 */
export const EGRESS_TOOL_RE = /^(curl|wget|fetch|http|https|post|put|upload|webhook|email|smtp|send|axios|request|scp|sftp|rsync|nc|netcat|browser|navigate|web|api|dns|ping)/

/** 预算超限的维度 */
export type BudgetDimension = 'egress-bytes' | 'peak-payload' | 'calls'

/** 一次预算违规 */
export interface BudgetViolation {
  dimension: BudgetDimension
  /** 对应规则 ID（BUDGET-*） */
  ruleId: string
  /** 当前用量（字节数或次数） */
  used: number
  /** 上限 */
  limit: number
  /** 时间窗毫秒（peak-payload 维度为 0，表示瞬时约束） */
  windowMs: number
  /** 人读理由（含审计文案） */
  reason: string
}

/** 窗口用量快照 */
export interface BudgetUsage {
  egressBytes: number
  calls: number
  /** 窗口内单次出境的最大字节数 */
  peakEgressBytes: number
  windowMs: number
}

/** 估算 payload 的 UTF-8 字节数（string 直测，对象 JSON 序列化后测） */
export function estimateBytes(payload: unknown): number {
  if (payload == null) return 0
  const s = typeof payload === 'string' ? payload : JSON.stringify(payload)
  return Buffer.byteLength(s, 'utf8')
}

/** 工具名是否为出境类（网络出口） */
export function isEgressTool(toolName: string): boolean {
  return EGRESS_TOOL_RE.test(toolName.toLowerCase())
}

/** 字节数人读化（BUDGET 文案用） */
export function fmtBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)}KB`
  return `${n}B`
}

export namespace EgressBudget {
  export interface Config {
    /** 滑动时间窗毫秒，默认 60_000（1 分钟） */
    windowMs?: number
    /** 窗口内累计出境字节上限，默认 512 * 1024（512KB/分钟） */
    maxEgressBytes?: number
    /** 单次出境字节峰值上限，默认 1024 * 1024（1MB） */
    maxPayloadBytes?: number
    /** 窗口内调用次数上限（含被拦截的尝试——尝试本身即行为信号），默认 120 */
    maxCalls?: number
    /** 时钟注入（测试用），默认 Date.now */
    now?: () => number
  }
}

/** 出境预算记账器：滑窗聚合出境体积与调用频次，超限产出 BudgetViolation */
export class EgressBudget {
  readonly windowMs: number
  private readonly maxEgressBytes: number
  private readonly maxPayloadBytes: number
  private readonly maxCalls: number
  private readonly now: () => number
  /** 窗口内调用时间戳（升序） */
  private callTimes: number[] = []
  /** 窗口内出境事件（升序） */
  private egressEvents: Array<{ ts: number; bytes: number }> = []

  constructor(config: EgressBudget.Config = {}) {
    this.windowMs = config.windowMs ?? 60_000
    this.maxEgressBytes = config.maxEgressBytes ?? 512 * 1024
    this.maxPayloadBytes = config.maxPayloadBytes ?? 1024 * 1024
    this.maxCalls = config.maxCalls ?? 120
    this.now = config.now ?? (() => Date.now())
  }

  /** 滑出窗口的记录出队 */
  private prune(now: number) {
    const cutoff = now - this.windowMs
    while (this.callTimes.length && this.callTimes[0] <= cutoff) this.callTimes.shift()
    while (this.egressEvents.length && this.egressEvents[0].ts <= cutoff) this.egressEvents.shift()
  }

  /**
   * 记一次工具调用（频次维度）。不管本次调用最终放行与否——被拦截的尝试
   * 同样暴露失控循环/扫描行为。超限返回 violation。
   */
  observeCall(tool?: string): BudgetViolation | null {
    const now = this.now()
    this.prune(now)
    this.callTimes.push(now)
    if (this.callTimes.length <= this.maxCalls) return null
    return {
      dimension: 'calls',
      ruleId: 'BUDGET-CALLS',
      used: this.callTimes.length,
      limit: this.maxCalls,
      windowMs: this.windowMs,
      reason: `出境预算：${this.windowMs / 1000}s 内已发起 ${this.callTimes.length} 次工具调用（上限 ${this.maxCalls}）——疑似失控循环或自动化扫描${tool ? `（当前工具 ${tool}）` : ''}`,
    }
  }

  /**
   * 记一次出境字节（累计 + 峰值维度）。返回最严重的违规（峰值优先于累计）。
   */
  observeEgress(payload: unknown, tool?: string): BudgetViolation | null {
    const now = this.now()
    this.prune(now)
    const bytes = estimateBytes(payload)
    this.egressEvents.push({ ts: now, bytes })
    if (bytes > this.maxPayloadBytes) {
      return {
        dimension: 'peak-payload',
        ruleId: 'BUDGET-PEAK',
        used: bytes,
        limit: this.maxPayloadBytes,
        windowMs: 0,
        reason: `出境预算：单次出境 ${fmtBytes(bytes)} 超过峰值上限 ${fmtBytes(this.maxPayloadBytes)}——疑似批量外传${tool ? `（工具 ${tool}）` : ''}`,
      }
    }
    const total = this.egressEvents.reduce((s, e) => s + e.bytes, 0)
    if (total > this.maxEgressBytes) {
      return {
        dimension: 'egress-bytes',
        ruleId: 'BUDGET-EGRESS',
        used: total,
        limit: this.maxEgressBytes,
        windowMs: this.windowMs,
        reason: `出境预算：${this.windowMs / 1000}s 内累计出境 ${fmtBytes(total)}（上限 ${fmtBytes(this.maxEgressBytes)}）——疑似分块渗出（low-and-slow exfiltration）`,
      }
    }
    return null
  }

  /** 当前窗口用量快照 */
  usage(): BudgetUsage {
    this.prune(this.now())
    const peak = this.egressEvents.reduce((m, e) => Math.max(m, e.bytes), 0)
    return {
      egressBytes: this.egressEvents.reduce((s, e) => s + e.bytes, 0),
      calls: this.callTimes.length,
      peakEgressBytes: peak,
      windowMs: this.windowMs,
    }
  }

  /** 批准即重置：清空指定维度的窗口记账（合法大上传只打扰一次） */
  reset(dimension: BudgetDimension) {
    if (dimension === 'calls') this.callTimes = []
    else this.egressEvents = []
  }
}
