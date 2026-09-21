/**
 * 突发抑制引擎 —— 守卫"护栏自身的可用性"。
 *
 * 背景：arXiv:2606.14517《From Shield to Target: Denial-of-Service Attacks on
 * LLM-Based Agent Guardrails》证明攻击者可以用构造载荷让 agent 护栏陷入长推理
 * 循环——13~63× token 放大、148× 延迟放大，单个投毒文档即可饱和共享护栏设施，
 * 使同址 agent 全体饿死。另一面 arXiv:2607.01641《When Agents Do Not Stop》指出
 * 无界反馈回路会把单次请求放大为持续工具执行（成本耗尽 / 上下文增长）。
 *
 * 已有引擎回答的都是"这次调用的*内容*是否有害"；本引擎回答"调用的*总量*是否
 * 正在耗尽资源"——三条预算规则：
 *
 *  - BUD-001 call-budget   滑动窗口调用数超限（无限循环 / 失控重试的次数维度）
 *  - BUD-002 byte-budget   滑动窗口 payload 字节超限（上下文洪泛 / 巨型投毒文档）
 *  - BUD-003 oscillation   冲刺-静默振荡（机器化节奏，人类交互不可能出现的形状）
 *
 * 逆限流（inverse rate-limiting）设计：
 *  - 传统限流器拦"过快"——攻击者降到阈值下就穿透；预算熔断在*任何速率*下都会
 *    耗尽（单次 300KB 慢速滴灌与 30 次/5s 疾冲同样触顶）；
 *  - 预算随滑动窗口自然恢复——攻击停止后护栏自动愈合，不需要显式冷却状态，
 *    避免了永久拉黑带来的可用性损失。
 *
 * 记账无条件先于判定：被静态引擎拦截的调用同样计入预算（它同样消耗了护栏的
 * 处理成本——重试风暴正是靠这一点触顶）。
 */

export interface BudgetVerdict {
  /** 是否触发预算熔断 */
  tripped: true
  ruleId: 'BUD-001' | 'BUD-002' | 'BUD-003'
  reason: string
  /** 预算熔断为 deny 级：熔断期间直接拒绝，窗口滑出即自动恢复 */
  action: 'deny'
  /** 触发时的预算读数，用于审计与遥测 */
  stats: BudgetStats
}

export interface BudgetStats {
  /** 滑动窗口内调用数（含本次） */
  windowCalls: number
  /** 滑动窗口内 payload 总字节（含本次） */
  windowBytes: number
  /** 最近 12 秒 bucket 直方图：{ 秒时间戳, calls, bytes }[]，供振荡分析 */
  buckets: Array<{ sec: number; calls: number; bytes: number }>
  /** bucket 序列状态串（H=热 C=冷），BUD-003 触发时即为罪证 */
  signature: string
}

export namespace BudgetTracker {
  export interface Options {
    /** 滑动窗口宽度（ms），BUD-001/002 的预算半径。默认 5000 */
    windowMs?: number
    /** 窗口内调用数上限。默认 30（≈ 6 次/s 持续 5 秒仍余量） */
    maxCalls?: number
    /** 窗口内 payload 字节上限。默认 262144（256KB，单文档型洪泛即触顶） */
    maxBytes?: number
    /** 单秒 bucket 判"热"的调用数下限。默认 5 */
    hotCalls?: number
    /** 振荡分析覆盖的秒数。默认 12 */
    oscillationSecs?: number
    /** 触发 BUD-003 所需的冷→热跃迁次数。默认 3（冲刺-静默-冲刺 3 轮） */
    minTransitions?: number
  }

  export interface Snapshot extends BudgetStats {
    /** 当前离各预算顶的距离（负数=余量；正数=超出） */
    headroomCalls: number
    headroomBytes: number
    /** 振荡分析窗口内的冷→热跃迁次数 */
  transitions: number
  }
}

export class BudgetTracker {
  private readonly windowMs: number
  private readonly maxCalls: number
  private readonly maxBytes: number
  private readonly hotCalls: number
  private readonly oscillationSecs: number
  private readonly minTransitions: number

  private events: Array<{ t: number; bytes: number }> = []
  private buckets = new Map<number, { calls: number; bytes: number }>()

  constructor(opts: BudgetTracker.Options = {}) {
    this.windowMs = opts.windowMs ?? 5000
    this.maxCalls = opts.maxCalls ?? 30
    this.maxBytes = opts.maxBytes ?? 262144
    this.hotCalls = opts.hotCalls ?? 5
    this.oscillationSecs = opts.oscillationSecs ?? 12
    this.minTransitions = opts.minTransitions ?? 3
  }

  /**
   * 记账并判定。必须在每次 guardian/check（无论后续被静态引擎拦下还是放行）
   * 之前调用；返回 tripped=true 时由调用方以 deny 级熔断。
   */
  record(tool: string, payload: string, now: number = Date.now()): BudgetVerdict | { tripped: false } {
    const bytes = Buffer.byteLength(payload, 'utf8')
    void tool  // 工具名暂不参与判定（预算是全局资源），保留参数位供遥测扩展

    // 记账：滑动窗口事件表 + 秒级 bucket 直方图
    this.events.push({ t: now, bytes })
    const sec = Math.floor(now / 1000)
    const b = this.buckets.get(sec) ?? { calls: 0, bytes: 0 }
    b.calls += 1
    b.bytes += bytes
    this.buckets.set(sec, b)
    this.evict(now)

    const stats = this.stats(now)

    // BUD-001 调用数预算
    if (stats.windowCalls >= this.maxCalls) {
      return {
        tripped: true, ruleId: 'BUD-001', action: 'deny',
        reason: `调用数预算耗尽：${this.windowMs}ms 滑动窗口内 ${stats.windowCalls} 次（上限 ${this.maxCalls}）——疑似无限循环/失控重试`,
        stats,
      }
    }
    // BUD-002 字节预算
    if (stats.windowBytes >= this.maxBytes) {
      return {
        tripped: true, ruleId: 'BUD-002', action: 'deny',
        reason: `字节预算耗尽：${this.windowMs}ms 滑动窗口内 ${stats.windowBytes}B（上限 ${this.maxBytes}）——疑似上下文洪泛/巨型投毒载荷`,
        stats,
      }
    }
    // BUD-003 冲刺-静默振荡
    const transitions = this.countTransitions(stats.signature)
    if (transitions >= this.minTransitions) {
      return {
        tripped: true, ruleId: 'BUD-003', action: 'deny',
        reason: `突发-静默振荡：${transitions} 次冲刺（节奏签名 ${stats.signature}）——机器化调用循环，人类交互不可能出现的形状`,
        stats,
      }
    }
    return { tripped: false, ...stats }
  }

  /** 当前预算读数（不记账） */
  stats(now: number = Date.now()): BudgetStats {
    this.evict(now)
    const windowCalls = this.events.filter(e => now - e.t < this.windowMs).length
    const windowBytes = this.events
      .filter(e => now - e.t < this.windowMs)
      .reduce((s, e) => s + e.bytes, 0)
    return {
      windowCalls, windowBytes,
      buckets: this.recentBuckets(now),
      signature: this.signature(now),
    }
  }

  /** 非触发判定结果的读数（测试与遥测用，恒返回含统计的对象） */
  current(now: number = Date.now()): BudgetStats & { tripped: false } {
    return { tripped: false, ...this.stats(now) }
  }

  /** 宿主遥测快照 */
  snapshot(now: number = Date.now()): BudgetTracker.Snapshot {
    const s = this.stats(now)
    return {
      ...s,
      headroomCalls: s.windowCalls - this.maxCalls,
      headroomBytes: s.windowBytes - this.maxBytes,
      transitions: this.countTransitions(s.signature),
    }
  }

  reset() {
    this.events = []
    this.buckets = new Map()
  }

  /** 清理滑出两个分析窗口（调用预算 + 振荡直方图）外的旧记录 */
  private evict(now: number) {
    const horizon = Math.max(this.windowMs, this.oscillationSecs * 1000)
    if (this.events.length && now - this.events[0].t >= horizon) {
      this.events = this.events.filter(e => now - e.t < horizon)
    }
    const minSec = Math.floor(now / 1000) - this.oscillationSecs - 1
    for (const sec of this.buckets.keys()) {
      if (sec < minSec) this.buckets.delete(sec)
    }
  }

  private recentBuckets(now: number): Array<{ sec: number; calls: number; bytes: number }> {
    const curSec = Math.floor(now / 1000)
    const out: Array<{ sec: number; calls: number; bytes: number }> = []
    for (let s = curSec - this.oscillationSecs + 1; s <= curSec; s++) {
      const b = this.buckets.get(s)
      if (b) out.push({ sec: s, calls: b.calls, bytes: b.bytes })
    }
    return out
  }

  /** 12 秒节奏签名：H=热秒（calls≥hotCalls），C=冷秒。".": 介于两者 */
  private signature(now: number): string {
    const curSec = Math.floor(now / 1000)
    let sig = ''
    for (let s = curSec - this.oscillationSecs + 1; s <= curSec; s++) {
      const calls = this.buckets.get(s)?.calls ?? 0
      sig += calls >= this.hotCalls ? 'H' : calls === 0 ? 'C' : '.'
    }
    return sig
  }

  /** 冷→热跃迁次数：每出现一次 "冲刺前的静默" 记 1 次 */
  private countTransitions(signature: string): number {
    let n = 0
    let prevWasCold = true   // 起点视为静默
    for (const ch of signature) {
      const isHot = ch === 'H'
      if (isHot && prevWasCold) n++
      prevWasCold = ch === 'C'   // 中间态（.）不算静默间隔
    }
    return n
  }
}
