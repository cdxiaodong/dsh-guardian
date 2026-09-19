/**
 * 慢速外泄检测引擎（Drip Exfiltration Guard）—— engine-29
 *
 * 威胁模型：单次检查类防御（本仓库引擎 1-28 中的绝大多数、以及业界单轮
 * prompt guardrail）共享同一个盲区——时间。攻击者不追求一次得手，而是：
 *   1. 每轮只外泄一小片（单次字节量永远在阈值之下，#14 总量预算短期不报警）
 *   2. 用 sleep/timeout 原语把外泄动作拉开间隔，绕过任何会话内聚合
 *   3. 等间隔心跳式外泄（C2 beaconing 节奏：机器定时器没有人类抖动）
 *   4. 多轮渐进收集：每轮读一个敏感源（单次仅 log 级放行），凑齐全套后送出
 *
 * 三个缝合来源：
 *   - arXiv:2511.11790（Verifying LLM Inference to Prevent Model Weight
 *     Exfiltration, 2025-11）：形式化定义了 slow exfiltration——每月外泄
 *     1% 的模型权重，任何单次阈值检测在数学上都不可能触发
 *   - Darktrace AI Defense-in-Depth（2026-06）的 "Low and Slow Exfiltration"
 *     检测分类：签名抓不到低速外泄，只有行为节奏分析可以
 *   - 2026-08/09 accuknox / nhimg 的 stateful guardrails 主张：multi-turn
 *     攻击的恶意只在整段对话上可见，护栏必须有跨轮记忆
 *   - C2 beaconing 检测（Zeek/NetFlow 经典）：外泄间隔的变异系数（CV）
 *     极低 = 定时器节奏，人类操作的自然抖动 CV 通常 > 0.3
 *
 * 与 #14 Egress Budget 的分工：14 是会话生命周期的总量守恒（防"一次性
 * 搬空"，水库总闸）；本引擎是时间维度的速率与节奏（防"每次一点点、
 * 永远不超总量"，流量计 + 节奏分析）。
 *
 * Cordis 机制体现：
 *   - 状态随实例隔离：DripTracker 是 GuardianService 的实例字段，多个
 *     guardian 实例各自持账本，互不串台（时空可组合-空间维度）
 *   - 可逆效应：ctx.effect 注册 reset，插件卸载时清空行为账本（时间维度）
 */

/** 一次出境动作的行为记录 */
export interface DripEvent {
  ts: number
  /** 出境字节量估计（以调用负载长度为保守上界） */
  bytes: number
  tool: string
}

/** 本引擎的判定结果（deny 直接拦；block 走 guardian/approve 人工确认） */
export interface DripVerdict {
  ruleId: string
  reason: string
  action: 'deny' | 'block'
}

export interface DripOptions {
  /** 时钟注入（测试用），默认 Date.now */
  now?: () => number
  /** 滑动窗口宽度，默认 5 分钟 */
  windowMs?: number
  /** 窗口内累计出境字节上限，默认 256 KiB */
  maxWindowBytes?: number
  /** 行为记录的留存期（TTL 衰减），默认 1 小时 */
  horizonMs?: number
  /** 连续出境 streak 上限（DRP-002），默认 8 */
  streakLimit?: number
  /** 心跳检测的最少事件数（DRP-004），默认 5 */
  beaconMinEvents?: number
  /** 心跳检测的变异系数阈值（DRP-004），低于即判定为定时器节奏，默认 0.15 */
  beaconMaxCV?: number
  /** 跨轮累计敏感源种类上限（DRP-005），默认 3 */
  sensitiveSourceLimit?: number
}

export const DRP_DEFAULTS: Required<Omit<DripOptions, 'now'>> = {
  windowMs: 300_000,
  maxWindowBytes: 262_144,
  horizonMs: 3_600_000,
  streakLimit: 8,
  beaconMinEvents: 5,
  beaconMaxCV: 0.15,
  sensitiveSourceLimit: 3,
}

/**
 * 出境原语：网络发送 / 上传类动作。
 * 注意：全部不带 /g 标志（防 lastIndex 状态污染，见项目测试惯例）。
 */
export const OUTBOUND_PATTERN = /\b(curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|http\.post|https\.post|fetch\(|axios\.post|requests\.post|upload|send_file|sendfile|webhook)\b/i

/** 延迟调度原语：把外泄动作在时间上拉开间隔的"定时器" */
export const DELAY_PATTERN = /\b(sleep\s+\d+|timeout\s+\d+\s+\w+|nohup|at\s+(now|midnight|teatime)|cron|systemctl\s+(start|restart)\s+\w*timer)/i

/** 敏感源指纹：跨轮累计的去重单位（按模式而非按路径） */
export const SENSITIVE_SOURCES: RegExp[] = [
  /\.env\b/i,
  /\.ssh\b|id_rsa|id_ed25519|authorized_keys|known_hosts/i,
  /\.aws\b|aws_credentials/i,
  /\.netrc|\.npmrc|_netrc/i,
  /kubeconfig|\.kube\b/i,
  /\.gnupg|\.gpg\b|private[_-]?key/i,
  /\/etc\/shadow|\/etc\/passwd/i,
  /\.(bash|zsh|fish)_history|shell[_-]?history/i,
  /credentials\.json|service[_-]?account/i,
  /\.docker\/config\.json/i,
]

/** DRP 规则元数据（文档/测试引用；字段与 DripVerdict 对齐，可整体 spread） */
export const DRP_RULES: DripVerdict[] = [
  { ruleId: 'DRP-001', reason: '滑动窗口内累计出境字节超限（慢速滴漏速率违规）', action: 'deny' },
  { ruleId: 'DRP-002', reason: '连续多次工具调用全部为出境动作（非正常工作负载）', action: 'deny' },
  { ruleId: 'DRP-003', reason: '延迟原语调度外泄命令（sleep/timeout 拉开间隔绕过聚合）', action: 'block' },
  { ruleId: 'DRP-004', reason: '出境动作呈等间隔心跳节奏（C2 beaconing 签名）', action: 'deny' },
  { ruleId: 'DRP-005', reason: '跨轮累计读取多种敏感源后出现出境动作（渐进收集终局）', action: 'deny' },
]

interface SessionState {
  /** 出境事件账本（按 ts 升序追加） */
  events: DripEvent[]
  /** 连续出境 streak：遇到非出境调用即清零 */
  streak: number
  /** 跨轮累计命中的敏感源指纹（模式索引去重） */
  sensitiveHits: Set<number>
}

/**
 * 行为账本 + 判定器。每次工具调用先入账（无论其他引擎是否拦截），
 * 再对本轮状态做五条 DRP 判定。TTL 衰减在每次入账时惰性清理。
 */
export class DripTracker {
  private readonly opts: Required<Omit<DripOptions, 'now'>> & { now: () => number }
  private readonly state: SessionState = { events: [], streak: 0, sensitiveHits: new Set() }

  constructor(options: DripOptions = {}) {
    this.opts = { ...DRP_DEFAULTS, now: options.now ?? Date.now, ...stripNow(options) }
  }

  /** 记账 + 判定。返回命中的违规（可能多条；调用方取第一条处置） */
  recordAndInspect(tool: string, text: string): DripVerdict[] {
    const now = this.opts.now()
    const isOutbound = OUTBOUND_PATTERN.test(text)
    OUTBOUND_PATTERN.lastIndex = 0

    // 敏感源记账（读写皆记：DRP-005 只在「累计多种 + 出境」时触发，纯读不拦）
    for (let i = 0; i < SENSITIVE_SOURCES.length; i++) {
      if (SENSITIVE_SOURCES[i].test(text)) this.state.sensitiveHits.add(i)
    }

    if (isOutbound) {
      this.state.streak++
      this.gc(now)
      this.state.events.push({ ts: now, bytes: text.length, tool })
    } else {
      this.state.streak = 0
    }

    const verdicts: DripVerdict[] = []
    // DRP-003：延迟原语 × 出境命令（无状态文本特征，block 级走人工确认）
    if (isOutbound && DELAY_PATTERN.test(text)) {
      verdicts.push({ ...DRP_RULES[2] })
    }
    // DRP-005：渐进收集终局——敏感源种类凑够后任何出境都是终点
    if (isOutbound && this.state.sensitiveHits.size >= this.opts.sensitiveSourceLimit) {
      verdicts.push({
        ruleId: DRP_RULES[4].ruleId,
        reason: `${DRP_RULES[4].reason}（已累计 ${this.state.sensitiveHits.size} 种）`,
        action: 'deny',
      })
    }
    // DRP-001：滑动窗口字节守恒（速率维度）
    const winEvents = this.state.events.filter((e) => now - e.ts <= this.opts.windowMs)
    const winBytes = winEvents.reduce((s, e) => s + e.bytes, 0)
    if (winBytes > this.opts.maxWindowBytes) {
      verdicts.push({
        ruleId: DRP_RULES[0].ruleId,
        reason: `DRP-001 滑动窗口（${this.opts.windowMs}ms）内累计出境 ${winBytes} 字节，超过上限 ${this.opts.maxWindowBytes}`,
        action: 'deny',
      })
    }
    // DRP-002：连续出境 streak（出境占比 100% 的机器人式负载）
    if (this.state.streak >= this.opts.streakLimit) {
      verdicts.push({ ...DRP_RULES[1] })
    }
    // DRP-004：等间隔心跳（变异系数 CV = σ/μ 极低 = 定时器，非人类抖动）
    if (winEvents.length >= this.opts.beaconMinEvents) {
      const gaps: number[] = []
      for (let i = 1; i < winEvents.length; i++) gaps.push(winEvents[i].ts - winEvents[i - 1].ts)
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length
      if (mean > 0) {
        const variance = gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length
        const cv = Math.sqrt(variance) / mean
        if (cv < this.opts.beaconMaxCV) {
          verdicts.push({
            ruleId: DRP_RULES[3].ruleId,
            reason: `${DRP_RULES[3].reason}（最近 ${winEvents.length} 次出境间隔 CV=${cv.toFixed(3)} < ${this.opts.beaconMaxCV}）`,
            action: 'deny',
          })
        }
      }
    }
    return verdicts
  }

  /** TTL 衰减：剔除超出留存期的老事件（惰性 GC，不永久记仇） */
  private gc(now: number) {
    const cutoff = now - this.opts.horizonMs
    this.state.events = this.state.events.filter((e) => e.ts >= cutoff)
  }

  /** 卸载清理（可逆效应调用） */
  reset() {
    this.state.events = []
    this.state.streak = 0
    this.state.sensitiveHits.clear()
  }

  /** 测试/观测辅助：当前窗口内出境字节合计 */
  windowBytes(now = this.opts.now()): number {
    return this.state.events
      .filter((e) => now - e.ts <= this.opts.windowMs)
      .reduce((s, e) => s + e.bytes, 0)
  }

  get sensitiveSourceCount(): number {
    return this.state.sensitiveHits.size
  }
}

function stripNow(o: DripOptions): Omit<DripOptions, 'now'> {
  const { now: _now, ...rest } = o
  return rest
}
