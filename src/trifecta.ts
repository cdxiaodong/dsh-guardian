/**
 * 时空致命三角检测引擎（Lethal Trifecta / Meta "Agents Rule of Two"）。
 *
 * 借鉴来源：
 *  - Simon Willison "Lethal Trifecta"：Agent 同时具备 ①私有数据访问 ②不可信内容摄入 ③外部通信能力 时即高危，
 *    因为间接提示注入可以把私有数据顺着外部通道泄露出去。
 *  - Meta AI "Agents Rule of Two"：一个会话**最多只能占三条中的两条**，超过即违反部署启发式。
 *  - armosec "AI Agent Attack Kill Chain"：单次调用各自合法，只有"序列的形状"暴露攻击；
 *    外泄 = "允许的通道 + 允许的目的地 + 异常的形态"。
 *
 * 现有引擎都是**空间维度**（单次调用、无状态判定）；本引擎补齐**时间维度**：
 * 把一个会话滑动窗口内的工具调用投影到三类能力，三者齐备即判定致命三角成形。
 * 这正是 cordis「时空可组合」中"时间"维度的落地——单看每一次调用都可能合法，组合起来才暴露攻击。
 */

/** 三类能力维度（致命三角的三条边） */
export type Capability = 'private-data' | 'untrusted-content' | 'external-egress'

export const CAPABILITIES: readonly Capability[] = ['private-data', 'untrusted-content', 'external-egress']

/** 一次能力观测事件 */
export interface TrifectaEvent {
  ts: number
  capability: Capability
  tool: string
  /** 为什么归到这类能力（审计/说明用） */
  evidence: string
}

export interface TrifectaTrackerOptions {
  /** 滑动窗口时长 ms（默认 10 分钟） */
  windowMs?: number
  /** 窗口内最多保留事件数（默认 200，防爆内存） */
  maxEvents?: number
  /** 注入时钟，便于测试（默认 Date.now） */
  now?: () => number
}

export interface TrifectaStatus {
  /** 三者是否齐备（致命三角成形） */
  assembled: boolean
  /** 窗口内已出现的能力 */
  present: Capability[]
  /** 尚缺的能力（Rule of Two：缺一条即合规） */
  missing: Capability[]
  /** 各能力在窗事件数 */
  counts: Record<Capability, number>
  /** 各能力最近一次事件（用于审计/说明） */
  latest: Partial<Record<Capability, TrifectaEvent>>
}

/**
 * 会话级滑动窗口能力追踪器。
 * 读取/写入都会先修剪过期事件，无需后台定时器（确定性、易测试）。
 */
export class TrifectaTracker {
  private events: TrifectaEvent[] = []
  private readonly windowMs: number
  private readonly maxEvents: number
  private readonly now: () => number

  constructor(opts: TrifectaTrackerOptions = {}) {
    this.windowMs = opts.windowMs ?? 10 * 60 * 1000
    this.maxEvents = opts.maxEvents ?? 200
    this.now = opts.now ?? (() => Date.now())
  }

  /** 记录一次能力观测（随后修剪过期/超量事件） */
  record(capability: Capability, tool: string, evidence: string): void {
    this.events.push({ ts: this.now(), capability, tool, evidence })
    this.prune()
  }

  /** 修剪：先剔除滑出时间窗的，再按容量上限 FIFO 淘汰 */
  private prune(): void {
    const cutoff = this.now() - this.windowMs
    let firstLive = 0
    while (firstLive < this.events.length && this.events[firstLive].ts < cutoff) firstLive++
    if (firstLive > 0) this.events.splice(0, firstLive)
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents)
    }
  }

  /** 当前窗口状态（读取前修剪一次，保证不读到过期事件） */
  status(): TrifectaStatus {
    this.prune()
    const counts: Record<Capability, number> = { 'private-data': 0, 'untrusted-content': 0, 'external-egress': 0 }
    const latest: Partial<Record<Capability, TrifectaEvent>> = {}
    for (const ev of this.events) {   // events 按时间升序，遍历时后者覆盖前者即“最近”
      counts[ev.capability]++
      latest[ev.capability] = ev
    }
    const present = CAPABILITIES.filter((c) => counts[c] > 0)
    const missing = CAPABILITIES.filter((c) => counts[c] === 0)
    return { assembled: missing.length === 0, present, missing, counts, latest }
  }

  /** 致命三角是否成形 */
  assembled(): boolean {
    return this.status().assembled
  }

  /** 清空窗口（插件卸载时的可逆效应清理） */
  reset(): void {
    this.events = []
  }
}

/** 规则 category → 能力维度（复用 mcp-safeguard 分类法语义，只取映射明确的） */
const CATEGORY_CAPABILITY: Record<string, Capability> = {
  credential: 'private-data',            // 读 .ssh/.aws/.env 等凭据
  'prompt-injection': 'untrusted-content', // 命中提示注入 ⇒ 内容来自不可信源
  'tool-poisoning': 'untrusted-content',   // 工具返回/描述被投毒 ⇒ 不可信内容
  exfil: 'external-egress',              // 显式外泄组合
  network: 'external-egress',            // 网络目标
  injection: 'external-egress',          // 反弹shell/命令注入会打开外联通道
}

/**
 * 工具名启发式（规则未命中时补充判断意图）。
 * 读文件≈私有数据访问；抓外部内容≈不可信摄入；发数据出站≈外部通道。
 * 注意：用环视 (?<![a-z0-9])/(?![a-z0-9]) 而非 \b——因为 \b 不把下划线当分隔符，
 * 会漏掉 read_file / web_fetch / http_post 这类 snake_case 工具名。
 */
const TOOL_HINTS: Array<[RegExp, Capability]> = [
  [/(?<![a-z0-9])(read|cat|load|open|view|getfile|get_file|readfile|read_file|secret|credential|getenv|env|download)(?![a-z0-9])/i, 'private-data'],
  [/(?<![a-z0-9])(fetch|browse|scrape|crawl|search|readurl|read_url|websearch|web_search|geturl|get_url|httpget|http_get|retrieve|loadurl|load_url|visit)(?![a-z0-9])/i, 'untrusted-content'],
  [/(?<![a-z0-9])(send|post|upload|email|webhook|publish|httppost|http_post|httprequest|http_request|request|put|curl|wget|transmit|exfil|share)(?![a-z0-9])/i, 'external-egress'],
]

/** 一次工具调用的观测输入（由宿主/服务从既有检测器输出组装） */
export interface CapabilityObservation {
  /** 工具名 */
  tool?: string
  /** 本次命中规则的 category 集合 */
  categories?: Iterable<string>
  /** 本次是否检出明文密钥（secret 引擎） */
  secret?: boolean
  /** 本次是否命中网络目标（ssrf 引擎） */
  network?: boolean
}

/** 把一次工具调用投影到能力维度集合（去重、确定性顺序） */
export function classifyCapabilities(obs: CapabilityObservation): Capability[] {
  const caps = new Set<Capability>()
  for (const cat of obs.categories ?? []) {
    const cap = CATEGORY_CAPABILITY[cat as string]
    if (cap) caps.add(cap)
  }
  if (obs.secret) caps.add('private-data')
  if (obs.network) caps.add('external-egress')
  if (obs.tool) {
    for (const [re, cap] of TOOL_HINTS) {
      re.lastIndex = 0
      if (re.test(obs.tool)) caps.add(cap)
    }
  }
  return [...caps]
}
