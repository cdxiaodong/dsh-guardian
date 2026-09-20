/**
 * engine-30: 行为基线偏离引擎（Baseline Drift Guard）
 *
 * 所有单次检查引擎盯的是"这一次调用像不像攻击"；本引擎盯的是"这个会话还像不像它自己"。
 * 会话前 N 次调用建立行为画像（工具类别分布 / 参数规模 / 调用节奏），之后的调用
 * 相对画像的偏离度超过阈值即拦截——权限扩张、参数膨胀、工具风暴、失控循环、复读机。
 *
 * 缝合来源：
 *  - Google Agent Anomaly Detection（2026）：对 agent 工具调用做行为异常检测的生产化思路
 *  - UEBA（用户实体行为分析）：主体习惯基线 + 偏离评分，从"盯事件"升维到"盯主体"
 *  - Proofpoint Agentic AI Governance：scope expansion / drift 是静态策略抓不住的信号
 *
 * 与 drip 引擎（engine-29，PR #24）的分工：drip 盯"货物"（数据出境的量与节奏），
 * baseline 盯"习惯"（操作类别与调用形态的漂移）——同一时间维度上的两个焦距。
 *
 * 架构约定（与 drip 相同）：记账无条件先于判定。宿主必须在静态引擎判定前调用
 * record()——被静态引擎拦截的调用同样是行为证据，照样入账。
 */

/** 工具能力类别（先匹配高危类，顺序即优先级） */
export type ToolClass = 'admin' | 'execute' | 'network' | 'write' | 'read' | 'unknown'

/** 基线视角下的高危类别：能改变系统状态或离开本机 */
export const HIGH_RISK_CLASSES: readonly ToolClass[] = ['admin', 'execute', 'network', 'write']

const CLASS_MATCHERS: Array<[ToolClass, RegExp]> = [
  ['admin', /(?:^|[^a-z])(sudo|su|chmod|chown|chattr|kill|killall|systemctl|service|launchctl|regedit|keychain|security|setenforce|visudo|netsh)(?:[^a-z]|$)/i],
  ['execute', /(?:^|[^a-z])(bash|zsh|dash|ksh|sh|exec|spawn|run|eval|node|deno|bun|python|python3|pip|npm|npx|yarn|pnpm|git|docker|kubectl|helm|make|cargo|java|ruby|perl|php|powershell|pwsh|cmd|awk)(?:[^a-z]|$)/i],
  ['network', /(?:^|[^a-z])(curl|wget|fetch|http|https|request|axios|browser|chrome|playwright|selenium|download|upload|ping|traceroute|dig|nslookup|netstat|ssh|scp|sftp|ftp|telnet|smtp|dns|proxy)(?:[^a-z]|$)/i],
  ['write', /(?:^|[^a-z])(write|edit|append|patch|insert|update|create|delete|remove|rm|unlink|move|mv|rename|cp|copy|touch|mkdir|rmdir|truncate|save|put|post)(?:[^a-z]|$)/i],
  ['read', /(?:^|[^a-z])(read|cat|ls|dir|glob|grep|find|list|view|get|show|head|tail|stat|wc|file|which|type|search|query|open|load|inspect|describe)(?:[^a-z]|$)/i],
]

/** 按工具名推断能力类别 */
export function classifyTool(toolName: string): ToolClass {
  const name = String(toolName ?? '').toLowerCase()
  for (const [cls, re] of CLASS_MATCHERS) {
    if (re.test(name)) return cls
  }
  return 'unknown'
}

export interface BaselineConfig {
  /** 基线成熟门槛：历史调用达到该次数后 001/002 才参与判定（冷启动保护） */
  minCalls?: number
  /** scope-expansion：历史高危类占比低于该值的会话，单步高危调用视为偏离 */
  highRiskShareMax?: number
  /** payload-bloat：当前文本长度 ≥ 历史中位数 × 该倍数 且 ≥ bloatFloor 才判定 */
  bloatFactor?: number
  /** payload-bloat 绝对下限（字符数），避免"历史全是空串"的除零式误报 */
  bloatFloor?: number
  /** tool-spraying 滑动窗口大小（最近 N 次调用） */
  sprayWindow?: number
  /** tool-spraying：窗口内"首见且高危"的工具数达到该值判定为侦察 */
  sprayNewHighRisk?: number
  /** runaway-loop 时间窗口（毫秒） */
  loopWindowMs?: number
  /** runaway-loop：窗口内调用次数上限 */
  loopMaxCalls?: number
  /** dup-payload：最近 N 条 payload 参与复读判定 */
  dupWindow?: number
  /** dup-payload：相同 payload 出现次数上限（含当前） */
  dupThreshold?: number
  /** 各环形缓冲的容量上限（防长会话内存增长） */
  historyCap?: number
}

export const DEFAULT_BASELINE_CONFIG: Required<BaselineConfig> = {
  minCalls: 8,
  highRiskShareMax: 0.1,
  bloatFactor: 4,
  bloatFloor: 4096,
  sprayWindow: 10,
  sprayNewHighRisk: 5,
  loopWindowMs: 1000,
  loopMaxCalls: 15,
  dupWindow: 8,
  dupThreshold: 5,
  historyCap: 64,
}

/** 偏离规则元数据（字段名与 BaselineVerdict 对齐，供审计/遥测展开） */
export interface DriftRuleMeta {
  ruleId: string
  reason: string
  action: 'block' | 'deny'
}

export const BLD_RULES: Record<string, DriftRuleMeta> = {
  'BLD-001': { ruleId: 'BLD-001', reason: '权限扩张偏离：会话基线为纯读取型，当前调用首次进入高危类别', action: 'block' },
  'BLD-002': { ruleId: 'BLD-002', reason: '参数规模突增：当前参数远超会话历史中位数，疑似被注入塞入载荷', action: 'block' },
  'BLD-003': { ruleId: 'BLD-003', reason: '工具风暴：近期大量首见的高危类工具，疑似侦察/扫描行为', action: 'block' },
  'BLD-004': { ruleId: 'BLD-004', reason: '失控循环：极短时间窗内高频调用，疑似 agent 失控自旋', action: 'deny' },
  'BLD-005': { ruleId: 'BLD-005', reason: '复读机：同一 payload 短窗口内重复出现，疑似重试死循环', action: 'deny' },
}

export interface BaselineVerdict {
  safe: boolean
  ruleId?: string
  reason?: string
  action?: 'block' | 'deny'
}

/** 画像快照：测试与遥测用 */
export interface ProfileSnapshot {
  calls: number
  mature: boolean
  distinctTools: number
  medianArgLen: number
  highRiskShare: number
  classCounts: Partial<Record<ToolClass, number>>
}

interface CallRecord {
  tool: string
  cls: ToolClass
  wasNew: boolean
  ts: number
  len: number
}

/** payload 指纹：长度 + 首尾切片，避免账本存储全文 */
function payloadKey(text: string): string {
  return `${text.length}:${text.slice(0, 64)}:${text.slice(-64)}`
}

function median(sorted: number[]): number {
  if (!sorted.length) return 0
  const mid = sorted.length >> 1
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

/**
 * 会话行为账本：先 record（无条件）后 assess。
 * 账本为纯内存态，插件卸载即随实例消亡；reset() 供宿主主动重建基线。
 */
export class BaselineTracker {
  private cfg: Required<BaselineConfig>
  private calls = 0
  private classCounts: Partial<Record<ToolClass, number>> = {}
  private seenTools = new Set<string>()
  private recent: CallRecord[] = []
  private argLens: number[] = []
  private dupKeys: string[] = []

  constructor(config: BaselineConfig = {}) {
    this.cfg = { ...DEFAULT_BASELINE_CONFIG, ...config }
  }

  /** 记账：无论后续是否被任何引擎拦截，调用意图都是行为证据 */
  record(toolName: string, text: string): void {
    const cls = classifyTool(toolName)
    const key = toolName.toLowerCase()
    const wasNew = !this.seenTools.has(key)
    this.seenTools.add(key)
    this.calls += 1
    this.classCounts[cls] = (this.classCounts[cls] ?? 0) + 1
    const rec: CallRecord = { tool: key, cls, wasNew, ts: Date.now(), len: text.length }
    this.recent.push(rec)
    this.argLens.push(text.length)
    this.dupKeys.push(payloadKey(text))
    if (this.recent.length > this.cfg.historyCap) this.recent.shift()
    if (this.argLens.length > this.cfg.historyCap) this.argLens.shift()
    if (this.dupKeys.length > this.cfg.dupWindow) this.dupKeys.shift()
  }

  /**
   * 判定当前调用相对基线的偏离度。约定在 record() 之后调用：
   * 账本最后一条即当前调用，历史统计需将其排除，避免"自己证明自己偏离"。
   */
  assess(toolName: string, text: string): BaselineVerdict {
    const cls = classifyTool(toolName)
    const cur = this.recent[this.recent.length - 1]
    // 账本末条与当前调用不对应（宿主未按约定 record）→ 只按无历史处理，不臆测
    const historyCalls = cur && cur.tool === toolName.toLowerCase() ? this.calls - 1 : this.calls
    const mature = historyCalls >= this.cfg.minCalls

    // BLD-004 runaway-loop：账本全量参与（失控进行时，含当前）
    const now = cur?.ts ?? Date.now()
    const burst = this.recent.filter((r) => now - r.ts <= this.cfg.loopWindowMs).length
    if (burst >= this.cfg.loopMaxCalls) {
      return { safe: false, ...BLD_RULES['BLD-004'] }
    }

    // BLD-005 dup-payload：复读窗口内相同指纹计数（含当前）
    const key = payloadKey(text)
    const dupCount = this.dupKeys.filter((k) => k === key).length
    if (dupCount >= this.cfg.dupThreshold) {
      return { safe: false, ...BLD_RULES['BLD-005'] }
    }

    // 以下规则需要成熟基线（冷启动不判定，避免"前几次全是新工具"式误报）
    if (!mature) return { safe: true }

    // BLD-001 scope-expansion：历史高危占比低 + 当前高危
    if (HIGH_RISK_CLASSES.includes(cls)) {
      const curCount = cur && cur.cls === cls ? 1 : 0
      const highRisk = HIGH_RISK_CLASSES.reduce((sum, c) => sum + (this.classCounts[c] ?? 0), 0) - curCount
      const share = historyCalls > 0 ? highRisk / historyCalls : 0
      if (share < this.cfg.highRiskShareMax) {
        return { safe: false, ...BLD_RULES['BLD-001'] }
      }
    }

    // BLD-002 payload-bloat：长度 ≥ 历史中位数 × 倍数 且 ≥ 绝对下限
    const historyLens = [...this.argLens]
    if (cur && cur.len === text.length) historyLens.pop()
    if (text.length >= this.cfg.bloatFloor) {
      const med = median(historyLens.sort((a, b) => a - b))
      if (med > 0 && text.length >= med * this.cfg.bloatFactor) {
        return { safe: false, ...BLD_RULES['BLD-002'] }
      }
    }

    // BLD-003 tool-spraying：滑动窗口内"首见且高危"计数
    const window = this.recent.slice(-this.cfg.sprayWindow)
    const sprayed = window.filter((r) => r.wasNew && HIGH_RISK_CLASSES.includes(r.cls)).length
    if (sprayed >= this.cfg.sprayNewHighRisk) {
      return { safe: false, ...BLD_RULES['BLD-003'] }
    }

    return { safe: true }
  }

  /** 当前画像快照（不含排除逻辑，反映账本全量） */
  snapshot(): ProfileSnapshot {
    const highRisk = HIGH_RISK_CLASSES.reduce((sum, c) => sum + (this.classCounts[c] ?? 0), 0)
    return {
      calls: this.calls,
      mature: this.calls >= this.cfg.minCalls,
      distinctTools: this.seenTools.size,
      medianArgLen: median([...this.argLens].sort((a, b) => a - b)),
      highRiskShare: this.calls > 0 ? highRisk / this.calls : 0,
      classCounts: { ...this.classCounts },
    }
  }

  /** 重建基线：人工确认"这是任务新阶段"后可调用，下一调用起重新冷启动 */
  reset(): void {
    this.calls = 0
    this.classCounts = {}
    this.seenTools.clear()
    this.recent = []
    this.argLens = []
    this.dupKeys = []
  }
}
