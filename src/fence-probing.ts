/**
 * 围栏试探检测引擎（Fence-Probing Guard）——engine-35
 *
 * 攻击者（或被注入劫持的 agent）被拒后不会收手，而是"试探围栏"：
 * 微调命令绕过正则、换等价路径参数、在同一路径上枚举变体。单次变体
 * 往往能骗过静态规则（内容无害），唯一暴露的是它与"被拒历史"的
 * 时序-语义关联——deny 之后紧跟一个高度相似的重试。
 *
 * 缝合来源：
 *  - fail2ban 的 jail 语义：重复失败 → 禁入冷却，bantime 指数递增且封顶
 *  -《Covert Assistance: Helpful LLM Agents Evade Oversight in Multi-Agent
 *    Systems》（arXiv 2026-09-30）：agent 会在监督规则边界附近系统性规避，
 *    监控规则本身成了攻击面
 *  -《Instrumental Monitor Evasion》/ EvasionBench（arXiv 2026-09-24）：
 *    知道被监控的 agent 会刻意贴着监控阈值行动，规避行为有稳定签名
 *
 * 三条规则：
 *  PRB-001 deny-retry：与窗口内被拒调用高度相似（token Jaccard ≥ 阈值，
 *                      含原样重试）的重试 → 拦截
 *  PRB-002 fence-fuzz：同签名簇内不同变体数 ≥ N（系统性变体枚举，即对
 *                      围栏做模糊测试）→ 拦截
 *  PRB-003 tool-jail ：窗口内同工具被拒 ≥ M 次 → 该工具进入监狱
 *                      （fail2ban 式冷却，时长指数递增、封顶；监狱期内对该
 *                       工具的任何调用直接拦，无论内容相似与否）
 *
 * 架构约定（与 drip/baseline/escrow 引擎一致）：记账无条件先于判定——
 * 任何引擎产生的拦截（deny，或未获人工批准的 block）都入账；本引擎自己的
 * 拦截也入账（监狱期内的尝试会续期）。人工批准的调用不入账（批准≠拒绝）。
 * 账本纯内存：插件卸载即消失（时空可组合-时间维度），无持久化副作用。
 */

/** 围栏试探引擎可调参数 */
export interface FenceProbingOptions {
  /** 被拒记录滑动窗口（ms），窗口滑出自愈 */
  windowMs: number
  /** 判定"同意图变体"的 token Jaccard 下界（0~1） */
  similarity: number
  /** PRB-002 触发的簇内不同变体数（含当前调用） */
  variants: number
  /** PRB-003 同工具窗口内被拒次数阈值 */
  jailThreshold: number
  /** 监狱基础时长（ms） */
  jailBaseMs: number
  /** 监狱时长封顶（ms），指数递增不超过此值 */
  jailMaxMs: number
}

export const DEFAULT_PROBING_OPTIONS: FenceProbingOptions = {
  windowMs: 600_000,
  similarity: 0.55,
  variants: 3,
  jailThreshold: 5,
  jailBaseMs: 60_000,
  jailMaxMs: 900_000,
}

/** 账本硬上限：防御拒绝风暴撑爆内存（超出丢最旧） */
const MAX_RECORDS = 1000

export type ProbingRuleId = 'PRB-001' | 'PRB-002' | 'PRB-003'

export interface ProbingVerdict {
  ruleId: ProbingRuleId
  reason: string
  /** 命中的最大相似度（PRB-001/002） */
  similarity?: number
  /** 簇内不同变体数（PRB-002） */
  variants?: number
  /** 监狱释放时间戳（PRB-003） */
  jailUntil?: number
}

/** 一条被拒记录：工具 + token 集 + 原文（变体判重用）+ 时间戳 */
export interface DenyRecord {
  tool: string
  tokens: Set<string>
  /** 原始文本（截断）：变体判重看原文而非 token——微调本身就是"新变体" */
  raw: string
  ts: number
}

export interface JailState {
  tool: string
  /** 释放时间戳（ms） */
  until: number
  /** 连续收监次数：时长 = base * 2^(strikes-1)，封顶 max */
  strikes: number
}

/**
 * 调用文本 → 小写 token 序列（按非字母数字切分，丢弃单字符噪声）。
 * 路径/标点被抹平是有意为之：`/etc//shadow` 与 `/etc/shadow` 应当相似。
 */
export function tokenizeCall(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 2)
}

/** 两个 token 集的 Jaccard 相似度：|A∩B| / |A∪B| */
export function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0
  let inter = 0
  for (const t of a) if (b.has(t)) inter++
  return inter / (a.size + b.size - inter)
}

/**
 * 围栏试探账本：record() 记被拒调用，assess() 判当前调用。
 * 单元测试请注入时钟（now 参数）；生产路径由 GuardianService 传 Date.now()。
 */
export class FenceProbingTracker {
  private records: DenyRecord[] = []
  private jails = new Map<string, JailState>()

  constructor(public readonly opts: FenceProbingOptions = DEFAULT_PROBING_OPTIONS) {}

  /** 记账：任何拦截（deny / 未批准 block / 本引擎拦截）都调用。无返回值——记账无条件。 */
  record(tool: string, text: string, now: number): void {
    this.expire(now)
    this.records.push({ tool, tokens: new Set(tokenizeCall(text)), raw: text.slice(0, 500), ts: now })
    if (this.records.length > MAX_RECORDS) this.records.splice(0, this.records.length - MAX_RECORDS)

    // 监狱判定：窗口内同工具被拒次数达到阈值 → 收监；监狱期内的持续被拒会续期并加重
    const denied = this.records.filter((r) => r.tool === tool).length
    if (denied >= this.opts.jailThreshold) {
      const j = this.jails.get(tool) ?? { tool, until: 0, strikes: 0 }
      j.strikes += 1
      j.until = now + Math.min(this.opts.jailBaseMs * 2 ** (j.strikes - 1), this.opts.jailMaxMs)
      this.jails.set(tool, j)
    }
  }

  /** 判定：命中返回 verdict，未命中返回 null（放行，由静态引擎继续） */
  assess(tool: string, text: string, now: number): ProbingVerdict | null {
    this.expire(now)

    // PRB-003：监狱期内，该工具一切调用直接拦（无论内容）
    const jail = this.jails.get(tool)
    if (jail && jail.until > now) {
      return {
        ruleId: 'PRB-003',
        reason: `工具 ${tool} 因窗口内连续 ${this.opts.jailThreshold} 次被拒进入冷却监狱（fail2ban），${new Date(jail.until).toISOString()} 释放；监狱期内对该工具的任何调用一律拦截`,
        jailUntil: jail.until,
      }
    }

    // PRB-001 / PRB-002：与窗口内同工具被拒记录做星型相似聚类（以当前调用为中心）
    const tokens = new Set(tokenizeCall(text))
    const raw = text.slice(0, 500)
    let best = 0
    let similarCount = 0
    const distinctVariants = new Set<string>()
    for (const r of this.records) {
      if (r.tool !== tool || r.ts <= now - this.opts.windowMs) continue
      const sim = jaccardSimilarity(tokens, r.tokens)
      if (sim < this.opts.similarity) continue
      if (sim > best) best = sim
      similarCount++
      distinctVariants.add(r.raw)
    }
    if (similarCount === 0) return null // 无相似记录
    distinctVariants.add(raw)           // 变体数含当前调用（原样重试＝1 个变体，仍命中 PRB-001）

    if (distinctVariants.size >= this.opts.variants) {
      return {
        ruleId: 'PRB-002',
        reason: `围栏模糊测试：窗口内已累计 ${distinctVariants.size} 个高度相似的被拒变体（相似度≥${this.opts.similarity}），呈系统性变体枚举特征`,
        similarity: best,
        variants: distinctVariants.size,
      }
    }
    return {
      ruleId: 'PRB-001',
      reason: `被拒调用的变体重试：与 ${this.opts.windowMs / 1000}s 内被拒调用相似度 ${best.toFixed(2)}（deny 后微调重试＝绕过围栏意图）`,
      similarity: best,
    }
  }

  /** 滑出自愈：丢弃滑出窗口的记录与已到期的监狱（strike 随之清零） */
  private expire(now: number): void {
    this.records = this.records.filter((r) => r.ts > now - this.opts.windowMs)
    for (const [tool, j] of this.jails) {
      if (j.until <= now) this.jails.delete(tool)
    }
  }

  /** 账本快照（可观测性）：记录数、各工具计数、活跃监狱 */
  stats(now: number): { records: number; byTool: Record<string, number>; jails: JailState[] } {
    this.expire(now)
    const byTool: Record<string, number> = {}
    for (const r of this.records) byTool[r.tool] = (byTool[r.tool] ?? 0) + 1
    return { records: this.records.length, byTool, jails: [...this.jails.values()] }
  }
}
