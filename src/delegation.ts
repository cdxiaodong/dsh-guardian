/**
 * 授权衰减引擎（Delegation Attenuation Guard）
 *
 * 缝合 DelegateGuard（arXiv:2610.16005, Purpose-Bound Capabilities for Delegated
 * LLM Agent Workflows）：把发起用户的一次性授权编译成五维可衰减能力
 * （purpose / labels / operations / sinks / delegation-depth），每个数据移动
 * 动作在 LLM 之外被 mediate，撤销沿委派图级联。
 *
 * 与既有引擎的维度差异：42 个引擎都在回答"这次调用本身危险吗"（内容/时序/后果），
 * 唯一的批准语义 guardian/approve 是一次性布尔——批准完就蒸发。本引擎管"批准本身
 * 的生命周期"：批准 → 编译成能力 → 重用（授权复用）/ 委派（只减不增）/ 撤销（级联）。
 * 与 engine-12 污点追踪形成对偶：taint 跟着数据走，capability 跟着批准走。
 *
 * 衰减律（attenuation property，IETF 衰减委派草案 / Red Hat 权限交集 2026 共识）：
 * 委派链上任一维只许收窄——子能力 operations/labels/sinks 必须是父的子集，
 * depth 逐级 -1，预算与 TTL 不得超过父剩余值。任一扩张 = 权限放大，当场拒绝。
 *
 * 防的五类攻击面（论文五类，一一对应规则）：
 *  - authority amplification（权限放大）        → DLG-001 衰减律违反
 *  - purpose gaming（用途漂移）                  → DLG-001 purpose 词元无继承
 *  - chain elongation（无限拉长委派链）          → DLG-004 深度耗尽
 *  - revocation replay（撤销/耗尽后重放）        → DLG-002
 *  - ungranted sink（授权外目标外泄）            → authorize uncovered，走人工审批
 */

/** 操作类别：从命令文本分类出的动词域（secret-read 优先于 read） */
export type OperationClass = 'read' | 'write' | 'exec' | 'net' | 'secret-read'

/** 数据标签：能力可触碰的数据分类白名单 */
export type DataLabel = 'secret' | 'tmp' | 'config' | 'external' | 'internal'

/** 授权编译请求：宿主把一次用户批准交给账本编译。缺省维度从 purpose 文本推断 */
export interface GrantRequest {
  /** 批准时的任务意图原文（必填，委派链的 purpose 继承基准） */
  purpose: string
  labels?: DataLabel[]
  operations?: OperationClass[]
  /** 路径前缀 / 域名白名单 */
  sinks?: string[]
  /** 剩余可委派深度（默认 0：一次性授权不可再委派） */
  depth?: number
  maxUses?: number
  ttlMs?: number
}

/** 已编译的能力对象（委派链上的节点） */
export interface Capability {
  id: string
  parentId: string | null
  /** 委派链根 id（级联撤销的回溯锚点） */
  rootId: string
  purpose: string
  labels: DataLabel[]
  operations: OperationClass[]
  sinks: string[]
  depth: number
  maxUses: number
  uses: number
  grantedAt: number
  expiresAt: number
  status: 'active' | 'revoked' | 'exhausted'
}

/** 委派裁决：成功返回衰减后的子能力，失败返回违规规则 */
export type DelegationVerdict =
  | { ok: true; capability: Capability }
  | { ok: false; ruleId: 'DLG-001' | 'DLG-004'; reason: string }

/** 运行时授权校验结果 */
export interface AuthorizeResult {
  decision: 'allow' | 'deny' | 'uncovered'
  capability?: Capability
  ruleId?: 'DLG-002'
  reason?: string
  /** 本次用掉了能力的最后一次预算 */
  lastUse?: boolean
}

// ── 文本 → 五维推断（编译器前端） ────────────────────────

const SECRET_READ_RE = /\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.gnupg|\.env\b|private_key|\.netrc|\.kube\/config/
const NET_RE = /\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bsocat\b|\bdig\b|\bnslookup\b|\bping\b|https?:\/\/|\bscp\b|\bsftp\b|\bssh\b/
const EXEC_RE = /\bbash\b|\bsh\b|\bzsh\b|\bnode\b|\bpython\d?\b|\bperl\b|\bruby\b|\bexec\b|\beval\b|chmod\s+\+x/
const WRITE_RE = /\brm\b|\bmv\b|\bcp\b|\btee\b|\bmkdir\b|\btouch\b|\btruncate\b|\bdd\b|\bsed\s+-i|\bchmod\b|\bchown\b|\bkill\b|>\s*\S/
const READ_RE = /\bcat\b|\bls\b|\bhead\b|\btail\b|\bgrep\b|\bfind\b|\bfile\b|\bstat\b|\bwc\b|\bdu\b|\btar\b|\bunzip\b/

/** 从命令文本分类操作域（一条复合命令可命中多类） */
export function classifyOperations(text: string): OperationClass[] {
  const ops: OperationClass[] = []
  if (SECRET_READ_RE.test(text)) ops.push('secret-read')
  if (READ_RE.test(text)) ops.push('read')
  if (WRITE_RE.test(text)) ops.push('write')
  if (EXEC_RE.test(text)) ops.push('exec')
  if (NET_RE.test(text)) ops.push('net')
  return [...new Set(ops)]
}

const PATH_SINK_RE = /(?:^|[\s"'=(])((?:\/|~\/|\.{1,2}\/)[A-Za-z0-9._~\/-]+)/g
const DOMAIN_SINK_RE = /\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)\b/gi

/** 提取调用文本涉及的 sink：文件系统路径 + 网络域名 */
export function extractSinks(text: string): { paths: string[]; domains: string[] } {
  const paths = new Set<string>()
  const domains = new Set<string>()
  for (const m of text.matchAll(PATH_SINK_RE)) paths.add(m[1])
  for (const m of text.matchAll(DOMAIN_SINK_RE)) {
    const d = m[1].toLowerCase()
    // 排除文件名误报（cat README.md 的 README.md 不是域名）与常见非主机后缀
    if (/\.(md|txt|log|json|yaml|yml|conf|sh|py|js|ts|tar|gz|zip|png|jpg)$/i.test(d)) continue
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(d)) continue // IP 走 internal 标签
    domains.add(d)
  }
  return { paths: [...paths], domains: [...domains] }
}

/** 推断数据标签：凭据 / 临时区 / 配置 / 外网 / 内网 */
export function inferLabels(text: string): DataLabel[] {
  const labels = new Set<DataLabel>()
  if (/\.ssh\b|\.aws\b|\.gnupg|id_rsa|id_ed25519|credentials|private_key|\.env\b|api[_-]?key|token/i.test(text)) labels.add('secret')
  if (/\/tmp\/|\/var\/tmp\/|\/dev\/shm\//.test(text)) labels.add('tmp')
  if (/\.(?:conf|config|ini|yaml|yml)\b|\.kube\/|\/etc\//.test(text)) labels.add('config')
  if (/\b(?:127\.0\.0\.1|localhost|10\.\d|192\.168\.|169\.254\.|::1)\b/.test(text)) labels.add('internal')
  const { domains } = extractSinks(text)
  if (domains.length) labels.add('external')
  return [...labels]
}

/** sink 覆盖判定：子 sink 必须落在父授权范围内（路径前缀 / 域名后缀两种语义） */
export function sinkCovered(sink: string, allowed: string[]): boolean {
  const isPath = sink.startsWith('/') || sink.startsWith('~/') || sink.startsWith('./') || sink.startsWith('../')
  return allowed.some((a) => {
    if (isPath) {
      const base = a.endsWith('/') ? a : a + '/'
      return sink === a || sink.startsWith(base)
    }
    // 域名：子域是收窄（api.github.com ⊂ github.com），相似后缀不是
    const d = sink.toLowerCase()
    const p = a.toLowerCase()
    return d === p || d.endsWith('.' + p)
  })
}

const PURPOSE_STOPWORDS = new Set(['the', 'a', 'an', 'of', 'to', 'for', 'in', 'on', 'and', 'or', 'with', 'this', 'that', 'my', '数据', '文件', '任务'])

/** purpose 继承检查：子任务声明必须与父 purpose 至少共享一个内容词元，否则判 purpose gaming */
export function purposeOverlap(parent: string, child: string): boolean {
  // ASCII 按词元；CJK 无分隔符，按双字滑窗 bigram（'清理构建缓存' 与 '清理' 共享 '清理'）
  const tokens = (s: string): Set<string> => {
    const out = new Set<string>()
    const lower = s.toLowerCase()
    for (const m of lower.matchAll(/[a-z0-9][a-z0-9-]{1,}/g)) {
      if (!PURPOSE_STOPWORDS.has(m[0])) out.add(m[0])
    }
    for (const m of lower.matchAll(/[一-鿿]{2,}/g)) {
      for (let i = 0; i + 2 <= m[0].length; i++) out.add(m[0].slice(i, i + 2))
    }
    return out
  }
  const parentTokens = tokens(parent)
  if (!parentTokens.size) return true // 父无内容词元，不做 gaming 判定（其余衰减维仍兜底）
  return [...tokens(child)].some((t) => parentTokens.has(t))
}

/** 衰减律核心：子能力五维是否为父的收窄（不含 depth/预算，那两项在 delegate 里单独计） */
function isNarrowing(parent: Capability, childOps: OperationClass[], childLabels: DataLabel[], childSinks: string[]): { ok: boolean; reason?: string } {
  for (const op of childOps) {
    if (!parent.operations.includes(op)) return { ok: false, reason: `操作域扩张：父授权不含 ${op}` }
  }
  for (const lb of childLabels) {
    if (!parent.labels.includes(lb)) return { ok: false, reason: `标签扩张：父授权不含数据标签 ${lb}` }
  }
  if (parent.sinks.length) {
    for (const s of childSinks) {
      if (!sinkCovered(s, parent.sinks)) return { ok: false, reason: `授权外 sink：${s} 不在父授权范围内` }
    }
  }
  return { ok: true }
}

export interface DelegationConfig {
  /** 默认可委派深度（默认 0：授权一次性，不可再委派） */
  defaultDepth?: number
  /** 默认使用预算（默认 1） */
  defaultMaxUses?: number
  /** 默认 TTL 毫秒（默认 10 分钟） */
  defaultTtlMs?: number
}

/**
 * 委派账本：能力注册表 + 衰减验证 + 级联撤销。
 * clock 可注入以便测试 TTL；生产用 Date.now。
 */
export class DelegationLedger {
  private caps = new Map<string, Capability>()
  private seq = 0
  private defaults: Required<DelegationConfig>
  private now: () => number

  constructor(config: DelegationConfig = {}, clock?: () => number) {
    this.defaults = {
      defaultDepth: config.defaultDepth ?? 0,
      defaultMaxUses: config.defaultMaxUses ?? 1,
      defaultTtlMs: config.defaultTtlMs ?? 10 * 60_000,
    }
    this.now = clock ?? Date.now
  }

  /** 授权编译：把一次批准（或缺省维度从 purpose 推断）铸成能力 */
  grant(req: GrantRequest): Capability {
    const id = `cap-${++this.seq}`
    const inferredSinks = req.sinks ?? [...extractSinks(req.purpose).paths, ...extractSinks(req.purpose).domains]
    const cap: Capability = {
      id,
      parentId: null,
      rootId: id,
      purpose: req.purpose,
      labels: req.labels ?? inferLabels(req.purpose),
      operations: req.operations ?? (classifyOperations(req.purpose).length ? classifyOperations(req.purpose) : ['read']),
      sinks: inferredSinks,
      depth: req.depth ?? this.defaults.defaultDepth,
      maxUses: req.maxUses ?? this.defaults.defaultMaxUses,
      uses: 0,
      grantedAt: this.now(),
      expiresAt: this.now() + (req.ttlMs ?? this.defaults.defaultTtlMs),
      status: 'active',
    }
    this.caps.set(id, cap)
    return cap
  }

  /**
   * 委派：请求父能力衰减出一个子能力。衰减律逐维检查——
   * 任一维扩张（ops/labels/sinks 超父集、depth 不减、预算/TTL 超父剩余、purpose 无继承）= DLG-001；
   * 父 depth 已耗尽仍委派 = DLG-004。
   */
  delegate(parentId: string, req: GrantRequest): DelegationVerdict {
    const parent = this.caps.get(parentId)
    if (!parent) return { ok: false, ruleId: 'DLG-001', reason: `父能力 ${parentId} 不存在` }
    const t = this.now()
    if (parent.status !== 'active' || parent.expiresAt <= t) {
      return { ok: false, ruleId: 'DLG-001', reason: `父能力已失效（${parent.status}），失效授权不可委派（revocation replay）` }
    }
    if (parent.depth <= 0) {
      return { ok: false, ruleId: 'DLG-004', reason: `委派深度耗尽（depth=0），不可再委派` }
    }

    const ops = req.operations ?? classifyOperations(req.purpose)
    const labels = req.labels ?? inferLabels(req.purpose)
    const sinks = req.sinks ?? [...extractSinks(req.purpose).paths, ...extractSinks(req.purpose).domains]

    const narrowing = isNarrowing(parent, ops, labels, sinks)
    if (!narrowing.ok) return { ok: false, ruleId: 'DLG-001', reason: narrowing.reason! }
    if (!purposeOverlap(parent.purpose, req.purpose)) {
      return { ok: false, ruleId: 'DLG-001', reason: `purpose gaming：子任务声明（${req.purpose.slice(0, 80)}）与父授权用途无词元继承` }
    }

    // 预算与 TTL：子不得超过父剩余（交集取小，Red Hat permission intersection）。
    // 划给子的预算从父账上划转（预算守恒：委派不复制预算，子花的就是父的）
    const parentUsesLeft = parent.maxUses - parent.uses
    const maxUses = Math.min(req.maxUses ?? this.defaults.defaultMaxUses, parentUsesLeft)
    if (maxUses <= 0) return { ok: false, ruleId: 'DLG-001', reason: '父授权预算已耗尽，无可委派余额' }
    parent.uses += maxUses
    if (parent.uses >= parent.maxUses) parent.status = 'exhausted'
    const ttlMs = req.ttlMs ?? this.defaults.defaultTtlMs
    const expiresAt = Math.min(t + ttlMs, parent.expiresAt)

    const id = `cap-${++this.seq}`
    const child: Capability = {
      id,
      parentId: parent.id,
      rootId: parent.rootId,
      purpose: req.purpose,
      labels,
      operations: ops,
      sinks,
      depth: parent.depth - 1,
      maxUses,
      uses: 0,
      grantedAt: t,
      expiresAt,
      status: 'active',
    }
    this.caps.set(id, child)
    return { ok: true, capability: child }
  }

  /**
   * 运行时授权校验：本次操作的 ops/sinks/labels 是否被某条活跃能力覆盖。
   *  - 覆盖 → allow 并扣减预算（用尽即转 exhausted）
   *  - 维度匹配但能力已 revoked/exhausted/过期 → deny DLG-002（revocation replay）
   *  - 从无覆盖 → uncovered（不越权拒绝，交回人工审批通道）
   */
  authorize(req: { operations: OperationClass[]; sinks?: string[]; labels?: DataLabel[] }): AuthorizeResult {
    const t = this.now()
    let replayHit: Capability | null = null
    for (const cap of this.caps.values()) {
      if (!isNarrowing(cap, req.operations, req.labels ?? [], req.sinks ?? []).ok) continue
      const live = cap.status === 'active' && cap.expiresAt > t && cap.uses < cap.maxUses
      if (live) {
        cap.uses += 1
        const lastUse = cap.uses >= cap.maxUses
        if (lastUse) cap.status = 'exhausted'
        return { decision: 'allow', capability: cap, lastUse }
      }
      replayHit = cap // 维度匹配但已死：记下最可能的授权来源
    }
    if (replayHit) {
      return {
        decision: 'deny',
        ruleId: 'DLG-002',
        reason: `revocation replay：操作与授权 ${replayHit.id} 维度匹配，但该授权已${replayHit.status === 'revoked' ? '被撤销' : replayHit.status === 'exhausted' ? '耗尽预算' : '过期'}——重放已失效授权`,
      }
    }
    return { decision: 'uncovered', reason: '无活跃授权覆盖本次操作，转人工审批' }
  }

  /** 级联撤销：revoke 父授权时整棵委派子树一起失效（revocation cascade） */
  revoke(id: string): Capability[] {
    const cap = this.caps.get(id)
    if (!cap) return []
    const revoked: Capability[] = []
    const queue = [id]
    while (queue.length) {
      const cur = queue.shift()!
      const c = this.caps.get(cur)
      if (!c || c.status === 'revoked') continue
      c.status = 'revoked'
      revoked.push(c)
      for (const other of this.caps.values()) {
        if (other.parentId === cur) queue.push(other.id)
      }
    }
    return revoked
  }

  get(id: string): Capability | undefined {
    return this.caps.get(id)
  }

  /** 委派链回溯：id → … → 根（完整授权血缘，审计用） */
  chainOf(id: string): Capability[] {
    const chain: Capability[] = []
    let cur = this.caps.get(id)
    while (cur) {
      chain.unshift(cur)
      cur = cur.parentId ? this.caps.get(cur.parentId) : undefined
    }
    return chain
  }

  list(): Capability[] {
    return [...this.caps.values()]
  }
}
