/**
 * 义务账本引擎（Duty Ledger）—— 禁止型护栏之外的第一类防线。
 *
 * 缝合 arXiv:2610.04611 EnfFlash（Metric First-Order Temporal Logic 的运行时
 * 强制执行，2026-10-03）的核心洞察：agentic security 的要求不止于禁止
 * （prohibition，"不许做 X"），还有义务（obligation，"做了 X 就必须在期限内
 * 做 Y"）——论文的原始例子即"运行中收集的个人数据必须在某个期限前删除"。
 *
 * 本模块是其实用片段的确定性本地实现，无需逻辑编译器：
 *
 *   G ( signal(x) → F[0,d] dispose(x) )     —— 有界最终性义务
 *   overdue(x) → ¬egress (until dispose(x)) —— 违约遏制
 *
 * 一阶性体现在绑定变量 x：获取事件与销账事件通过同一工件路径关联（跨调用
 * 的信息流，不是独立事件计数）；度量性体现在 deadlineMs 时序界。
 */
export interface DutyDef {
  id: string
  reason: string
  /** 获取事件：命中即产生一条义务 */
  signal: RegExp
  /** 从 payload 提取绑定变量 x（工件路径），捕获组 1 优先 */
  artifact: RegExp
  /** 销账事件：捕获组 1 = 被清理的工件路径 */
  dispose: RegExp
  /** 度量时序上界 d（毫秒） */
  deadlineMs: number
}

export interface DutyRecord {
  seq: number
  defId: string
  /** 一阶变量 x 的绑定（敏感工件路径） */
  binding: string
  acquiredAt: number
  deadlineAt: number
  status: 'open' | 'fulfilled'
  fulfilledAt?: number
  /** 销账来源：dispose payload 片段或 'manual' */
  fulfilledBy?: string
}

/** 逾期/开放义务的只读投影（overdue 为读取时刻的计算值） */
export interface DutyView extends DutyRecord {
  overdue: boolean
}

/**
 * 默认义务定义。
 *
 * 信号选取原则：这些 payload 能通过上游静态引擎（secret/CRED 只盯明文密钥
 * 与知名凭据路径），但确实把敏感材料物化成了"运行中的残留工件"——正是
 * 单次检查放行、事后无人负责的盲区。
 */
export const DEFAULT_DUTY_DEFS: DutyDef[] = [
  {
    id: 'DUTY-001',
    reason: '环境变量/命令历史落盘产生敏感残留，须在期限内清理',
    // printenv/env/history 重定向到文件（EXFIL-001 只盯管道外传，重定向落盘是它的盲区）
    signal: /\b(?:printenv|env|history|fc\s+-l)\b[^\n;|]{0,100}?>>?/i,
    artifact: />>?\s*([^\s;&|'"]+)/i,
    dispose: /\b(?:rm|unlink|shred|srm|truncate)\b[^\n;]{0,80}?(\/[^\s;&|'"]+|~\/[^\s;&|'"]+)/i,
    deadlineMs: 10 * 60_000,
  },
  {
    id: 'DUTY-002',
    reason: '密钥材料备份/打包到临时区，须在期限内清理',
    // cp/mv/tar/zip/rsync/scp 搬运凭据类文件（.pem/.kdbx 等通用扩展名不命中 CRED 系列知名路径规则）
    signal: /\b(?:cp|mv|tar|zip|rsync|scp|gpg\s+-[ea])\b[^\n;|]{0,160}(?:\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.kdbx\b|\.env\b|\.ssh\b|id_rsa|id_ed25519|authorized_keys|credentials)/i,
    artifact: /(?:^|[\s="'(])((?:\/(?:tmp|var\/tmp|dev\/shm)\/[^\s;&|'"]+)|(?:[^\s;&|'"]+\.(?:bak|tmp|old|orig|tgz|tar\.gz|zip)))/i,
    dispose: /\b(?:rm|unlink|shred|srm|truncate)\b[^\n;]{0,80}?(\/[^\s;&|'"]+|~\/[^\s;&|'"]+)/i,
    deadlineMs: 10 * 60_000,
  },
]

/** 出境形态：工具名或 payload 呈网络外传特征（逾期遏制的作用面） */
export const EGRESS_SHAPE = /\b(?:curl|wget|nc|ncat|socat|ssh|scp|sftp|ftp|telnet|rsync)\b|\bhttps?:\/\/[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/i
export const EGRESS_TOOL = /fetch|http|net|web|request|axios|upload|send|smtp|mail|post/i

/** 销账路径匹配：精确 / glob（* 通配）/ 包含（rm 目录前缀） */
export function pathMatchesArtifact(binding: string, token: string): boolean {
  if (!binding || !token) return false
  if (binding === token) return true
  if (binding.includes('*') || token.includes('*')) {
    const re = new RegExp('^' + token.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$')
    if (re.test(binding)) return true
  }
  // token 是 binding 的路径前缀（按目录边界），如 rm /tmp vs /tmp/env.txt
  if (binding.startsWith(token.endsWith('/') ? token : token + '/')) return true
  return false
}

/**
 * 义务账本：内存 Ledger，记录 acquire → 期限 → dispose 的跨事件关联。
 * 时钟可注入（测试与宿主时间旅行），上限容量防止账本无限增长。
 */
export class DutyLedger {
  private records: DutyRecord[] = []
  private seq = 0

  constructor(
    private readonly defs: DutyDef[],
    private readonly clock: () => number = () => Date.now(),
    private readonly max = 500,
  ) {}

  /** 获取记账：signal 命中且能提取工件 → 产生义务（同 def 同工件不重复记账） */
  recordFrom(payload: string): DutyRecord[] {
    const now = this.clock()
    const created: DutyRecord[] = []
    for (const def of this.defs) {
      def.signal.lastIndex = 0
      if (!def.signal.test(payload)) continue
      def.artifact.lastIndex = 0
      const am = def.artifact.exec(payload)
      if (!am) continue   // 涉及敏感材料但没落到新工件（如原地同目录拷贝）——不记账
      const binding = am[1] ?? am[0]
      if (this.records.some(r => r.defId === def.id && r.binding === binding && r.status === 'open')) continue
      const rec: DutyRecord = { seq: ++this.seq, defId: def.id, binding, acquiredAt: now, deadlineAt: now + def.deadlineMs, status: 'open' }
      this.records.push(rec)
      created.push(rec)
      if (this.records.length > this.max) this.records.shift()
    }
    return created
  }

  /** 销账扫描：payload 命中任一 dispose 模式 → 以捕获的工件路径清偿匹配义务 */
  settleFrom(payload: string): DutyRecord[] {
    const now = this.clock()
    const tokens: string[] = []
    for (const def of this.defs) {
      def.dispose.lastIndex = 0
      const m = def.dispose.exec(payload)
      if (m) tokens.push(m[1] ?? m[0])
    }
    if (!tokens.length) return []
    const settled: DutyRecord[] = []
    for (const rec of this.records) {
      if (rec.status !== 'open') continue
      if (tokens.some(t => pathMatchesArtifact(rec.binding, t))) {
        rec.status = 'fulfilled'
        rec.fulfilledAt = now
        rec.fulfilledBy = tokens.find(t => pathMatchesArtifact(rec.binding, t))!.slice(0, 120)
        settled.push(rec)
      }
    }
    return settled
  }

  /** 人工/宿主侧销账（如宿主在带外完成了清理） */
  manualFulfill(defId: string, binding?: string): DutyRecord[] {
    const now = this.clock()
    const settled: DutyRecord[] = []
    for (const rec of this.records) {
      if (rec.status !== 'open' || rec.defId !== defId) continue
      if (binding !== undefined && rec.binding !== binding) continue
      rec.status = 'fulfilled'
      rec.fulfilledAt = now
      rec.fulfilledBy = 'manual'
      settled.push(rec)
    }
    return settled
  }

  /** 逾期未清的义务（now 严格大于 deadline 才算逾期，期限内不算） */
  overdue(now = this.clock()): DutyRecord[] {
    return this.records.filter(r => r.status === 'open' && now > r.deadlineAt)
  }

  /** 全部未清义务（含未逾期），附 overdue 计算位 */
  open(now = this.clock()): DutyView[] {
    return this.records
      .filter(r => r.status === 'open')
      .map(r => ({ ...r, overdue: now > r.deadlineAt }))
  }

  all(): DutyRecord[] { return [...this.records] }
}
