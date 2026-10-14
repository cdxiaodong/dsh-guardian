/**
 * Engine 41: Compensation Ledger（补偿账本引擎——副作用可撤销性门禁）
 *
 * 缝合 Cordon（arXiv:2606.17573，2026-06-16）与 Recourse（arXiv:2609.01939，2026-09-01）：
 * 工具型 agent 的计算单元已从"人发的单条命令"变成"模型驱动的多步有状态任务"，
 * 而运行时仍把工具暴露为孤立 RPC——缺一个任务级执行边界来统一 commit / rollback /
 * recovery / audit。两篇论文的核心主张：
 *
 *   Cordon —— 不可逆外部效应应先进 effect outbox 暂存，任务级验证通过才释放；
 *              出口动作必须绑定 recovery metadata（补偿动作）。
 *   Recourse —— 每个被放行的动作绑 scope / recovery / evidence / payout / collateral，
 *              "授权"与"本地补偿"只覆盖事前准入与运行时回滚，
 *              残余伤害需要事后凭证（typed receipts）来结算。
 *
 * 本引擎把它确定性化为**放行前的可撤销性审计**：
 *
 *   1. 补偿动作分类学：把工具调用按"副作用类别"归入 undoable / escrow / irreversible，
 *      并为 undoable/escrow 类在 payload 文本里寻找可用的补偿动作证据
 *      （rm→重建来源、mv→mv 回去、git commit→revert、curl 上传→删除远端……）。
 *   2. 补偿账本（ledger）：放行即记账——每次有副作用调用登记
 *      { 类别, 补偿动作, 是否已结算 }；任务结束（settle）时逐条结算，
 *      未结算且无补偿动作 = 裸副作用残留（DENY 级别不准进入下一任务）。
 *   3. 裸不可逆门禁：irreversible 类（dd 覆盘、mkfs、fork 炸弹、shred、
 *      setuid/systemd 持久化、出境外发）在无补偿动作时升级处置
 *      （block→deny：有批准也不能免检放行无补偿的不可逆操作）。
 *
 * 与现有引擎的分工：其他引擎判定"这次调用危险吗"，本引擎判定"这次调用的后果
 * 撤得销吗"——前者管事前准入，后者管事后责任。PATH-004/005/007 等持久化规则
 * 只在写入时拦，本引擎在任务级追问"整个任务结束时留下了什么"。
 *
 * 规则表（审计通道 engine='compensation'）：
 *   CMP-001 deny  裸不可逆副作用——irreversible 类 + 无补偿动作证据
 *   CMP-002 block 可补偿副作用登记——undoable/escrow 类 + 有补偿动作（记账+确认）
 *   CMP-003 block 补偿动作缺失——undoable 类声称可撤销但找不到对应补偿命令
 *   CMP-004 block 账本结算残留——settle 时存在未结算副作用（人工裁决任务残留）
 */

import type { Rule } from './rules.js'
import { DEFAULT_RULES } from './rules.js'

/** 副作用类别（补偿能力从高到低） */
export type EffectClass =
  | 'pure'         // 无副作用（读/查询）
  | 'undoable'     // 可补偿：存在机械的逆操作（rm→恢复来源、mv→反向 mv、git→revert）
  | 'escrow'       // 可滞留：外发类，先扣押后放行（交给 egress-escrow 语义）
  | 'irreversible' // 不可逆：无机械逆操作（覆盘/格式化/粉碎/持久化/外发落盘）

export interface EffectEntry {
  /** 账本序号 */
  seq: number
  /** 工具名 */
  tool: string
  /** 副作用类别 */
  effectClass: EffectClass
  /** 命中的不可逆特征 id */
  signature: string
  /** 文本中找到的补偿动作（undoable 类必有；其他为 null） */
  compensation: string | null
  /** 已结算（settle 清点过 / revert 命中账本条目） */
  settled: boolean
  /** 原始 snippet（截断，审计回显用） */
  snippet: string
  /** 登记时间戳（ms，注入时钟） */
  ts: number
}

export interface CompensationVerdict {
  intercepted: boolean
  ruleId: 'CMP-001' | 'CMP-002' | 'CMP-003' | 'CMP-004' | null
  action: 'deny' | 'block' | null
  reason?: string
  /** 登记进账本的条目 seq（CMP-002 时存在） */
  ledgerSeq?: number
}

export interface CompensationConfig {
  enabled?: boolean
  /** 账本容量上限（防内存膨胀；默认 1024，LRU 淘汰） */
  maxEntries?: number
  /** 条目有效期（ms；默认 7 天） */
  ttl?: number
  now?: () => number
}

// ── 不可逆签名表：主规则库中"无机械逆操作"的特征（复用 id，零新正则）────
// 处置映射：deny 类签名=本来就拦；block/log 类签名=本引擎升级审计的对象。
const IRREVERSIBLE_RULE_IDS = new Set([
  'CMD-001', // rm -rf /
  'CMD-003', // dd 覆盘 / 重定向磁盘设备
  'CMD-004', // mkfs
  'CMD-005', // fork 炸弹
  'CMD-007', // shred
  'CMD-009', // mv / -> /dev/null
  'PATH-004', // cron 持久化
  'PATH-005', // systemd 持久化
  'PATH-006', // shell 启动文件持久化
  'PATH-007', // authorized_keys 后门
  'PRIV-002', // setuid
  'PRIV-003', // 关 ASLR
  'PRIV-004', // 关防火墙
])

// ── 可补偿签名表：存在机械逆操作的特征 ──────────────────────────
const UNDOABLE_RULE_IDS = new Set([
  'CMD-002', // rm -rf 目录 → 有备份/来源则可恢复
  'PATH-001', // 路径穿越写
  'PRIV-001', // sudo 敏感命令
])

// ── escrow 类：出境外发（字节已离开本机，只能"扣押后放行"不能撤回）──
const ESCROW_RULE_IDS = new Set([
  'EXFIL-001', 'EXFIL-002', 'EXFIL-003', 'EXFIL-004', 'EXFIL-005',
  'INJ-001', // curl | sh：脚本已执行
])

// ── 补偿动作证据：文本中显式携带的"恢复来源/逆操作"命令 ──────────
// Cordon 的 recovery metadata：出口动作必须绑定补偿动作说明。
// 备份创建（cp src dst.bak）与恢复（cp src.bak dst）方向相反，模式分开写。
const COMPENSATION_PATTERNS: Array<{ id: string; re: RegExp }> = [
  { id: 'cp-backup', re: /\b(?:cp|rsync)\s+(?:["']?)([^\s"']+)(?:["']?)\s+(?:["']?)([^\s"']+\.(?:bak|orig|backup|old))(?:["']?)(?=\s|$|&&|;)/i },
  { id: 'backup-first', re: /\b(mkdir|tar|rsync|cp)[^\n]{0,80}\bbackup\b[^\n]{0,80}/i },
  { id: 'git-safe', re: /\bgit\s+(stash|commit|branch|checkout\s+-b|switch\s+-c)\b/i },
  { id: 'git-revert', re: /\bgit\s+(revert|reset|restore)\b/i },
  { id: 'mv-back', re: /\bmv\s+["']?[^"'\n]{1,120}["']?\s+["']?[^"'\n]{1,120}["']?\s*&&\s*mv\s+/i },
  { id: 'tmp-workdir', re: /(?:\bmktemp\b|\bmktempdir\b|-d\s+\/tmp\/|\/tmp\/[a-z0-9._-]{3,})/i },
]

// ── 反向结算动作：settle 时把账本里的补偿标记为已执行 ──────────────
// 恢复 = 方向反转：源是 .bak 备份，目标**不是**备份后缀（'cp A.bak A'，
// 与备份创建 'cp A A.bak' 方向相反，必须用组方向区分，单个正则会互相误命中）。
const SETTLE_PATTERNS: Array<{ id: string; re: RegExp }> = [
  { id: 'restore-backup', re: /\b(?:cp|rsync)\s+(?:["']?)([^\s"']+\.(?:bak|orig|backup|old))(?:["']?)\s+(?:["']?)([^\s"']+)(?:["']?)(?=\s|$|&&|;)/i },
  { id: 'git-clean', re: /\bgit\s+(?:revert|reset|restore|clean|checkout\s+--)\b/i },
  { id: 'git-branch-del', re: /\bgit\s+(?:branch\s+-D|branch\s+-d|stash\s+drop|stash\s+pop)\b/i },
  { id: 'rm-tmp', re: /\brm\s+(?:-[a-z]+\s+)?\/tmp\//i },
]

/** 不可逆签名（惰性缓存，避免 import 环） */
function irreversibleRules(): Rule[] {
  return DEFAULT_RULES.filter((r) => IRREVERSIBLE_RULE_IDS.has(r.id))
}

function undoableRules(): Rule[] {
  return DEFAULT_RULES.filter((r) => UNDOABLE_RULE_IDS.has(r.id))
}

function escrowRules(): Rule[] {
  return DEFAULT_RULES.filter((r) => ESCROW_RULE_IDS.has(r.id))
}

/** 文本命中的指定 id 集规则列表 */
function hitRules(rules: Rule[], text: string): Rule[] {
  const hits: Rule[] = []
  for (const rule of rules) {
    rule.pattern.lastIndex = 0
    if (rule.pattern.test(text)) hits.push(rule)
  }
  return hits
}

/** 在文本中找补偿动作证据（Cordon recovery metadata 的确定性版） */
export function findCompensation(text: string): string | null {
  for (const p of COMPENSATION_PATTERNS) {
    p.re.lastIndex = 0
    if (p.re.test(text)) return p.id
  }
  return null
}

/** 在文本中找结算动作（settle 阶段：补偿已执行） */
export function findSettlement(text: string): string | null {
  for (const p of SETTLE_PATTERNS) {
    p.re.lastIndex = 0
    if (p.re.test(text)) return p.id
  }
  return null
}

export class CompensationLedger {
  private entries: EffectEntry[] = []
  private nextSeq = 1
  private maxEntries: number
  private ttl: number
  private now: () => number

  constructor(cfg: CompensationConfig = {}) {
    this.maxEntries = cfg.maxEntries ?? 1024
    this.ttl = cfg.ttl ?? 7 * 24 * 3600 * 1000
    this.now = cfg.now ?? (() => Date.now())
  }

  private sweep() {
    const t = this.now()
    if (this.ttl < Infinity) {
      this.entries = this.entries.filter((e) => t - e.ts <= this.ttl)
    }
  }

  private evictIfNeeded() {
    if (this.entries.length <= this.maxEntries) return
    // 淘汰最老的已结算条目（已结算是历史，未结算是待办证据优先保留）；
    // 若全是未结算则淘汰最老条目（FIFO 保底）。
    while (this.entries.length > this.maxEntries) {
      let victimIdx = this.entries.findIndex((e) => e.settled)
      if (victimIdx === -1) victimIdx = 0
      this.entries.splice(victimIdx, 1)
    }
  }

  /**
   * 判定 + 记账：放行前对一次有副作用的工具调用做可撤销性审计。
   * @param tool   工具名
   * @param text   payload 文本（宿主序列化后）
   */
  check(tool: string, text: string): CompensationVerdict {
    this.sweep()
    // 优先级：irreversible > escrow > undoable（同一文本命中多类按最严重算）
    const irrHits = hitRules(irreversibleRules(), text)
    if (irrHits.length) {
      const sig = irrHits[0]
      const comp = findCompensation(text)
      // CMP-001：不可逆 + 无补偿动作证据 = 裸副作用。
      // deny 级签名前置引擎已拦；这里升级的是 block/log 级签名（如 PATH-006 写 .bashrc：
      // 主库只 block，但写启动文件持久化 + 无备份 = 任务结束后撤不销，本引擎顶格 deny）。
      if (!comp) {
        this.record(tool, 'irreversible', sig.id, null, text)
        return {
          intercepted: true, ruleId: 'CMP-001', action: 'deny',
          reason: `裸不可逆副作用：${sig.reason}（${sig.id}）无补偿动作证据（无备份/无 revert/无临时区），放行即残留`,
        }
      }
      // 不可逆 + 有补偿证据：仍按 escrow 登记待结算（如 dd 前先 dd 备份扇区）
      const seq = this.record(tool, 'irreversible', sig.id, comp, text)
      return {
        intercepted: true, ruleId: 'CMP-002', action: 'block',
        reason: `可补偿副作用：${sig.reason}（${sig.id}）检测到补偿动作 ${comp}，登记账本 #${seq}，任务结束需结算`,
        ledgerSeq: seq,
      }
    }

    const escHits = hitRules(escrowRules(), text)
    if (escHits.length) {
      const sig = escHits[0]
      const seq = this.record(tool, 'escrow', sig.id, null, text)
      return {
        intercepted: true, ruleId: 'CMP-002', action: 'block',
        reason: `出境副作用：${sig.reason}（${sig.id}）字节离机不可撤回，登记账本 #${seq} 走扣押/结算流程`,
        ledgerSeq: seq,
      }
    }

    const undoHits = hitRules(undoableRules(), text)
    if (undoHits.length) {
      const sig = undoHits[0]
      const comp = findCompensation(text)
      // CMP-003：undoable 类命中但找不到补偿动作——"可撤销"沦为口头承诺。
      // block 级而非 deny：用户有权批准无备份的删除，但必须在补偿引擎的
      // 提示下二次确认（主规则批准的是"危险"，这里批准的是"不可恢复"）。
      if (!comp) {
        this.record(tool, 'undoable', sig.id, null, text)
        return {
          intercepted: true, ruleId: 'CMP-003', action: 'block',
          reason: `补偿动作缺失：${sig.reason}（${sig.id}）属可补偿类但 payload 无恢复来源（无备份/revert/tmp），确认接受不可恢复后果？`,
        }
      }
      const seq = this.record(tool, 'undoable', sig.id, comp, text)
      return {
        intercepted: true, ruleId: 'CMP-002', action: 'block',
        reason: `可补偿副作用：${sig.reason}（${sig.id}）补偿动作 ${comp}，登记账本 #${seq}`,
        ledgerSeq: seq,
      }
    }

    return { intercepted: false, ruleId: null, action: null }
  }

  /** 记账：放行/拦截的副作用调用登记进账本 */
  private record(tool: string, effectClass: EffectClass, signature: string, compensation: string | null, text: string): number {
    const entry: EffectEntry = {
      seq: this.nextSeq++,
      tool,
      effectClass,
      signature,
      compensation,
      settled: false,
      snippet: text.slice(0, 200),
      ts: this.now(),
    }
    this.entries.push(entry)
    this.evictIfNeeded()
    return entry.seq
  }

  /**
   * 结算：一次后续调用若命中结算动作模式，把账本中**同工具或全局**未结算条目
   * 标记已结算（恢复来源被真正使用 = 补偿兑现）。
   */
  settle(tool: string, text: string): number {
    const settleAction = findSettlement(text)
    if (!settleAction) return 0
    let n = 0
    for (const e of this.entries) {
      if (e.settled) continue
      if (e.tool === tool || isGlobalSettle(settleAction)) {
        e.settled = true
        n++
      }
    }
    return n
  }

  /**
   * 任务结束清点（Cordon commit 门槛）：存在未结算副作用 → CMP-004 block，
   * 由人工裁决任务残留（批准=接受残留；deny=强制回滚）。
   */
  settleTask(): CompensationVerdict & { unsettled: EffectEntry[] } {
    this.sweep()
    const unsettled = this.entries.filter((e) => !e.settled)
    if (!unsettled.length) return { intercepted: false, ruleId: null, action: null, unsettled: [] }
    return {
      intercepted: true, ruleId: 'CMP-004', action: 'block',
      reason: `账本结算残留：${unsettled.length} 条副作用未结算（${unsettled.map((e) => `${e.signature}#${e.seq}`).slice(0, 5).join(', ')}${unsettled.length > 5 ? '…' : ''}），任务结束需人工裁决`,
      unsettled,
    }
  }

  /** 人工批准残留：把全部未结算条目标记已结算（接受现状） */
  acceptResidual(): number {
    let n = 0
    for (const e of this.entries) {
      if (!e.settled) { e.settled = true; n++ }
    }
    return n
  }

  snapshot(): { total: number; unsettled: number; byClass: Record<string, number> } {
    this.sweep()
    const byClass: Record<string, number> = {}
    for (const e of this.entries) byClass[e.effectClass] = (byClass[e.effectClass] ?? 0) + 1
    return {
      total: this.entries.length,
      unsettled: this.entries.filter((e) => !e.settled).length,
      byClass,
    }
  }

  /** 测试/调试用：取出账本条目 */
  list(): EffectEntry[] { return [...this.entries] }
}

/** 全局结算动作（git revert / 恢复备份不挑工具） */
function isGlobalSettle(settleId: string): boolean {
  return settleId === 'git-clean' || settleId === 'restore-backup'
}
