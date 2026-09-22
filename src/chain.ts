/**
 * 审计日志防篡改哈希链（Tamper-Evident Audit Chain）
 *
 * 借鉴 auditd 受信审计、AWS CloudTrail 完整性验证、Bitcoin 区块哈希链：
 * 每条审计事件串接前一条的哈希，形成链式证据。任何对历史记录的
 * 修改 / 删除 / 插入 / 重排序都会破坏后续哈希验证——证据独立于
 * 防御者进程存活（这是 Sentinel Self-Guard 的盲区：护栏被杀后仍可验伤）。
 *
 * 威胁模型（对应 PR #20 承认的组合边界）：
 *  1. 编辑历史 —— 攻击者事后篡改某条 deny 记录（抹掉作案证据）
 *  2. 截断日志 —— 删掉最后 N 条（销毁最近攻击痕迹）
 *  3. 混入假链 —— 伪造一条"合法"链让全文件验证通过
 */

import { createHash } from 'node:crypto'

export interface ChainEntry {
  /** 链序号（从 1 递增） */
  seq: number
  /** 本条业务内容（JSON 单行，不含链字段） */
  entry: string
  /** 前一条的 recordHash（创世块为 64 个 0） */
  prevHash: string
  /** sha256(entry + '\n' + seq + '\n' + prevHash) */
  recordHash: string
}

export interface ChainHead {
  seq: number
  recordHash: string
}

export const GENESIS_HASH = '0'.repeat(64)

/** 计算一条链记录的哈希（独立纯函数，验证器与写入器共用同一实现） */
export function computeRecordHash(entry: string, seq: number, prevHash: string): string {
  return createHash('sha256').update(`${entry}\n${seq}\n${prevHash}`).digest('hex')
}

/** 把审计业务字段序列化为链上载荷：字段按 key 排序，保证字节级确定性 */
export function canonicalizeEvent(event: Record<string, unknown>): string {
  const keys = Object.keys(event).sort()
  const parts: string[] = []
  for (const k of keys) {
    const v = event[k]
    parts.push(`${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
  }
  return parts.join('\u0001')
}

export interface VerifyResult {
  ok: boolean
  /** 损坏类型 */
  problem:
    | 'empty'            // 空文件（无链可验）
    | 'parse'            // 行不是合法 JSON
    | 'format'           // 缺链字段 / 序号断档
    | 'link'             // prevHash 不接上一条 recordHash（编辑/删除/插入/重排）
    | 'hash'             // recordHash 对不上内容（本条被改）
    | 'genesis'          // 第一条 prevHash 非创世值（整条链是伪造的）
    | null
  /** 第一处损坏的 1-based 行号 */
  line: number
  /** 验证通过的记录数（ok=false 时是损坏前的条数） */
  verifiedCount: number
  /** 锁定的链头（ok=false 时为损坏前最后一条） */
  head: ChainHead | null
  /** 损坏行之前的最后一条原始记录（供宿主展示上下文） */
  lastGood: string | null
}

/**
 * 离线验证一条审计链文件的全部内容。
 * 设计为可在任何机器上运行（只需文件），不依赖护栏进程——
 * 护栏被杀后，事故取证仍可拿着这份文件证明"何时被谁改了"。
 */
export function verifyChain(lines: string[]): VerifyResult {
  if (!lines.length) return { ok: false, problem: 'empty', line: 0, verifiedCount: 0, head: null, lastGood: null }
  let prevHash = GENESIS_HASH
  let expectSeq = 1
  let lastGood: string | null = null
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    let rec: ChainEntry
    try {
      rec = JSON.parse(raw)
    } catch {
      return { ok: false, problem: 'parse', line: i + 1, verifiedCount: i, head: i > 0 ? { seq: expectSeq - 1, recordHash: prevHash } : null, lastGood }
    }
    if (typeof rec.seq !== 'number' || typeof rec.prevHash !== 'string' || typeof rec.recordHash !== 'string' || rec.seq !== expectSeq) {
      return { ok: false, problem: 'format', line: i + 1, verifiedCount: i, head: i > 0 ? { seq: expectSeq - 1, recordHash: prevHash } : null, lastGood }
    }
    if (rec.prevHash !== prevHash) {
      // 第一条接不上创世值 → 整条链是伪造的；中间接不上 → 编辑/删除/插入/重排
      return { ok: false, problem: i === 0 ? 'genesis' : 'link', line: i + 1, verifiedCount: i, head: { seq: expectSeq - 1, recordHash: prevHash }, lastGood }
    }
    const actual = computeRecordHash(rec.entry, rec.seq, rec.prevHash)
    if (actual !== rec.recordHash) {
      return { ok: false, problem: 'hash', line: i + 1, verifiedCount: i, head: { seq: expectSeq - 1, recordHash: prevHash }, lastGood }
    }
    prevHash = rec.recordHash
    expectSeq = rec.seq + 1
    lastGood = raw
  }
  return { ok: true, problem: null, line: 0, verifiedCount: lines.length, head: { seq: expectSeq - 1, recordHash: prevHash }, lastGood }
}

/**
 * TamperEvidence 类：GuardianService 内部的链式写入器。
 * 把每条审计事件串接成链后落盘；内存中维护链头，
 * 跨进程时从磁盘链尾重建（只信记录哈希，不信内存）。
 */
export class TamperEvidence {
  private head: ChainHead
  readonly logFile: string

  constructor(logFile: string, initialHead?: ChainHead) {
    this.logFile = logFile
    // 无初始链头 → 创世态；宿主从磁盘恢复时传入 verifyChain 得到的 head
    this.head = initialHead ?? { seq: 0, recordHash: GENESIS_HASH }
  }

  /** 当前链头（供宿主做外部备份 / 监控告警联动） */
  chainHead(): ChainHead {
    return { ...this.head }
  }

  /**
   * 把一条业务事件追加进链并返回序列化后的行（含链字段）。
   * 拆开"算链"与"写盘"两步：写入策略（同步 fsync / 流式追加）由宿主决定。
   */
  append(event: Record<string, unknown>): string {
    const entry = canonicalizeEvent(event)
    const seq = this.head.seq + 1
    const recordHash = computeRecordHash(entry, seq, this.head.recordHash)
    const rec: ChainEntry = { seq, entry, prevHash: this.head.recordHash, recordHash }
    this.head = { seq, recordHash }
    return JSON.stringify(rec)
  }

  /** 校验内存链头是否与磁盘链尾一致（磁盘被外部改动即检出） */
  checkAgainstDisk(readFileLines: (f: string) => string[]): VerifyResult {
    const lines = readFileLines(this.logFile)
    const res = verifyChain(lines)
    if (res.ok && res.head && res.head.recordHash !== this.head.recordHash) {
      // 链本身自洽但与内存账本不同步：磁盘链尾是外部续写/替换的
      return { ...res, ok: false, problem: 'link' }
    }
    return res
  }
}
