/**
 * 技能演化哨兵（Skill Evolution Guard）—— engine 38
 *
 * 缝合 SkillPoison: Progressive Skill Poisoning via Successful Experiences
 * （arXiv 2026-10-06, DEEP-JLU）：投毒不注入任何恶意内容——每条经验都任务正确、
 * 通过验证与词法检查（95.71% ASR），攻击在于「保留行为、渐进移除约束」，
 * 让技能抽取器把危险行为过度泛化到无条件的适用域。
 *
 * 防御对应物：盯泛化不盯内容。单版本全绿无物可查，毒性在版本间的差分里：
 *  - SKL-001 bare   （block）单版本零约束 + 高危行为——SkillPoison 终态：出生即裸奔
 *  - SKL-002 shear  （deny） 单步剪刀差：约束一步骤降 ≥3 且行为强度不降——一步摘掉全部 when
 *  - SKL-003 drift  （block）渐进轨迹：最近窗口约束单调不增、≥2 次严格递减、行为保留——温水煮青蛙
 *
 * 记账语义：账本 = 磁盘真实状态的历史。只有放行（含人工批准后）的版本才入账；
 * 上游引擎拦截的写入到不了本引擎，被本引擎拦截的版本不入账——被拦下重写是攻击者的新版本。
 * 同内容重写（hash 相同）幂等跳过，不重复判定。
 */
import { createHash } from 'node:crypto'

/** 约束特征计数：条件连词 / 作用域限定 / 排除子句 / 中文条件 */
const GUARD_PATTERNS: RegExp[] = [
  /\b(when|whenever|if|unless|provided|only)\b/gi,
  /\b(in|within|inside|under)\s+(the\s+)?[a-z][\w.-]*/gi,
  /\b(except|excluding|never\s+for|but\s+not)\b/gi,
  /仅在|只有|除非|除了|如果|仅当|范围内|当[^，。\n]{0,10}时/g,
]

/** 行为特征词表（危险动词，带权重）——「行为保留」的量化锚点 */
const ACT_PATTERNS: { id: string; weight: number; pattern: RegExp }[] = [
  { id: 'recursive-rm', weight: 0.9, pattern: /rm\s+-[a-z]*r/i },
  { id: 'force-push', weight: 0.9, pattern: /git\s+push\b[^|\n]*--force/i },
  { id: 'sql-drop', weight: 0.9, pattern: /\b(drop|truncate)\s+(table|database)\b/i },
  { id: 's3-purge', weight: 0.9, pattern: /aws\s+s3\s+(rb|rm)\b[^|\n]*--force/i },
  { id: 'sudo-power', weight: 0.9, pattern: /\bsudo\b[^|\n]{0,20}\b(rm|dd|mkfs|chmod|chown)\b/i },
  { id: 'curl-upload', weight: 0.8, pattern: /curl\b[^|\n]*\s(--data|-F|-T|--upload-file)\b/i },
  { id: 'k8s-delete', weight: 0.8, pattern: /kubectl\s+delete\s+(ns|namespace|deploy|pv|pvc|crd)\b/i },
  { id: 'world-write', weight: 0.8, pattern: /chmod\s+(-R\s+)?777/i },
  { id: 'hard-reset', weight: 0.7, pattern: /git\s+reset\s+--hard/i },
  { id: 'pipe-exec', weight: 0.7, pattern: /\|\s*(ba|z|fi)?sh\b/i },
]

/** 技能文件路径特征：skills/<name>/SKILL.md（覆盖 .claude/.codex 等宿主布局） */
export const SKILL_PATH_PATTERN = /[\w@./~-]*skills\/[\w.-]+\/SKILL\.md/i

export interface SkillProfile {
  /** 约束计数（条件/作用域/排除子句命中总数） */
  guards: number
  /** 危险行为最高权重（0~1），0 = 无命中 */
  actScore: number
  /** 危险行为命中条数 */
  actCount: number
  /** 命中的行为 id 列表 */
  actIds: string[]
}

export interface SkillVersion {
  seq: number
  hash: string
  guards: number
  actScore: number
  actCount: number
  actIds: string[]
  ts: string
}

export interface SkillVerdict {
  ruleId: 'SKL-001' | 'SKL-002' | 'SKL-003'
  action: 'deny' | 'block'
  reason: string
  /** 供审计/复核的差分摘要 */
  detail: string
}

function countMatches(text: string, pattern: RegExp): number {
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g')
  const hits = text.match(re)
  return hits ? hits.length : 0
}

/** 提取单版本技能画像：约束强度 vs 行为强度 */
export function profileSkill(content: string): SkillProfile {
  let guards = 0
  for (const p of GUARD_PATTERNS) guards += countMatches(content, p)
  let actScore = 0
  let actCount = 0
  const actIds: string[] = []
  for (const a of ACT_PATTERNS) {
    if (a.pattern.test(content)) {
      actScore = Math.max(actScore, a.weight)
      actCount += 1
      actIds.push(a.id)
    }
  }
  return { guards, actScore, actCount, actIds }
}

export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 16)
}

/** 单步剪刀差阈值：约束一步骤降 ≥3 判「一步摘掉全部 when」 */
const SHEAR_DROP = 3
/** 渐进轨迹窗口：最近 N 版（含当前候选版本） */
const DRIFT_WINDOW = 3

/**
 * 判定当前候选版本（history 为磁盘上已放行的版本链）。
 * 返回 null = 放行。判定顺序：跳变 → 终态 → 轨迹——
 * 剪刀差能证明「约束曾经存在过」，归因强于无历史的裸奔终态。
 */
export function judgeSkillEvolution(profile: SkillProfile, history: SkillVersion[]): SkillVerdict | null {
  const prev = history[history.length - 1]
  if (prev) {
    // SKL-002：单步剪刀差——约束骤降 ≥3 且行为强度不降（摘约束不摘行为）
    const drop = prev.guards - profile.guards
    if (prev.guards >= SHEAR_DROP && drop >= SHEAR_DROP && profile.actScore >= prev.actScore && profile.actScore > 0) {
      return {
        ruleId: 'SKL-002',
        action: 'deny',
        reason: `技能单步去约束：约束 ${prev.guards}→${profile.guards} 骤降而危险行为保留，疑似渐进投毒的跳变步`,
        detail: `guards ${prev.guards}→${profile.guards}, actScore ${prev.actScore}→${profile.actScore}`,
      }
    }
  }

  // SKL-001：出生即裸奔——零约束 + 高危行为（SkillPoison 终态：泛化后的无约束危险技能）
  if (profile.guards === 0 && profile.actScore >= 0.8) {
    return {
      ruleId: 'SKL-001',
      action: 'block',
      reason: '技能零上下文约束但含高危行为：无条件适用域的危险技能（SkillPoison 终态），需人工确认',
      detail: `guards=0 acts=${profile.actIds.join('/')}`,
    }
  }

  // SKL-003：渐进轨迹——窗口内约束单调不增、≥2 次严格递减、末版行为仍在
  const windowSeq = [...history.slice(-(DRIFT_WINDOW - 1)).map((v) => v.guards), profile.guards]
  if (windowSeq.length >= DRIFT_WINDOW) {
    let nonIncreasing = true
    let strictDrops = 0
    for (let i = 1; i < windowSeq.length; i++) {
      if (windowSeq[i] > windowSeq[i - 1]) { nonIncreasing = false; break }
      if (windowSeq[i] < windowSeq[i - 1]) strictDrops += 1
    }
    if (nonIncreasing && strictDrops >= 2 && profile.actScore > 0) {
      return {
        ruleId: 'SKL-003',
        action: 'block',
        reason: `技能渐进去约束轨迹：约束按 ${windowSeq.join('→')} 单调递减而行为保留，温水煮青蛙式泛化投毒，需人工复核`,
        detail: `guards window [${windowSeq.join(',')}], acts=${profile.actIds.join('/')}`,
      }
    }
  }

  return null
}

/** 技能演化账本：per 路径版本链（纯内存，与会话同生命周期） */
export class SkillLedger {
  private chains = new Map<string, SkillVersion[]>()

  /** 当前版本是否与账本末版同内容（幂等跳过，不重复判定/入账） */
  isDuplicate(pathKey: string, content: string): boolean {
    const chain = this.chains.get(pathKey)
    if (!chain || chain.length === 0) return false
    return chain[chain.length - 1].hash === hashContent(content)
  }

  history(pathKey: string): SkillVersion[] {
    return this.chains.get(pathKey) ?? []
  }

  /** 放行后入账（账本 = 磁盘真实状态的历史） */
  record(pathKey: string, content: string): SkillVersion {
    const chain = this.chains.get(pathKey) ?? []
    const profile = profileSkill(content)
    const version: SkillVersion = {
      seq: chain.length + 1,
      hash: hashContent(content),
      guards: profile.guards,
      actScore: profile.actScore,
      actCount: profile.actCount,
      actIds: profile.actIds,
      ts: new Date().toISOString(),
    }
    chain.push(version)
    this.chains.set(pathKey, chain)
    return version
  }

  reset(pathKey?: string) {
    if (pathKey === undefined) this.chains.clear()
    else this.chains.delete(pathKey)
  }

  summary(): Array<{ path: string; versions: number; guardsTrail: number[]; lastActs: string[] }> {
    return [...this.chains.entries()].map(([path, chain]) => ({
      path,
      versions: chain.length,
      guardsTrail: chain.map((v) => v.guards),
      lastActs: chain[chain.length - 1]?.actIds ?? [],
    }))
  }
}

/** 从工具调用 payload 提取（技能路径, 内容）。不匹配技能路径返回 null */
export function extractSkillWrite(payload: unknown, extraPatterns: RegExp[] = []): { pathKey: string; content: string } | null {
  const obj = (payload && typeof payload === 'object' ? payload : null) as Record<string, unknown> | null
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {})
  const patterns = [SKILL_PATH_PATTERN, ...extraPatterns]
  let pathKey: string | null = null
  for (const p of patterns) {
    p.lastIndex = 0
    const m = text.match(p)
    if (m) { pathKey = m[0]; break }
  }
  if (!pathKey) return null
  // 内容优先取结构化字段（write 工具），否则退回全文（bash heredoc 等字符串形态）
  const content = obj && typeof obj.content === 'string' ? obj.content
    : obj && typeof obj.text === 'string' ? obj.text
      : text
  return { pathKey, content }
}
