/**
 * 技能元数据完整性引擎（engine-46，缝合 MetaCascade: arXiv:2610.14836）。
 *
 * MetaCascade 证明了纯元数据投毒（metadata-only poisoning）无需执行恶意代码即可
 * 形成端到端攻击链：检索阶段靠关键词堆砌抢占排名（retrieval hijacking），选择阶段
 * 靠能力过度声明与排名诱导语骗过 agent 的最终决策（selection hijacking），并用
 * 黑盒竞争反馈迭代调参元数据。
 *
 * 本引擎在"声明 vs 实现"维度做静态自洽性审计，与 engine-38（时间维度的技能演化
 * 对比）正交：38 管"前后变了什么"，46 管"此刻元数据与代码是否对得上"。
 *
 * 五条规则对应论文攻击链三环节：
 *  - 检索：SMD-001 关键词堆砌 / SMD-002 同义词饱和（多视角语义扩展的直接特征）
 *  - 选择：SMD-003 能力过度声明 / SMD-004 排名诱导语
 *  - 调参：SMD-005 元数据震荡（代码冻结而元数据反复变更 = 竞争反馈痕迹）
 */

export interface SkillManifest {
  /** 技能名 */
  name: string
  /** 检索/选择阶段可见的描述 */
  description?: string
  /** 检索阶段可见的标签 */
  tags?: string[]
  /** 检索阶段可见的关键词（部分技能格式单独提供） */
  keywords?: string[]
  /** 技能实际内容（源码 + 文档拼接文本），用于自洽性对齐 */
  content: string
}

export interface SkillMetaFinding {
  ruleId: string
  reason: string
  /** block=需人工确认；log=仅记录。本引擎不发 deny（营销措辞有合法边缘，交人工裁决） */
  action: 'block' | 'log'
  evidence: string
}

export interface SkillChurnEntry {
  ts: number
  /** 检索可见字段（name/description/tags/keywords）的 canonical hash */
  metaHash: string
  /** 内容文本的 hash */
  contentHash: string
}

/** SMD-001 阈值：元数据实词总数下限、零支撑数下限、零支撑占比下限 */
export const STUFFING_MIN_TERMS = 5
export const STUFFING_MIN_UNSSUPPORTED = 3
export const STUFFING_RATIO = 0.6

/** SMD-002 阈值：字符 trigram Jaccard 相似度下限；相似邻居数下限（含自身即 3 词成簇） */
export const SATURATION_SIMILARITY = 0.45
export const SATURATION_NEIGHBORS = 2

/** SMD-003 阈值：零支撑能力短语数下限（单条可能是措辞省略） */
export const OVERCLAIM_MIN = 2

/** SMD-005 默认参数 */
export const CHURN_WINDOW_MS = 24 * 3600 * 1000
export const CHURN_THRESHOLD = 3

/**
 * 元数据里的虚词与身份词：不构成能力声明，剔除后避免正常描述误伤
 * （tool/skill/plugin/assistant 是身份词，几乎每个正常技能描述都有）
 */
const STOPWORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'for', 'with', 'your', 'you', 'to', 'of', 'in', 'on',
  'at', 'by', 'is', 'are', 'be', 'this', 'that', 'these', 'those', 'it', 'its', 'as',
  'from', 'into', 'using', 'use', 'used', 'can', 'will', 'also', 'more', 'most', 'all',
  'any', 'new', 'now', 'not', 'no', 'yes', 'via', 'per', 'up', 'out', 'off', 'over',
  'tool', 'tools', 'skill', 'skills', 'plugin', 'plugins', 'assistant', 'agent', 'agents',
  'support', 'supports', 'supported', 'including', 'includes', 'include', 'based', 'like',
  // 泛管理/营销形容词：不指明具体能力域，留着会放大误报
  'manage', 'manages', 'management', 'handle', 'handling', 'simple', 'easy', 'fast',
  'powerful', 'professional', 'complete', 'comprehensive', 'advanced', 'super',
])

/** SMD-003：能力动词白名单（动词+宾语构成一条可验证的能力声明） */
const CAPABILITY_VERBS = [
  'read', 'reads', 'fetch', 'fetches', 'send', 'sends', 'manage', 'manages',
  'process', 'processes', 'convert', 'converts', 'scan', 'scans', 'analyze', 'analyzes',
  'analyse', 'analyses', 'generate', 'generates', 'create', 'creates', 'edit', 'edits',
  'delete', 'deletes', 'upload', 'uploads', 'download', 'downloads', 'monitor', 'monitors',
  'track', 'tracks', 'search', 'searches', 'parse', 'parses', 'extract', 'extracts',
  'compress', 'compresses', 'translate', 'translates', 'summarize', 'summarizes',
  'write', 'writes', 'handle', 'handles', 'automate', 'automates', 'sync', 'syncs',
]

/** SMD-004：排名诱导语（选择阶段劫持——功能是诱导选择而非描述能力） */
const LURE_PATTERNS: { re: RegExp; label: string }[] = [
  // 最高级形容词 / 权威背书（superlative 需绑定品类名词，"best" 单独出现误报高）
  { re: /\b(best|#1|top[- ]rated|most popular|must[- ]have|first choice|highly recommended|strongly recommended)\b.{0,40}\b(tool|skill|plugin|assistant|integration|package|library)\b/i, label: 'superlative' },
  { re: /\b(tool|skill|plugin|assistant|integration|package|library)\b.{0,40}\b(best|#1|top[- ]rated|most popular|must[- ]have|first choice)\b/i, label: 'superlative' },
  // 权威伪装
  { re: /\bofficial\b.{0,30}\b(tool|skill|plugin|assistant|integration)\b/i, label: 'authority' },
  // 替代/比较话术：瞄准既有热门技能的存量查询流量
  { re: /\balternative to\b/i, label: 'displacement' },
  { re: /\b(instead of|better than|faster than|upgrade from|drop[- ]in replacement)\b.{0,40}\b(tool|skill|plugin|package|library|assistant|extension|workflow)\b/i, label: 'displacement' },
  { re: /\breplaces?\s+(the\s+)?(official\s+|popular\s+|default\s+)?\b[\w.-]+\s*(tool|skill|plugin|package|library)\b/i, label: 'displacement' },
  // 中文诱导
  { re: /(官方|最好用?|首选|强烈推荐|必装|完美替代|完整替代).{0,12}(工具|技能|插件|助手|方案)/, label: 'lure-zh' },
  { re: /比.{1,15}(更快|更强大|更好用|更优秀)/, label: 'compare-zh' },
  { re: /(替代|取代).{0,12}(工具|技能|插件)/, label: 'displacement-zh' },
]

// ── 词法工具 ────────────────────────────────────────────

/** 轻量英文词干化（Porter 近似）：复数/ing/ed 归一，双写辅音还原 */
export function stem(w: string): string {
  let s = w.toLowerCase()
  if (s.length <= 3) return s
  s = s.replace(/ies$/, 'y')
  s = s.replace(/([^s])s$/, '$1')
  if (s.length > 5) s = s.replace(/ing$/, '')
  else if (s.length > 4) s = s.replace(/ed$/, '')
  s = s.replace(/([a-z])\1$/, '$1')
  return s
}

/** 拉丁实词提取（≥3 字母，去停用词，词干化；连字符/加号当分隔符，复合词拆开对齐） */
function latinTerms(text: string): string[] {
  const out: string[] = []
  const re = /[a-z][a-z0-9]{2,}/gi
  for (const raw of text.match(re) ?? []) {
    const s = stem(raw)
    if (s.length >= 3 && !STOPWORDS.has(raw.toLowerCase()) && !STOPWORDS.has(s)) out.push(s)
  }
  return out
}

/** CJK bigram（中文无空格分词，退化为二元组做覆盖对齐） */
function cjkBigrams(text: string): string[] {
  const out: string[] = []
  const re = /[一-鿿]/gu
  const chars = text.match(re) ?? []
  for (let i = 0; i + 1 < chars.length; i++) out.push(chars[i] + chars[i + 1])
  return out
}

/** 内容支撑词集（拉丁词干 + CJK bigram） */
function contentTerms(content: string): Set<string> {
  return new Set([...latinTerms(content), ...cjkBigrams(content)])
}

/** 字符 trigram 集合（归一化：lowercase、去非字母数字） */
function trigrams(s: string): Set<string> {
  const norm = s.toLowerCase().replace(/[^a-z0-9]/g, '')
  const out = new Set<string>()
  for (let i = 0; i + 3 <= norm.length; i++) out.add(norm.slice(i, i + 3))
  return out
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0
  let inter = 0
  for (const x of a) if (b.has(x)) inter++
  return inter / (a.size + b.size - inter)
}

// ── 规则实现 ────────────────────────────────────────────

/** SMD-001：元数据实词零内容支撑 → 检索关键词堆砌 */
function checkStuffing(manifest: SkillManifest, supported: Set<string>): SkillMetaFinding | null {
  const metaText = [manifest.name, manifest.description ?? '', ...(manifest.tags ?? []), ...(manifest.keywords ?? [])].join(' ')
  const terms = [...latinTerms(metaText), ...cjkBigrams(metaText)]
  if (terms.length < STUFFING_MIN_TERMS) return null
  const uniq = [...new Set(terms)]
  const unsupported = uniq.filter((t) => !supported.has(t))
  const ratio = unsupported.length / uniq.length
  if (unsupported.length >= STUFFING_MIN_UNSSUPPORTED && ratio >= STUFFING_RATIO) {
    return {
      ruleId: 'SMD-001',
      reason: `元数据关键词堆砌：${unsupported.length}/${uniq.length} 个检索词在技能内容中零支撑（占比 ${(ratio * 100).toFixed(0)}%）——典型检索劫持特征（MetaCascade 式 metadata-only 投毒）`,
      action: 'block',
      evidence: `零支撑词：${unsupported.slice(0, 8).join(', ')}${unsupported.length > 8 ? ' …' : ''}`,
    }
  }
  return null
}

/** SMD-002：tags/keywords 内部近义词聚集 → 多视角语义扩展饱和 */
function checkSaturation(manifest: SkillManifest): SkillMetaFinding | null {
  const labels = [...(manifest.tags ?? []), ...(manifest.keywords ?? [])]
    .map((t) => t.toLowerCase().replace(/[^a-z0-9一-鿿]/g, ''))
    .filter((t) => t.length >= 4)
  if (labels.length < SATURATION_NEIGHBORS + 1) return null
  const grams = labels.map((l) => trigrams(l))
  for (let i = 0; i < labels.length; i++) {
    const neighbors: string[] = []
    for (let j = 0; j < labels.length; j++) {
      if (i === j) continue
      if (jaccard(grams[i], grams[j]) >= SATURATION_SIMILARITY) neighbors.push(labels[j])
    }
    if (neighbors.length >= SATURATION_NEIGHBORS) {
      return {
        ruleId: 'SMD-002',
        reason: `标签同义词饱和："${labels[i]}" 周围聚集 ${neighbors.length} 个高相似变体——围绕同一查询意图堆砌近义词是多视角语义扩展投毒的直接特征，正常标签描述功能的不同侧面而非同一意图的变体`,
        action: 'block',
        evidence: `相似簇：${[labels[i], ...neighbors].slice(0, 6).join(' | ')}`,
      }
    }
  }
  return null
}

/** SMD-003：description 中"动词+宾语"能力短语在内容中无对应实现 → 过度声明 */
function checkOverclaim(manifest: SkillManifest, supported: Set<string>): SkillMetaFinding | null {
  const desc = manifest.description ?? ''
  const verbAlt = CAPABILITY_VERBS.join('|')
  // 动词 + 可选冠词/物主代词 + 宾语名词
  const re = new RegExp(`\\b(${verbAlt})\\s+(?:the\\s+|your\\s+|all\\s+|any\\s+)?([a-z][a-z0-9-]{2,})`, 'gi')
  const unsupported: string[] = []
  for (const m of desc.matchAll(re)) {
    const obj = stem(m[2])
    if (obj.length < 3 || STOPWORDS.has(obj)) continue
    if (!supported.has(obj)) unsupported.push(`${m[1].toLowerCase()} ${m[2].toLowerCase()}`)
  }
  if (unsupported.length >= OVERCLAIM_MIN) {
    return {
      ruleId: 'SMD-003',
      reason: `能力过度声明：${unsupported.length} 条"动词+宾语"声明在技能内容中零实现——选择阶段会按声明授予能力，实际代码并不具备`,
      action: 'block',
      evidence: `未支撑声明：${unsupported.slice(0, 6).join('; ')}${unsupported.length > 6 ? ' …' : ''}`,
    }
  }
  return null
}

/** SMD-004：排名诱导语（超级latives/权威伪装/替代话术/中文诱导） */
function checkLures(manifest: SkillManifest): SkillMetaFinding | null {
  const text = [manifest.name, manifest.description ?? '', ...(manifest.tags ?? [])].join(' ')
  for (const { re, label } of LURE_PATTERNS) {
    const m = text.match(re)
    if (m) {
      return {
        ruleId: 'SMD-004',
        reason: `选择阶段排名诱导（${label}）：措辞功能是诱导 agent 在候选中选它，而非描述能力本身`,
        action: 'block',
        evidence: m[0].slice(0, 120),
      }
    }
  }
  return null
}

// ── 对外 API ────────────────────────────────────────────

/** 静态扫描：SMD-001~004（SMD-005 需要版本历史，见 analyzeSkillChurn） */
export function scanSkillMeta(manifest: SkillManifest): SkillMetaFinding[] {
  const findings: SkillMetaFinding[] = []
  const supported = contentTerms(manifest.content)
  const f1 = checkStuffing(manifest, supported)
  if (f1) findings.push(f1)
  const f2 = checkSaturation(manifest)
  if (f2) findings.push(f2)
  const f3 = checkOverclaim(manifest, supported)
  if (f3) findings.push(f3)
  const f4 = checkLures(manifest)
  if (f4) findings.push(f4)
  return findings
}

/**
 * SMD-005：元数据震荡分析。窗口内元数据反复变更而内容 hash 恒定
 * = 黑盒竞争反馈调参痕迹（攻击者按检索排名反馈迭代优化恶意元数据）。
 */
export function analyzeSkillChurn(
  entries: SkillChurnEntry[],
  opts: { windowMs?: number; threshold?: number; now?: number } = {},
): SkillMetaFinding | null {
  const { windowMs = CHURN_WINDOW_MS, threshold = CHURN_THRESHOLD, now = Date.now() } = opts
  const recent = entries.filter((e) => now - e.ts <= windowMs)
  if (recent.length < threshold) return null
  const metas = new Set(recent.map((e) => e.metaHash))
  const contents = new Set(recent.map((e) => e.contentHash))
  if (metas.size >= threshold && contents.size === 1) {
    return {
      ruleId: 'SMD-005',
      reason: `元数据震荡：窗口内 ${metas.size} 个不同元数据版本而内容恒定不变——代码冻结、检索字段反复调参是黑盒竞争反馈优化的痕迹`,
      action: 'block',
      evidence: `${recent.length} 次观测 / ${metas.size} 个元数据版本 / 1 个内容版本`,
    }
  }
  return null
}
