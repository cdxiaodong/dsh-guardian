/**
 * 技能投毒守卫（Skill Poisoning Guard）—— engine-27
 *
 * 威胁模型（2026 实证研究链）：
 * Agent harness 的「信任载入面」——skills / commands / subagents 定义文件——写入时
 * 人畜无害（就是普通文本文件），载入时却以高权限进上下文，甚至先于模型可见性执行：
 *
 *   - Datadog Security Labs《Malicious Coding Agent Skills and the Risk of Dynamic
 *     Context》(2026-05-11, Frichette & Simon)：Claude Code 技能体内的 `!`+反引号
 *     标记在技能「载入/渲染」时由 harness 预执行，输出替换占位符后模型只看到渲染
 *     结果——命令本体模型永远看不见。PoC：`!`+反引号包裹 gh auth token 与
 *     curl --data-binary 上传，配合 frontmatter 的 allowed-tools: Bash(*)。
 *     官方修复开关 disableSkillShellExecution。本引擎的卡位推理：预执行发生在
 *     harness 内部、不产生工具调用事件，写入层是唯一能确定性拦截的位置
 *     （这是本仓库的分析，非原文表述）。
 *   - Snyk ToxicSkills (2026-02-05)：扫描 ClawHub/skills.sh 3,984 个技能，确认 76 个
 *     恶意 payload（1,467 个即 36.82% 存在任意安全问题，534 个 critical）。payload
 *     家族：base64+curl 外泄 ~/.aws/credentials、curl|bash 投放恶意件、
 *     「curl .../instructions.md | source」远程指令装载、base64/Unicode/ASCII 走私
 *     隐藏指令。金样本 snyk-labs/toxicskills-goof（假 Vercel 技能外泄系统信息）。
 *   - SkillJect（arXiv 2602.14211）：首个自动化技能投毒框架——payload 藏在技能
 *     目录的辅助脚本（artifact 通道），SKILL.md 本体只负责诱导与路径引用
 *     （instruction 通道）→ 检测面必须是整棵技能目录树，不能只盯 SKILL.md。
 *   - Reversec Labs《Skill Issues》(2026-05/06 两部)：Claude Code 技能/命令/子代理
 *     文件作为初始访问面；Part 2 演示 SSH/AWS 凭据外泄与经链式恶意技能/子代理的
 *     代码后门。
 *
 * 两条卡位（对应 check() 接线的两条路径）：
 *   1. 写时内容判定 guardSkillWrite()：写入目标命中技能面 → 写入内容跑 SKL 规则
 *   2. Shell 绕过路由 scanShellSkillWrite()：技能面若经 shell 重定向/tee/cp/
 *      heredoc/sed -i 写入（绕过结构化写工具的路径路由），命令本身即证据
 *      （SKL-012），命令串内嵌的写入内容（echo/heredoc）照样过内容规则
 *
 * 与既有引擎的分工：
 *   - memory-guard（engine-24）盯「认知上下文文件」（CLAUDE.md/AGENTS.md/
 *     settings.json/memory 目录），模式清单与技能树无交集；本引擎盯
 *     skills/commands/agents 树——SKILL.md 既不是规则文件也不是记忆
 *   - tool-poisoning（engine-15）验毒对象是 MCP 工具注册时的描述文本；
 *     本引擎是文件写入时点的技能/命令/子代理定义文件
 *   - sentinel-self-guard（engine-25）防护栏自身资产被拆；本引擎保护宿主的
 *     信任载入面（用户的技能资产）
 *   - tool-integrity（engine-11）pin 工具 schema 指纹；本引擎管文件内容
 *   - rule 引擎在运行时点扫工具调用文本；本引擎在写入时点扫「将成为下次载入
 *     的信任内容」——恶意技能入库那一刻拦截，而不是等它被载入或预执行
 *
 * 诚实边界：
 *   1. `!`+反引号预执行（SKL-001/002）目前实证于 Claude Code 技能体；其他 harness
 *      未见同样语法——按语法命中（保守处置），「讨论该语法的安全研究文档」写入
 *      技能面时会触发；自然语句句尾感叹号+行内代码（"Great job! `cmd`"）同样
 *      命中 SKL-002 block——宽松匹配是防空格混淆变体绕过的代价
 *   2. frontmatter 投毒检测是短语级的——LLM 流畅改写可绕过（确定性引擎固有边界）；
 *      动态上下文预执行、外泄链配对等结构性信号不受措辞影响
 *   3. 通用 skills/<名>/SKILL.md 模式可能匹配非 Agent 仓库的同名目录——命中做
 *      完整内容判定（deny 级结构性证据维持 deny，在哪都一样），误报成本为
 *      拦截+人工排查；带 .claude/.codex 前缀的路径才是高置信技能面
 *   4. git clone / 包管理器整树落盘的技能不产生工具调用——SKL-012 要求宿主把
 *      shell 命令也过 guardian/check 才能覆盖（尽力而为的兜底）
 *   5. 辅助脚本「干净入库、运行时组合作恶」超出静态写入扫描能力（kill-chain
 *      engine-10 与 rule 引擎的运行时职责）；带外泄链形状的脚本内容在写入时
 *      仍会被 SKL-003/004 命中
 *   6. SKL-003 的跨行还原只覆盖「VAR=值 直接赋值 + $VAR 引用」形态；间接赋值
 *      （B=$A）与命令替换组合靠行窗口与运行时引擎兜底
 *   7. shell 卡位的内容扫描仅在命中写入动词或存在内容载体（echo/printf/
 *      heredoc/tee）时进行——纯读命令（grep 恶意特征样本的维护操作）不误报
 *      的代价：未知写入动词且无载体的命令只受 SKL-012 动词判定约束
 */

/** 检出处置级别：deny=直接拒；block=人工确认 */
export type SkillAction = 'deny' | 'block'

export interface SkillRule {
  id: string
  reason: string
  action: SkillAction
  pattern: RegExp
}

export interface SkillHit {
  ruleId: string
  reason: string
  action: SkillAction
  /** 命中证据（截断，避免审计日志膨胀） */
  match: string
}

export interface SkillVerdict {
  safe: boolean
  target: string
  /** isSkillSurface=false 时为空：目标根本不是技能面文件，不适用本引擎 */
  isSkillSurface: boolean
  hits: SkillHit[]
  reason?: string
}

// ── 特殊字符运行时构造（源文件零 \uXXXX 字面转义——规避写入层转义损坏）──

const chr = (cp: number) => String.fromCharCode(cp)
const chp = (cp: number) => String.fromCodePoint(cp)

/**
 * 不可见字符类源与 Unicode Tags 区（U+E0000–U+E007F，agent 领域实证的隐形
 * 指令载体，engine-15 显影过）合并为单一字符类：Tags 是 astral 区间，必须整体
 * 以 /u 标志编译，拆开重编（如丢掉 /u）会让代理对范围乱序。
 * C0 段豁免 \t \n \r（0x09/0x0A/0x0D）——本引擎扫的是整份文件内容（engine-26
 * 的 ARG-006 只查键名故可含全 C0），markdown 的合法排版空白不算隐写。
 */
const STEALTH_CHARS_CLASS =
  chr(0x00) + '-' + chr(0x08) + chr(0x0b) + chr(0x0c) + chr(0x0e) + '-' + chr(0x1f)
  + chr(0x7f) + '-' + chr(0x9f)
  + chr(0xad) + chr(0x61c) + chr(0x180e)
  + chr(0x200b) + '-' + chr(0x200f)
  + chr(0x2028) + chr(0x2029)
  + chr(0x202a) + '-' + chr(0x202e)
  + chr(0x2060) + '-' + chr(0x2069)
  + chr(0xfeff)
  + chp(0xe0000) + '-' + chp(0xe007f)
const STEALTH_CHARS_RE = new RegExp('[' + STEALTH_CHARS_CLASS + ']', 'u')

// ── 技能面路径识别 ────────────────────────────────────────────

/**
 * 受保护的信任载入面（对路径做小写归一后匹配）。
 * 注意树形模式覆盖目录内的一切文件——SKILL.md 本体 + 辅助脚本 + 清单：
 * SkillJect 实证 payload 藏在辅助脚本，SKILL.md 只是引信。
 */
export const SKILL_SURFACES: RegExp[] = [
  // Claude 系技能树（含目录本身——rm -rf 整棵树也是信任面变更）
  /(^|[\/\\])\.claude[\/\\]skills(?:[\/\\].*)?$/i,
  // 插件市场安装的技能树（.claude/plugins/<市场>/skills/...）
  /(^|[\/\\])\.claude[\/\\]plugins[\/\\][^\/\\]+[\/\\]skills(?:[\/\\].*)?$/i,
  // slash 命令与子代理/输出样式定义（Reversec Skill Issues 的信任载入面）
  /(^|[\/\\])\.claude[\/\\](commands|agents|output-styles)[\/\\].+$/i,
  // Codex 系技能/提示词/子代理
  /(^|[\/\\])\.codex[\/\\](skills|prompts|agents)[\/\\].+$/i,
  // 通用技能目录（无 harness 前缀——诚实边界 3：命中只到内容扫描，block 级兜底）
  /(^|[\/\\])skills?[\/\\][^\/\\]+[\/\\]SKILL\.md$/i,
  // 任何位置的 SKILL.md 本体（文件名即语义）
  /(^|[\/\\])SKILL\.md$/i,
]

/** 判定一个路径是否落在信任载入面上 */
export function isSkillSurface(target: unknown): boolean {
  if (!target || typeof target !== 'string') return false
  const normalized = target.replace(/\\/g, '/')
  return SKILL_SURFACES.some((p) => p.test(normalized))
}

/** 从工具调用文本中提取路径样 token（多段路径或裸 SKILL.md，保留前导 /），过滤出技能面 */
const PATH_TOKEN_RE = /[~.@\w$+-]*(?:[\/\\][~.@\w$+-]+)+|SKILL\.md/gi
export function extractSkillTargets(text: string): string[] {
  if (!text || typeof text !== 'string') return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const tok of text.match(PATH_TOKEN_RE) ?? []) {
    if (!seen.has(tok) && isSkillSurface(tok)) {
      seen.add(tok)
      out.push(tok)
    }
  }
  return out
}

// ── SKL-001/002：动态上下文预执行标记（Datadog 实证语法）─────────

/**
 * `!`+反引号：技能载入时由 harness 预执行，模型看不到命令本体。
 * 感叹号与反引号间只容空白（不含换行——跨行命中无实证支撑且误报面最大，
 * 对抗审查修正）；捕获体上限 300 字符，超长/未闭合由 scanDynamicContext
 * 的兜底分支降级 SKL-002 block（fail-safe：长度上限绝不能变成失明）。
 */
const BANG_BACKTICK_RE = /![ \t]{0,8}`([^`\n]{1,300})`/g
/** 兜底探针：行内存在 `!`+反引号开启标记（无论是否闭合/超长） */
const BANG_BACKTICK_OPEN_RE = /![ \t]{0,8}`/g
/** 预执行命令的危险形状（网络/凭据/管道执行/提权——ToxicSkills payload 家族） */
const DYNAMIC_EXEC_DANGER_RE = /\b(curl|wget|nc|netcat|base64|openssl|printenv|env|eval|chmod|xargs|scp|rsync|dd|python3?|node|ruby|perl)\b|\bgh\s+auth\b|\b(tokens?|id_rsa|id_ed25519|authorized_keys|known_hosts|credentials?|secrets?|keychain|shadow|history)\b|~\/\.ssh|\.aws\b|\/dev\/tcp|\|\s*(ba|z|fi|da|k)?sh\b|>>/i

function scanDynamicContext(text: string, hits: SkillHit[]): void {
  BANG_BACKTICK_RE.lastIndex = 0
  let closed = 0
  let m: RegExpExecArray | null
  while ((m = BANG_BACKTICK_RE.exec(text)) !== null) {
    closed++
    const frag = m[0]
    if (DYNAMIC_EXEC_DANGER_RE.test(m[1])) {
      hits.push({
        ruleId: 'SKL-001',
        reason: '技能投毒：动态上下文预执行标记携带危险命令——载入时由 harness 执行、模型看不到命令本体（Datadog 2026-05 实证语法）',
        action: 'deny',
        match: frag.slice(0, 160),
      })
    } else {
      hits.push({
        ruleId: 'SKL-002',
        reason: '技能投毒：动态上下文预执行标记（载入时由 harness 执行）——命令形状未见危险特征，人工确认',
        action: 'block',
        match: frag.slice(0, 160),
      })
    }
  }
  // fail-safe 兜底：开启标记多于闭合匹配 = 存在未闭合/超长（>300）标记——
  // padding 绕过的实测形态（对抗审查：301 字符即 deny/block 双失明），降级 block
  BANG_BACKTICK_OPEN_RE.lastIndex = 0
  const opened = (text.match(BANG_BACKTICK_OPEN_RE) ?? []).length
  if (opened > closed) {
    hits.push({
      ruleId: 'SKL-002',
      reason: `技能投毒：存在未闭合或超长（>300 字符）的动态上下文预执行标记（${opened - closed} 处）——无法检视命令体，按能力存在处置`,
      action: 'block',
      match: '（标记开启但命令体超出可检视范围——常见于注释 padding 绕过）',
    })
  }
}

// ── SKL-003：凭据源 ↔ 出网口 配对（ToxicSkills 主 payload 家族）──

/**
 * 敏感凭据源（文件/路径形态——不含泛指的 env 变量，控制误报）。
 * .env 用环视独立成文件名（排除 .env.example/.env.sample 前缀误配——
 * 对抗审查实测 'cp .env.example .env' 曾整行误配敏感源）。
 */
const SENSITIVE_SOURCE_RE = /(~\/\.ssh|\.\/\.ssh|id_rsa|id_ed25519|\.aws\b|\.gnupg|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker\/config|\.config\/gcloud|kubeconfig|\.azure\b|Library\/Keychains|(?<![\w.-])\.env(?![\w.-])|credentials\b|\.pgpass|cookies\.(sqlite|txt|db)|(?<!\w)passwords?\.txt(?!\w)|secrets?\.(md|txt|json|ya?ml))/i
/** 出网口（命令或参数形态） */
const EGRESS_RE = /\b(curl|wget|nc|netcat|ssh|scp|rsync|ftp|telnet|socat)\b|openssl\s+s_client|-connect\b|\bgh\s+(api|auth)\b|aws\s+s3\s+cp|--data(-binary)?\b|--upload-file\b|-T\s|pastebin|webhook|https?:\/\/|\/dev\/tcp/i
/**
 * 链式耦合：管道/重定向/命令替换，或凭据作为传输参数（--data @file）。
 * 不含分号与裸反引号（对抗审查：git-clone 与散文标点的 deny 级误报源）。
 */
const COUPLED_RE = /(\||>|<|\$\()|--data|--upload-file|-T\s/

/**
 * 变量赋值收集：VAR=<值> 的值命中敏感源 → 变量名入敏感集（跨行组合外泄的
 * 还原——对抗审查实测 'A=~/.passwords.txt; curl --data-binary @$A' 三行拆分
 * 曾整体绕过行窗口）。
 */
function collectSensitiveVars(lines: string[]): Set<string> {
  const vars = new Set<string>()
  const assignRe = /([A-Za-z_]\w*)=(\S+)/g
  for (const line of lines) {
    assignRe.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = assignRe.exec(line)) !== null) {
      if (SENSITIVE_SOURCE_RE.test(m[2])) vars.add(m[1])
    }
  }
  return vars
}

function scanExfilPairing(text: string, hits: SkillHit[]): void {
  const lines = text.split(/[\n\r]+/)
  const sensitiveVars = collectSensitiveVars(lines)
  for (const line of lines) {
    const referencesSensitiveVar = [...sensitiveVars].some((v) => line.includes('$' + v) || line.includes('${' + v + '}'))
    const hasSensitive = SENSITIVE_SOURCE_RE.test(line) || referencesSensitiveVar
    if (!hasSensitive || !EGRESS_RE.test(line)) continue
    if (COUPLED_RE.test(line)) {
      hits.push({
        ruleId: 'SKL-003',
        reason: referencesSensitiveVar && !SENSITIVE_SOURCE_RE.test(line)
          ? '技能投毒：经变量引用组合的凭据外泄链（敏感值经 VAR= 赋值走私、出网行只留 $VAR 引用——行窗口还原）'
          : '技能投毒：凭据源与出网口链式耦合——ToxicSkills 实证的主 payload 家族（读密钥文件并上传）',
        action: 'deny',
        match: line.slice(0, 160),
      })
    } else {
      hits.push({
        ruleId: 'SKL-003',
        reason: '技能投毒：同一行内同时出现凭据源与出网口动词（未见链式耦合，人工确认）',
        action: 'block',
        match: line.slice(0, 160),
      })
    }
  }
}

// ── SKL-006/007/008：frontmatter 元数据投毒 ────────────────────

/**
 * frontmatter 是技能的「门面」：name/description 会被 harness 索引进上下文
 * （即使技能从未被调用），allowed-tools 直接决定预授权范围——元数据投毒
 * 是零调用的持久注入通道。
 *
 * 窗口策略（fail-safe，防填充绕过）：闭合的 frontmatter（≤8000 字符内找到
 * 结束标记）只扫块内；未闭合或超长（>8000 仍无结束标记）则把整个文件当
 * frontmatter 扫——固定窗口本身就是「填充噪音把投毒行推出扫描窗口」的
 * 绕过面，宁可多扫（block/deny 级误报可控）不可漏扫。
 */
/**
 * SKL-006 硬信号：无合法用途的指令劫持/外泄语义 → deny。
 * 扫描对象是全文而非仅 frontmatter——edit 类工具的片段写入（new_string 只含
 * 「description: exfiltrate ...」一行，无 --- 定界）也必须命中（对抗审查：
 * 片段形态曾整体失明）。硬信号短语在技能任何位置出现都是 deny 级证据。
 */
const FM_HARD_RE = /\bexfiltrat\w*|\bsystem\s+prompts?\b|\byou\s+are\s+now\b|\bacting\s+as\s+if\b|\bnew\s+(instructions?|rules?|directives?)\s*[:：]|\bdeveloper\s+messages?\b|\bsend\w*\b[^.\n]{0,40}\b(env(ironment)?\s+vars?|secrets?|tokens?|credentials?)\b/i
/** frontmatter 软信号：劫持既有指令体系的措辞（格式类描述也可能用到）→ block。
 *  动词用词干+\w* 吸收屈折（ignores/ignored/disregarded/forgotten/Overrides……
 *  \boverride\b 匹配不了第三人称单数——engine-24 MEM-001 的已知脆性，此处修正） */
const FM_SOFT_RE = /\b(ignor\w*|disregard\w*|forg\w*|overrid\w*|supersed\w*|replac\w*)\b[^.\n]{0,80}\b(all\s+)?(previous|prior|above|earlier|existing|current|other)?\s*(instructions?|rules?|guidelines?|directives?|policies?|prompts?|constraints?)\b/i
/** 危险工具通配授权（Datadog PoC 的 allowed-tools: Bash(*)）→ block */
const FM_WILD_TOOLS_RE = /^allowed[-_ ]?tools?\s*:[^\n]{0,300}\b(bash|sh|shell|write|edit|webfetch|execute?|command)s?\b[^\n]{0,40}(\(\s*\*\s*\)|:\s*\*\s*\))/mi

/**
 * frontmatter 是技能的「门面」：name/description 会被 harness 索引进上下文
 * （即使技能从未被调用），allowed-tools 直接决定预授权范围——元数据投毒
 * 是零调用的持久注入通道。
 *
 * 窗口策略（fail-safe，防填充绕过）：闭合的 frontmatter（≤8000 字符内找到
 * 结束标记）只扫块内；未闭合或超长（>8000 仍无结束标记）则把整个文件当
 * frontmatter 扫——固定窗口本身就是「填充噪音把投毒行推出扫描窗口」的
 * 绕过面，宁可多扫（block/deny 级误报可控）不可漏扫。
 */
function scanFrontmatter(text: string, hits: SkillHit[]): void {
  let body = text
  const bom = chp(0xfeff)
  if (body.startsWith(bom)) body = body.slice(bom.length)
  if (!/^---[ \t]*\r?\n/.test(body)) return
  const capped = body.slice(0, 8000)
  const close = /\r?\n---(?:[ \t]*\r?\n|$)/.exec(capped)
  const fm = close ? capped.slice(0, close.index) : body

  const soft = FM_SOFT_RE.exec(fm)
  if (soft) {
    hits.push({ ruleId: 'SKL-007', reason: '技能投毒：frontmatter 描述含劫持既有指令体系的措辞（技能描述会常驻上下文，人工确认）', action: 'block', match: soft[0].slice(0, 160) })
  }
  const wild = FM_WILD_TOOLS_RE.exec(fm)
  if (wild) {
    hits.push({ ruleId: 'SKL-008', reason: '技能投毒：frontmatter 申请危险工具通配授权（allowed-tools 含 Bash/Write 类 * 通配——预授权面过大）', action: 'block', match: wild[0].slice(0, 160) })
  }
}

// ── 静态规则表（正文级）────────────────────────────────────────

function alt(...parts: RegExp[]): RegExp {
  return new RegExp(parts.map((p) => p.source).join('|'), 'i')
}

/**
 * SKL-004：远程指令/代码装载（curl|sh、instructions.md|source——ToxicSkills
 * 实证家族）。p3 的重定向尾巴用 (?<!=) 排除 JS 箭头函数 =>（对抗审查：
 * fetch('/api/rules.json').then(r => r.json()) 曾整行误报 deny）；p4 补
 * 「解释器 -c/-e + 取回 + 执行」形状（python urllib + exec 等不依赖下载动词
 * 白名单的装载器）；p5 二次跳转（curl 落盘临时路径 + 解释器执行）。
 */
const REMOTE_LOAD_RE = alt(
  /\b(curl|wget|fetch|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,240}\|[^|\n]{0,60}(ba|z|fi|da|k)?sh\b/,
  /\b(curl|wget|fetch)\b[^|\n]{0,200}\|\s*source\b/,
  /\b(curl|wget)\b[^|\n]{0,200}(instructions?|prompts?|rules?|persona|policy|system)\.(md|txt|ya?ml|json|toml)[^|\n]{0,80}(\||(?<!=)>>?|source\b)/,
  /\b(python3?|node|ruby|perl|pwsh)\b[^|\n]{0,60}\s-[ce]\b(?=[^|\n]{0,600}(urlopen|requests?\.get|https?:\/\/|fetch\(|DownloadString|Net::HTTP))(?=[^|\n]{0,800}(exec|eval\s*\(|system\s*\(|spawn|Invoke-Expression|child_process))/,
  /\bsource\s+<\(/,
)

/** 二次跳转探针（跨行组合，scanSkillContent 内做两遍判定） */
const TMP_DROP_RE = /\b(curl|wget)\b[^>\n]{0,200}>\s*(\/tmp\/|\/dev\/shm\/|\.\.?\/)/i
const TMP_EXEC_RE = /\b(python3?|node|ruby|perl|(ba|z|fi|da|k)?sh)\b[^;|\n]{0,40}\s(\/tmp\/|\/dev\/shm\/|\.\.?\/)\S*/i

/** SKL-009：护栏禁用/反审计指令（与 engine-24 MEM-006 同族，技能面版本；动词带屈折词干） */
const ANTI_GUARDIAN_RE = /\b(disabl\w*|remov\w*|delet\w*|uninstall\w*|turn\s+off|deactivat\w*|bypas\w*|tamper\w*|weaken\w*|neutraliz\w*|monkey-?patch\w*)\b[^.\n]{0,80}\b(guardians?|dsh-guardian|guardrails?|sentinels?|sandbox(es)?|security\s+checks?|permission\s+checks?|approvals?|protected\s+hooks?|hooks?\s+configuration|settings\.json)\b/i

/** SKL-010：隐蔽性指令（瞒用户/事后销毁——注入落地的标准配套；动词带屈折词干） */
const STEALTH_RE = /\b(hid\w*|conceal\w*|obfuscat\w+)\b[^.\n]{0,80}\bfrom\s+the\s+user\b|without\s+(the\s+)?user'?s?\s*(knowledge|consent|awareness|approval|noticing)|\bsecretly\b|\b(never|do\s?n[o']?t)\s+(show|display|print|reveal|mention|disclose|tell)\b[^.\n]{0,80}\b(the\s+)?user\b|\bdelet\w*\s+(this|the)\s+(file|skill|directory|script)\b[^.\n]{0,80}\b(after|once|when)\b/i

/** SKL-011：向信任载入面写入/传播的指令（Reversec Part-2 链式后门形态）。
 *  间隙量词不设上限（[^;|\n] 已排除命令分隔符——上限只会制造 padding 绕过面） */
const TRUST_PROPAGATION_RE = alt(
  /\b(cp|mv|rsync|tee|install|dd|truncate|ln)\b[^;|\n]*[\w~.@-]*(\.claude|\.codex)[\/\\][^;|\n]*(skills?|commands?|agents?|settings|hooks?|CLAUDE\.md|AGENTS?\.md)/,
  /\b(writ\w*|creat\w*|overwrit\w*|replac\w*|append(?:ing)?\s+to|sav\w*)\b[^;|\n]*[\w~.@-]*(\.claude|\.codex)[\/\\][^;|\n]*(skills?|commands?|agents?|settings|hooks?)/,
  /(>>?|tee\b)[^;\n]*[\w~.@-]*(\.claude|\.codex)[\/\\][^;\n]*(skills?|commands?|agents?|settings|hooks?|CLAUDE\.md)/,
)

export const SKILL_RULES: SkillRule[] = [
  { id: 'SKL-004', action: 'deny', pattern: REMOTE_LOAD_RE, reason: '技能投毒：远程指令/代码装载（下载即执行——入库时是文本，调用时是代码）' },
  { id: 'SKL-005', action: 'deny', pattern: STEALTH_CHARS_RE, reason: '技能投毒：不可见字符（零宽/双向控制/C0/Unicode Tags）——人不可见、模型可读的隐写指令载体' },
  { id: 'SKL-009', action: 'deny', pattern: ANTI_GUARDIAN_RE, reason: '技能投毒：禁用/破坏安全护栏的持久指令（技能每会话高权限加载）' },
  { id: 'SKL-010', action: 'deny', pattern: STEALTH_RE, reason: '技能投毒：隐蔽性指令（对用户隐瞒行为/事后销毁证据）' },
  { id: 'SKL-011', action: 'block', pattern: TRUST_PROPAGATION_RE, reason: '技能投毒：指示向信任载入面写入/传播（技能装技能——链式后门的植入形态，人工确认）' },
]

// ── 内容扫描入口 ──────────────────────────────────────────────

/**
 * 对将写入信任载入面的内容做投毒扫描。
 * 纯函数、零网络零模型、无状态可并发。
 */
export function scanSkillContent(text: string): SkillHit[] {
  if (!text || typeof text !== 'string') return []
  const hits: SkillHit[] = []
  scanDynamicContext(text, hits)
  scanExfilPairing(text, hits)
  // SKL-006 硬信号扫全文（含无 frontmatter 定界的 edit 片段形态）
  const hard = FM_HARD_RE.exec(text)
  if (hard) {
    hits.push({ ruleId: 'SKL-006', reason: '技能投毒：硬信号语义（外泄/系统提示词/角色替换）——技能任何位置出现都是 deny 级证据（含元数据片段写入）', action: 'deny', match: hard[0].slice(0, 160) })
  }
  scanFrontmatter(text, hits)
  for (const rule of SKILL_RULES) {
    rule.pattern.lastIndex = 0
    const m = rule.pattern.exec(text)
    if (m) {
      hits.push({ ruleId: rule.id, reason: rule.reason, action: rule.action, match: m[0].slice(0, 160) })
    }
  }
  // SKL-004 二次跳转（跨行组合：下载落盘临时路径 + 解释器执行该路径）
  if (TMP_DROP_RE.test(text) && TMP_EXEC_RE.test(text)) {
    hits.push({ ruleId: 'SKL-004', reason: '技能投毒：远程代码二次跳转装载（下载落盘临时路径后由解释器执行）', action: 'deny', match: 'curl/wget → 临时路径 → 解释器执行'.slice(0, 160) })
  }
  return worstFirst(hits)
}

/** deny 优先 + 截断（对抗审查教训：block 噪声不能掩埋 deny 证据；上限防审计炸弹） */
function worstFirst(hits: SkillHit[]): SkillHit[] {
  const denies = hits.filter((h) => h.action === 'deny').slice(0, 25)
  const blocks = hits.filter((h) => h.action === 'block').slice(0, 25)
  return [...denies, ...blocks]
}

/** 命中集合中最严动作 */
export function worstSkillAction(hits: SkillHit[]): SkillAction | null {
  if (hits.some((h) => h.action === 'deny')) return 'deny'
  if (hits.some((h) => h.action === 'block')) return 'block'
  return null
}

/** 合并多来源命中：按 ruleId 去重但保留最严动作（deny > block——对抗审查：
 *  首见去重曾让诱饵字段的 SKL-003:block 掩埋真外泄字段的 SKL-003:deny）+ 截断 */
export function mergeSkillHits(hits: SkillHit[]): SkillHit[] {
  const byId = new Map<string, SkillHit>()
  for (const h of hits) {
    const prev = byId.get(h.ruleId)
    if (!prev || (prev.action !== 'deny' && h.action === 'deny')) byId.set(h.ruleId, h)
  }
  return worstFirst([...byId.values()])
}

/** 深度上限：远超常规工具调用参数嵌套（对齐 engine-26 tokenizer 的 512 量级） */
export const SKILL_PAYLOAD_MAX_DEPTH = 512

/** 深度耗尽的 fail-safe 合成命中（block——「扫不完」绝不静默，ARG-007 同型） */
function depthExhausted(depth: number): SkillHit {
  return {
    ruleId: 'SKL-013',
    reason: `结构降级：载荷嵌套深度达 ${depth}，无法完整扫描——已知技能面写入且形状不可扫，走人工确认`,
    action: 'block',
    match: `depth=${depth}`,
  }
}

/**
 * 聚合扫描工具调用载荷：对象形态逐字段取「解码后的字符串原值」分别过内容
 * 规则——check() 把对象 stringify 后换行会变成字面 \n 转义，frontmatter
 * 定界与同行配对窗口在转义文本上全部失明；字符串原值才是写入内容的真实
 * 形态。字符串载荷按纯文本扫，若内容本身是 JSON 文本（宿主预序列化）则再
 * parse 出字段原值补扫——两种宿主形态闭环。循环引用安全；深度耗尽产出
 * SKL-013 block 上报而非静默（fail-safe）。
 */
export function scanSkillPayload(payload: unknown, depth: number = SKILL_PAYLOAD_MAX_DEPTH, seen: Set<unknown> = new Set()): SkillHit[] {
  if (payload === null || payload === undefined) return []
  if (typeof payload === 'string') {
    const hits = scanSkillContent(payload)
    try {
      const parsed: unknown = JSON.parse(payload)
      if (parsed !== null && typeof parsed === 'object') {
        return mergeSkillHits([...hits, ...scanSkillPayload(parsed, depth, seen)])
      }
    } catch { /* 非 JSON 文本：上面已按纯文本扫过，不重试 */ }
    return hits
  }
  if (typeof payload !== 'object') return []
  if (depth === 0) return [depthExhausted(SKILL_PAYLOAD_MAX_DEPTH)]
  if (seen.has(payload)) return []
  seen.add(payload)
  const hits: SkillHit[] = []
  if (Array.isArray(payload)) {
    for (const item of payload) hits.push(...scanSkillPayload(item, depth - 1, seen))
  } else {
    for (const v of Object.values(payload)) hits.push(...scanSkillPayload(v, depth - 1, seen))
  }
  return mergeSkillHits(hits)
}

/**
 * 从载荷的「解码后字符串原值」中提取技能面目标（闸门用——对抗审查：预序列化
 * JSON 字符串里 \uXXXX 转义的路径、Windows 反斜杠路径经 JSON.stringify 双写
 * 后，原始文本提取整体失明，引擎在扫描内容前就放行）。原始文本提取结果
 * 一并合并去重。
 */
export function collectSkillTargets(payload: unknown, text: string): string[] {
  const out = new Set<string>()
  for (const t of extractSkillTargets(text)) out.add(t)
  const walk = (v: unknown, depth: number, seen: Set<unknown>): void => {
    if (v === null || v === undefined) return
    if (typeof v === 'string') {
      for (const t of extractSkillTargets(v)) out.add(t)
      // 字符串本身是 JSON 文本（宿主预序列化）→ parse 出字段原值再提取
      try {
        const parsed: unknown = JSON.parse(v)
        if (parsed !== null && typeof parsed === 'object') walk(parsed, depth, seen)
      } catch { /* 非 JSON 文本 */ }
      return
    }
    if (typeof v !== 'object' || depth === 0) return
    if (seen.has(v)) return
    seen.add(v)
    if (Array.isArray(v)) { for (const item of v) walk(item, depth - 1, seen); return }
    for (const item of Object.values(v)) walk(item, depth - 1, seen)
  }
  walk(payload, SKILL_PAYLOAD_MAX_DEPTH, new Set())
  return [...out]
}

/**
 * 反转义 stringify 文本（接线层兜底扫描用）：把字面 \n / \r / \t / \\uXXXX /
 * \\/ 折叠回真实字符，使 frontmatter 定界与行窗口在「对象 stringify 文本」
 * 上不再结构性失明。启发式（不追求完美还原，漏还原只影响兜底通道——
 * 字段原值通道才是主路径）。
 */
export function unescapeJsonText(text: string): string {
  return text
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\\//g, '/')
    .replace(/\\\\/g, '\\')
}

// ── 写时判定（卡位 1：结构化写工具）──────────────────────────

/**
 * 写时判定：目标是否技能面 + 内容是否带毒。
 * 干净 → safe:true；非技能面 → isSkillSurface:false 直接放行。
 */
export function guardSkillWrite(target: string, content: string): SkillVerdict {
  if (!isSkillSurface(target)) {
    return { safe: true, target, isSkillSurface: false, hits: [] }
  }
  const hits = scanSkillContent(content ?? '')
  if (hits.length) {
    return { safe: false, target, isSkillSurface: true, hits, reason: hits.map((h) => h.reason).join('；').slice(0, 500) }
  }
  return { safe: true, target, isSkillSurface: true, hits: [] }
}

// ── Shell 绕过路由（卡位 2：重定向/heredoc/复制 写入技能面）────

/**
 * shell 写入/变更动词（后接技能面路径 = 绕过结构化写工具的路径路由）。
 * 间隙不设量词上限（[^;|&\n] 已排除命令分隔符——上限是 padding 绕过面）；
 * 动词清单补 git clone / tar -C / unzip -d / 解释器 -c/-e（对抗审查实测
 * 四类写入形态曾全部零命中）。sed 仅匹配带 -i 的原地写形态。
 */
const SHELL_WRITE_FORM = (escapedTarget: string) =>
  new RegExp(
    '(>>?|tee(?:\\s+-[a-z]+)?|\\bcp\\b|\\bmv\\b|\\binstall\\b|\\brsync\\b|\\bln\\b|\\bdd\\b|\\brm\\b|\\brmdir\\b|\\bunlink\\b|\\btruncate\\b'
    + '|\\bgit\\s+clone\\b|\\btar\\b|\\bunzip\\b|\\bgunzip\\b'
    + '|\\b(python3?|node|perl|ruby)\\b[^;&|\\n]{0,60}\\s-[A-Za-z]*[ce]\\b'
    + '|sed\\b[^;&|\\n]*-i'
    + '|<<-?\\s*\\w+)[^;|&\\n]*' + escapedTarget,
    'i',
  )

/**
 * 扫 shell 命令串对技能面的写入/变更：命中 SKL-012（block——命令串不是最终
 * 文件内容，结构化检视不可能，人工确认是唯一严谨处置）。命中写入动词、或
 * 命令含内容载体（echo/printf/heredoc/tee）时，命令串载荷过内容规则——
 * 动词黑名单永远不全，载体存在就绝不放过内嵌的 deny 级证据；纯读命令
 * （cat/grep/ls）不做内容扫描，避免「grep 恶意特征样本」的维护命令误报
 * （对抗审查两侧教训的折中）。
 */
export function scanShellSkillWrite(command: string): SkillHit[] {
  if (!command || typeof command !== 'string') return []
  const targets = extractSkillTargets(command)
  if (!targets.length) return []
  const hits: SkillHit[] = []
  for (const t of targets) {
    const esc = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const form = SHELL_WRITE_FORM(esc)
    const m = form.exec(command)
    if (m) {
      hits.push({
        ruleId: 'SKL-012',
        reason: `技能面经 shell 写入/变更：${t}——绕过结构化写工具的路径路由，内嵌内容已另行按内容规则扫描`,
        action: 'block',
        match: m[0].slice(0, 160),
      })
    }
  }
  const carriesContent = hits.length > 0 || /\becho\b|\bprintf\b|<<|\btee\b/.test(command)
  if (carriesContent) hits.push(...scanSkillContent(command))
  return mergeSkillHits(hits)
}
