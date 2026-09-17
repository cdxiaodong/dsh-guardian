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
export type SkillAction = 'deny' | 'block';
export interface SkillRule {
    id: string;
    reason: string;
    action: SkillAction;
    pattern: RegExp;
}
export interface SkillHit {
    ruleId: string;
    reason: string;
    action: SkillAction;
    /** 命中证据（截断，避免审计日志膨胀） */
    match: string;
}
export interface SkillVerdict {
    safe: boolean;
    target: string;
    /** isSkillSurface=false 时为空：目标根本不是技能面文件，不适用本引擎 */
    isSkillSurface: boolean;
    hits: SkillHit[];
    reason?: string;
}
/**
 * 受保护的信任载入面（对路径做小写归一后匹配）。
 * 注意树形模式覆盖目录内的一切文件——SKILL.md 本体 + 辅助脚本 + 清单：
 * SkillJect 实证 payload 藏在辅助脚本，SKILL.md 只是引信。
 */
export declare const SKILL_SURFACES: RegExp[];
/** 判定一个路径是否落在信任载入面上 */
export declare function isSkillSurface(target: unknown): boolean;
export declare function extractSkillTargets(text: string): string[];
export declare const SKILL_RULES: SkillRule[];
/**
 * 对将写入信任载入面的内容做投毒扫描。
 * 纯函数、零网络零模型、无状态可并发。
 */
export declare function scanSkillContent(text: string): SkillHit[];
/** 命中集合中最严动作 */
export declare function worstSkillAction(hits: SkillHit[]): SkillAction | null;
/** 合并多来源命中：按 ruleId 去重但保留最严动作（deny > block——对抗审查：
 *  首见去重曾让诱饵字段的 SKL-003:block 掩埋真外泄字段的 SKL-003:deny）+ 截断 */
export declare function mergeSkillHits(hits: SkillHit[]): SkillHit[];
/** 深度上限：远超常规工具调用参数嵌套（对齐 engine-26 tokenizer 的 512 量级） */
export declare const SKILL_PAYLOAD_MAX_DEPTH = 512;
/**
 * 聚合扫描工具调用载荷：对象形态逐字段取「解码后的字符串原值」分别过内容
 * 规则——check() 把对象 stringify 后换行会变成字面 \n 转义，frontmatter
 * 定界与同行配对窗口在转义文本上全部失明；字符串原值才是写入内容的真实
 * 形态。字符串载荷按纯文本扫，若内容本身是 JSON 文本（宿主预序列化）则再
 * parse 出字段原值补扫——两种宿主形态闭环。循环引用安全；深度耗尽产出
 * SKL-013 block 上报而非静默（fail-safe）。
 */
export declare function scanSkillPayload(payload: unknown, depth?: number, seen?: Set<unknown>): SkillHit[];
/**
 * 从载荷的「解码后字符串原值」中提取技能面目标（闸门用——对抗审查：预序列化
 * JSON 字符串里 \uXXXX 转义的路径、Windows 反斜杠路径经 JSON.stringify 双写
 * 后，原始文本提取整体失明，引擎在扫描内容前就放行）。原始文本提取结果
 * 一并合并去重。
 */
export declare function collectSkillTargets(payload: unknown, text: string): string[];
/**
 * 反转义 stringify 文本（接线层兜底扫描用）：把字面 \n / \r / \t / \\uXXXX /
 * \\/ 折叠回真实字符，使 frontmatter 定界与行窗口在「对象 stringify 文本」
 * 上不再结构性失明。启发式（不追求完美还原，漏还原只影响兜底通道——
 * 字段原值通道才是主路径）。
 */
export declare function unescapeJsonText(text: string): string;
/**
 * 写时判定：目标是否技能面 + 内容是否带毒。
 * 干净 → safe:true；非技能面 → isSkillSurface:false 直接放行。
 */
export declare function guardSkillWrite(target: string, content: string): SkillVerdict;
/**
 * 扫 shell 命令串对技能面的写入/变更：命中 SKL-012（block——命令串不是最终
 * 文件内容，结构化检视不可能，人工确认是唯一严谨处置）。命中写入动词、或
 * 命令含内容载体（echo/printf/heredoc/tee）时，命令串载荷过内容规则——
 * 动词黑名单永远不全，载体存在就绝不放过内嵌的 deny 级证据；纯读命令
 * （cat/grep/ls）不做内容扫描，避免「grep 恶意特征样本」的维护命令误报
 * （对抗审查两侧教训的折中）。
 */
export declare function scanShellSkillWrite(command: string): SkillHit[];
