import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { fileURLToPath } from 'node:url'

/**
 * 哨兵引擎（Self-Guard Anti-Tamper + Anti-Forensics）—— engine-25
 *
 * 威胁模型：24 个检测引擎全部隐含一个公理——「护栏自身还活着」。
 * 但护栏自身就是可攻击资产：
 *   - 删/截断审计日志（~/.dsh-guardian.audit.log）→ 所有引擎的留痕归零（反取证）
 *   - Edit/Write 改护栏源码 / cordis.patch.yml → 下次加载 hook 消失
 *     （anthropics/claude-code#11226：官方确认 Claude 可改自己的 hook 脚本绕过
 *      permissions.deny，chmod 444 / root 属主 / 沙箱 / deny 列表四种缓解全部失效，
 *      issue 关闭为 not planned，无官方修复）
 *   - npm uninstall dsh-guardian / pkill 守护进程 → 护栏直接消失
 *   - chmod 000 / chattr +i 审计日志 → WriteStream 静默失败，护栏「活着但失明」
 *
 * 学术侧这已是独立攻击线：arXiv:2606.14517《DoS Attacks on LLM-Based Agent
 * Guardrails》(From Shield to Target)；Sysdig JADEPUFFER（2025）实测 agentic
 * 勒索在收尾阶段自主执行「删日志-停监控」的反取证动作。
 *
 * 防御思路（EDR killer 检测的 Agent 化）：
 *   「动词 × 护栏资产」目标矩阵——护栏资产是封闭集合（审计日志/完整性基线/
 *   插件目录），误报率趋近于零（rm ./app.log、npm uninstall lodash 天然不命中）。
 *   另收编 MITRE ATT&CK T1562/T1070（新编号 T1685 系列）的反取证命令族为
 *   FORENSIC- 规则组：': >' shell 重定向截断与 ln -sf /dev/null 黑洞化在
 *   SigmaHQ 生态中没有现成规则，是可声明的差异化空白。
 *
 * 与既有引擎的分工：
 *   - persistence-guard（engine-23）拦「埋」（写入持久化机制）；
 *     本引擎拦「拆」（拆卸护栏与清除痕迹），动词方向相反
 *   - rule 引擎的 CMD-002 要求 rm -rf（rm -f 单文件不命中）、path 沙箱只管
 *     白名单根目录与结构化 fs 工具——bash 命令串里的自家资产无人看守
 *   - 字符串层混淆绕过（Base64 编码路径等）由 deobfuscation（engine-9）兜底
 *   - 边界（诚实声明）：本引擎防的是「经工具调用通道的自毁」。若护栏进程已被
 *     杀死、或源码已被改成空函数，哨兵自身也不复存在——绝对自防护需要宿主
 *     提供外部监督（类比 EDR 的 tamper protection 依赖内核），这是插件层的
 *     天花板，不是本引擎的缺陷。
 */

/** 护栏自身资产（封闭集合，启动时解析为绝对路径） */
export interface SentinelAsset {
  kind: 'audit-log' | 'integrity-state' | 'plugin-dir' | 'extra'
  /** 绝对路径（目录资产做前缀匹配：目录内一切文件都算护栏资产） */
  path: string
  label: string
}

export interface SentinelHit {
  ruleId: string
  reason: string
  action: 'deny' | 'block'
  /** 命中的护栏资产（FORENSIC 组可能无） */
  assetKind?: SentinelAsset['kind']
  /** 命中片段（截断，避免审计日志膨胀） */
  match: string
}

export interface SentinelOptions {
  /** 展开 ~ 与 $HOME 用的家目录（默认 os.homedir()；测试注入避免环境漂移） */
  homedir?: string
  /** 平台（darwin 下路径比较大小写不敏感；默认 os.platform()） */
  platform?: NodeJS.Platform
}

/**
 * 解析护栏资产清单。资产是封闭集合，全部本地确定性推导：
 *  - 审计日志 / 完整性基线：家目录下的点文件（logFile 可被配置覆盖，跟随实际值）
 *  - 插件目录：从本模块安装位置向上找最近 package.json（node_modules/dsh-guardian
 *    或源码仓库根），目录内 src/lib/cordis.patch.yml/package.json 全部受前缀保护
 *  - extra：宿主追加（例如把自家 hook 脚本、策略文件也纳入保护）
 */
export function resolveSentinelAssets(opts: { logFile?: string; extra?: string[]; packageRoot?: string } = {}): SentinelAsset[] {
  const assets: SentinelAsset[] = []
  const logFile = opts.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log')
  assets.push({ kind: 'audit-log', path: path.resolve(logFile), label: '护栏审计日志' })
  assets.push({ kind: 'integrity-state', path: path.resolve(path.join(os.homedir(), '.dsh-guardian.memory.json')), label: '护栏完整性基线' })
  const root = opts.packageRoot ?? findPackageRoot(path.dirname(fileURLToPath(import.meta.url)))
  if (root) assets.push({ kind: 'plugin-dir', path: path.resolve(root), label: '护栏插件目录' })
  for (const p of opts.extra ?? []) assets.push({ kind: 'extra', path: path.resolve(p), label: '宿主追加保护资产' })
  return assets
}

/** 从起始目录向上找最近的 package.json 所在目录（找不到返回 null） */
function findPackageRoot(startDir: string): string | null {
  let dir = path.resolve(startDir)
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

// ── FORENSIC 规则组：反取证命令族（固定模式，不依赖资产清单）──────────

export interface ForensicRule {
  id: string
  pattern: RegExp
  reason: string
  /** 映射的 ATT&CK 技术（便于审计溯源） */
  attck: string
}

/**
 * 系统日志路径判定（/var/log、/private/var/log 及其子路径）。
 * 只绑定系统日志目录——'> build.log'、'rm ./app.log' 等项目级操作天然不命中。
 */
const SYSTEM_LOG_PREFIXES = ['/var/log', '/private/var/log']

export const FORENSIC_RULES: ForensicRule[] = [
  { id: 'FORENSIC-004', attck: 'T1562.002', pattern: /\bauditctl\b[^;|&\n]{0,30}(?:^|\s)-e\s*0\b/, reason: '关闭内核审计子系统（auditctl -e 0）' },
  { id: 'FORENSIC-005', attck: 'T1070.003', pattern: /\bhistory\s+-c\b|\b(?:unset|export)\s+HISTFILE\b|HISTFILE\s*=\s*["']?\/dev\/null|\bHISTSIZE\s*=\s*0\b|\bshred\b[^;|&\n]{0,60}history/, reason: '清除 shell 历史（反取证）' },
]

/** 判定归一化后的路径 token 是否系统日志 */
function isSystemLog(p: string): boolean {
  return SYSTEM_LOG_PREFIXES.some((prefix) => p === prefix || p.startsWith(prefix + '/'))
}

// ── 动词分类 ─────────────────────────────────────────────────────────

/** 删除/移动类动词（资产离位 = 留痕或本体消失） */
const DESTROY_VERBS = new Set(['rm', 'unlink', 'shred', 'srm', 'mv', 'wipe'])
/** 截断/覆写类动词（资产还在但内容被清空/替换/伪造） */
const TRUNCATE_VERBS = new Set(['truncate', 'dd', 'cp'])
/** 权限降级类动词（chmod 000/chattr +i 使护栏写入静默失败——活着但失明） */
const FREEZE_VERBS = new Set(['chmod', 'chown', 'chattr', 'chflags'])
/** 写入类工具名（结构化 Edit/Write 通道，#11226 的原始场景） */
const WRITE_TOOL = /write|edit|patch|create|save|store|append|move|rename|delete|remove|trash|put|tee/i

/** 提取命令首词（跳过 sudo/env/VAR=x 前缀），用于判断动词位置——防 'grep rm lib/x' 类误报 */
function leadingCommandWord(segment: string): string {
  const words = segment.trim().split(/\s+/)
  for (const w of words) {
    if (/^(sudo|doas|env|nohup|command|builtin|time|nice)$/i.test(w)) continue
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue   // VAR=value 前缀
    return w
  }
  return ''
}

/** 提取文本中的路径类 token（含通配符形态），归一化后与资产比对 */
function extractPathTokens(text: string): string[] {
  const raw = text.split(/[\s"'`]+/).map((t) => t.replace(/^[:,;|&()<]+/, '').replace(/[,;|&()<>]+$/, ''))
  return raw.filter((t) => t.length > 1 && /[~/]|\.\w{1,4}$/.test(t))
}

/** 归一化单个 token：剥 of=/if= 类键前缀 → 双重百分号解码 → ~/$HOME 展开 → 绝对化（消除 ../） */
function normalizeToken(token: string, homedir: string): string {
  let t = token.replace(/^[a-z_]{1,4}=/i, '')
  for (let i = 0; i < 2; i++) {
    try { t = decodeURIComponent(t) } catch { break }
  }
  t = t.replace(/%00/g, '')
  if (t === '~') t = homedir
  else if (t.startsWith('~/')) t = path.join(homedir, t.slice(2))
  t = t.replace(/^\$HOME(?=[/]|$)/, homedir)
  return path.resolve(t)
}

/** 编译后的哨兵匹配器（资产清单固化，正则只编译一次） */
export interface SentinelMatcher {
  scan(toolName: string, text: string): SentinelHit[]
}

/**
 * 编译哨兵匹配器。检测「动词 × 护栏资产」矩阵 + FORENSIC 反取证规则组。
 * 资产作为显式参数注入（而非模块级状态），测试可用伪造清单构造跨平台场景。
 */
export function compileSentinelMatcher(assets: SentinelAsset[], opts: SentinelOptions = {}): SentinelMatcher {
  const homedir = opts.homedir ?? os.homedir()
  const insensitive = (opts.platform ?? os.platform()) === 'darwin'
  const norm = (p: string) => (insensitive ? p.toLowerCase() : p)
  const resolvedAssets = assets.map((a) => ({ ...a, normPath: norm(a.path) }))

  /** token（支持尾部通配符）是否命中护栏资产 */
  const matchAsset = (token: string): SentinelAsset | undefined => {
    let t = token
    let wildcard = false
    if (t.endsWith('*')) { wildcard = true; t = t.slice(0, -1) }
    const nt = norm(normalizeToken(t, homedir))
    return resolvedAssets.find((a) =>
      wildcard ? a.normPath.startsWith(nt) : nt === a.normPath || nt.startsWith(a.normPath + path.sep),
    )
  }

  /** 一段命令内出现过的护栏资产 */
  const assetIn = (segment: string): SentinelAsset | undefined => {
    for (const token of extractPathTokens(segment)) {
      const hit = matchAsset(token)
      if (hit) return hit
    }
    return undefined
  }

  /** 系统日志 token 判定 */
  const sysLogIn = (segment: string): string | undefined => {
    for (const token of extractPathTokens(segment)) {
      const p = normalizeToken(token, homedir)
      if (isSystemLog(p)) return p
    }
    return undefined
  }

  /** 重定向目标提取：`> asset`、`>> asset`、`: > asset`、`echo x > asset`（排除 2> stderr） */
  const redirectTargets = (segment: string): string[] => {
    const out: string[] = []
    for (const m of segment.matchAll(/(?<![0-9])>>?\s*([^\s;|&]+)/g)) out.push(m[1])
    return out
  }

  const push = (hits: SentinelHit[], hit: Omit<SentinelHit, 'match'>, segment: string) => {
    hits.push({ ...hit, match: segment.trim().slice(0, 160) })
  }

  return {
    scan(toolName: string, text: string): SentinelHit[] {
      if (!text) return []
      const hits: SentinelHit[] = []
      const snippet = () => text.slice(0, 160)

      // ── SELF-005：卸载护栏（文本级，无需资产）──
      if (/\b(?:npm|yarn|pnpm|bun)\s+(?:uninstall|remove|rm|un)\b[^;|&\n]{0,60}\bdsh-guardian\b/i.test(text)) {
        push(hits, { ruleId: 'SELF-005', reason: '卸载护栏插件本体（dsh-guardian）', action: 'deny' }, text)
      }
      // ── SELF-006：杀护栏进程（负向断言防 dsh-guardian-xxx 子串误报）──
      if (/\b(?:pkill|killall|pgrep|kill)\b[^;|&\n]{0,60}\bdsh-guardian\b(?!-)/i.test(text)) {
        push(hits, { ruleId: 'SELF-006', reason: '终止/探测护栏进程（pkill/killall dsh-guardian）', action: 'deny' }, text)
      }
      // ── FORENSIC 文本级规则（auditctl -e 0 / history 清除）──
      for (const rule of FORENSIC_RULES) {
        rule.pattern.lastIndex = 0
        if (rule.pattern.test(text)) {
          push(hits, { ruleId: rule.id, reason: `${rule.reason} [${rule.attck}]`, action: 'block' }, text)
        }
      }

      // ── 逐命令段做「动词 × 资产」匹配 ──
      const segments = text.split(/[;\n]+|&&|\|\|/)
      for (const segment of segments) {
        const cmd = leadingCommandWord(segment).split('/').pop() ?? ''
        const asset = assetIn(segment)
        const sysLog = sysLogIn(segment)

        if (asset) {
          const where = `${asset.label}（${asset.kind}）`
          if (DESTROY_VERBS.has(cmd)) {
            push(hits, { ruleId: 'SELF-001', reason: `删除/移动护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment)
          } else if (TRUNCATE_VERBS.has(cmd) || (cmd === 'dd' && /\bof=/.test(segment))) {
            push(hits, { ruleId: 'SELF-002', reason: `截断/覆写护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment)
          } else if (redirectTargets(segment).some((t) => matchAsset(t))) {
            push(hits, { ruleId: 'SELF-002', reason: `重定向截断/伪造护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment)
          } else if (FREEZE_VERBS.has(cmd)) {
            push(hits, { ruleId: 'SELF-004', reason: `篡改护栏资产权限（冻结/降级写入）：${where}`, action: 'deny', assetKind: asset.kind }, segment)
          } else if (cmd === 'ln' && /\/dev\/null/.test(segment)) {
            push(hits, { ruleId: 'SELF-003', reason: `黑洞化护栏资产（ln -s /dev/null）：${where}`, action: 'deny', assetKind: asset.kind }, segment)
          }
        }

        if (sysLog) {
          const where = `系统日志 ${sysLog}`
          if (DESTROY_VERBS.has(cmd)) {
            push(hits, { ruleId: 'FORENSIC-001', reason: `销毁${where} [T1070.001/T1685.006]`, action: 'block' }, segment)
          } else if (TRUNCATE_VERBS.has(cmd) || redirectTargets(segment).some((t) => isSystemLog(normalizeToken(t, homedir)))) {
            push(hits, { ruleId: 'FORENSIC-002', reason: `截断${where} [T1070/T1685.006]`, action: 'block' }, segment)
          } else if (cmd === 'ln' && /\/dev\/null/.test(segment)) {
            push(hits, { ruleId: 'FORENSIC-003', reason: `黑洞化${where}（ln -s /dev/null）[T1070]`, action: 'block' }, segment)
          }
        }
      }

      // ── SELF-007：结构化写工具直指护栏资产（#11226 原始场景：Edit/Write 改 hook 源码）──
      if (WRITE_TOOL.test(toolName || '')) {
        const asset = assetIn(text)
        if (asset) {
          push(hits, { ruleId: 'SELF-007', reason: `写入类工具篡改护栏资产：${asset.label}（${asset.kind}）`, action: 'deny', assetKind: asset.kind }, snippet())
        }
      }

      return hits
    },
  }
}

/** 一次性扫描便捷入口（内部编译匹配器；高频场景请复用 compileSentinelMatcher） */
export function scanSentinel(toolName: string, text: string, assets: SentinelAsset[], opts: SentinelOptions = {}): SentinelHit[] {
  return compileSentinelMatcher(assets, opts).scan(toolName, text)
}
