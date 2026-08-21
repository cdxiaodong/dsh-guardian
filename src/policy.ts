import { parse } from 'yaml'

/**
 * 声明式 YAML 安全策略引擎（Policy-as-Code）。
 *
 * 借鉴 Edictum（2026 运行时治理库）的 YAML 安全契约思想：
 * 工具调用先按外部 YAML 策略评估（工具名通配 + 参数正则 + 优先级 + allow 白名单豁免），
 * 再落入内置规则引擎——策略即数据，不改代码即可上线下线护栏。
 *
 * 热加载安全原则：解析/校验失败时保留旧策略并告警，绝不因配置错误而裸奔。
 */

/** 策略动作。allow=显式放行（豁免后续 rule 引擎，仍保留密钥扫描） */
export type PolicyAction = 'allow' | 'deny' | 'block' | 'log'

export interface PolicyRule {
  id: string
  /** 工具名匹配，支持 * 通配（shell* / browser.* / *）。缺省=匹配所有工具 */
  tool?: string | string[]
  /** 参数内容正则（字符串形式，YAML 里写）。缺省=该工具的任意调用都命中 */
  match?: string
  matchFlags?: string
  action: PolicyAction
  reason?: string
  /** 数值越小越先评估（默认 100）。首个命中的策略生效 */
  priority?: number
}

/** YAML 策略文件结构 */
export interface PolicyFile {
  version?: number
  policies: PolicyRule[]
}

/** 编译后的策略（match 已编译成正则、tool 已编译成 glob 正则） */
export interface CompiledPolicy extends PolicyRule {
  /** 仅供排序与调试；不影响对外 API */
  priority: number
}

export interface PolicyLoadResult {
  ok: boolean
  /** 生效策略数（失败时为当前保留的旧策略数） */
  count: number
  errors: string[]
}

/** glob → RegExp：* 匹配任意字符段，其余字面量化 */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`)
}

/** 校验并编译策略列表。返回 { policies, errors }——有错时 policies 为空（原子性：要么全过要么不生效） */
export function compilePolicies(raw: PolicyFile): { policies: CompiledPolicy[]; errors: string[] } {
  const errors: string[] = []
  const policies: CompiledPolicy[] = []
  const seen = new Set<string>()

  const list = Array.isArray(raw?.policies) ? raw.policies : []
  if (!Array.isArray(raw?.policies)) errors.push('策略文件缺少 policies 数组')

  list.forEach((p, i) => {
    const where = `policies[${i}]`
    if (!p || typeof p !== 'object') { errors.push(`${where}：必须是对象`); return }
    if (!p.id || typeof p.id !== 'string') { errors.push(`${where}：缺少 id`); return }
    if (seen.has(p.id)) { errors.push(`${where}：id "${p.id}" 重复`); return }
    seen.add(p.id)
    if (!['allow', 'deny', 'block', 'log'].includes(p.action)) {
      errors.push(`${where}(${p.id})：action 必须是 allow/deny/block/log`)
      return
    }
    if (p.match !== undefined) {
      try {
        new RegExp(p.match, p.matchFlags ?? 'i')
      } catch (e: any) {
        errors.push(`${where}(${p.id})：match 不是合法正则（${e.message}）`)
        return
      }
    }
    const tools = p.tool === undefined ? [] : Array.isArray(p.tool) ? p.tool : [p.tool]
    for (const t of tools) {
      if (typeof t !== 'string' || !t.length) { errors.push(`${where}(${p.id})：tool 必须是非空字符串或数组`); return }
      try { globToRegExp(t) } catch { errors.push(`${where}(${p.id})：tool 通配符 "${t}" 非法`); return }
    }
    policies.push({ ...p, priority: p.priority ?? 100 })
  })

  if (errors.length) return { policies: [], errors }
  policies.sort((a, b) => a.priority - b.priority)
  return { policies, errors: [] }
}

/** 解析 YAML 文本 → 校验编译。失败返回空 + errors（不抛异常，供热加载安全回退） */
export function parsePolicyYaml(text: string): { policies: CompiledPolicy[]; errors: string[] } {
  let raw: unknown
  try {
    raw = parse(text)
  } catch (e: any) {
    return { policies: [], errors: [`YAML 语法错误：${e.message.split('\n')[0]}`] }
  }
  if (raw === null || raw === undefined) return { policies: [], errors: ['策略文件为空'] }
  return compilePolicies(raw as PolicyFile)
}

/** 单条已编译策略是否命中 (toolName, payloadText) */
export function policyMatches(p: CompiledPolicy, toolName: string, text: string): boolean {
  const tools = p.tool === undefined ? [] : Array.isArray(p.tool) ? p.tool : [p.tool]
  if (tools.length) {
    const hit = tools.some((t) => globToRegExp(t).test(toolName))
    if (!hit) return false
  }
  if (p.match === undefined) return true
  return new RegExp(p.match, p.matchFlags ?? 'i').test(text)
}

/** 按优先级评估，返回首条命中策略；无命中返回 null */
export function evaluatePolicies(policies: CompiledPolicy[], toolName: string, text: string): CompiledPolicy | null {
  for (const p of policies) {
    if (policyMatches(p, toolName, text)) return p
  }
  return null
}
