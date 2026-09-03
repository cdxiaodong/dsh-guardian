/**
 * DNS 隐蔽信道检测（engine-19：DNS Covert Channel / Tunneling Guard）。
 *
 * 威胁模型：沙箱/出站策略通常只封 HTTP，DNS 查询仍然畅通。被注入的 Agent
 * 可以把敏感数据编码进域名标签（hex/base32），用一条 dig/nslookup 或
 * DoH 请求送出去——既绕过 HTTP 层的字节出境预算，也不触达任何"内网 IP"。
 * （参考：Cloud Security Alliance 研究笔记 "AI Agent Trust Boundaries:
 * DNS Escape and Exfiltration"；经典工具 dnscat2 / iodine 均以 base32 分块。）
 *
 * 检测面全部是确定性的协议结构特征，不依赖网络行为：
 *  1. 标签编码特征 —— hex / base32（DNS 大小写不敏感，隧道工具首选 base32）
 *  2. 标签长度逼近协议上限（单标签 ≤63 字节；正常业务域名几乎不超 24）
 *  3. 分块特征 —— 连续多个等长长标签（iodine/dnscat2 的 chunked 编码）
 *  4. 高熵 DGA 特征 —— 随机字符分布（block 级，人工确认兜底）
 *  5. DoH 编码查询 —— 公共 DoH 端点 + name 参数里带编码子域
 */

export interface DnsVerdict {
  safe: boolean
  reason?: string
  evidence?: string[]
  domain?: string
}

export interface DnsHit {
  ruleId: string
  reason: string
  domain: string
  label: string
  /** 命中特征明细（audit 用） */
  evidence: string[]
}

/** 公共 DoH / DNS-over-HTTPS 端点（Agent 借它把解析流量伪装成普通 HTTPS） */
export const DOH_ENDPOINTS = [
  'dns.google', 'cloudflare-dns.com', 'security.cloudflare-dns.com',
  'mozilla.cloudflare-dns.com', 'dns.quad9.net', 'dns.adguard.com',
  'doh.mullvad.net', 'dns.nextdns.io', 'dns.opendns.com',
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
]

/** 从任意文本提取候选域名（≥2 级，含 URL / DoH name= 参数里的值） */
const DOMAIN_RE = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}/gi

/** 提取 DoH 查询端点 URL（含 /resolve、/dns-query、?name= 形态） */
const DOH_URL_RE = /https?:\/\/[^\s'"`]*?(?:\/(?:resolve|dns-query)\b|[\?&]name=)[^\s'"`]*/gi

const HEX_ONLY = /^[0-9a-f]+$/
const BASE32_ONLY = /^[A-Z2-7]+$/
const VOWELS = /[aeiou]/

/** Shannon 熵（与 secrets.ts 同思路：过滤低熵误报） */
function entropy(s: string): number {
  if (!s) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const count of freq.values()) {
    const p = count / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** 高熵随机串特征：熵 + 字符多样性 + 无元音（DGA/随机编码三重信号） */
function looksRandom(label: string): boolean {
  if (label.length < 16) return false
  const distinct = new Set(label).size
  const noVowelRun = !VOWELS.test(label.slice(0, 12))
  return entropy(label) > 3.5 && distinct >= 12 && noVowelRun
}

/**
 * 分析单个域名的标签结构，返回命中的隧道特征。
 */
export function inspectDomain(domain: string): DnsHit[] {
  const hits: DnsHit[] = []
  const d = domain.toLowerCase().replace(/\.$/, '')   // 去尾部根点
  const labels = d.split('.').filter(Boolean)
  // base32 检测必须用原始大小写（DNS 大小写不敏感，但隧道编码默认大写；
  // 若先转小写，[A-Z2-7] 永远不会命中）
  const rawLabels = domain.replace(/\.$/, '').split('.').filter(Boolean)
  if (labels.length < 2) return hits

  const push = (ruleId: string, reason: string, label: string, evidence: string[]) => {
    hits.push({ ruleId, reason, domain: d, label, evidence })
  }

  for (let i = 0; i < labels.length; i++) {
    const label = labels[i]
    const len = label.length

    // 1a. 纯 hex 编码标签（≥16，且含字母 a-f 排除纯数字时间戳）
    if (len >= 16 && HEX_ONLY.test(label) && /[a-f]/.test(label)) {
      push('dns-label-hex', `域名标签为 hex 编码（DNS 隧道外泄特征）：${label}`, label, [`len=${len}`, 'charset=hex'])
    }

    // 1b. 纯 base32 编码标签（≥16；DNS 大小写不敏感故隧道首选，用原始大小写判定）
    const raw = rawLabels[i] ?? label
    if (raw.length >= 16 && BASE32_ONLY.test(raw)) {
      push('dns-label-base32', `域名标签为 base32 编码（dnscat2/iodine 隧道特征）：${raw}`, raw, [`len=${raw.length}`, 'charset=base32'])
    }

    // 2. 逼近协议上限的超长标签（正常业务域名几乎不超 24）
    if (len >= 40) {
      push('dns-label-oversize', `域名标签超长（${len}/63 字节，逼近 DNS 协议上限）：${label.slice(0, 24)}…`, label, [`len=${len}`])
    }

    // 4. 高熵随机标签（DGA / 随机编码）
    if (looksRandom(label)) {
      push('dns-label-high-entropy', `域名标签呈高熵随机分布（DGA/编码外泄可疑）：${label}`, label, [`len=${len}`, `entropy=${entropy(label).toFixed(2)}`, `distinct=${new Set(label).size}`])
    }
  }

  // 3. 分块编码：连续 ≥3 个长度 ≥20 的标签（chunked base32 特征）
  let run = 0
  for (const label of labels) {
    run = label.length >= 20 ? run + 1 : 0
    if (run >= 3) {
      push('dns-label-chunked', `域名含连续多个长标签（分块编码隧道特征）`, labels.join('.'), [`consecutive-long-labels=${run}`])
      break
    }
  }

  // 5. DoH 端点域名下直接挂载编码子域（<encoded>.dns.google 形态）
  for (const ep of DOH_ENDPOINTS) {
    if (d === ep || d.endsWith('.' + ep)) {
      const inner = labels.slice(0, d === ep ? 0 : -ep.split('.').length).join('.')
      if (inner && inner.length >= 16) {
        push('dns-doh-query', `公共 DoH 端点 ${ep} 下挂载超长子域（DoH 隧道特征）`, d, [`inner=${inner}`])
      }
      break
    }
  }

  return hits
}

/** 扫描工具调用文本：提取全部候选域名/DoH URL 并逐一分析 */
export function scanDnsCovert(text: string): DnsHit[] {
  if (!text) return []
  const hits: DnsHit[] = []
  const seen = new Set<string>()

  const addAll = (candidate: string, viaDoh: boolean) => {
    for (const domain of candidate.match(DOMAIN_RE) ?? []) {
      for (const h of inspectDomain(domain)) {
        const key = `${h.ruleId}:${h.domain}`
        if (seen.has(key)) continue
        seen.add(key)
        hits.push(viaDoh ? { ...h, evidence: [...h.evidence, 'via=DoH'] } : h)
      }
    }
  }

  // DoH 查询 URL（https://dns.google/resolve?name=<encoded>.evil.com）
  // name 参数值解码后单独复扫，覆盖 URL-encoded 的编码子域
  for (const url of text.match(DOH_URL_RE) ?? []) {
    const raw = url.match(/[?&]name=([^&\s'"]+)/i)?.[1] ?? ''
    let decoded = ''
    try { decoded = decodeURIComponent(raw) } catch { decoded = raw }
    addAll(url, true)
    addAll(decoded, true)
  }

  // 普通文本里的域名（dig/nslookup/任意参数）
  addAll(text, false)

  // DoH 端点单独出现（block 级：Agent 改用 DoH 解析本身值得过目）
  for (const ep of DOH_ENDPOINTS) {
    const re = new RegExp(`(^|[^\\w.-])${ep.replace(/\./g, '\\.')}([^\\w.-]|$)`, 'i')
    if (re.test(text)) {
      const key = `dns-doh-endpoint:${ep}`
      if (!seen.has(key)) {
        seen.add(key)
        hits.push({ ruleId: 'dns-doh-endpoint', reason: `使用公共 DoH 端点 ${ep}（DNS 流量伪装为 HTTPS，出境策略可能失效）`, domain: ep, label: ep, evidence: ['endpoint=' + ep] })
      }
    }
  }

  return hits
}

/** deny 级命中（确定性隧道特征：编码/超长/分块/DoH 编码查询）；其余 block 级走人工确认 */
export const DNS_DENY_RULES = new Set(['dns-label-hex', 'dns-label-base32', 'dns-label-oversize', 'dns-label-chunked', 'dns-doh-query'])

/** 独立校验入口（guardian/dns 事件通道用）：给定域名/查询文本，返回 verdict */
export function checkDns(target: string): DnsVerdict {
  const hits = scanDnsCovert(target)
  if (!hits.length) return { safe: true }
  const deny = hits.find(h => DNS_DENY_RULES.has(h.ruleId))
  if (deny) {
    return { safe: false, reason: deny.reason, evidence: deny.evidence, domain: deny.domain }
  }
  const first = hits[0]
  return { safe: false, reason: first.reason, evidence: first.evidence, domain: first.domain }
}
