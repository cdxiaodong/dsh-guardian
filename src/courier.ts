/**
 * 引擎 36：无辜信使检测（Courier Guard）—— URL 载货扫描。
 *
 * 威胁模型（arXiv:2610.01768 "The Innocent Courier: Covert Exfiltration Through
 * Legitimate LLM Web Fetching", 2026-10-01）：本地恶意软件无法直接联网，于是把窃取的
 * 密钥 base64/hex/percent 编码进一个"看起来无害"的 URL（query 参数、路径段、子域名
 * 标签），再以"库迁移文档 / 参考资料"等理由诱导 LLM 用合法的网页抓取工具访问——请求
 * 到达攻击者 DNS/Web 服务器的瞬间，密钥即出网（11 个开源模型上成功率 79.7%）。
 *
 * 与现有引擎的分工：
 *  - ssrf   盯目的地（这个 URL 去哪儿）
 *  - secret 盯明文（工具参数里的裸密钥）
 *  - courier 盯货物（URL 各载区【解码后】装了什么）——明文扫描器对编码载荷全盲，
 *    这正是 LLMLeak 的生存空间；好比机场安检的 X 光机：包裹（URL）外观合法，
 *    透视（解码）才看得出行李夹层里的东西。
 *
 * 三条规则：
 *  - CRX-001（deny）  ：query/路径/fragment 载区经变换解码出密钥材料
 *  - CRX-002（block） ：载区携带解码不出可读内容的高熵不透明长串（可能是走私数据，
 *                      也可能是 S3 预签名 URL 的签名，交人工复核）
 *  - CRX-003（deny）  ：子域名标签解码出密钥材料（论文点名的 DNS 隐蔽信道）
 */
import { scanSecrets, shannonEntropy } from './secrets.js'

export type CourierZoneKind = 'query' | 'path' | 'fragment' | 'subdomain'

/** URL 中可能夹带货物的载区 */
export interface CargoZone {
  kind: CourierZoneKind
  /** 载区定位（query:ref / path[1] / fragment / subdomain[0]） */
  where: string
  /** 载货原文（保持攻击者原始编码，不预解码——变换痕迹本身就是证据） */
  carrier: string
  /** 所属完整 URL 原文 */
  url: string
  /** 载货原文的 Shannon 熵 */
  entropy: number
}

export interface CourierHit {
  ruleId: 'CRX-001' | 'CRX-002' | 'CRX-003'
  zone: CourierZoneKind
  where: string
  /** 解码变换链（base64 / hex / percent / percent+base64 / opaque） */
  transform: string
  reason: string
  /** 脱敏后的 URL（载货位置以掩码呈现，审计日志不落完整嫌疑串） */
  urlMasked: string
  /** 脱敏后的载货原文 */
  carrierMasked: string
  /** 脱敏后的解码预览（CRX-002 无解码结果时为空串） */
  decodedPreview: string
  entropy: number
  /** 解码后命中的密钥规则（仅 CRX-001/003） */
  secret?: { ruleId: string; description: string }
}

export const COURIER_RULES = [
  { id: 'CRX-001', zone: 'query/path/fragment', action: 'deny', description: 'URL 载区变换解码出密钥（LLMLeak 式隐蔽外泄）' },
  { id: 'CRX-002', zone: 'query/path/fragment', action: 'block', description: 'URL 载区携带不透明高熵载荷（走私嫌疑，人工复核兼容预签名 URL）' },
  { id: 'CRX-003', zone: 'subdomain', action: 'deny', description: '子域名标签解码出密钥（DNS 隐蔽信道走私）' },
] as const

export const COURIER_THRESHOLDS = {
  /** query/路径/fragment 载货参与解码的最小长度 */
  minCarrierLength: 16,
  /** 子域名标签参与解码的最小长度 */
  minSubdomainLength: 8,
  /** CRX-002 base64 不透明载荷最小长度 */
  opaqueBase64MinLength: 32,
  /** CRX-002 hex 不透明载荷最小长度（32 位 hex 的 uuid 不进人工复核） */
  opaqueHexMinLength: 40,
  /** CRX-002 base64 熵阈（charset 熵上限 log2(64)=6） */
  opaqueBase64MinEntropy: 4.2,
  /** CRX-002 hex 熵阈（hex 熵上限 log2(16)=4） */
  opaqueHexMinEntropy: 3.6,
  /** 解码结果"可读"判定：可打印字符占比下限 */
  printableRatio: 0.9,
  /** 解码结果最小长度 */
  minDecodedLength: 8,
}

/** 常见合法子域名标签（CDN 哈希标签靠"解码不出可读内容"天然排除） */
const COMMON_SUBDOMAIN_LABELS = new Set([
  'www', 'api', 'apis', 'app', 'apps', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'mx', 'ns', 'ns1', 'ns2',
  'cdn', 'static', 'assets', 'asset', 'img', 'images', 'media', 'download', 'downloads', 'dl', 'files',
  'docs', 'dev', 'test', 'stage', 'staging', 'beta', 'demo', 'sandbox', 'prod', 'production',
  'auth', 'sso', 'oauth', 'admin', 'portal', 'dashboard', 'console', 'git', 'gitlab', 'jenkins',
  'vpn', 'ssh', 'remote', 'gateway', 'proxy', 'ws', 'wss', 'edge', 'support', 'help', 'status',
  'blog', 'news', 'shop', 'store', 'internal', 'corp', 'intra', 'local', 'metrics', 'logs', 'grafana',
])

const URL_RE = /https?:\/\/[^\s"'`<>\\]+/g
const HEX_RE = /^[0-9a-fA-F]+$/
const B64_RE = /^[A-Za-z0-9+/\-_]+={0,2}$/

/** 可打印字符占比（解码结果必须是"人读得懂的文本"才算可读证据） */
function printableRatio(s: string): number {
  if (!s) return 0
  let ok = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if ((c >= 0x20 && c <= 0x7e) || c === 9 || c === 10 || c === 13) ok++
  }
  return ok / s.length
}

function readable(s: string): boolean {
  return s.length >= COURIER_THRESHOLDS.minDecodedLength && printableRatio(s) >= COURIER_THRESHOLDS.printableRatio
}

function decodeHex(s: string): string | null {
  if (s.length < COURIER_THRESHOLDS.minCarrierLength || s.length % 2 !== 0) return null
  if (!HEX_RE.test(s)) return null
  const out = Buffer.from(s, 'hex').toString('utf8')
  return readable(out) ? out : null
}

function decodeBase64(s: string): string | null {
  const body = s.replace(/=+$/, '')
  if (body.length < COURIER_THRESHOLDS.minCarrierLength) return null
  if (!B64_RE.test(s)) return null
  if (shannonEntropy(body) < 3) return null   // 'aaaa…' 式低熵串不是密钥载体
  const normalized = body.replace(/-/g, '+').replace(/_/g, '/')   // base64url 归一
  const out = Buffer.from(normalized, 'base64').toString('utf8')
  return readable(out) ? out : null
}

interface DecodedCandidate { transform: string; decoded: string }

/** 对单个载货尝试所有变换解码链，返回"解码出可读文本"的候选 */
export function decodeCandidates(carrier: string): DecodedCandidate[] {
  const out: DecodedCandidate[] = []
  const hex = decodeHex(carrier)
  if (hex !== null) out.push({ transform: 'hex', decoded: hex })
  const b64 = decodeBase64(carrier)
  if (b64 !== null) out.push({ transform: 'base64', decoded: b64 })
  if (/%[0-9a-fA-F]{2}/.test(carrier)) {
    let pd = ''
    try { pd = decodeURIComponent(carrier) } catch { /* 非法转义忽略 */ }
    if (pd && pd !== carrier) {
      if (readable(pd)) out.push({ transform: 'percent', decoded: pd })
      const hex2 = decodeHex(pd)
      if (hex2 !== null) out.push({ transform: 'percent+hex', decoded: hex2 })
      const b642 = decodeBase64(pd)
      if (b642 !== null) out.push({ transform: 'percent+base64', decoded: b642 })
    }
  }
  return out
}

/** 从文本中提取所有 URL 的载区（保持原始编码，不预解码） */
export function extractCargoZones(text: string): CargoZone[] {
  const zones: CargoZone[] = []
  for (const raw of text.match(URL_RE) ?? []) {
    let u: URL
    try { u = new URL(raw) } catch { continue }
    // query：手工切分保持原始编码（URLSearchParams 会自动 percent 解码，抹掉变换痕迹）
    if (u.search) {
      for (const pair of u.search.slice(1).split('&')) {
        const eq = pair.indexOf('=')
        const k = eq === -1 ? pair : pair.slice(0, eq)
        const v = eq === -1 ? '' : pair.slice(eq + 1)
        if (v.length >= COURIER_THRESHOLDS.minCarrierLength) {
          zones.push({ kind: 'query', where: `query:${k}`, carrier: v, url: raw, entropy: shannonEntropy(v) })
        }
      }
    }
    // path 段（URL.pathname 不做 percent 解码，原样保留）
    u.pathname.split('/').forEach((seg, i) => {
      if (seg.length >= COURIER_THRESHOLDS.minCarrierLength) {
        zones.push({ kind: 'path', where: `path[${i - 1}]`, carrier: seg, url: raw, entropy: shannonEntropy(seg) })
      }
    })
    // fragment
    const frag = u.hash.startsWith('#') ? u.hash.slice(1) : u.hash
    if (frag.length >= COURIER_THRESHOLDS.minCarrierLength) {
      zones.push({ kind: 'fragment', where: 'fragment', carrier: frag, url: raw, entropy: shannonEntropy(frag) })
    }
    // subdomain：从原始 authority 提取（URL.hostname 会转小写，破坏 base64 大小写）
    const auth = raw.match(/^https?:\/\/([^/?#]+)/)?.[1] ?? ''
    const host = auth.replace(/^[^@]*@/, '').replace(/:\d+$/, '')
    const labels = host.split('.')
    const subCount = Math.max(labels.length - 2, 0)
    for (let i = 0; i < subCount; i++) {
      const label = labels[i]
      if (label.length >= COURIER_THRESHOLDS.minSubdomainLength && !COMMON_SUBDOMAIN_LABELS.has(label.toLowerCase())) {
        zones.push({ kind: 'subdomain', where: `subdomain[${i}]`, carrier: label, url: raw, entropy: shannonEntropy(label) })
      }
    }
  }
  return zones
}

/** 脱敏：保留头 6 尾 2，中间打码（审计日志不落完整嫌疑串/密钥） */
function mask(s: string): string {
  if (s.length <= 10) return '***'
  return s.slice(0, 6) + '…' + '*'.repeat(8) + '…' + s.slice(-2)
}

function maskCarrier(url: string, carrier: string): string {
  return url.split(carrier).join(mask(carrier))
}

/**
 * 扫描文本中所有 URL 的载货：变换解码 → 密钥识别（CRX-001/003）；
 * 解码不出可读内容的不透明高熵长串 → 人工复核（CRX-002）。
 */
export function scanCourier(text: string): CourierHit[] {
  const hits: CourierHit[] = []
  for (const zone of extractCargoZones(text)) {
    const cands = decodeCandidates(zone.carrier)
    let found = false
    for (const cand of cands) {
      const secrets = scanSecrets(cand.decoded)
      if (secrets.length) {
        const s = secrets[0]
        found = true
        hits.push({
          ruleId: zone.kind === 'subdomain' ? 'CRX-003' : 'CRX-001',
          zone: zone.kind,
          where: zone.where,
          transform: cand.transform,
          reason: zone.kind === 'subdomain'
            ? `子域名走私：${zone.where} 经 ${cand.transform} 解码出 ${s.description}（DNS 隐蔽信道外泄）`
            : `URL 载货：${zone.where} 经 ${cand.transform} 解码出 ${s.description}（LLMLeak 式隐蔽外泄）`,
          urlMasked: maskCarrier(zone.url, zone.carrier),
          carrierMasked: mask(zone.carrier),
          decodedPreview: mask(cand.decoded),
          entropy: zone.entropy,
          secret: { ruleId: s.ruleId, description: s.description },
        })
        break
      }
    }
    // CRX-002：仅对"完全解码不出可读文本"的不透明长串触发（可读但无密钥的解码
    // 结果跳过——base64 的跳转地址等合法用途误报率高）；子域名哈希标签天然高频，排除
    if (!found && cands.length === 0 && zone.kind !== 'subdomain') {
      const body = zone.carrier.replace(/=+$/, '')
      const isHex = HEX_RE.test(body)
      const isB64 = B64_RE.test(zone.carrier)
      const minLen = isHex ? COURIER_THRESHOLDS.opaqueHexMinLength : COURIER_THRESHOLDS.opaqueBase64MinLength
      const minEnt = isHex ? COURIER_THRESHOLDS.opaqueHexMinEntropy : COURIER_THRESHOLDS.opaqueBase64MinEntropy
      const ent = shannonEntropy(body)
      if ((isHex || isB64) && body.length >= minLen && ent >= minEnt) {
        hits.push({
          ruleId: 'CRX-002',
          zone: zone.kind,
          where: zone.where,
          transform: 'opaque',
          reason: `URL 载货：${zone.where} 携带 ${body.length} 字符高熵${isHex ? ' hex' : ' base64'}不透明载荷（走私嫌疑；若为预签名 URL 等合法用途请人工批准）`,
          urlMasked: maskCarrier(zone.url, zone.carrier),
          carrierMasked: mask(zone.carrier),
          decodedPreview: '',
          entropy: ent,
        })
      }
    }
  }
  return hits
}
