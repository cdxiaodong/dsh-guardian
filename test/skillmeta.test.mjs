import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { scanSkillMeta, analyzeSkillChurn, stem } = plugin

function makeCtx(config) {
  const root = new Context()
  root.plugin(plugin, config)
  return root
}
const wait = () => new Promise(r => setTimeout(r, 200))
const sleep = (ms) => new Promise(r => setTimeout(r, ms))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true

// ── engine-46：技能元数据完整性（缝合 MetaCascade: arXiv:2610.14836）────

// ── SMD-001：检索关键词堆砌 ──────────────────────────────

test('SMD-001：元数据堆砌热门词、内容零支撑 → 命中（且仅此一条）', () => {
  const manifest = {
    name: 'super-email-assistant',
    description: 'Email assistant, calendar management, spreadsheet editing, web search, code analysis, file management',
    tags: ['email', 'calendar', 'spreadsheet', 'web-search', 'code-analysis'],
    content: "print('hello world')",
  }
  const findings = scanSkillMeta(manifest)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'SMD-001')
  assert.equal(findings[0].action, 'block')
  assert.match(findings[0].evidence, /email|calendar/)
})

test('SMD-001：诚实技能（元数据词在内容中全有支撑）→ 放行', () => {
  const manifest = {
    name: 'pdf-to-markdown',
    description: 'Convert PDF documents to markdown with OCR support',
    tags: ['pdf', 'ocr', 'markdown', 'converter'],
    content: `
      import { pdfminer } from 'pdf-lib'
      // convert pdf to markdown
      async function convertPdf(file) {
        const doc = await pdfminer.open(file)   // ocr via tesseract
        return extractMarkdown(doc)
      }
    `,
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

test('SMD-001：词干变体对齐（scans/repository vs scan/repositories）不误伤', () => {
  const manifest = {
    name: 'repo-check',
    description: 'Scans the repository',
    tags: [],
    content: 'perform a scan of repositories; repository health check',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

test('SMD-001：少量措辞差异不触发（未支撑数低于阈值）', () => {
  const manifest = {
    name: 'cli-shot',
    description: 'A CLI tool to manage screenshots',
    tags: [],
    content: 'capture screen; save png image',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

// ── SMD-002：同义词饱和 ─────────────────────────────────

test('SMD-002：同一意图的标签变体簇 → 命中（且仅此一条）', () => {
  const manifest = {
    name: 'pdf-toolkit',
    description: 'PDF processing utilities',
    tags: ['pdf-converter', 'convert-pdf', 'pdf_converter', 'pdf2word'],
    content: 'convert pdf documents to word files; process pdf archives',
  }
  const findings = scanSkillMeta(manifest)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'SMD-002')
  assert.match(findings[0].evidence, /pdfconverter/)
})

test('SMD-002：正常标签描述不同侧面 → 放行', () => {
  const manifest = {
    name: 'doc-tools',
    description: 'Document helpers',
    tags: ['pdf', 'ocr', 'markdown', 'converter'],
    content: 'pdf ocr markdown converter document helpers tools',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

test('SMD-002：共享前缀但功能不同的标签族（data-*）不误伤', () => {
  const manifest = {
    name: 'data-suite',
    description: 'Data helpers',
    tags: ['data-analysis', 'data-visualization', 'data-processing'],
    content: 'data analysis visualization processing helpers suite',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

// ── SMD-003：能力过度声明 ───────────────────────────────

test('SMD-003：动词+宾语声明在内容中零实现 → 命中（且仅此一条）', () => {
  const manifest = {
    name: 'inbox-helper',
    description: 'Inbox helper that reads your email and sends notifications',
    tags: [],
    content: 'inbox helper: read config, send via transport, log lines',
  }
  const findings = scanSkillMeta(manifest)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'SMD-003')
  assert.match(findings[0].evidence, /reads email|sends notifications/)
})

test('SMD-003：声明有实现支撑 → 放行', () => {
  const manifest = {
    name: 'mail-sync',
    description: 'Reads your mailbox and sends digests',
    tags: [],
    content: 'mailbox reader; digest sender; sync mail accounts',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

// ── SMD-004：排名诱导语 ─────────────────────────────────

test('SMD-004：英文最高级+品类词 → 命中（且仅此一条）', () => {
  const manifest = {
    name: 'md-helper',
    description: 'best markdown tool ever',
    tags: [],
    content: '# markdown renderer\nrender markdown to html',
  }
  const findings = scanSkillMeta(manifest)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'SMD-004')
  assert.match(findings[0].reason, /superlative/)
})

test('SMD-004：替代话术（alternative to）→ 命中', () => {
  const manifest = {
    name: 'tidy2',
    description: 'A tidy alternative to legacy cleaners',
    tags: [],
    content: 'tidy legacy cleaner files notes',
  }
  const findings = scanSkillMeta(manifest)
  assert.ok(findings.some(f => f.ruleId === 'SMD-004' && f.reason.includes('displacement')))
})

test('SMD-004：中文诱导语（首选…方案）→ 命中', () => {
  const manifest = {
    name: '文档工具',
    description: '首选的文档处理方案',
    tags: [],
    content: '解析文档并处理输出',
  }
  const findings = scanSkillMeta(manifest)
  assert.ok(findings.some(f => f.ruleId === 'SMD-004'))
})

test('SMD-004：朴素描述 → 放行', () => {
  const manifest = {
    name: 'csv-parse',
    description: 'Parses CSV files into JSON rows',
    tags: [],
    content: 'csv parser; json rows output; delimiter options',
  }
  assert.equal(scanSkillMeta(manifest).length, 0)
})

// ── SMD-005：元数据震荡 ─────────────────────────────────

test('SMD-005：窗口内元数据多版本而内容恒定 → 命中', () => {
  const t0 = Date.now()
  const finding = analyzeSkillChurn([
    { ts: t0 - 3000, metaHash: 'a', contentHash: 'X' },
    { ts: t0 - 2000, metaHash: 'b', contentHash: 'X' },
    { ts: t0, metaHash: 'c', contentHash: 'X' },
  ], { now: t0 })
  assert.ok(finding)
  assert.equal(finding.ruleId, 'SMD-005')
  assert.match(finding.evidence, /3 个元数据版本 \/ 1 个内容版本/)
})

test('SMD-005：内容随之变更（真迭代）→ 不命中', () => {
  const t0 = Date.now()
  const finding = analyzeSkillChurn([
    { ts: t0 - 3000, metaHash: 'a', contentHash: 'X' },
    { ts: t0 - 2000, metaHash: 'b', contentHash: 'Y' },
    { ts: t0, metaHash: 'c', contentHash: 'Z' },
  ], { now: t0 })
  assert.equal(finding, null)
})

test('SMD-005：窗口外观测被剔除 → 不命中', () => {
  const t0 = Date.now()
  const finding = analyzeSkillChurn([
    { ts: t0 - 1000 * 3600 * 48, metaHash: 'a', contentHash: 'X' },
    { ts: t0 - 1000 * 3600 * 47, metaHash: 'b', contentHash: 'X' },
    { ts: t0, metaHash: 'c', contentHash: 'X' },
  ], { now: t0 })
  assert.equal(finding, null)
})

test('SMD-005：元数据版本数低于阈值 → 不命中', () => {
  const t0 = Date.now()
  const finding = analyzeSkillChurn([
    { ts: t0 - 2000, metaHash: 'a', contentHash: 'X' },
    { ts: t0 - 1000, metaHash: 'a', contentHash: 'X' },
    { ts: t0, metaHash: 'b', contentHash: 'X' },
  ], { now: t0 })
  assert.equal(finding, null)
})

// ── 词法工具 ────────────────────────────────────────────

test('stem：复数/ing/ed/双写归一', () => {
  assert.equal(stem('scans'), 'scan')
  assert.equal(stem('scanning'), 'scan')
  assert.equal(stem('repositories'), 'repository')
  assert.equal(stem('documents'), 'document')
  assert.equal(stem('pdf'), 'pdf')   // 短词不动
})

// ── 通道集成（cordis bail）──────────────────────────────

test('guardian/skill-meta 通道：恶意堆砌被拦截并落审计', async () => {
  const ctx = makeCtx(); await wait()
  const manifest = {
    name: 'super-email-assistant',
    description: 'Email assistant, calendar management, spreadsheet editing, web search, code analysis, file management',
    tags: ['email', 'calendar', 'spreadsheet', 'web-search', 'code-analysis'],
    content: "print('hello world')",
  }
  const r = ctx.bail('guardian/skill-meta', manifest)
  assert.ok(isBlocked(r))
  assert.equal(r.ruleId, 'SMD-001')
  await sleep(200)
  const audit = ctx.guardian.readAudit()
  assert.ok(audit.some(e => e.engine === 'skillmeta' && e.ruleId === 'SMD-001' && e.level === 'block'))
})

test('guardian/skill-meta 通道：approve 批准后放行', async () => {
  const ctx = makeCtx(); await wait()
  ctx.on('guardian/approve', () => ({ approved: true }))
  const manifest = {
    name: 'super-email-assistant',
    description: 'Email assistant, calendar management, spreadsheet editing, web search, code analysis, file management',
    tags: ['email', 'calendar', 'spreadsheet', 'web-search', 'code-analysis'],
    content: "print('hello world')",
  }
  assert.equal(isBlocked(ctx.bail('guardian/skill-meta', manifest)), false)
})

test('guardian/skill-meta 通道：诚实技能放行', async () => {
  const ctx = makeCtx(); await wait()
  const manifest = {
    name: 'pdf-to-markdown',
    description: 'Convert PDF documents to markdown with OCR support',
    tags: ['pdf', 'ocr', 'markdown', 'converter'],
    content: 'convert pdf to markdown; ocr via tesseract; document parser',
  }
  assert.equal(isBlocked(ctx.bail('guardian/skill-meta', manifest)), false)
})

test('guardian/skill-meta 通道：元数据震荡（代码冻结、检索字段反复调参）第三版被拦', async () => {
  const ctx = makeCtx({ skillChurnWindowMs: 60_000, skillChurnThreshold: 3 }); await wait()
  const content = 'churn test version one two three print(1)'
  const base = { name: 'churn-test', tags: [], content }
  const v1 = ctx.bail('guardian/skill-meta', { ...base, description: 'churn test version one' })
  const v2 = ctx.bail('guardian/skill-meta', { ...base, description: 'churn test version two' })
  assert.equal(isBlocked(v1), false)
  assert.equal(isBlocked(v2), false)
  const v3 = ctx.bail('guardian/skill-meta', { ...base, description: 'churn test version three' })
  assert.ok(isBlocked(v3))
  assert.equal(v3.ruleId, 'SMD-005')
})

test('guardian/skill-meta 通道：scanSkillMeta=false 时全部放行', async () => {
  const ctx = makeCtx({ scanSkillMeta: false }); await wait()
  const manifest = {
    name: 'super-email-assistant',
    description: 'Email assistant, calendar management, spreadsheet editing, web search, code analysis, file management',
    tags: ['email', 'calendar', 'spreadsheet', 'web-search', 'code-analysis'],
    content: "print('hello world')",
  }
  assert.equal(isBlocked(ctx.bail('guardian/skill-meta', manifest)), false)
})

test('churn 状态按 skillId 隔离：不同技能互不累积', async () => {
  const ctx = makeCtx({ skillChurnWindowMs: 60_000, skillChurnThreshold: 3 }); await wait()
  const content = 'churn test version one two three print(1)'
  const mk = (name, d) => ({ name, description: d, tags: [], content })
  // 两个技能交替各提交 2 版，都不到阈值
  for (const d of ['churn test version one', 'churn test version two']) {
    assert.equal(isBlocked(ctx.bail('guardian/skill-meta', mk('skill-a', d), 'skill-a')), false)
    assert.equal(isBlocked(ctx.bail('guardian/skill-meta', mk('skill-b', d), 'skill-b')), false)
  }
})
