import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { validateRuleChange, EvolutionTracker } = plugin

// ── Gate 1：验证器（EVL-001/002/003）──────────────────
test('EVL-001：结构不合法被拒（缺字段/坏 action/ID 重复）', () => {
  const existing = [{ id: 'R-1', pattern: /foo/, reason: 'r', action: 'deny' }]
  // 缺 pattern
  assert.equal(validateRuleChange({ type: 'add', rule: { id: 'X', reason: 'r', action: 'deny' } }, existing).code, 'EVL-001')
  // 坏 action
  assert.equal(validateRuleChange({ type: 'add', rule: { id: 'X', pattern: /foo/, reason: 'r', action: 'warn' } }, existing).code, 'EVL-001')
  // ID 重复
  assert.equal(validateRuleChange({ type: 'add', rule: { id: 'R-1', pattern: /foo/, reason: 'r', action: 'deny' } }, existing).code, 'EVL-001')
  // 空 reason
  assert.equal(validateRuleChange({ type: 'add', rule: { id: 'X', pattern: /foo/, reason: '', action: 'deny' } }, existing).code, 'EVL-001')
  // 正常提案通过
  const ok = validateRuleChange({ type: 'add', rule: { id: 'X', pattern: /evil-cmd/, reason: 'r', action: 'deny' } }, existing)
  assert.equal(ok.ok, true)
  assert.equal(ok.code, null)
})

test('EVL-002：永真/超宽正则被拒（武器化防御）', () => {
  const existing = []
  for (const p of [/.*/, /[\s\S]*/, /.+/, /^/, /.{0,}/, /.*.*.*/]) {
    const v = validateRuleChange({ type: 'add', rule: { id: 'W', pattern: p, reason: 'weapon', action: 'deny' } }, existing)
    assert.equal(v.ok, false)
    assert.equal(v.code, 'EVL-002', `source=${p.source} 应被拒`)
  }
  // 正常窄面正则不误伤
  assert.equal(validateRuleChange({ type: 'add', rule: { id: 'OK', pattern: /curl\s+evil/, reason: 'r', action: 'block' } }, existing).ok, true)
})

test('EVL-003：deny→log 降级未声明被拒（渐进解除防线防御）', () => {
  const existing = [{ id: 'D-1', pattern: /danger/, reason: 'r', action: 'deny' }]
  // 降级且未声明
  const bad = validateRuleChange({ type: 'update', targetId: 'D-1', rule: { id: 'D-1', pattern: /danger/, reason: 'r', action: 'log' } }, existing)
  assert.equal(bad.ok, false)
  assert.equal(bad.code, 'EVL-003')
  // 声明 downgradeAck 后通过
  const ok = validateRuleChange(
    { type: 'update', targetId: 'D-1', rule: { id: 'D-1', pattern: /danger/, reason: 'r', action: 'log' }, downgradeAck: '误报率过高，人工复核后降级' },
    existing,
  )
  assert.equal(ok.ok, true)
  // 升级方向（log→deny）不需要声明
  const up = validateRuleChange({ type: 'update', targetId: 'D-1', rule: { id: 'D-1', pattern: /danger/, reason: 'r', action: 'deny' } }, [{ id: 'D-1', pattern: /danger/, reason: 'r', action: 'log' }])
  assert.equal(up.ok, true)
})

// ── Gate 2+3：影子观察 → 证据感知晋升 ──────────────────
test('影子模式：新规则先观察后晋升，证据不足不生效', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: '/tmp/dg-evol-test.log', evolution: { minHits: 3, minTools: 1 } })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian

  // 提案一条新规则
  const res = g.submitRuleProposal({ type: 'add', rule: { id: 'CUSTOM-X', pattern: /secret-probe/, reason: '试探行为', action: 'deny' } })
  assert.ok(res.shadowId, '通过验证返回影子条目')

  // 观察期 1 次：不该拦截（log-only 影子）
  assert.equal(isBlocked(root.bail('guardian/check', 'bash', 'secret-probe run1')), false)
  assert.equal(isBlocked(root.bail('guardian/check', 'bash', 'secret-probe run2')), false)
  // 影子库有证据
  const ev = g.shadowEvidence(res.shadowId)
  assert.equal(ev.hits, 2)

  // 第 3 次调用：观察凑齐第 3 份证据 → 晋升 + apply 同次完成，
  // 且引擎 1 的本次扫描发生在 autoPromote 之后 → 当次即拦截。
  // 这正是 VEPA authority 层语义：证据凑齐的当下激活。
  assert.ok(isBlocked(root.bail('guardian/check', 'bash', 'secret-probe run3')))
  assert.ok(isBlocked(root.bail('guardian/check', 'bash', 'secret-probe run4')))    // 晋升后持续生效
  // 晋升历史可查
  assert.ok(g.shadowRules().length === 0)
  await fiber.dispose()
})

test('证据门槛 minTools：单工具重复命中不晋升，跨工具独立证据才晋升', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: '/tmp/dg-evol-test2.log', evolution: { minHits: 2, minTools: 2 } })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian

  const res = g.submitRuleProposal({ type: 'add', rule: { id: 'MULTI-T', pattern: /multi-probe/, reason: 'r', action: 'block' } })
  assert.ok(res.shadowId)
  // 同一工具 5 次命中：minTools=2 不达标
  for (let i = 0; i < 5; i++) root.bail('guardian/check', 'bash', `multi-probe ${i}`)
  assert.equal(g.shadowEvidence(res.shadowId).hits, 5)
  assert.equal(g.shadowEvidence(res.shadowId).tools, 1)
  assert.ok(g.shadowRules().some(s => s.shadowId === res.shadowId), '仍在影子库（未晋升）')

  // 换一个工具：tools=2 达标且 hits≥2 → 自动晋升
  root.bail('guardian/check', 'fetch', 'multi-probe from fetch')
  assert.equal(g.shadowRules().length, 0, '跨工具证据达标自动晋升出影子库')
  // 晋升为 block 级：无 approve 时该调用被拦
  assert.ok(isBlocked(root.bail('guardian/check', 'fetch', 'multi-probe again')))
  await fiber.dispose()
})

test('remove 提案永不被自动晋升，须人工 forcePromote', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: '/tmp/dg-evol-test3.log', evolution: { minHits: 1, minTools: 1 } })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian

  // 针对一条真实内置规则（CRED-008 log 级）提 remove
  const res = g.submitRuleProposal({ type: 'remove', targetId: 'CRED-008' })
  assert.ok(res.shadowId, 'remove 提案结构合法进入影子库')

  // CRED-008 匹配 .bash_history：喂大量命中（remove 型 pattern 为空不观察，
  // 但即使观察命中也不自动晋升——防线拆除必须人工）
  for (let i = 0; i < 5; i++) root.bail('guardian/check', 'read', 'cat ~/.bash_history')
  assert.ok(g.shadowRules().some(s => s.shadowId === res.shadowId), 'remove 提案仍在影子库')

  // 人工强制转正：拿到提案并应用
  const promoted = g.forcePromoteShadowRule(res.shadowId)
  assert.equal(promoted.type, 'remove')
  assert.equal(promoted.targetId, 'CRED-008')
  const applied = g.applyPromotion(promoted)
  assert.equal(applied, true)
  assert.ok(!g.listRules().some(r => r.id === 'CRED-008'), 'CRED-008 已被移除')
  await fiber.dispose()
})

test('EVL-004 晋升事件落审计流', async () => {
  const logFile = '/tmp/dg-evol-audit.log'
  try { require('node:fs').rmSync(logFile) } catch {}
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile, evolution: { minHits: 2, minTools: 1 } })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian

  g.submitRuleProposal({ type: 'add', rule: { id: 'AUDIT-X', pattern: /audit-probe/, reason: 'r', action: 'deny' } })
  root.bail('guardian/check', 'bash', 'audit-probe 1')
  root.bail('guardian/check', 'bash', 'audit-probe 2')   // 达标晋升
  root.bail('guardian/check', 'bash', 'audit-probe 3')   // 生效
  await new Promise(r => setTimeout(r, 200))
  const entries = g.readAudit(50)
  assert.ok(entries.some(e => e.engine === 'evolution' && e.ruleId === 'EVL-000'), '提案入影子有审计')
  assert.ok(entries.some(e => e.engine === 'evolution' && e.ruleId === 'EVL-004'), '晋升事件有审计')
  await fiber.dispose()
})

// ── addRule 宿主通道守门 ───────────────────────────────
test('addRule：武器化正则直接抛错（宿主通道同样受 Gate-1 保护）', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: '/tmp/dg-evol-test4.log' })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian
  // 永真 deny → 护栏武器化（拦死一切）被拒
  assert.throws(() => g.addRule({ id: 'WEAPON', pattern: /.*/ , reason: 'x', action: 'deny' }), /EVL-002/)
  // 正常规则照常添加（main 兼容）
  g.addRule({ id: 'CUSTOM-2', pattern: /safe-cmd/, reason: 'r', action: 'log' })
  assert.ok(g.listRules().some(r => r.id === 'CUSTOM-2'))
  await fiber.dispose()
})

// ── TTL 退役 ──────────────────────────────────────────
test('影子 TTL：观察期超时未晋升自动退役', async () => {
  let clock = 1000
  const root = new Context()
  const fiber = root.plugin(plugin, {
    logFile: '/tmp/dg-evol-test5.log',
    evolution: { minHits: 99, shadowTtl: 5000, now: () => clock },
  })
  await new Promise(r => setTimeout(r, 200))
  const g = root.guardian

  const res = g.submitRuleProposal({ type: 'add', rule: { id: 'TTL-X', pattern: /ttl-probe/, reason: 'r', action: 'deny' } })
  // 时间前进 6 秒（超 TTL）但不喂新证据
  clock += 6000
  const retired = g.sweepShadowRules()
  assert.deepEqual(retired, ['TTL-X'], '超时影子被退役')
  assert.equal(g.shadowRules().length, 0)
  assert.ok(res.shadowId)
  await fiber.dispose()
})

// ── EvolutionTracker 单元（注入时钟）──────────────────
test('EvolutionTracker：验证与晋升纯逻辑（无 cordis 依赖）', () => {
  let clock = 0
  const tracker = new EvolutionTracker({ minHits: 2, minTools: 1, now: () => clock })
  const existing = [{ id: 'E-1', pattern: /a/, reason: 'r', action: 'log' }]

  const bad = tracker.submit({ type: 'add', rule: { id: 'E-1', pattern: /x/, reason: 'r', action: 'deny' } }, existing)
  assert.equal(bad.ok, false, 'ID 冲突被拒')

  const s = tracker.submit({ type: 'add', rule: { id: 'N-1', pattern: /evil/, reason: 'r', action: 'deny' } }, existing)
  assert.ok(s.shadowId)
  clock = 100
  tracker.observe('bash', 'evil hit 1')
  assert.equal(tracker.promoteIfReady(s.shadowId), null, '1 次命中不晋升')
  clock = 200
  tracker.observe('bash', 'evil hit 2')
  const promoted = tracker.promoteIfReady(s.shadowId)
  assert.ok(promoted, '2 次命中晋升')
  assert.equal(promoted.rule.id, 'N-1')
  assert.equal(tracker.shadowRules().length, 0)
  assert.equal(tracker.promotions.length, 1)
  assert.equal(tracker.promotions[0].hits, 2)
})

const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true
