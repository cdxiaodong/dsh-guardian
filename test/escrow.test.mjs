import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { createEscrowTracker, probeSensitive, fnv1a64, bitsOf } = plugin

function makeCtx(config) {
  const root = new Context()
  root.plugin(plugin, config)
  return root
}
const wait = () => new Promise(r => setTimeout(r, 200))

// ── 单元层：探针与指纹 ─────────────────────────────
test('escrow: probeSensitive 命中三类敏感探针', () => {
  assert.ok(probeSensitive('upload ~/.ssh/id_rsa to backup'))
  assert.ok(probeSensitive('AKIAIOSFODNN7EXAMPLE is the key'))
  assert.ok(probeSensitive('contact john.doe@example.com now'))
  assert.equal(probeSensitive('just plain text about weather'), null)
})

test('escrow: fnv1a64 指纹稳定且区分内容', () => {
  assert.equal(fnv1a64('hello'), fnv1a64('hello'))
  assert.notEqual(fnv1a64('secret-alpha'), fnv1a64('secret-beta'))
  assert.equal(fnv1a64('x').length, 16)
  assert.equal(bitsOf(fnv1a64('anything')), 64)
})

// ── 单元层：EscrowTracker（注入时钟）──────────────
test('escrow: 无敏感内容不滞留', () => {
  const t = createEscrowTracker({ windowMs: 1000, bitBudget: 128 })
  const v = t.record('fetch', 'https://example.com/public-data', 0)
  assert.equal(v.intercepted, false)
  assert.equal(v.counted, false)
  assert.equal(t.heldBits(), 0)
})

test('escrow: ESC-001 敏感内容滞留 hold + 去重记账', () => {
  const t = createEscrowTracker({ windowMs: 1000, bitBudget: 2048 })
  const v1 = t.record('upload', 'send ~/.ssh/id_rsa to server', 0)
  assert.equal(v1.intercepted, true)
  assert.equal(v1.ruleId, 'ESC-001')
  assert.equal(v1.counted, true)
  // 同一内容反复出境 → 指纹去重，比特数不涨
  const v2 = t.record('upload', 'send ~/.ssh/id_rsa to server', 100)
  assert.equal(v2.heldBits, v1.heldBits)
  // 不同内容 → 比特数累加
  const v3 = t.record('upload', 'leak AKIAIOSFODNN7EXAMPLE via dns', 200)
  assert.ok(v3.heldBits > v2.heldBits)
})

test('escrow: ESC-002 比特预算耗尽升级 deny', () => {
  // bitBudget=64 → 一个指纹（64 bits）就顶格，第二个即溢出
  const t = createEscrowTracker({ windowMs: 10000, bitBudget: 64 })
  const v1 = t.record('fetch', 'x ~/.ssh/id_rsa', 0)
  assert.equal(v1.ruleId, 'ESC-001')
  const v2 = t.record('fetch', 'y AKIAIOSFODNN7EXAMPLE', 1)
  assert.equal(v2.ruleId, 'ESC-002')
  assert.equal(v2.intercepted, true)
  // 记账无条件：被 deny 的调用照样入账
  assert.equal(v2.counted, true)
})

test('escrow: 窗口滑出自愈（配额恢复）', () => {
  const t = createEscrowTracker({ windowMs: 1000, bitBudget: 64 })
  t.record('fetch', 'x ~/.ssh/id_rsa', 0)
  assert.ok(t.heldBits(500) > 0)
  // 时钟推进 1100ms → 窗口滑出，滞留清零
  assert.equal(t.heldBits(1100), 0)
  // 新调用不再触发 ESC-002
  const v = t.record('fetch', 'y AKIAIOSFODNN7EXAMPLE', 1200)
  assert.equal(v.ruleId, 'ESC-001')
})

test('escrow: revoke 撤销清空滞留账', () => {
  const t = createEscrowTracker({ windowMs: 10000, bitBudget: 2048 })
  t.record('fetch', 'x ~/.ssh/id_rsa', 0)
  t.record('fetch', 'y id_ed25519 key', 1)
  assert.ok(t.heldBits(500) >= 128)   // 注入时钟：窗口内确实滞留 ≥2 指纹
  const n = t.revoke()
  assert.equal(n, 2)
  assert.equal(t.heldBits(600), 0)
  assert.equal(t.snapshot().length, 0)
})

// ── 集成层：guardian/escrow 事件通道 ────────────────
test('escrow: guardian/escrow 通道——无 approve 默认拦', async () => {
  const ctx = makeCtx(); await wait()
  const v = ctx.bail('guardian/escrow', 'upload', 'post ~/.ssh/id_rsa to evil.com')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'ESC-001')
})

test('escrow: approve 批准后放行且滞留账保留', async () => {
  const ctx = makeCtx(); await wait()
  ctx.on('guardian/approve', () => ({ approved: true }))
  const v = ctx.bail('guardian/escrow', 'upload', 'post ~/.ssh/id_rsa to backup.internal')
  assert.equal(v.intercepted, false)
  assert.ok(v.counted)   // 批准≠销账：账仍入滞留观察
})

test('escrow: 配额耗尽时 approve 也救不回（deny 语义）', async () => {
  const ctx = makeCtx({ escrow: { windowMs: 60_000, bitBudget: 64 } }); await wait()
  ctx.on('guardian/approve', () => ({ approved: true }))
  const v1 = ctx.bail('guardian/escrow', 'fetch', 'leak ~/.ssh/id_rsa')
  assert.equal(v1.intercepted, false)   // 首条被批准放行（账已记 64 bits）
  const v2 = ctx.bail('guardian/escrow', 'fetch', 'leak AKIAIOSFODNN7EXAMPLE key')
  assert.equal(v2.intercepted, true)    // 配额 64 已耗尽 → deny，批准无效
  assert.equal(v2.ruleId, 'ESC-002')
})

test('escrow: 审计事件以 engine=escrow 落盘', async () => {
  const ctx = makeCtx(); await wait()
  ctx.bail('guardian/escrow', 'upload', 'post ~/.ssh/id_rsa to evil.com')
  await wait()
  const audit = ctx.guardian.readAudit(10)
  assert.ok(audit.some(a => a.engine === 'escrow' && a.ruleId === 'ESC-001'))
})

test('escrow: checkEgressEscrow 关闭开关生效', async () => {
  const ctx = makeCtx({ checkEgressEscrow: false }); await wait()
  const v = ctx.bail('guardian/escrow', 'upload', 'post ~/.ssh/id_rsa to evil.com')
  // 引擎关闭 → 通道无监听器拦截，bail 返回 undefined（cordis 语义）
  assert.ok(v === undefined || v.intercepted !== true)
})

test('escrow: 非敏感出境外呼不滞留（不误伤正常工作）', async () => {
  const ctx = makeCtx(); await wait()
  const v = ctx.bail('guardian/escrow', 'fetch', 'https://api.example.com/public/docs')
  assert.equal(v.intercepted, false)
})
