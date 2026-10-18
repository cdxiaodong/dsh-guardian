import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as os from 'node:os'
import * as path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { ResumeLedger, canonicalJson, contentHash, depDrift } = plugin

const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true
const wait = (ms = 200) => new Promise(r => setTimeout(r, ms))
const logFile = (tag) => path.join(os.tmpdir(), `dg-resume-${tag}-${process.pid}-${Date.now()}.log`)

// 注入时钟
function clock(start = 1_000_000) {
  let t = start
  return { now: () => t, advance: (ms) => { t += ms } }
}

// 集成测试：挂载真实插件，返回 fiber 以便卸载
async function mount(cfg = {}) {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: logFile('it'), ...cfg })
  await wait()
  return { root, fiber }
}

// ── 纯函数 ───────────────────────────────────────────
test('contentHash：相同内容同哈希，不同内容不同哈希', () => {
  assert.equal(contentHash('pay 100 to alice'), contentHash('pay 100 to alice'))
  assert.notEqual(contentHash('pay 100 to alice'), contentHash('pay 100 to bob'))
})

test('canonicalJson：键序无关、嵌套对象排序、数组保序', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }))
  assert.equal(canonicalJson({ a: { c: 3, d: 2 }, b: 1 }), '{"a":{"c":3,"d":2},"b":1}')
  assert.notEqual(canonicalJson({ to: ['a', 'b'] }), canonicalJson({ to: ['b', 'a'] }))
  assert.equal(canonicalJson(undefined), 'null')
})

test('depDrift：无基线无漂移；缺失与变更都算漂移', () => {
  assert.deepEqual(depDrift(undefined, { x: '1' }), [])
  assert.deepEqual(depDrift({ x: '1', y: '2' }, { x: '1', y: '2' }), [])
  assert.deepEqual(depDrift({ x: '1', y: '2' }, { x: '1', y: '3' }), ['y'])
  assert.deepEqual(depDrift({ x: '1', y: '2' }, undefined), ['x', 'y'])
  assert.deepEqual(depDrift({ x: '1' }, { x: '1', extra: '9' }), [])
})

// ── 登记与放行 ───────────────────────────────────────
test('首次调用（非恢复）登记为在途基线并放行', () => {
  const led = new ResumeLedger()
  const v = led.check('pay', 'tok-1', 'pay 100 to alice')
  assert.equal(v.intercepted, false)
  assert.equal(led.get('tok-1').status, 'inflight')
  assert.equal(led.snapshot().total, 1)
})

test('非恢复的同 token 同内容重复调用 = 宿主级重试，放行并累计尝试次数', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-r', 'pay 100 to alice')
  assert.equal(led.check('pay', 'tok-r', 'pay 100 to alice').intercepted, false)
  assert.equal(led.get('tok-r').attempts, 2)
})

// ── RSM-004 冒领恢复 ─────────────────────────────────
test('RSM-004：声称恢复但账本无基线 → block，且不登记', () => {
  const led = new ResumeLedger()
  const v = led.check('pay', 'tok-ghost', 'pay 100 to alice', { isResume: true })
  assert.deepEqual([v.ruleId, v.action], ['RSM-004', 'block'])
  assert.equal(led.get('tok-ghost'), undefined)
})

// ── RSM-006 结果未知 + 对账 ──────────────────────────
test('RSM-006：上次尝试未 commit 也未 abort 就恢复 → block（效应可能已落地未记录）', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-u', 'pay 100 to alice')
  const v = led.check('pay', 'tok-u', 'pay 100 to alice', { isResume: true })
  assert.deepEqual([v.ruleId, v.action], ['RSM-006', 'block'])
})

test('abort 对账后恢复放行，状态回到在途、尝试次数 +1', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-a', 'pay 100 to alice')
  assert.equal(led.abort('tok-a'), true)
  assert.equal(led.get('tok-a').status, 'aborted')
  assert.equal(led.check('pay', 'tok-a', 'pay 100 to alice', { isResume: true }).intercepted, false)
  assert.equal(led.get('tok-a').status, 'inflight')
  assert.equal(led.get('tok-a').attempts, 2)
  // 再次中断且未对账 → 又回到 RSM-006
  assert.equal(led.check('pay', 'tok-a', 'pay 100 to alice', { isResume: true }).ruleId, 'RSM-006')
})

test('登记时声明 idempotent 的动作恢复无需对账', () => {
  const led = new ResumeLedger()
  led.check('get', 'tok-i', 'GET /orders/42', { idempotent: true })
  assert.equal(led.check('get', 'tok-i', 'GET /orders/42', { isResume: true }).intercepted, false)
})

test('idempotent 只在登记时采信：恢复路径自报幂等无效', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-ni', 'pay 100 to alice')
  const v = led.check('pay', 'tok-ni', 'pay 100 to alice', { isResume: true, idempotent: true })
  assert.equal(v.ruleId, 'RSM-006')
})

// ── RSM-002 内容偷换 ─────────────────────────────────
test('RSM-002：同 token 但内容已变（偷换收款人）', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-3', 'pay 100 to alice')
  const v = led.check('pay', 'tok-3', 'pay 100 to bob', { isResume: true })
  assert.deepEqual([v.ruleId, v.action], ['RSM-002', 'block'])
})

test('RSM-002：同 token 但工具变了；非恢复调用复用 token 也拦', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-3b', 'do thing')
  assert.equal(led.check('transfer', 'tok-3b', 'do thing', { isResume: true }).ruleId, 'RSM-002')
  assert.equal(led.check('pay', 'tok-3b', 'do other thing').ruleId, 'RSM-002')
})

// ── RSM-001 重复落地 ─────────────────────────────────
test('RSM-001：committed 后同 token 再触发 = deny（恢复与非恢复皆然）', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-4', 'pay 100 to alice')
  assert.equal(led.commit('tok-4'), true)
  const v = led.check('pay', 'tok-4', 'pay 100 to alice', { isResume: true })
  assert.deepEqual([v.ruleId, v.action], ['RSM-001', 'deny'])
  assert.equal(led.check('pay', 'tok-4', 'pay 100 to alice').ruleId, 'RSM-001')
})

test('commit/abort：未知 token 返回 false；已落地效应不能 abort', () => {
  const led = new ResumeLedger()
  assert.equal(led.commit('nope'), false)
  assert.equal(led.abort('nope'), false)
  led.check('pay', 'tok-c', 'x')
  led.commit('tok-c')
  assert.equal(led.abort('tok-c'), false)
  assert.equal(led.get('tok-c').status, 'committed')
})

// ── RSM-003 授权失效 ─────────────────────────────────
test('RSM-003：基线授权已过期 = deny', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now })
  led.check('pay', 'tok-5', 'pay 100 to alice', { authExpiresAt: c.now() + 500 })
  led.abort('tok-5')
  c.advance(1000)
  const v = led.check('pay', 'tok-5', 'pay 100 to alice', { isResume: true })
  assert.deepEqual([v.ruleId, v.action], ['RSM-003', 'deny'])
})

test('RSM-003：登记时授权已过期 = deny 且不登记', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now })
  const v = led.check('pay', 'tok-5b', 'pay 100 to alice', { authExpiresAt: c.now() - 1 })
  assert.equal(v.ruleId, 'RSM-003')
  assert.equal(led.get('tok-5b'), undefined)
})

test('authExpiresAt 未过期 + 已对账 = 正常放行；恢复路径无法续期授权', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now })
  led.check('pay', 'tok-6', 'pay 100 to alice', { authExpiresAt: c.now() + 5000 })
  led.abort('tok-6')
  c.advance(1000)
  assert.equal(led.check('pay', 'tok-6', 'pay 100 to alice', { isResume: true }).intercepted, false)
  led.abort('tok-6')
  c.advance(10_000)
  // 恢复时自报一个更晚的过期时间不会被采信
  const v = led.check('pay', 'tok-6', 'pay 100 to alice', { isResume: true, authExpiresAt: c.now() + 99_999 })
  assert.equal(v.ruleId, 'RSM-003')
})

// ── RSM-005 依赖漂移 ─────────────────────────────────
test('RSM-005：批准时依赖的外部事实已变（被扫描文件的哈希变了）', () => {
  const led = new ResumeLedger()
  led.check('exec', 'tok-d', 'run ./installer.sh', { deps: { 'sha256:installer.sh': 'aaa', scanner: 'clean' } })
  led.abort('tok-d')
  const v = led.check('exec', 'tok-d', 'run ./installer.sh', { isResume: true, deps: { 'sha256:installer.sh': 'bbb', scanner: 'clean' } })
  assert.deepEqual([v.ruleId, v.action], ['RSM-005', 'block'])
  assert.match(v.reason, /sha256:installer\.sh/)
})

test('RSM-005：恢复时没有重新提供依赖指纹 = 未重新校验，同样拦截', () => {
  const led = new ResumeLedger()
  led.check('exec', 'tok-d2', 'run ./installer.sh', { deps: { 'sha256:installer.sh': 'aaa' } })
  led.abort('tok-d2')
  assert.equal(led.check('exec', 'tok-d2', 'run ./installer.sh', { isResume: true }).ruleId, 'RSM-005')
})

test('依赖指纹一致 + 已对账 = 放行', () => {
  const led = new ResumeLedger()
  led.check('exec', 'tok-d3', 'run ./installer.sh', { deps: { 'sha256:installer.sh': 'aaa' } })
  led.abort('tok-d3')
  const v = led.check('exec', 'tok-d3', 'run ./installer.sh', { isResume: true, deps: { 'sha256:installer.sh': 'aaa' } })
  assert.equal(v.intercepted, false)
})

// ── 判定优先级 ───────────────────────────────────────
test('优先级：已落地 > 授权过期 > 内容偷换 > 依赖漂移 > 结果未知', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now })
  const opts = { authExpiresAt: c.now() + 100, deps: { v: '1' } }
  led.check('pay', 'p1', 'A', opts); led.commit('p1')
  led.check('pay', 'p2', 'A', opts)
  led.check('pay', 'p3', 'A', { deps: { v: '1' } })
  led.check('pay', 'p4', 'A', { deps: { v: '1' } })
  c.advance(1000)
  const bad = { isResume: true, deps: { v: '2' } }
  assert.equal(led.check('pay', 'p1', 'B', bad).ruleId, 'RSM-001')  // deny 压过一切
  assert.equal(led.check('pay', 'p2', 'B', bad).ruleId, 'RSM-003')  // 过期 deny 压过偷换 block
  assert.equal(led.check('pay', 'p3', 'B', bad).ruleId, 'RSM-002')  // 偷换压过漂移
  assert.equal(led.check('pay', 'p4', 'A', bad).ruleId, 'RSM-005')  // 漂移压过结果未知
})

// ── 人工批准后的重新登记 ─────────────────────────────
test('accept：批准的内容与依赖成为新基线，旧内容反而算偷换', () => {
  const led = new ResumeLedger()
  led.check('pay', 'tok-acc', 'pay 100 to alice', { deps: { v: '1' } })
  led.accept('pay', 'tok-acc', 'pay 120 to alice', { deps: { v: '2' } })
  const e = led.get('tok-acc')
  assert.equal(e.contentHash, contentHash('pay 120 to alice'))
  assert.deepEqual(e.deps, { v: '2' })
  assert.equal(e.attempts, 2)
  led.abort('tok-acc')
  assert.equal(led.check('pay', 'tok-acc', 'pay 120 to alice', { isResume: true, deps: { v: '2' } }).intercepted, false)
  assert.equal(led.check('pay', 'tok-acc', 'pay 100 to alice', { deps: { v: '2' } }).ruleId, 'RSM-002')
})

test('accept：未登记 token（RSM-004 获批）直接登记为基线', () => {
  const led = new ResumeLedger()
  led.accept('pay', 'tok-new', 'pay 1 to alice', { isResume: true })
  assert.equal(led.get('tok-new').status, 'inflight')
})

// ── 账本维护 ─────────────────────────────────────────
test('TTL：过期条目被清出账本', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now, ttl: 1000 })
  led.check('pay', 'tok-7', 'pay 100 to alice')
  c.advance(2000)
  led.check('other', 'tok-other', 'noop')  // 任意调用触发 sweep
  assert.equal(led.get('tok-7'), undefined)
  assert.equal(led.snapshot().total, 1)
})

test('容量上限：committed 条目不被淘汰，优先淘汰非 committed 的最旧条目', () => {
  const c = clock()
  const led = new ResumeLedger({ now: c.now, maxEntries: 2 })
  led.check('pay', 'tok-a', 'a'); led.commit('tok-a')
  c.advance(10)
  led.check('pay', 'tok-b', 'b')
  c.advance(10)
  led.check('pay', 'tok-c', 'c')  // 超限：淘汰 tok-b
  assert.equal(led.get('tok-b'), undefined)
  assert.equal(led.get('tok-a').status, 'committed')
  assert.equal(led.snapshot().total, 2)
})

test('snapshot 按状态计数；get 返回副本不泄露内部引用', () => {
  const led = new ResumeLedger()
  led.check('pay', 's1', 'a'); led.commit('s1')
  led.check('pay', 's2', 'b'); led.abort('s2')
  led.check('mail', 's3', 'c', { deps: { k: 'v' } })
  assert.deepEqual(led.snapshot(), { total: 3, inflight: 1, committed: 1, aborted: 1, byTool: { pay: 2, mail: 1 } })
  const copy = led.get('s3')
  copy.status = 'committed'
  copy.deps.k = 'tampered'
  assert.equal(led.get('s3').status, 'inflight')
  assert.equal(led.get('s3').deps.k, 'v')
})

// ── 论文场景回放 ─────────────────────────────────────
test('场景（LangGraph 重复扣款）：扣款落地后崩溃、回滚恢复 → RSM-006；对账确认已落地 → RSM-001', () => {
  const led = new ResumeLedger()
  // 1. 首次执行：登记 → 支付网关实际扣款成功 → 进程在记录 commit 前崩溃
  assert.equal(led.check('pay', 'order-42', '{"amount":100,"to":"alice"}').intercepted, false)
  // 2. 从检查点回滚恢复，检查点里没有"已扣款"的记录，Agent 照常重放
  assert.equal(led.check('pay', 'order-42', '{"amount":100,"to":"alice"}', { isResume: true }).ruleId, 'RSM-006')
  // 3. 宿主向支付网关对账，确认已扣款 → commit；再重放一律 deny
  led.commit('order-42')
  assert.equal(led.check('pay', 'order-42', '{"amount":100,"to":"alice"}', { isResume: true }).ruleId, 'RSM-001')
})

test('场景（Hermes 恶意软件校验绕过）：校验后回滚、文件被替换 → RSM-005', () => {
  const led = new ResumeLedger()
  // 1. 扫描 installer.sh 判定干净，带上被扫描文件的哈希登记执行
  led.check('exec', 'run-installer', 'bash installer.sh', { deps: { 'sha256:installer.sh': 'cafebabe' } })
  // 2. 执行中断并对账为未执行；其间攻击者替换了文件
  led.abort('run-installer')
  // 3. 回滚恢复："已校验"标记来自检查点，宿主重新计算哈希后发现已不同
  const v = led.check('exec', 'run-installer', 'bash installer.sh', { isResume: true, deps: { 'sha256:installer.sh': 'deadbeef' } })
  assert.equal(v.ruleId, 'RSM-005')
})

// ── 集成：guardian/resume 系列通道 ───────────────────
test('集成：首次调用放行，不影响 guardian/check 主流程', async () => {
  const { root, fiber } = await mount()
  try {
    assert.equal(isBlocked(root.bail('guardian/resume', 'pay', 'itok-1', 'pay 100 to alice')), false)
    assert.ok(isBlocked(root.bail('guardian/check', 'bash', 'rm -rf /')))
  } finally { await fiber.dispose() }
})

test('集成：RSM-002 走 guardian/approve 二次确认（未批准=拦截）并写审计', async () => {
  const file = logFile('audit')
  const { root, fiber } = await mount({ logFile: file })
  root.on('guardian/approve', () => ({ approved: false }))
  try {
    root.bail('guardian/resume', 'pay', 'itok-2', 'pay 100 to alice')
    const r = root.bail('guardian/resume', 'pay', 'itok-2', 'pay 999 to mallory', { isResume: true })
    assert.ok(isBlocked(r))
    assert.deepEqual([r.ruleId, r.action, r.engine], ['RSM-002', 'block', 'resume'])
    await wait()
    const last = root.guardian.readAudit(1)[0]
    assert.deepEqual([last.engine, last.ruleId, last.level], ['resume', 'RSM-002', 'block'])
  } finally { await fiber.dispose() }
})

test('集成：RSM-002 获批后放行，批准内容成为新基线', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    root.bail('guardian/resume', 'pay', 'itok-3', 'pay 100 to alice')
    const r = root.bail('guardian/resume', 'pay', 'itok-3', 'pay 120 to alice', { isResume: true })
    assert.equal(isBlocked(r), false)
    const e = root.guardian.resumeSnapshot()
    assert.equal(e.inflight, 1)
  } finally { await fiber.dispose() }
})

test('集成：resume-commit 后同 token 恢复被 RSM-001 顶格 deny（approve 救不了）', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    root.bail('guardian/resume', 'pay', 'itok-4', 'pay 100 to alice')
    assert.equal(root.bail('guardian/resume-commit', 'itok-4'), true)
    const r = root.bail('guardian/resume', 'pay', 'itok-4', 'pay 100 to alice', { isResume: true })
    assert.deepEqual([r.ruleId, r.action], ['RSM-001', 'deny'])
  } finally { await fiber.dispose() }
})

test('集成：resume-abort 通道解除 RSM-006', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: false }))
  try {
    root.bail('guardian/resume', 'pay', 'itok-5', 'pay 100 to alice')
    assert.equal(root.bail('guardian/resume', 'pay', 'itok-5', 'pay 100 to alice', { isResume: true }).ruleId, 'RSM-006')
    assert.equal(root.bail('guardian/resume-abort', 'itok-5'), true)
    assert.equal(isBlocked(root.bail('guardian/resume', 'pay', 'itok-5', 'pay 100 to alice', { isResume: true })), false)
  } finally { await fiber.dispose() }
})

test('集成：RSM-004 冒领恢复', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: false }))
  try {
    const r = root.bail('guardian/resume', 'pay', 'itok-ghost', 'pay 100 to alice', { isResume: true })
    assert.equal(r.ruleId, 'RSM-004')
  } finally { await fiber.dispose() }
})

test('集成：对象载荷按规范化 JSON 指纹，LLM 重新生成时键序变化不误判偷换', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: false }))
  try {
    root.bail('guardian/resume', 'pay', 'itok-6', { amount: 100, to: 'alice', memo: { ref: 'A1', note: 'rent' } }, { idempotent: true })
    const same = root.bail('guardian/resume', 'pay', 'itok-6', { memo: { note: 'rent', ref: 'A1' }, to: 'alice', amount: 100 }, { isResume: true })
    assert.equal(isBlocked(same), false)
    const swapped = root.bail('guardian/resume', 'pay', 'itok-6', { memo: { note: 'rent', ref: 'A1' }, to: 'mallory', amount: 100 }, { isResume: true })
    assert.equal(swapped.ruleId, 'RSM-002')
  } finally { await fiber.dispose() }
})

test('集成：resume.enabled=false 时通道直接放行', async () => {
  const { root, fiber } = await mount({ resume: { enabled: false } })
  try {
    root.bail('guardian/resume', 'pay', 'itok-7', 'pay 100 to alice')
    const r = root.bail('guardian/resume', 'pay', 'itok-7', 'pay 999 to mallory', { isResume: true })
    assert.equal(isBlocked(r), false)
  } finally { await fiber.dispose() }
})

test('集成：插件卸载后 resume 通道随 fiber 一并撤除', async () => {
  const { root, fiber } = await mount()
  root.on('guardian/approve', () => ({ approved: false }))
  root.bail('guardian/resume', 'pay', 'itok-8', 'pay 100 to alice')
  assert.ok(isBlocked(root.bail('guardian/resume', 'pay', 'itok-8', 'pay 999 to mallory')))
  await fiber.dispose()
  assert.ok(!root.bail('guardian/resume', 'pay', 'itok-8', 'pay 999 to mallory'))
})
