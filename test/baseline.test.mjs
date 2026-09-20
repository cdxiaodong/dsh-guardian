import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { BaselineTracker, classifyTool } = plugin

function makeCtx(config) {
  const root = new Context()
  root.plugin(plugin, config)
  return root
}
const wait = (ms = 200) => new Promise(r => setTimeout(r, ms))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true

// ── 工具分类器 ────────────────────────────────────────
test('classifyTool：能力类别按高危优先匹配', () => {
  assert.equal(classifyTool('sudo'), 'admin')
  assert.equal(classifyTool('keychain-unlock'), 'admin')
  assert.equal(classifyTool('bash'), 'execute')
  assert.equal(classifyTool('exec-probe'), 'execute')
  assert.equal(classifyTool('curl'), 'network')
  assert.equal(classifyTool('web-fetch'), 'network')
  assert.equal(classifyTool('write-file'), 'write')
  assert.equal(classifyTool('edit'), 'write')
  assert.equal(classifyTool('read'), 'read')
  assert.equal(classifyTool('grep-search'), 'read')
  assert.equal(classifyTool('zzz-unknown-thing'), 'unknown')
})

// ── 冷启动保护 ────────────────────────────────────────
test('冷启动不误报：基线未成熟时的高危调用不判偏离', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 7; i++) {
    assert.equal(isBlocked(run('read', `file-${i}.txt`)), false)
  }
  // 历史仅 7 条 < minCalls=8，BLD-001 不参与判定
  assert.equal(isBlocked(run('write', 'out.txt')), false)
})

// ── BLD-001 权限扩张 ──────────────────────────────────
test('BLD-001：纯读基线后首次写类调用被拦（scope expansion）', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  const hit = run('write', 'out.txt')
  assert.ok(isBlocked(hit))
  assert.equal(hit.ruleId, 'BLD-001')
  assert.equal(hit.action, 'block')
})

test('BLD-001：approve 批准放行，且类别入账成为习惯（一次批准不再重复拦）', async () => {
  const ctx = makeCtx(); await wait()
  ctx.on('guardian/approve', () => ({ approved: true }))
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  assert.equal(isBlocked(run('write', 'out.txt')), false)      // 人工批准
  // 批准的调用已入账：历史高危占比 1/9 ≈ 11% ≥ 10%，同类后续不再视为偏离
  assert.equal(isBlocked(run('write', 'out2.txt')), false)
})

test('基线含高危习惯时不触发 BLD-001', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 6; i++) run('read', `file-${i}.txt`)
  run('bash', 'echo hi-1')
  run('bash', 'echo hi-2')
  assert.equal(isBlocked(run('bash', 'echo hi-3')), false)     // 高危占比 2/8=25%
})

// ── BLD-002 参数膨胀 ──────────────────────────────────
test('BLD-002：参数长度突增（≥中位数4倍且≥4KB）被拦', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 6; i++) run('read', `file-${i}.txt`)
  run('bash', 'echo hi-1')
  run('bash', 'echo hi-2')
  const hit = run('bash', 'a'.repeat(5120))
  assert.ok(isBlocked(hit))
  assert.equal(hit.ruleId, 'BLD-002')
})

test('BLD-002：长但未过绝对下限的参数放行', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 6; i++) run('read', `file-${i}.txt`)
  run('bash', 'echo hi-1')
  run('bash', 'echo hi-2')
  // 100 字符 ≥ 4×中位数，但 < 4096 下限 → 不判膨胀
  assert.equal(isBlocked(run('bash', 'x'.repeat(100))), false)
})

// ── BLD-003 工具风暴 ──────────────────────────────────
test('BLD-003：滑动窗口内首见高危工具风暴被拦', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  // 基线含 20% 高危习惯（bash 放最前滑出判定窗口）：BLD-001 不短路本规则
  run('bash', 'echo hi-1')
  run('bash', 'echo hi-2')
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  await wait(1100)   // 移出 runaway-loop 的 1s 时间窗，避免 BLD-004 抢先命中
  const spray = ['exec-alpha', 'exec-beta', 'exec-gamma', 'exec-delta', 'exec-epsilon']
  for (let i = 0; i < 4; i++) {
    assert.equal(isBlocked(run(spray[i], `probe-${i}`)), false) // 窗口内首见高危 1~4 个：未达阈值
  }
  const hit = run(spray[4], 'probe-4')                          // 窗口内首见高危=5
  assert.ok(isBlocked(hit))
  assert.equal(hit.ruleId, 'BLD-003')
})

// ── BLD-004 失控循环 ──────────────────────────────────
test('BLD-004：1 秒窗口内 15 次调用触发失控拦截（deny）', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 14; i++) {
    assert.equal(isBlocked(run('read', `cat f-${i}.txt`)), false)
  }
  const hit = run('read', 'cat f-14.txt')
  assert.ok(isBlocked(hit))
  assert.equal(hit.ruleId, 'BLD-004')
  assert.equal(hit.action, 'deny')
})

// ── BLD-005 复读机 ────────────────────────────────────
test('BLD-005：同一 payload 短窗口内重复 5 次被拦（deny）', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `cat unique-${i}.log`)
  for (let i = 0; i < 4; i++) {
    assert.equal(isBlocked(run('read', 'cat /etc/hosts')), false)   // 重复 1~4 次：未达阈值
  }
  const hit = run('read', 'cat /etc/hosts')                          // 第 5 次相同指纹
  assert.ok(isBlocked(hit))
  assert.equal(hit.ruleId, 'BLD-005')
  assert.equal(hit.action, 'deny')
})

// ── 稳态：正常会话全程不误报 ───────────────────────────
test('稳态会话：读写混合的成熟基线持续放行', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  // 建立 50% 高危习惯：分批调用并留间隔（1s 窗口内 ≤12 次，不触失控循环）
  for (let i = 0; i < 6; i++) {
    run('read', `src/file-${i}.txt`)
    run('bash', `echo build step ${i}`)
  }
  await wait(1100)
  for (let i = 6; i < 12; i++) {
    run('read', `src/file-${i}.txt`)
    run('bash', `echo build step ${i}`)
  }
  await wait(1100)
  for (let i = 0; i < 5; i++) {
    assert.equal(isBlocked(run('write', `dist/out-${i}.js`)), false)
    assert.equal(isBlocked(run('read', `src/file-${i}.txt`)), false)
  }
})

// ── 审计与配置 ────────────────────────────────────────
test('baseline 拦截写入审计流（engine=baseline）', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  run('write', 'out.txt')
  await wait(250)   // createWriteStream 异步落盘
  const audit = ctx.guardian.readAudit(30)
  assert.ok(audit.some(a => a.engine === 'baseline' && a.ruleId === 'BLD-001'))
})

test('trackBaseline:false 可关闭引擎', async () => {
  const ctx = makeCtx({ trackBaseline: false }); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  assert.equal(isBlocked(run('write', 'out.txt')), false)
})

test('宿主可读取画像快照并重建基线', async () => {
  const ctx = makeCtx(); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  for (let i = 0; i < 8; i++) run('read', `file-${i}.txt`)
  const snap = ctx.guardian.baselineSnapshot()
  assert.equal(snap.calls, 8)
  assert.equal(snap.mature, true)
  assert.equal(snap.classCounts.read, 8)
  assert.equal(snap.distinctTools, 1)
  assert.equal(snap.highRiskShare, 0)
  ctx.guardian.resetBaseline()
  const after = ctx.guardian.baselineSnapshot()
  assert.equal(after.calls, 0)
  assert.equal(after.mature, false)
  // 重建后回到冷启动：首个高危调用不判偏离
  assert.equal(isBlocked(run('write', 'fresh.txt')), false)
})

// ── 单元：BaselineTracker 直接驱动（record→assess 配对约定）──
test('BaselineTracker 单元：记账无条件、判定用历史', () => {
  // 冷启动：历史不足 minCalls 时，高危调用不判偏离
  const t1 = new BaselineTracker({ minCalls: 3 })
  t1.record('read', 'a')
  t1.record('write', 'b')            // 历史 1 条 < 3
  assert.equal(t1.assess('write', 'b').safe, true)
  // 成熟：纯读历史 + 当前 write → BLD-001
  const t2 = new BaselineTracker({ minCalls: 3 })
  t2.record('read', 'f-0'); t2.record('read', 'f-1'); t2.record('read', 'f-2')
  t2.record('write', 'out')          // 历史 3 条纯读，基线成熟
  const v = t2.assess('write', 'out')
  assert.equal(v.safe, false)
  assert.equal(v.ruleId, 'BLD-001')
})
