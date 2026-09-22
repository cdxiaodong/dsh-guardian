import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { TamperEvidence, verifyChain, computeRecordHash, canonicalizeEvent, GENESIS_HASH } = plugin

const wait = () => new Promise(r => setTimeout(r, 200))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true
const tmpLog = () => path.join(os.tmpdir(), `guardian-chain-${Date.now()}-${Math.random().toString(36).slice(2)}.log`)
const readLines = (f) => fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean)

// ── 单元：哈希链纯函数 ────────────────────────────────
test('链纯函数：canonical 序列化确定性 + 哈希链计算', () => {
  // 字段排序保证同内容字节级一致
  assert.equal(canonicalizeEvent({ b: '2', a: '1' }), canonicalizeEvent({ a: '1', b: '2' }))
  assert.equal(canonicalizeEvent({ a: '1' }), 'a=1')
  // 哈希对 (entry, seq, prevHash) 三元组敏感
  const h1 = computeRecordHash('e', 1, GENESIS_HASH)
  const h2 = computeRecordHash('e', 2, GENESIS_HASH)
  const h3 = computeRecordHash('e2', 1, GENESIS_HASH)
  assert.equal(h1.length, 64)
  assert.notEqual(h1, h2)
  assert.notEqual(h1, h3)
})

test('链纯函数：创世哈希为 64 个 0', () => {
  assert.equal(GENESIS_HASH, '0'.repeat(64))
})

// ── 单元：TamperEvidence 写入器 ──────────────────────
test('TamperEvidence：append 串接链并可通过验证', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = []
  for (let i = 1; i <= 5; i++) lines.push(te.append({ ts: `t${i}`, level: 'deny', ruleId: `R-${i}` }))
  const res = verifyChain(lines)
  assert.equal(res.ok, true)
  assert.equal(res.verifiedCount, 5)
  assert.equal(res.head.seq, 5)
  assert.equal(res.head.recordHash, te.chainHead().recordHash)
  // 每条 prevHash 接前条 recordHash
  const recs = lines.map(l => JSON.parse(l))
  assert.equal(recs[0].prevHash, GENESIS_HASH)
  for (let i = 1; i < 5; i++) assert.equal(recs[i].prevHash, recs[i - 1].recordHash)
})

test('TamperEvidence：带初始链头续写（跨进程语义）', () => {
  const te1 = new TamperEvidence(tmpLog())
  te1.append({ a: '1' })
  te1.append({ a: '2' })
  // 新进程：从磁盘链尾恢复链头（只信记录哈希）
  const te2 = new TamperEvidence(tmpLog(), te1.chainHead())
  const l3 = te2.append({ a: '3' })
  const all = [JSON.stringify({ seq: 1, entry: 'a=1', prevHash: GENESIS_HASH, recordHash: computeRecordHash('a=1', 1, GENESIS_HASH) })]
  // 完整链应是 te1 两条 + te2 一条 —— 用 te1 重新生成前两条再拼上第三条
  const te1Lines = []
  const teX = new TamperEvidence(tmpLog())
  const l1 = teX.append({ a: '1' })
  const l2 = teX.append({ a: '2' })
  const teY = new TamperEvidence(tmpLog(), teX.chainHead())
  const l3b = teY.append({ a: '3' })
  const res = verifyChain([l1, l2, l3b])
  assert.equal(res.ok, true)
  assert.equal(res.verifiedCount, 3)
  assert.equal(res.head.recordHash, teY.chainHead().recordHash)
  // 第三条 seq=3 且接在 te1 链尾之后
  const r3 = JSON.parse(l3)
  assert.equal(r3.seq, 3)
  assert.equal(r3.prevHash, te1.chainHead().recordHash)
})

// ── 单元：verifyChain 四种篡改检出 ───────────────────
test('verifyChain：编辑历史（改动中间条内容）被检出', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = [te.append({ n: '1' }), te.append({ n: '2' }), te.append({ n: '3' })]
  // 篡改第 2 条内容：entry 改但 recordHash 不变 → hash 不匹配
  const tampered = JSON.parse(lines[1])
  tampered.entry = 'n=hacked'
  lines[1] = JSON.stringify(tampered)
  const res = verifyChain(lines)
  assert.equal(res.ok, false)
  assert.equal(res.problem, 'hash')
  assert.equal(res.line, 2)
  assert.equal(res.verifiedCount, 1)   // 第 1 条仍验过
})

test('verifyChain：截断删除中间条（prevHash 断链）被检出', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = [te.append({ n: '1' }), te.append({ n: '2' }), te.append({ n: '3' })]
  // 删掉第 2 条 → 第 3 条 prevHash 接不上第 1 条 recordHash
  const res = verifyChain([lines[0], lines[2]])
  assert.equal(res.ok, false)
  // 删中间条：seq 断档（3 ≠ 期望 2）先于 prevHash 比对触发 → format
  assert.equal(res.problem, 'format')
  assert.equal(res.line, 2)
  // 链接性检出用「改内容但保留 seq」的构造
  const rec3 = JSON.parse(lines[2])
  rec3.seq = 2
  const res2 = verifyChain([lines[0], JSON.stringify(rec3)])
  assert.equal(res2.ok, false)
  assert.equal(res2.problem, 'link')
})

test('verifyChain：尾部截断后整体仍自洽（诚实边界：链验不出"少了尾巴"）', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = [te.append({ n: '1' }), te.append({ n: '2' }), te.append({ n: '3' })]
  // 删掉最后一条：剩下两条仍是合法链 —— 这是哈希链的结构性盲区，
  // 需要链头外部备份（auditChainHead()）才能检出，见集成测试
  const res = verifyChain(lines.slice(0, 2))
  assert.equal(res.ok, true)
  assert.equal(res.verifiedCount, 2)
})

test('verifyChain：伪造整条链（首条 prevHash 非创世）被检出', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = [te.append({ n: '1' }), te.append({ n: '2' })]
  // 攻击者伪造一条全新链想冒充：首条 prevHash 不是创世值
  const fakeLine = JSON.stringify({ seq: 1, entry: 'n=fake', prevHash: 'f'.repeat(64), recordHash: computeRecordHash('n=fake', 1, 'f'.repeat(64)) })
  const res = verifyChain([fakeLine])
  assert.equal(res.ok, false)
  assert.equal(res.problem, 'genesis')
})

test('verifyChain：解析失败与空文件', () => {
  assert.deepEqual(verifyChain([]).problem, 'empty')
  const res = verifyChain(['not json at all'])
  assert.equal(res.ok, false)
  assert.equal(res.problem, 'parse')
  assert.equal(res.line, 1)
})

test('verifyChain：序号断档（插入新行重排序）被检出', () => {
  const te = new TamperEvidence(tmpLog())
  const lines = [te.append({ n: '1' }), te.append({ n: '2' }), te.append({ n: '3' })]
  // 重排序：3,2,1 → 第一条 seq=3 ≠ 期望 1
  const res = verifyChain([...lines].reverse())
  assert.equal(res.ok, false)
  assert.equal(res.problem, 'format')
})

// ── 集成：guardian 审计走哈希链 ──────────────────────
function makeCtx(logFile, config = {}) {
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile, tamperEvidence: true, ...config })
  return { root, fiber }
}
async function disposeCtx(c) { await c.fiber.dispose() }

test('集成：链模式审计落盘 + verifyAudit 全绿 + readAudit 还原事件', async () => {
  const log = tmpLog()
  const { root: ctx, fiber } = makeCtx(log); await wait()
  ctx.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')   // deny → 审计
  ctx.bail('guardian/check', 'bash', 'cat ~/.bash_history')           // log 级 → allow 审计
  await wait()
  const g = ctx.guardian
  const v = g.verifyAudit()
  assert.equal(v.mode, 'chain')
  assert.equal(v.ok, true)
  assert.equal(v.verifiedCount, 2)
  // 链头可溯源
  assert.equal(g.auditChainHead().seq, 2)
  // readAudit 还原业务事件（canonical → 对象）
  const entries = g.readAudit(10)
  assert.equal(entries.length, 2)
  assert.equal(entries[0].ruleId, 'CMD-003')
  assert.equal(entries[0].level, 'deny')
  assert.equal(entries[1].ruleId, 'CRED-008')
  assert.ok(entries[0].ts)
  await fiber.dispose()
})

test('集成：磁盘篡改（编辑历史 deny 记录）被 verifyAudit 检出', async () => {
  const log = tmpLog()
  const { root: ctx, fiber } = makeCtx(log); await wait()
  ctx.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')
  ctx.bail('guardian/check', 'bash', 'cat ~/.bash_history')
  await wait()
  await fiber.dispose()
  // 攻击者事后把 deny 记录改成 allow（抹证据）
  const lines = readLines(log)
  const rec = JSON.parse(lines[0])
  assert.ok(rec.entry.includes('deny'))
  lines[0] = JSON.stringify({ ...rec, entry: rec.entry.replace('deny', 'allow') })
  fs.writeFileSync(log, lines.join('\n') + '\n')
  // 新进程加载 → initChain 发现磁盘链损坏 → verifyAudit 报警
  const { root: ctx2, fiber: fiber2 } = makeCtx(log); await wait()
  const v = ctx2.guardian.verifyAudit()
  assert.equal(v.ok, false)
  assert.equal(v.mode, 'chain')
  await fiber2.dispose()
})

test('集成：截断日志（删尾部攻击痕迹）经链头比对被检出', async () => {
  const log = tmpLog()
  const { root: ctx, fiber } = makeCtx(log); await wait()
  ctx.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')
  ctx.bail('guardian/check', 'bash', 'cat ~/.bash_history')
  await wait()
  // 内存链头（seq=2）还在——模拟"护栏进程活着但磁盘被外部截断"
  const headBefore = ctx.guardian.auditChainHead()
  assert.equal(headBefore.seq, 2)
  const lines = readLines(log)
  fs.writeFileSync(log, lines[0] + '\n')   // 截掉最后一条
  const v = ctx.guardian.verifyAudit()
  // 剩一条自成合法链（结构性盲区），但与内存链头对不上 → checkAgainstDisk 检出
  assert.equal(v.ok, false)
  await fiber.dispose()
})

test('集成：新进程从磁盘链尾续写（跨会话持久链）', async () => {
  const log = tmpLog()
  const { root: ctx1, fiber: fiber1 } = makeCtx(log); await wait()
  ctx1.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')
  await wait()
  const head1 = ctx1.guardian.auditChainHead()
  await fiber1.dispose()
  // 第二个进程：应从 seq=1 续到 seq=2，链不断
  const { root: ctx2, fiber: fiber2 } = makeCtx(log); await wait()
  ctx2.bail('guardian/check', 'bash', 'mkfs.ext4 /dev/sda1')
  await wait()
  const v = ctx2.guardian.verifyAudit()
  assert.equal(v.ok, true)
  assert.equal(v.verifiedCount, 2)
  const head2 = ctx2.guardian.auditChainHead()
  assert.equal(head2.seq, 2)
  assert.notEqual(head2.recordHash, head1.recordHash)
  // 两条事件都还原可读
  const entries = ctx2.guardian.readAudit(10)
  assert.equal(entries.length, 2)
  assert.equal(entries[1].ruleId, 'CMD-004')
  await fiber2.dispose()
})

test('集成：普通模式（默认）不受影响，verifyAudit 返回 plain', async () => {
  const log = tmpLog()
  const root = new Context()
  const fiber = root.plugin(plugin, { logFile: log })
  await wait()
  root.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')
  await wait()
  const v = root.guardian.verifyAudit()
  assert.equal(v.mode, 'plain')
  assert.equal(v.ok, true)
  assert.equal(v.verifiedCount, 1)
  assert.equal(root.guardian.auditChainHead(), null)
  await fiber.dispose()
})

test('集成：链模式下正常拦截与放行行为不变', async () => {
  const log = tmpLog()
  const { root: ctx, fiber } = makeCtx(log); await wait()
  const run = (t, p) => ctx.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('bash', 'dd if=/dev/zero of=/dev/sda')))
  assert.equal(isBlocked(run('bash', 'git status')), false)
  await wait()
  assert.equal(ctx.guardian.verifyAudit().ok, true)
  await fiber.dispose()
})

// ── 集成：多实例隔离 ─────────────────────────────────
test('多实例：两条独立链互不污染', async () => {
  const logA = tmpLog(), logB = tmpLog()
  const { root: ctxA, fiber: fiberA } = makeCtx(logA)
  const { root: ctxB, fiber: fiberB } = makeCtx(logB)
  await wait()
  ctxA.bail('guardian/check', 'bash', 'dd if=/dev/zero of=/dev/sda')
  ctxB.bail('guardian/check', 'bash', 'cat ~/.bash_history')   // log 级 → allow 审计
  ctxB.bail('guardian/check', 'bash', 'mkfs.ext4 /dev/sda1')   // deny → 审计
  await wait()
  assert.equal(ctxA.guardian.auditChainHead().seq, 1)
  assert.equal(ctxB.guardian.auditChainHead().seq, 2)
  assert.ok(ctxA.guardian.verifyAudit().ok)
  assert.ok(ctxB.guardian.verifyAudit().ok)
  assert.notEqual(ctxA.guardian.auditChainHead().recordHash, ctxB.guardian.auditChainHead().recordHash)
  await fiberA.dispose()
  await fiberB.dispose()
})
