import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, DEFAULT_RULES } = plugin
const wait = () => new Promise(r => setTimeout(r, 150))
const tmpLog = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-b-')), 'audit.log')
const blocked = r => typeof r === 'object' && r !== null && r.intercepted === true

async function boot(config = {}) {
  const logFile = tmpLog()
  const ctx = new Context()
  ctx.plugin(plugin, { logFile, ...config })
  await wait()
  return { ctx, logFile, g: ctx.guardian }
}

// ── Action levels ─────────────────────────────────────
test('deny: intercepted, no approve consulted, audited as deny', async () => {
  const { ctx, g } = await boot()
  let asked = 0
  ctx.on('guardian/approve', () => { asked++; return { approved: true } })
  const r = ctx.bail('guardian/check', 'bash', 'cat /etc/shadow')
  assert.ok(blocked(r)); assert.equal(r.action, 'deny'); assert.equal(asked, 0)
  await wait()
  assert.ok(g.readAudit(5).some(a => a.level === 'deny' && a.ruleId === 'CRED-003'))
})

test('block: no approve listener => intercepted "(not approved)"', async () => {
  const { ctx } = await boot()
  const r = ctx.bail('guardian/check', 'bash', 'rm -rf ~/x')
  assert.ok(blocked(r)); assert.equal(r.action, 'block'); assert.match(r.reason, /\(not approved\)$/)
})

test('block: approve => allowed; payload passed to listener', async () => {
  const { ctx } = await boot()
  let seen
  ctx.on('guardian/approve', (req) => { seen = req; return { approved: true } })
  assert.ok(!blocked(ctx.bail('guardian/check', 'bash', 'rm -rf ~/x')))
  assert.equal(seen.tool, 'bash'); assert.equal(seen.rule.id, 'CMD-002'); assert.match(seen.snippet, /rm -rf/)
})

test('block: approve false / malformed => still intercepted', async () => {
  for (const answer of [{ approved: false }, { approved: 'yes' }, true, undefined]) {
    const { ctx } = await boot()
    ctx.on('guardian/approve', () => answer)
    assert.ok(blocked(ctx.bail('guardian/check', 'bash', 'rm -rf ~/x')), JSON.stringify(answer))
  }
})

test('log: allowed but audited as allow', async () => {
  const { ctx, g } = await boot()
  assert.ok(!blocked(ctx.bail('guardian/check', 'bash', 'cat ~/.zsh_history')))
  await wait()
  assert.ok(g.readAudit(5).some(a => a.level === 'allow' && a.ruleId === 'CRED-008'))
})

test('clean command: allowed and not audited', async () => {
  const { ctx, g } = await boot()
  assert.ok(!blocked(ctx.bail('guardian/check', 'bash', 'ls -la')))
  await wait()
  assert.equal(g.readAudit(5).length, 0)
})

// ── Payload shapes ────────────────────────────────────
test('object payloads are scanned via JSON; null/undefined do not throw', async () => {
  const { ctx } = await boot()
  assert.ok(blocked(ctx.bail('guardian/check', 'bash', { command: 'mkfs.ext4 /dev/sda1' })))
  assert.ok(!blocked(ctx.bail('guardian/check', 'bash', null)))
  assert.ok(!blocked(ctx.bail('guardian/check', 'bash', undefined)))
})

// ── Engine toggles ────────────────────────────────────
const fakeKey = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('')
test('scanSecrets toggle', async () => {
  const on = await boot(); const off = await boot({ scanSecrets: false })
  const text = `export AWS_ACCESS_KEY_ID=${fakeKey}`
  assert.ok(blocked(on.ctx.bail('guardian/check', 'bash', text)))
  assert.ok(!blocked(off.ctx.bail('guardian/check', 'bash', text)))
})

test('scanSSRF toggle', async () => {
  const on = await boot(); const off = await boot({ scanSSRF: false })
  const text = 'curl http://192.168.1.10/admin'
  assert.ok(blocked(on.ctx.bail('guardian/check', 'fetch', text)))
  assert.ok(!blocked(off.ctx.bail('guardian/check', 'fetch', text)))
})

test('secret hit audited at engine=secret, ssrf at engine=ssrf', async () => {
  const { ctx, g } = await boot()
  ctx.bail('guardian/check', 'bash', `token ${fakeKey}`)
  ctx.bail('guardian/check', 'fetch', 'http://10.0.0.5/')
  await wait()
  const a = g.readAudit(10)
  assert.ok(a.some(e => e.engine === 'secret' && e.level === 'deny'))
  assert.ok(a.some(e => e.engine === 'ssrf' && e.level === 'block'))
})

// ── Custom rules ──────────────────────────────────────
test('config.rules adds rules; addRule/listRules work; defaults kept', async () => {
  const { ctx, g } = await boot({ rules: [{ id: 'X-1', pattern: /forbidden-word/, reason: 'Custom', action: 'deny' }] })
  assert.ok(blocked(ctx.bail('guardian/check', 'bash', 'echo forbidden-word')))
  assert.equal(g.listRules().length, DEFAULT_RULES.length + 1)
  g.addRule({ id: 'X-2', pattern: /other-word/, reason: 'Custom2', action: 'deny' })
  assert.ok(blocked(ctx.bail('guardian/check', 'bash', 'other-word')))
})

test('rule precedence: first matching rule in list order wins', async () => {
  const { ctx } = await boot()
  const r = ctx.bail('guardian/check', 'bash', 'cat /etc/shadow && rm -rf ~/x')
  assert.equal(r.ruleId, 'CMD-002')   // CMD-* precedes CRED-* in DEFAULT_RULES, even though CRED-003 is deny
})

// ── Path sandbox via service ──────────────────────────
test('guardian/path: allowedRoots enforced and audited as PATH-SANDBOX', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-root-'))
  const { ctx, g } = await boot({ allowedRoots: [root] })
  assert.equal(ctx.bail('guardian/path', path.join(root, 'a.txt')).safe, true)
  assert.equal(ctx.bail('guardian/path', path.join(root, '..', 'x')).safe, false)
  await wait()
  assert.ok(g.readAudit(5).some(e => e.ruleId === 'PATH-SANDBOX'))
})

// ── Audit log ─────────────────────────────────────────
test('snippet truncated to 300 chars; readAudit limit; corrupt lines skipped', async () => {
  const { ctx, g, logFile } = await boot()
  ctx.bail('guardian/check', 'bash', 'cat /etc/shadow ' + 'a'.repeat(1000))
  await wait()
  assert.ok(g.readAudit(1)[0].snippet.length <= 300)
  fs.appendFileSync(logFile, 'not json\n')
  assert.equal(g.readAudit(10).every(e => typeof e === 'object'), true)
  for (let i = 0; i < 5; i++) ctx.bail('guardian/check', 'bash', 'cat /etc/shadow')
  await wait()
  assert.ok(g.readAudit(3).length <= 3)
})

test('readAudit returns [] when log file is missing', async () => {
  const { g, logFile } = await boot()
  fs.rmSync(logFile, { force: true })
  assert.deepEqual(g.readAudit(), [])
})

// ── Lifecycle / isolation ─────────────────────────────
test('two instances keep separate audit logs', async () => {
  const a = await boot(); const b = await boot()
  a.ctx.bail('guardian/check', 'bash', 'cat /etc/shadow')
  await wait()
  assert.equal(a.g.readAudit().length, 1); assert.equal(b.g.readAudit().length, 0)
})

test('disposing the context closes the stream without throwing', async () => {
  const { ctx } = await boot()
  await ctx.dispose?.()
  await wait()
})

// ── Risk scoring ──────────────────────────────────────
const sig = w => ({ ruleId: 'T', reason: 't', weight: w })

test('scoreSignals: empty => 0/allow', () => {
  assert.deepEqual(scoreSignals([]), { score: 0, signals: [], verdict: 'allow' })
})

test('scoreSignals: thresholds at the boundary', () => {
  const t = DEFAULT_THRESHOLDS
  assert.deepEqual([t.warn, t.block, t.deny], [0.25, 0.5, 0.9])
  assert.equal(scoreSignals([sig(0.24)]).verdict, 'allow')
  assert.equal(scoreSignals([sig(0.25)]).verdict, 'warn')
  assert.equal(scoreSignals([sig(0.49)]).verdict, 'warn')
  assert.equal(scoreSignals([sig(0.5)]).verdict, 'block')
  assert.equal(scoreSignals([sig(0.89)]).verdict, 'block')
  assert.equal(scoreSignals([sig(0.9)]).verdict, 'deny')
})

test('scoreSignals: probabilistic union, capped at 1, weights clamped', () => {
  assert.equal(scoreSignals([sig(0.5), sig(0.5)]).score, 0.75)
  assert.equal(scoreSignals([sig(2), sig(0.3)]).score, 1)
  assert.equal(scoreSignals([sig(-1)]).score, 0)
  assert.ok(scoreSignals([sig(0.4), sig(0.4), sig(0.4)]).score <= 1)
})

test('scoreSignals: custom thresholds', () => {
  assert.equal(scoreSignals([sig(0.3)], { deny: 0.9, block: 0.3, warn: 0.1 }).verdict, 'block')
})

test('collectSignals: uses rule weight, else action default (deny .95/block .6/log .3)', () => {
  const rules = [
    { id: 'A', pattern: /aaa/, reason: 'a', action: 'deny' },
    { id: 'B', pattern: /bbb/, reason: 'b', action: 'block' },
    { id: 'C', pattern: /ccc/, reason: 'c', action: 'log' },
    { id: 'D', pattern: /ddd/, reason: 'd', action: 'log', weight: 0.77 },
  ]
  const w = Object.fromEntries(collectSignals(rules, 'aaa bbb ccc ddd').map(s => [s.ruleId, s.weight]))
  assert.deepEqual(w, { A: 0.95, B: 0.6, C: 0.3, D: 0.77 })
  assert.deepEqual(collectSignals(rules, 'nothing'), [])
})

test('secretEntropySignal: high entropy > mid > placeholder', () => {
  const hi = secretEntropySignal('k', 'Key', 'aB3$xY9!qZ7#mK2@pL5%wR8^tN4&')
  const mid = secretEntropySignal('k', 'Key', 'abcdefabcdefabcdefabcdef')
  const lo = secretEntropySignal('k', 'Key', 'xxxxxxxxxxxxxxxxxxxxxxxx')
  assert.equal(hi.weight, 0.95); assert.equal(lo.weight, 0.2)
  assert.ok(mid.weight >= lo.weight && mid.weight <= hi.weight)
  assert.match(hi.reason, /^Plaintext secret: Key \(entropy \d/)
})

// ── scanSecrets entropy filter ────────────────────────
test('scanSecrets minEntropy filters low-entropy matches', () => {
  const { scanSecrets, shannonEntropy } = plugin
  assert.equal(shannonEntropy(''), 0)
  assert.ok(shannonEntropy('abcdefghij') > shannonEntropy('aaaaaaaaaa'))
  const text = 'api_key = ' + 'x'.repeat(32)
  assert.ok(scanSecrets(text, 0).length >= scanSecrets(text, 4).length)
})
