import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkPath, DEFAULT_RULES, SECRET_RULES, SSRF_RULES, scanSecrets, scanNetworkTarget,
  SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES } from '../lib/index.js'
import rules from './fixtures/rules.cases.mjs'
import secrets from './fixtures/secrets.cases.mjs'
import { ssrf, paths } from './fixtures/ssrf-path.cases.mjs'

const ids = list => list.map(r => r.id).sort()

// ── Meta: every shipped rule has a fixture, and no stale fixtures ──
test('fixtures cover every DEFAULT_RULES id', () => assert.deepEqual(Object.keys(rules).sort(), ids(DEFAULT_RULES)))
test('fixtures cover every SECRET_RULES id', () => assert.deepEqual(Object.keys(secrets).sort(), ids(SECRET_RULES)))
test('fixtures cover every SSRF_RULES id', () => assert.deepEqual(Object.keys(ssrf).sort(), ids(SSRF_RULES)))

// ── Per-rule positives / negatives ────────────────────
for (const rule of DEFAULT_RULES) {
  const c = rules[rule.id]
  test(`rule ${rule.id}: ${rule.reason}`, () => {
    assert.ok(c.positive.length >= 1 && c.negative.length >= 1, 'needs positive and negative samples')
    for (const s of c.positive) assert.ok(rule.pattern.test(s), `should match: ${s}`)
    for (const s of c.negative) assert.ok(!rule.pattern.test(s), `should NOT match: ${s}`)
  })
}

for (const rule of SECRET_RULES) {
  const c = secrets[rule.id]
  test(`secret ${rule.id}`, () => {
    assert.ok(c.positive.length >= 1 && c.negative.length >= 1)
    for (const f of c.positive) assert.ok(scanSecrets(f()).some(h => h.ruleId === rule.id), `should detect ${rule.id}`)
    for (const f of c.negative) assert.ok(!scanSecrets(f()).some(h => h.ruleId === rule.id), `should NOT detect ${rule.id}`)
  })
}

for (const rule of SSRF_RULES) {
  const c = ssrf[rule.id]
  test(`ssrf ${rule.id}: ${rule.reason}`, () => {
    assert.ok(c.positive.length >= 1 && c.negative.length >= 1)
    for (const s of c.positive) assert.ok(scanNetworkTarget(s).some(h => h.ruleId === rule.id), `should match: ${s}`)
    for (const s of c.negative) assert.ok(!scanNetworkTarget(s).some(h => h.ruleId === rule.id), `should NOT match: ${s}`)
  })
}

// ── Path sandbox ──────────────────────────────────────
test('path: every sensitive prefix and suffix has an unsafe sample', () => {
  const joined = paths.unsafe.map(u => u.path).join('\n')
  for (const p of SENSITIVE_PREFIXES) assert.ok(joined.includes(p), `no sample for prefix ${p}`)
  for (const s of SENSITIVE_SUFFIXES) assert.ok(joined.includes(s), `no sample for suffix ${s}`)
})
test('path: unsafe samples are blocked', () => {
  for (const { path: p } of paths.unsafe) assert.equal(checkPath(p).safe, false, p)
})
test('path: safe samples pass', () => {
  for (const { path: p } of paths.safe) assert.equal(checkPath(p).safe, true, p)
})
test('path: allowedRoots inside/outside', () => {
  const { roots, inside, outside } = paths.withRoots
  for (const p of inside) assert.equal(checkPath(p, roots).safe, true, p)
  for (const p of outside) assert.equal(checkPath(p, roots).safe, false, p)
})
