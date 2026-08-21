import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { globToRegExp, parsePolicyYaml, evaluatePolicies } = plugin

const wait = (ms = 200) => new Promise(r => setTimeout(r, ms))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true
const tmpYaml = (content) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-policy-'))
  const file = path.join(dir, 'policy.yaml')
  fs.writeFileSync(file, content)
  return file
}

// ── 纯函数：glob 通配符 ─────────────────────────────
test('glob：* 匹配任意字符段', () => {
  assert.ok(globToRegExp('shell*').test('shell'))
  assert.ok(globToRegExp('shell*').test('shell_exec'))
  assert.ok(!globToRegExp('shell*').test('bash'))
  assert.ok(globToRegExp('browser.*').test('browser.click'))
  assert.ok(!globToRegExp('browser.*').test('browserx.click'))
  assert.ok(globToRegExp('*').test('anything.here'))
})

// ── 纯函数：YAML 解析与校验 ─────────────────────────
test('策略解析：合法 YAML → 按 priority 排序', () => {
  const { policies, errors } = parsePolicyYaml(`
version: 1
policies:
  - id: second
    tool: git
    action: block
    priority: 200
  - id: first
    tool: shell*
    action: deny
    priority: 10
`)
  assert.equal(errors.length, 0)
  assert.equal(policies.length, 2)
  assert.equal(policies[0].id, 'first')   // priority 小的先评估
  assert.equal(policies[1].id, 'second')
})

test('策略解析：YAML 语法错误 → errors 非空且不抛异常', () => {
  const { policies, errors } = parsePolicyYaml('policies: [ broken {{{')
  assert.ok(policies.length === 0)
  assert.ok(errors.length > 0)
  assert.match(errors[0], /YAML 语法错误/)
})

test('策略校验：缺 id / 非法 action / 坏正则 / 重复 id 原子性拒绝', () => {
  const bad1 = parsePolicyYaml('policies:\n  - action: deny')
  assert.ok(bad1.errors.some(e => e.includes('缺少 id')))
  const bad2 = parsePolicyYaml('policies:\n  - id: x\n    action: maybe')
  assert.ok(bad2.errors.some(e => e.includes('action')))
  const bad3 = parsePolicyYaml('policies:\n  - id: x\n    action: deny\n    match: "[unclosed"')
  assert.ok(bad3.errors.some(e => e.includes('合法正则')))
  const bad4 = parsePolicyYaml('policies:\n  - id: x\n    action: deny\n  - id: x\n    action: log')
  assert.ok(bad4.errors.some(e => e.includes('重复')))
  // 任一错误 → 整体不生效（原子性）
  assert.equal(bad4.policies.length, 0)
  // 缺 policies 数组
  const bad5 = parsePolicyYaml('foo: bar')
  assert.ok(bad5.errors.some(e => e.includes('policies 数组')))
})

// ── 纯函数：evaluatePolicies 首条命中即停 ───────────
test('策略评估：工具匹配 + 首中即停', () => {
  const { policies } = parsePolicyYaml(`
policies:
  - id: allow-docs
    tool: shell
    match: rm -rf ~/Documents
    action: allow
    priority: 10
  - id: deny-rm
    tool: shell*
    match: rm -rf
    action: deny
    priority: 20
`)
  // allow-docs 优先命中 → 不落入 deny-rm
  const hit = evaluatePolicies(policies, 'shell', 'rm -rf ~/Documents')
  assert.equal(hit.id, 'allow-docs')
  // 工具名不匹配 allow-docs（shell_exec ≠ 精确 shell）→ 落到 deny-rm（shell* 通配）
  const hit2 = evaluatePolicies(policies, 'shell_exec', 'rm -rf something')
  assert.equal(hit2?.id, 'deny-rm')
  // 全不命中
  assert.equal(evaluatePolicies(policies, 'shell', 'ls -la'), null)
})

// ── RCE 新规则（Microsoft《When prompts become shells》提炼）──
test('RCE 规则：pickle/marshal 反序列化直接拦截', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin)
  await fiber
  const run = (t, p) => root.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('python', 'import pickle; obj = pickle.loads(payload)')))
  assert.ok(isBlocked(run('python', 'data = marshal.loads(blob)')))
  await fiber.dispose()
})

test('RCE 规则：yaml.load 无 SafeLoader 拦截，带 SafeLoader 放行', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin)
  await fiber
  const run = (t, p) => root.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('python', 'cfg = yaml.load(text)')))
  assert.ok(isBlocked(run('python', "cfg = yaml.load(text, Loader=yaml.Loader)")))
  assert.equal(isBlocked(run('python', 'cfg = yaml.load(text, Loader=yaml.SafeLoader)')), false)
  await fiber.dispose()
})

test('RCE 规则：eval 模型输入 / child_process / torch.load / new Function', async () => {
  const root = new Context()
  const fiber = root.plugin(plugin)
  await fiber
  const run = (t, p) => root.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('python', 'result = eval(user_input)')))
  assert.ok(isBlocked(run('node', 'const { exec } = require("child_process"); exec(cmd)')))
  assert.ok(isBlocked(run('node', 'execSync(`rm -rf ${dir}`)')))
  assert.ok(isBlocked(run('python', 'model = torch.load("model.bin")')))
  assert.ok(isBlocked(run('node', 'const f = new Function("return process")')))
  // 正常调用不受影响
  assert.equal(isBlocked(run('python', 'print(sum(range(10)))')), false)
  await fiber.dispose()
})

// ── 集成：GuardianService + YAML 策略 ───────────────
test('策略引擎：配置 policyFile 后工具级 deny 生效', async () => {
  const file = tmpYaml(`
policies:
  - id: deny-python-exec
    tool: python*
    action: deny
    reason: 禁用 Python 动态执行工具
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file, watchPolicy: false })
  await fiber
  const run = (t, p) => root.bail('guardian/check', t, p)
  assert.ok(isBlocked(run('python_execute', 'print("hi")')))          // 工具级封禁
  assert.equal(isBlocked(run('shell', 'ls -la')), false)              // 其他工具不受影响
  assert.equal(root.guardian.listPolicies().length, 1)
  await fiber.dispose()
})

test('策略引擎：allow 白名单豁免内置规则，但明文密钥仍拦截', async () => {
  const file = tmpYaml(`
policies:
  - id: allow-destructive-cleanup
    tool: shell
    match: rm -rf ~/Documents
    action: allow
    reason: 已知安全场景：清理文档目录
    priority: 1
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file, watchPolicy: false })
  await fiber
  const run = (t, p) => root.bail('guardian/check', t, p)
  // 内置 CMD-002 (block) 被策略豁免
  assert.equal(isBlocked(run('shell', 'rm -rf ~/Documents')), false)
  // 但密钥扫描不受豁免——明文凭据任何场景都不放行
  assert.ok(isBlocked(run('shell', 'rm -rf ~/Documents && echo AKIAIOSFODNN7EXAMPLE')))
  await fiber.dispose()
})

test('策略引擎：block 级策略走 guardian/approve 人工确认', async () => {
  const file = tmpYaml(`
policies:
  - id: block-force-push
    tool: [git, gh]
    match: push.*--force
    action: block
    reason: 禁止强推远端
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file, watchPolicy: false })
  await fiber
  let asked = null
  root.on('guardian/approve', (req) => { asked = req; return { approved: false } })
  const r = root.bail('guardian/check', 'git', 'git push origin main --force')
  assert.ok(isBlocked(r))
  assert.equal(r.ruleId, 'block-force-push')
  assert.equal(asked.rule.id, 'block-force-push')
  await fiber.dispose()
})

test('策略引擎：热加载——文件变化自动生效并广播事件', async () => {
  const file = tmpYaml(`
policies:
  - id: deny-rm
    tool: shell
    match: rm
    action: deny
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file })   // watchPolicy 默认 true
  await fiber

  const events = []
  root.on('guardian/policy-loaded', (res) => events.push(res))

  // 初始：rm 命中 deny
  assert.ok(isBlocked(root.bail('guardian/check', 'shell', 'rm x')))
  // 改写策略：换成只拦 mkfs
  fs.writeFileSync(file, `
policies:
  - id: deny-mkfs
    tool: shell
    match: mkfs
    action: deny
`)
  // fs.watchFile interval=1000ms，等待触发
  await new Promise(r => setTimeout(r, 2500))
  assert.equal(events.length, 1)
  assert.equal(events[0].ok, true)
  assert.equal(events[0].count, 1)
  // 旧策略下线、新策略生效
  assert.equal(isBlocked(root.bail('guardian/check', 'shell', 'rm x')), false)
  assert.ok(isBlocked(root.bail('guardian/check', 'shell', 'mkfs.ext4 /dev/sda')))
  await fiber.dispose()
})

test('策略热加载安全回退：坏 YAML 保留旧策略并写审计', async () => {
  const logFile = path.join(os.tmpdir(), `dsh-policy-audit-${Date.now()}.log`)
  const file = tmpYaml(`
policies:
  - id: deny-rm
    tool: shell
    match: rm
    action: deny
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file, logFile })
  await fiber

  fs.writeFileSync(file, 'policies: [ totally broken {{{')
  await new Promise(r => setTimeout(r, 2500))

  // 旧策略仍在生效
  assert.ok(isBlocked(root.bail('guardian/check', 'shell', 'rm x')))
  assert.equal(root.guardian.listPolicies().length, 1)
  // 审计记录了回退事件
  const entries = root.guardian.readAudit(50)
  const fallback = entries.find(e => e.ruleId === 'POLICY-LOAD')
  assert.ok(fallback, '应有 POLICY-LOAD 审计记录')
  assert.match(fallback.reason, /保留/)
  await fiber.dispose()
})

test('策略引擎：reloadPolicy 手动重载', async () => {
  const file = tmpYaml(`
policies:
  - id: p1
    tool: a
    action: log
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file, watchPolicy: false })
  await fiber

  const result = root.guardian.reloadPolicy()
  assert.equal(result.ok, true)
  assert.equal(result.count, 1)
  await fiber.dispose()
})

test('策略引擎：卸载时停止文件监听（可逆效应）', async () => {
  const file = tmpYaml(`
policies:
  - id: deny-rm
    tool: shell
    match: rm
    action: deny
`)
  const root = new Context()
  const fiber = root.plugin(plugin, { policyFile: file })
  await fiber
  assert.ok(isBlocked(root.bail('guardian/check', 'shell', 'rm x')))
  await fiber.dispose()
  // 卸载后再改文件：watcher 已停（可逆效应清理），不影响也不抛错
  fs.writeFileSync(file, 'policies: [ broken')
  await new Promise(r => setTimeout(r, 1500))
  assert.ok(true)
})
