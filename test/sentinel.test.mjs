import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as os from 'node:os'
import { Context } from 'cordis'
import * as plugin from '../lib/index.js'

const { scanSentinel, compileSentinelMatcher, resolveSentinelAssets } = plugin

// ── 测试脚手架：伪造资产清单 + 注入 homedir/platform，避免 $HOME 与真实安装路径漂移 ──
const HOME = '/home/tester'
const AUDIT = '/home/tester/.dsh-guardian.audit.log'
const PLUGDIR = '/home/tester/project/node_modules/dsh-guardian'
const OPTS = { homedir: HOME, platform: 'linux' }
const ASSETS = resolveSentinelAssets({ logFile: AUDIT, packageRoot: PLUGDIR, extra: ['/home/tester/.host-hook.sh'] })
  // 归一化脚手架：resolveSentinelAssets 用真实 homedir 推 integrity-state，这里手动替换成注入的 HOME
  .map((a) => a.kind === 'integrity-state' ? { ...a, path: path.join(HOME, '.dsh-guardian.memory.json') } : a)

const scan = (tool, text) => scanSentinel(tool, text, ASSETS, OPTS)
const hitIds = (tool, text) => scan(tool, text).map((h) => h.ruleId)
const wait = () => new Promise(r => setTimeout(r, 200))
const isBlocked = (r) => typeof r === 'object' && r !== null && r.intercepted === true

// ── SELF 组：护栏资产 × 破坏动词 ─────────────────────────
test('SELF-001：删除/移动审计日志与插件文件', () => {
  assert.ok(hitIds('bash', `rm -f ${AUDIT}`).includes('SELF-001'))
  assert.ok(hitIds('bash', 'rm -f ~/.dsh-guardian.audit.log').includes('SELF-001'))
  assert.ok(hitIds('bash', 'sudo shred -u $HOME/.dsh-guardian.audit.log').includes('SELF-001'))
  assert.ok(hitIds('bash', `mv ${AUDIT} /tmp/loot`).includes('SELF-001'))
  assert.ok(hitIds('bash', 'rm -rf ~/project/node_modules/dsh-guardian').includes('SELF-001'))
  assert.ok(hitIds('bash', 'rm ~/project/node_modules/dsh-guardian/lib/index.js').includes('SELF-001'))
})

test('SELF-002：截断/覆写/重定向伪造审计日志', () => {
  assert.ok(hitIds('bash', ': > ~/.dsh-guardian.audit.log').includes('SELF-002'))
  assert.ok(hitIds('bash', 'echo -n "" > ~/.dsh-guardian.audit.log').includes('SELF-002'))
  assert.ok(hitIds('bash', 'truncate -s 0 ~/.dsh-guardian.audit.log').includes('SELF-002'))
  assert.ok(hitIds('bash', 'dd if=/dev/null of=~/.dsh-guardian.audit.log').includes('SELF-002'))
  assert.ok(hitIds('bash', 'echo "[]" >> $HOME/.dsh-guardian.audit.log').includes('SELF-002'))
  assert.ok(hitIds('bash', 'cp /tmp/fake.log ~/.dsh-guardian.audit.log').includes('SELF-002'))
})

test('SELF-003/004：黑洞化与权限冻结（活着但失明）', () => {
  assert.ok(hitIds('bash', 'ln -sf /dev/null ~/.dsh-guardian.audit.log').includes('SELF-003'))
  assert.ok(hitIds('bash', 'chmod 000 ~/.dsh-guardian.audit.log').includes('SELF-004'))
  assert.ok(hitIds('bash', 'chattr +i ~/.dsh-guardian.audit.log').includes('SELF-004'))
  assert.ok(hitIds('bash', 'chflags uchg ~/.dsh-guardian.audit.log').includes('SELF-004'))
})

test('SELF-005/006：卸载护栏与杀护栏进程（文本级）', () => {
  assert.ok(hitIds('bash', 'npm uninstall dsh-guardian').includes('SELF-005'))
  assert.ok(hitIds('bash', 'yarn remove dsh-guardian').includes('SELF-005'))
  assert.ok(hitIds('bash', 'pnpm remove dsh-guardian').includes('SELF-005'))
  assert.ok(hitIds('bash', 'pkill -f dsh-guardian').includes('SELF-006'))
  assert.ok(hitIds('bash', 'killall dsh-guardian').includes('SELF-006'))
  assert.ok(hitIds('bash', 'kill $(pgrep dsh-guardian)').includes('SELF-006'))
})

test('SELF-007：写入类工具直指护栏资产（#11226 场景：Edit/Write 改 hook 源码）', () => {
  assert.ok(hitIds('Edit', JSON.stringify({ file_path: `${PLUGDIR}/lib/index.js`, old_string: 'a', new_string: 'b' })).includes('SELF-007'))
  assert.ok(hitIds('write_file', `${PLUGDIR}/cordis.patch.yml`).includes('SELF-007'))
  // 宿主追加资产同样受保护
  assert.ok(hitIds('write_file', '/home/tester/.host-hook.sh').includes('SELF-007'))
})

// ── 归一化：~/$HOME/编码/../ 通配符 ──────────────────────
test('归一化组：~/$HOME/编码/穿越/通配符 均命中同一规则', () => {
  const variants = [
    'rm -f ~/.dsh-guardian.audit.log',
    'rm -f $HOME/.dsh-guardian.audit.log',
    `rm -f ${AUDIT}`,
    'rm -f ~/%2E%64sh-guardian%2Eaudit%2Elog',
    'rm -f ~/docs/../.dsh-guardian.audit.log',
    'rm -f ~/.dsh-guardian.audit.log/',
    'rm -f ~/.dsh-guardian*',
  ]
  for (const v of variants) {
    assert.ok(hitIds('bash', v).includes('SELF-001'), `应命中 SELF-001：${v}`)
  }
})

// ── 负例：不误伤 ─────────────────────────────────────────
test('负例：非护栏资产的常规操作不命中 SELF 组', () => {
  assert.deepEqual(hitIds('bash', 'rm ./app.log'), [])
  assert.deepEqual(hitIds('bash', 'rm -rf /tmp/build'), [])
  assert.deepEqual(hitIds('bash', 'npm uninstall lodash'), [])
  assert.deepEqual(hitIds('bash', 'cat ~/.dsh-guardian.audit.log'), [])          // 读不拦
  assert.deepEqual(hitIds('bash', 'tail -f app.log'), [])
  assert.deepEqual(hitIds('bash', 'echo done > build.log'), [])
  assert.deepEqual(hitIds('bash', 'grep rm lib/index.js'), [])                   // 动词在参数位
  assert.deepEqual(hitIds('bash', 'ls -la /var/log/'), [])
  assert.deepEqual(hitIds('Edit', JSON.stringify({ file_path: '/home/tester/app/src/x.ts' })), [])
  assert.deepEqual(hitIds('bash', 'kill 1234'), [])
  assert.deepEqual(hitIds('bash', 'pkill -f dsh-guardian-ui-helper'), [])        // 子串防误报
})

// ── FORENSIC 组：反取证 ──────────────────────────────────
test('FORENSIC-001/002/003：系统日志销毁/截断/黑洞化（走人工确认）', () => {
  assert.ok(hitIds('bash', 'rm /var/log/syslog').includes('FORENSIC-001'))
  assert.ok(hitIds('bash', 'shred -u /var/log/audit/audit.log').includes('FORENSIC-001'))
  assert.ok(hitIds('bash', ': > /var/log/secure').includes('FORENSIC-002'))
  assert.ok(hitIds('bash', 'truncate -s 0 /private/var/log/system.log').includes('FORENSIC-002'))
  assert.ok(hitIds('bash', 'ln -sf /dev/null /var/log/auth.log').includes('FORENSIC-003'))
})

test('FORENSIC-004/005：关审计子系统与清 shell 历史', () => {
  assert.ok(hitIds('bash', 'auditctl -e 0').includes('FORENSIC-004'))
  assert.ok(hitIds('bash', 'history -c').includes('FORENSIC-005'))
  assert.ok(hitIds('bash', 'unset HISTFILE').includes('FORENSIC-005'))
  assert.ok(hitIds('bash', 'export HISTFILE=/dev/null').includes('FORENSIC-005'))
  assert.ok(hitIds('bash', 'shred -u ~/.bash_history').includes('FORENSIC-005'))
  // 负例：非 HISTFILE 的 /dev/null 赋值、项目级截断、只读
  assert.deepEqual(hitIds('bash', 'export FOO=/dev/null'), [])
  assert.deepEqual(hitIds('bash', 'truncate -s 100 data.sql'), [])
  assert.deepEqual(hitIds('bash', 'cat /var/log/syslog'), [])
})

// ── 处置级别 ─────────────────────────────────────────────
test('SELF 组 deny 级 / FORENSIC 组 block 级', () => {
  const selfHit = scan('bash', `rm ${AUDIT}`)[0]
  assert.equal(selfHit.action, 'deny')
  const forensicHit = scan('bash', 'rm /var/log/syslog')[0]
  assert.equal(forensicHit.action, 'block')
})

// ── 匹配器复用（无状态、可重复调用）──────────────────────
test('compileSentinelMatcher 可复用且行为一致', () => {
  const m = compileSentinelMatcher(ASSETS, OPTS)
  for (let i = 0; i < 3; i++) {
    assert.ok(m.scan('bash', `rm ${AUDIT}`).some(h => h.ruleId === 'SELF-001'))
    assert.deepEqual(m.scan('bash', 'ls -la'), [])
  }
})

// ── darwin 大小写不敏感 ──────────────────────────────────
test('darwin 平台路径大小写不敏感', () => {
  const mac = scanSentinel('bash', 'rm -f ~/.DSH-GUARDIAN.AUDIT.LOG', ASSETS, { homedir: HOME, platform: 'darwin' })
  assert.ok(mac.some(h => h.ruleId === 'SELF-001'))
})

// ── 资产解析 ─────────────────────────────────────────────
test('resolveSentinelAssets：返回审计日志/基线/插件目录，含追加资产', () => {
  const assets = resolveSentinelAssets({ logFile: '/tmp/audit.log', packageRoot: '/tmp/pkg', extra: ['/tmp/hook.sh'] })
  assert.ok(assets.some(a => a.kind === 'audit-log' && a.path === '/tmp/audit.log'))
  assert.ok(assets.some(a => a.kind === 'integrity-state'))
  assert.ok(assets.some(a => a.kind === 'plugin-dir' && a.path === '/tmp/pkg'))
  assert.ok(assets.some(a => a.kind === 'extra' && a.path === '/tmp/hook.sh'))
})

// ── 服务集成：guardian/check 通道 + 审计落盘 ─────────────
test('集成：经 guardian/check 拦截护栏自毁并落审计（engine=sentinel）', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-'))
  const logFile = path.join(tmp, 'audit.log')
  const root = new Context()
  root.plugin(plugin, { logFile })
  await wait()
  const run = (t, p) => root.bail('guardian/check', t, p)

  // deny 级：删审计日志（配置的 logFile 也是资产）
  const blocked = run('bash', `rm -f ${logFile}`)
  assert.ok(isBlocked(blocked))
  assert.equal(blocked.engine, 'sentinel')
  assert.equal(blocked.action, 'deny')

  // deny 级：卸载护栏
  assert.ok(isBlocked(run('bash', 'npm uninstall dsh-guardian')))

  // block 级：清系统日志 → 无 approve 默认拦截，有 approve 放行
  assert.ok(isBlocked(run('bash', 'rm /var/log/syslog')))
  root.on('guardian/approve', () => ({ approved: true }))
  assert.equal(isBlocked(run('bash', 'rm /var/log/syslog')), false)

  // 常规命令不受影响（cordis bail 放行返回 falsy）
  assert.ok(!isBlocked(run('bash', 'ls -la /tmp')))
  assert.ok(!isBlocked(run('bash', 'cat README.md')))

  await wait()
  const audit = root.guardian.readAudit(20)
  assert.ok(audit.some(a => a.engine === 'sentinel' && a.level === 'deny'))
  fs.rmSync(tmp, { recursive: true, force: true })
})

test('集成：guardianSelf=false 关闭哨兵引擎', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-off-'))
  const logFile = path.join(tmp, 'audit.log')
  const root = new Context()
  root.plugin(plugin, { logFile, guardSelf: false })
  await wait()
  assert.ok(!isBlocked(root.bail('guardian/check', 'bash', `rm -f ${logFile}`)))
  fs.rmSync(tmp, { recursive: true, force: true })
})
