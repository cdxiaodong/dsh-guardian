# dsh-guardian

> **Agent 安全护栏** · 基于 [Cordis](https://github.com/cordiverse/cordis) 时空可组合元内核的 DeepSeek Harness 插件。
> 在 Agent 每次工具调用前做安全审查，命中危险即拦截或要求人工确认。

[![CI](https://github.com/cdxiaodong/dsh-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/cdxiaodong/dsh-guardian/actions/workflows/ci.yml)

---

## 🎯 解决什么问题

LLM Agent（Claude Code / DeepSeek Harness）能自主执行 shell、读写文件、发网络请求。一旦被**提示注入**、**工具投毒**或**模型误判**带偏，可能在你不知情时 `rm -rf`、读取 `.ssh/id_rsa`、把密钥外泄到远程。本插件是一道**运行时安全网**：

```
Agent 想执行工具 → guardian/check 前置审查 → 命中规则 → 拦截 / 人工批准 → 才放行
```

## 🛡️ 五大检测引擎

| 引擎 | 检测内容 | 借鉴来源 |
|---|---|---|
| **CMD/INJ** 危险命令 | rm -rf、dd、mkfs、fork炸弹、反弹shell、管道执行、提权 | Sigma 规则、PayloadsAllTheThings |
| **CRED** 凭据保护 | 读 .ssh/.aws/.env/kubeconfig、/etc/shadow | mcp-safeguard CRED 系列 |
| **SECRET** 密钥泄露 | AWS/GitHub/OpenAI/Anthropic/Slack/Stripe 等 25+ 种密钥正则 + Shannon 熵过滤降误报 | gitleaks、trufflehog |
| **SSRF** 网络目标 | 云 metadata（169.254.169.254）、内网网段、file://、gopher:// | mcp-safeguard SS 系列 |
| **PI/TP** 提示注入+工具投毒 | ignore previous instructions、DAN越狱、零宽字符、HTML注释藏指令、瞒用户指令 | Rebuff、LLM Guard、Vigil |

外加：

- **路径沙箱**（`guardian/path`）：realpath 解析 + 白名单根目录 + 编码变体解码 + 空字节截断检测——比纯正则可靠
- **风险评分引擎**（`risk.ts`）：多信号并集概率式加权成 0~1 分，按阈值分级处置（deny/block/warn/allow）
- **Kairos 延迟判定门**（`kairos.ts`，事务化执法）：缝合 [Kairos](https://arxiv.org/abs/2610.18457)（arXiv:2610.18457）——**合法动作与攻击第一步在单点观测上不可分，区分证据出现在后续 trace 里**。只会 allow/deny 的监视器被迫在证据积累前裁决；本引擎引入第三态 `defer`（扣留）：`log` 级灰区信号（读 shell history、DNS 子域名特征等）不再"记录后放行"，而是扣留待裁决——Agent 继续投机执行，后续每次工具调用都作为 trace 证据按**类别亲和度**累积（凭据读取 ↔ 外泄 = 0.9，经典攻击链的两半），过阈确定性拒绝。事务语义：`defer`=BEGIN / `release`=COMMIT / `refuse`=ROLLBACK；**有界权威原则**——确定性层只能 refuse（证据过阈 / TTL 过期 / 预算驱逐），release 权只属于 oracle（`guardian/adjudicate`）与任务结算（`guardian/settle` commit），无人裁决时 fail-safe 全拒（借鉴 LLMSentinel 的 deterministic fail-safe policy layer）。默认关闭，`kairos: { enabled: true }` 开启

## 🚦 四级处置

| 级别 | 行为 | 例子 |
|---|---|---|
| `deny` | 直接拒绝 | 反弹shell、mkfs、读 /etc/shadow、明文密钥 |
| `block` | 需人工确认（走 `guardian/approve`） | rm -rf ~、读 .ssh、curl 上传文件 |
| `defer` | **扣留暂缓**（Kairos：证据累积 / oracle 裁决 / 任务结算后再 release 或 refuse） | 读 shell history、可疑 DNS 子域名 |
| `log` | 仅记录审计 | 路径穿越 |

## 📦 安装

```bash
dsh plugin --profile web add github:cdxiaodong/dsh-guardian
```

## 🚀 用法

```js
import { Context } from 'cordis'
import * as guardian from 'dsh-guardian'

const ctx = new Context()
ctx.plugin(guardian, {
  allowedRoots: ['/home/user/workspace'],   // 可选：文件访问沙箱白名单
  scanSecrets: true, scanSSRF: true,        // 开关各引擎
  kairos: { enabled: true, ttlMs: 60_000 }, // 可选：延迟判定门（默认关闭）
})

// ① 接入人工批准（无此监听器时 block 级默认拒绝）
ctx.on('guardian/approve', async ({ tool, rule, snippet }) => {
  const ok = await confirm(`${rule.reason}：${snippet}`)  // 你的 UI 弹窗
  return { approved: ok }
})

// ② 工具调用前审查（同步短路）
const r = ctx.bail('guardian/check', toolName, args)
if (r && r.intercepted) {
  if (r.action === 'defer') {
    // Kairos 扣留：不执行但 Agent 可继续其他工作；后续证据过阈会自动 refuse，
    // 也可主动调 ctx.guardian.adjudicate() 交给 oracle 裁决
  } else throw new Error(`已拦截：${r.reason}`)
}

// ③ 文件访问前校验路径
const v = ctx.bail('guardian/path', filePath)
if (v && v.safe === false) throw new Error(`路径被拦截：${v.reason}`)

// ④ Kairos oracle 裁决（可选）：扣留效应连同累积证据交给你的 LM/人工
ctx.on('guardian/adjudicate', (items) => ({
  verdicts: items.map(i => ({ id: i.id, verdict: judge(i) ? 'release' : 'refuse' })),
}))
ctx.guardian.adjudicate()

// ⑤ 任务结束结算（事务边界）：成功 commit 释放剩余扣留；失败 abort 全拒
ctx.bail('guardian/settle', 'commit')

// ⑥ 查审计日志
console.log(ctx.guardian.readAudit(20))
```

## 🔧 对应论文机制

| Cordis / 时空可组合概念 | 本插件体现 |
|---|---|
| 响应式协效应（provide/inject） | `provide=['guardian']` 对外提供服务；依赖 cordis 事件系统 |
| 可逆效应（Revertible Effects） | `ctx.effect(() => () => stream.end())` 注册撤销函数，卸载自动关文件流、零残留 |
| 拦截机制（Intercept） | `ctx.bail('guardian/check')` 全局短路拦截，不改被保护组件代码 |
| 时间维度（Kairos 事务化执法） | 扣留账本把裁决从"调用瞬间"延展到"trace 时间窗"：`guardian/settle` 事务边界、`guardian/adjudicate` 有界权威 oracle，证据随每次调用累积 |
| 隔离机制 | 多实例可绑定独立配置/白名单 |

## 🧪 测试

```bash
npm ci && npm test     # 43/43 通过
```

## 🙏 致谢 / 参考

本插件的规则与架构缝合自以下优秀开源方案：

- [Kairos: Transactional Security Enforcement at the System Boundary for LLM Agents](https://arxiv.org/abs/2610.18457) — 延迟判定门：defer/证据累积/oracle 裁决的事务化执法（AgentDojo 攻击成功率 47.0%→2.7%）
- [LLMSentinel](https://github.com/ayushmgarg/LLMSentinel) — deterministic fail-safe policy layer（无人裁决宁可错拒）
- [gitleaks](https://github.com/gitleaks/gitleaks) — 密钥正则库 + 熵过滤
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — 密钥检测器设计
- [protectai/llm-guard](https://github.com/protectai/llm-guard) — scanner pipeline 架构
- [protectai/rebuff](https://github.com/protectai/rebuff) — 四层纵深检测思想
- [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — 提示注入签名
- [SyedAnas01/mcp-safeguard](https://github.com/SyedAnas01/mcp-safeguard) — TP/PI/SSRF/CRED 规则分类法
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — 危险命令检测规则

> ⚠️ **安全认知**：所有正则/启发式护栏都可能被绕过（对抗样本实测可绕过多种护栏）。本插件是 **risk reducer**，关键操作仍需**人在环确认 + 最小权限沙箱**，不能替代这两者。

## 📜 License

MIT
