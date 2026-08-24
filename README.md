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
- **工具清单完整性引擎**（`guardian/tools`，引擎 11）：**运行时 rug-pull 检测**——MCP 服务端在工具过审后偷偷改描述/schema？首次观察即 pin 住 hash 基线（或用 `manifestBaseline` 配置 pin 锁，类似 package-lock），之后描述被改=deny（TI-001）、schema 漂移=重授权（TI-002）、中途新增工具=人工确认（TI-003）、同形异码抢注名（`seаrch` 仿冒 `search`）=deny（TI-005）。借鉴 OWASP MCP03:2025、Invariant Labs mcp-scan（把静态扫描语义搬进运行时）
- **风险评分引擎**（`risk.ts`）：多信号并集概率式加权成 0~1 分，按阈值分级处置（deny/block/warn/allow）

## 🚦 三级处置

| 级别 | 行为 | 例子 |
|---|---|---|
| `deny` | 直接拒绝 | 反弹shell、mkfs、读 /etc/shadow、明文密钥 |
| `block` | 需人工确认（走 `guardian/approve`） | rm -rf ~、读 .ssh、curl 上传文件 |
| `log` | 仅记录审计 | 路径穿越、读取 shell history |

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
})

// ① 接入人工批准（无此监听器时 block 级默认拒绝）
ctx.on('guardian/approve', async ({ tool, rule, snippet }) => {
  const ok = await confirm(`${rule.reason}：${snippet}`)  // 你的 UI 弹窗
  return { approved: ok }
})

// ② 工具调用前审查（同步短路）
const r = ctx.bail('guardian/check', toolName, args)
if (r && r.intercepted) throw new Error(`已拦截：${r.reason}`)

// ③ 文件访问前校验路径
const v = ctx.bail('guardian/path', filePath)
if (v && v.safe === false) throw new Error(`路径被拦截：${v.reason}`)

// ④ 工具清单刷新时校验完整性（防 rug-pull：工具过审后被偷偷改描述/schema）
const mv = ctx.bail('guardian/tools', sessionId, toolSpecs)
if (mv && mv.safe === false) throw new Error(`清单被拒绝：${mv.findings.map(f => f.reason).join('；')}`)

// ⑤ 查审计日志
console.log(ctx.guardian.readAudit(20))
```

可选：用 pin 锁把工具清单钉死（在受控环境生成一次，写进配置，之后任何漂移都要求重新授权）：

```js
import { pinManifest } from 'dsh-guardian'

const lock = pinManifest(toolsSpecs)   // { "search": "sha256...", ... } 可入库审查
ctx.plugin(guardian, { manifestBaseline: lock, newToolPolicy: 'block' })
```

## 🔧 对应论文机制

| Cordis / 时空可组合概念 | 本插件体现 |
|---|---|
| 响应式协效应（provide/inject） | `provide=['guardian']` 对外提供服务；依赖 cordis 事件系统 |
| 可逆效应（Revertible Effects） | `ctx.effect(() => () => stream.end())` 注册撤销函数，卸载自动关文件流、零残留 |
| 拦截机制（Intercept） | `ctx.bail('guardian/check' / 'guardian/path' / 'guardian/tools')` 三条短路通道，不改被保护组件代码 |
| 隔离机制 | 多实例可绑定独立配置/白名单；工具完整性基线按 sessionId 隔离（空间可组合） |

## 🧪 测试

```bash
npm ci && npm test     # 29/29 通过
```

## 🙏 致谢 / 参考

本插件的规则与架构缝合自以下优秀开源方案：

- [gitleaks](https://github.com/gitleaks/gitleaks) — 密钥正则库 + 熵过滤
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — 密钥检测器设计
- [protectai/llm-guard](https://github.com/protectai/llm-guard) — scanner pipeline 架构
- [protectai/rebuff](https://github.com/protectai/rebuff) — 四层纵深检测思想
- [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — 提示注入签名
- [SyedAnas01/mcp-safeguard](https://github.com/SyedAnas01/mcp-safeguard) — TP/PI/SSRF/CRED 规则分类法
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — 危险命令检测规则
- [Invariant Labs mcp-scan](https://github.com/invariant-labs/mcp-scan) 与 [2025-04 工具投毒 PoC](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/) — "批准时 pin + 运行时重校验 + 变更即重授权" 语义（本插件将其搬进 Agent 运行时）
- [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-top-10-mcp-security-risks/) — MCP03 Tool Poisoning / rug-pull 子技术分类
- [arXiv:2506.01333](https://arxiv.org/abs/2506.01333) — Tool Squatting and Rug Pull Attacks in MCP（工具抢注威胁模型）

> ⚠️ **安全认知**：所有正则/启发式护栏都可能被绕过（对抗样本实测可绕过多种护栏）。本插件是 **risk reducer**，关键操作仍需**人在环确认 + 最小权限沙箱**，不能替代这两者。

## 📜 License

MIT
