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

## 🛡️ 检测引擎

**空间维度**（单次调用 · 无状态判定）：

| 引擎 | 检测内容 | 借鉴来源 |
|---|---|---|
| **CMD/INJ** 危险命令 | rm -rf、dd、mkfs、fork炸弹、反弹shell、管道执行、提权 | Sigma 规则、PayloadsAllTheThings |
| **CRED** 凭据保护 | 读 .ssh/.aws/.env/kubeconfig、/etc/shadow | mcp-safeguard CRED 系列 |
| **SECRET** 密钥泄露 | AWS/GitHub/OpenAI/Anthropic/Slack/Stripe 等 25+ 种密钥正则 + Shannon 熵过滤降误报 | gitleaks、trufflehog |
| **SSRF** 网络目标 | 云 metadata（169.254.169.254）、内网网段、file://、gopher:// | mcp-safeguard SS 系列 |
| **PI/TP** 提示注入+工具投毒 | ignore previous instructions、DAN越狱、零宽字符、HTML注释藏指令、瞒用户指令 | Rebuff、LLM Guard、Vigil |

**时空维度**（跨调用 · 会话级关联）：

| 引擎 | 检测内容 | 借鉴来源 |
|---|---|---|
| **TRIFECTA** 致命三角 | 会话滑动窗口内 **私有数据访问 + 不可信内容摄入 + 外部通信通道** 三者齐备即拦——单看每次调用可能都合法，组合才暴露数据外泄链 | Simon Willison「Lethal Trifecta」、Meta「Agents Rule of Two」、armosec「Agent Attack Kill Chain」 |

外加：

- **路径沙箱**（`guardian/path`）：realpath 解析 + 白名单根目录 + 编码变体解码 + 空字节截断检测——比纯正则可靠
- **风险评分引擎**（`risk.ts`）：多信号并集概率式加权成 0~1 分，按阈值分级处置（deny/block/warn/allow）

### 🕒 为什么需要时空维度引擎

现有引擎都是**无状态**的：每次工具调用独立判定。但真实的 Agent 数据外泄是**多步**的——先读凭据、再摄入被投毒的内容、最后把数据发出去，**每一步单独看都合法**。这正是 Simon Willison 提出的 [Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)：当 Agent 同时具备①私有数据访问②不可信内容摄入③外部通信能力时，间接提示注入即可驱动外泄。Meta 的 [Agents Rule of Two](https://www.facebook.com/ai/research) 进一步给出部署启发式：**一个会话最多只能占三条中的两条**。

引擎 7 把会话内每次调用投影到三类能力，记入一个滑动时间窗；三者齐备（三角成形）即拦截"补全三角"的那次调用，并在三角持续期间看住外部数据通道：

```
read_file notes.txt        → private-data     ✅ 放行（只占一条）
web_fetch <不可信网页>      → untrusted-content ✅ 放行（占两条，Rule of Two 仍合规）
http_post <外部地址>        → external-egress   🛑 三角成形，拦截并要求人工确认
```

可用 `ctx.guardian.trifectaStatus()` 查询当前窗口的能力分布（present/missing/counts），用 `trifectaWindowMs` / `trifectaAction` / `scanTrifecta` 配置窗口时长、处置动作与开关。

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

// ④ 查审计日志
console.log(ctx.guardian.readAudit(20))
```

## 🔧 对应论文机制

| Cordis / 时空可组合概念 | 本插件体现 |
|---|---|
| 响应式协效应（provide/inject） | `provide=['guardian']` 对外提供服务；依赖 cordis 事件系统 |
| 可逆效应（Revertible Effects） | `ctx.effect(() => () => stream.end())` 注册撤销函数，卸载自动关文件流、零残留 |
| 时空可组合-时间维度 | 引擎 7 用会话滑动窗口关联跨调用行为；`ctx.effect(() => () => trifecta.reset())` 卸载即清窗口 |
| 拦截机制（Intercept） | `ctx.bail('guardian/check')` 全局短路拦截，不改被保护组件代码 |
| 隔离机制 | 多实例可绑定独立配置/白名单 |

## 🧪 测试

```bash
npm ci && npm test     # 31/31 通过
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

时空维度引擎（引擎 7）的理论来源：

- [Simon Willison — The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) — 私有数据 + 不可信内容 + 外部通信三能力齐备即高危
- Meta AI — Agents Rule of Two — 一个会话最多只能占三条中的两条
- [armosec — The AI Agent Attack Kill Chain](https://www.armosec.io/blog/the-ai-agent-attack-kill-chain/) — 单步合法、序列形状才暴露攻击

> ⚠️ **安全认知**：所有正则/启发式护栏都可能被绕过（对抗样本实测可绕过多种护栏）。本插件是 **risk reducer**，关键操作仍需**人在环确认 + 最小权限沙箱**，不能替代这两者。

## 📜 License

MIT
