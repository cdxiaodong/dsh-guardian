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

## 🛡️ 六大检测引擎

| 引擎 | 检测内容 | 借鉴来源 |
|---|---|---|
| **CMD/INJ** 危险命令 | rm -rf、dd、mkfs、fork炸弹、反弹shell、管道执行、提权 | Sigma 规则、PayloadsAllTheThings |
| **CRED** 凭据保护 | 读 .ssh/.aws/.env/kubeconfig、/etc/shadow | mcp-safeguard CRED 系列 |
| **SECRET** 密钥泄露 | AWS/GitHub/OpenAI/Anthropic/Slack/Stripe 等 25+ 种密钥正则 + Shannon 熵过滤降误报 | gitleaks、trufflehog |
| **SSRF** 网络目标 | 云 metadata（169.254.169.254）、内网网段、file://、gopher:// | mcp-safeguard SS 系列 |
| **PI/TP** 提示注入+工具投毒 | ignore previous instructions、DAN越狱、零宽字符、HTML注释藏指令、瞒用户指令 | Rebuff、LLM Guard、Vigil |
| **DNS** 隐蔽信道 | 域名标签 hex/base32 编码、超长标签（63 字节上限）、分块隧道、DoH 编码查询 | CSA "AI Sandbox DNS Escape"研究笔记、dnscat2/iodine 隧道特征、DGA 检测 |

外加：

- **路径沙箱**（`guardian/path`）：realpath 解析 + 白名单根目录 + 编码变体解码 + 空字节截断检测——比纯正则可靠
- **DNS 隧道校验**（`guardian/dns`）：沙箱封了 HTTP 封不了 DNS——数据编码进域名标签用一条 `dig`/DoH 请求即可出境，此通道在 DNS 查询前独立校验
- **风险评分引擎**（`risk.ts`）：多信号并集概率式加权成 0~1 分，按阈值分级处置（deny/block/warn/allow）

## 🚦 三级处置

| 级别 | 行为 | 例子 |
|---|---|---|
| `deny` | 直接拒绝 | 反弹shell、mkfs、读 /etc/shadow、明文密钥、DNS 隧道编码标签 |
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
| 拦截机制（Intercept） | `ctx.bail('guardian/check')` 全局短路拦截，不改被保护组件代码 |
| 隔离机制 | 多实例可绑定独立配置/白名单 |

## 🧪 测试

```bash
npm ci && npm test     # 19/19 通过
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
- [Cloud Security Alliance: AI Sandbox DNS Escape and Exfiltration](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-sandbox-dns-exfiltration-bedrock-langsm/) — "沙箱隔离仍放行出站 DNS"的威胁模型（DNS 隧道引擎依据）
- [arthepsy/dnscat2](https://github.com/iagox86/dnscat2) / [yarrick/iodine](https://code.kryo.se/iodine/) — DNS 隧道工具的 base32 分块编码特征

> ⚠️ **安全认知**：所有正则/启发式护栏都可能被绕过（对抗样本实测可绕过多种护栏）。本插件是 **risk reducer**，关键操作仍需**人在环确认 + 最小权限沙箱**，不能替代这两者。
>
> ⚠️ **DNS 引擎已知局限**：小写 base32 编码与英文单词同字符集，无法用确定性规则区分（业界 DGA 检测同样难题），由超长标签/分块/高熵特征兜底；建议宿主网络层另行限制递归 DNS 出站。

## 📜 License

MIT
