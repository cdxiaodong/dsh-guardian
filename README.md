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
- **授权衰减引擎**（`delegation.ts`，DelegateGuard）：缝合 [DelegateGuard](https://arxiv.org/abs/2610.16005)（arXiv:2610.16005, Purpose-Bound Capabilities）——42 个引擎都在回答"这次调用危险吗"，唯一的批准语义 `guardian/approve` 却是一次性布尔，批准完就蒸发。本引擎管**批准本身的生命周期**：用户批准 → 编译成五维可衰减能力（purpose / labels / operations / sinks / delegation-depth）→ 后续同类操作**授权复用**（reference monitor：不再打扰用户）、子 agent **委派只减不增**（衰减律，IETF 衰减委派草案 / Red Hat 权限交集 2026 共识）、**撤销沿委派图级联**（先委派再撤销父也绕不过）。防论文五类攻击面：权限放大（DLG-001）、purpose gaming（词元继承检查）、授权外 sink（uncovered 转人工）、撤销/耗尽重放（DLG-002）、无限拉长委派链（DLG-004）。与污点追踪对偶：taint 跟数据走，capability 跟批准走。默认关闭，`delegation: { enabled: true }` 开启

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
  delegation: { enabled: true, defaultDepth: 2 },  // 可选：授权衰减（默认关）
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

// ④ 授权编译（DelegateGuard）：用户批准一次 → 铸成五维能力，同类操作免打扰复用
const { capability } = ctx.bail('guardian/grant', {
  purpose: '清理构建缓存',          // 用途声明（委派链 purpose 继承基准）
  operations: ['write'],             // 操作域
  sinks: ['/tmp'],                   // 路径前缀 / 域名白名单
  depth: 2, maxUses: 5,              // 可委派深度 / 预算
})
// 子 agent 委派：逐维只减不增（扩张 = 权限放大，当场 DLG-001 拒绝）
const sub = ctx.bail('guardian/delegate', capability.id, {
  purpose: '清理构建缓存子目录', operations: ['write'], sinks: ['/tmp/build'],
})
// 撤销级联：整棵委派子树一起失效，预委派的子能力绕不过对根的撤销
ctx.guardian.delegation.revoke(capability.id)

// ⑤ 查审计日志
console.log(ctx.guardian.readAudit(20))
```

## 🔧 对应论文机制

| Cordis / 时空可组合概念 | 本插件体现 |
|---|---|
| 响应式协效应（provide/inject） | `provide=['guardian']` 对外提供服务；依赖 cordis 事件系统 |
| 可逆效应（Revertible Effects） | `ctx.effect(() => () => stream.end())` 注册撤销函数，卸载自动关文件流、零残留 |
| 拦截机制（Intercept） | `ctx.bail('guardian/check')` 全局短路拦截，不改被保护组件代码 |
| 隔离机制 | 多实例可绑定独立配置/白名单 |
| 委派图（授权的可组合性） | `guardian/grant` / `guardian/delegate` 把用户批准编译成子能力——组合子能力 = 五维交集 + 深度递减，撤销按图级联；授权像组件一样可派生、可衰减、可回收 |

## 🧪 测试

```bash
npm ci && npm test     # 43/43 通过（19 基线 + 24 授权衰减）
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
- [DelegateGuard](https://arxiv.org/abs/2610.16005)（arXiv:2610.16005）— purpose-bound 五维可衰减能力 + 撤销级联穿透委派图

> ⚠️ **安全认知**：所有正则/启发式护栏都可能被绕过（对抗样本实测可绕过多种护栏）。本插件是 **risk reducer**，关键操作仍需**人在环确认 + 最小权限沙箱**，不能替代这两者。

## 📜 License

MIT
