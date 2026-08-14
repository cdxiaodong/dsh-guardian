# dsh-guardian

> Agent 安全护栏 · 基于 [Cordis](https://github.com/cordiverse/cordis) 时空可组合元内核的 DeepSeek Harness 插件。
> 拦截并审计 Agent 的所有工具调用，命中敏感操作即要求人工确认。

## ✨ 特性

- 🛡️ **多引擎危险识别**：命令注入 / 破坏操作（rm -rf、dd、mkfs）/ 反弹 shell / 凭据读取 / 环境外泄 / git 强推
- 🚦 **三级处置**：`deny`（直接拒绝）/ `block`（需人工批准）/ `log`（仅审计）
- 📊 **全量审计**：每次工具调用写入本地 JSONL 日志，可查询
- 🧩 **纯 Cordis 插件**：随插随拔，`ctx.effect` 自动清理资源，卸载零残留（这正是时空可组合的时间维度）
- 🔌 **事件驱动接入**：通过 cordis `bail` 事件做同步短路拦截

## 📦 安装

```bash
dsh plugin --profile web add github:cdxiaodong/dsh-guardian
```

## 🚀 用法（宿主接入）

```js
import { Context } from 'cordis'
import * as guardian from 'dsh-guardian'

const ctx = new Context()
ctx.plugin(guardian)

// 可选：接入人工批准（无此监听器时 block 级操作默认拒绝）
ctx.on('guardian/approve', async ({ tool, rule, snippet }) => {
  const ok = await 弹窗确认(`${rule.reason}：${snippet}`)
  return { approved: ok }   // 约定返回 { approved: boolean }
})

// 每次工具调用前，用 bail 同步询问护栏：
const r = ctx.bail('guardian/check', toolName, args)
if (r && r.intercepted) {
  throw new Error(`已拦截：${r.reason}`)
}
// 否则继续执行工具
```

## 🔧 工作原理（对应论文机制）

| 论文概念 | 本插件体现 |
|---|---|
| 响应式协效应 | `provide = ['guardian']` 声明对外提供服务；`ctx.on('guardian/check')` 依赖事件系统 |
| 可逆效应 | `ctx.effect(() => () => stream.end())` 注册撤销函数，卸载自动关文件流 |
| 拦截机制 | `ctx.bail('guardian/check')` 全局短路拦截，不改被护栏保护的组件代码 |

## 🧪 测试

```bash
npm run build && node smoke.mjs   # 8/8 通过
```

## 📜 License

MIT
