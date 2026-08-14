# dsh-guardian

> Agent 安全护栏：拦截并审计 DeepSeek Harness 的所有工具调用，命中敏感操作就要求人工确认。

## 功能

- 🔍 **全量审计**：每次工具调用都写入本地 `~/.dsh-guardian.audit.log`
- 🛡️ **危险拦截**：内置规则（rm -rf、写盘、fork 炸弹、读密钥、远程脚本管道…）命中即弹人工确认
- 📊 **可查询**：注册 `guardian_audit_query` 工具，Agent / 用户可随时拉取审计日志
- 🧩 **纯 Cordis 插件**：随插随拔，卸载自动清理，不污染宿主

## 安装

```bash
dsh plugin --profile web add dsh-guardian
```

或从 GitHub 直接装：

```bash
dsh plugin --profile web add github:你的用户名/dsh-guardian
```

## 自定义规则

编辑 `src/index.ts` 里的 `DANGER_RULES`，`npm run build` 后热替换即生效（无需重启）。

## License

MIT
