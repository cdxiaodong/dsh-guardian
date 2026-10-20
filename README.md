# dsh-guardian

> **Agent security guardrail** · a DeepSeek Harness plugin built on the [Cordis](https://github.com/cordiverse/cordis) spatio-temporal composable meta-kernel.
> Performs a security review before every tool call the Agent makes; if a dangerous operation is matched, it blocks it or requires manual confirmation.

[![CI](https://github.com/cdxiaodong/dsh-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/cdxiaodong/dsh-guardian/actions/workflows/ci.yml)

---

## 🎯 What problem it solves

LLM Agents (Claude Code / DeepSeek Harness) can autonomously run shell commands, read and write files, and make network requests. If they are steered by **prompt injection**, **tool poisoning**, or **model misjudgment**, they can run `rm -rf`, read `.ssh/id_rsa`, or exfiltrate keys to a remote host without your knowledge. This plugin is a **runtime safety net**:

```
Agent wants to run a tool → guardian/check pre-review → rule matched → block / manual approval → only then allowed
```

## 🛡️ Five Detection Engines

| Engine | What it detects | Inspired by |
|---|---|---|
| **CMD/INJ** dangerous commands | rm -rf, dd, mkfs, fork bombs, reverse shells, pipe-to-shell execution, privilege escalation | Sigma rules, PayloadsAllTheThings |
| **CRED** credential protection | reading .ssh/.aws/.env/kubeconfig, /etc/shadow | mcp-safeguard CRED series |
| **SECRET** secret leakage | regexes for 25+ secret types (AWS/GitHub/OpenAI/Anthropic/Slack/Stripe, etc.) + Shannon entropy filtering to reduce false positives | gitleaks, trufflehog |
| **SSRF** network targets | cloud metadata (169.254.169.254), internal network ranges, file://, gopher:// | mcp-safeguard SS series |
| **PI/TP** prompt injection + tool poisoning | ignore previous instructions, DAN jailbreaks, zero-width characters, HTML comments hiding instructions, instructions to conceal from the user | Rebuff, LLM Guard, Vigil |

In addition:

- **Path sandbox** (`guardian/path`): realpath resolution + allowlisted root directories + encoded-variant decoding + null-byte truncation detection — more reliable than pure regex
- **Risk scoring engine** (`risk.ts`): multiple signals are combined via a probabilistic weighted union into a 0~1 score, which maps to a disposition by threshold (deny/block/warn/allow)

## 🚦 Three Disposition Levels

| Level | Behavior | Examples |
|---|---|---|
| `deny` | Reject outright | reverse shell, mkfs, reading /etc/shadow, plaintext secrets |
| `block` | Requires manual confirmation (via `guardian/approve`) | rm -rf ~, reading .ssh, curl uploading a file |
| `log` | Audit record only | path traversal, reading shell history |

## 📦 Installation

```bash
dsh plugin --profile web add github:cdxiaodong/dsh-guardian
```

## 🚀 Usage

```js
import { Context } from 'cordis'
import * as guardian from 'dsh-guardian'

const ctx = new Context()
ctx.plugin(guardian, {
  allowedRoots: ['/home/user/workspace'],   // optional: file-access sandbox allowlist
  scanSecrets: true, scanSSRF: true,        // toggle each engine
})

// ① Hook up manual approval (without this listener, block-level defaults to deny)
ctx.on('guardian/approve', async ({ tool, rule, snippet }) => {
  const ok = await confirm(`${rule.reason}: ${snippet}`)  // your UI dialog
  return { approved: ok }
})

// ② Pre-tool-call review (synchronous short-circuit)
const r = ctx.bail('guardian/check', toolName, args)
if (r && r.intercepted) throw new Error(`Blocked: ${r.reason}`)

// ③ Validate the path before file access
const v = ctx.bail('guardian/path', filePath)
if (v && v.safe === false) throw new Error(`Path blocked: ${v.reason}`)

// ④ Query the audit log
console.log(ctx.guardian.readAudit(20))
```

## 🔧 Corresponding Paper Mechanisms

| Cordis / spatio-temporal composable concept | How this plugin reflects it |
|---|---|
| Reactive co-effects (provide/inject) | `provide=['guardian']` exposes the service to others; relies on the cordis event system |
| Revertible Effects | `ctx.effect(() => () => stream.end())` registers an undo function; on unload, file streams are closed automatically, leaving zero residue |
| Intercept mechanism | `ctx.bail('guardian/check')` global short-circuit interception, without modifying the protected component's code |
| Isolation mechanism | multiple instances can bind independent configurations/allowlists |

## 🧪 Testing

```bash
npm ci && npm test     # unit + coverage tests (every rule id has positive/negative fixtures)
```

## 🙏 Acknowledgements / References

The rules and architecture of this plugin are stitched together from the following excellent open-source projects:

- [gitleaks](https://github.com/gitleaks/gitleaks) — secret regex library + entropy filtering
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — secret detector design
- [protectai/llm-guard](https://github.com/protectai/llm-guard) — scanner pipeline architecture
- [protectai/rebuff](https://github.com/protectai/rebuff) — the four-layer defense-in-depth detection idea
- [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — prompt injection signatures
- [SyedAnas01/mcp-safeguard](https://github.com/SyedAnas01/mcp-safeguard) — TP/PI/SSRF/CRED rule taxonomy
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — dangerous command detection rules

> ⚠️ **Security note**: All regex/heuristic guardrails can be bypassed (adversarial examples have been shown to bypass several guardrails). This plugin is a **risk reducer**; critical operations still require **human-in-the-loop confirmation + least-privilege sandboxing**, and it cannot replace either of these.

## 📜 License

MIT
