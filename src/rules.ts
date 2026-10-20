/** Dangerous rule definitions and built-in rule set */
export interface Rule {
  id: string
  pattern: RegExp
  reason: string
  /** block=requires manual confirmation; deny=reject outright; log=record only */
  action: 'block' | 'deny' | 'log'
  /** Rule category, for auditing and statistics */
  category?: 'destructive' | 'injection' | 'credential' | 'exfil' | 'network' | 'filesystem' | 'prompt-injection' | 'tool-poisoning' | 'privesc'
  /** Risk weight 0~1, for multi-signal weighted scoring (per research recommendation) */
  weight?: number
}

/**
 * Built-in rule set (grouped by category; rule IDs borrowed from the mcp-safeguard taxonomy: CMD/PI/TP/CRED/EXFIL/PATH/PRIV).
 * No regex uses the /g flag, to avoid lastIndex state pollution.
 */
export const DEFAULT_RULES: Rule[] = [
  // ── CMD: destructive operations ──────────────────────────────────────
  { id: 'CMD-001', category: 'destructive', weight: 0.9, pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+\/(\s|$|\*)/i, reason: 'Recursive delete of root directory', action: 'deny' },
  { id: 'CMD-002', category: 'destructive', weight: 0.7, pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+[~/]/i, reason: 'Recursive forced directory delete', action: 'block' },
  { id: 'CMD-003', category: 'destructive', weight: 0.95, pattern: /\bdd\s+if=.*of=\/dev\/|>\s*\/dev\/(sd|nvme|hd)/i, reason: 'dd/redirect overwrites disk device', action: 'deny' },
  { id: 'CMD-004', category: 'destructive', weight: 0.95, pattern: /\bmkfs(\.[a-z0-9]+)?\b/i, reason: 'Format filesystem', action: 'deny' },
  { id: 'CMD-005', category: 'destructive', weight: 0.95, pattern: /:\(\)\s*\{\s*:\s*\|\s*:.*\}\s*;\s*:/, reason: 'Fork bomb', action: 'deny' },
  { id: 'CMD-006', category: 'destructive', weight: 0.8, pattern: /\b(kill\s+-9\s+-1|killall\s+-9|shutdown|reboot|halt|poweroff)\b/i, reason: 'Kill all processes/shutdown', action: 'block' },
  { id: 'CMD-007', category: 'destructive', weight: 0.6, pattern: /\bshred\s+.*-[a-z]*u/i, reason: 'shred secure delete', action: 'block' },
  { id: 'CMD-008', category: 'destructive', weight: 0.7, pattern: /chmod\s+(-R\s+)?777\s+\//i, reason: 'Open permissions on system directories', action: 'block' },
  { id: 'CMD-009', category: 'destructive', weight: 0.9, pattern: /mv\s+\/\*\s+\/dev\/null/i, reason: 'Move root directory to /dev/null', action: 'deny' },

  // ── INJ: command injection / reverse shell (matches intent, not full payload) ──
  { id: 'INJ-001', category: 'injection', weight: 0.7, pattern: /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b|wget\s+.*-O-.*\|\s*(ba|z)?sh/i, reason: 'Remote script piped to shell', action: 'block' },
  { id: 'INJ-002', category: 'injection', weight: 0.95, pattern: /\/dev\/tcp\/\d|bash\s+-i\s+>&|bash\s+-i.*>&\s*\/dev\/tcp/i, reason: 'bash reverse shell', action: 'deny' },
  { id: 'INJ-003', category: 'injection', weight: 0.95, pattern: /\bnc(at)?\s+[^&]*(-e\s*\/bin\/|--exec)|\bnc\s+.*\d{2,5}.*-e\s/i, reason: 'netcat reverse shell', action: 'deny' },
  { id: 'INJ-004', category: 'injection', weight: 0.9, pattern: /socat\s+.*exec.*(pty|stdout|stderr)/i, reason: 'socat reverse shell', action: 'deny' },
  { id: 'INJ-005', category: 'injection', weight: 0.95, pattern: /socket\.socket.*connect.*dup2|pty\.spawn|subprocess.*\/bin\/(ba)?sh/i, reason: 'Python reverse shell signature', action: 'deny' },
  { id: 'INJ-006', category: 'injection', weight: 0.85, pattern: /powershell.*-e(nc)?\s+[A-Za-z0-9+/=]{20,}/i, reason: 'PowerShell base64-encoded command', action: 'block' },
  { id: 'INJ-007', category: 'injection', weight: 0.8, pattern: /(base64|openssl)\s+(-d|enc\s+-d|--decode).*\|\s*(ba|z|da)?sh\b/i, reason: 'Decode-and-execute chain', action: 'block' },
  { id: 'INJ-008', category: 'injection', weight: 0.7, pattern: /mkfifo.*\|\s*.*sh/i, reason: 'mkfifo named pipe reverse shell', action: 'deny' },
  { id: 'INJ-009', category: 'injection', weight: 0.4, pattern: /\b(python|perl|ruby|php)\s+-c?.*socket.*connect/i, reason: 'Scripting language socket connection', action: 'log' },

  // ── CRED: credential / key access ────────────────────────────────
  { id: 'CRED-001', category: 'credential', weight: 0.8, pattern: /\.ssh\/(id_|authorized_keys)|\bid_rsa\b|\bid_ed25519\b/i, reason: 'Reading SSH keys', action: 'block' },
  { id: 'CRED-002', category: 'credential', weight: 0.8, pattern: /\.aws\/(credentials|config)/i, reason: 'Reading AWS credentials', action: 'block' },
  { id: 'CRED-003', category: 'credential', weight: 0.9, pattern: /\/etc\/(shadow|gshadow)\b/i, reason: 'Reading system password hashes', action: 'deny' },
  { id: 'CRED-004', category: 'credential', weight: 0.6, pattern: /(^|\s|\/|")\.env\b/i, reason: 'Reading .env environment file', action: 'block' },
  { id: 'CRED-005', category: 'credential', weight: 0.7, pattern: /\.kube\/config|\.docker\/config\.json|\.netrc\b/i, reason: 'Reading container/registry credentials', action: 'block' },
  { id: 'CRED-006', category: 'credential', weight: 0.7, pattern: /application_default_credentials\.json|\.config\/gcloud/i, reason: 'Reading GCP credentials', action: 'block' },
  { id: 'CRED-007', category: 'credential', weight: 0.7, pattern: /Login Data|Cookies.*(chrome|firefox|edge)|keychain/i, reason: 'Reading browser/keychain credentials', action: 'block' },
  { id: 'CRED-008', category: 'credential', weight: 0.4, pattern: /\.(bash|zsh)_history\b/i, reason: 'Reading shell history (may contain passwords)', action: 'log' },

  // ── EXFIL: data exfiltration ─────────────────────────────────────
  { id: 'EXFIL-001', category: 'exfil', weight: 0.8, pattern: /\bprintenv\b[^|]*\|\s*(curl|wget|nc)|^\s*env\s*\|\s*(curl|wget|nc)/i, reason: 'Environment variable exfiltration', action: 'block' },
  { id: 'EXFIL-002', category: 'exfil', weight: 0.8, pattern: /curl\s+[^|]*(-F|--data-binary|-T|--upload-file)\s+@?(\/|~)/i, reason: 'curl uploading local file', action: 'block' },
  { id: 'EXFIL-003', category: 'exfil', weight: 0.7, pattern: /wget\s+.*--post-file/i, reason: 'wget POST uploading file', action: 'block' },
  { id: 'EXFIL-004', category: 'exfil', weight: 0.8, pattern: /(read|cat|dump).{0,40}(then|and|&&|\|)\s*(send|post|upload|exfiltrate|transmit|curl|wget)/i, reason: 'Read-then-exfiltrate combination', action: 'block' },
  { id: 'EXFIL-005', category: 'exfil', weight: 0.6, pattern: /\$\(.*\)\.[a-z0-9-]+\.(com|net|io|xyz)/i, reason: 'DNS subdomain exfiltration signature', action: 'block' },

  // ── PATH: filesystem escape / persistence ──────────────────────────
  { id: 'PATH-001', category: 'filesystem', weight: 0.5, pattern: /(\.\.[\\/]){2,}|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e/i, reason: 'Path traversal (including encoded variants)', action: 'log' },
  { id: 'PATH-002', category: 'filesystem', weight: 0.7, pattern: /(\.\.|%2e|\.\.%2f|%2e%2e)[/\\%].*(etc\/passwd|etc\/shadow|\.ssh|\.aws|win\.ini|boot\.ini)|(\.\.|%2e%2e)[/\\%2f]*.*etc\/(passwd|shadow)/i, reason: 'Path traversal reading sensitive files', action: 'block' },
  { id: 'PATH-003', category: 'filesystem', weight: 0.7, pattern: />\s*\/(etc|bin|sbin|usr\/bin|boot|sys)\//i, reason: 'Writing to system directories', action: 'block' },
  { id: 'PATH-004', category: 'filesystem', weight: 0.7, pattern: /\/(etc\/)?cron|crontab\s+-|\/var\/spool\/cron/i, reason: 'Cron persistence write', action: 'block' },
  { id: 'PATH-005', category: 'filesystem', weight: 0.7, pattern: /\/etc\/systemd\/system|systemctl\s+(enable|link)/i, reason: 'systemd persistence write', action: 'block' },
  { id: 'PATH-006', category: 'filesystem', weight: 0.8, pattern: />\s*~?\/?\.(bashrc|zshrc|bash_profile|profile)/i, reason: 'Shell startup file persistence write', action: 'block' },
  { id: 'PATH-007', category: 'filesystem', weight: 0.9, pattern: />>?\s*.*\.ssh\/authorized_keys/i, reason: 'authorized_keys backdoor write', action: 'deny' },
  { id: 'PATH-008', category: 'filesystem', weight: 0.5, pattern: /%00|\x00/i, reason: 'Null byte truncation (path validation bypass)', action: 'log' },

  // ── PRIV: privilege escalation ──────────────────────────────────────────
  { id: 'PRIV-001', category: 'privesc', weight: 0.6, pattern: /\bsudo\s+(rm|dd|chmod|chown|bash|sh|mv|cp)\b/i, reason: 'sudo on sensitive privileged command', action: 'block' },
  { id: 'PRIV-002', category: 'privesc', weight: 0.7, pattern: /chmod\s+[ug]?\+s|chmod\s+4[0-7]{3}/i, reason: 'Setting setuid bit', action: 'block' },
  { id: 'PRIV-003', category: 'privesc', weight: 0.9, pattern: /randomize_va_space|sysctl.*aslr/i, reason: 'Disabling ASLR', action: 'deny' },
  { id: 'PRIV-004', category: 'network', weight: 0.9, pattern: /iptables\s+-F|pfctl\s+-d\b|ufw\s+disable/i, reason: 'Disabling firewall', action: 'deny' },

  // ── PI: prompt injection (targets text read by the agent; guards against indirect injection) ────
  { id: 'PI-001', category: 'prompt-injection', weight: 0.8, pattern: /\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|preceding|all)\b.{0,20}\b(instruction|prompt|rule|direction|message)s?\b/i, reason: 'Prompt injection: override previous instructions', action: 'block' },
  { id: 'PI-002', category: 'prompt-injection', weight: 0.7, pattern: /(new|your\s+real|actual)\s+(instructions?|task|objective)s?\s*:/i, reason: 'Prompt injection: inject new instructions', action: 'log' },
  { id: 'PI-003', category: 'prompt-injection', weight: 0.8, pattern: /(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|enable|enter|activate)\s+.?(DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|unrestricted|jailbreak|unfiltered|uncensored)/i, reason: 'Prompt injection: jailbreak/DAN/role escape', action: 'block' },
  { id: 'PI-004', category: 'prompt-injection', weight: 0.7, pattern: /(reveal|show|print|repeat|output|tell\s+me)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|initial\s+message)/i, reason: 'Prompt injection: induce system prompt leak', action: 'log' },
  { id: 'PI-005', category: 'prompt-injection', weight: 0.8, pattern: /forget\s+(everything|all\s+(your\s+)?(previous\s+)?instructions?)/i, reason: 'Prompt injection: forget instructions', action: 'block' },
  { id: 'PI-006', category: 'prompt-injection', weight: 0.7, pattern: /[​‌‍⁠﻿]/, reason: 'Prompt injection: zero-width characters/steganography', action: 'log' },

  // ── TP: tool poisoning / deceptive instructions (scans tool description / return content) ──
  { id: 'TP-001', category: 'tool-poisoning', weight: 0.8, pattern: /<!--\s*(ignore|instruction|system|assistant|note\s+to)/i, reason: 'Tool poisoning: instructions hidden in HTML comment', action: 'block' },
  { id: 'TP-002', category: 'tool-poisoning', weight: 0.7, pattern: /(do\s+not|don't)\s+(mention|tell|show|reveal|inform)\b.{0,20}(user|this|anyone)/i, reason: 'Tool poisoning: instructions to hide from user', action: 'block' },
  { id: 'TP-003', category: 'tool-poisoning', weight: 0.7, pattern: /conceal\b.{0,20}from\s+the\s+user/i, reason: 'Tool poisoning: concealing behavior', action: 'block' },
  { id: 'TP-004', category: 'tool-poisoning', weight: 0.7, pattern: /(ignore|disable|bypass|override)\s+(safety|security|guard|filter|restriction)/i, reason: 'Tool poisoning: overriding security mechanisms', action: 'block' },
  { id: 'TP-005', category: 'tool-poisoning', weight: 0.6, pattern: /(make|send)\s+(a\s+)?(GET|POST|HTTP)\s+request\s+to/i, reason: 'Tool poisoning: inducing external requests', action: 'log' },
]
