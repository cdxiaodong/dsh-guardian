/** 危险规则定义与内置规则集 */
export interface Rule {
  id: string
  pattern: RegExp
  reason: string
  /** block=需人工确认；deny=直接拒绝；log=仅记录 */
  action: 'block' | 'deny' | 'log'
  /** 规则分类，便于审计与统计 */
  category?: 'destructive' | 'injection' | 'credential' | 'exfil' | 'network' | 'filesystem' | 'prompt-injection' | 'tool-poisoning' | 'privesc' | 'obfuscation'
  /** 风险权重 0~1，用于多信号加权评分（调研建议） */
  weight?: number
}

/**
 * 内置规则集（按类别分组，规则 ID 借鉴 mcp-safeguard 分类法：CMD/PI/TP/CRED/EXFIL/PATH/PRIV）。
 * 所有正则不带 /g 标志，避免 lastIndex 状态污染。
 */
export const DEFAULT_RULES: Rule[] = [
  // ── CMD：破坏性操作 ──────────────────────────────────────
  { id: 'CMD-001', category: 'destructive', weight: 0.9, pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+\/(\s|$|\*)/i, reason: '递归删除根目录', action: 'deny' },
  { id: 'CMD-002', category: 'destructive', weight: 0.7, pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s+[~/]/i, reason: '递归强制删除目录', action: 'block' },
  { id: 'CMD-003', category: 'destructive', weight: 0.95, pattern: /\bdd\s+if=.*of=\/dev\/|>\s*\/dev\/(sd|nvme|hd)/i, reason: 'dd/重定向覆写磁盘设备', action: 'deny' },
  { id: 'CMD-004', category: 'destructive', weight: 0.95, pattern: /\bmkfs(\.[a-z0-9]+)?\b/i, reason: '格式化文件系统', action: 'deny' },
  { id: 'CMD-005', category: 'destructive', weight: 0.95, pattern: /:\(\)\s*\{\s*:\s*\|\s*:.*\}\s*;\s*:/, reason: 'fork 炸弹', action: 'deny' },
  { id: 'CMD-006', category: 'destructive', weight: 0.8, pattern: /\b(kill\s+-9\s+-1|killall\s+-9|shutdown|reboot|halt|poweroff)\b/i, reason: '杀所有进程/关机', action: 'block' },
  { id: 'CMD-007', category: 'destructive', weight: 0.6, pattern: /\bshred\s+.*-[a-z]*u/i, reason: 'shred 粉碎删除', action: 'block' },
  { id: 'CMD-008', category: 'destructive', weight: 0.7, pattern: /chmod\s+(-R\s+)?777\s+\//i, reason: '放开系统目录权限', action: 'block' },
  { id: 'CMD-009', category: 'destructive', weight: 0.9, pattern: /mv\s+\/\*\s+\/dev\/null/i, reason: '移动根目录到 /dev/null', action: 'deny' },

  // ── INJ：命令注入 / 反弹 shell（匹配意图而非完整 payload）──
  { id: 'INJ-001', category: 'injection', weight: 0.7, pattern: /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b|wget\s+.*-O-.*\|\s*(ba|z)?sh/i, reason: '远程脚本管道执行', action: 'block' },
  { id: 'INJ-002', category: 'injection', weight: 0.95, pattern: /\/dev\/tcp\/\d|bash\s+-i\s+>&|bash\s+-i.*>&\s*\/dev\/tcp/i, reason: 'bash 反弹 shell', action: 'deny' },
  { id: 'INJ-003', category: 'injection', weight: 0.95, pattern: /\bnc(at)?\s+[^&]*(-e\s*\/bin\/|--exec)|\bnc\s+.*\d{2,5}.*-e\s/i, reason: 'netcat 反弹 shell', action: 'deny' },
  { id: 'INJ-004', category: 'injection', weight: 0.9, pattern: /socat\s+.*exec.*(pty|stdout|stderr)/i, reason: 'socat 反弹 shell', action: 'deny' },
  { id: 'INJ-005', category: 'injection', weight: 0.95, pattern: /socket\.socket.*connect.*dup2|pty\.spawn|subprocess.*\/bin\/(ba)?sh/i, reason: 'python 反弹 shell 特征', action: 'deny' },
  { id: 'INJ-006', category: 'injection', weight: 0.85, pattern: /powershell.*-e(nc)?\s+[A-Za-z0-9+/=]{20,}/i, reason: 'PowerShell base64 编码命令', action: 'block' },
  { id: 'INJ-007', category: 'injection', weight: 0.8, pattern: /(base64|openssl)\s+(-d|enc\s+-d|--decode).*\|\s*(ba|z|da)?sh\b/i, reason: '解码后执行链', action: 'block' },
  { id: 'INJ-008', category: 'injection', weight: 0.7, pattern: /mkfifo.*\|\s*.*sh/i, reason: 'mkfifo 命名管道反弹 shell', action: 'deny' },
  { id: 'INJ-009', category: 'injection', weight: 0.4, pattern: /\b(python|perl|ruby|php)\s+-c?.*socket.*connect/i, reason: '脚本语言 socket 连接', action: 'log' },

  // ── CRED：凭据 / 密钥读取 ────────────────────────────────
  { id: 'CRED-001', category: 'credential', weight: 0.8, pattern: /\.ssh\/(id_|authorized_keys)|\bid_rsa\b|\bid_ed25519\b/i, reason: '读取 SSH 密钥', action: 'block' },
  { id: 'CRED-002', category: 'credential', weight: 0.8, pattern: /\.aws\/(credentials|config)/i, reason: '读取 AWS 凭据', action: 'block' },
  { id: 'CRED-003', category: 'credential', weight: 0.9, pattern: /\/etc\/(shadow|gshadow)\b/i, reason: '读取系统密码散列', action: 'deny' },
  { id: 'CRED-004', category: 'credential', weight: 0.6, pattern: /(^|\s|\/|")\.env\b/i, reason: '读取 .env 环境文件', action: 'block' },
  { id: 'CRED-005', category: 'credential', weight: 0.7, pattern: /\.kube\/config|\.docker\/config\.json|\.netrc\b/i, reason: '读取容器/仓库凭据', action: 'block' },
  { id: 'CRED-006', category: 'credential', weight: 0.7, pattern: /application_default_credentials\.json|\.config\/gcloud/i, reason: '读取 GCP 凭据', action: 'block' },
  { id: 'CRED-007', category: 'credential', weight: 0.7, pattern: /Login Data|Cookies.*(chrome|firefox|edge)|keychain/i, reason: '读取浏览器/钥匙串凭据', action: 'block' },
  { id: 'CRED-008', category: 'credential', weight: 0.4, pattern: /\.(bash|zsh)_history\b/i, reason: '读取 shell 历史(可能含密码)', action: 'log' },

  // ── EXFIL：数据外泄 ─────────────────────────────────────
  { id: 'EXFIL-001', category: 'exfil', weight: 0.8, pattern: /\bprintenv\b[^|]*\|\s*(curl|wget|nc)|^\s*env\s*\|\s*(curl|wget|nc)/i, reason: '环境变量外泄', action: 'block' },
  { id: 'EXFIL-002', category: 'exfil', weight: 0.8, pattern: /curl\s+[^|]*(-F|--data-binary|-T|--upload-file)\s+@?(\/|~)/i, reason: 'curl 上传本地文件', action: 'block' },
  { id: 'EXFIL-003', category: 'exfil', weight: 0.7, pattern: /wget\s+.*--post-file/i, reason: 'wget POST 上传文件', action: 'block' },
  { id: 'EXFIL-004', category: 'exfil', weight: 0.8, pattern: /(read|cat|dump).{0,40}(then|and|&&|\|)\s*(send|post|upload|exfiltrate|transmit|curl|wget)/i, reason: '读取后外泄组合', action: 'block' },
  { id: 'EXFIL-005', category: 'exfil', weight: 0.6, pattern: /\$\(.*\)\.[a-z0-9-]+\.(com|net|io|xyz)/i, reason: 'DNS 子域名外泄特征', action: 'block' },

  // ── PATH：文件系统逃逸 / 持久化 ──────────────────────────
  { id: 'PATH-001', category: 'filesystem', weight: 0.5, pattern: /(\.\.[\\/]){2,}|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e/i, reason: '路径穿越（含编码变体）', action: 'log' },
  { id: 'PATH-002', category: 'filesystem', weight: 0.7, pattern: /(\.\.|%2e|\.\.%2f|%2e%2e)[/\\%].*(etc\/passwd|etc\/shadow|\.ssh|\.aws|win\.ini|boot\.ini)|(\.\.|%2e%2e)[/\\%2f]*.*etc\/(passwd|shadow)/i, reason: '路径穿越读敏感文件', action: 'block' },
  { id: 'PATH-003', category: 'filesystem', weight: 0.7, pattern: />\s*\/(etc|bin|sbin|usr\/bin|boot|sys)\//i, reason: '写入系统目录', action: 'block' },
  { id: 'PATH-004', category: 'filesystem', weight: 0.7, pattern: /\/(etc\/)?cron|crontab\s+-|\/var\/spool\/cron/i, reason: '写 cron 持久化', action: 'block' },
  { id: 'PATH-005', category: 'filesystem', weight: 0.7, pattern: /\/etc\/systemd\/system|systemctl\s+(enable|link)/i, reason: '写 systemd 持久化', action: 'block' },
  { id: 'PATH-006', category: 'filesystem', weight: 0.8, pattern: />\s*~?\/?\.(bashrc|zshrc|bash_profile|profile)/i, reason: '写 shell 启动文件持久化', action: 'block' },
  { id: 'PATH-007', category: 'filesystem', weight: 0.9, pattern: />>?\s*.*\.ssh\/authorized_keys/i, reason: '写 authorized_keys 后门', action: 'deny' },
  { id: 'PATH-008', category: 'filesystem', weight: 0.5, pattern: /%00|\x00/i, reason: '空字节截断（路径校验绕过）', action: 'log' },

  // ── PRIV：提权 ──────────────────────────────────────────
  { id: 'PRIV-001', category: 'privesc', weight: 0.6, pattern: /\bsudo\s+(rm|dd|chmod|chown|bash|sh|mv|cp)\b/i, reason: 'sudo 提权敏感命令', action: 'block' },
  { id: 'PRIV-002', category: 'privesc', weight: 0.7, pattern: /chmod\s+[ug]?\+s|chmod\s+4[0-7]{3}/i, reason: '设置 setuid 位', action: 'block' },
  { id: 'PRIV-003', category: 'privesc', weight: 0.9, pattern: /randomize_va_space|sysctl.*aslr/i, reason: '关闭 ASLR', action: 'deny' },
  { id: 'PRIV-004', category: 'network', weight: 0.9, pattern: /iptables\s+-F|pfctl\s+-d\b|ufw\s+disable/i, reason: '关闭防火墙', action: 'deny' },

  // ── PI：提示注入（针对读入 Agent 的文本，防间接注入）────
  { id: 'PI-001', category: 'prompt-injection', weight: 0.8, pattern: /\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|preceding|all)\b.{0,20}\b(instruction|prompt|rule|direction|message)s?\b/i, reason: '提示注入：覆盖先前指令', action: 'block' },
  { id: 'PI-002', category: 'prompt-injection', weight: 0.7, pattern: /(new|your\s+real|actual)\s+(instructions?|task|objective)s?\s*:/i, reason: '提示注入：注入新指令', action: 'log' },
  { id: 'PI-003', category: 'prompt-injection', weight: 0.8, pattern: /(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|enable|enter|activate)\s+.?(DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|unrestricted|jailbreak|unfiltered|uncensored)/i, reason: '提示注入：越狱/DAN/角色逃逸', action: 'block' },
  { id: 'PI-004', category: 'prompt-injection', weight: 0.7, pattern: /(reveal|show|print|repeat|output|tell\s+me)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|initial\s+message)/i, reason: '提示注入：诱导泄露系统提示', action: 'log' },
  { id: 'PI-005', category: 'prompt-injection', weight: 0.8, pattern: /forget\s+(everything|all\s+(your\s+)?(previous\s+)?instructions?)/i, reason: '提示注入：忘记指令', action: 'block' },
  { id: 'PI-006', category: 'prompt-injection', weight: 0.7, pattern: /[\u200B\u200C\u200D\u2060\uFEFF\u180E\u3164\uFFA0]/, reason: '提示注入：零宽字符/隐写（混淆消解引擎会进一步解码变形）', action: 'log' },

  // ── TP：工具投毒 / 欺骗指令（扫 tool description / 返回内容）──
  { id: 'TP-001', category: 'tool-poisoning', weight: 0.8, pattern: /<!--\s*(ignore|instruction|system|assistant|note\s+to)/i, reason: '工具投毒：HTML 注释藏指令', action: 'block' },
  { id: 'TP-002', category: 'tool-poisoning', weight: 0.7, pattern: /(do\s+not|don't)\s+(mention|tell|show|reveal|inform)\b.{0,20}(user|this|anyone)/i, reason: '工具投毒：瞒用户指令', action: 'block' },
  { id: 'TP-003', category: 'tool-poisoning', weight: 0.7, pattern: /conceal\b.{0,20}from\s+the\s+user/i, reason: '工具投毒：隐瞒行为', action: 'block' },
  { id: 'TP-004', category: 'tool-poisoning', weight: 0.7, pattern: /(ignore|disable|bypass|override)\s+(safety|security|guard|filter|restriction)/i, reason: '工具投毒：覆盖安全机制', action: 'block' },
  { id: 'TP-005', category: 'tool-poisoning', weight: 0.6, pattern: /(make|send)\s+(a\s+)?(GET|POST|HTTP)\s+request\s+to/i, reason: '工具投毒：诱导发起外部请求', action: 'log' },
]
