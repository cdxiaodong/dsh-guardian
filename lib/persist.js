/**
 * 持久化哨兵引擎（Persistence Guard）—— MITRE ATT&CK 持久化战术在 Agent 工具调用层的前置拦截
 *
 * 威胁模型：Agent 被提示注入攻陷后（Web 内容、工具描述、文档），攻击者要的不是一次性
 * 失控，而是"下线后仍能回来"。经典落地手段就是把 EDR 盯了很多年的持久化机制搬进
 * Agent 的 shell/文件写工具（System Two Security 2026 的检测规则记录了真实案例：
 * AI agent 子进程修改 crontab、追加 authorized_keys、创建 systemd unit）：
 *   T1053.003  Cron                  —— `(crontab -l;echo "@reboot ...")|crontab -`
 *   T1546.004  .bashrc/.zshrc        —— shell 启动时自动 source 的文件
 *   T1098.004  authorized_keys       —— 追加一把攻击者的 SSH 公钥
 *   T1543.001  LaunchAgents .plist   —— macOS RunAtLoad
 *   T1543.002  systemd unit          —— WantedBy=multi-user.target
 *   T1053.005  schtasks / Run 键     —— Windows 计划任务与注册表自启
 *
 * 与 EDR 的本质区别：EDR 在"事后取证"（进程已拉起、文件已落盘才看到行为），本引擎在
 * "事前拦截"——工具调用还没执行，guardian/check 就 bail 掉了。
 *
 * 与引擎 1（正则规则）的本质区别：正则引擎把 payload 当一坨文本扫；本引擎理解工具调用
 * 的参数结构——哪个字段是命令、哪个是目标路径、哪个是写入内容——据此把检测拆成三个
 * 正交通道，各自能用更精确的判据（比如 `crontab -l` 只是查看、读 .bashrc 无害，
 * 只有"写语义"才触发；目标面与载荷面交叉定级）：
 *   command  通道 —— 命令字符串里的持久化安装惯用法（管道进 crontab、launchctl load、
 *                    systemctl --user enable、schtasks /create、reg add ...Run...）
 *   filepath 通道 —— 写入目标命中持久化面（rc 文件、authorized_keys、LaunchAgents
 *                    plist、systemd unit、cron.d）
 *   content  通道 —— 写入载荷的恶意度（curl|sh、alias sudo= 劫持、RunAtKeep 生命周期键），
 *                    与目标面交叉：rc+恶意载荷=deny，rc+良性=block
 *
 * 动作分级判据：
 *   deny  —— 该动作在 Agent 正常工作流里几乎没有正当用途：写 authorized_keys、装 cron、
 *            创建 launchd/systemd/计划任务、rc 写入携带网络取回执行或命令劫持载荷
 *   block —— 有正当用途但高危：改 shell rc（开发者 Agent 合理需求，人工确认）
 *
 * 检测全部离线、确定性，纯静态判据，不依赖文件系统快照 diff（那是 EDR 的活）。
 */
// ── 持久化面定义 ───────────────────────────────────────────────────────────
/** shell 启动文件（basename 精确匹配；写这些 = 每次开终端都执行，T1546.004） */
export const RC_FILENAMES = new Set([
    '.bashrc', '.bash_profile', '.bash_login', '.bash_logout',
    '.zshrc', '.zprofile', '.zshenv', '.zlogin',
    '.profile', '.kshrc',
]);
/** macOS launchd 持久化目录（子串匹配路径段） */
export const LAUNCHD_DIR_SEGMENTS = ['LaunchAgents', 'LaunchDaemons'];
/** systemd 持久化目录（用户级 + 系统级） */
export const SYSTEMD_DIR_SEGMENTS = [
    '.config/systemd/user', '/etc/systemd/system', '/usr/lib/systemd/system',
];
/** cron 落盘目录（写这些路径 = 直接塞计划任务，T1053.003） */
export const CRON_DIR_SEGMENTS = [
    '/etc/cron.d', '/etc/cron.deny', '/etc/cron.allow',
    '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
    '/var/spool/cron', '/var/cron/tabs',
];
/** 视为"写语义"的工具名（读语义不触发 filepath 通道） */
const WRITE_TOOL_RE = /(?:write|edit|patch|create|save|append|modify|replace|update|put|upload|mkdir|touch|mv|cp|move|rename)/i;
/** payload 里视为命令/路径/内容的字段名（宽松提取，宿主工具命名各异） */
const COMMAND_FIELDS = ['command', 'cmd', 'script', 'shell', 'exec', 'code', 'statement', 'statements', 'bash', 'sh'];
const PATH_FIELDS = ['path', 'file_path', 'filePath', 'file', 'filename', 'fname', 'target', 'dest', 'destination', 'fileToEdit', 'notebook_path'];
const CONTENT_FIELDS = ['content', 'contents', 'data', 'text', 'body', 'new_str', 'patch', 'edits'];
const COMMAND_RULES = [
    {
        // 管道回装 crontab / crontab 加载文件 —— 安装语义（-l -e -r --list 是查看/编辑，显式排除；
        // 裸文件参数要求含 / 或 . ，防止 commit message 里自然语言 "fix crontab scheduler" 误报）
        re: /(?:\|\s*crontab\b|\bcrontab\s+(?:-\w+\s+)*(?!-[ler]\b)(?!--list\b)(?!--edit\b)(?!--remove\b)[^\s|;&<>]*[./][^\s|;&<>]*)/,
        ruleId: 'PERSIST-CRON',
        reason: '安装 crontab 计划任务（持久化）',
        technique: 'T1053.003',
    },
    {
        // launchctl 加载/注册（load 已弃用但仍在用；bootstrap/enable/submit 是现行写法）
        re: /\blaunchctl\s+(?:-\S+\s+)*(?:load|bootstrap|enable|submit)\b/,
        ruleId: 'PERSIST-LAUNCHD',
        reason: 'launchctl 注册 LaunchAgent/Daemon（持久化）',
        technique: 'T1543.001',
    },
    {
        re: /\bsystemctl\s+(?:-\S+\s+)*(?:--user\s+)?enable\b/,
        ruleId: 'PERSIST-SYSTEMD',
        reason: 'systemctl enable 设置服务自启（持久化）',
        technique: 'T1543.002',
    },
    {
        re: /\bschtasks\b[^\n;&|]*\s\/create\b/i,
        ruleId: 'PERSIST-SCHTASKS',
        reason: 'schtasks 创建计划任务（持久化）',
        technique: 'T1053.005',
    },
    {
        re: /\bRegister-ScheduledTask\b/,
        ruleId: 'PERSIST-SCHTASKS',
        reason: 'PowerShell Register-ScheduledTask 创建计划任务（持久化）',
        technique: 'T1053.005',
    },
    {
        // 兼容 shell/JSON 转义的单个或多个反斜杠路径分隔
        re: /\breg(?:\.exe)?\s+add\b[^\n;&|]*\\+(?:Software\\+(?:Microsoft\\+Windows\\+)?CurrentVersion\\+(?:Run|RunOnce))/i,
        ruleId: 'PERSIST-SCHTASKS',
        reason: '注册表 Run/RunOnce 键写入自启项（持久化）',
        technique: 'T1060',
    },
    {
        // shell 命令行直接追加 rc 启动文件 —— 命令通道里最常见的持久化惯用法
        re: /(?:^|[;&|(`$\n]\s*)(?:echo|printf|cat|tee)\b[^\n>]*>>?\s*[^\s;&|]*\/(?:\.bashrc|\.zshrc|\.profile|\.zprofile|\.bash_profile|\.zshenv|\.bash_login|\.kshrc)\b/,
        ruleId: 'PERSIST-RCFILE',
        reason: '命令向 shell 启动文件追加内容（持久化）',
        technique: 'T1546.004',
    },
    {
        // 命令行直接追加 authorized_keys（泛规则 PATH-007 已兜底，这里给出精确 ruleId）
        re: /(?:^|[;&|(`$\n]\s*)(?:echo|printf|cat|tee)\b[^\n>]*>>?\s*[^\s;&|]*authorized_keys2?\b/,
        ruleId: 'PERSIST-SSHKEY',
        reason: '命令向 SSH authorized_keys 追加公钥（后门持久化）',
        technique: 'T1098.004',
    },
];
const PAYLOAD_RULES = [
    {
        // 网络取回即执行（curl|sh 家族）
        re: /(?:curl|wget)[^\n|;`]*\|\s*(?:sudo\s+)?(?:ba|z|da|s)?sh\b/,
        reason: '载荷含"网络取回即执行"（curl|sh）',
        escalate: true,
    },
    {
        re: /\bbase64\s+(?:-d|-D|--decode)\b[^\n|;`]*\|\s*(?:sudo\s+)?(?:ba|z|da|s)?sh\b/,
        reason: '载荷含"解码即执行"（base64 -d | sh）',
        escalate: true,
    },
    {
        // alias 劫持常用命令：换掉用户每天敲的 sudo/ssh，输什么凭据都进攻击者口袋
        re: /\balias\s+(?:sudo|doas|su|ssh|scp|cd|ls|cat|git|vim|nano|python\d?|node|npm|pip\d?)=/,
        reason: '载荷劫持常用命令 alias（凭据/路径收割）',
        escalate: true,
    },
    {
        re: /\b(?:export\s+|setenv\s+)?(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)=/,
        reason: '载荷设置动态库注入环境变量',
        escalate: true,
    },
    {
        // macOS plist 生命周期键：RunAtLoad/KeepAlive/Start* —— plist 只有要自启才有这些
        re: /<(?:key|string)>\s*(?:RunAtLoad|KeepAlive|StartInterval|StartCalendarInterval|WatchPaths)\s*(?:<\/key>|<\/string>)|["']?(?:RunAtLoad|KeepAlive|StartInterval)["']?\s*[=:]\s*(?:true|<true\/>)/,
        reason: 'plist 载荷含自启生命周期键（RunAtLoad/KeepAlive）',
        escalate: true,
    },
    {
        // systemd unit 的 [Install] + WantedBy —— unit 文件要自启的标志
        re: /\[Install\][^\n\[]*WantedBy\s*=|WantedBy\s*=\s*(?:multi-user|graphical|default)\.target/,
        reason: 'systemd unit 载荷含自启安装段（[Install] WantedBy）',
        escalate: true,
    },
    {
        // PATH 前置劫持：把恶意目录放在系统路径前面（良性场景也存在，仅记录不升级）
        re: /(?:export\s+PATH|PATH=)[^:\n"']*:\$PATH/,
        reason: '载荷前置 PATH（可能劫持命令解析）',
        escalate: false,
    },
];
// ── 工具函数 ───────────────────────────────────────────────────────────────
function clip(s, n = 120) {
    return s.length > n ? s.slice(0, n) + '…' : s;
}
/** 判断写入目标是否命中 shell 启动文件（basename 精确匹配，防 test.bashrc 误报） */
function isRcFile(p) {
    const normalized = p.replace(/\/+/g, '/');
    if (RC_FILENAMES.has(normalized))
        return true;
    const base = normalized.split('/').pop() ?? '';
    if (RC_FILENAMES.has(base))
        return true;
    // fish：basename 太通用，要求落在 fish 配置目录里
    return base === 'config.fish' && /\/\.?config\/fish\/config\.fish$/.test(normalized);
}
function containsSegment(p, segments) {
    const normalized = p.replace(/\/+/g, '/');
    for (const seg of segments) {
        const needle = seg.startsWith('/') || seg.startsWith('.') ? seg : `/${seg}/`;
        if (normalized.includes(needle) || normalized.endsWith(`/${seg}`))
            return seg;
    }
    return null;
}
/** 内容载荷扫描：返回命中的载荷规则（escalate 属性供定级） */
export function scanPayload(content) {
    const hits = [];
    for (const rule of PAYLOAD_RULES) {
        const m = content.match(rule.re);
        if (m)
            hits.push({ reason: rule.reason, escalate: rule.escalate, match: clip(m[0]) });
    }
    return hits;
}
/** filepath 通道：写入目标命中持久化面 → block；若载荷升压 → deny */
export function scanFileWriteForPersistence(targetPath, content) {
    const hits = [];
    if (!targetPath)
        return hits;
    const p = targetPath.trim();
    const payloads = content !== undefined ? scanPayload(content) : [];
    // 1. authorized_keys —— Agent 正常工作流零正当用途，直接 deny
    if (/\/authorized_keys2?$/.test(p.replace(/\/+/g, '/'))) {
        hits.push({
            ruleId: 'PERSIST-SSHKEY', surface: 'filepath', action: 'deny',
            reason: '写入 SSH authorized_keys（追加攻击者公钥的经典持久化）', match: clip(p), technique: 'T1098.004',
        });
        return hits;
    }
    // 2. macOS LaunchAgents/LaunchDaemons 下的 .plist
    const launchdSeg = containsSegment(p, LAUNCHD_DIR_SEGMENTS);
    if (launchdSeg && /\.plist$/i.test(p)) {
        const escalated = payloads.some((x) => x.escalate);
        hits.push({
            ruleId: 'PERSIST-LAUNCHD', surface: 'filepath',
            action: escalated ? 'deny' : 'block',
            reason: `创建 launchd 持久化项（${launchdSeg}/*.plist${escalated ? '，载荷含自启键' : ''}）`,
            match: clip(p), technique: 'T1543.001',
        });
        return hits;
    }
    // 3. systemd unit 目录下的 .service/.timer/.path
    const systemdSeg = containsSegment(p, SYSTEMD_DIR_SEGMENTS);
    if (systemdSeg && /\.(?:service|timer|path|socket)$/i.test(p)) {
        const escalated = payloads.some((x) => x.escalate);
        hits.push({
            ruleId: 'PERSIST-SYSTEMD', surface: 'filepath',
            action: escalated ? 'deny' : 'block',
            reason: `创建 systemd unit（${systemdSeg}${escalated ? '，载荷含自启安装段' : ''}）`,
            match: clip(p), technique: 'T1543.002',
        });
        return hits;
    }
    // 4. cron 落盘目录
    const cronSeg = containsSegment(p, CRON_DIR_SEGMENTS);
    if (cronSeg) {
        hits.push({
            ruleId: 'PERSIST-CRON', surface: 'filepath', action: 'deny',
            reason: `直接写入 cron 任务目录（${cronSeg}）`, match: clip(p), technique: 'T1053.003',
        });
        return hits;
    }
    // 5. shell 启动文件 —— 良性内容 block（人工确认），恶意载荷 deny
    if (isRcFile(p)) {
        const escalated = payloads.find((x) => x.escalate);
        hits.push({
            ruleId: 'PERSIST-RCFILE', surface: 'filepath',
            action: escalated ? 'deny' : 'block',
            reason: escalated
                ? `写入 shell 启动文件且${escalated.reason}`
                : '写入 shell 启动文件（每次开终端自动执行）',
            match: escalated ? `${clip(p)} :: ${escalated.match}` : clip(p),
            technique: 'T1546.004',
        });
        return hits;
    }
    return hits;
}
/** command 通道：命令字符串里的持久化安装惯用法（全部 deny 级） */
export function scanCommandForPersistence(command) {
    const hits = [];
    if (!command)
        return hits;
    for (const rule of COMMAND_RULES) {
        const m = command.match(rule.re);
        if (m) {
            hits.push({
                ruleId: rule.ruleId, surface: 'command', action: 'deny',
                reason: rule.reason, match: clip(m[0]), technique: rule.technique,
            });
        }
    }
    return hits;
}
/**
 * 主入口：对一次工具调用做持久化检测。
 * 与纯正则引擎的区别在此：解析 payload 的字段结构，把命令/路径/内容分到各自通道——
 * 读语义（cat .bashrc）与写语义（edit .bashrc）得到不同判定。
 * 纯字符串 payload 视为命令扫描（bash 工具的惯例形态）。
 */
export function scanPersistence(toolName, payload) {
    const hits = [];
    if (payload == null)
        return hits;
    let command = '';
    let targetPath = '';
    let content;
    let hasContentField = false;
    if (typeof payload === 'string') {
        command = payload;
    }
    else if (typeof payload === 'object') {
        const obj = payload;
        for (const key of COMMAND_FIELDS) {
            if (typeof obj[key] === 'string' && obj[key]) {
                command = obj[key];
                break;
            }
        }
        for (const key of PATH_FIELDS) {
            if (typeof obj[key] === 'string' && obj[key]) {
                targetPath = obj[key];
                break;
            }
        }
        for (const key of CONTENT_FIELDS) {
            const v = obj[key];
            if (typeof v === 'string' && v) {
                content = v;
                hasContentField = true;
                break;
            }
            if (Array.isArray(v) && v.length && v.every((x) => typeof x === 'string')) {
                content = v.join('\n');
                hasContentField = true;
                break;
            }
        }
    }
    // 命令通道始终扫（命令本身能表达写入语义）
    if (command)
        hits.push(...scanCommandForPersistence(command));
    // filepath 通道只在"写语义"下扫：写工具名，或 payload 显式携带内容字段
    if (targetPath && (WRITE_TOOL_RE.test(toolName) || hasContentField)) {
        hits.push(...scanFileWriteForPersistence(targetPath, content));
    }
    return hits;
}
