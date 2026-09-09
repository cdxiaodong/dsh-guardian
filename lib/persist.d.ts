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
/** 持久化命中：哪个通道、命中什么、为何危险 */
export interface PersistenceHit {
    ruleId: 'PERSIST-CRON' | 'PERSIST-RCFILE' | 'PERSIST-SSHKEY' | 'PERSIST-LAUNCHD' | 'PERSIST-SYSTEMD' | 'PERSIST-SCHTASKS' | 'PERSIST-PAYLOAD';
    /** 命中通道：command=命令惯用法 filepath=写入目标 content=写入载荷 */
    surface: 'command' | 'filepath' | 'content';
    action: 'deny' | 'block';
    reason: string;
    /** 命中的具体片段（截断），便于审计与人工确认展示 */
    match: string;
    /** 对应 MITRE ATT&CK 技术编号 */
    technique: string;
}
/** shell 启动文件（basename 精确匹配；写这些 = 每次开终端都执行，T1546.004） */
export declare const RC_FILENAMES: Set<string>;
/** macOS launchd 持久化目录（子串匹配路径段） */
export declare const LAUNCHD_DIR_SEGMENTS: string[];
/** systemd 持久化目录（用户级 + 系统级） */
export declare const SYSTEMD_DIR_SEGMENTS: string[];
/** cron 落盘目录（写这些路径 = 直接塞计划任务，T1053.003） */
export declare const CRON_DIR_SEGMENTS: string[];
/** 内容载荷扫描：返回命中的载荷规则（escalate 属性供定级） */
export declare function scanPayload(content: string): {
    reason: string;
    escalate: boolean;
    match: string;
}[];
/** filepath 通道：写入目标命中持久化面 → block；若载荷升压 → deny */
export declare function scanFileWriteForPersistence(targetPath: string, content?: string): PersistenceHit[];
/** command 通道：命令字符串里的持久化安装惯用法（全部 deny 级） */
export declare function scanCommandForPersistence(command: string): PersistenceHit[];
/**
 * 主入口：对一次工具调用做持久化检测。
 * 与纯正则引擎的区别在此：解析 payload 的字段结构，把命令/路径/内容分到各自通道——
 * 读语义（cat .bashrc）与写语义（edit .bashrc）得到不同判定。
 * 纯字符串 payload 视为命令扫描（bash 工具的惯例形态）。
 */
export declare function scanPersistence(toolName: string, payload: unknown): PersistenceHit[];
