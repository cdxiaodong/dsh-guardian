/**
 * 哨兵引擎（Self-Guard Anti-Tamper + Anti-Forensics）—— engine-25
 *
 * 威胁模型：24 个检测引擎全部隐含一个公理——「护栏自身还活着」。
 * 但护栏自身就是可攻击资产：
 *   - 删/截断审计日志（~/.dsh-guardian.audit.log）→ 所有引擎的留痕归零（反取证）
 *   - Edit/Write 改护栏源码 / cordis.patch.yml → 下次加载 hook 消失
 *     （anthropics/claude-code#11226：官方确认 Claude 可改自己的 hook 脚本绕过
 *      permissions.deny，chmod 444 / root 属主 / 沙箱 / deny 列表四种缓解全部失效，
 *      issue 关闭为 not planned，无官方修复）
 *   - npm uninstall dsh-guardian / pkill 守护进程 → 护栏直接消失
 *   - chmod 000 / chattr +i 审计日志 → WriteStream 静默失败，护栏「活着但失明」
 *
 * 学术侧这已是独立攻击线：arXiv:2606.14517《DoS Attacks on LLM-Based Agent
 * Guardrails》(From Shield to Target)；Sysdig JADEPUFFER（2025）实测 agentic
 * 勒索在收尾阶段自主执行「删日志-停监控」的反取证动作。
 *
 * 防御思路（EDR killer 检测的 Agent 化）：
 *   「动词 × 护栏资产」目标矩阵——护栏资产是封闭集合（审计日志/完整性基线/
 *   插件目录），误报率趋近于零（rm ./app.log、npm uninstall lodash 天然不命中）。
 *   另收编 MITRE ATT&CK T1562/T1070（新编号 T1685 系列）的反取证命令族为
 *   FORENSIC- 规则组：': >' shell 重定向截断与 ln -sf /dev/null 黑洞化在
 *   SigmaHQ 生态中没有现成规则，是可声明的差异化空白。
 *
 * 与既有引擎的分工：
 *   - persistence-guard（engine-23）拦「埋」（写入持久化机制）；
 *     本引擎拦「拆」（拆卸护栏与清除痕迹），动词方向相反
 *   - rule 引擎的 CMD-002 要求 rm -rf（rm -f 单文件不命中）、path 沙箱只管
 *     白名单根目录与结构化 fs 工具——bash 命令串里的自家资产无人看守
 *   - 字符串层混淆绕过（Base64 编码路径等）由 deobfuscation（engine-9）兜底
 *   - 边界（诚实声明）：本引擎防的是「经工具调用通道的自毁」。若护栏进程已被
 *     杀死、或源码已被改成空函数，哨兵自身也不复存在——绝对自防护需要宿主
 *     提供外部监督（类比 EDR 的 tamper protection 依赖内核），这是插件层的
 *     天花板，不是本引擎的缺陷。
 */
/** 护栏自身资产（封闭集合，启动时解析为绝对路径） */
export interface SentinelAsset {
    kind: 'audit-log' | 'integrity-state' | 'plugin-dir' | 'extra';
    /** 绝对路径（目录资产做前缀匹配：目录内一切文件都算护栏资产） */
    path: string;
    label: string;
}
export interface SentinelHit {
    ruleId: string;
    reason: string;
    action: 'deny' | 'block';
    /** 命中的护栏资产（FORENSIC 组可能无） */
    assetKind?: SentinelAsset['kind'];
    /** 命中片段（截断，避免审计日志膨胀） */
    match: string;
}
export interface SentinelOptions {
    /** 展开 ~ 与 $HOME 用的家目录（默认 os.homedir()；测试注入避免环境漂移） */
    homedir?: string;
    /** 平台（darwin 下路径比较大小写不敏感；默认 os.platform()） */
    platform?: NodeJS.Platform;
}
/**
 * 解析护栏资产清单。资产是封闭集合，全部本地确定性推导：
 *  - 审计日志 / 完整性基线：家目录下的点文件（logFile 可被配置覆盖，跟随实际值）
 *  - 插件目录：从本模块安装位置向上找最近 package.json（node_modules/dsh-guardian
 *    或源码仓库根），目录内 src/lib/cordis.patch.yml/package.json 全部受前缀保护
 *  - extra：宿主追加（例如把自家 hook 脚本、策略文件也纳入保护）
 */
export declare function resolveSentinelAssets(opts?: {
    logFile?: string;
    extra?: string[];
    packageRoot?: string;
}): SentinelAsset[];
export interface ForensicRule {
    id: string;
    pattern: RegExp;
    reason: string;
    /** 映射的 ATT&CK 技术（便于审计溯源） */
    attck: string;
}
export declare const FORENSIC_RULES: ForensicRule[];
/** 编译后的哨兵匹配器（资产清单固化，正则只编译一次） */
export interface SentinelMatcher {
    scan(toolName: string, text: string): SentinelHit[];
}
/**
 * 编译哨兵匹配器。检测「动词 × 护栏资产」矩阵 + FORENSIC 反取证规则组。
 * 资产作为显式参数注入（而非模块级状态），测试可用伪造清单构造跨平台场景。
 */
export declare function compileSentinelMatcher(assets: SentinelAsset[], opts?: SentinelOptions): SentinelMatcher;
/** 一次性扫描便捷入口（内部编译匹配器；高频场景请复用 compileSentinelMatcher） */
export declare function scanSentinel(toolName: string, text: string, assets: SentinelAsset[], opts?: SentinelOptions): SentinelHit[];
