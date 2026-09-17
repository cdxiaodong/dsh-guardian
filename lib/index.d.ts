import { Context, Service } from 'cordis';
import { DEFAULT_RULES, type Rule } from './rules.js';
import { type SkillVerdict } from './skills.js';
export declare const name = "dsh-guardian";
export { DEFAULT_RULES, type Rule };
export { scanSecrets, SECRET_RULES, shannonEntropy, type SecretHit } from './secrets.js';
export { scanNetworkTarget, SSRF_RULES } from './ssrf.js';
export { checkPath, SENSITIVE_PREFIXES, SENSITIVE_SUFFIXES, type PathVerdict } from './path.js';
export { scoreSignals, collectSignals, secretEntropySignal, DEFAULT_THRESHOLDS, type RiskScore, type RiskSignal, type RiskThresholds } from './risk.js';
export { isSkillSurface, SKILL_SURFACES, SKILL_RULES, scanSkillContent, guardSkillWrite, scanShellSkillWrite, extractSkillTargets, worstSkillAction, scanSkillPayload, mergeSkillHits, collectSkillTargets, unescapeJsonText, type SkillRule, type SkillHit, type SkillVerdict, type SkillAction, } from './skills.js';
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    engine: 'rule' | 'secret' | 'ssrf' | 'skill';
    tool?: string;
    ruleId?: string;
    reason?: string;
    snippet?: string;
}
export interface Interception {
    intercepted: true;
    reason: string;
    ruleId: string;
    action: Rule['action'];
    engine: AuditEntry['engine'];
}
declare module 'cordis' {
    interface Context {
        guardian: GuardianService;
    }
}
/**
 * Agent 安全护栏服务（cordis Service，name='guardian'）。
 *
 * 工作流：宿主在每次工具调用前 `ctx.bail('guardian/check', tool, payload)`。
 *  - 返回 Interception 对象 → 拦截（deny 直接拒；block 先走 guardian/approve 人工确认）
 *  - 返回 false → 放行
 *
 * 四个检测引擎：
 *  1. skill  —— 技能面投毒（skills/commands/agents 树写入时扫描：动态上下文
 *     预执行标记、凭据外泄配对、frontmatter 元数据投毒、隐形字符）
 *  2. rule   —— 危险命令 / 破坏操作 / 提示注入正则规则
 *  3. secret —— 密钥/凭据泄露（gitleaks 风格）
 *  4. ssrf   —— 内网/元数据地址访问
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    private enableSecret;
    private enableSSRF;
    private enablePath;
    private enableSkills;
    private allowedRoots;
    constructor(ctx: Context, config?: GuardianService.Config);
    /** 路径沙箱校验：realpath + 白名单，返回 PathVerdict */
    checkPathAccess(target: string): import("./path.js").PathVerdict;
    /** 技能面写入判定：非技能面直接放行；技能面内容带毒则拦截并落审计 */
    checkSkillWriteAccess(target: string, content: string): SkillVerdict;
    /**
     * 识别「写技能面」的工具调用并判定（guardian/check 通道内用）——两条卡位
     * 并联而非互斥（工具名像写工具 ≠ payload 不是 shell 命令，对抗审查：互斥
     * 曾让 sed -i 经 run_command 工具名整体绕过）：
     *  - 路径 A：写入类工具 + 载荷中出现技能面路径 → 对载荷做内容判定
     *    （对象形态先逐字段取解码后的字符串原值——stringify 会把换行转义，
     *    frontmatter 定界与同行配对窗口在转义文本上失明；兜底扫描前先做
     *    JSON 反转义）
     *  - 路径 B：shell 写入/变更动词或内容载体指向技能面（echo 重定向/tee/cp/
     *    heredoc/sed -i/rm/git clone/tar/unzip/解释器 -c——绕过结构化写工具
     *    的路径路由）→ SKL-012 + 命令串内嵌内容扫描
     * 闸门用 collectSkillTargets：对载荷解码后的字段原值提取目标（对抗审查：
     * \uXXXX 转义路径与 Windows 反斜杠路径在原始文本上曾整体失明）。
     */
    private checkSkillSurface;
    /** 技能命中 → Interception：deny 直接拦；block 走人工确认（透出全部命中 ruleId） */
    private interceptSkillHits;
    /** 核心判定。返回 Interception=拦截；false=放行（cordis bail 语义） */
    check(toolName: string, payload: unknown): Interception | false;
    /** 处理单条命中规则：deny 直接拦；block 走人工确认 */
    private handleRule;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
}
export declare namespace GuardianService {
    interface Config {
        logFile?: string;
        rules?: Rule[];
        /** 是否启用密钥泄露扫描（默认 true） */
        scanSecrets?: boolean;
        /** 是否启用 SSRF/内网访问扫描（默认 true） */
        scanSSRF?: boolean;
        /** 是否启用路径沙箱校验（默认 true） */
        checkPaths?: boolean;
        /** 是否启用技能面投毒引擎：skills/commands/agents 树写入扫描（默认 true） */
        guardSkills?: boolean;
        /** 沙箱白名单根目录（设置后，路径必须落在其中之一） */
        allowedRoots?: string[];
    }
}
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
