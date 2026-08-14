import { Context, Service } from 'cordis';
export declare const name = "dsh-guardian";
/** 危险规则 */
export interface Rule {
    id: string;
    pattern: RegExp;
    reason: string;
    /** block=需人工确认；deny=直接拒绝；log=仅记录 */
    action: 'block' | 'deny' | 'log';
}
/** 内置规则集（命令注入 / 破坏操作 / 凭据读取 / 反弹shell / 外泄） */
export declare const DEFAULT_RULES: Rule[];
export interface AuditEntry {
    ts: string;
    level: 'allow' | 'block' | 'deny';
    tool?: string;
    ruleId?: string;
    reason?: string;
    snippet?: string;
}
declare module 'cordis' {
    interface Context {
        guardian: GuardianService;
    }
}
/**
 * 护栏服务：继承 cordis Service，name='guardian' 即对外提供的服务标识。
 * 宿主/上层在每次工具调用前触发 'guardian/check' 事件即可完成拦截。
 */
export declare class GuardianService extends Service {
    private stream;
    readonly logFile: string;
    private rules;
    constructor(ctx: Context, config?: GuardianService.Config);
    /**
     * 核心判定（适配 cordis bail 语义）：
     *  - 返回 { intercepted, reason, ruleId } 对象 → 命中规则，bail 短路返回该对象 = 拦截
     *  - 返回 false → 放行
     * 宿主用法：`const r = ctx.bail('guardian/check', tool, payload)`；r 为对象即被拦截。
     */
    check(toolName: string, payload: unknown): {
        intercepted: true;
        reason: string;
        ruleId: string;
        action: Rule['action'];
    } | false;
    audit(entry: Omit<AuditEntry, 'ts'>): void;
    readAudit(limit?: number): AuditEntry[];
    addRule(rule: Rule): void;
    listRules(): Rule[];
}
export declare namespace GuardianService {
    interface Config {
        logFile?: string;
        rules?: Rule[];
    }
}
/** cordis 插件入口（Function 形式），provide 声明对外提供 'guardian' 服务 */
export declare const provide: string[];
export declare function apply(ctx: Context, config?: GuardianService.Config): void;
