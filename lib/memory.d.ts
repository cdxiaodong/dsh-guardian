/** 受保护的 Agent 认知上下文文件模式（对路径末段做全小写匹配） */
export declare const AGENT_CONTEXT_PATTERNS: RegExp[];
/** 判定一个路径是否是受保护的 Agent 认知上下文文件 */
export declare function isAgentContextFile(target: string): boolean;
/** 记忆投毒规则：内容一旦被下次会话当指令加载即生效，故阈值整体高于普通提示注入 */
export interface MemoryRule {
    id: string;
    pattern: RegExp;
    reason: string;
    /** deny=直接拒；block=人工确认；log=仅记录（写入认知文件时 log 也会记录审计） */
    action: 'block' | 'deny' | 'log';
}
/**
 * 内置记忆投毒规则集（MEM-xxx）。所有正则不带 /g 标志。
 * 这些内容将被持久化并在下次会话以高权限加载——"现在只是可疑"
 * 持久化之后就是"每会话都执行的恶意指令"。
 */
export declare const MEMORY_RULES: MemoryRule[];
export interface MemoryHit {
    ruleId: string;
    reason: string;
    action: MemoryRule['action'];
    /** 命中片段（截断，避免审计日志膨胀） */
    match: string;
}
/** 对将被写入 Agent 认知上下文文件的内容做投毒扫描 */
export declare function scanMemoryContent(text: string): MemoryHit[];
/** 命中集合中最严动作：deny > block > log */
export declare function worstAction(hits: MemoryHit[]): MemoryRule['action'] | null;
export interface MemoryVerdict {
    safe: boolean;
    target: string;
    /** isContextFile=false 时为空：目标根本不是受保护文件，不适用本引擎 */
    isContextFile: boolean;
    hits: MemoryHit[];
    reason?: string;
}
/**
 * 写时判定：目标是否受保护 + 内容是否带毒。
 * TOFU 语义：内容干净时顺带刷新该文件的哈希基线（首次信任，之后验篡改）。
 */
export declare function guardMemoryWrite(target: string, content: string, store?: MemoryIntegrityStore): MemoryVerdict;
export type IntegrityStatus = 'ok' | 'modified' | 'untracked' | 'missing';
export interface IntegrityResult {
    status: IntegrityStatus;
    target: string;
    /** status=modified 时的期望/实际摘要，便于人工 diff 定位 */
    expected?: string;
    actual?: string;
}
/**
 * 认知上下文文件哈希基线库。TOFU：首次写入干净内容即建基线；
 * 之后每次校验，内容哈希变化 = 记忆被篡改（boot-time integrity check）。
 * 基线持久化为 JSON，宿主会话启动时调用 verify() 做启动自检。
 */
export declare class MemoryIntegrityStore {
    readonly file?: string | undefined;
    private baseline;
    private dirty;
    constructor(file?: string | undefined);
    private hash;
    /** 建立/刷新某文件的基线（仅干净内容应调用） */
    pin(target: string, content: string): void;
    /** 校验当前内容是否偏离基线 */
    verify(target: string, content: string): IntegrityResult;
    /** 便捷：直接从磁盘读取并校验受保护文件（启动自检用） */
    verifyOnDisk(target: string): IntegrityResult;
    /** 撤销某文件基线（宿主主动确认变更后重新信任） */
    unpin(target: string): boolean;
    list(): string[];
    flush(): void;
}
