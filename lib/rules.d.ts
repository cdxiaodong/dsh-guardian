/** 危险规则定义与内置规则集 */
export interface Rule {
    id: string;
    pattern: RegExp;
    reason: string;
    /** block=需人工确认；deny=直接拒绝；log=仅记录 */
    action: 'block' | 'deny' | 'log';
    /** 规则分类，便于审计与统计 */
    category?: 'destructive' | 'injection' | 'credential' | 'exfil' | 'network' | 'filesystem' | 'prompt-injection' | 'tool-poisoning' | 'privesc' | 'rce';
    /** 风险权重 0~1，用于多信号加权评分（调研建议） */
    weight?: number;
}
/**
 * 内置规则集（按类别分组，规则 ID 借鉴 mcp-safeguard 分类法：CMD/PI/TP/CRED/EXFIL/PATH/PRIV）。
 * 所有正则不带 /g 标志，避免 lastIndex 状态污染。
 */
export declare const DEFAULT_RULES: Rule[];
