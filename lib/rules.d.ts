/** Dangerous rule definitions and built-in rule set */
export interface Rule {
    id: string;
    pattern: RegExp;
    reason: string;
    /** block=requires manual confirmation; deny=reject outright; log=record only */
    action: 'block' | 'deny' | 'log';
    /** Rule category, for auditing and statistics */
    category?: 'destructive' | 'injection' | 'credential' | 'exfil' | 'network' | 'filesystem' | 'prompt-injection' | 'tool-poisoning' | 'privesc';
    /** Risk weight 0~1, for multi-signal weighted scoring (per research recommendation) */
    weight?: number;
}
/**
 * Built-in rule set (grouped by category; rule IDs borrowed from the mcp-safeguard taxonomy: CMD/PI/TP/CRED/EXFIL/PATH/PRIV).
 * No regex uses the /g flag, to avoid lastIndex state pollution.
 */
export declare const DEFAULT_RULES: Rule[];
