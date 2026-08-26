/** 一条攻击记忆（归一化后的攻击指纹） */
export interface AttackRecord {
    /** 宽松指纹（sha256 前 16 位）：记忆去重合并的键 */
    fp: string;
    /** 严格指纹（sha256 前 16 位）：完全重复攻击的判定键 */
    strictFp: string;
    /** 归一化后的去重 token 集（供 Jaccard 比对） */
    tokens: string[];
    /** 首次记住该攻击的时间（ISO） */
    ts: string;
    /** 命中的原始规则 ID（MEMORY-* 表示由记忆引擎自身的变种命中学习而来） */
    ruleId: string;
    /** 原始处置级别：deny 级攻击的精确重复仍 deny；block 级仍走人工确认 */
    severity: 'deny' | 'block';
    tool?: string;
    reason?: string;
}
/** 记忆命中结果 */
export interface MemoryHit {
    kind: 'exact' | 'similar';
    /** 相似度 0~1；exact 恒为 1 */
    similarity: number;
    record: AttackRecord;
}
/**
 * 宽松归一化（折叠 URL host 与路径）：同一攻击模板换目标/换路径后收敛到同一形态。
 * 用于"同形状"判定（similar 级）与记忆去重合并。
 * 顺序敏感：UUID → URL(先于 IP，让 IP 型 URL 整体折叠) → IP → 长 hex → 长 base64 → 路径 → 数字 → 空白。
 */
export declare function normalizePayload(text: string): string;
/**
 * 严格归一化：只折叠真正易变的原子要素（UUID/IP/长 hex/长 base64/裸数字/大小写/空白），
 * 保留 URL 与路径原样 —— 严格指纹一致才算"精确重复攻击"（deny 级语义）。
 */
export declare function strictNormalize(text: string): string;
/** 宽松指纹（sha256 前 16 位）：记忆去重合并的键 */
export declare function fingerprint(text: string): string;
/** 严格指纹（sha256 前 16 位）：完全重复攻击的判定键 */
export declare function strictFingerprint(text: string): string;
/** 归一化后按空白切分并去重的 token 集 */
export declare function tokenSet(text: string): string[];
/** Jaccard 相似度：|A∩B| / |A∪B|；任一侧为空返回 0 */
export declare function jaccard(a: string[], b: string[]): number;
export declare namespace AttackMemory {
    interface Config {
        /** 记忆文件路径；设为 '' 关闭持久化（仅内存态）。默认 ~/.dsh-guardian.memory.json */
        file?: string;
        /** 变种判定阈值 0~1，默认 0.55 */
        threshold?: number;
        /** 记忆容量上限（LRU 淘汰），默认 500 */
        maxRecords?: number;
        /** token 数低于该值的文本只做精确指纹匹配（避免 "rm -rf <path>" 之类短命令误报），默认 4 */
        minTokens?: number;
    }
}
/** 攻击记忆库：remember 落库，lookup 查询（精确指纹优先，其次相似度） */
export declare class AttackMemory {
    /** fp → record；Map 插入序即 LRU 序（重新 remember 会刷新到末尾） */
    private records;
    private readonly file;
    readonly threshold: number;
    private readonly maxRecords;
    private readonly minTokens;
    constructor(config?: AttackMemory.Config);
    /** 从磁盘载入记忆，返回载入条数（文件不存在/损坏时返回 0，不抛错） */
    load(): number;
    size(): number;
    clear(): void;
    /** 遗忘指定指纹（用户人工批准了记忆命中的攻击时调用） */
    forget(fp: string): void;
    /**
     * 记住一次攻击。宽松指纹相同视为同一条记忆（合并：刷新时间与 LRU 位、severity 就高不就低）。
     * 返回落库记录；文本归一化后无 token 时返回 null。
     */
    remember(text: string, meta: {
        ruleId: string;
        severity: 'deny' | 'block';
        tool?: string;
        reason?: string;
    }): AttackRecord | null;
    /**
     * 查询文本是否命中记忆（严格 → 宽松 → 相似度，逐级放松）：
     *  - exact：严格指纹一致（仅 UUID/IP/hex/base64/数字/大小写/空白差异）→ 完全重复攻击
     *  - similar(形状)：宽松指纹一致（换了路径/URL host 的同形状攻击）
     *  - similar(措辞)：token Jaccard ≥ threshold（改写措辞的变种）
     * token 过少的文本跳过宽松与相似度两级（避免 "rm -rf <path>" 类短命令泛化误报）。
     * 未命中返回 null。
     */
    lookup(text: string): MemoryHit | null;
    private persist;
}
