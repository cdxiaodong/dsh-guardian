/**
 * 出境滞留引擎（Egress Escrow Guard）——"先扣货、后放行"的延迟出境闸门。
 *
 * 借鉴 Provisional Reachability（arXiv:2609.18741, 2026-09-18）的核心思想：
 * 防御者每周期要拦的不是"次数"而是"比特数"；把每次携带敏感数据的出境
 * 调用先押入 escrow（滞留/托管）一个观察窗口，窗口内审计若发现风险信号
 * 即可撤销（rollback 那次调用），从而把"秘密可在任一时刻组装完成"降级为
 * "秘密必须在整个窗口内持续未被发现才能组装"。
 *
 * 本引擎是该论文 escrow+revoke 机制的确定性本地实现（LLM Agent 工具调用层）：
 *  - ESC-001：payload 命中敏感内容（凭据路径/密钥/PII 关键段）的出境外呼
 *              → hold（block 变体：需人工批准，且即便批准也计入滞留配额）
 *  - ESC-002：滞留配额 —— 观察窗口内出境比特数（去重脱敏后的内容指纹数）
 *              超过 bitBudget 即升级 deny（速率维度，逆限流）
 *  - ESC-003：自愈 —— 敏感指纹滑出窗口后自动释放，配额恢复
 *  - 撤销语义：宿主调用 release/rollback 时输出审计事件，供外部联动
 *
 * 与 engine-9（Egress Budget）的区别：budget 是"即时字节守恒"，本引擎是
 * "时间维度上的可撤销出境"—— 每次敏感出境都先扣为 escrow，观察期是宽限
 * 而非放行；审计信号在窗口内出现则整批撤销。
 */
export interface EscrowEntry {
    /** 调用序号 */
    seq: number;
    /** 工具名 */
    tool: string;
    /** 指纹（脱敏采样 + FNV-1a），用于去重记账 */
    fingerprint: string;
    /** 记账时间戳（可注入时钟） */
    at: number;
}
export interface EscrowVerdict {
    /** true = 拦截（hold/deny） */
    intercepted: boolean;
    ruleId: 'ESC-001' | 'ESC-002' | null;
    reason: string;
    /** 当前窗口内滞留的比特数（配额读数） */
    heldBits: number;
    /** 本次是否计入滞留（被拦也入账：逆限流记账原则） */
    counted: boolean;
}
export interface EscrowConfig {
    /** 观察窗口毫秒数（默认 10 分钟） */
    windowMs?: number;
    /** 窗口内允许滞留的比特数配额（默认 2048） */
    bitBudget?: number;
    /** 是否启用 PII 内容检测（默认 true） */
    scanContent?: boolean;
}
/** FNV-1a 64 位哈希（BigInt），内容指纹用 */
export declare function fnv1a64(s: string): string;
/**
 * 估算一个指纹承载的"比特数"。
 * 去重后每个独立内容指纹记 64 比特（哈希宽度）——同一内容反复出境
 * 不增记，这就是"秘密重组需要的是多样性而非次数"的量化表达。
 */
export declare function bitsOf(fingerprint: string): number;
/** 判定 payload 是否携带敏感内容（返回首个命中探针，供审计展示） */
export declare function probeSensitive(text: string): {
    id: string;
    label: string;
    snippet: string;
} | null;
/**
 * 出境滞留账本。所有携带敏感内容的出境调用（含被拦的）都入账——
 * 记账无条件先于判定，同 engine-29/30/31 惯例。
 */
export declare class EscrowTracker {
    private config;
    private entries;
    private seq;
    constructor(config: Required<EscrowConfig>);
    private prune;
    /**
     * 记账并判定。返回 verdict；counted=true 表示本条已入滞留账。
     * 记账无条件：即使 deny 也入账（逆限流：被拦的尝试照样消耗注意力预算）。
     */
    record(tool: string, payload: string, now?: number): EscrowVerdict;
    /** 当前窗口滞留比特数（去重） */
    heldBits(now?: number): number;
    /** 撤销：清空滞留账（审计信号命中时宿主调用，对应论文的 revoke） */
    revoke(): number;
    /** 窗口内明细（审计用） */
    snapshot(): EscrowEntry[];
}
export declare function createEscrowTracker(config?: EscrowConfig): EscrowTracker;
