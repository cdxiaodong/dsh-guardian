/**
 * 时空致命三角检测引擎（Lethal Trifecta / Meta "Agents Rule of Two"）。
 *
 * 借鉴来源：
 *  - Simon Willison "Lethal Trifecta"：Agent 同时具备 ①私有数据访问 ②不可信内容摄入 ③外部通信能力 时即高危，
 *    因为间接提示注入可以把私有数据顺着外部通道泄露出去。
 *  - Meta AI "Agents Rule of Two"：一个会话**最多只能占三条中的两条**，超过即违反部署启发式。
 *  - armosec "AI Agent Attack Kill Chain"：单次调用各自合法，只有"序列的形状"暴露攻击；
 *    外泄 = "允许的通道 + 允许的目的地 + 异常的形态"。
 *
 * 现有引擎都是**空间维度**（单次调用、无状态判定）；本引擎补齐**时间维度**：
 * 把一个会话滑动窗口内的工具调用投影到三类能力，三者齐备即判定致命三角成形。
 * 这正是 cordis「时空可组合」中"时间"维度的落地——单看每一次调用都可能合法，组合起来才暴露攻击。
 */
/** 三类能力维度（致命三角的三条边） */
export type Capability = 'private-data' | 'untrusted-content' | 'external-egress';
export declare const CAPABILITIES: readonly Capability[];
/** 一次能力观测事件 */
export interface TrifectaEvent {
    ts: number;
    capability: Capability;
    tool: string;
    /** 为什么归到这类能力（审计/说明用） */
    evidence: string;
}
export interface TrifectaTrackerOptions {
    /** 滑动窗口时长 ms（默认 10 分钟） */
    windowMs?: number;
    /** 窗口内最多保留事件数（默认 200，防爆内存） */
    maxEvents?: number;
    /** 注入时钟，便于测试（默认 Date.now） */
    now?: () => number;
}
export interface TrifectaStatus {
    /** 三者是否齐备（致命三角成形） */
    assembled: boolean;
    /** 窗口内已出现的能力 */
    present: Capability[];
    /** 尚缺的能力（Rule of Two：缺一条即合规） */
    missing: Capability[];
    /** 各能力在窗事件数 */
    counts: Record<Capability, number>;
    /** 各能力最近一次事件（用于审计/说明） */
    latest: Partial<Record<Capability, TrifectaEvent>>;
}
/**
 * 会话级滑动窗口能力追踪器。
 * 读取/写入都会先修剪过期事件，无需后台定时器（确定性、易测试）。
 */
export declare class TrifectaTracker {
    private events;
    private readonly windowMs;
    private readonly maxEvents;
    private readonly now;
    constructor(opts?: TrifectaTrackerOptions);
    /** 记录一次能力观测（随后修剪过期/超量事件） */
    record(capability: Capability, tool: string, evidence: string): void;
    /** 修剪：先剔除滑出时间窗的，再按容量上限 FIFO 淘汰 */
    private prune;
    /** 当前窗口状态（读取前修剪一次，保证不读到过期事件） */
    status(): TrifectaStatus;
    /** 致命三角是否成形 */
    assembled(): boolean;
    /** 清空窗口（插件卸载时的可逆效应清理） */
    reset(): void;
}
/** 一次工具调用的观测输入（由宿主/服务从既有检测器输出组装） */
export interface CapabilityObservation {
    /** 工具名 */
    tool?: string;
    /** 本次命中规则的 category 集合 */
    categories?: Iterable<string>;
    /** 本次是否检出明文密钥（secret 引擎） */
    secret?: boolean;
    /** 本次是否命中网络目标（ssrf 引擎） */
    network?: boolean;
}
/** 把一次工具调用投影到能力维度集合（去重、确定性顺序） */
export declare function classifyCapabilities(obs: CapabilityObservation): Capability[];
