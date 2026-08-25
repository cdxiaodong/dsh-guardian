/**
 * 污点追踪引擎（Engine 12）：跨调用的信息流控制（IFC）。
 *
 * 思想借鉴 Google DeepMind 的 CaMeL（Capabilities for Machine Learning, 2025-04）：
 * 提示注入无法被 100% 检测，但可以追踪"不可信/敏感数据"在系统里的流动，
 * 让污点值流向高危 sink（外传/exec）时必须显式获得能力（capability）授权。
 *
 * 与其他引擎的本质区别：其余引擎做"单点检测"（每次工具调用独立扫描内容），
 * 本引擎做"跨调用数据流检测"——
 *   ① 敏感内容进入上下文（读 .env / 私钥 / 用户 PII）→ 注册污点源，提取内容指纹
 *   ② 后续任何工具调用参数携带该内容（原文 / base64 / hex / URL 编码 / ROT13 变体）
 *      → 视为污点外传，拦截并要求人工授权
 *
 * 攻击场景：单看每次调用都无害（"读配置文件"放行、"POST 到合法 API"放行），
 * 但数据流构成泄露——只有污点追踪能抓到。
 *
 * 指纹方案：规范化（小写+去空白）后切固定宽度字符窗口（shingle），
 * FNV-1a 哈希入池；匹配时对 payload 的各解码变体切窗口求交集，
 * 交集 ≥ minHits（默认 3，要求 ~10+ 连续字符相同）即判定携带污点。
 */
/** FNV-1a 32bit 哈希：短串指纹，快且分布均匀 */
export declare function fnv1a(s: string): number;
/** 规范化：小写 + 去所有空白。让 "sk-AbC" / "sk-Ab C" / "sk-abc\n" 指纹一致 */
export declare function normalizeText(s: string): string;
/** 滚动字符窗口（shingle）切分 + 哈希。内容过长时均匀采样，封顶防膨胀 */
export declare function shingles(s: string, windowSize?: number, cap?: number): number[];
export type TaintVariant = 'plain' | 'base64' | 'hex' | 'url' | 'rot13';
/**
 * 对 payload 生成解码变体候选集：
 *  - plain：原文
 *  - base64：所有 ≥16 字符的 base64 片段各自解码（对抗"编码后塞 URL/body"）
 *  - hex：所有 ≥32 字符的 hex 片段解码
 *  - url：整体 decodeURIComponent + 所有 %XX 密集片段解码
 *  - rot13：整体 ROT13（对抗字母替换混淆外传）
 */
export declare function decodeVariants(payload: string): Array<{
    variant: TaintVariant;
    text: string;
}>;
/** 污点源注册请求（宿主在敏感内容进入上下文后调用 guardian/taint 事件） */
export interface TaintSource {
    /** 源标识，如 'fs:/Users/x/.env' 或 'pii:user-profile' */
    id: string;
    /** 人话描述，出现在拦截理由与审计日志里 */
    description: string;
    /** 敏感内容本体（用于提取指纹；引擎不保留原文） */
    content: string;
    /** 覆盖全局 TTL */
    ttlMs?: number;
}
export interface TaintRecord {
    id: string;
    description: string;
    fingerprint: Set<number>;
    registeredAt: number;
    expiresAt: number;
}
export interface TaintHit {
    sourceId: string;
    description: string;
    /** 命中的 shingle 交集数（≥ minHits） */
    matched: number;
    /** 通过哪种变体匹配到（编码外传的归因证据） */
    variant: TaintVariant;
}
export interface TaintEngineConfig {
    enable?: boolean;
    /** shingle 窗口宽度（默认 8 字符） */
    windowSize?: number;
    /** 判定命中的最小指纹交集（默认 3） */
    minHits?: number;
    /** 污点源存活时长（默认 30 分钟；防上下文早已遗忘后仍误拦） */
    ttlMs?: number;
    /** 污点源数量上限，超出淘汰最旧的（默认 64） */
    maxSources?: number;
    /** 每个源指纹数上限（默认 512） */
    maxShinglesPerSource?: number;
    /** 命中后动作：block=人工确认后放行（CaMeL 式 capability 授予），deny=直接拦（默认 block） */
    action?: 'deny' | 'block';
    /** 过期清扫周期 ms；0=仅惰性清理（默认 60_000） */
    sweepIntervalMs?: number;
}
export declare const DEFAULT_TAINT_CONFIG: Required<TaintEngineConfig>;
/**
 * 污点池：源注册 / 过期清扫（惰性 + 定时）/ 变体感知匹配。
 * 纯内存状态，随插件实例生命周期销毁（时间维度：宿主 dispose 即整池清空）。
 */
export declare class TaintPool {
    private readonly sources;
    private readonly cfg;
    constructor(cfg?: TaintEngineConfig);
    get config(): Required<TaintEngineConfig>;
    get size(): number;
    /** 注册污点源（同 id 重复注册 = 刷新指纹与 TTL） */
    register(src: TaintSource): TaintRecord;
    /** 清除过期源。返回被清除的 id 列表 */
    sweep(now?: number): string[];
    /**
     * 匹配：对 text 的所有解码变体切指纹，与每个存活源求交集。
     * 命中即返回证据（含变体归因）——同一个源只报最强命中（plain 优先保留）。
     */
    match(text: string): TaintHit[];
    clear(): void;
}
