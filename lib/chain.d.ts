/**
 * 攻击链时序检测引擎（Engine 10：Kill-Chain / 跨调用状态机）。
 *
 * 灵感与借鉴：
 *  - MITRE ATLAS™（https://atlas.mitre.org/）—— kill chain 战术序列知识库
 *    （16 tactics / 84 techniques），攻击按 Reconnaissance → Credential Access →
 *    Collection → Exfiltration 的阶段序列推进；
 *  - ARMO "assemble signals into an attack story" —— 把离散的单次告警组装成
 *    完整攻击叙事，而不是孤立地看每次工具调用；
 *  - Promptfoo 红队的多步攻击插件（context poisoning / memory manipulation）——
 *    验证了针对有状态 Agent 的攻击天然是跨调用、多步骤的。
 *
 * 核心创新：现有引擎全部是"单次调用"视角——读 .env（block）、base64 编码（放行）、
 * curl 上传（block）每一步单独看都有各自处置，但序列组合起来是完整的凭据外传链。
 * 本引擎为每条内置链维护一个有限状态机，按序消费工具调用事件，链达成时输出
 * 高置信度攻击叙事并升级处置（deny / 人工确认）。
 */
import { type Rule } from './rules.js';
/** 一次工具调用归一化后的信号摘要（喂给状态机的输入） */
export interface ChainEvent {
    tool: string;
    /** 调用文本（前若干字符，供 where 谓词做语义匹配） */
    text?: string;
    /** 本次命中的所有规则/引擎信号 ID，如 ['CRED-004', 'cloud-metadata-aws'] */
    ruleIds: string[];
    /** 归一化后的类别，如 ['credential']（SSRF 命中归 network，密钥命中归 credential） */
    categories: string[];
    /** 本次调用是否已被单步引擎拦截——被拦截的尝试同样推进链（暴露攻击意图序列） */
    intercepted?: boolean;
    /** 事件时间戳（毫秒）。可注入以便测试，默认 Date.now() */
    ts?: number;
}
/** 链阶段匹配器：各条件取并集（任一满足即匹配当前阶段） */
export interface StageMatcher {
    /** 阶段名（攻击叙事用），如 'Credential Access' */
    label?: string;
    /** 命中任一规则 ID 即匹配（含 SSRF/secret 等非 Rule 引擎的 ID） */
    anyRuleIds?: string[];
    /** 命中任一类别即匹配 */
    anyCategories?: string[];
    /** 工具名任一匹配（支持前缀通配，如 'web*'） */
    anyTools?: string[];
    /** 自定义谓词（可读 event.text 做语义判断） */
    where?: (event: ChainEvent) => boolean;
}
export interface ChainPattern {
    id: string;
    name: string;
    /** ATLAS 风格的战术序列描述 */
    tactics: string;
    severity: 'critical' | 'high';
    /** 链达成的处置：deny=直接拒绝；block=人工确认 */
    action: 'deny' | 'block';
    /** 链窗口毫秒数：相邻阶段间隔超过则重置（默认 15 分钟） */
    windowMs?: number;
    /** 完成度触发阈值（已完成阶段数/总阶段数 ≥ 此值即触发，默认 1=全链完成） */
    triggerAt?: number;
    /** 按序推进的阶段序列 */
    stages: StageMatcher[];
}
/** 某条链的运行时进度快照 */
export interface ChainProgress {
    chainId: string;
    /** 已完成阶段数（下一个待匹配下标） */
    stageIndex: number;
    startedAt: number;
    lastAdvancedAt: number;
    /** 各阶段命中事件快照（攻击叙事素材） */
    events: Array<{
        stage: number;
        ts: number;
        tool: string;
        signals: string[];
        snippet?: string;
    }>;
}
export interface ChainVerdict {
    chainId: string;
    name: string;
    /** complete=全链完成；threshold=达到 triggerAt 升级阈值 */
    trigger: 'complete' | 'threshold';
    /** 完成度 0~1 */
    progress: number;
    action: 'deny' | 'block';
    severity: 'critical' | 'high';
    /** 人类可读的攻击叙事：每阶段一行 */
    story: string[];
}
/**
 * 内置攻击链库（编号沿用 mcp-safeguard 风格前缀 CHAIN-）。
 * 阶段信号尽量复用现有五引擎的规则 ID / 类别，跨引擎组装叙事。
 */
export declare const KILL_CHAINS: ChainPattern[];
/**
 * 攻击链状态机引擎。
 * 每条 ChainPattern 一个独立状态机；同一事件可同时推进多条链；
 * 阶段必须按序匹配（kill-chain 语义），乱序事件忽略。
 */
export declare class ChainEngine {
    private patterns;
    private categoryIndex;
    private active;
    constructor(patterns?: ChainPattern[], rules?: Rule[]);
    /** 消费一次工具调用事件，返回本次达成的链 verdict（可能多条，也可能为空） */
    observe(event: ChainEvent): ChainVerdict[];
    /** 阶段匹配：anyRuleIds / anyCategories / anyTools / where 任一满足即可 */
    private matchStage;
    /** 所有进行中的链进度快照（宿主可查询做态势展示） */
    progress(): ChainProgress[];
    /** 重置状态（全部或指定链） */
    reset(chainId?: string): void;
}
