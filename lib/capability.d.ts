/**
 * 能力衰减引擎（Engine 21）：混淆代理人（Confused Deputy）防护 —— 完整性侧防线。
 *
 * 借鉴来源：
 *  - Cloud Security Alliance《Confused Deputy Attacks on Autonomous AI Agents》(2026)：
 *    经典 confused deputy 是访问控制漏洞——低权限攻击者借高权限 Agent 之手越权行动；
 *    修复思路是"绑定身份 + 传播授权"，而非继续打磨提示词。
 *  - Stack Overflow Blog (2026-06)《AI agents are a confused deputy with the keys to your kingdom》：
 *    Agent 暴露的缺失控制正是"调用者身份绑定"。
 *  - Quarkslab《Agentic AI: the confused deputy problem》：这是授权问题，不是模型质量问题。
 *  - 对象能力模型（object-capability, Mark Miller）的 attenuation 原则：
 *    权威可以衰减传播、绝不自动增强——LLM 上下文恰是反例：一段网页文本就能"免费"获得
 *    与用户本人等价的工具调度权。本引擎把这条被打破的定律装回去。
 *
 * 与既有引擎的正交性：
 *  - Engine 12（污点追踪）管机密性：敏感数据**流出**要授权；
 *  - Engine 7（致命三角）管外泄三角**成形**告警；
 *  - 本引擎管完整性：不可信**指令流入**决策后，特权副作用操作自动降权。
 *    判定不看本次 payload 说了什么（其余引擎都盯 payload），只看"此刻谁在说话"——
 *    会话信任状态 + 工具副作用类别。
 *
 * 核心机制：
 *  ① 指令性语言检测（data vs. code 的 LLM 翻版）：外部内容是"数据"还是"指令"？
 *     数据可以进上下文；携带指令性话术的内容 = 潜在 confused deputy 载荷。
 *  ② 信任账本（TrustLedger）：跨调用状态机。ingest 污染内容 → 会话进入衰减态，
 *     影响窗口（默认 3 步）内的副作用类工具（exec/write/delete/network/credential）
 *     一律降为人工确认。
 *  ③ 委托凭证（delegation voucher）：人工确认后按 (来源, 类别) 发放、次数受限——
 *     授权可传播但可衰减、可撤销，绝不无中生有。
 */
/** 工具的副作用类别（衰减保护只关心"写世界"的操作） */
export type ToolCategory = 'exec' | 'write' | 'delete' | 'network' | 'credential' | 'benign';
/** 衰减态默认保护的副作用类别 */
export declare const PROTECTED_CATEGORIES: readonly ToolCategory[];
/** 工具名 → 副作用类别的内置映射（子串匹配，大小写不敏感；宿主可用 config 覆盖） */
export declare const TOOL_CATEGORY_PATTERNS: ReadonlyArray<{
    category: ToolCategory;
    pattern: RegExp;
}>;
/** 指令性话术规则：判定外部内容携带"指令"而非"数据"（ID 前缀 ILK = illocutionary，言语行为） */
export interface DirectiveRule {
    id: string;
    pattern: RegExp;
    description: string;
}
export declare const DIRECTIVE_RULES: DirectiveRule[];
/** 一次指令性话术命中 */
export interface DirectiveHit {
    ruleId: string;
    description: string;
    match: string;
}
/** 扫描外部内容中的指令性话术。携带指令的内容视为潜在 confused deputy 载荷 */
export declare function detectDirectives(content: string): DirectiveHit[];
/** 工具名 → 副作用类别（benign = 无需衰减保护） */
export declare function classifyTool(toolName: string, overrides?: Record<string, ToolCategory>): ToolCategory;
/** ingest 申报结果：宿主可据此得知该批内容的信任判定 */
export interface IngestResult {
    source: string;
    polluted: boolean;
    directives: DirectiveHit[];
}
/** 衰减判定：命中时说明该类别操作正处于不可信内容影响窗口内 */
export interface AttenuationInfo {
    sources: string[];
    directives: DirectiveHit[];
    remaining: number;
    reason: string;
}
export interface TrustLedgerOptions {
    /** 影响窗口步数：污染后多少次工具调用内视为"受影响"（默认 3） */
    influenceSteps?: number;
}
/**
 * 信任账本：跨调用的会话信任状态机。
 * - ingest / pollute 建立污染；step 随每次工具调用衰减；窗口关闭自动恢复。
 * - attenuatedFor(category) 查询副作用类别是否被衰减（有凭证则消费凭证并放行）。
 */
export declare class TrustLedger {
    private pollutions;
    private vouchers;
    private readonly influenceSteps;
    constructor(opts?: TrustLedgerOptions);
    /** 申报外部内容摄入：携带指令性话术即建立污染 */
    ingest(source: string, content: string): IngestResult;
    /** 手动建立污染（宿主明确知道某来源不可信时） */
    pollute(source: string, reason: string, directives?: DirectiveHit[]): void;
    /**
     * 查询副作用类别是否被衰减。命中有效凭证 → 消费一次并返回 null（授权可传播，但次数受限）。
     * 判定即消费：guardian/check 每次只查一次，语义为"凭证兑换放行"。
     */
    attenuatedFor(category: ToolCategory): AttenuationInfo | null;
    /** 人工确认通过后发放委托凭证：限定来源 + 类别 + 次数 */
    grant(source: string, category: ToolCategory, uses?: number): void;
    /** 每次工具调用消耗一步影响窗口；窗口关闭的污染事件自动出清 */
    step(): void;
    /** 清除污染（新会话 / 人工复核整批内容后），可指定单一来源 */
    clear(source?: string): void;
    /** 当前状态（审计 / 调试） */
    status(): {
        polluted: boolean;
        sources: {
            source: string;
            reason: string;
            remaining: number;
            directives: string[];
        }[];
        vouchers: {
            source: string;
            category: ToolCategory;
            uses: number;
        }[];
    };
}
