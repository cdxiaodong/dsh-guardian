/**
 * 声明式 YAML 安全策略引擎（Policy-as-Code）。
 *
 * 借鉴 Edictum（2026 运行时治理库）的 YAML 安全契约思想：
 * 工具调用先按外部 YAML 策略评估（工具名通配 + 参数正则 + 优先级 + allow 白名单豁免），
 * 再落入内置规则引擎——策略即数据，不改代码即可上线下线护栏。
 *
 * 热加载安全原则：解析/校验失败时保留旧策略并告警，绝不因配置错误而裸奔。
 */
/** 策略动作。allow=显式放行（豁免后续 rule 引擎，仍保留密钥扫描） */
export type PolicyAction = 'allow' | 'deny' | 'block' | 'log';
export interface PolicyRule {
    id: string;
    /** 工具名匹配，支持 * 通配（shell* / browser.* / *）。缺省=匹配所有工具 */
    tool?: string | string[];
    /** 参数内容正则（字符串形式，YAML 里写）。缺省=该工具的任意调用都命中 */
    match?: string;
    matchFlags?: string;
    action: PolicyAction;
    reason?: string;
    /** 数值越小越先评估（默认 100）。首个命中的策略生效 */
    priority?: number;
}
/** YAML 策略文件结构 */
export interface PolicyFile {
    version?: number;
    policies: PolicyRule[];
}
/** 编译后的策略（match 已编译成正则、tool 已编译成 glob 正则） */
export interface CompiledPolicy extends PolicyRule {
    /** 仅供排序与调试；不影响对外 API */
    priority: number;
}
export interface PolicyLoadResult {
    ok: boolean;
    /** 生效策略数（失败时为当前保留的旧策略数） */
    count: number;
    errors: string[];
}
/** glob → RegExp：* 匹配任意字符段，其余字面量化 */
export declare function globToRegExp(pattern: string): RegExp;
/** 校验并编译策略列表。返回 { policies, errors }——有错时 policies 为空（原子性：要么全过要么不生效） */
export declare function compilePolicies(raw: PolicyFile): {
    policies: CompiledPolicy[];
    errors: string[];
};
/** 解析 YAML 文本 → 校验编译。失败返回空 + errors（不抛异常，供热加载安全回退） */
export declare function parsePolicyYaml(text: string): {
    policies: CompiledPolicy[];
    errors: string[];
};
/** 单条已编译策略是否命中 (toolName, payloadText) */
export declare function policyMatches(p: CompiledPolicy, toolName: string, text: string): boolean;
/** 按优先级评估，返回首条命中策略；无命中返回 null */
export declare function evaluatePolicies(policies: CompiledPolicy[], toolName: string, text: string): CompiledPolicy | null;
