/** 宿主上报的最小工具定义（MCP tools/list 条目的子集） */
export interface ToolSpec {
    name: string;
    description?: string;
    /** JSON Schema 形态的参数定义 */
    inputSchema?: unknown;
}
/** 基线条目：批准时刻的指纹 + 描述快照（供审计比对） */
export interface BaselineEntry {
    hash: string;
    description?: string;
}
export type ManifestFindingKind = 'rugpull' | 'schema-drift' | 'new-tool' | 'removed-tool' | 'squat';
export interface ManifestFinding {
    kind: ManifestFindingKind;
    ruleId: string;
    tool: string;
    reason: string;
    severity: 'deny' | 'block' | 'log';
    /** 新旧摘要（截断），便于人工审计比对 */
    detail?: string;
}
export interface ManifestVerdict {
    safe: boolean;
    findings: ManifestFinding[];
    /** 本次清单整体指纹（sha256 前 16 位 hex） */
    fingerprint: string;
}
export interface IntegrityOptions {
    /** 会话中途新增工具的处置（默认 'block' 走人工确认；'allow' 则不产生 finding） */
    newToolPolicy?: 'deny' | 'block' | 'log' | 'allow';
}
/** 稳定序列化：对象键排序，保证同内容不同键序 → 同 hash */
export declare function canonicalJson(v: unknown): string;
/** 单个工具的指纹：sha256(name + description + inputSchema) */
export declare function hashToolSpec(spec: ToolSpec): string;
/** 整份清单的指纹：按工具名排序后级联，用于快速比对/审计引用 */
export declare function manifestFingerprint(specs: ToolSpec[]): string;
/** 工具清单 → 基线（批准时刻 pin） */
export declare function toBaseline(tools: ToolSpec[]): Map<string, BaselineEntry>;
/**
 * 生成 pin 锁文件（name → hash 映射，类似 package-lock 的角色）。
 * 宿主在受控环境下生成一次，写进配置 manifestBaseline，之后任何漂移都会被拒绝。
 */
export declare function pinManifest(tools: ToolSpec[]): Record<string, string>;
/** 工具名规范化：NFKC（全角→半角）+ 去零宽 + 同形字符折叠 + 小写 */
export declare function normalizeName(name: string): string;
/** Dice 双字符相似度（0~1），识别重命名/仿冒名 */
export declare function diceSimilarity(a: string, b: string): number;
/**
 * 比对当前工具清单与授权基线，产出 findings（纯函数，无副作用，便于测试）。
 * - 描述被改 → rugpull（deny）
 * - 仅 schema 被改 → schema-drift（block，人工重授权）
 * - 新增工具 → new-tool（默认 block，按 newToolPolicy）
 * - 工具消失 → removed-tool（log）
 * - 同形异码/高相似仿冒名 → squat（deny）
 */
export declare function diffManifests(baseline: ReadonlyMap<string, BaselineEntry>, current: ToolSpec[], opts?: IntegrityOptions): ManifestFinding[];
