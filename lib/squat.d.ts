/**
 * 供应链抢注引擎（Squat Guard）—— slopsquatting + typosquatting 的确定性本地防线
 *
 * 威胁模型：LLM Agent 按模型建议执行 `npm install <pkg>` 时，包名可能来自
 *  1. 人类手滑打错（typosquatting：`lodash` → `lodahs`）
 *  2. 模型幻觉出的不存在包名（slopsquatting：arXiv:2406.10279 实测 ~19.7% 的
 *     生成包名是幻觉，且 21.7% 的幻觉名在样本间重复出现——重复意味着可被攻击者
 *     预先抢注，CSA 2026-04 研究注记将其列为 AI 供应链攻击面）
 * 两种情况下，攻击者只要抢注这个名字，Agent 就会把恶意 postinstall 直接送进沙箱。
 *
 * 检测全部离线、确定性，不需要注册表网络查询（借鉴 Socket.dev / Endor Labs 的
 * 云端思路，但把其中可本地化的部分抽出来）：
 *  - T1 typosquat：Damerau-Levenshtein（OSA）编辑距离 ≤ 阈值，命中主流包基线
 *    （先做同形字归一 + leet 归一，复扫变体，思路同 Engine-9 decode-before-scan）
 *  - T2 信任后缀/作用域仿冒：`<主流包>-utils/sdk/official/...`、`@<主流包>/x`
 *    ——幻觉包名的典型构词法（"熟悉的词 + 通用后缀 = 看起来真实"）
 *  - T3 已知抢注语料：有公开事件背书的真实抢注名（crossenv、colourama 等），deny 级
 *
 * 可组合增强：宿主可注册 `guardian/registry` 监听器提供注册表事实
 * （返回 { known: boolean }），引擎用它把"疑似"升级为"实锤"——
 * 判定逻辑归 guardian，网络能力归宿主（对象能力模型的分工）。
 */
/** 包生态系统 */
export type Ecosystem = 'npm' | 'pypi' | 'cargo' | 'gem';
export interface SquatHit {
    ruleId: 'SQUAT-TYPO' | 'SQUAT-SUFFIX' | 'SQUAT-SCOPE' | 'SQUAT-CORPUS';
    ecosystem: Ecosystem;
    /** 实际要安装的包名 */
    package: string;
    /** 疑似仿冒的主流包名（T3 为空） */
    target?: string;
    /** T1 的编辑距离（归一化后） */
    distance?: number;
    /** 变体归一类型：homoglyph（同形字）/ leet（形近数字符号替换）/ none */
    variant?: 'homoglyph' | 'leet' | 'none';
    reason: string;
    /** corpus 命中为 deny 级；其余为 block 级（人工确认） */
    action: 'deny' | 'block';
}
export declare const BASELINE_PACKAGES: Record<Ecosystem, string[]>;
export declare const KNOWN_SQUATS: string[];
/** 通用"信任后缀"：幻觉包名的典型构词成分（T2） */
export declare const TRUST_SUFFIXES: string[];
/** 归一化：全角 → 小写 → 同形字。返回 (归一结果, 是否发生了同形字替换) */
export declare function normalizeName(name: string): {
    text: string;
    homoglyph: boolean;
};
/** Damerau-Levenshtein（Optimal String Alignment）：相邻换位计 1 次操作 */
export declare function editDistance(a: string, b: string): number;
export interface ExtractedPackage {
    ecosystem: Ecosystem;
    name: string;
    /** npm 作用域名（@scope/pkg）的作用域部分 */
    scope?: string;
}
/** 判断命令文本属于哪个生态（未命中安装动词则返回 null） */
export declare function detectEcosystem(text: string): Ecosystem | null;
/** 从安装命令中提取包名 token（跳过 flag、flag 值、路径、URL） */
export declare function extractPackages(text: string): ExtractedPackage[];
export interface SquatOptions {
    /** 追加到各生态基线（内部包等自有依赖可借此豁免误报） */
    extraBaseline?: Partial<Record<Ecosystem, string[]>>;
    /** 追加已知抢注名 */
    knownSquats?: string[];
}
/**
 * 对单个包名做抢注检测（独立导出，便于宿主在别处复用）。
 * 规则优先级：T3 语料(deny) > T2 作用域 > T2 后缀 > T1 编辑距离。
 */
export declare function checkPackage(pkg: ExtractedPackage, options?: SquatOptions): SquatHit | null;
/** 扫描整段命令文本：命中安装动词即逐包检测，返回全部命中（无命中返回 []） */
export declare function scanSupplyChain(text: string, options?: SquatOptions): SquatHit[];
