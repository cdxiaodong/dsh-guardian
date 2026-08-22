/**
 * 混淆消解引擎（decode-before-scan）。
 *
 * 背景：正则规则引擎只看原文，攻击者可以把 payload 编码/隐藏后绕过：
 *  - Unicode Tags block（U+E0000 区）：隐形编码 ASCII 指令，肉眼与正则均不可见
 *    （CSA Research Note 2026「Hidden Unicode Instruction Injection in AI Agent Skills」）
 *  - 零宽字符 / Hangul filler：拆散关键词（arXiv:2508.14070 实测零宽注入 ASR 54.2%）
 *  - 双向覆盖控制符：Trojan Source（CVE-2021-42574）的 LLM 变体
 *  - Base64 / HTML 实体 / 百分号编码 / 全角同形字 / leetspeak
 *    （F5 DevCentral、SecureLayer7 对 prompt obfuscation 攻击面的分类）
 *
 * 防御思路（业界共识 decode-before-scan）：先把文本归一化折叠成 canonical，
 * 再连同 base64 解码、leetspeak 还原等附加变体一起交给既有检测引擎
 * （rule / secret / ssrf）复扫，使所有引擎的检出率同时提升——
 * 不需要为每种混淆手法单独写一套规则（类比 WAF 的请求归一化层）。
 */
/** 归一化管线中实际发生作用的变换种类 */
export type TransformKind = 'zero-width' | 'tags-block' | 'bidi' | 'nfkc' | 'html-entity' | 'percent' | 'base64' | 'leet';
export interface NormalizedText {
    /** 折叠后的规范文本（原文无混淆时 === 原文，零成本短路） */
    canonical: string;
    /** canonical 相对原文应用过的变换链（仅记录实际产生变化的步骤） */
    transforms: TransformKind[];
}
/** 一个待扫描文本变体：text + 它由哪些变换得到 */
export interface TextVariant {
    text: string;
    via: TransformKind[];
}
/** base64 候选段：按长度降序取前 maxSegments 个可解码段（解码结果须为可打印文本） */
export declare function findBase64Segments(text: string, maxSegments?: number): {
    segment: string;
    decoded: string;
}[];
/**
 * 归一化：隐形字符剥离 → Tags block 解码 → bidi 剥离 → NFKC →
 * 实体/百分号交替迭代到固定点（≤3 轮，防 &amp;#x72; 双层编码）。
 */
export declare function normalizeText(input: string): NormalizedText;
/**
 * 展开扫描变体集：[原文, canonical, base64 段解码变体(≤2), leet 变体]，上限 5。
 * 原文始终排第一（保证原文命中的行为与未启用本引擎时完全一致）；
 * 纯净文本 canonical === 原文时只剩一个变体，零额外开销。
 */
export declare function expandTexts(input: string): TextVariant[];
/** 变换种类的中文名（审计展示用） */
export declare const TRANSFORM_LABELS: Record<TransformKind, string>;
