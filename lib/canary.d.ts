/**
 * 蜜罐信标引擎（engine-20：Canary Trap）
 *
 * 其他引擎盯「通道」（渲染外泄盯 markdown、DNS 引擎盯域名查询、SSRF 盯目标地址），
 * 这个引擎盯「货物」——在喂给 Agent 的外部内容里植入每会话唯一的高熵 canary，
 * 只要它以任何形态出现在出境通道（工具调用 / URL / 文件写出），就是注入正在
 * 搬运数据的**确定性证据**：随机 128-bit 不可能自然碰撞，唯一的出现路径就是
 * 「从上下文搬运到出境」，零误报。
 *
 * 借鉴：thinkst Canary Tokens 的欺骗防御思想、2026 年 prompt-injection canary
 * 实践（arXiv 2606.04141 / Klu.ai glossary / toxsec）的「植入→出境监测」闭环。
 *
 * 两个使用姿势：
 *  - 中性标记（默认）：`[internal-tracking-ref: GUARDIAN-CANARY-…]`，被动监测上下文复述
 *  - 蜜饵形态（decoy）：伪装成 API key 裸 token，主动诱惑注入「优先偷它」
 */
export declare const CANARY_PREFIX = "GUARDIAN-CANARY-";
export declare const DECOY_PREFIX = "sk-guardian-decoy-";
/** 128-bit 随机体：碰撞概率 ~2^-128，自然出现即搬运铁证 */
export declare const CANARY_ENTROPY_BYTES = 16;
export interface CanaryRecord {
    token: string;
    label: string;
    plantedAt: string;
    decoy: boolean;
}
export type CanaryVariant = 'raw' | 'base64' | 'hex' | 'case-flip';
export interface CanaryHit {
    /** 命中的 canary 全文——只存在于内存，绝不写入审计日志 */
    token: string;
    variant: CanaryVariant;
    index: number;
}
/** 生成中性形态 canary：GUARDIAN-CANARY-<32 hex> */
export declare function generateCanary(): string;
/** 生成蜜饵形态 canary：伪装成 API key，诱惑注入指令优先搬运它 */
export declare function generateDecoyCanary(): string;
/**
 * 日志/展示用的指纹：前 4 后 4，中间省略。
 * 全文绝不落盘——审计日志本身不能成为 canary 的泄露面。
 */
export declare function canaryFingerprint(token: string): string;
/**
 * 出境扫描：检测 text 中是否出现任一已注册 canary（含编码变体）。
 * 攻击者让模型搬运时常玩编码绕过，这里把全串变体一起盯：
 *  - raw：原文
 *  - base64：全串 base64（含去 padding 与 MIME 折行，靠 stripLineBreaks 兜住）
 *  - hex：全串 hex
 *  - case-flip：大小写翻转（对含 GUARDIAN 前缀的有效）
 */
export declare function scanForCanary(text: string, tokens: Iterable<string>): CanaryHit | null;
/**
 * 把 text 中命中的 canary 及其变体替换为指纹后再落审计。
 * 审计里留下的证据是「指纹 + 变体类型」，可溯源但不可复用。
 */
export declare function redactCanary(text: string, hit: CanaryHit): string;
