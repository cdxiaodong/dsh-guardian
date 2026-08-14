/** 密钥/敏感信息泄露检测（正则借鉴 gitleaks.toml + trufflehog 检测器前缀） */
export interface SecretRule {
    id: string;
    pattern: RegExp;
    description: string;
    secretType: string;
}
export declare const SECRET_RULES: SecretRule[];
export interface SecretHit {
    ruleId: string;
    secretType: string;
    description: string;
    match: string;
    /** Shannon 熵（降误报用） */
    entropy: number;
}
/** 计算字符串 Shannon 熵（trufflehog/gitleaks 用它过滤低熵误报，如 'aaaaaaaa'） */
export declare function shannonEntropy(s: string): number;
/** 在文本中扫描密钥，返回命中列表（含熵值，低熵命中可信度低） */
export declare function scanSecrets(text: string, minEntropy?: number): SecretHit[];
