/** Secret/sensitive data leak detection (regexes borrowed from gitleaks.toml + trufflehog detector prefixes) */
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
    /** Shannon entropy (reduces false positives) */
    entropy: number;
}
/** Computes the Shannon entropy of a string (trufflehog/gitleaks use it to filter low-entropy false positives, e.g. 'aaaaaaaa') */
export declare function shannonEntropy(s: string): number;
/** Scans text for secrets and returns the hits (with entropy; low-entropy hits are less reliable) */
export declare function scanSecrets(text: string, minEntropy?: number): SecretHit[];
