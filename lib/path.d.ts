/**
 * Path sandbox validation (research takeaway: realpath + commonpath comparison, more reliable than pure regex).
 * Resolves the requested path to a real absolute path and confirms it falls within an allowed root directory.
 */
/** Default sensitive prefixes (anything outside the allowlist is blocked on access) */
export declare const SENSITIVE_PREFIXES: string[];
/** Default sensitive suffixes (credential-related) */
export declare const SENSITIVE_SUFFIXES: string[];
export interface PathVerdict {
    safe: boolean;
    reason?: string;
    resolved?: string;
}
/**
 * Validates whether the target path is safe.
 * @param target Requested path (may contain ../ or encoding)
 * @param allowedRoots Allowed sandbox root directories (the host supplies the workspace concept under the user's home)
 */
export declare function checkPath(target: string, allowedRoots?: string[]): PathVerdict;
