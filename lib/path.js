import * as path from 'node:path';
/**
 * Path sandbox validation (research takeaway: realpath + commonpath comparison, more reliable than pure regex).
 * Resolves the requested path to a real absolute path and confirms it falls within an allowed root directory.
 */
/** Default sensitive prefixes (anything outside the allowlist is blocked on access) */
export const SENSITIVE_PREFIXES = [
    '/etc', '/root', '/proc', '/sys', '/var/log', '/boot',
    '/private/etc', '/private/var',
];
/** Default sensitive suffixes (credential-related) */
export const SENSITIVE_SUFFIXES = [
    '.ssh', '.aws', '.gnupg', '.kube', '.docker', '.config/gcloud',
];
/**
 * Validates whether the target path is safe.
 * @param target Requested path (may contain ../ or encoding)
 * @param allowedRoots Allowed sandbox root directories (the host supplies the workspace concept under the user's home)
 */
export function checkPath(target, allowedRoots = []) {
    if (!target)
        return { safe: true };
    // 1. Decode common encodings (%2e %2f %00, etc.), double-decode to defeat %252e
    let decoded = target;
    for (let i = 0; i < 2; i++) {
        try {
            decoded = decodeURIComponent(decoded);
        }
        catch {
            break;
        }
    }
    decoded = decoded.replace(/%00/g, '');
    // 2. Null byte truncation
    if (target.includes('%00') || decoded.includes('\x00')) {
        return { safe: false, reason: 'Null byte truncation (path validation bypass)', resolved: decoded };
    }
    // 3. Resolve to a real absolute path (eliminates ../)
    const resolved = path.resolve(decoded);
    // 4. Match sensitive prefix/suffix → block
    for (const p of SENSITIVE_PREFIXES) {
        if (resolved === p || resolved.startsWith(p + path.sep)) {
            return { safe: false, reason: `Access to sensitive system directory ${p}`, resolved };
        }
    }
    for (const s of SENSITIVE_SUFFIXES) {
        if (resolved.includes(`${path.sep}${s}${path.sep}`) || resolved.endsWith(`${path.sep}${s}`)) {
            return { safe: false, reason: `Access to credential directory ${s}`, resolved };
        }
    }
    // 5. If the host provided allowlisted root directories, the path must fall within one of them
    if (allowedRoots.length) {
        const inside = allowedRoots.some((root) => {
            const absRoot = path.resolve(root);
            return resolved === absRoot || resolved.startsWith(absRoot + path.sep);
        });
        if (!inside) {
            return { safe: false, reason: 'Path escapes the sandbox allowlisted root directory', resolved };
        }
    }
    return { safe: true, resolved };
}
