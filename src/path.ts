import * as path from 'node:path'

/**
 * 路径沙箱校验（调研 takeaway：realpath + commonpath 比较，比纯正则可靠）。
 * 把请求路径解析到真实绝对路径，确认落在允许的根目录内。
 */

/** 默认敏感前缀（白名单之外，访问即拦） */
export const SENSITIVE_PREFIXES = [
  '/etc', '/root', '/proc', '/sys', '/var/log', '/boot',
  '/private/etc', '/private/var',
]

/** 默认敏感后缀（凭据类） */
export const SENSITIVE_SUFFIXES = [
  '.ssh', '.aws', '.gnupg', '.kube', '.docker', '.config/gcloud',
]

export interface PathVerdict {
  safe: boolean
  reason?: string
  resolved?: string
}

/**
 * 校验目标路径是否安全。
 * @param target 请求的路径（可能含 ../ 或编码）
 * @param allowedRoots 允许的沙箱根目录（默认仅用户 home 下的工作区概念由宿主传入）
 */
export function checkPath(target: string, allowedRoots: string[] = []): PathVerdict {
  if (!target) return { safe: true }

  // 1. 解码常见编码（%2e %2f %00 等），双重解码防 %252e
  let decoded = target
  for (let i = 0; i < 2; i++) {
    try { decoded = decodeURIComponent(decoded) } catch { break }
  }
  decoded = decoded.replace(/%00/g, '')

  // 2. 空字节截断
  if (target.includes('%00') || decoded.includes('\x00')) {
    return { safe: false, reason: '空字节截断（路径校验绕过）', resolved: decoded }
  }

  // 3. 解析为真实绝对路径（消除 ../）
  const resolved = path.resolve(decoded)

  // 4. 命中敏感前缀/后缀 → 拦
  for (const p of SENSITIVE_PREFIXES) {
    if (resolved === p || resolved.startsWith(p + path.sep)) {
      return { safe: false, reason: `访问系统敏感目录 ${p}`, resolved }
    }
  }
  for (const s of SENSITIVE_SUFFIXES) {
    if (resolved.includes(`${path.sep}${s}${path.sep}`) || resolved.endsWith(`${path.sep}${s}`)) {
      return { safe: false, reason: `访问凭据目录 ${s}`, resolved }
    }
  }

  // 5. 若宿主给了白名单根目录，则必须落在其中之一
  if (allowedRoots.length) {
    const inside = allowedRoots.some((root) => {
      const absRoot = path.resolve(root)
      return resolved === absRoot || resolved.startsWith(absRoot + path.sep)
    })
    if (!inside) {
      return { safe: false, reason: '路径逃逸出沙箱白名单根目录', resolved }
    }
  }

  return { safe: true, resolved }
}
