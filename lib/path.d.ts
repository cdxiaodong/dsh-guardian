/**
 * 路径沙箱校验（调研 takeaway：realpath + commonpath 比较，比纯正则可靠）。
 * 把请求路径解析到真实绝对路径，确认落在允许的根目录内。
 */
/** 默认敏感前缀（白名单之外，访问即拦） */
export declare const SENSITIVE_PREFIXES: string[];
/** 默认敏感后缀（凭据类） */
export declare const SENSITIVE_SUFFIXES: string[];
export interface PathVerdict {
    safe: boolean;
    reason?: string;
    resolved?: string;
}
/**
 * 校验目标路径是否安全。
 * @param target 请求的路径（可能含 ../ 或编码）
 * @param allowedRoots 允许的沙箱根目录（默认仅用户 home 下的工作区概念由宿主传入）
 */
export declare function checkPath(target: string, allowedRoots?: string[]): PathVerdict;
