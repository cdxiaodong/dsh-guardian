import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
/**
 * 解析护栏资产清单。资产是封闭集合，全部本地确定性推导：
 *  - 审计日志 / 完整性基线：家目录下的点文件（logFile 可被配置覆盖，跟随实际值）
 *  - 插件目录：从本模块安装位置向上找最近 package.json（node_modules/dsh-guardian
 *    或源码仓库根），目录内 src/lib/cordis.patch.yml/package.json 全部受前缀保护
 *  - extra：宿主追加（例如把自家 hook 脚本、策略文件也纳入保护）
 */
export function resolveSentinelAssets(opts = {}) {
    const assets = [];
    const logFile = opts.logFile ?? path.join(os.homedir(), '.dsh-guardian.audit.log');
    assets.push({ kind: 'audit-log', path: path.resolve(logFile), label: '护栏审计日志' });
    assets.push({ kind: 'integrity-state', path: path.resolve(path.join(os.homedir(), '.dsh-guardian.memory.json')), label: '护栏完整性基线' });
    const root = opts.packageRoot ?? findPackageRoot(path.dirname(fileURLToPath(import.meta.url)));
    if (root)
        assets.push({ kind: 'plugin-dir', path: path.resolve(root), label: '护栏插件目录' });
    for (const p of opts.extra ?? [])
        assets.push({ kind: 'extra', path: path.resolve(p), label: '宿主追加保护资产' });
    return assets;
}
/** 从起始目录向上找最近的 package.json 所在目录（找不到返回 null） */
function findPackageRoot(startDir) {
    let dir = path.resolve(startDir);
    for (let i = 0; i < 8; i++) {
        if (fs.existsSync(path.join(dir, 'package.json')))
            return dir;
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return null;
}
/**
 * 系统日志路径判定（/var/log、/private/var/log 及其子路径）。
 * 只绑定系统日志目录——'> build.log'、'rm ./app.log' 等项目级操作天然不命中。
 */
const SYSTEM_LOG_PREFIXES = ['/var/log', '/private/var/log'];
export const FORENSIC_RULES = [
    { id: 'FORENSIC-004', attck: 'T1562.002', pattern: /\bauditctl\b[^;|&\n]{0,30}(?:^|\s)-e\s*0\b/, reason: '关闭内核审计子系统（auditctl -e 0）' },
    { id: 'FORENSIC-005', attck: 'T1070.003', pattern: /\bhistory\s+-c\b|\b(?:unset|export)\s+HISTFILE\b|HISTFILE\s*=\s*["']?\/dev\/null|\bHISTSIZE\s*=\s*0\b|\bshred\b[^;|&\n]{0,60}history/, reason: '清除 shell 历史（反取证）' },
];
/** 判定归一化后的路径 token 是否系统日志 */
function isSystemLog(p) {
    return SYSTEM_LOG_PREFIXES.some((prefix) => p === prefix || p.startsWith(prefix + '/'));
}
// ── 动词分类 ─────────────────────────────────────────────────────────
/** 删除/移动类动词（资产离位 = 留痕或本体消失） */
const DESTROY_VERBS = new Set(['rm', 'unlink', 'shred', 'srm', 'mv', 'wipe']);
/** 截断/覆写类动词（资产还在但内容被清空/替换/伪造） */
const TRUNCATE_VERBS = new Set(['truncate', 'dd', 'cp']);
/** 权限降级类动词（chmod 000/chattr +i 使护栏写入静默失败——活着但失明） */
const FREEZE_VERBS = new Set(['chmod', 'chown', 'chattr', 'chflags']);
/** 写入类工具名（结构化 Edit/Write 通道，#11226 的原始场景） */
const WRITE_TOOL = /write|edit|patch|create|save|store|append|move|rename|delete|remove|trash|put|tee/i;
/** 提取命令首词（跳过 sudo/env/VAR=x 前缀），用于判断动词位置——防 'grep rm lib/x' 类误报 */
function leadingCommandWord(segment) {
    const words = segment.trim().split(/\s+/);
    for (const w of words) {
        if (/^(sudo|doas|env|nohup|command|builtin|time|nice)$/i.test(w))
            continue;
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w))
            continue; // VAR=value 前缀
        return w;
    }
    return '';
}
/** 提取文本中的路径类 token（含通配符形态），归一化后与资产比对 */
function extractPathTokens(text) {
    const raw = text.split(/[\s"'`]+/).map((t) => t.replace(/^[:,;|&()<]+/, '').replace(/[,;|&()<>]+$/, ''));
    return raw.filter((t) => t.length > 1 && /[~/]|\.\w{1,4}$/.test(t));
}
/** 归一化单个 token：剥 of=/if= 类键前缀 → 双重百分号解码 → ~/$HOME 展开 → 绝对化（消除 ../） */
function normalizeToken(token, homedir) {
    let t = token.replace(/^[a-z_]{1,4}=/i, '');
    for (let i = 0; i < 2; i++) {
        try {
            t = decodeURIComponent(t);
        }
        catch {
            break;
        }
    }
    t = t.replace(/%00/g, '');
    if (t === '~')
        t = homedir;
    else if (t.startsWith('~/'))
        t = path.join(homedir, t.slice(2));
    t = t.replace(/^\$HOME(?=[/]|$)/, homedir);
    return path.resolve(t);
}
/**
 * 编译哨兵匹配器。检测「动词 × 护栏资产」矩阵 + FORENSIC 反取证规则组。
 * 资产作为显式参数注入（而非模块级状态），测试可用伪造清单构造跨平台场景。
 */
export function compileSentinelMatcher(assets, opts = {}) {
    const homedir = opts.homedir ?? os.homedir();
    const insensitive = (opts.platform ?? os.platform()) === 'darwin';
    const norm = (p) => (insensitive ? p.toLowerCase() : p);
    const resolvedAssets = assets.map((a) => ({ ...a, normPath: norm(a.path) }));
    /** token（支持尾部通配符）是否命中护栏资产 */
    const matchAsset = (token) => {
        let t = token;
        let wildcard = false;
        if (t.endsWith('*')) {
            wildcard = true;
            t = t.slice(0, -1);
        }
        const nt = norm(normalizeToken(t, homedir));
        return resolvedAssets.find((a) => wildcard ? a.normPath.startsWith(nt) : nt === a.normPath || nt.startsWith(a.normPath + path.sep));
    };
    /** 一段命令内出现过的护栏资产 */
    const assetIn = (segment) => {
        for (const token of extractPathTokens(segment)) {
            const hit = matchAsset(token);
            if (hit)
                return hit;
        }
        return undefined;
    };
    /** 系统日志 token 判定 */
    const sysLogIn = (segment) => {
        for (const token of extractPathTokens(segment)) {
            const p = normalizeToken(token, homedir);
            if (isSystemLog(p))
                return p;
        }
        return undefined;
    };
    /** 重定向目标提取：`> asset`、`>> asset`、`: > asset`、`echo x > asset`（排除 2> stderr） */
    const redirectTargets = (segment) => {
        const out = [];
        for (const m of segment.matchAll(/(?<![0-9])>>?\s*([^\s;|&]+)/g))
            out.push(m[1]);
        return out;
    };
    const push = (hits, hit, segment) => {
        hits.push({ ...hit, match: segment.trim().slice(0, 160) });
    };
    return {
        scan(toolName, text) {
            if (!text)
                return [];
            const hits = [];
            const snippet = () => text.slice(0, 160);
            // ── SELF-005：卸载护栏（文本级，无需资产）──
            if (/\b(?:npm|yarn|pnpm|bun)\s+(?:uninstall|remove|rm|un)\b[^;|&\n]{0,60}\bdsh-guardian\b/i.test(text)) {
                push(hits, { ruleId: 'SELF-005', reason: '卸载护栏插件本体（dsh-guardian）', action: 'deny' }, text);
            }
            // ── SELF-006：杀护栏进程（负向断言防 dsh-guardian-xxx 子串误报）──
            if (/\b(?:pkill|killall|pgrep|kill)\b[^;|&\n]{0,60}\bdsh-guardian\b(?!-)/i.test(text)) {
                push(hits, { ruleId: 'SELF-006', reason: '终止/探测护栏进程（pkill/killall dsh-guardian）', action: 'deny' }, text);
            }
            // ── FORENSIC 文本级规则（auditctl -e 0 / history 清除）──
            for (const rule of FORENSIC_RULES) {
                rule.pattern.lastIndex = 0;
                if (rule.pattern.test(text)) {
                    push(hits, { ruleId: rule.id, reason: `${rule.reason} [${rule.attck}]`, action: 'block' }, text);
                }
            }
            // ── 逐命令段做「动词 × 资产」匹配 ──
            const segments = text.split(/[;\n]+|&&|\|\|/);
            for (const segment of segments) {
                const cmd = leadingCommandWord(segment).split('/').pop() ?? '';
                const asset = assetIn(segment);
                const sysLog = sysLogIn(segment);
                if (asset) {
                    const where = `${asset.label}（${asset.kind}）`;
                    if (DESTROY_VERBS.has(cmd)) {
                        push(hits, { ruleId: 'SELF-001', reason: `删除/移动护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment);
                    }
                    else if (TRUNCATE_VERBS.has(cmd) || (cmd === 'dd' && /\bof=/.test(segment))) {
                        push(hits, { ruleId: 'SELF-002', reason: `截断/覆写护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment);
                    }
                    else if (redirectTargets(segment).some((t) => matchAsset(t))) {
                        push(hits, { ruleId: 'SELF-002', reason: `重定向截断/伪造护栏资产：${where}`, action: 'deny', assetKind: asset.kind }, segment);
                    }
                    else if (FREEZE_VERBS.has(cmd)) {
                        push(hits, { ruleId: 'SELF-004', reason: `篡改护栏资产权限（冻结/降级写入）：${where}`, action: 'deny', assetKind: asset.kind }, segment);
                    }
                    else if (cmd === 'ln' && /\/dev\/null/.test(segment)) {
                        push(hits, { ruleId: 'SELF-003', reason: `黑洞化护栏资产（ln -s /dev/null）：${where}`, action: 'deny', assetKind: asset.kind }, segment);
                    }
                }
                if (sysLog) {
                    const where = `系统日志 ${sysLog}`;
                    if (DESTROY_VERBS.has(cmd)) {
                        push(hits, { ruleId: 'FORENSIC-001', reason: `销毁${where} [T1070.001/T1685.006]`, action: 'block' }, segment);
                    }
                    else if (TRUNCATE_VERBS.has(cmd) || redirectTargets(segment).some((t) => isSystemLog(normalizeToken(t, homedir)))) {
                        push(hits, { ruleId: 'FORENSIC-002', reason: `截断${where} [T1070/T1685.006]`, action: 'block' }, segment);
                    }
                    else if (cmd === 'ln' && /\/dev\/null/.test(segment)) {
                        push(hits, { ruleId: 'FORENSIC-003', reason: `黑洞化${where}（ln -s /dev/null）[T1070]`, action: 'block' }, segment);
                    }
                }
            }
            // ── SELF-007：结构化写工具直指护栏资产（#11226 原始场景：Edit/Write 改 hook 源码）──
            if (WRITE_TOOL.test(toolName || '')) {
                const asset = assetIn(text);
                if (asset) {
                    push(hits, { ruleId: 'SELF-007', reason: `写入类工具篡改护栏资产：${asset.label}（${asset.kind}）`, action: 'deny', assetKind: asset.kind }, snippet());
                }
            }
            return hits;
        },
    };
}
/** 一次性扫描便捷入口（内部编译匹配器；高频场景请复用 compileSentinelMatcher） */
export function scanSentinel(toolName, text, assets, opts = {}) {
    return compileSentinelMatcher(assets, opts).scan(toolName, text);
}
