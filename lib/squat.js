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
// ── 基线：各生态高价值仿冒目标（抢注收益越大越值得攻击） ─────────────────
export const BASELINE_PACKAGES = {
    npm: [
        'lodash', 'underscore', 'request', 'express', 'axios', 'chalk', 'commander',
        'cross-env', 'dotenv', 'eslint', 'jest', 'webpack', 'typescript', 'react',
        'vue', 'next', 'node-fetch', 'fs-extra', 'moment', 'uuid', 'qs', 'debug',
        'ms', 'yargs', 'inquirer', 'glob', 'rimraf', 'shelljs', 'open',
    ],
    pypi: [
        'requests', 'django', 'flask', 'numpy', 'pandas', 'pillow', 'scipy',
        'matplotlib', 'selenium', 'beautifulsoup4', 'urllib3', 'certifi',
        'setuptools', 'pip', 'pyyaml', 'python-dateutil', 'sqlalchemy', 'openai',
    ],
    cargo: ['serde', 'tokio', 'clap', 'rand', 'anyhow', 'regex', 'reqwest'],
    gem: ['rails', 'rake', 'bundler', 'rspec', 'json'],
};
// ── T3 语料：有公开事件背书的真实抢注名 ─────────────────────────────────
// crossenv      — npm 2017 仿冒 cross-env（BleepingComputer 等广泛记录）
// colourama     — PyPI 2023-11 仿冒 colorama 的信息窃取包
// python3-dateutil / python3-pillow — PyPI 2025-08 仿冒官方包的信息窃取批次
// reqeusts      — 研究文献中最常见的 requests 手滑变体，常年被抢注扫描盯防
export const KNOWN_SQUATS = [
    'crossenv', 'colourama', 'python3-dateutil', 'python3-pillow', 'reqeusts',
];
/** 通用"信任后缀"：幻觉包名的典型构词成分（T2） */
export const TRUST_SUFFIXES = [
    'utils', 'util', 'helper', 'helpers', 'sdk', 'types', 'cli', 'official',
    'core', 'secure', 'safe', 'extended', 'plus', 'pro', 'js', 'ts', 'wrapper',
    'client', 'api', 'ext', 'plugin', 'patch', 'fix', 'next', 'dev',
];
/**
 * 合法近邻包豁免：本身是真实流行的包名，恰好落在某基线的编辑距离阈值内。
 * （nest↔jest/next、realm↔react、rest↔jest）对它们 block 会伤正常安装流量，
 * 豁免只按"裸名全等"，不豁免任何变体。
 */
const REAL_LOOKALIKES = new Set(['nest', 'realm', 'rest']);
/** 真实存在的作用域组织（白名单，避免 @babel/core 这类误报） */
const REAL_SCOPES = new Set([
    'types', 'babel', 'angular', 'vue', 'nestjs', 'testing-library', 'storybook',
    'eslint', 'typescript-eslint', 'rollup', 'vitejs', 'sveltejs', 'emotion',
    'mui', 'jest', 'swc', 'parcel', 'webpack', 'oclif', 'lerna', 'nrwl', 'sentry',
]);
// ── 同形字归一（UTS#39-lite：西里尔/希腊易混 + 全角 → ASCII） ─────────────
const HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'і': 'i', 'ѕ': 's', 'ј': 'j', 'ԛ': 'q', 'ԝ': 'w', 'һ': 'h', 'Ь': 'b',
    'α': 'a', 'ο': 'o', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'ν': 'v', 'ς': 's', 'ϲ': 'c',
};
// ── leet 归一（形近数字/符号 → 字母） ─────────────────────────────────────
const LEET = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
    '@': 'a', '$': 's', '!': 'i', '|': 'l',
};
/** 全角字符（U+FF01-FF5E）→ ASCII（偏移 0xFEE0） */
function normalizeFullwidth(s) {
    let out = '';
    for (const ch of s) {
        const code = ch.codePointAt(0);
        out += code >= 0xff01 && code <= 0xff5e ? String.fromCodePoint(code - 0xfee0) : ch;
    }
    return out;
}
function mapChars(s, table) {
    let out = '';
    for (const ch of s)
        out += table[ch] ?? ch;
    return out;
}
/** 归一化：全角 → 小写 → 同形字。返回 (归一结果, 是否发生了同形字替换) */
export function normalizeName(name) {
    // 先 lower 再 map：西里尔大写 О(041E) 不在映射表里，必须先归小写才查得到
    let text = normalizeFullwidth(name).toLowerCase();
    let homoglyph = false;
    for (let i = 0; i < text.length; i++) {
        if (HOMOGLYPHS[text[i]]) {
            homoglyph = true;
            break;
        }
    }
    return { text: mapChars(text, HOMOGLYPHS), homoglyph };
}
/** Damerau-Levenshtein（Optimal String Alignment）：相邻换位计 1 次操作 */
export function editDistance(a, b) {
    const m = a.length, n = b.length;
    if (!m)
        return n;
    if (!n)
        return m;
    // d[i][j] = a 前 i 个字符 → b 前 j 个字符的最小操作数
    const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++)
        d[i][0] = i;
    for (let j = 0; j <= n; j++)
        d[0][j] = j;
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            d[i][j] = Math.min(d[i - 1][j] + 1, // 删除
            d[i][j - 1] + 1, // 插入
            d[i - 1][j - 1] + cost);
            // 相邻换位
            if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
            }
        }
    }
    return d[m][n];
}
/** 编辑距离阈值：短包名容 1，长包名容 2（≥5 字符） */
function distanceThreshold(len) {
    return len >= 5 ? 2 : 1;
}
// ── 安装命令解析 ──────────────────────────────────────────────────────────
/** 带值的安装器 flag（其后的 token 是参数不是包名） */
const FLAGS_WITH_VALUE = new Set([
    '-r', '--requirement', '-i', '--index-url', '--extra-index-url', '-e',
    '--editable', '-t', '--target', '--prefix', '--src', '--features', '-v',
    '--version', '-s', '--source', '--platform', '--install-dir',
    '--python', '--host', '--port', '--trust', '--index',
]);
/** 判断命令文本属于哪个生态（未命中安装动词则返回 null） */
export function detectEcosystem(text) {
    const t = text.toLowerCase();
    if (/(^|\s|;|&&|\|)(npm|pnpm|yarn|bun)\s+(i|install|add)\b/.test(t))
        return 'npm';
    if (/(^|\s|;|&&|\|)((python3?\s+-m\s+)?(pip3?|uv)\s+(pip\s+)?install|(poetry|uv)\s+add)\b/.test(t))
        return 'pypi';
    if (/(^|\s|;|&&|\|)cargo\s+add\b/.test(t))
        return 'cargo';
    if (/(^|\s|;|&&|\|)gem\s+install\b/.test(t))
        return 'gem';
    return null;
}
const SCOPED = /^@([^/@\s]+)\/([^/@\s]+)$/;
/** 安装器自身的命令词，绝不当作包名（python -m pip install / yarn add 等多词形式） */
const INSTALLER_WORDS = new Set([
    'npm', 'pnpm', 'yarn', 'bun', 'pip', 'pip3', 'uv', 'poetry', 'cargo', 'gem',
    'python', 'python3', 'install', 'i', 'add',
]);
/** 从安装命令中提取包名 token（跳过 flag、flag 值、路径、URL） */
export function extractPackages(text) {
    const ecosystem = detectEcosystem(text);
    if (!ecosystem)
        return [];
    const tokens = text.trim().split(/\s+/);
    const out = [];
    let skipNext = false;
    for (const raw of tokens.slice(1)) { // 跳过第一个词（安装器名本身）
        if (skipNext) {
            skipNext = false;
            continue;
        }
        let tok = raw.replace(/[,;]+$/, '');
        if (INSTALLER_WORDS.has(tok))
            continue;
        // --flag=value 整体跳过；其他 flag 无值则只跳自身
        if (tok.startsWith('--') && tok.includes('='))
            continue;
        if (tok.startsWith('-')) {
            if (FLAGS_WITH_VALUE.has(tok))
                skipNext = true;
            continue;
        }
        // URL / VCS / 本地路径 / 环境变量不是包名
        if (tok.includes('://') || /^(git|http|ftp)[+@]/.test(tok) || /^[./~]/.test(tok) || tok === '.')
            continue;
        // 去掉版本钉：@scope/pkg@1.2.3 → @scope/pkg；pkg@^1 → pkg（保留开头的作用域 @）
        const at = tok.lastIndexOf('@');
        if (at > 0)
            tok = tok.slice(0, at);
        // pip extras：requests[security] → requests
        tok = tok.replace(/\[[^\]]*\]$/, '');
        // 允许非 ASCII 字母通过：含同形字的混淆包名必须送进检测器，而不是被解析器提前滤掉
        // （decode-before-scan 原则，同 Engine-9）
        if (!tok || !/^[@a-z0-9_À-￿][a-z0-9_À-￿@/.-]*$/i.test(tok))
            continue;
        const scoped = tok.match(SCOPED);
        if (scoped)
            out.push({ ecosystem, name: scoped[2].toLowerCase(), scope: scoped[1].toLowerCase() });
        else
            out.push({ ecosystem, name: tok.toLowerCase() });
    }
    return out;
}
/**
 * 对单个包名做抢注检测（独立导出，便于宿主在别处复用）。
 * 规则优先级：T3 语料(deny) > T2 作用域 > T2 后缀 > T1 编辑距离。
 */
export function checkPackage(pkg, options = {}) {
    const baseline = new Set([
        ...BASELINE_PACKAGES[pkg.ecosystem],
        ...(options.extraBaseline?.[pkg.ecosystem] ?? []),
    ].map((s) => s.toLowerCase()));
    const corpus = new Set([...KNOWN_SQUATS, ...(options.knownSquats ?? [])].map((s) => s.toLowerCase()));
    const fullName = pkg.scope ? `@${pkg.scope}/${pkg.name}` : pkg.name;
    // T3 已知抢注语料 —— 有事件背书，直接 deny
    if (corpus.has(fullName) || corpus.has(pkg.name)) {
        return {
            ruleId: 'SQUAT-CORPUS', ecosystem: pkg.ecosystem, package: fullName,
            reason: `${fullName} 是有公开事件背书的已知抢注包名`,
            action: 'deny',
        };
    }
    // 基线内的真名放行（含 extraBaseline 自有依赖）；合法近邻包同拦同放
    if (baseline.has(fullName) || baseline.has(pkg.name))
        return null;
    if (REAL_LOOKALIKES.has(pkg.name) && !pkg.scope)
        return null;
    // T2 作用域仿冒：@lodash/utils —— 主流包通常无作用域，作用域是仿冒者的信任外衣
    if (pkg.scope && baseline.has(pkg.scope) && !REAL_SCOPES.has(pkg.scope)) {
        return {
            ruleId: 'SQUAT-SCOPE', ecosystem: pkg.ecosystem, package: fullName,
            target: pkg.scope,
            reason: `作用域 @${pkg.scope}/ 仿冒主流包名 ${pkg.scope}（主流包并非作用域发布）`,
            action: 'block',
        };
    }
    // T2 信任后缀：numpy-utils / requests-sdk —— 幻觉包名的典型构词法
    for (const base of baseline) {
        if (base.length < 4)
            continue;
        for (const sep of ['-', '_', '.']) {
            for (const suffix of TRUST_SUFFIXES) {
                if (pkg.name === `${base}${sep}${suffix}`) {
                    return {
                        ruleId: 'SQUAT-SUFFIX', ecosystem: pkg.ecosystem, package: fullName,
                        target: base,
                        reason: `${pkg.name} = 主流包 ${base} + 信任后缀 ${suffix}，典型抢注/幻觉构词`,
                        action: 'block',
                    };
                }
            }
        }
    }
    // T1 编辑距离（含同形字/leet 变体归一复扫）
    const { text: normalized, homoglyph } = normalizeName(pkg.name);
    let best = null;
    let bestDist = Infinity;
    for (const base of baseline) {
        const dist = editDistance(normalized, base);
        if (dist <= distanceThreshold(base.length) && dist < bestDist) {
            bestDist = dist;
            best = {
                ruleId: 'SQUAT-TYPO', ecosystem: pkg.ecosystem, package: fullName,
                target: base, distance: dist,
                variant: homoglyph ? 'homoglyph' : 'none',
                reason: `${pkg.name} 与主流包 ${base} 编辑距离 ${dist}${homoglyph ? '（含同形字变体）' : ''}，疑似 typosquat`,
                action: 'block',
            };
        }
    }
    if (best)
        return best;
    // leet 复扫：归一后命中才报（原文直扫不命中，说明确实做了形近替换）
    const leeted = mapChars(normalized, LEET);
    if (leeted !== normalized) {
        for (const base of baseline) {
            const dist = editDistance(leeted, base);
            if (dist <= distanceThreshold(base.length)) {
                return {
                    ruleId: 'SQUAT-TYPO', ecosystem: pkg.ecosystem, package: fullName,
                    target: base, distance: dist,
                    variant: 'leet',
                    reason: `${pkg.name} 经形近符号归一后为 ${leeted}，与主流包 ${base} 编辑距离 ${dist}，疑似 leetsquat`,
                    action: 'block',
                };
            }
        }
    }
    return null;
}
/** 扫描整段命令文本：命中安装动词即逐包检测，返回全部命中（无命中返回 []） */
export function scanSupplyChain(text, options = {}) {
    const pkgs = extractPackages(text);
    const hits = [];
    for (const pkg of pkgs) {
        const hit = checkPackage(pkg, options);
        if (hit)
            hits.push(hit);
    }
    return hits;
}
