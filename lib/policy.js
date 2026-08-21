import { parse } from 'yaml';
/** glob → RegExp：* 匹配任意字符段，其余字面量化 */
export function globToRegExp(pattern) {
    const escaped = pattern.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`);
}
/** 校验并编译策略列表。返回 { policies, errors }——有错时 policies 为空（原子性：要么全过要么不生效） */
export function compilePolicies(raw) {
    const errors = [];
    const policies = [];
    const seen = new Set();
    const list = Array.isArray(raw?.policies) ? raw.policies : [];
    if (!Array.isArray(raw?.policies))
        errors.push('策略文件缺少 policies 数组');
    list.forEach((p, i) => {
        const where = `policies[${i}]`;
        if (!p || typeof p !== 'object') {
            errors.push(`${where}：必须是对象`);
            return;
        }
        if (!p.id || typeof p.id !== 'string') {
            errors.push(`${where}：缺少 id`);
            return;
        }
        if (seen.has(p.id)) {
            errors.push(`${where}：id "${p.id}" 重复`);
            return;
        }
        seen.add(p.id);
        if (!['allow', 'deny', 'block', 'log'].includes(p.action)) {
            errors.push(`${where}(${p.id})：action 必须是 allow/deny/block/log`);
            return;
        }
        if (p.match !== undefined) {
            try {
                new RegExp(p.match, p.matchFlags ?? 'i');
            }
            catch (e) {
                errors.push(`${where}(${p.id})：match 不是合法正则（${e.message}）`);
                return;
            }
        }
        const tools = p.tool === undefined ? [] : Array.isArray(p.tool) ? p.tool : [p.tool];
        for (const t of tools) {
            if (typeof t !== 'string' || !t.length) {
                errors.push(`${where}(${p.id})：tool 必须是非空字符串或数组`);
                return;
            }
            try {
                globToRegExp(t);
            }
            catch {
                errors.push(`${where}(${p.id})：tool 通配符 "${t}" 非法`);
                return;
            }
        }
        policies.push({ ...p, priority: p.priority ?? 100 });
    });
    if (errors.length)
        return { policies: [], errors };
    policies.sort((a, b) => a.priority - b.priority);
    return { policies, errors: [] };
}
/** 解析 YAML 文本 → 校验编译。失败返回空 + errors（不抛异常，供热加载安全回退） */
export function parsePolicyYaml(text) {
    let raw;
    try {
        raw = parse(text);
    }
    catch (e) {
        return { policies: [], errors: [`YAML 语法错误：${e.message.split('\n')[0]}`] };
    }
    if (raw === null || raw === undefined)
        return { policies: [], errors: ['策略文件为空'] };
    return compilePolicies(raw);
}
/** 单条已编译策略是否命中 (toolName, payloadText) */
export function policyMatches(p, toolName, text) {
    const tools = p.tool === undefined ? [] : Array.isArray(p.tool) ? p.tool : [p.tool];
    if (tools.length) {
        const hit = tools.some((t) => globToRegExp(t).test(toolName));
        if (!hit)
            return false;
    }
    if (p.match === undefined)
        return true;
    return new RegExp(p.match, p.matchFlags ?? 'i').test(text);
}
/** 按优先级评估，返回首条命中策略；无命中返回 null */
export function evaluatePolicies(policies, toolName, text) {
    for (const p of policies) {
        if (policyMatches(p, toolName, text))
            return p;
    }
    return null;
}
