import { Effect, Schema } from 'effect';
import { ValidationError } from './errors.ts';
import { type Change, type GatewayRule } from './model.ts';
import { owner } from './policy.ts';

// Canonicalize the AND/OR grammar emitted by Go. Gateway drops redundant
// parentheses and host CIDR suffixes; preserving those must not cause writes.
export const canonicalExpression = (input: string): string => {
  const tokens = input
    .replace(/[(){}]/g, ' $& ')
    .trim()
    .split(/\s+/)
    .map((t) => t.replace(/\/(?:32|128)$/, ''));
  let pos = 0;
  type Node = { op: string; children: Node[] };
  const parse = (op: string, next: () => Node | undefined): Node | undefined => {
    const children: Node[] = [];
    const first = next();
    if (!first) return undefined;
    children.push(first);
    while (tokens[pos] === op) {
      pos++;
      const n = next();
      if (!n) return undefined;
      children.push(n);
    }
    return children.length === 1 ? first : { op, children };
  };
  const atom = (): Node | undefined => {
    if (tokens[pos] === '(') {
      pos++;
      const n = or();
      if (tokens[pos++] !== ')') return undefined;
      return n;
    }
    const words: string[] = [];
    let braces = 0;
    while (pos < tokens.length) {
      const t = tokens[pos];
      if (t === undefined || (!braces && ['and', 'or', ')'].includes(t))) break;
      if (t === '{') braces++;
      if (t === '}') braces--;
      words.push(t);
      pos++;
    }
    return words.length && braces === 0 ? { op: words.join(' '), children: [] } : undefined;
  };
  const and = (): Node | undefined => parse('and', atom);
  const or = (): Node | undefined => parse('or', and);
  const key = (n: Node): string => {
    if (!n.children.length) return n.op;
    const flatten = (c: Node): Node[] =>
      c.op === n.op && c.children.length ? c.children.flatMap(flatten) : [c];
    return `(${n.op} ${n.children.flatMap(flatten).map(key).join(' ')})`;
  };
  const root = or();
  return root && pos === tokens.length ? key(root) : `invalid:${input}`;
};
const comparable = (r: GatewayRule) =>
  JSON.stringify({
    ...r,
    id: '',
    read_only: false,
    traffic: canonicalExpression(r.traffic ?? ''),
    identity: r.identity ?? '',
    device_posture: r.device_posture ?? '',
    rule_settings:
      r.rule_settings?.override_ips?.length || r.rule_settings?.override_host
        ? r.rule_settings
        : null,
    schedule: r.schedule ?? null,
    expiration: r.expiration ?? null,
  });
export const networkDiff = (desired: readonly GatewayRule[], existing: readonly GatewayRule[]) =>
  Effect.try({
    try: () => {
      const bad = (message: string): never => {
        throw new ValidationError({ message });
      };
      const byOwner = new Map<string, GatewayRule[]>();
      const occupied = new Set<number>();
      let limit = Number.MAX_SAFE_INTEGER;
      let others = 0;
      for (const r of existing) {
        const id = owner(r);
        if (id) {
          if (!r.id || r.read_only)
            return bad(`Owned network rule ${r.name} is read-only or has no ID`);
          byOwner.set(id, [...(byOwner.get(id) ?? []), r]);
        } else if (r.filters.includes('l4')) {
          others++;
          occupied.add(r.precedence);
          if (r.enabled) limit = Math.min(limit, r.precedence);
        }
      }
      if (desired.length && others + desired.length > 500)
        return bad('Network policies exceed the default 500-rule limit');
      let next = limit <= 1000 + desired.length ? 0 : 1000;
      const seen = new Set<string>();
      const changes: Change[] = [];
      const deletes: Change[] = [];
      for (const rule of desired) {
        const id = owner(rule);
        if (!id || seen.has(id)) return bad('Unowned or duplicate desired network rule');
        seen.add(id);
        while (occupied.has(next) && next < limit) next++;
        if (next >= limit)
          return bad(`Insufficient precedence space before customer policy at ${limit}`);
        const old = [...(byOwner.get(id) ?? [])].sort((a, b) => a.id.localeCompare(b.id));
        const first = old[0];
        const wanted = { ...rule, id: first?.id ?? '', precedence: next++ };
        if (!first) changes.push({ operation: 'create', rule: wanted });
        else if (comparable(first) !== comparable(wanted))
          changes.push({ operation: 'update', rule: wanted });
        deletes.push(...old.slice(1).map((r) => ({ operation: 'delete' as const, rule: r })));
      }
      for (const [id, old] of byOwner)
        if (!seen.has(id))
          deletes.push(...old.map((r) => ({ operation: 'delete' as const, rule: r })));
      deletes.sort(
        (a, b) =>
          Number(b.rule.action === 'block') - Number(a.rule.action === 'block') ||
          a.rule.id.localeCompare(b.rule.id),
      );
      const peak =
        others +
        [...byOwner.values()].flat().length +
        changes.filter((c) => c.operation === 'create').length;
      if (desired.length && peak > 500)
        return bad('Sync would temporarily exceed 500 network policies');
      return [...changes, ...deletes];
    },
    catch: (e) =>
      Schema.is(ValidationError)(e) ? e : new ValidationError({ message: 'Cannot plan rules' }),
  });
