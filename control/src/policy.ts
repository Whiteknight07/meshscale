import { rulePrefix, ruleMarker } from './markers.ts';
export { rulePrefix, ruleMarker } from './markers.ts';
import { Effect, Schema } from 'effect';
import ipaddr from 'ipaddr.js';
import { ValidationError } from './errors.ts';
import { type Machine, type GatewayRule } from './model.ts';

const nonempty = Schema.Array(Schema.String).check(Schema.isMinLength(1));
export const Policy = Schema.Struct({
  groups: Schema.optional(
    Schema.Record(Schema.String.check(Schema.isPattern(/^(?!\*$)[^:@/\[\]\s]+$/)), nonempty),
  ),
  rules: Schema.Array(Schema.Struct({ from: nonempty, to: nonempty })),
});
export type Policy = typeof Policy.Type;
const mesh4 = '100.96.0.0/12';
const mesh6 = '2606:4700:cf1:1000::/64';
export const owner = (r: GatewayRule) =>
  r.name.startsWith(rulePrefix) &&
  r.description?.startsWith(ruleMarker) &&
  r.filters.length === 1 &&
  r.filters[0] === 'l4'
    ? r.description.slice(ruleMarker.length)
    : '';
const fail = (message: string): never => {
  throw new ValidationError({ message });
};

// netip.ParsePrefix + Masked semantics; reject mapped IPv6 and zones just like Go.
export const meshPrefix = (value: string): string | undefined => {
  if (value.includes('%') || !/^[0-9a-fA-F:./]+$/.test(value)) return undefined;
  const slash = value.indexOf('/');
  const address = slash < 0 ? value : value.slice(0, slash);
  if (!ipaddr.isValid(address)) return undefined;
  const ip = ipaddr.parse(address);
  if (
    ip.kind() === 'ipv6' &&
    ipaddr.IPv6.isValid(address) &&
    ipaddr.IPv6.parse(address).isIPv4MappedAddress()
  )
    return undefined;
  const bits = slash < 0 ? (ip.kind() === 'ipv4' ? 32 : 128) : Number(value.slice(slash + 1));
  if (slash >= 0 && (!/^\d+$/.test(value.slice(slash + 1)) || !ipaddr.isValidCIDR(value)))
    return undefined;
  const base = ipaddr.parse(ip.kind() === 'ipv4' ? '100.96.0.0' : '2606:4700:cf1:1000::');
  const minimum = ip.kind() === 'ipv4' ? 12 : 64;
  if (bits < minimum || !ip.match(base, minimum)) return undefined;
  const bytes = ip
    .toByteArray()
    .map(
      (b, i) => b & (bits >= (i + 1) * 8 ? 255 : bits <= i * 8 ? 0 : 255 << (8 - (bits - i * 8))),
    );
  return `${ipaddr.fromByteArray(bytes).toString()}/${bits}`;
};
const expand = (
  p: Policy,
  s: string,
  stack: ReadonlySet<string> = new Set(),
): readonly string[] => {
  if (!s || s !== s.trim()) return fail(`Invalid selector ${JSON.stringify(s)}`);
  const name = s.startsWith('group:') ? s.slice(6) : s;
  const members = p.groups?.[name];
  if (s.startsWith('group:') || members !== undefined) {
    if (!members) return fail(`Unknown group ${name}`);
    if (stack.has(name)) return fail(`Group cycle at ${name}`);
    if (stack.size >= 64) return fail('Group nesting exceeds 64 levels');
    return members.flatMap((m) => expand(p, m, new Set([...stack, name])));
  }
  if (s !== '*' && !meshPrefix(s) && (ipaddr.isValid(s) || /[:/\[\]*\p{Cc}]/u.test(s)))
    return fail(`Invalid selector ${s}: expected a Mesh IP, CIDR, owner email or device name`);
  return [s];
};
const destination = (s: string): readonly [string, string] => {
  const i = s.lastIndexOf(':');
  if (i < 1 || i === s.length - 1) return fail('Expected selector:ports');
  let selector = s.slice(0, i);
  if (selector.startsWith('[') && selector.endsWith(']')) selector = selector.slice(1, -1);
  else if (selector.includes(':') && !selector.startsWith('group:'))
    return fail('IPv6 destinations require [address]:ports');
  return [selector, s.slice(i + 1)];
};
const ports = (s: string): string => {
  if (s === '*') return '';
  const parts = s.split(',').map((value) => {
    const bounds = value.split('-');
    if (bounds.length > 2) return fail(`Invalid ports ${s}`);
    const ns = bounds.map((b) =>
      /^(?:[1-9]\d*)$/.test(b) && Number(b) <= 65535
        ? Number(b)
        : fail(`Port ${b} must be 1..65535`),
    );
    const a = ns[0] ?? fail('Missing port');
    const b = ns[1];
    if (b === undefined) return `net.dst.port == ${a}`;
    if (a > b) return fail(`Reversed port range ${value}`);
    return `(net.dst.port >= ${a} and net.dst.port <= ${b})`;
  });
  return parts.length === 1 ? (parts[0] ?? '') : `(${parts.join(' or ')})`;
};
export const parsePolicy = (json: string) =>
  Schema.decodeUnknownEffect(Schema.fromJsonString(Policy), { onExcessProperty: 'error' })(
    json,
  ).pipe(
    Effect.mapError((e) => new ValidationError({ message: String(e) })),
    Effect.flatMap((p) =>
      Effect.try({
        try: () => {
          for (const name of Object.keys(p.groups ?? {})) expand(p, `group:${name}`);
          for (const r of p.rules) {
            r.from.forEach((s) => expand(p, s));
            r.to.forEach((s) => {
              const [selector, port] = destination(s);
              expand(p, selector);
              ports(port);
            });
          }
          return p;
        },
        catch: (e) =>
          Schema.is(ValidationError)(e) ? e : new ValidationError({ message: 'Invalid policy' }),
      }),
    ),
  );
const resolve = (p: Policy, s: string, machines: readonly Machine[]) => {
  const found = new Set<string>();
  for (const selector of expand(p, s)) {
    const prefix = meshPrefix(selector);
    if (selector === '*') {
      found.add(mesh4);
      found.add(mesh6);
      continue;
    }
    if (prefix) {
      found.add(prefix);
      continue;
    }
    const matches = machines.filter((d) =>
      selector.includes('@') ? d.ownerEmail === selector : d.name === selector,
    );
    if (!matches.length) return fail(`Selector ${selector} matches no active registrations`);
    if (matches.length > 1 && !selector.includes('@'))
      return fail(`Ambiguous device name ${selector}; use IPs or an owner email`);
    for (const m of matches) {
      if (!m.ipv4 && !m.ipv6)
        return fail(`Device ${m.name} has no known Mesh IP; sync when it connects`);
      for (const ip of [m.ipv4, m.ipv6].filter(Boolean))
        found.add(meshPrefix(ip) ?? fail(`Device ${m.name} has an invalid Mesh IP`));
    }
  }
  return [...found].sort();
};
export const networkRule = (id: string, action: string, traffic: string): GatewayRule => ({
  id: '',
  name: rulePrefix + id,
  description: ruleMarker + id,
  enabled: true,
  action,
  filters: ['l4'],
  traffic,
  identity: '',
  device_posture: '',
  precedence: 0,
  read_only: false,
  rule_settings: null,
  schedule: null,
  expiration: null,
});
const ipExpression = (field: 'src' | 'dst', ips: readonly string[]) =>
  `${field === 'src' ? 'net.src.internal_src_ip' : 'net.dst.ip'} in {${ips.join(' ')}}`;
export const compilePolicy = (
  p: Policy,
  machines: readonly Machine[],
  secureEndpoints: readonly string[] = machines
    .filter((m) => m.secure && m.ipv4)
    .map((m) => m.ipv4),
) =>
  Effect.try({
    try: () => {
      const result = p.rules.map((r, i) => {
        const src = [...new Set(r.from.flatMap((s) => resolve(p, s, machines)))];
        const dst = r.to.map((t) => {
          const [selector, port] = destination(t);
          const expression = ipExpression('dst', resolve(p, selector, machines));
          const condition = ports(port);
          return condition ? `(${expression} and ${condition})` : expression;
        });
        return networkRule(
          `allow-${i + 1}`,
          'allow',
          `${ipExpression('src', src)} and (${dst.join(' or ')})`,
        );
      });
      result.push(networkRule('default-deny', 'block', ipExpression('dst', [mesh4, mesh6])));
      const secure = [
        ...new Set(
          secureEndpoints.map((ip) => meshPrefix(ip) ?? fail('Invalid secure Mesh endpoint')),
        ),
      ].sort();
      if (secure.length >= 2)
        result.unshift(
          networkRule(
            'secure-wireguard',
            'allow',
            `${ipExpression('src', secure)} and ${ipExpression('dst', secure)} and net.ip.proto == 17 and net.dst.port == 51821`,
          ),
        );
      if (result.some((r) => r.traffic !== null && r.traffic.length > 140000))
        return fail('Gateway expression exceeds 140,000 characters');
      return result;
    },
    catch: (e) =>
      Schema.is(ValidationError)(e) ? e : new ValidationError({ message: 'Cannot compile policy' }),
  });
