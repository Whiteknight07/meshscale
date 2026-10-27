import { dnsPrefix, dnsMarker } from './markers.ts';
export { dnsPrefix, dnsMarker } from './markers.ts';
import { Effect, Schema } from 'effect';
import { ValidationError } from './errors.ts';
import { type Change, type GatewayRule, type Machine } from './model.ts';

export const dnsOwner = (r: GatewayRule) =>
  r.name.startsWith(dnsPrefix) && r.description?.startsWith(dnsMarker)
    ? r.description.slice(dnsMarker.length)
    : '';
const sanitize = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 63)
    .replace(/-+$/, '') || 'device';
export const buildNames = (machines: readonly Machine[]) => {
  const sorted = [...machines].sort((a, b) =>
    `${a.kind}/${a.id}`.localeCompare(`${b.kind}/${b.id}`),
  );
  const reserved = new Set(sorted.map((m) => sanitize(m.name)));
  const used = new Set<string>();
  return sorted
    .map((m) => {
      const base = sanitize(m.name);
      let label = base;
      for (let n = 2; used.has(label); n++) {
        const tail = `-${n}`;
        label = base.slice(0, 63 - tail.length).replace(/-+$/, '') + tail;
        if (reserved.has(label)) {
          label = base;
          continue;
        }
      }
      used.add(label);
      return { id: `${m.kind}/${m.id}`, name: `${label}.mesh`, ip: m.ipv4 || m.ipv6 };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
};
export const dnsDiff = (machines: readonly Machine[], existing: readonly GatewayRule[]) =>
  Effect.try({
    try: () => {
      const wanted = new Map(buildNames(machines).map((r) => [r.id, r]));
      const seen = new Set<string>();
      const changes: Change[] = [];
      let precedence = Math.max(
        0,
        ...existing.filter((r) => r.filters.includes('dns')).map((r) => r.precedence),
      );
      const ruleFor = (
        record: { id: string; name: string; ip: string },
        old?: GatewayRule,
      ): GatewayRule => ({
        id: old?.id ?? '',
        name: dnsPrefix + record.name,
        description: dnsMarker + record.id,
        action: 'override',
        enabled: true,
        filters: ['dns'],
        traffic: `dns.fqdn == ${JSON.stringify(record.name)}`,
        identity: '',
        device_posture: '',
        precedence: old?.precedence ?? ++precedence,
        read_only: false,
        rule_settings: { override_ips: [record.ip], override_host: '' },
        schedule: null,
        expiration: null,
      });
      for (const old of [...existing].sort((a, b) => a.id.localeCompare(b.id))) {
        const id = dnsOwner(old);
        if (!id) continue;
        if (!old.id || old.read_only)
          throw new ValidationError({
            message: `Owned DNS rule ${old.name} is read-only or has no ID`,
          });
        const record = wanted.get(id);
        if (!record || seen.has(id)) {
          changes.push({ operation: 'delete', rule: old });
          continue;
        }
        seen.add(id);
        if (!record.ip) continue;
        const r = ruleFor(record, old);
        if (
          old.name !== r.name ||
          old.description !== r.description ||
          !old.enabled ||
          old.action !== 'override' ||
          old.filters.join() !== 'dns' ||
          old.traffic?.trim().replace(/\s+/g, ' ') !== r.traffic ||
          old.identity ||
          old.device_posture ||
          old.schedule ||
          old.expiration ||
          old.rule_settings?.override_host ||
          old.rule_settings?.override_ips?.join() !== record.ip
        )
          changes.push({ operation: 'update', rule: r });
      }
      for (const record of wanted.values())
        if (!seen.has(record.id) && record.ip)
          changes.push({ operation: 'create', rule: ruleFor(record) });
      return changes;
    },
    catch: (e) =>
      Schema.is(ValidationError)(e) ? e : new ValidationError({ message: 'Cannot plan DNS names' }),
  });
