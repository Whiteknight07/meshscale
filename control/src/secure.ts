import { Effect, Schema } from 'effect';
import { SecureRecord, type GatewayList, type Registration } from './model.ts';
import { ValidationError } from './errors.ts';

const prefix = 'meshscale-secure-v1-';
const marker = 'meshscale secure v1: ';
const keyBytes = (s: string) =>
  Effect.try({
    try: () => {
      const raw = atob(s);
      if (raw.length !== 32 || btoa(raw) !== s)
        throw new ValidationError({ message: 'Invalid WireGuard public key' });
      return Uint8Array.from(raw, (c) => c.charCodeAt(0));
    },
    catch: () => new ValidationError({ message: 'Invalid WireGuard public key' }),
  });
const validateKey = Effect.fn('Secure.validateKey')(function* (s: string) {
  const bytes = yield* keyBytes(s);
  yield* Effect.tryPromise({
    try: async () => {
      const pair = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
      if (!('privateKey' in pair)) throw new ValidationError({ message: 'X25519 unavailable' });
      const pub = await crypto.subtle.importKey('raw', bytes, 'X25519', false, []);
      await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, pair.privateKey, 256);
    },
    catch: () => new ValidationError({ message: 'Invalid X25519 public key' }),
  });
  return bytes;
});
export const secureRecords = Effect.fn('Secure.records')(function* (lists: readonly GatewayList[]) {
  const records: SecureRecord[] = [];
  const warnings: string[] = [];
  const counts = new Map<string, number>();
  for (const l of lists) counts.set(l.name, (counts.get(l.name) ?? 0) + 1);
  for (const l of lists.filter((l) => l.name.startsWith(prefix))) {
    if (
      counts.get(l.name) !== 1 ||
      !l.id ||
      l.type !== 'IP' ||
      !l.description?.startsWith(marker)
    ) {
      warnings.push(`Secure directory: ignored conflicting list ${l.name}`);
      continue;
    }
    const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(SecureRecord))(
      l.description.slice(marker.length),
    ).pipe(Effect.result);
    if (
      parsed._tag === 'Failure' ||
      !parsed.success.registration_id ||
      l.name !== prefix + parsed.success.registration_id
    ) {
      warnings.push(`Secure directory: ignored malformed list ${l.name}`);
      continue;
    }
    const r = parsed.success;
    const valid = yield* validateKey(r.public_key).pipe(Effect.result);
    if (valid._tag === 'Failure') {
      warnings.push(`Secure directory: ignored invalid key ${l.name}`);
      continue;
    }
    if (r.enabled) records.push(r);
  }
  return { records, warnings };
});
export const activeSecure = Effect.fn('Secure.active')(function* (
  account: string,
  records: readonly SecureRecord[],
  registrations: readonly Registration[],
) {
  const active = registrations.filter(
    (r) =>
      !r.revoked_at && !r.deleted_at && (!r.registration_type || r.registration_type === 'warp'),
  );
  const keys = new Set<string>();
  const ids = new Set<string>();
  const result = new Map<string, SecureRecord>();
  for (const record of records) {
    const r = active.find((r) => r.id === record.registration_id);
    if (!r) continue;
    if (
      !r.device.id ||
      !/^100\.(?:9[6-9]|10[0-9]|11[01])\./.test(r.virtual_ipv4 ?? '') ||
      ids.has(r.id) ||
      keys.has(record.public_key) ||
      active.filter((other) => other.virtual_ipv4 === r.virtual_ipv4).length !== 1
    )
      return yield* new ValidationError({ message: 'Ambiguous secure registration directory' });
    if (
      (record.exit_version !== 0 && record.exit_version !== 2) ||
      (record.exit_version === 0 && (record.offers_exit_node || record.ipv4))
    )
      return yield* new ValidationError({ message: 'Unsupported exit directory record' });
    if (record.exit_version === 2) {
      const data = new TextEncoder().encode(`meshscale-exit-v2\0${account}\0${record.public_key}`);
      const hash = yield* Effect.tryPromise({
        try: () => crypto.subtle.digest('SHA-256', data),
        catch: () => new ValidationError({ message: 'Cannot verify exit binding' }),
      });
      const h = new Uint8Array(hash);
      const expected = `10.${192 | ((h[0] ?? 0) & 63)}.${h[1] ?? 0}.${1 + ((h[2] ?? 0) % 254)}`;
      if (record.ipv4 !== expected)
        return yield* new ValidationError({ message: 'Invalid secure IPv4 binding' });
    }
    keys.add(record.public_key);
    ids.add(r.id);
    result.set(r.id, record);
  }
  return result;
});
