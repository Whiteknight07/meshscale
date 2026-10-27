import { Context, Effect, Layer, Schema } from 'effect';
import { Cloudflare } from './cloudflare.ts';
import { Settings } from './config.ts';
import { Storage } from './storage.ts';
import { CloudflareError, StorageError, ValidationError } from './errors.ts';
import {
  Connector,
  GatewayList,
  GatewayRule,
  MeshNode,
  PhysicalDevice,
  Registration,
  Snapshot,
  Target,
  type Machine,
} from './model.ts';
import { buildNames } from './names.ts';
import { activeSecure, secureRecords } from './secure.ts';

const associationSchema = Schema.Struct({
  version: Schema.Literal(1),
  nodes: Schema.Record(Schema.String, Schema.Array(Schema.String)),
});
export interface JoinedNode {
  readonly node: MeshNode;
  readonly registrations: readonly string[];
}
export const mergeMachines = (
  registrations: readonly Registration[],
  physical: readonly PhysicalDevice[],
  nodes: readonly JoinedNode[],
  now: number,
): Machine[] => {
  const seen = new Set<string>();
  const joined = new Map<string, Machine>();
  const recentlySeen = (s: string | null) => s !== null && now - Date.parse(s) <= 300000;
  const base = (id: string): Machine => ({
    id,
    deviceId: '',
    registrationId: '',
    kind: 'device',
    name: '',
    owner: '',
    ownerEmail: '',
    ipv4: '',
    ipv6: '',
    os: '',
    online: false,
    lastSeen: null,
    state: '',
    secure: false,
    offersExit: false,
    ssh: 'unknown',
    dns: '',
  });
  const machines: Machine[] = [];
  for (const r of registrations) {
    if (r.deleted_at || r.revoked_at || (r.registration_type && r.registration_type !== 'warp'))
      continue;
    const p = physical.find((p) => p.id === r.device.id);
    if (p?.deleted_at) continue;
    seen.add(r.device.id);
    const n = nodes.find(
      (n) => n.registrations.includes(r.id) || n.registrations.includes(r.device.id),
    )?.node;
    const d: Machine = {
      ...base(r.id),
      deviceId: r.device.id,
      registrationId: r.id,
      name: p?.name || r.device.name || '',
      owner:
        r.user?.email || r.user?.name || p?.last_seen_user?.email || p?.last_seen_user?.name || '',
      ownerEmail: r.user?.email ?? '',
      ipv4: r.virtual_ipv4 ?? '',
      ipv6: r.virtual_ipv6 ?? '',
      os: p?.device_type ?? '',
      lastSeen: r.last_seen_at,
      online: recentlySeen(r.last_seen_at),
    };
    if (n) {
      // A node can have several active registrations. Prefer the latest activity,
      // then registration ID, so API ordering never changes its address or name.
      const previous = joined.get(n.id);
      const activity = Date.parse(d.lastSeen ?? '') || 0;
      const priorActivity = Date.parse(previous?.lastSeen ?? '') || 0;
      if (
        !previous ||
        activity > priorActivity ||
        (activity === priorActivity && d.registrationId < previous.registrationId)
      ) {
        joined.set(n.id, {
          ...d,
          id: n.id,
          kind: 'node',
          name: n.name ?? '',
          owner: 'Mesh node',
          os: 'linux',
          online: ['healthy', 'degraded'].includes(n.status ?? ''),
          state: n.status ?? '',
        });
      }
    } else machines.push(d);
  }
  machines.push(...joined.values());
  for (const p of physical)
    if (!seen.has(p.id) && !p.deleted_at)
      machines.push({
        ...base(p.id),
        deviceId: p.id,
        name: p.name ?? '',
        owner: p.last_seen_user?.email || p.last_seen_user?.name || '',
        os: p.device_type ?? '',
        lastSeen: p.last_seen_at,
        online: recentlySeen(p.last_seen_at),
      });
  for (const { node: n } of nodes)
    if (!joined.has(n.id))
      machines.push({
        ...base(n.id),
        kind: 'node',
        name: n.name ?? '',
        owner: 'Mesh node',
        os: 'linux',
        online: ['healthy', 'degraded'].includes(n.status ?? ''),
        lastSeen: null,
        state: n.status ?? '',
      });
  return machines.sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : a.id < b.id ? -1 : 1,
  );
};
export class Inventory extends Context.Service<
  Inventory,
  {
    readonly load: (
      fresh?: boolean,
    ) => Effect.Effect<Snapshot, CloudflareError | StorageError | ValidationError>;
  }
>()('meshscale/Inventory') {
  static readonly layer = Layer.effect(Inventory)(
    Effect.gen(function* () {
      const api = yield* Cloudflare;
      const store = yield* Storage;
      const settings = yield* Settings;
      return {
        load: Effect.fn('Inventory.load')(function* (fresh = false) {
          const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
          if (!fresh) {
            const cached = yield* store
              .read('snapshot-v1', Snapshot)
              .pipe(
                Effect.catchTag('StorageError', () =>
                  Effect.logWarning('Snapshot cache read failed').pipe(Effect.as(null)),
                ),
              );
            if (cached && now - cached.fetchedAt < 15000) return cached;
          }
          const [registrations, physical, nodes, rules, lists, targets] = yield* Effect.all(
            [
              api.list('/devices/registrations', Registration, 'cursor'),
              api.list('/devices/physical-devices', PhysicalDevice, 'cursor'),
              api.list('/warp_connector', MeshNode, 'page'),
              api.list('/gateway/rules', GatewayRule),
              api.list('/gateway/lists', GatewayList, 'page'),
              api.list('/infrastructure/targets', Target, 'page').pipe(Effect.result),
            ],
            { concurrency: 6 },
          );
          const active = nodes.filter((n) => !n.deleted_at);
          const cachedAssociations = yield* store
            .read('node-associations-v1', associationSchema)
            .pipe(
              Effect.tapError(() => Effect.logWarning('Node association cache read failed')),
              Effect.result,
            );
          const associations =
            cachedAssociations._tag === 'Success' ? cachedAssociations.success : null;
          const joinedNodes = yield* Effect.forEach(
            active,
            (n) =>
              Effect.gen(function* () {
                const connections = yield* api.list(
                  `/warp_connector/${encodeURIComponent(n.id)}/connections`,
                  Connector,
                  'page',
                );
                return {
                  node: n,
                  registrations: connections.length
                    ? connections.map((c) => c.id)
                    : (associations?.nodes[n.id] ?? []),
                };
              }),
            { concurrency: 4 },
          );
          const learned = {
            version: 1 as const,
            nodes: Object.fromEntries(joinedNodes.map((n) => [n.node.id, n.registrations])),
          };
          // Empty live connections need the cache to retain node identity and DNS ownership.
          const nodeAssociationsError =
            cachedAssociations._tag === 'Failure' &&
            joinedNodes.some((n) => n.registrations.length === 0)
              ? cachedAssociations.failure
              : null;
          if (!nodeAssociationsError && JSON.stringify(learned) !== JSON.stringify(associations))
            yield* store
              .write('node-associations-v1', associationSchema, learned)
              .pipe(
                Effect.catchTag('StorageError', () =>
                  Effect.logWarning('Node association cache write failed'),
                ),
              );
          const directory = yield* secureRecords(lists);
          const secured = yield* activeSecure(
            settings.accountId,
            directory.records,
            registrations,
          ).pipe(Effect.result);
          const secureDirectoryError =
            secured._tag === 'Failure'
              ? secured.failure
              : directory.warnings.length
                ? new ValidationError({
                    message: 'Secure directory contains invalid or conflicting records',
                  })
                : null;
          const sshTargetsError = targets._tag === 'Failure' ? targets.failure : null;
          const warnings = [...directory.warnings];
          if (cachedAssociations._tag === 'Failure')
            warnings.push('Node association cache unavailable; using live connections.');
          if (nodeAssociationsError)
            warnings.push('Node associations incomplete; rule and DNS changes blocked.');
          if (secureDirectoryError)
            warnings.push('Secure directory validation failed; rule changes blocked.');
          if (sshTargetsError)
            warnings.push('Cloudflare SSH targets unavailable; rule changes blocked.');
          const machines = mergeMachines(registrations, physical, joinedNodes, now);
          const dns = new Map(buildNames(machines).map((r) => [r.id, r.name]));
          const enriched = machines.map((m) => {
            const secure =
              secured._tag === 'Success' ? secured.success.get(m.registrationId) : undefined;
            const cloudflareSSH =
              targets._tag === 'Success' &&
              targets.success.some(
                (t) =>
                  (m.ipv4 && t.ip.ipv4?.ip_addr === m.ipv4) ||
                  (m.ipv6 && t.ip.ipv6?.ip_addr === m.ipv6),
              );
            return {
              ...m,
              secure: secure !== undefined,
              offersExit: secure?.exit_version === 2 && secure.offers_exit_node,
              ssh: cloudflareSSH ? ('cloudflare' as const) : ('unknown' as const),
              dns: dns.get(`${m.kind}/${m.id}`) ?? '',
            };
          });
          const snapshot = {
            fetchedAt: now,
            machines: enriched,
            // Carrier endpoints must include registrations hidden by the single node display row.
            secureEndpoints:
              secured._tag === 'Success'
                ? registrations
                    .filter((r) => secured.success.has(r.id))
                    .flatMap((r) => (r.virtual_ipv4 ? [r.virtual_ipv4] : []))
                : [],
            rules,
            warnings,
            nodeAssociationsError,
            secureDirectoryError,
            sshTargetsError,
          };
          yield* store
            .write('snapshot-v1', Snapshot, snapshot, 60)
            .pipe(
              Effect.catchTag('StorageError', () =>
                Effect.logWarning('Snapshot cache write failed'),
              ),
            );
          return snapshot;
        }),
      };
    }),
  );
}
