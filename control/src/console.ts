import { Context, Effect, Layer, Schema } from 'effect';
import { Cloudflare } from './cloudflare.ts';
import { Inventory } from './inventory.ts';
import { Storage } from './storage.ts';
import { Conflict, ValidationError, type CloudflareError, type StorageError } from './errors.ts';
import {
  GatewayRule,
  StoredPolicy,
  type Action,
  type Change,
  type Preview,
  type Snapshot,
} from './model.ts';
import { compilePolicy, owner, parsePolicy } from './policy.ts';
import { dnsDiff, dnsOwner } from './names.ts';
import { networkDiff } from './diff.ts';

type ConsoleError = CloudflareError | StorageError | ValidationError | Conflict;
const identifier = (m: Snapshot['machines'][number]) => `${m.kind}/${m.id}`;
const hash = (value: string) =>
  Effect.tryPromise({
    try: async () =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))),
        (b) => b.toString(16).padStart(2, '0'),
      ).join(''),
    catch: () => new ValidationError({ message: 'Cannot create change fingerprint' }),
  });
const json = (value: unknown) => JSON.stringify(value, null, 2);
export const plan = Effect.fn('Console.plan')(function* (action: Action, snapshot: Snapshot) {
  if (snapshot.nodeAssociationsError && (action.type === 'rules' || action.type === 'rename'))
    return yield* new ValidationError({
      message:
        'Cannot plan rule or DNS changes until node associations are complete. Refresh inventory and retry.',
    });
  let changes: readonly Change[] = [];
  let before = '';
  let after = '';
  let notice = '';
  if (action.type === 'rules') {
    if (snapshot.secureDirectoryError || snapshot.sshTargetsError)
      return yield* new ValidationError({
        message:
          'Cannot plan rules until the secure directory and SSH targets have been validated. Refresh inventory and retry.',
      });
    const p = yield* parsePolicy(action.policy);
    const desired = yield* compilePolicy(p, snapshot.machines, snapshot.secureEndpoints);
    changes = yield* networkDiff(desired, snapshot.rules);
    before = json(snapshot.rules.filter((r) => owner(r)));
    after = json(desired);
    notice =
      'Only meshscale-owned network policies change. Gateway propagation can take about 60 seconds. Apply can be partial on an API error; preview again to resume. Encrypted secure traffic retains its UDP carrier; inner access is enforced on devices. CLI rules.json remains local: keep it in sync to avoid a later CLI sync overwriting these rules.';
  } else {
    const m = snapshot.machines.find((m) => identifier(m) === action.id);
    if (!m) return yield* new ValidationError({ message: 'Machine no longer exists' });
    if (action.type === 'rename') {
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(action.name))
        return yield* new ValidationError({
          message: 'Use a DNS label: 1–63 lowercase letters, digits or hyphens',
        });
      if (!m.ipv4 && !m.ipv6)
        return yield* new ValidationError({
          message: 'Machine has no known Mesh address; wait for it to connect',
        });
      changes = yield* dnsDiff(
        snapshot.machines.map((d) =>
          identifier(d) === action.id ? { ...d, name: action.name } : d,
        ),
        snapshot.rules,
      );
      before = json({ name: m.name, dns: snapshot.rules.filter((r) => dnsOwner(r)) });
      after = json({ name: action.name, changes });
      notice =
        m.kind === 'node'
          ? 'Renames the Cloudflare Mesh node and reconciles Gateway DNS using the CLI ownership markers. Device syncs will retain this node name.'
          : 'Creates a Gateway DNS alias using the CLI DNS mechanism. Cloudflare cannot remotely rename the OS hostname. A later CLI dns sync derives names from the OS hostname and may replace this alias; rename the host there to make it permanent.';
    } else {
      before = json({
        id: identifier(m),
        name: m.name,
        deviceId: m.deviceId,
        registrationId: m.registrationId,
        ipv4: m.ipv4,
        ipv6: m.ipv6,
      });
      after =
        m.kind === 'node'
          ? 'Delete this Cloudflare Mesh node. Its connector token stops working.'
          : m.registrationId
            ? 'Revoke this device registration. It must enroll again to rejoin.'
            : 'Revoke every registration on this physical device.';
      notice =
        'This disconnects the machine. It does not uninstall meshscale or remove local private keys. Other devices are unchanged. Stale DNS and public-key records stay visible until the next CLI sync; revoked registrations cannot become active secure peers.';
    }
  }
  const fingerprint = yield* hash(json({ action, changes, before, after }));
  return { fingerprint, changes, before, after, notice } satisfies Preview;
});
export class Console extends Context.Service<
  Console,
  {
    readonly snapshot: (fresh?: boolean) => Effect.Effect<Snapshot, ConsoleError>;
    readonly policy: Effect.Effect<StoredPolicy | null, StorageError>;
    readonly preview: (action: Action) => Effect.Effect<Preview, ConsoleError>;
    readonly apply: (
      action: Action,
      fingerprint: string,
      confirmed: boolean,
    ) => Effect.Effect<{ message: string }, ConsoleError>;
  }
>()('meshscale/Console') {
  static readonly layer = Layer.effect(Console)(
    Effect.gen(function* () {
      const inventory = yield* Inventory;
      const api = yield* Cloudflare;
      const store = yield* Storage;
      const preview = (action: Action) =>
        inventory.load(true).pipe(Effect.flatMap((s) => plan(action, s)));
      const apply = Effect.fn('Console.apply')(function* (
        action: Action,
        fingerprint: string,
        confirmed: boolean,
      ) {
        if (!confirmed)
          return yield* new ValidationError({ message: 'Explicit confirmation required' });
        const snapshot = yield* inventory.load(true);
        const current = yield* plan(action, snapshot);
        if (current.fingerprint !== fingerprint)
          return yield* new Conflict({
            message: 'Account state changed since preview. Review a fresh diff before applying.',
          });
        const mutate = Effect.gen(function* () {
          if (action.type === 'rename' || action.type === 'revoke') {
            const m = snapshot.machines.find((m) => identifier(m) === action.id);
            if (!m) return yield* new Conflict({ message: 'Machine no longer exists' });
            if (action.type === 'rename' && m.kind === 'node') {
              yield* api.request(
                'PATCH',
                `/warp_connector/${encodeURIComponent(m.id)}`,
                Schema.Struct({ id: Schema.String, name: Schema.String }),
                { name: action.name },
              );
            }
            if (action.type === 'revoke') {
              if (m.kind === 'node')
                yield* api.request(
                  'DELETE',
                  `/warp_connector/${encodeURIComponent(m.id)}`,
                  Schema.Unknown,
                );
              else if (m.registrationId)
                yield* api.request(
                  'POST',
                  `/devices/registrations/revoke?id=${encodeURIComponent(m.registrationId)}`,
                  Schema.Unknown,
                );
              else
                yield* api.request(
                  'POST',
                  `/devices/physical-devices/${encodeURIComponent(m.deviceId)}/revoke`,
                  Schema.Unknown,
                );
            }
          }
          for (const c of current.changes) {
            if (
              (!owner(c.rule) && !dnsOwner(c.rule)) ||
              c.rule.read_only ||
              (c.operation !== 'create' && !c.rule.id)
            )
              return yield* new ValidationError({
                message: 'Refusing to mutate unowned, read-only or unidentified Gateway rule',
              });
            const body = { ...c.rule, id: undefined, read_only: undefined };
            if (c.operation === 'create')
              yield* api.request('POST', '/gateway/rules', GatewayRule, body);
            else if (c.operation === 'update')
              yield* api.request(
                'PUT',
                `/gateway/rules/${encodeURIComponent(c.rule.id)}`,
                GatewayRule,
                body,
              );
            else
              yield* api.request(
                'DELETE',
                `/gateway/rules/${encodeURIComponent(c.rule.id)}`,
                Schema.Unknown,
              );
          }
          if (action.type === 'rules') {
            const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
            yield* store.write('policy-v1', StoredPolicy, {
              version: 1,
              json: action.policy,
              updatedAt: now,
            });
          }
          return { message: 'Change applied. Gateway propagation may take about 60 seconds.' };
        });
        return yield* mutate.pipe(
          Effect.ensuring(
            store
              .remove('snapshot-v1')
              .pipe(
                Effect.catchCause(() => Effect.logWarning('Snapshot cache invalidation failed')),
              ),
          ),
        );
      });
      return {
        snapshot: inventory.load,
        policy: store.read('policy-v1', StoredPolicy),
        preview,
        apply,
      };
    }),
  );
}
