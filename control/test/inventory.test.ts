import { Cloudflare } from '../src/cloudflare.ts';
import { Settings } from '../src/config.ts';
import { Storage } from '../src/storage.ts';
import { CloudflareError } from '../src/errors.ts';
import { Snapshot } from '../src/model.ts';
import { compilePolicy, parsePolicy, networkRule } from '../src/policy.ts';
import { plan } from '../src/console.ts';
import { activityLabel } from '../src/browser-view.ts';
import { expect, it } from '@effect/vitest';
import { Effect, Layer, Redacted, Schema } from 'effect';
import { Inventory, mergeMachines } from '../src/inventory.ts';
import { buildNames, dnsDiff } from '../src/names.ts';
import { activeSecure, secureRecords } from '../src/secure.ts';
import { machine, node, physical, registration, rule, snapshot } from './fixtures.ts';

it('matches CLI node joins, device preference, revocation and online threshold', () => {
  const now = Date.parse('2026-10-26T00:04:00Z');
  const devices = mergeMachines(
    [registration(), registration({ id: 'revoked', revoked_at: '2026-10-26T00:01:00Z' })],
    [physical({ name: 'Preferred' })],
    [{ node: node(), registrations: ['r1'] }],
    now,
  );
  expect(devices).toHaveLength(1);
  expect(devices[0]).toMatchObject({
    id: 'n1',
    registrationId: 'r1',
    kind: 'node',
    name: 'server',
    ipv4: '100.96.0.2',
    online: true,
  });
  expect(mergeMachines([registration()], [physical({ name: 'Preferred' })], [], now)[0]?.name).toBe(
    'Preferred',
  );
  expect(mergeMachines([registration()], [], [], now + 120000)[0]?.online).toBe(false);
});
it('keeps offline nodes and physical devices with unknown addresses visible', () => {
  const devices = mergeMachines(
    [],
    [physical()],
    [{ node: node({ status: 'down' }), registrations: [] }],
    Date.now(),
  );
  expect(devices).toHaveLength(2);
  expect(devices.every((d) => d.ipv4 === '')).toBe(true);
});
it('reserves natural DNS names before resolving duplicates', () => {
  const records = buildNames([
    machine({ id: '1', name: 'Laptop' }),
    machine({ id: '2', name: 'Laptop' }),
    machine({ id: '3', name: 'laptop-2' }),
  ]);
  expect(records.map((r) => r.name)).toEqual(['laptop-2.mesh', 'laptop-3.mesh', 'laptop.mesh']);
});
it.effect('DNS reconciliation preserves unrelated rules and offline addresses', () =>
  Effect.gen(function* () {
    const old = rule({
      name: 'meshscale dns: laptop.mesh',
      description: 'Managed by meshscale DNS v1; participant=device/r1',
      filters: ['dns'],
      action: 'override',
      traffic: 'dns.fqdn == "laptop.mesh"',
      rule_settings: { override_ips: ['100.96.0.2'] },
    });
    expect(yield* dnsDiff([machine()], [old, rule()])).toHaveLength(0);
    expect(yield* dnsDiff([machine({ ipv4: '' })], [old])).toHaveLength(0);
    expect((yield* dnsDiff([machine({ name: 'new-name' })], [old]))[0]?.rule.name).toBe(
      'meshscale dns: new-name.mesh',
    );
  }),
);
it.effect('isolates malformed and duplicate secure directory records', () =>
  Effect.gen(function* () {
    const list = {
      id: 'l1',
      name: 'meshscale-secure-v1-r1',
      type: 'IP',
      description:
        'meshscale secure v1: {"registration_id":"r1","public_key":"invalid","enabled":true}',
    };
    const records = yield* secureRecords([list, { ...list, id: 'l2' }]);
    expect(records.records).toEqual([]);
    expect(records.warnings).toHaveLength(2);
    const invalid = yield* secureRecords([list]);
    expect(invalid.warnings).toHaveLength(1);
  }),
);
it.effect('rejects invalid exit IPv4 bindings instead of advertising an exit', () =>
  Effect.gen(function* () {
    const record = {
      registration_id: 'r1',
      public_key: 'base64-public-key',
      enabled: true,
      exit_version: 2,
      offers_exit_node: true,
      ipv4: '10.0.0.1',
    };
    expect(
      (yield* activeSecure('account', [record], [registration()]).pipe(Effect.result))._tag,
    ).toBe('Failure');
  }),
);

it.effect('groups active node registrations into one stable row, policy target and DNS name', () =>
  Effect.gen(function* () {
    const older = registration({
      id: 'old',
      device: { id: 'old-device' },
      virtual_ipv4: '100.96.0.3',
      last_seen_at: '2026-10-25T00:00:00Z',
    });
    for (const registrations of [
      [older, registration()],
      [registration(), older],
    ]) {
      const machines = mergeMachines(
        registrations,
        [],
        [{ node: node(), registrations: ['old', 'r1'] }],
        Date.now(),
      );
      expect(machines).toHaveLength(1);
      expect(machines[0]).toMatchObject({ id: 'n1', registrationId: 'r1', ipv4: '100.96.0.2' });
      expect(buildNames(machines)).toEqual([
        { id: 'node/n1', name: 'server.mesh', ip: '100.96.0.2' },
      ]);
      const compiled = yield* compilePolicy(
        yield* parsePolicy('{"rules":[{"from":["server"],"to":["server:22"]}]}'),
        machines,
      );
      expect(compiled[0]?.traffic).toContain('100.96.0.2/32');
      const renamed = yield* dnsDiff(
        machines.map((m) => ({ ...m, name: 'x' })),
        [],
      );
      expect(renamed.map((c) => c.rule.name)).toEqual(['meshscale dns: x.mesh']);
    }
  }),
);
it('does not use a node inactivity timestamp as last activity', () => {
  const machines = mergeMachines(
    [],
    [],
    [{ node: node({ conns_inactive_at: '2026-10-25T00:00:00Z' }), registrations: [] }],
    Date.now(),
  );
  expect(machines[0]).toMatchObject({ online: true, lastSeen: null });
  expect(activityLabel(machines[0]?.lastSeen ?? null, true)).toBe('Active');
});
it('checks ISO dates in upstream inventory and browser snapshots', () => {
  for (const date of [
    'invalid',
    '2026-13-01T00:00:00Z',
    '2026-01-01',
    '123',
    '2026-02-30T00:00:00Z',
    '2026-01-01T24:00:00Z',
  ]) {
    expect(() => registration({ last_seen_at: date })).toThrow();
    expect(() => physical({ last_seen_at: date })).toThrow();
    expect(() => node({ conns_inactive_at: date })).toThrow();
    expect(() =>
      Schema.decodeUnknownSync(Snapshot)(snapshot({ machines: [machine({ lastSeen: date })] })),
    ).toThrow();
  }
  expect(() => registration({ last_seen_at: '2026-10-26T01:00:00.123+01:00' })).not.toThrow();
  expect(activityLabel('invalid', true)).toBe('Active');
});
const inventoryLayer = (
  options: {
    failTargets?: boolean;
    failCache?: boolean;
    malformedDirectory?: boolean;
    ambiguousSecure?: boolean;
    associationCache?: string | Error;
    data?: Readonly<Record<string, readonly unknown[]>>;
    writes?: Map<string, string>;
  } = {},
) => {
  const api = Layer.succeed(Cloudflare)({
    request: (_method, path) =>
      Effect.fail(
        new CloudflareError({ operation: path, status: 500, message: 'Unexpected mutation' }),
      ),
    list: (path, schema) => {
      if (path === '/infrastructure/targets' && options.failTargets)
        return Effect.fail(
          new CloudflareError({ operation: path, status: 403, message: 'Denied' }),
        );
      const registrations = options.ambiguousSecure
        ? [registration(), registration({ id: 'r2' })]
        : [registration()];
      const directory = options.malformedDirectory
        ? [{ id: 'bad', name: 'meshscale-secure-v1-r1', type: 'IP', description: 'bad' }]
        : options.ambiguousSecure
          ? [
              {
                id: 'secure',
                name: 'meshscale-secure-v1-r1',
                type: 'IP',
                description:
                  'meshscale secure v1: ' +
                  JSON.stringify({
                    registration_id: 'r1',
                    public_key: btoa(String.fromCharCode(9) + '\0'.repeat(31)),
                    enabled: true,
                  }),
              },
            ]
          : [];
      const values =
        options.data?.[path] ??
        (path === '/devices/registrations'
          ? registrations
          : path === '/gateway/lists'
            ? directory
            : []);
      return Schema.decodeUnknownEffect(Schema.Array(schema))(values).pipe(
        Effect.mapError(
          () =>
            new CloudflareError({ operation: path, status: 502, message: 'Invalid test payload' }),
        ),
      );
    },
  });
  const store = Storage.layer({
    get: (key) => {
      if (options.failCache && key === 'snapshot-v1')
        return Promise.reject(new Error('KV unavailable'));
      if (key === 'node-associations-v1')
        return options.associationCache instanceof Error
          ? Promise.reject(options.associationCache)
          : Promise.resolve(options.associationCache ?? null);
      return Promise.resolve(null);
    },
    put: (key, value) => {
      if (options.failCache) return Promise.reject(new Error('KV rate limit'));
      options.writes?.set(key, value);
      return Promise.resolve();
    },
    delete: () => Promise.resolve(),
  });
  const settings = Layer.succeed(Settings)({
    accountId: 'account',
    token: Redacted.make('test-token'),
    teamDomain: 'team.cloudflareaccess.com',
    audience: 'audience',
    ownerEmail: 'owner@example.com',
  });
  return Inventory.layer.pipe(Layer.provide(Layer.mergeAll(api, store, settings)));
};
it.effect(
  'retains the secure carrier for an older secure registration hidden by node deduplication',
  () =>
    Effect.gen(function* () {
      const desired = yield* compilePolicy(yield* parsePolicy('{"rules":[]}'), [
        machine({ secure: true }),
        machine({ id: 'peer', secure: true, ipv4: '100.96.0.4' }),
      ]);
      const data = {
        '/devices/registrations': [
          registration(),
          registration({
            id: 'new',
            device: { id: 'new-device' },
            virtual_ipv4: '100.96.0.3',
            last_seen_at: '2026-10-26T00:01:00Z',
          }),
          registration({
            id: 'peer',
            device: { id: 'peer-device', name: 'peer' },
            virtual_ipv4: '100.96.0.4',
          }),
        ],
        '/warp_connector': [node()],
        '/warp_connector/n1/connections': [{ id: 'r1' }, { id: 'new' }],
        '/gateway/lists': ['r1', 'peer'].map((id, index) => ({
          id: `secure-${id}`,
          name: `meshscale-secure-v1-${id}`,
          type: 'IP',
          description:
            'meshscale secure v1: ' +
            JSON.stringify({
              registration_id: id,
              public_key: btoa(String.fromCharCode(9 + index) + '\0'.repeat(31)),
              enabled: true,
            }),
        })),
        '/gateway/rules': desired.map((r, index) => ({
          ...r,
          id: `existing-${index}`,
          precedence: 1000 + index,
        })),
      };
      const inventory = yield* Inventory.pipe(
        Effect.flatMap((inventory) => inventory.load(true)),
        Effect.provide(inventoryLayer({ data })),
      );
      expect(inventory.machines).toHaveLength(2);
      expect(inventory.machines.find((m) => m.id === 'n1')).toMatchObject({
        registrationId: 'new',
        ipv4: '100.96.0.3',
        secure: false,
      });
      expect(inventory.secureEndpoints).toEqual(['100.96.0.2', '100.96.0.4']);
      const cached = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Snapshot))(
        yield* Schema.encodeEffect(Schema.fromJsonString(Snapshot))(inventory),
      );
      const preview = yield* plan({ type: 'rules', policy: '{"rules":[]}' }, cached);
      expect(preview.changes.filter((change) => change.operation === 'delete')).toEqual([]);
      expect(preview.after).toContain('secure-wireguard');
      expect(preview.after).toContain('100.96.0.2/32 100.96.0.4/32');
    }),
);
const associationFailures = [
  { label: 'KV read failure', value: new Error('KV unavailable') },
  { label: 'malformed JSON', value: '{invalid' },
  { label: 'malformed association record', value: '{"version":1,"nodes":{"n1":42}}' },
];
it.effect('retains cached node associations when live connections are empty', () =>
  Effect.gen(function* () {
    const inventory = yield* Inventory;
    const data = yield* inventory.load(true);
    expect(data.machines).toHaveLength(1);
    expect(data.machines[0]).toMatchObject({ id: 'n1', registrationId: 'r1', kind: 'node' });
    expect(data.nodeAssociationsError).toBeNull();
    yield* plan({ type: 'rename', id: 'node/n1', name: 'renamed' }, data);
  }).pipe(
    Effect.provide(
      inventoryLayer({
        associationCache: '{"version":1,"nodes":{"n1":["r1"]}}',
        data: { '/warp_connector': [node()] },
      }),
    ),
  ),
);
it.effect.each(associationFailures)(
  'uses complete live connections after association-cache $label',
  ({ value }) =>
    Effect.gen(function* () {
      const inventory = yield* Inventory;
      const data = yield* inventory.load(true);
      expect(data.machines).toHaveLength(1);
      expect(data.machines[0]).toMatchObject({ id: 'n1', registrationId: 'r1', kind: 'node' });
      expect(data.nodeAssociationsError).toBeNull();
      expect(data.warnings).toContain(
        'Node association cache unavailable; using live connections.',
      );
      yield* plan({ type: 'rules', policy: '{"rules":[]}' }, data);
      yield* plan({ type: 'rename', id: 'node/n1', name: 'renamed' }, data);
    }).pipe(
      Effect.provide(
        inventoryLayer({
          associationCache: value,
          data: {
            '/warp_connector': [node()],
            '/warp_connector/n1/connections': [{ id: 'r1' }],
          },
        }),
      ),
    ),
);
it.effect.each(associationFailures)(
  'blocks rule and DNS planning when empty live connections need associations after $label',
  ({ value }) =>
    Effect.gen(function* () {
      const writes = new Map<string, string>();
      const data = yield* Inventory.pipe(
        Effect.flatMap((inventory) => inventory.load(true)),
        Effect.provide(
          inventoryLayer({
            associationCache: value,
            writes,
            data: {
              '/warp_connector': [node()],
              '/gateway/rules': [
                { ...networkRule('secure-wireguard', 'allow', 'encrypted traffic'), id: 'carrier' },
                rule({
                  name: 'meshscale dns: server.mesh',
                  description: 'Managed by meshscale DNS v1; participant=node/n1',
                  filters: ['dns'],
                  action: 'override',
                  traffic: 'dns.fqdn == "server.mesh"',
                  rule_settings: { override_ips: ['100.96.0.2'] },
                }),
              ],
            },
          }),
        ),
      );
      expect(data.nodeAssociationsError?._tag).toBe('StorageError');
      expect(data.warnings).toContain(
        'Node associations incomplete; rule and DNS changes blocked.',
      );
      expect(writes.has('node-associations-v1')).toBe(false);
      const cached = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Snapshot))(
        writes.get('snapshot-v1') ?? '',
      );
      expect(cached.nodeAssociationsError?._tag).toBe('StorageError');
      for (const action of [
        { type: 'rules' as const, policy: '{"rules":[]}' },
        { type: 'rename' as const, id: 'device/r1', name: 'renamed' },
      ]) {
        const result = yield* plan(action, cached).pipe(Effect.result);
        expect(result._tag).toBe('Failure');
        if (result._tag === 'Failure') {
          expect(result.failure._tag).toBe('ValidationError');
          expect(result.failure.message).toContain('node associations are complete');
        }
      }
    }),
);
it.effect('carries typed directory and SSH-target failures in the inventory snapshot', () =>
  Effect.gen(function* () {
    const inventory = yield* Inventory;
    const data = yield* inventory.load(true);
    expect(data.secureDirectoryError?._tag).toBe('ValidationError');
    expect(data.sshTargetsError?._tag).toBe('CloudflareError');
    const result = yield* plan({ type: 'rules', policy: '{"rules":[]}' }, data).pipe(Effect.result);
    expect(result._tag).toBe('Failure');
  }).pipe(Effect.provide(inventoryLayer({ failTargets: true, malformedDirectory: true }))),
);
it.effect('returns fresh inventory even when snapshot cache reads and writes fail', () =>
  Effect.gen(function* () {
    const inventory = yield* Inventory;
    const data = yield* inventory.load();
    expect(data.machines).toHaveLength(1);
    expect(data.secureDirectoryError).toBeNull();
  }).pipe(Effect.provide(inventoryLayer({ failCache: true }))),
);

it.effect(
  'blocks rules when secure registration validation fails after parsing the key directory',
  () =>
    Effect.gen(function* () {
      const inventory = yield* Inventory;
      const data = yield* inventory.load(true);
      expect(data.secureDirectoryError?.message).toBe('Ambiguous secure registration directory');
      const result = yield* plan(
        { type: 'rules', policy: '{"rules":[]}' },
        {
          ...data,
          rules: [
            { ...networkRule('secure-wireguard', 'allow', 'encrypted traffic'), id: 'carrier' },
          ],
        },
      ).pipe(Effect.result);
      expect(result._tag).toBe('Failure');
    }).pipe(Effect.provide(inventoryLayer({ ambiguousSecure: true }))),
);
