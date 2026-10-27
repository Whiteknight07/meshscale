import { expect, it } from '@effect/vitest';
import { Effect, Layer, Schema } from 'effect';
import { networkRule } from '../src/policy.ts';
import { Console, plan } from '../src/console.ts';
import { Cloudflare } from '../src/cloudflare.ts';
import { CloudflareError, StorageError, ValidationError } from '../src/errors.ts';
import { Inventory } from '../src/inventory.ts';
import { Storage } from '../src/storage.ts';
import { machine, snapshot } from './fixtures.ts';

const testServices = (
  mutations: string[],
  fail = false,
  failDelete = false,
  load = () => Effect.succeed(snapshot()),
) => {
  const kv = new Map<string, string>([['snapshot-v1', 'cached']]);
  const store = Storage.layer({
    get: (key) => Promise.resolve(kv.get(key) ?? null),
    put: (key, value) => {
      kv.set(key, value);
      return Promise.resolve();
    },
    delete: (key) => {
      if (failDelete) return Promise.reject(new Error('KV rate limit'));
      kv.delete(key);
      return Promise.resolve();
    },
  });
  const api = Layer.succeed(Cloudflare)({
    request: (method, path, schema, body) => {
      mutations.push(`${method} ${path}`);
      return fail
        ? Effect.fail(new CloudflareError({ operation: path, status: 403, message: 'Denied' }))
        : Schema.decodeUnknownEffect(schema)({
            id: 'generated',
            ...(typeof body === 'object' ? body : {}),
          }).pipe(
            Effect.mapError(
              () =>
                new CloudflareError({
                  operation: path,
                  status: 502,
                  message: 'Test response invalid',
                }),
            ),
          );
    },
    list: (_path, schema) =>
      Schema.decodeUnknownEffect(Schema.Array(schema))([]).pipe(
        Effect.mapError(
          () =>
            new CloudflareError({
              operation: 'list',
              status: 502,
              message: 'Test response invalid',
            }),
        ),
      ),
  });
  const inventory = Layer.succeed(Inventory)({ load });
  return { layer: Console.layer.pipe(Layer.provide(Layer.mergeAll(store, api, inventory))), kv };
};
it.effect('requires confirmation and rejects a stale preview before any mutation', () =>
  Effect.gen(function* () {
    const mutations: string[] = [];
    const test = testServices(mutations);
    yield* Effect.gen(function* () {
      const console = yield* Console;
      const action = { type: 'revoke' as const, id: 'device/r1' };
      const preview = yield* console.preview(action);
      expect(
        (yield* console.apply(action, preview.fingerprint, false).pipe(Effect.result))._tag,
      ).toBe('Failure');
      expect((yield* console.apply(action, 'stale', true).pipe(Effect.result))._tag).toBe(
        'Failure',
      );
      expect(mutations).toEqual([]);
      yield* console.apply(action, preview.fingerprint, true);
      expect(mutations).toEqual(['POST /devices/registrations/revoke?id=r1']);
      expect(test.kv.has('snapshot-v1')).toBe(false);
    }).pipe(Effect.provide(test.layer));
  }),
);
it.effect('invalidates cached data after a partially failed write', () =>
  Effect.gen(function* () {
    const test = testServices([], true);
    yield* Effect.gen(function* () {
      const console = yield* Console;
      const action = { type: 'revoke' as const, id: 'device/r1' };
      const preview = yield* console.preview(action);
      expect(
        (yield* console.apply(action, preview.fingerprint, true).pipe(Effect.result))._tag,
      ).toBe('Failure');
      expect(test.kv.has('snapshot-v1')).toBe(false);
    }).pipe(Effect.provide(test.layer));
  }),
);
it.effect('binds preview to changed resource identity but ignores online heartbeat drift', () =>
  Effect.gen(function* () {
    const action = { type: 'revoke' as const, id: 'device/r1' };
    const a = yield* plan(action, snapshot());
    const b = yield* plan(
      action,
      snapshot({ machines: [machine({ lastSeen: '2026-10-26T00:01:00Z', online: false })] }),
    );
    const c = yield* plan(action, snapshot({ machines: [machine({ name: 'changed' })] }));
    expect(a.fingerprint).toBe(b.fingerprint);
    expect(a.fingerprint).not.toBe(c.fingerprint);
  }),
);

it.effect('blocks rule planning on typed secure-directory or SSH-target failure', () =>
  Effect.gen(function* () {
    const carrier = {
      ...networkRule('secure-wireguard', 'allow', 'encrypted traffic'),
      id: 'carrier',
    };
    for (const errors of [
      { secureDirectoryError: new ValidationError({ message: 'Invalid directory' }) },
      {
        sshTargetsError: new CloudflareError({
          operation: 'GET /infrastructure/targets',
          status: 403,
          message: 'Denied',
        }),
      },
    ]) {
      const result = yield* plan(
        { type: 'rules', policy: '{"rules":[]}' },
        snapshot({ ...errors, rules: [carrier] }),
      ).pipe(Effect.result);
      expect(result._tag).toBe('Failure');
      if (result._tag === 'Failure') expect(result.failure._tag).toBe('ValidationError');
    }
  }),
);
it.effect('rejects previews and applies before mutation if node associations become degraded', () =>
  Effect.gen(function* () {
    for (const action of [
      { type: 'rules' as const, policy: '{"rules":[]}' },
      { type: 'rename' as const, id: 'node/n1', name: 'renamed' },
    ]) {
      let data = snapshot({ machines: [machine({ kind: 'node', id: 'n1' })] });
      const mutations: string[] = [];
      const test = testServices(mutations, false, false, () => Effect.succeed(data));
      yield* Effect.gen(function* () {
        const console = yield* Console;
        const preview = yield* console.preview(action);
        data = {
          ...data,
          nodeAssociationsError: new StorageError({ operation: 'read', message: 'KV unavailable' }),
        };
        for (const operation of [
          console.preview(action).pipe(Effect.asVoid),
          console.apply(action, preview.fingerprint, true).pipe(Effect.asVoid),
        ]) {
          const result = yield* operation.pipe(Effect.result);
          expect(result._tag).toBe('Failure');
          if (result._tag === 'Failure') {
            expect(result.failure._tag).toBe('ValidationError');
            expect(result.failure.message).toContain('node associations are complete');
          }
        }
        expect(mutations).toEqual([]);
      }).pipe(Effect.provide(test.layer));
    }
  }),
);
it.effect(
  'cache invalidation failure preserves a successful revoke and its original API error',
  () =>
    Effect.gen(function* () {
      for (const fail of [false, true]) {
        const mutations: string[] = [];
        const test = testServices(mutations, fail, true);
        yield* Effect.gen(function* () {
          const console = yield* Console;
          const action = { type: 'revoke' as const, id: 'device/r1' };
          const preview = yield* console.preview(action);
          const result = yield* console
            .apply(action, preview.fingerprint, true)
            .pipe(Effect.result);
          expect(mutations).toEqual(['POST /devices/registrations/revoke?id=r1']);
          if (fail) {
            expect(result._tag).toBe('Failure');
            if (result._tag === 'Failure')
              expect(result.failure).toMatchObject({ _tag: 'CloudflareError', status: 403 });
          } else expect(result._tag).toBe('Success');
        }).pipe(Effect.provide(test.layer));
      }
    }),
);
