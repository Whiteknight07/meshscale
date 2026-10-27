import { expect, it } from '@effect/vitest';
import { Effect, Layer, Logger } from 'effect';
import { HttpRouter, HttpServerResponse } from 'effect/http';
import { Access } from '../src/auth.ts';
import { Console, plan } from '../src/console.ts';
import { Unauthorized, CloudflareError, StorageError } from '../src/errors.ts';
import { AssetFiles, Routes } from '../src/http.ts';
import { snapshot } from './fixtures.ts';

const services = (authorized: boolean, failure?: CloudflareError | StorageError) =>
  Layer.mergeAll(
    Layer.succeed(Access)({
      verify: () =>
        authorized
          ? Effect.succeed({ email: 'owner@example.com', sub: 'owner', exp: 9999999999, iat: 0 })
          : Effect.fail(new Unauthorized({ message: 'Denied' })),
    }),
    Layer.succeed(AssetFiles)({ script: Effect.succeed(HttpServerResponse.text('/* script */')) }),
    Layer.succeed(Console)({
      snapshot: () => (failure ? Effect.fail(failure) : Effect.succeed(snapshot())),
      policy: Effect.succeed(null),
      preview: (action) => plan(action, snapshot()),
      apply: () => Effect.succeed({ message: 'applied' }),
    }),
  );
const withApp = <A, E>(
  authorized: boolean,
  use: (handler: (r: Request) => Promise<Response>) => Effect.Effect<A, E>,
  failure?: CloudflareError | StorageError,
  logs: unknown[] = [],
) =>
  Effect.acquireUseRelease(
    Effect.sync(() =>
      HttpRouter.toWebHandler(Routes.pipe(Layer.provide(services(authorized, failure))), {
        disableLogger: true,
        middleware: (effect) =>
          effect.pipe(
            Effect.withLogger(
              Logger.make(({ message }) => {
                logs.push(message);
              }),
            ),
          ),
      }),
    ),
    (app) => use(app.handler),
    (app) => Effect.promise(app.dispose),
  );
it.effect('protects HTML, assets, API and OpenAPI before reading account data', () =>
  withApp(false, (handler) =>
    Effect.gen(function* () {
      for (const path of ['/', '/api/snapshot', '/api/openapi.json', '/console.js']) {
        const response = yield* Effect.promise(() =>
          handler(new Request(`https://console.example${path}`)),
        );
        expect(response.status).toBe(403);
      }
    }),
  ),
);
it.effect('serves schema-encoded inventory and a fast data-independent shell', () =>
  withApp(true, (handler) =>
    Effect.gen(function* () {
      const shell = yield* Effect.promise(() => handler(new Request('https://console.example/')));
      expect(shell.status).toBe(200);
      expect(shell.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
      const response = yield* Effect.promise(() =>
        handler(new Request('https://console.example/api/snapshot')),
      );
      const data: unknown = yield* Effect.promise(() => response.json());
      expect(data).toMatchObject({ machines: [{ name: 'laptop', ipv4: '100.96.0.2' }] });
    }),
  ),
);
it.effect('rejects cross-origin writes and malformed requests', () =>
  withApp(true, (handler) =>
    Effect.gen(function* () {
      const cross = yield* Effect.promise(() =>
        handler(
          new Request('https://console.example/api/preview', {
            method: 'POST',
            headers: {
              origin: 'https://evil.example',
              host: 'console.example',
              'Content-Type': 'application/json',
            },
            body: '{"type":"rules","policy":"{\\"rules\\":[]}"}',
          }),
        ),
      );
      expect(cross.status).toBe(403);
      const invalid = yield* Effect.promise(() =>
        handler(
          new Request('https://console.example/api/apply', {
            method: 'POST',
            headers: {
              origin: 'https://console.example',
              host: 'console.example',
              'Content-Type': 'application/json',
            },
            body: '{"confirm":false}',
          }),
        ),
      );
      expect(invalid.status).toBe(400);
    }),
  ),
);

it.effect('returns schema-encoded Unauthorized for API authentication failures', () =>
  withApp(false, (handler) =>
    Effect.gen(function* () {
      const response = yield* Effect.promise(() =>
        handler(new Request('https://console.example/api/snapshot')),
      );
      expect(response.status).toBe(403);
      expect(response.headers.get('Content-Type')).toContain('application/json');
      const data: unknown = yield* Effect.promise(() => response.json());
      expect(data).toEqual({ _tag: 'Unauthorized', message: 'Denied' });
    }),
  ),
);
it.effect('returns schema-encoded Unauthorized for cross-origin API writes', () =>
  withApp(true, (handler) =>
    Effect.gen(function* () {
      const response = yield* Effect.promise(() =>
        handler(
          new Request('https://console.example/api/preview', {
            method: 'POST',
            headers: { origin: 'https://evil.example', host: 'console.example' },
            body: '{}',
          }),
        ),
      );
      expect(response.status).toBe(403);
      const data: unknown = yield* Effect.promise(() => response.json());
      expect(data).toMatchObject({ _tag: 'Unauthorized' });
    }),
  ),
);
it.effect('stops reading chunked bodies over 256 KiB, regardless of content-length', () =>
  withApp(true, (handler) =>
    Effect.gen(function* () {
      for (const length of [undefined, '2']) {
        let pulled = 0;
        let cancelled = false;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            const chunk =
              pulled++ === 0 ? '{"type":"rules","policy":"{\\"rules\\":[]}"}' : ' '.repeat(16384);
            controller.enqueue(new TextEncoder().encode(chunk));
            if (pulled === 64) controller.close();
          },
          cancel() {
            cancelled = true;
          },
        });
        const init = {
          method: 'POST',
          headers: {
            origin: 'https://console.example',
            host: 'console.example',
            'Content-Type': 'application/json',
            ...(length === undefined ? {} : { 'Content-Length': length }),
          },
          body: stream,
          duplex: 'half',
        };
        const response = yield* Effect.promise(() =>
          handler(new Request('https://console.example/api/preview', init)),
        );
        expect(response.status).toBe(413);
        expect(pulled).toBeLessThan(64);
        expect(cancelled).toBe(true);
      }
    }),
  ),
);
it.effect('accepts a valid API body exactly at the byte limit', () =>
  withApp(true, (handler) =>
    Effect.gen(function* () {
      const json = '{"type":"rules","policy":"{\\"rules\\":[]}"}';
      const body = json + ' '.repeat(256 * 1024 - new TextEncoder().encode(json).byteLength);
      const response = yield* Effect.promise(() =>
        handler(
          new Request('https://console.example/api/preview', {
            method: 'POST',
            headers: {
              origin: 'https://console.example',
              host: 'console.example',
              'Content-Type': 'application/json',
            },
            body,
          }),
        ),
      );
      expect(response.status).toBe(200);
    }),
  ),
);

it.effect('logs failed Cloudflare and storage handlers without emitting sensitive causes', () =>
  Effect.gen(function* () {
    const lines: unknown[] = [];
    for (const error of [
      new CloudflareError({
        operation: 'GET /items',
        status: 403,
        message: 'Denied',
        cause: new Error('Bearer secret-test-token'),
      }),
      new StorageError({ operation: 'read', message: 'Storage unavailable' }),
    ]) {
      yield* withApp(
        true,
        (handler) =>
          Effect.gen(function* () {
            const response = yield* Effect.promise(() =>
              handler(new Request('https://console.example/api/snapshot')),
            );
            expect(response.status).toBe(error._tag === 'CloudflareError' ? 502 : 503);
            const body = yield* Effect.promise(() => response.text());
            expect(body).not.toContain('secret-test-token');
          }),
        error,
        lines,
      );
    }
    expect(JSON.stringify(lines)).toContain('Console snapshot failed');
    expect(JSON.stringify(lines)).not.toContain('secret-test-token');
  }),
);

it.effect('maps asset binding failures to a typed AssetError', () =>
  Effect.gen(function* () {
    const assets = yield* AssetFiles;
    const result = yield* assets.script.pipe(Effect.result);
    expect(result._tag).toBe('Failure');
    if (result._tag === 'Failure') expect(result.failure._tag).toBe('AssetError');
  }).pipe(
    Effect.provide(
      AssetFiles.layer({ fetch: () => Promise.reject(new Error('Asset binding failed')) }),
    ),
  ),
);

it.effect('sets security and cache headers on authentication and body-limit denials', () =>
  Effect.gen(function* () {
    for (const authorized of [false, true]) {
      yield* withApp(authorized, (handler) =>
        Effect.gen(function* () {
          const response = yield* Effect.promise(() =>
            handler(
              new Request('https://console.example/api/preview', {
                method: 'POST',
                headers: {
                  origin: 'https://console.example',
                  host: 'console.example',
                  'Content-Length': '262145',
                },
                body: '{}',
              }),
            ),
          );
          expect(response.status).toBe(authorized ? 413 : 403);
          expect(response.headers.get('Cache-Control')).toBe('private, no-store');
          expect(response.headers.get('Content-Security-Policy')).toContain(
            "frame-ancestors 'none'",
          );
          expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
        }),
      );
    }
  }),
);
