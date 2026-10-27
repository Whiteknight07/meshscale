import { afterEach, expect, it, vi } from '@effect/vitest';
import { Effect, Fiber, Layer, Redacted, Schema } from 'effect';
import { TestClock, TestConsole } from 'effect/testing';
import { Cloudflare } from '../src/cloudflare.ts';
import { Settings } from '../src/config.ts';
import { CloudflareError } from '../src/errors.ts';

const settings = Layer.succeed(Settings)({
  accountId: 'account',
  token: Redacted.make('test-token'),
  teamDomain: 'team.cloudflareaccess.com',
  audience: 'audience',
  ownerEmail: 'owner@example.com',
});
const layer = Cloudflare.layer.pipe(Layer.provide(settings));
const ok = (result: unknown, result_info?: unknown) =>
  Response.json({ success: true, result, result_info });
afterEach(() => vi.unstubAllGlobals());

it.effect('paginates cursor and page collections with Stream', () =>
  Effect.gen(function* () {
    const urls: string[] = [];
    vi.stubGlobal('fetch', (url: string) => {
      urls.push(url);
      const second = url.includes('cursor=next') || url.includes('page=2');
      return Promise.resolve(
        ok([second ? 'b' : 'a'], { cursor: second ? null : 'next', total_pages: 2 }),
      );
    });
    const api = yield* Cloudflare;
    for (const pagination of ['cursor', 'page'] as const)
      expect(yield* api.list('/items', Schema.String, pagination)).toEqual(['a', 'b']);
    expect(urls).toHaveLength(4);
    expect(urls[1]).toContain('&cursor=next');
    expect(urls[3]).toContain('&page=2');
  }).pipe(Effect.provide(layer)),
);
it.effect('rejects repeated cursors instead of looping forever', () =>
  Effect.gen(function* () {
    let calls = 0;
    vi.stubGlobal('fetch', () => {
      calls++;
      return Promise.resolve(ok([], { cursor: 'repeat' }));
    });
    const api = yield* Cloudflare;
    const result = yield* api.list('/items', Schema.String, 'cursor').pipe(Effect.result);
    expect(result._tag).toBe('Failure');
    expect(calls).toBe(2);
  }).pipe(Effect.provide(layer)),
);
it.effect('retries GET 429 and 5xx with backoff and numeric Retry-After', () =>
  Effect.gen(function* () {
    const times: number[] = [];
    vi.stubGlobal('fetch', () => {
      const status = times.length === 0 ? 429 : times.length === 1 ? 503 : 200;
      times.push(0);
      return Promise.resolve(
        status === 200
          ? ok('done')
          : new Response(null, { status, headers: { 'Retry-After': status === 429 ? '2' : '0' } }),
      );
    });
    const api = yield* Cloudflare;
    const fiber = yield* api.request('GET', '/items', Schema.String).pipe(Effect.forkChild);
    yield* TestClock.adjust('1999 millis');
    expect(times).toHaveLength(1);
    yield* TestClock.adjust('1 millis');
    expect(times).toHaveLength(2);
    // The second exponential delay is jittered into [400ms, 600ms].
    yield* TestClock.adjust('399 millis');
    expect(times).toHaveLength(2);
    yield* TestClock.adjust('201 millis');
    expect(yield* Fiber.join(fiber)).toBe('done');
    expect(times).toHaveLength(3);
  }).pipe(Effect.provide(layer)),
);
it.effect('honors HTTP-date Retry-After and bounds retries', () =>
  Effect.gen(function* () {
    let calls = 0;
    vi.stubGlobal('fetch', () => {
      calls++;
      return Promise.resolve(
        new Response(null, {
          status: 503,
          headers: { 'Retry-After': 'Thu, 01 Jan 1970 00:00:03 GMT' },
        }),
      );
    });
    const api = yield* Cloudflare;
    const fiber = yield* api
      .request('GET', '/items', Schema.Unknown)
      .pipe(Effect.result, Effect.forkChild);
    yield* TestClock.adjust('2999 millis');
    expect(calls).toBe(1);
    yield* TestClock.adjust('5001 millis');
    const result = yield* Fiber.join(fiber);
    expect(result._tag).toBe('Failure');
    expect(calls).toBe(4);
  }).pipe(Effect.provide(layer)),
);
it.effect('does not retry mutations or non-transient GET failures', () =>
  Effect.gen(function* () {
    const api = yield* Cloudflare;
    for (const [method, status] of [
      ['POST', 429],
      ['PUT', 503],
      ['PATCH', 500],
      ['DELETE', 503],
      ['GET', 403],
    ] as const) {
      let calls = 0;
      vi.stubGlobal('fetch', () => {
        calls++;
        return Promise.resolve(new Response(null, { status }));
      });
      expect((yield* api.request(method, '/items', Schema.Unknown).pipe(Effect.result))._tag).toBe(
        'Failure',
      );
      expect(calls).toBe(1);
    }
  }).pipe(Effect.provide(layer)),
);
it.effect('retains transport causes while excluding them from API responses and logs', () =>
  Effect.gen(function* () {
    const secretCause = new Error('Bearer test-token-private');
    vi.stubGlobal('fetch', () => Promise.reject(secretCause));
    const api = yield* Cloudflare;
    const result = yield* api.request('GET', '/items', Schema.Unknown).pipe(Effect.result);
    expect(result._tag).toBe('Failure');
    if (result._tag === 'Failure') {
      expect(result.failure.cause).toBe(secretCause);
      const encoded = yield* Schema.encodeEffect(CloudflareError)(result.failure);
      expect(encoded).toEqual({
        _tag: 'CloudflareError',
        operation: 'GET /items',
        status: 0,
        message: 'Cloudflare request failed',
      });
      expect(JSON.stringify(encoded)).not.toContain('test-token-private');
    }
    const lines = yield* TestConsole.logLines;
    expect(JSON.stringify(lines)).toContain('Cloudflare operation failed');
    expect(JSON.stringify(lines)).not.toContain('test-token');
  }).pipe(Effect.provide(layer)),
);

it.effect('does not silently accept incomplete or mismatched page inventories', () =>
  Effect.gen(function* () {
    const api = yield* Cloudflare;
    for (const info of [
      { page: 1, total_pages: 2 },
      { page: 9, total_pages: 1 },
      { total_count: 1 },
      { total_pages: -1 },
    ]) {
      vi.stubGlobal('fetch', () => Promise.resolve(ok([], info)));
      expect((yield* api.list('/items', Schema.String, 'page').pipe(Effect.result))._tag).toBe(
        'Failure',
      );
    }
  }).pipe(Effect.provide(layer)),
);

it.effect('bounds response-body time and cancels a stalled body', () =>
  Effect.gen(function* () {
    let cancelled = false;
    vi.stubGlobal('fetch', () =>
      Promise.resolve(
        new Response(
          new ReadableStream({
            cancel() {
              cancelled = true;
            },
          }),
        ),
      ),
    );
    const api = yield* Cloudflare;
    const fiber = yield* api
      .request('POST', '/items', Schema.Unknown)
      .pipe(Effect.result, Effect.forkChild);
    yield* TestClock.adjust('16 seconds');
    const result = yield* Fiber.join(fiber);
    expect(result._tag).toBe('Failure');
    expect(cancelled).toBe(true);
  }).pipe(Effect.provide(layer)),
);

it.effect('rejects contradictory success/error envelopes and oversized response streams', () =>
  Effect.gen(function* () {
    const api = yield* Cloudflare;
    let cancelled = false;
    for (const response of [
      Response.json({ success: true, errors: [{ message: 'test-token' }], result: [] }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(16 * 1024 * 1024 + 1));
          },
          cancel() {
            cancelled = true;
          },
        }),
      ),
    ]) {
      vi.stubGlobal('fetch', () => Promise.resolve(response));
      expect((yield* api.request('POST', '/items', Schema.Unknown).pipe(Effect.result))._tag).toBe(
        'Failure',
      );
    }
    expect(cancelled).toBe(true);
  }).pipe(Effect.provide(layer)),
);
it.effect('accepts nullable cursor totals and paginates page collections without total_pages', () =>
  Effect.gen(function* () {
    const api = yield* Cloudflare;
    vi.stubGlobal('fetch', () =>
      Promise.resolve(ok(['cursor-item'], { cursor: null, total_count: null, total_pages: null })),
    );
    expect(yield* api.list('/items', Schema.String, 'cursor')).toEqual(['cursor-item']);
    let calls = 0;
    vi.stubGlobal('fetch', () => {
      calls++;
      return Promise.resolve(ok([calls], { page: calls, per_page: 1, total_count: 2 }));
    });
    expect(yield* api.list('/items', Schema.Number, 'page')).toEqual([1, 2]);
  }).pipe(Effect.provide(layer)),
);
it.effect('returns rate limits with excessive Retry-After without waiting or retrying early', () =>
  Effect.gen(function* () {
    let calls = 0;
    vi.stubGlobal('fetch', () => {
      calls++;
      return Promise.resolve(
        new Response(null, { status: 429, headers: { 'Retry-After': '999999999' } }),
      );
    });
    const api = yield* Cloudflare;
    expect((yield* api.request('GET', '/items', Schema.Unknown).pipe(Effect.result))._tag).toBe(
      'Failure',
    );
    expect(calls).toBe(1);
  }).pipe(Effect.provide(layer)),
);
