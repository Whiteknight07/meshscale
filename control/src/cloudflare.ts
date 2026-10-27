import {
  Context,
  Duration,
  Effect,
  Layer,
  Option,
  Redacted,
  Schedule,
  Schema,
  Stream,
} from 'effect';
import { CloudflareError } from './errors.ts';
import { Settings } from './config.ts';

const Envelope = Schema.Struct({
  success: Schema.Boolean,
  result: Schema.optional(Schema.Unknown),
  errors: Schema.optional(Schema.Array(Schema.Unknown)),
  result_info: Schema.optional(
    Schema.Struct({
      cursor: Schema.optional(Schema.NullOr(Schema.String)),
      page: Schema.optional(Schema.NullOr(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)))),
      per_page: Schema.optional(Schema.NullOr(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0)))),
      total_count: Schema.optional(
        Schema.NullOr(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0))),
      ),
      total_pages: Schema.optional(
        Schema.NullOr(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0))),
      ),
    }),
  ),
});
const backoff: Schedule.Schedule<Duration.Duration, CloudflareError> = Schedule.exponential(
  '250 millis',
).pipe(Schedule.jittered);
const getRetry = backoff.pipe(
  Schedule.modifyDelay(({ duration, input }) =>
    Effect.succeed(Math.max(Duration.toMillis(duration), input.retryAfterMs ?? 0)),
  ),
);
const retryAfter = (value: string | null, now: number) => {
  if (!value) return 0;
  const ms = /^\d+(?:\.\d+)?$/.test(value) ? Number(value) * 1000 : Date.parse(value) - now;
  return Number.isFinite(ms) ? Math.max(0, ms) : 0;
};
export interface CloudflareClient {
  readonly request: <S extends Schema.Constraint>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    schema: S,
    body?: unknown,
  ) => Effect.Effect<S['Type'], CloudflareError, S['DecodingServices']>;
  readonly list: <S extends Schema.Constraint>(
    path: string,
    schema: S,
    pagination?: 'cursor' | 'page' | 'none',
  ) => Effect.Effect<readonly S['Type'][], CloudflareError, S['DecodingServices']>;
}
export class Cloudflare extends Context.Service<Cloudflare, CloudflareClient>()(
  'meshscale/Cloudflare',
) {
  static readonly layer = Layer.effect(Cloudflare)(
    Effect.gen(function* () {
      const settings = yield* Settings;
      const call = Effect.fn('Cloudflare.request')(function* (
        method: string,
        path: string,
        body?: unknown,
      ) {
        const operation = `${method} ${path.split('?')[0] ?? path}`;
        const send = Effect.gen(function* () {
          const response = yield* Effect.tryPromise({
            try: (signal) =>
              fetch(`https://api.cloudflare.com/client/v4/accounts/${settings.accountId}${path}`, {
                method,
                signal,
                redirect: 'error',
                headers: {
                  Authorization: `Bearer ${Redacted.value(settings.token)}`,
                  'Content-Type': 'application/json',
                },
                ...(body === undefined ? {} : { body: JSON.stringify(body) }),
              }),
            catch: (cause) =>
              new CloudflareError({
                operation,
                status: 0,
                message: 'Cloudflare request failed',
                cause,
              }),
          }).pipe(Effect.timeoutOption('15 seconds'));
          if (response._tag === 'None')
            return yield* new CloudflareError({
              operation,
              status: 504,
              message: 'Cloudflare request timed out',
            });
          const res = response.value;
          if (!res.ok) {
            const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
            // Release the failed response before retrying; do not log its body or headers.
            yield* Effect.promise(
              () => res.body?.cancel().catch(() => undefined) ?? Promise.resolve(),
            );
            return yield* new CloudflareError({
              operation,
              status: res.status,
              message: 'Cloudflare rejected the operation; check token permissions',
              retryAfterMs: retryAfter(res.headers.get('Retry-After'), now),
            });
          }
          return res;
        });
        const res = yield* method === 'GET'
          ? send.pipe(
              Effect.retry({
                schedule: getRetry,
                times: 3,
                while: (e) =>
                  (e.retryAfterMs ?? 0) <= 60000 &&
                  (e.status === 429 || (e.status >= 500 && e.status <= 599)),
              }),
            )
          : send;
        const json = yield* Effect.tryPromise({
          try: (signal) => readJson(res, signal),
          catch: (cause) =>
            new CloudflareError({
              operation,
              status: 502,
              message: 'Cloudflare returned invalid JSON',
              cause,
            }),
        }).pipe(Effect.timeoutOption('15 seconds'));
        if (json._tag === 'None')
          return yield* new CloudflareError({
            operation,
            status: 504,
            message: 'Cloudflare response body timed out',
          });
        const envelope = yield* Schema.decodeUnknownEffect(Envelope)(json.value).pipe(
          Effect.mapError(
            (cause) =>
              new CloudflareError({
                operation,
                status: 502,
                message: 'Cloudflare response envelope is invalid',
                cause,
              }),
          ),
        );
        if (!envelope.success || (envelope.errors?.length ?? 0) > 0)
          return yield* new CloudflareError({
            operation,
            status: 502,
            message: 'Cloudflare operation failed',
          });
        return envelope;
      });
      // Log only known-safe metadata. A transport exception may contain credentials.
      const trace = <A, R>(effect: Effect.Effect<A, CloudflareError, R>) =>
        effect.pipe(
          Effect.tapError((error) =>
            Effect.logError('Cloudflare operation failed', {
              operation: error.operation,
              status: error.status,
            }),
          ),
        );
      return {
        request: (method, path, schema, body) =>
          trace(
            call(method, path, body).pipe(
              Effect.flatMap((result) =>
                Schema.decodeUnknownEffect(schema)(result.result).pipe(
                  Effect.mapError(
                    (cause) =>
                      new CloudflareError({
                        operation: `${method} ${path.split('?')[0] ?? path}`,
                        status: 502,
                        message: 'Cloudflare payload does not match its schema',
                        cause,
                      }),
                  ),
                ),
              ),
            ),
          ),
        list: (path, schema, pagination = 'none') =>
          trace(
            Stream.paginate({ cursor: '', page: 1, count: 0, seen: new Set<string>() }, (state) =>
              Effect.gen(function* () {
                const query =
                  pagination === 'cursor'
                    ? `?per_page=100${state.cursor ? `&cursor=${encodeURIComponent(state.cursor)}` : ''}`
                    : pagination === 'page'
                      ? `?per_page=100&page=${state.page}`
                      : '';
                const result = yield* call('GET', path + query);
                const values = yield* Schema.decodeUnknownEffect(Schema.Array(schema))(
                  result.result,
                ).pipe(
                  Effect.mapError(
                    (cause) =>
                      new CloudflareError({
                        operation: `GET ${path}`,
                        status: 502,
                        message: 'Cloudflare collection does not match its schema',
                        cause,
                      }),
                  ),
                );
                const info = result.result_info;
                const cursor = info?.cursor ?? '';
                const count = state.count + values.length;
                const invalid = () =>
                  new CloudflareError({
                    operation: `GET ${path}`,
                    status: 502,
                    message: 'Cloudflare pagination is incomplete or inconsistent',
                  });
                if (pagination === 'page' && info?.page && info.page !== state.page)
                  return yield* invalid();
                const morePages =
                  info?.total_count != null
                    ? count < info.total_count
                    : info?.total_pages != null
                      ? state.page < info.total_pages
                      : values.length >= (info?.per_page || 100);
                if (pagination === 'page' && morePages && values.length === 0)
                  return yield* invalid();
                if (pagination === 'page' && !info && values.length >= 100) return yield* invalid();
                if (
                  pagination === 'none' ||
                  (pagination === 'cursor' && !cursor) ||
                  (pagination === 'page' && !morePages)
                )
                  return [values, Option.none()] as const;
                if (state.page >= 1000 || (pagination === 'cursor' && state.seen.has(cursor)))
                  return yield* new CloudflareError({
                    operation: `GET ${path}`,
                    status: 502,
                    message: 'Cloudflare pagination did not terminate',
                  });
                return [
                  values,
                  Option.some({
                    cursor,
                    page: state.page + 1,
                    count,
                    seen: new Set([...state.seen, cursor]),
                  }),
                ] as const;
              }),
            ).pipe(Stream.runCollect),
          ),
      } satisfies CloudflareClient;
    }),
  );
}

// Bound bytes as well as time; cancel the stream on interruption instead of
// letting a stalled or oversized API body retain an isolate indefinitely.
async function readJson(response: Response, signal: AbortSignal): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Missing response body');
  const abort = () => {
    void reader.cancel().catch(() => undefined);
  };
  signal.addEventListener('abort', abort, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    signal.throwIfAborted();
    for (let next = await reader.read(); !next.done; next = await reader.read()) {
      signal.throwIfAborted();
      size += next.value.byteLength;
      if (size > 16 * 1024 * 1024) throw new Error('Response exceeds 16 MiB');
      chunks.push(next.value);
    }
    signal.throwIfAborted();
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } finally {
    signal.removeEventListener('abort', abort);
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
