import { Context, Data, Effect, Layer, Stream, type Types } from 'effect';
import { HttpRouter, HttpServer, HttpServerRequest, HttpServerResponse } from 'effect/http';
import { HttpApiBuilder } from 'effect/http-api';
import { ConsoleApi } from './api.ts';
import { Console } from './console.ts';
import { Access } from './auth.ts';
import { css, shell } from './ui.ts';
import { AssetError, Unauthorized } from './errors.ts';

export const securityHeaders = {
  'Cache-Control': 'private, no-store',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
} as const;
const handlers = HttpApiBuilder.group(
  ConsoleApi,
  'console',
  Effect.fn(function* (h) {
    const console = yield* Console;
    return h
      .handle('snapshot', () =>
        console.snapshot().pipe(Effect.tapCause(() => Effect.logError('Console snapshot failed'))),
      )
      .handle('policy', () =>
        console.policy.pipe(Effect.tapCause(() => Effect.logError('Console policy read failed'))),
      )
      .handle('preview', ({ payload }) =>
        console
          .preview(payload)
          .pipe(Effect.tapCause(() => Effect.logError('Console preview failed'))),
      )
      .handle('apply', ({ payload }) =>
        console
          .apply(payload.action, payload.fingerprint, payload.confirm)
          .pipe(Effect.tapCause(() => Effect.logError('Console apply failed'))),
      );
  }),
);
export class AssetFiles extends Context.Service<
  AssetFiles,
  { readonly script: Effect.Effect<HttpServerResponse.HttpServerResponse, AssetError> }
>()('meshscale/Assets') {
  static layer = (assets: { fetch: (request: Request) => Promise<Response> }) =>
    Layer.succeed(AssetFiles)({
      script: Effect.tryPromise({
        try: () => assets.fetch(new Request('https://assets.local/console.js')),
        catch: () => new AssetError({ message: 'Script unavailable' }),
      }).pipe(Effect.map(HttpServerResponse.fromWeb)),
    });
}
const pages = Layer.mergeAll(
  Layer.unwrap(
    Effect.gen(function* () {
      const assets = yield* AssetFiles;
      return HttpRouter.add(
        'GET',
        '/console.js',
        assets.script.pipe(
          Effect.tapCause(() => Effect.logError('Asset fetch failed')),
          Effect.catchTag('AssetError', () =>
            Effect.succeed(HttpServerResponse.text('Script unavailable', { status: 503 })),
          ),
        ),
      );
    }),
  ),
  HttpRouter.add('GET', '/', HttpServerResponse.html(shell)),
  HttpRouter.add(
    'GET',
    '/console.css',
    HttpServerResponse.text(css, { contentType: 'text/css; charset=utf-8' }),
  ),
);
class BodyTooLarge extends Data.TaggedError('BodyTooLarge') {}
const bodyLimit = 256 * 1024;
const boundedRequest = (request: HttpServerRequest.HttpServerRequest) =>
  request.stream.pipe(
    Stream.runFoldEffect(
      () => ({ size: 0, chunks: [] as Uint8Array[] }),
      (state, chunk) => {
        if (state.size + chunk.byteLength > bodyLimit) return Effect.fail(new BodyTooLarge());
        state.chunks.push(chunk);
        state.size += chunk.byteLength;
        return Effect.succeed(state);
      },
    ),
    Effect.map(({ chunks, size }) => {
      const body = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return HttpServerRequest.fromWeb(
        new Request(
          new URL(request.originalUrl, `https://${request.headers.host ?? 'localhost'}`),
          {
            method: request.method,
            headers: request.headers,
            body,
          },
        ),
      );
    }),
  );
const forbidden = (request: HttpServerRequest.HttpServerRequest, error: Unauthorized) =>
  request.url.startsWith('/api/')
    ? HttpServerResponse.schemaJson(Unauthorized)(error, { status: 403 })
    : Effect.succeed(HttpServerResponse.text(error.message, { status: 403 }));
const guard = HttpRouter.middleware(
  Effect.gen(function* () {
    const auth = yield* Access;
    return (next: Effect.Effect<HttpServerResponse.HttpServerResponse, Types.unhandled>) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const result = yield* auth
          .verify(request.headers['cf-access-jwt-assertion'])
          .pipe(Effect.result);
        if (result._tag === 'Failure') return yield* forbidden(request, result.failure);
        let activeRequest = request;
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          const origin = request.headers.origin;
          const host = request.headers.host;
          if (
            !origin ||
            origin !== `https://${host ?? ''}` ||
            request.headers['sec-fetch-site'] === 'cross-site'
          )
            return yield* forbidden(
              request,
              new Unauthorized({ message: 'Same-origin browser request required' }),
            );
          const length = Number(request.headers['content-length'] ?? '0');
          if (length > bodyLimit)
            return HttpServerResponse.text('Request body too large', { status: 413 });
          const body = yield* boundedRequest(request).pipe(Effect.result);
          if (body._tag === 'Failure')
            return HttpServerResponse.text(
              body.failure._tag === 'BodyTooLarge'
                ? 'Request body too large'
                : 'Cannot read request body',
              { status: body.failure._tag === 'BodyTooLarge' ? 413 : 400 },
            );
          activeRequest = body.success;
        }
        return yield* next.pipe(
          Effect.provideService(HttpServerRequest.HttpServerRequest, activeRequest),
        );
      }).pipe(Effect.map(HttpServerResponse.setHeaders(securityHeaders)));
  }),
);
export const Routes = Layer.mergeAll(
  HttpApiBuilder.layer(ConsoleApi, { openapiPath: '/api/openapi.json' }).pipe(
    Layer.provide(handlers),
  ),
  pages,
).pipe(Layer.provide(guard.layer), Layer.provide(HttpServer.layerServices));
