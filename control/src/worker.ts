import { ConfigProvider, Layer } from 'effect';
import { HttpRouter } from 'effect/http';
import type { WorkerEnv } from '../alchemy.run.ts';
import { Settings } from './config.ts';
import { Cloudflare } from './cloudflare.ts';
import { Access } from './auth.ts';
import { Storage } from './storage.ts';
import { Inventory } from './inventory.ts';
import { Console } from './console.ts';
import { AssetFiles, Routes, securityHeaders } from './http.ts';

export const makeApp = (env: WorkerEnv) => {
  const settings = Settings.layer.pipe(
    Layer.provide(ConfigProvider.layer(ConfigProvider.fromUnknown(env))),
  );
  const base = Layer.mergeAll(settings, Storage.layer(env.CACHE), AssetFiles.layer(env.ASSETS));
  const services = Layer.mergeAll(Cloudflare.layer, Access.layer).pipe(Layer.provideMerge(base));
  const inventory = Inventory.layer.pipe(Layer.provideMerge(services));
  const console = Console.layer.pipe(Layer.provideMerge(inventory));
  return HttpRouter.toWebHandler(Routes.pipe(Layer.provide(console)), { disableLogger: true });
};
// Only the service graph is shared across requests; authenticated identity and
// request data stay in the Effect request scope. Alchemy infers all bindings.
let app: ReturnType<typeof makeApp> | undefined;
export default {
  fetch(request: Request, env: WorkerEnv): Promise<Response> {
    app ??= makeApp(env);
    return app.handler(request).catch(() => {
      globalThis.console.error('Console request failed');
      return new Response('Console unavailable', {
        status: 503,
        headers: securityHeaders,
      });
    });
  },
};
