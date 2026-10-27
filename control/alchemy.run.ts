import * as Alchemy from 'alchemy';
import * as Cloudflare from '@alchemy.run/cloudflare';
import { Config, Effect } from 'effect';

// Native Alchemy Access resources carry ownership and lifecycle state. This
// stack never adopts the account's enrollment application or unrelated rules.
export const Worker = Cloudflare.Worker(
  'Console',
  Effect.gen(function* () {
    const stack = yield* Alchemy.Stack;
    const owner = yield* Config.String('MESHSCALE_OWNER_EMAIL');
    const application = yield* Cloudflare.Access.Application('OwnerAccess', {
      type: 'self_hosted',
      name: `meshscale console (${stack.stage})`,
      sessionDuration: '12h',
      httpOnlyCookieAttribute: true,
      allowedIdps: [yield* Config.String('MESHSCALE_OWNER_IDP_ID')],
      autoRedirectToIdentity: true,
      sameSiteCookieAttribute: 'strict',
      enableBindingCookie: true,
      policies: [
        {
          name: 'meshscale console owner only',
          decision: 'allow',
          include: [{ email: owner }],
          exclude: [],
          require: [],
        },
      ],
    });
    const cache = yield* Cloudflare.KV.Namespace('ConsoleCache');
    return {
      name: stack.stage === 'dev' ? 'meshscale-console' : `meshscale-console-${stack.stage}`,
      main: './src/worker.ts',
      compatibility: { date: '2026-10-26', flags: ['nodejs_compat'] },
      workersDev: { enabled: true, previewsEnabled: false },
      access: application,
      assets: { directory: './public', runWorkerFirst: true },
      observability: {
        logs: { enabled: true, invocationLogs: false },
        traces: { enabled: true, headSamplingRate: 0.1 },
      },
      env: {
        CACHE: cache,
        ACCOUNT_ID: Config.String('CLOUDFLARE_ACCOUNT_ID'),
        API_TOKEN: Config.Redacted('MESHSCALE_CONSOLE_API_TOKEN'),
        TEAM_DOMAIN: Config.String('MESHSCALE_TEAM_DOMAIN'),
        OWNER_EMAIL: owner,
        ACCESS_AUD: application.aud,
      },
    };
  }),
);
export type WorkerEnv = Cloudflare.InferEnv<typeof Worker>;

// Public project page. It is the verified client URL for "Sign in with
// Cloudflare", so its hostname must never change once verified.
export const Site = Cloudflare.Worker('Site', {
  name: 'meshscale-site',
  compatibility: { date: '2026-10-26' },
  domain: 'meshscale.stavan.ai',
  workersDev: { enabled: false },
  assets: {
    directory: './site',
    htmlHandling: 'auto-trailing-slash',
    notFoundHandling: '404-page',
  },
});
export default Alchemy.Stack(
  'meshscale-console',
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const worker = yield* Worker;
    const site = yield* Site;
    return { url: worker.url, name: worker.workerName, site: site.url };
  }),
);
