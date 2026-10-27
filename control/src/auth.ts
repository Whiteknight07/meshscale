import { Context, Effect, Layer, Schema } from 'effect';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { Unauthorized } from './errors.ts';
import { Settings } from './config.ts';

const Claims = Schema.Struct({
  email: Schema.String,
  sub: Schema.String,
  exp: Schema.Number,
  iat: Schema.Number,
});
export interface AccessVerifier {
  readonly verify: (
    assertion: string | undefined,
  ) => Effect.Effect<typeof Claims.Type, Unauthorized>;
}
export class Access extends Context.Service<Access, AccessVerifier>()('meshscale/Access') {
  static readonly make = (
    domain: string,
    audience: string,
    owner: string,
    key?: JWTVerifyGetKey,
  ): AccessVerifier => {
    const issuer = `https://${domain}`;
    const keys =
      key ??
      createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), {
        timeoutDuration: 5000,
        cacheMaxAge: 600000,
      });
    return {
      verify: Effect.fn('Access.verify')(function* (assertion) {
        if (
          !assertion ||
          assertion.length > 16384 ||
          !audience ||
          !owner.trim() ||
          !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(domain)
        )
          return yield* new Unauthorized({ message: 'Cloudflare Access authentication required' });
        const result = yield* Effect.tryPromise({
          try: () =>
            jwtVerify(assertion, keys, {
              issuer,
              audience,
              algorithms: ['RS256'],
              requiredClaims: ['exp', 'iat', 'sub', 'email'],
              clockTolerance: 5,
              maxTokenAge: '12 hours',
            }),
          catch: () => new Unauthorized({ message: 'Invalid Cloudflare Access assertion' }),
        });
        const claims = yield* Schema.decodeUnknownEffect(Claims)(result.payload).pipe(
          Effect.mapError(() => new Unauthorized({ message: 'Invalid Access identity claims' })),
        );
        if (!claims.sub.trim() || claims.email.toLowerCase() !== owner.toLowerCase())
          return yield* new Unauthorized({
            message: 'Only the account owner can open this console',
          });
        return claims;
      }),
    };
  };

  static readonly layer = Layer.effect(Access)(
    Effect.gen(function* () {
      const settings = yield* Settings;
      return Access.make(settings.teamDomain, settings.audience, settings.ownerEmail);
    }),
  );
}
