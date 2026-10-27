import { expect, it } from '@effect/vitest';
import { Effect } from 'effect';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Access } from '../src/auth.ts';

it.effect('rejects missing and forged Access assertions without a network call', () =>
  Effect.gen(function* () {
    const verifier = Access.make(
      'team.cloudflareaccess.com',
      'audience',
      'owner@example.com',
      () => {
        throw new Error('A forged algorithm must not request keys');
      },
    );
    const forged = `${btoa(JSON.stringify({ alg: 'none' }))}.${btoa(JSON.stringify({ aud: ['audience'], email: 'owner@example.com' }))}.`;
    for (const assertion of [undefined, 'forged', forged])
      expect((yield* verifier.verify(assertion).pipe(Effect.result))._tag).toBe('Failure');
  }),
);
it.effect('checks signature, issuer, audience, expiration and owner email', () =>
  Effect.gen(function* () {
    const fixture = yield* Effect.tryPromise(async () => {
      const pair = await generateKeyPair('RS256');
      const jwk = await exportJWK(pair.publicKey);
      return { pair, keys: createLocalJWKSet({ keys: [{ ...jwk, kid: 'test' }] }) };
    });
    const verify = Access.make(
      'team.cloudflareaccess.com',
      'audience',
      'owner@example.com',
      fixture.keys,
    ).verify;
    for (const [email, audience, issuer, expiration, valid] of [
      ['owner@example.com', 'audience', 'https://team.cloudflareaccess.com', '1h', true],
      ['other@example.com', 'audience', 'https://team.cloudflareaccess.com', '1h', false],
      ['owner@example.com', 'wrong', 'https://team.cloudflareaccess.com', '1h', false],
      ['owner@example.com', 'audience', 'https://evil.cloudflareaccess.com', '1h', false],
      ['owner@example.com', 'audience', 'https://team.cloudflareaccess.com', '-1h', false],
    ] as const) {
      const token = yield* Effect.tryPromise(() =>
        new SignJWT({ email })
          .setProtectedHeader({ alg: 'RS256', kid: 'test' })
          .setIssuer(issuer)
          .setAudience(audience)
          .setSubject('owner')
          .setIssuedAt()
          .setExpirationTime(expiration)
          .sign(fixture.pair.privateKey),
      );
      expect((yield* verify(token).pipe(Effect.result))._tag).toBe(valid ? 'Success' : 'Failure');
    }
  }),
);

it.effect('rejects future-issued, stale and empty-subject assertions', () =>
  Effect.gen(function* () {
    const pair = yield* Effect.tryPromise(() => generateKeyPair('RS256'));
    const jwk = yield* Effect.tryPromise(() => exportJWK(pair.publicKey));
    const keys = createLocalJWKSet({ keys: [{ ...jwk, kid: 'test' }] });
    const verify = Access.make(
      'team.cloudflareaccess.com',
      'audience',
      'owner@example.com',
      keys,
    ).verify;
    const now = Math.floor(Date.now() / 1000);
    for (const [sub, iat] of [
      ['owner', now + 60],
      ['owner', now - 13 * 3600],
      ['', now],
    ] as const) {
      const token = yield* Effect.tryPromise(() =>
        new SignJWT({ email: 'owner@example.com' })
          .setProtectedHeader({ alg: 'RS256', kid: 'test' })
          .setIssuer('https://team.cloudflareaccess.com')
          .setAudience('audience')
          .setSubject(sub)
          .setIssuedAt(iat)
          .setExpirationTime(now + 3600)
          .sign(pair.privateKey),
      );
      expect((yield* verify(token).pipe(Effect.result))._tag).toBe('Failure');
    }
  }),
);
