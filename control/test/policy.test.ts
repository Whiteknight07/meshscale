import { describe, it, expect } from '@effect/vitest';
import { Effect } from 'effect';
import { compilePolicy, meshPrefix, parsePolicy } from '../src/policy.ts';
import { canonicalExpression, networkDiff } from '../src/diff.ts';
import { machine, rule } from './fixtures.ts';

const invalid = [
  'null',
  '{}',
  '{"rules":null}',
  '{"rules":[],"extra":1}',
  '{"rules":[]} {}',
  '{"rules":[{"from":[],"to":["*:22"]}]}',
  '{"groups":{"bad:name":["*"]},"rules":[]}',
  '{"groups":{"empty":[]},"rules":[]}',
  '{"groups":{"a":["group:b"],"b":["group:a"]},"rules":[]}',
  '{"groups":{"unused":["group:missing"]},"rules":[]}',
  ...[
    '*:0',
    '*:65536',
    '*:022',
    '*:2-1',
    '*:1,,2',
    '*:1-2-3',
    '2606:4700:cf1:1000::2:22',
    '[::ffff:100.96.0.2]:22',
    '1.1.1.1:22',
    'group:missing:22',
    ' *:22',
    'bad/name:22',
  ].map((to) => JSON.stringify({ rules: [{ from: ['*'], to: [to] }] })),
];
describe('Go-compatible policy validation', () => {
  it.effect.each(invalid)('rejects %s', (json) =>
    Effect.gen(function* () {
      expect((yield* parsePolicy(json).pipe(Effect.result))._tag).toBe('Failure');
    }),
  );
  it.effect('keeps destination/port associations and emits Mesh deny', () =>
    Effect.gen(function* () {
      const policy = yield* parsePolicy(
        '{"groups":{"admins":["owner@example.com"]},"rules":[{"from":["admins"],"to":["laptop:22","[2606:4700:cf1:1000::2]:80,443-445"]}]}',
      );
      const rules = yield* compilePolicy(policy, [machine()]);
      expect(rules[0]?.traffic).toBe(
        'net.src.internal_src_ip in {100.96.0.2/32} and ((net.dst.ip in {100.96.0.2/32} and net.dst.port == 22) or (net.dst.ip in {2606:4700:cf1:1000::2/128} and (net.dst.port == 80 or (net.dst.port >= 443 and net.dst.port <= 445))))',
      );
      expect(rules.at(-1)?.action).toBe('block');
    }),
  );
  it.effect('denies all for an explicit empty policy', () =>
    Effect.gen(function* () {
      const rules = yield* compilePolicy(yield* parsePolicy('{"rules":[]}'), []);
      expect(rules).toHaveLength(1);
      expect(rules[0]?.name).toBe('meshscale rule: default-deny');
    }),
  );
  it.effect('rejects unresolved or ambiguous machine names', () =>
    Effect.gen(function* () {
      const p = yield* parsePolicy('{"rules":[{"from":["laptop"],"to":["*:22"]}]}');
      for (const machines of [
        [],
        [machine(), machine({ id: 'r2', ipv4: '100.96.0.3' })],
        [machine({ ipv4: '' })],
      ])
        expect((yield* compilePolicy(p, machines).pipe(Effect.result))._tag).toBe('Failure');
    }),
  );
  it.effect('preserves the Go secure UDP carrier before the default deny', () =>
    Effect.gen(function* () {
      const rules = yield* compilePolicy(yield* parsePolicy('{"rules":[]}'), [
        machine({ secure: true }),
        machine({ id: 'r2', secure: true, ipv4: '100.96.0.3' }),
      ]);
      expect(rules[0]?.traffic).toBe(
        'net.src.internal_src_ip in {100.96.0.2/32 100.96.0.3/32} and net.dst.ip in {100.96.0.2/32 100.96.0.3/32} and net.ip.proto == 17 and net.dst.port == 51821',
      );
    }),
  );
  it('masks Mesh prefixes and rejects external and mapped ranges', () => {
    expect(meshPrefix('100.96.0.9/24')).toBe('100.96.0.0/24');
    expect(meshPrefix('100.95.0.2')).toBeUndefined();
    expect(meshPrefix('::ffff:100.96.0.2')).toBeUndefined();
    expect(meshPrefix('100.96.0.2/8')).toBeUndefined();
  });
});
describe('owned network reconciliation', () => {
  it('normalizes Gateway host prefixes and redundant parentheses', () => {
    expect(canonicalExpression('(net.dst.ip in {100.96.0.2/32}) and ((net.dst.port == 22))')).toBe(
      canonicalExpression('net.dst.ip in {100.96.0.2} and net.dst.port == 22'),
    );
  });
  it.effect('retains customer rules and reserves precedence before them', () =>
    Effect.gen(function* () {
      const desired = yield* compilePolicy(yield* parsePolicy('{"rules":[]}'), []);
      const changes = yield* networkDiff(desired, [rule({ precedence: 4 })]);
      expect(changes).toHaveLength(1);
      expect(changes[0]?.operation).toBe('create');
      expect(changes[0]?.rule.precedence).toBe(0);
      expect(
        (yield* networkDiff(desired, [rule({ precedence: 0 })]).pipe(Effect.result))._tag,
      ).toBe('Failure');
    }),
  );
  it.effect('refuses read-only owned rules and both ownership markers are required', () =>
    Effect.gen(function* () {
      const desired = yield* compilePolicy(yield* parsePolicy('{"rules":[]}'), []);
      expect(
        (yield* networkDiff(desired, [
          rule({
            name: 'meshscale rule: default-deny',
            description: 'Managed by meshscale network rules v1; rule=default-deny',
            read_only: true,
          }),
        ]).pipe(Effect.result))._tag,
      ).toBe('Failure');
      const changes = yield* networkDiff(
        [],
        [rule({ name: 'meshscale rule: customer', description: 'Customer owned' })],
      );
      expect(changes).toHaveLength(0);
    }),
  );
});
