import { expect, it } from '@effect/vitest';
import { viewFromHash } from '../src/browser-view.ts';

it('defaults unknown hashes to the Machines view', () => {
  expect(viewFromHash('#foo')).toBe('machines');
  expect(viewFromHash('')).toBe('machines');
  for (const view of ['machines', 'rules', 'dns', 'exits'])
    expect(viewFromHash(`#${view}`)).toBe(view);
});
