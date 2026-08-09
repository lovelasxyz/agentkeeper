import { describe, expect, it } from 'vitest';
import { mapWithConcurrency } from '../../../src/application/services/BoundedConcurrency.js';

describe('mapWithConcurrency', () => {
  it('overlaps independent work up to the limit and preserves input order', async () => {
    let active = 0;
    let maximum = 0;

    const output = await mapWithConcurrency([1, 2, 3, 4, 5, 6], 3, async (value) => {
      active += 1;
      maximum = Math.max(maximum, active);
      await new Promise((resolve) => setTimeout(resolve, 8 - value));
      active -= 1;
      return value * 10;
    });

    expect(output).toEqual([10, 20, 30, 40, 50, 60]);
    expect(maximum).toBe(3);
  });

  it('does not start workers for an empty input', async () => {
    let calls = 0;
    const output = await mapWithConcurrency([], 4, async () => {
      calls += 1;
      return 'unreachable';
    });

    expect(output).toEqual([]);
    expect(calls).toBe(0);
  });

  it.each([0, -1, 1.5, Number.POSITIVE_INFINITY])(
    'rejects an invalid concurrency limit %s',
    async (limit) => {
      await expect(mapWithConcurrency([1], limit, async (value) => value)).rejects.toThrow(
        /positive integer/,
      );
    },
  );
});
