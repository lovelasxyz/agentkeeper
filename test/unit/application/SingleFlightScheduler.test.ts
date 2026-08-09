import { describe, expect, it } from 'vitest';
import { SingleFlightScheduler } from '../../../src/application/services/SingleFlightScheduler.js';

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe('SingleFlightScheduler', () => {
  it('coalesces a burst into one dirty rerun and never overlaps work', async () => {
    const first = deferred();
    const second = deferred();
    const gates = [first, second];
    let runs = 0;
    let active = 0;
    let maximumActive = 0;

    const scheduler = new SingleFlightScheduler(async () => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      const gate = gates[runs];
      runs += 1;
      await gate?.promise;
      active -= 1;
    });

    const completion = scheduler.request();
    void scheduler.request();
    void scheduler.request();
    expect(scheduler.active).toBe(true);
    expect(runs).toBe(1);
    expect(maximumActive).toBe(1);

    first.resolve();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(runs).toBe(2);
    expect(maximumActive).toBe(1);

    second.resolve();
    await completion;
    expect(runs).toBe(2);
    expect(active).toBe(0);
    expect(scheduler.active).toBe(false);
  });

  it('reports a failed pass and remains usable for the next event', async () => {
    const errors: Error[] = [];
    let attempts = 0;
    const scheduler = new SingleFlightScheduler(
      async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('comparison failed');
      },
      async (error) => {
        errors.push(error);
      },
    );

    await scheduler.request();
    await scheduler.request();

    expect(attempts).toBe(2);
    expect(errors.map((error) => error.message)).toEqual(['comparison failed']);
  });

  it('contains a failing error sink instead of producing an unhandled rejection', async () => {
    const scheduler = new SingleFlightScheduler(
      async () => {
        throw new Error('task failed');
      },
      async () => {
        throw new Error('audit failed too');
      },
    );

    await expect(scheduler.request()).resolves.toBeUndefined();
  });
});
