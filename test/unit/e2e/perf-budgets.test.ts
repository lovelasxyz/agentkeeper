import { describe, expect, it } from 'vitest';

import { PERF_BUDGETS, budgetViolations } from '../../e2e/perf-budgets.mjs';

/**
 * The CI performance gate (spec §12): bench.mjs measures, perf-budgets decides.
 * A budget that is measured but never enforced regresses silently, so the
 * comparison lives in one pure function shared by the bench and the e2e suite.
 */
describe('performance budget enforcement', () => {
  const within = {
    bareNodeStartup: 30,
    sandboxExecCost: 5,
    hookOwnCost: 13,
    scanOwnCost: 15,
    wrapperOwnCost: 36,
    wrapperTotalOverhead: 59,
  };

  it('declares a budget for every measured hot path', () => {
    const keys = ['hookOwnCost', 'scanOwnCost', 'wrapperOwnCost', 'wrapperTotalOverhead'] as const;
    for (const key of keys) {
      expect(PERF_BUDGETS[key], `missing budget for ${key}`).toBeTypeOf('number');
    }
  });

  it('reports no violations when every figure is within budget', () => {
    expect(budgetViolations(within)).toEqual([]);
  });

  it('names every exceeded budget with the measured figure and the limit', () => {
    const violations = budgetViolations({ ...within, hookOwnCost: 121, wrapperOwnCost: 200 });
    expect(violations).toHaveLength(2);
    expect(violations[0]).toContain('hookOwnCost');
    expect(violations[0]).toContain('121');
    expect(violations[0]).toContain(String(PERF_BUDGETS['hookOwnCost']));
    expect(violations[1]).toContain('wrapperOwnCost');
  });

  it('treats a figure exactly at the limit as within budget', () => {
    expect(budgetViolations({ ...within, hookOwnCost: PERF_BUDGETS['hookOwnCost'] })).toEqual([]);
  });

  it('fails loudly on a missing measurement instead of passing it', () => {
    const violations = budgetViolations({ scanOwnCost: 10 });
    expect(violations.some((violation) => violation.includes('hookOwnCost'))).toBe(true);
  });
});
