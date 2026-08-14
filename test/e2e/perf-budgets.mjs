/**
 * The one source of truth for the performance budgets of spec §12.
 *
 * `bench.mjs` measures, this module decides, and both the CI gate
 * (`bench.mjs --enforce`) and the e2e regression suite assert against the
 * same numbers so the gate and the suite cannot drift apart.
 *
 * These are regression guards for a loaded CI machine, not the published
 * idle-machine figures (hook ≤ 50 ms, wrapper ≤ 100 ms): contention shifts
 * even the minimum, so the bounds here catch a change that makes the hot
 * path several times slower without making the suite flaky.
 */
export const PERF_BUDGETS = Object.freeze({
  hookOwnCost: 120,
  scanOwnCost: 250,
  wrapperOwnCost: 150,
  wrapperTotalOverhead: 300,
});

/**
 * One human-readable violation per exceeded or missing budget; empty when
 * every measured figure is within its limit. A missing measurement is a
 * violation: a gate that cannot see a figure must not pass it.
 */
export function budgetViolations(measured, budgets = PERF_BUDGETS) {
  const violations = [];
  for (const [key, limit] of Object.entries(budgets)) {
    const value = measured[key];
    if (typeof value !== 'number' || Number.isNaN(value)) {
      violations.push(`${key}: no measurement (budget ${limit} ms)`);
    } else if (value > limit) {
      violations.push(`${key}: ${value} ms exceeds the ${limit} ms budget`);
    }
  }
  return violations;
}
