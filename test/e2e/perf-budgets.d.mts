export interface PerfBudgets {
  readonly hookOwnCost: number;
  readonly scanOwnCost: number;
  readonly wrapperOwnCost: number;
  readonly wrapperTotalOverhead: number;
}

export const PERF_BUDGETS: PerfBudgets;

export function budgetViolations(
  measured: Readonly<Record<string, number>>,
  budgets?: Readonly<Record<string, number>>,
): string[];
