import type { Rule } from './Rule.js';

/** Which rules the user turned off (spec §10.3). Blocking rules are not listed here. */
export interface RuleSwitches {
  isEnabled(ruleId: string): boolean;
}

export const ALL_RULES_ENABLED: RuleSwitches = { isEnabled: () => true };

/**
 * Registry pattern (spec §8.3): one place that knows which rules exist, and the
 * only place that honours the enable/disable configuration.
 */
export class RuleRegistry<TSubject> {
  private constructor(private readonly rules: readonly Rule<TSubject>[]) {
    Object.freeze(this);
  }

  static of<T>(rules: readonly Rule<T>[]): RuleRegistry<T> {
    const seen = new Set<string>();
    for (const rule of rules) {
      const id = rule.id.toString();
      if (seen.has(id)) throw new Error(`Duplicate rule id: ${id}`);
      seen.add(id);
    }
    return new RuleRegistry(Object.freeze([...rules]));
  }

  all(): readonly Rule<TSubject>[] {
    return this.rules;
  }

  enabled(switches: RuleSwitches): readonly Rule<TSubject>[] {
    return this.rules.filter(
      // A rule whose disposition is `block` is not negotiable through config:
      // spec §10.3 says configuration may narrow noise, never remove a refusal.
      (rule) => rule.defaultDisposition.stops || switches.isEnabled(rule.id.toString()),
    );
  }

  byId(id: string): Rule<TSubject> | null {
    return this.rules.find((rule) => rule.id.toString() === id) ?? null;
  }
}
