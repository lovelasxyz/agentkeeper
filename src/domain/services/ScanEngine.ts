import { ScanReport } from '../entities/ScanReport.js';
import { ALL_RULES_ENABLED, type RuleRegistry, type RuleSwitches } from '../rules/RuleRegistry.js';
import type { Finding } from '../entities/Finding.js';

/**
 * Applies a registry of rules to a batch of subjects.
 *
 * Pure: takes subjects, returns a report, mutates nothing. That property is
 * asserted with a property test, because a scanner that quietly edits what it
 * scans would be an unusually bad thing for this particular product to do.
 */
export class ScanEngine<TSubject> {
  constructor(private readonly registry: RuleRegistry<TSubject>) {}

  scan(subjects: readonly TSubject[], switches: RuleSwitches = ALL_RULES_ENABLED): ScanReport {
    const rules = this.registry.enabled(switches);
    const findings: Finding[] = [];

    for (const subject of subjects) {
      for (const rule of rules) {
        findings.push(...rule.evaluate(subject));
      }
    }
    return ScanReport.of(findings);
  }
}
