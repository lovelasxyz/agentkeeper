import { Disposition } from '../value-objects/Disposition.js';
import { Severity } from '../value-objects/Severity.js';
import type { Finding } from './Finding.js';

/** The result of a scan, ordered so the worst thing is the first thing read. */
export class ScanReport {
  private constructor(readonly findings: readonly Finding[]) {
    Object.freeze(this);
  }

  static of(findings: readonly Finding[]): ScanReport {
    const ordered = [...findings].sort((a, b) => {
      if (a.severity.rank !== b.severity.rank) return b.severity.rank - a.severity.rank;
      if (a.disposition.strictness !== b.disposition.strictness) {
        return b.disposition.strictness - a.disposition.strictness;
      }
      return a.ruleId.toString().localeCompare(b.ruleId.toString());
    });
    return new ScanReport(Object.freeze(ordered));
  }

  static empty(): ScanReport {
    return new ScanReport(Object.freeze([]));
  }

  get isClean(): boolean {
    return this.findings.length === 0;
  }

  get worstSeverity(): Severity {
    return this.findings.reduce(
      (worst, finding) => (finding.severity.isAtLeast(worst) ? finding.severity : worst),
      Severity.LOW,
    );
  }

  /** Findings that stop the action outright. */
  blocking(): readonly Finding[] {
    return this.findings.filter((finding) => finding.disposition.stops);
  }

  /** Findings that interrupt the user. The number spec §1.5 puts a budget on. */
  interrupting(): readonly Finding[] {
    return this.findings.filter((finding) => finding.disposition.interrupts);
  }

  overallDisposition(): Disposition {
    return Disposition.strictest(this.findings.map((finding) => finding.disposition));
  }

  concat(other: ScanReport): ScanReport {
    return ScanReport.of([...this.findings, ...other.findings]);
  }
}
