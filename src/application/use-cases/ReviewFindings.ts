import { ScanReport } from '../../domain/entities/ScanReport.js';
import type { Finding } from '../../domain/entities/Finding.js';
import type {
  AnswerChoice,
  AuditLog,
  Clock,
  Decision,
  DecisionStore,
  Prompter,
} from '../ports/index.js';

export interface ReviewFindingsOutcome {
  readonly report: ScanReport;
  readonly answers: number;
  readonly decisionsRecorded: number;
}

/**
 * Resolves the `ask` findings of an interactive workspace scan.
 *
 * The use case owns the distinction between a one-shot answer and durable,
 * content-addressed trust. Presentation only decides whether a scan is allowed
 * to be interactive; blocking and observing findings never reach the prompt.
 */
export class ReviewFindings {
  constructor(
    private readonly prompter: Prompter,
    private readonly decisions: DecisionStore,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
  ) {}

  async execute(report: ScanReport): Promise<ReviewFindingsOutcome> {
    const kept: Finding[] = [];
    let answers = 0;
    let decisionsRecorded = 0;

    for (const finding of report.findings) {
      if (!finding.disposition.interrupts) {
        kept.push(finding);
        continue;
      }

      const previous = await this.previousDecision(finding);
      if (previous !== null) {
        if (previous.verdict === 'deny') kept.push(finding);
        continue;
      }

      const answer = await this.prompter.ask(finding);
      if (answer === null) {
        kept.push(finding);
        continue;
      }

      answers += 1;
      if (answer === 'allow-once') {
        await this.recordAudit(finding, answer, false);
        continue;
      }
      if (answer === 'deny') {
        kept.push(finding);
        await this.recordAudit(finding, answer, false);
        continue;
      }

      const verdict = answer === 'allow-forever' ? 'allow' : 'deny';
      await this.decisions.record({
        key: finding.decisionKey,
        verdict,
        subject: finding.subject,
        ruleIds: [finding.ruleId.toString()],
        decidedAt: this.clock.now(),
      });
      decisionsRecorded += 1;

      if (verdict === 'deny') kept.push(finding);
      await this.recordAudit(finding, answer, true);
    }

    return {
      report: ScanReport.of(kept),
      answers,
      decisionsRecorded,
    };
  }

  private async previousDecision(finding: Finding): Promise<Decision | null> {
    return this.decisions.find(finding.decisionKey);
  }

  private async recordAudit(
    finding: Finding,
    answer: AnswerChoice,
    persisted: boolean,
  ): Promise<void> {
    await this.audit.append({
      at: this.clock.now(),
      event: 'finding.reviewed',
      details: {
        decisionKey: finding.decisionKey,
        rule: finding.ruleId.toString(),
        subject: finding.subject,
        answer,
        persisted,
      },
    });
  }
}
