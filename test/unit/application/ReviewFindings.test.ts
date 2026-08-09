import { describe, expect, it } from 'vitest';
import { ReviewFindings } from '../../../src/application/use-cases/ReviewFindings.js';
import { Finding } from '../../../src/domain/entities/Finding.js';
import { ScanReport } from '../../../src/domain/entities/ScanReport.js';
import { ContentHash } from '../../../src/domain/value-objects/ContentHash.js';
import { Disposition } from '../../../src/domain/value-objects/Disposition.js';
import { RuleId } from '../../../src/domain/value-objects/RuleId.js';
import { Severity } from '../../../src/domain/value-objects/Severity.js';
import type {
  AnswerChoice,
  AuditEntry,
  AuditLog,
  Clock,
  Decision,
  DecisionStore,
  Prompter,
} from '../../../src/application/ports/index.js';

class QueuePrompter implements Prompter {
  readonly asked: Finding[] = [];

  constructor(private readonly answers: readonly (AnswerChoice | null)[]) {}

  async ask(finding: Finding): Promise<AnswerChoice | null> {
    this.asked.push(finding);
    return this.answers[this.asked.length - 1] ?? null;
  }

  async confirm(): Promise<boolean> {
    return false;
  }
}

class MemoryDecisions implements DecisionStore {
  readonly values = new Map<string, Decision>();

  async find(key: string): Promise<Decision | null> {
    return this.values.get(key) ?? null;
  }

  async record(decision: Decision): Promise<void> {
    this.values.set(decision.key, decision);
  }

  async recordMany(decisions: readonly Decision[]): Promise<void> {
    for (const decision of decisions) this.values.set(decision.key, decision);
  }

  async all(): Promise<readonly Decision[]> {
    return [...this.values.values()];
  }
}

class MemoryAudit implements AuditLog {
  readonly entries: AuditEntry[] = [];

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async since(): Promise<readonly AuditEntry[]> {
    return this.entries;
  }
}

const clock: Clock = { now: () => new Date('2026-08-08T10:00:00Z') };

function finding(
  disposition: Disposition,
  options: { readonly rule?: string; readonly content?: string; readonly subject?: string } = {},
): Finding {
  return new Finding({
    ruleId: RuleId.of(options.rule ?? 'AG-I001'),
    severity: Severity.HIGH,
    disposition,
    title: 'Potentially hostile instruction',
    detail: 'The content included SUPERSECRET and must never reach the audit log.',
    remediation: 'Review SUPERSECRET outside the agent session.',
    subject: options.subject ?? 'AGENTS.md',
    contentHash: ContentHash.fromContent(options.content ?? 'same content'),
    location: null,
  });
}

function stack(answers: readonly (AnswerChoice | null)[]) {
  const prompter = new QueuePrompter(answers);
  const decisions = new MemoryDecisions();
  const audit = new MemoryAudit();
  return {
    prompter,
    decisions,
    audit,
    useCase: new ReviewFindings(prompter, decisions, audit, clock),
  };
}

describe('ReviewFindings', () => {
  it('never asks about block or observe findings', async () => {
    const { useCase, prompter } = stack(['allow-forever']);
    const blocked = finding(Disposition.BLOCK);
    const observed = finding(Disposition.OBSERVE, { rule: 'AG-I003' });

    const outcome = await useCase.execute(ScanReport.of([blocked, observed]));

    expect(outcome.report.findings).toEqual(expect.arrayContaining([blocked, observed]));
    expect(prompter.asked).toEqual([]);
  });

  it('allow-once hides only the current finding and records no decision', async () => {
    const { useCase, prompter, decisions } = stack(['allow-once', 'deny']);
    const first = finding(Disposition.ASK);
    const second = finding(Disposition.ASK, { subject: 'CLAUDE.md' });

    const outcome = await useCase.execute(ScanReport.of([first, second]));

    expect(outcome.report.findings).toEqual([second]);
    expect(prompter.asked).toEqual([first, second]);
    expect(await decisions.all()).toEqual([]);
  });

  it('allow-forever atomically records the content-addressed decision', async () => {
    const { useCase, prompter, decisions } = stack(['allow-forever']);
    const first = finding(Disposition.ASK);
    const duplicate = finding(Disposition.ASK, { subject: 'same-content-copy.md' });

    const outcome = await useCase.execute(ScanReport.of([first, duplicate]));

    expect(outcome.report.isClean).toBe(true);
    expect(prompter.asked).toEqual([first]);
    expect(await decisions.find(first.decisionKey)).toMatchObject({
      verdict: 'allow',
      subject: first.subject,
      ruleIds: ['AG-I001'],
    });
  });

  it('deny keeps the finding without persisting the answer', async () => {
    const { useCase, prompter, decisions } = stack(['deny', 'allow-once']);
    const first = finding(Disposition.ASK);
    const second = finding(Disposition.ASK, { subject: 'CLAUDE.md' });

    const outcome = await useCase.execute(ScanReport.of([first, second]));

    expect(outcome.report.findings).toEqual([first]);
    expect(prompter.asked).toEqual([first, second]);
    expect(await decisions.all()).toEqual([]);
  });

  it('keeps an ask finding when no interactive answer is available', async () => {
    const { useCase, prompter, decisions, audit } = stack([null]);
    const pending = finding(Disposition.ASK);

    const outcome = await useCase.execute(ScanReport.of([pending]));

    expect(outcome.report.findings).toEqual([pending]);
    expect(prompter.asked).toEqual([pending]);
    expect(await decisions.all()).toEqual([]);
    expect(audit.entries).toEqual([]);
  });

  it('deny-forever records a denial and does not ask again for the same finding', async () => {
    const { useCase, prompter, decisions } = stack(['deny-forever']);
    const first = finding(Disposition.ASK);
    const duplicate = finding(Disposition.ASK, { subject: 'same-content-copy.md' });

    const outcome = await useCase.execute(ScanReport.of([first, duplicate]));

    expect(outcome.report.findings).toEqual(expect.arrayContaining([first, duplicate]));
    expect(prompter.asked).toEqual([first]);
    expect(await decisions.find(first.decisionKey)).toMatchObject({ verdict: 'deny' });
  });

  it('writes review metadata to audit without finding contents', async () => {
    const { useCase, audit } = stack(['allow-forever']);

    await useCase.execute(ScanReport.of([finding(Disposition.ASK)]));

    const serialized = JSON.stringify(audit.entries);
    expect(serialized).toContain('finding.reviewed');
    expect(serialized).toContain('AG-I001');
    expect(serialized).not.toContain('SUPERSECRET');
    expect(serialized).not.toContain('same content');
  });
});
