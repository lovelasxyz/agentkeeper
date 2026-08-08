import { Finding } from '../entities/Finding.js';
import type { ContentHash } from '../value-objects/ContentHash.js';
import type { Disposition } from '../value-objects/Disposition.js';
import type { RuleId } from '../value-objects/RuleId.js';
import type { Severity } from '../value-objects/Severity.js';
import type { SourceLocation } from '../value-objects/SourceLocation.js';

/** What a rule needs to describe a hit, without knowing how it will be rendered. */
export interface FindingDraft {
  readonly title: string;
  readonly detail: string;
  readonly subject: string;
  readonly contentHash?: ContentHash | null;
  readonly location?: SourceLocation | null;
  readonly severity?: Severity;
  readonly disposition?: Disposition;
}

/**
 * Template Method (spec §8.3).
 *
 * `evaluate` is final: it fixes the one invariant every rule must hold — a rule
 * that does not apply returns nothing, and a rule never sees a subject it did
 * not claim. Subclasses supply the judgement, never the plumbing.
 *
 * Generic in its subject because the three rule families read genuinely
 * different things: files in the repository, tool calls the agent is about to
 * make, and changes to the system outside the sandbox. One shared base with one
 * shared `Finding` output keeps the reporting path identical for all three.
 */
export abstract class Rule<TSubject> {
  abstract readonly id: RuleId;
  abstract readonly severity: Severity;
  abstract readonly defaultDisposition: Disposition;
  abstract readonly title: string;
  abstract readonly remediation: string;

  abstract appliesTo(subject: TSubject): boolean;

  abstract inspect(subject: TSubject): readonly Finding[];

  evaluate(subject: TSubject): readonly Finding[] {
    if (!this.appliesTo(subject)) return [];
    return this.inspect(subject);
  }

  protected finding(draft: FindingDraft): Finding {
    return new Finding({
      ruleId: this.id,
      severity: draft.severity ?? this.severity,
      disposition: draft.disposition ?? this.defaultDisposition,
      title: draft.title,
      detail: draft.detail,
      remediation: this.remediation,
      subject: draft.subject,
      contentHash: draft.contentHash ?? null,
      location: draft.location ?? null,
    });
  }

  protected none(): readonly Finding[] {
    return [];
  }
}
