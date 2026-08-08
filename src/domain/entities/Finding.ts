import type { ContentHash } from '../value-objects/ContentHash.js';
import type { Disposition } from '../value-objects/Disposition.js';
import type { RuleId } from '../value-objects/RuleId.js';
import type { Severity } from '../value-objects/Severity.js';
import type { SourceLocation } from '../value-objects/SourceLocation.js';

export interface FindingProps {
  readonly ruleId: RuleId;
  readonly severity: Severity;
  readonly disposition: Disposition;
  /** One line: what was found. */
  readonly title: string;
  /** One or two lines: why it matters here. */
  readonly detail: string;
  /** What the user can do about it. */
  readonly remediation: string;
  readonly subject: string;
  readonly contentHash: ContentHash | null;
  readonly location: SourceLocation | null;
}

/**
 * One thing worth telling the user about.
 *
 * Carries the content hash rather than the content: a finding travels into the
 * audit log, and the log must never become the place the protected secrets end
 * up (spec §10.4).
 */
export class Finding {
  readonly ruleId: RuleId;
  readonly severity: Severity;
  readonly disposition: Disposition;
  readonly title: string;
  readonly detail: string;
  readonly remediation: string;
  readonly subject: string;
  readonly contentHash: ContentHash | null;
  readonly location: SourceLocation | null;

  constructor(props: FindingProps) {
    this.ruleId = props.ruleId;
    this.severity = props.severity;
    this.disposition = props.disposition;
    this.title = props.title;
    this.detail = props.detail;
    this.remediation = props.remediation;
    this.subject = props.subject;
    this.contentHash = props.contentHash;
    this.location = props.location;
    Object.freeze(this);
  }

  /** Same rule, same content — the key TOFU decisions are stored under (spec §7). */
  get decisionKey(): string {
    return this.contentHash === null
      ? `${this.ruleId.toString()}@${this.subject}`
      : this.contentHash.toString();
  }

  withDisposition(disposition: Disposition): Finding {
    return new Finding({ ...this, disposition });
  }

  toJSON(): Record<string, unknown> {
    return {
      ruleId: this.ruleId.toString(),
      severity: this.severity.name,
      disposition: this.disposition.name,
      title: this.title,
      subject: this.subject,
      contentHash: this.contentHash?.toString() ?? null,
      location: this.location?.toString() ?? null,
    };
  }
}
