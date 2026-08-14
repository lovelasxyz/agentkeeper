/**
 * Notification policy as a domain value: rate, cooldown and fairness decided
 * here, so the persistence use case orchestrates an answer instead of
 * inventing one. A security finding must not be able to scream forever, and a
 * hostile stream of findings must not be able to exhaust the daemon — both
 * are stated in one place and tested without a file system.
 */

export interface NotificationPolicySpec {
  readonly maxPerWindow: number;
  readonly windowMilliseconds: number;
  readonly duplicateCooldownMilliseconds: number;
}

export class NotificationPolicy {
  /** The shipped policy: a handful per minute, a repeat never inside 15 minutes. */
  static readonly STANDARD = NotificationPolicy.create({
    maxPerWindow: 5,
    windowMilliseconds: 60_000,
    duplicateCooldownMilliseconds: 15 * 60_000,
  });

  private constructor(
    readonly maxPerWindow: number,
    readonly windowMilliseconds: number,
    readonly duplicateCooldownMilliseconds: number,
  ) {}

  static create(spec: NotificationPolicySpec): NotificationPolicy {
    if (
      !Number.isSafeInteger(spec.maxPerWindow) ||
      spec.maxPerWindow < 1 ||
      spec.windowMilliseconds < 1 ||
      spec.duplicateCooldownMilliseconds < 1
    ) {
      throw new Error('Notification limits must be positive integers');
    }
    return new NotificationPolicy(
      spec.maxPerWindow,
      spec.windowMilliseconds,
      spec.duplicateCooldownMilliseconds,
    );
  }
}

export type NotificationClaim = 'duplicate' | 'rate-limit' | null;

/**
 * The sliding-window budget. A refused claim is not spent budget, and a
 * duplicate is not a new claim: a repeated finding must not crowd out the
 * next distinct one.
 */
export class NotificationBudget {
  private windowStartedAt: number | null = null;
  private sentInWindow = 0;
  private readonly recentlySent = new Map<string, number>();

  constructor(private readonly policy: NotificationPolicy) {}

  claim(key: string, at: Date): NotificationClaim {
    const timestamp = at.getTime();
    this.prune(timestamp);
    const previous = this.recentlySent.get(key);
    if (previous !== undefined && timestamp - previous < this.policy.duplicateCooldownMilliseconds) {
      return 'duplicate';
    }
    if (
      this.windowStartedAt === null ||
      timestamp - this.windowStartedAt >= this.policy.windowMilliseconds
    ) {
      this.windowStartedAt = timestamp;
      this.sentInWindow = 0;
    }
    if (this.sentInWindow >= this.policy.maxPerWindow) return 'rate-limit';
    this.sentInWindow += 1;
    this.recentlySent.set(key, timestamp);
    this.enforceRecentBound();
    return null;
  }

  private prune(now: number): void {
    for (const [key, sentAt] of this.recentlySent) {
      if (now - sentAt >= this.policy.duplicateCooldownMilliseconds) {
        this.recentlySent.delete(key);
      }
    }
  }

  private enforceRecentBound(): void {
    // A compromised stream of unique subjects must not grow the daemon forever.
    while (this.recentlySent.size > 512) {
      const oldest = this.recentlySent.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.recentlySent.delete(oldest);
    }
  }
}

export type NotificationSuppression = 'paused' | 'approved' | 'duplicate' | 'rate-limit' | null;

/**
 * The one place that decides whether a finding may notify. Order is the
 * policy: an operator pause outranks everything; an approved finding is
 * silent forever and never touches the budget; everything else buys its way
 * through the budget.
 */
export function suppressNotification(input: {
  readonly paused: boolean;
  readonly approvedHigh: boolean;
  readonly budget: NotificationBudget;
  readonly decisionKey: string;
  readonly at: Date;
}): NotificationSuppression {
  if (input.paused) return 'paused';
  if (input.approvedHigh) return 'approved';
  return input.budget.claim(input.decisionKey, input.at);
}
