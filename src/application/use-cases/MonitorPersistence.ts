import { BaselineChange } from '../../domain/entities/BaselineChange.js';
import type { Finding } from '../../domain/entities/Finding.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import { Severity } from '../../domain/value-objects/Severity.js';
import type {
  AuditLog,
  BaselineEntry,
  BaselineStore,
  Clock,
  Decision,
  DecisionStore,
  FileSystem,
  Notifier,
} from '../ports/index.js';
import type {
  BaselineSnapshotter,
  PauseState,
  PauseStateReader,
  PersistenceIncident,
  PersistencePendingStore,
  PersistenceScanner,
} from '../ports/PersistenceMonitor.js';
import { mapWithConcurrency } from '../services/BoundedConcurrency.js';

const CONTENT_READ_CONCURRENCY = 8;

export interface NotificationPolicy {
  readonly maxPerWindow: number;
  readonly windowMilliseconds: number;
  readonly duplicateCooldownMilliseconds: number;
}

export interface MonitorPersistenceDependencies {
  readonly files: FileSystem;
  readonly baseline: BaselineStore;
  readonly decisions: DecisionStore;
  readonly pending: PersistencePendingStore;
  readonly pause: PauseStateReader;
  readonly collector: BaselineSnapshotter;
  readonly scanner: PersistenceScanner;
  readonly switches: RuleSwitches;
  readonly notifier: Notifier;
  readonly audit: AuditLog;
  readonly clock: Clock;
  readonly context: PathContext;
  readonly sandboxActive: boolean;
  readonly notificationPolicy?: NotificationPolicy;
}

export interface MonitorPersistenceOutcome {
  readonly exitCode: 0 | 2;
  readonly changes: number;
  readonly findings: number;
  readonly pending: number;
  readonly notifications: number;
}

const DEFAULT_NOTIFICATION_POLICY: NotificationPolicy = Object.freeze({
  maxPerWindow: 5,
  windowMilliseconds: 60_000,
  duplicateCooldownMilliseconds: 15 * 60_000,
});

/**
 * Compares persistence state and advances trust conservatively.
 *
 * High/critical drift remains relative to the last trusted snapshot until all
 * applicable content-addressed decisions explicitly allow it. The daemon can
 * therefore restart, miss an event, or receive its own writes without ever
 * turning an alert into trust merely because it was observed once.
 */
export class MonitorPersistence {
  private readonly notifications: NotificationBudget;

  constructor(private readonly dependencies: MonitorPersistenceDependencies) {
    this.notifications = new NotificationBudget(
      dependencies.notificationPolicy ?? DEFAULT_NOTIFICATION_POLICY,
    );
  }

  async execute(): Promise<MonitorPersistenceOutcome> {
    const {
      audit,
      baseline,
      clock,
      collector,
      context,
      decisions,
      files,
      notifier,
      pause,
      pending,
      sandboxActive,
      scanner,
      switches,
    } = this.dependencies;
    const now = clock.now();

    // These reads are independent and bounded in number. Loading each exactly
    // once also provides a coherent decision view for the whole comparison.
    const [previousEntries, currentEntries, storedDecisions, storedIncidents, pauseState] =
      await Promise.all([
        baseline.load(),
        collector.collect(context),
        decisions.all(),
        pending.load(),
        pause.read(),
      ]);

    const changes = await buildChanges(
      previousEntries,
      currentEntries,
      files,
      context,
      sandboxActive,
    );
    const report = scanner.scan(changes, switches);
    const findingsBySubject = groupBySubject(report.findings);
    const decisionsByKey = new Map(storedDecisions.map((decision) => [decision.key, decision]));
    const incidentsById = new Map(storedIncidents.map((incident) => [incident.id, incident]));
    const nextIncidents: PersistenceIncident[] = [];
    const nextBaseline = new Map(previousEntries.map((entry) => [entry.path.value, entry]));
    const resolution = new Map<string, 'safe' | 'accepted' | 'pending'>();

    for (const change of changes) {
      const findings = findingsBySubject.get(change.display) ?? [];
      const risky = findings.filter((finding) => finding.severity.isAtLeast(Severity.HIGH));
      const approved = risky.every(
        (finding) => isDurablyAllowed(matchingDecision(decisionsByKey, finding), finding),
      );

      if (risky.length === 0 || approved) {
        applyTrustedChange(nextBaseline, currentEntries, change);
        resolution.set(change.display, risky.length === 0 ? 'safe' : 'accepted');
        continue;
      }

      resolution.set(change.display, 'pending');
      for (const finding of risky) {
        const decision = matchingDecision(decisionsByKey, finding);
        if (isDurablyAllowed(decision, finding)) continue;
        const id = incidentId(finding);
        const existing = incidentsById.get(id);
        nextIncidents.push({
          id,
          decisionKey: finding.decisionKey,
          subject: finding.subject,
          ruleIds: [finding.ruleId.toString()],
          severity: finding.severity.name,
          state: decision?.verdict === 'deny' ? 'quarantined' : 'pending',
          previousHash: change.previousHash?.toString() ?? null,
          currentHash: change.currentHash?.toString() ?? null,
          firstSeenAt: existing?.firstSeenAt ?? now,
          lastSeenAt: now,
          occurrences: Math.min((existing?.occurrences ?? 0) + 1, Number.MAX_SAFE_INTEGER),
        });
      }
    }

    const orderedIncidents = [...nextIncidents].sort((left, right) =>
      left.id.localeCompare(right.id),
    );
    if (!sameIncidents(storedIncidents, orderedIncidents)) await pending.save(orderedIncidents);

    const trustedEntries = [...nextBaseline.values()].sort((left, right) =>
      left.path.value.localeCompare(right.path.value),
    );
    if (!sameBaseline(previousEntries, trustedEntries)) await baseline.save(trustedEntries);

    if (pauseState.status === 'invalid') {
      await audit.append({
        at: now,
        event: 'pause.invalid',
        details: { reason: pauseState.reason },
      });
    }

    let sent = 0;
    for (const finding of report.findings) {
      const state = resolution.get(finding.subject) ?? 'safe';
      await audit.append({
        at: now,
        event: 'persistence.change',
        details: findingDetails(finding, sandboxActive),
      });

      if (state === 'pending' && finding.severity.isAtLeast(Severity.HIGH)) {
        const decision = matchingDecision(decisionsByKey, finding);
        await audit.append({
          at: now,
          event: isDurablyAllowed(decision, finding)
            ? 'persistence.finding.accepted'
            : decision?.verdict === 'deny'
              ? 'persistence.quarantined'
              : 'persistence.pending',
          details: {
            ...findingDetails(finding, sandboxActive),
            decisionKey: finding.decisionKey,
          },
        });
      } else if (state === 'accepted' && finding.severity.isAtLeast(Severity.HIGH)) {
        await audit.append({
          at: now,
          event: 'persistence.accepted',
          details: {
            ...findingDetails(finding, sandboxActive),
            decisionKey: finding.decisionKey,
          },
        });
      }

      const suppression = notificationSuppression(
        pauseState,
        state,
        finding,
        isDurablyAllowed(matchingDecision(decisionsByKey, finding), finding),
        this.notifications,
        now,
      );
      if (suppression !== null) {
        await audit.append({
          at: now,
          event: 'persistence.notification.suppressed',
          details: { ...findingDetails(finding, sandboxActive), reason: suppression },
        });
        continue;
      }

      try {
        await notifier.notify(finding);
        sent += 1;
        await audit.append({
          at: now,
          event: 'persistence.notification.sent',
          details: findingDetails(finding, sandboxActive),
        });
      } catch (cause) {
        await audit.append({
          at: now,
          event: 'persistence.notification.failed',
          details: {
            ...findingDetails(finding, sandboxActive),
            reason: cause instanceof Error ? cause.message : String(cause),
          },
        });
      }
    }

    return {
      exitCode: orderedIncidents.length > 0 ? 2 : 0,
      changes: changes.length,
      findings: report.findings.length,
      pending: orderedIncidents.length,
      notifications: sent,
    };
  }
}

async function buildChanges(
  previousEntries: readonly BaselineEntry[],
  currentEntries: readonly BaselineEntry[],
  files: FileSystem,
  context: PathContext,
  sandboxActive: boolean,
): Promise<readonly BaselineChange[]> {
  const previous = new Map(previousEntries.map((entry) => [entry.path.value, entry]));
  const current = new Map(currentEntries.map((entry) => [entry.path.value, entry]));
  const descriptors: Array<{
    readonly before: BaselineEntry | null;
    readonly after: BaselineEntry | null;
  }> = [];

  for (const after of currentEntries) {
    const before = previous.get(after.path.value) ?? null;
    if (before !== null && before.hash.equals(after.hash)) continue;
    descriptors.push({ before, after });
  }
  for (const before of previousEntries) {
    if (!current.has(before.path.value)) descriptors.push({ before, after: null });
  }

  const changes = await mapWithConcurrency(
    descriptors,
    CONTENT_READ_CONCURRENCY,
    async ({ before, after }) =>
      new BaselineChange({
        path: after?.path ?? (before as BaselineEntry).path,
        kind: before === null ? 'created' : after === null ? 'deleted' : 'modified',
        previousHash: before?.hash ?? null,
        currentHash: after?.hash ?? null,
        content: after === null ? null : await files.read(after.path),
        context,
        sandboxActive,
      }),
  );
  return [...changes].sort((left, right) => left.path.value.localeCompare(right.path.value));
}

function applyTrustedChange(
  baseline: Map<string, BaselineEntry>,
  currentEntries: readonly BaselineEntry[],
  change: BaselineChange,
): void {
  const current = currentEntries.find((entry) => entry.path.value === change.path.value);
  if (current === undefined) baseline.delete(change.path.value);
  else baseline.set(change.path.value, current);
}

function groupBySubject(findings: readonly Finding[]): ReadonlyMap<string, readonly Finding[]> {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const entries = grouped.get(finding.subject) ?? [];
    entries.push(finding);
    grouped.set(finding.subject, entries);
  }
  return grouped;
}

function incidentId(finding: Finding): string {
  return `${finding.ruleId.toString()}@${finding.subject}@${finding.decisionKey}`;
}

function findingDetails(finding: Finding, sandboxActive: boolean): Record<string, unknown> {
  return {
    rule: finding.ruleId.toString(),
    subject: finding.subject,
    severity: finding.severity.name,
    sandboxActive,
  };
}

function notificationSuppression(
  pause: PauseState,
  resolution: 'safe' | 'accepted' | 'pending',
  finding: Finding,
  findingApproved: boolean,
  budget: NotificationBudget,
  now: Date,
): 'paused' | 'approved' | 'duplicate' | 'rate-limit' | null {
  if (pause.status === 'active') return 'paused';
  if (
    finding.severity.isAtLeast(Severity.HIGH) &&
    (resolution === 'accepted' || findingApproved)
  ) {
    return 'approved';
  }
  return budget.claim(finding.decisionKey, now);
}

function matchingDecision(
  decisions: ReadonlyMap<string, Decision>,
  finding: Finding,
): Decision | undefined {
  const decision = decisions.get(finding.decisionKey);
  if (
    decision === undefined ||
    decision.subject !== finding.subject ||
    !decision.ruleIds.includes(finding.ruleId.toString())
  ) {
    return undefined;
  }
  return decision;
}

function isDurablyAllowed(decision: Decision | undefined, finding: Finding): boolean {
  // A deletion has no current content hash. Persistently approving it would
  // also approve every future deletion of that path, so deletion trust must be
  // established by an explicit baseline/repair operation instead.
  return decision?.verdict === 'allow' && finding.contentHash !== null;
}

function sameBaseline(
  previous: readonly BaselineEntry[],
  next: readonly BaselineEntry[],
): boolean {
  if (previous.length !== next.length) return false;
  const hashes = new Map(previous.map((entry) => [entry.path.value, entry.hash]));
  return next.every((entry) => hashes.get(entry.path.value)?.equals(entry.hash) === true);
}

function sameIncidents(
  previous: readonly PersistenceIncident[],
  next: readonly PersistenceIncident[],
): boolean {
  if (previous.length !== next.length) return false;
  return previous.every((entry, index) => {
    const candidate = next[index];
    return (
      candidate !== undefined &&
      entry.id === candidate.id &&
      entry.state === candidate.state &&
      entry.occurrences === candidate.occurrences &&
      entry.lastSeenAt.getTime() === candidate.lastSeenAt.getTime()
    );
  });
}

class NotificationBudget {
  private windowStartedAt: number | null = null;
  private sentInWindow = 0;
  private readonly recentlySent = new Map<string, number>();

  constructor(private readonly policy: NotificationPolicy) {
    if (
      !Number.isSafeInteger(policy.maxPerWindow) ||
      policy.maxPerWindow < 1 ||
      policy.windowMilliseconds < 1 ||
      policy.duplicateCooldownMilliseconds < 1
    ) {
      throw new Error('Notification limits must be positive integers');
    }
  }

  claim(key: string, now: Date): 'duplicate' | 'rate-limit' | null {
    const timestamp = now.getTime();
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
