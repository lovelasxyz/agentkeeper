import { randomBytes } from 'node:crypto';
import { JsonDocument } from './JsonDocument.js';
import { Grant, type GrantJSON } from '../../domain/entities/Grant.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { ContentHash } from '../../domain/value-objects/ContentHash.js';
import type {
  AuditEntry,
  AuditLog,
  BaselineEntry,
  BaselineStore,
  Decision,
  DecisionStore,
  FileSystem,
  GrantStore,
  Verdict,
} from '../../application/ports/index.js';

const SCHEMA_VERSION = 1;

interface AllowlistDocument {
  readonly version: number;
  readonly grants: readonly GrantJSON[];
}

/**
 * `allowlist.json` — what the sandbox opens (spec §7).
 *
 * Deliberately a separate file from `decisions.json`: one records what is
 * *reachable*, the other what was *approved*. Different lifecycles, different
 * risk, and merging them would make an accidental edit to one silently change
 * the other.
 */
export class JsonGrantStore implements GrantStore {
  private readonly document: JsonDocument<AllowlistDocument>;

  constructor(
    files: FileSystem,
    stateDir: AbsolutePath,
    private readonly home: AbsolutePath,
  ) {
    this.document = new JsonDocument(files, stateDir.join('allowlist.json'), SCHEMA_VERSION, () => ({
      version: SCHEMA_VERSION,
      grants: [],
    }));
  }

  async all(): Promise<readonly Grant[]> {
    const { grants } = await this.document.load();
    return grants.map((raw) => Grant.fromJSON(raw, this.home));
  }

  async add(grant: Grant): Promise<void> {
    const document = await this.document.load();
    const existing = document.grants.filter(
      (raw) => Grant.fromJSON(raw, this.home).id !== grant.id,
    );
    await this.document.save({
      version: SCHEMA_VERSION,
      grants: [...existing, grant.toJSON(this.home)],
    });
  }

  async revoke(id: string): Promise<boolean> {
    const document = await this.document.load();
    const remaining = document.grants.filter((raw) => Grant.fromJSON(raw, this.home).id !== id);
    if (remaining.length === document.grants.length) return false;
    await this.document.save({ version: SCHEMA_VERSION, grants: remaining });
    return true;
  }

  get location(): AbsolutePath {
    return this.document.location;
  }
}

interface DecisionsDocument {
  readonly version: number;
  readonly decisions: Readonly<Record<string, StoredDecision>>;
}

interface StoredDecision {
  readonly verdict: Verdict;
  readonly subject: string;
  readonly ruleIds: readonly string[];
  readonly decidedAt: string;
}

/** `decisions.json` — TOFU answers, keyed by content hash (spec §7). */
export class JsonDecisionStore implements DecisionStore {
  private readonly document: JsonDocument<DecisionsDocument>;

  constructor(files: FileSystem, stateDir: AbsolutePath) {
    this.document = new JsonDocument(files, stateDir.join('decisions.json'), SCHEMA_VERSION, () => ({
      version: SCHEMA_VERSION,
      decisions: {},
    }));
  }

  async find(key: string): Promise<Decision | null> {
    const { decisions } = await this.document.load();
    const stored = decisions[key];
    return stored === undefined ? null : { key, ...stored, decidedAt: new Date(stored.decidedAt) };
  }

  async record(decision: Decision): Promise<void> {
    await this.recordMany([decision]);
  }

  async recordMany(records: readonly Decision[]): Promise<void> {
    if (records.length === 0) return;
    const document = await this.document.load();
    const decisions: Record<string, StoredDecision> = { ...document.decisions };
    for (const decision of records) {
      decisions[decision.key] = {
        verdict: decision.verdict,
        subject: decision.subject,
        ruleIds: decision.ruleIds,
        decidedAt: decision.decidedAt.toISOString(),
      };
    }
    await this.document.save({
      version: SCHEMA_VERSION,
      decisions,
    });
  }

  async all(): Promise<readonly Decision[]> {
    const { decisions } = await this.document.load();
    return Object.entries(decisions).map(([key, stored]) => ({
      key,
      ...stored,
      decidedAt: new Date(stored.decidedAt),
    }));
  }
}

interface BaselineDocument {
  readonly version: number;
  readonly entries: readonly { path: string; hash: string; recordedAt: string }[];
}

/** `baseline.json` — the trusted snapshot of zone B (spec §5). */
export class JsonBaselineStore implements BaselineStore {
  private readonly document: JsonDocument<BaselineDocument>;

  constructor(files: FileSystem, stateDir: AbsolutePath) {
    this.document = new JsonDocument(files, stateDir.join('baseline.json'), SCHEMA_VERSION, () => ({
      version: SCHEMA_VERSION,
      entries: [],
    }));
  }

  async load(): Promise<readonly BaselineEntry[]> {
    const { entries } = await this.document.load();
    return entries.map((entry) => ({
      path: AbsolutePath.of(entry.path),
      hash: ContentHash.parse(entry.hash),
      recordedAt: new Date(entry.recordedAt),
    }));
  }

  async save(entries: readonly BaselineEntry[]): Promise<void> {
    await this.document.save({
      version: SCHEMA_VERSION,
      entries: entries.map((entry) => ({
        path: entry.path.value,
        hash: entry.hash.toString(),
        recordedAt: entry.recordedAt.toISOString(),
      })),
    });
  }
}

const DAY_MILLISECONDS = 24 * 60 * 60_000;
const MAX_DISCOVERED_AUDIT_FILES = 4_096;
const SEGMENT_PATTERN =
  /^audit-(\d{13})-(\d{10})-([0-9a-f]{12})-(\d{8})\.(open|closed)\.jsonl$/;
const LEGACY_SEGMENT_PATTERN = /^legacy-(\d{13})-([0-9a-f]{12})\.closed\.jsonl$/;
const DELETING_PATTERN = /^\.deleting-[0-9a-f]{12}$/;

export interface JsonlAuditLogOptions {
  readonly maxSegmentBytes?: number;
  readonly maxTotalBytes?: number;
  readonly maxSegments?: number;
  readonly maxEntryBytes?: number;
  readonly retentionDays?: number;
  readonly now?: () => Date;
  readonly processId?: number;
  readonly instanceId?: string;
  readonly processAlive?: (processId: number) => boolean;
}

interface ResolvedAuditOptions {
  readonly maxSegmentBytes: number;
  readonly maxTotalBytes: number;
  readonly maxSegments: number;
  readonly maxEntryBytes: number;
  readonly retentionDays: number;
  readonly now: () => Date;
  readonly processId: number;
  readonly instanceId: string;
  readonly processAlive: (processId: number) => boolean;
}

interface AuditSegment {
  readonly path: AbsolutePath;
  readonly name: string;
  readonly createdAt: number;
  readonly processId: number | null;
  readonly state: 'open' | 'closed';
  readonly size: number;
}

export class AuditEntryLimitError extends Error {
  constructor(readonly bytes: number, readonly limit: number) {
    super(`Audit entry is ${bytes} bytes and exceeds the ${limit}-byte entry limit`);
    this.name = 'AuditEntryLimitError';
  }
}

export class AuditCapacityError extends Error {
  constructor(reason: string) {
    super(`Audit capacity cannot be enforced without deleting active evidence: ${reason}`);
    this.name = 'AuditCapacityError';
  }
}

export class CorruptAuditArchiveError extends Error {
  constructor(readonly path: AbsolutePath, reason: string) {
    super(`Audit archive ${path.value} is not a managed segment: ${reason}`);
    this.name = 'CorruptAuditArchiveError';
  }
}

/**
 * Bounded append-only JSONL evidence.
 *
 * Each process owns a collision-resistant segment, so independent CLI and
 * daemon processes never truncate, rename, or interleave one another's active
 * writes. A local promise queue preserves invocation order. Rollover changes
 * only the owner's `.open` segment to `.closed` with an atomic same-filesystem
 * rename; retention claims immutable segments with another atomic rename
 * before deletion, making concurrent pruning idempotent without a stale lock.
 */
export class JsonlAuditLog implements AuditLog {
  private readonly archiveDir: AbsolutePath;
  private readonly legacyPath: AbsolutePath;
  private readonly options: ResolvedAuditOptions;
  private currentPath: AbsolutePath;
  private currentCreatedAt: number;
  private sequence = 0;
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly files: FileSystem,
    stateDir: AbsolutePath,
    options: JsonlAuditLogOptions = {},
  ) {
    this.archiveDir = stateDir.join('audit');
    this.legacyPath = stateDir.join('audit.log');
    this.options = resolveAuditOptions(options);
    this.currentCreatedAt = timestamp(this.options.now());
    this.currentPath = this.segmentPath(this.currentCreatedAt, this.sequence, 'open');
  }

  append(entry: AuditEntry): Promise<void> {
    return this.enqueue(async () => {
      const line = serialiseAuditEntry(entry, this.options.maxEntryBytes);
      await this.migrateLegacy();
      const current = await this.prepareCurrent(Buffer.byteLength(line));
      await this.maintain(Buffer.byteLength(line), current === null);
      await this.files.append(this.currentPath, line);
    });
  }

  since(moment: Date): Promise<readonly AuditEntry[]> {
    return this.enqueue(async () => {
      await this.migrateLegacy();
      await this.closeCurrentIfAged();
      await this.maintain(0, false);
      const segments = await this.discoverSegments();
      const entries: AuditEntry[] = [];
      let bytesRead = 0;

      for (const segment of segments) {
        bytesRead += segment.size;
        if (bytesRead > this.options.maxTotalBytes) {
          throw new AuditCapacityError(
            `reading ${bytesRead} bytes would exceed ${this.options.maxTotalBytes}`,
          );
        }
        const raw = await this.files.read(segment.path);
        if (raw === null) continue; // Concurrent pruner claimed it after discovery.
        entries.push(...parseAuditLines(raw, moment));
      }
      return entries;
    });
  }

  get location(): AbsolutePath {
    return this.currentPath;
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async prepareCurrent(lineBytes: number): Promise<Awaited<ReturnType<FileSystem['stat']>>> {
    const now = timestamp(this.options.now());
    let info = await this.files.stat(this.currentPath);
    if (info?.isDirectory === true) {
      throw new CorruptAuditArchiveError(this.currentPath, 'active segment is a directory');
    }
    if (info === null && now - this.currentCreatedAt >= DAY_MILLISECONDS) {
      this.advanceCurrent(now);
    } else if (
      info !== null &&
      (info.size + lineBytes > this.options.maxSegmentBytes ||
        now - this.currentCreatedAt >= DAY_MILLISECONDS)
    ) {
      await this.closeCurrent();
      this.advanceCurrent(now);
    }
    info = await this.files.stat(this.currentPath);
    return info;
  }

  private async closeCurrentIfAged(): Promise<void> {
    const now = timestamp(this.options.now());
    const info = await this.files.stat(this.currentPath);
    if (info === null || now - this.currentCreatedAt < DAY_MILLISECONDS) return;
    if (info.isDirectory) {
      throw new CorruptAuditArchiveError(this.currentPath, 'active segment is a directory');
    }
    await this.closeCurrent();
    this.advanceCurrent(now);
  }

  private async closeCurrent(): Promise<void> {
    const closed = withSegmentState(this.currentPath, 'closed');
    await this.files.move(this.currentPath, closed);
  }

  private advanceCurrent(now: number): void {
    this.sequence += 1;
    this.currentCreatedAt = now;
    this.currentPath = this.segmentPath(now, this.sequence, 'open');
  }

  private segmentPath(createdAt: number, sequence: number, state: 'open' | 'closed'): AbsolutePath {
    const processId = String(this.options.processId).padStart(10, '0');
    const serial = String(sequence).padStart(8, '0');
    return this.archiveDir.join(
      `audit-${String(createdAt).padStart(13, '0')}-${processId}-${this.options.instanceId}-${serial}.${state}.jsonl`,
    );
  }

  private async migrateLegacy(): Promise<void> {
    const info = await this.files.stat(this.legacyPath);
    if (info === null) return;
    if (info.isDirectory) {
      throw new CorruptAuditArchiveError(this.legacyPath, 'legacy audit.log is a directory');
    }
    const destination = this.archiveDir.join(
      `legacy-${String(timestamp(this.options.now())).padStart(13, '0')}-${randomBytes(6).toString('hex')}.closed.jsonl`,
    );
    try {
      await this.files.move(this.legacyPath, destination);
    } catch (cause) {
      // Another process may have won the same one-time migration.
      if (await this.files.exists(this.legacyPath)) throw cause;
    }
  }

  private async maintain(reservedBytes: number, createsSegment: boolean): Promise<void> {
    await this.removeDeletionClaims();
    const expiryBoundary =
      timestamp(this.options.now()) - this.options.retentionDays * DAY_MILLISECONDS - DAY_MILLISECONDS;

    for (;;) {
      const segments = await this.discoverSegments();
      const expired = segments.find(
        (segment) => this.evictable(segment) && segment.createdAt <= expiryBoundary,
      );
      if (expired !== undefined) {
        await this.claimAndDelete(expired);
        continue;
      }

      const total = segments.reduce((sum, segment) => sum + segment.size, 0) + reservedBytes;
      const count = segments.length + (createsSegment ? 1 : 0);
      if (total <= this.options.maxTotalBytes && count <= this.options.maxSegments) return;

      const oldest = segments.find((segment) => this.evictable(segment));
      if (oldest === undefined) {
        throw new AuditCapacityError(
          `${count} segments / ${total} bytes exceed ${this.options.maxSegments} segments / ` +
            `${this.options.maxTotalBytes} bytes`,
        );
      }
      await this.claimAndDelete(oldest);
    }
  }

  private evictable(segment: AuditSegment): boolean {
    if (segment.path.equals(this.currentPath)) return false;
    if (segment.state === 'closed' || segment.processId === null) return true;
    return !this.options.processAlive(segment.processId);
  }

  private async claimAndDelete(segment: AuditSegment): Promise<void> {
    const claim = this.archiveDir.join(`.deleting-${randomBytes(6).toString('hex')}`);
    try {
      await this.files.move(segment.path, claim);
    } catch (cause) {
      if (await this.files.exists(segment.path)) throw cause;
      return;
    }
    await this.files.remove(claim);
  }

  private async removeDeletionClaims(): Promise<void> {
    for (const path of await this.listArchiveFiles()) {
      if (DELETING_PATTERN.test(path.basename)) await this.files.remove(path);
    }
  }

  private async discoverSegments(): Promise<readonly AuditSegment[]> {
    const segments: AuditSegment[] = [];
    for (const path of await this.listArchiveFiles()) {
      if (DELETING_PATTERN.test(path.basename)) continue;
      const parsed = parseSegmentName(path);
      if (parsed === null) {
        throw new CorruptAuditArchiveError(path, 'unexpected file name');
      }
      const info = await this.files.stat(path);
      if (info === null) continue;
      if (info.isDirectory) throw new CorruptAuditArchiveError(path, 'segment is a directory');
      segments.push({ ...parsed, path, name: path.basename, size: info.size });
    }
    return segments.sort(compareSegments);
  }

  private listArchiveFiles(): Promise<readonly AbsolutePath[]> {
    return this.files.list(this.archiveDir, {
      maxEntries: MAX_DISCOVERED_AUDIT_FILES,
      maxDepth: 0,
      shouldDescend: () => false,
      failOnLimit: true,
      failOnError: true,
    });
  }
}

function resolveAuditOptions(options: JsonlAuditLogOptions): ResolvedAuditOptions {
  const resolved: ResolvedAuditOptions = {
    maxSegmentBytes: options.maxSegmentBytes ?? 4 * 1024 * 1024,
    maxTotalBytes: options.maxTotalBytes ?? 32 * 1024 * 1024,
    maxSegments: options.maxSegments ?? 32,
    maxEntryBytes: options.maxEntryBytes ?? 64 * 1024,
    retentionDays: options.retentionDays ?? 90,
    now: options.now ?? (() => new Date()),
    processId: options.processId ?? process.pid,
    instanceId: options.instanceId ?? randomBytes(6).toString('hex'),
    processAlive: options.processAlive ?? processIsAlive,
  };
  for (const [name, value] of [
    ['maxSegmentBytes', resolved.maxSegmentBytes],
    ['maxTotalBytes', resolved.maxTotalBytes],
    ['maxSegments', resolved.maxSegments],
    ['maxEntryBytes', resolved.maxEntryBytes],
    ['retentionDays', resolved.retentionDays],
    ['processId', resolved.processId],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  }
  if (resolved.maxEntryBytes > resolved.maxSegmentBytes) {
    throw new Error('maxEntryBytes cannot exceed maxSegmentBytes');
  }
  if (resolved.maxSegmentBytes > resolved.maxTotalBytes) {
    throw new Error('maxSegmentBytes cannot exceed maxTotalBytes');
  }
  if (!/^[0-9a-f]{12}$/.test(resolved.instanceId)) {
    throw new Error('instanceId must be exactly 12 lowercase hexadecimal characters');
  }
  timestamp(resolved.now());
  return Object.freeze(resolved);
}

function serialiseAuditEntry(entry: AuditEntry, limit: number): string {
  const line = `${JSON.stringify({
    ...entry.details,
    at: entry.at.toISOString(),
    event: entry.event,
  })}\n`;
  const bytes = Buffer.byteLength(line);
  if (bytes > limit) throw new AuditEntryLimitError(bytes, limit);
  return line;
}

function parseAuditLines(raw: string, moment: Date): readonly AuditEntry[] {
  const entries: AuditEntry[] = [];
  for (const line of raw.split('\n')) {
    if (line.trim().length === 0) continue;
    try {
      const value = JSON.parse(line) as unknown;
      if (!isObject(value) || typeof value['at'] !== 'string' || typeof value['event'] !== 'string') {
        continue;
      }
      const when = new Date(value['at']);
      if (!Number.isFinite(when.getTime()) || when < moment) continue;
      const { at: _at, event, ...details } = value;
      entries.push({ at: when, event, details });
    } catch {
      // A crash may truncate only the final line; complete preceding evidence survives.
    }
  }
  return entries;
}

function parseSegmentName(path: AbsolutePath): Omit<AuditSegment, 'path' | 'name' | 'size'> | null {
  const managed = SEGMENT_PATTERN.exec(path.basename);
  if (managed !== null) {
    return {
      createdAt: Number(managed[1]),
      processId: Number(managed[2]),
      state: managed[5] === 'open' ? 'open' : 'closed',
    };
  }
  const legacy = LEGACY_SEGMENT_PATTERN.exec(path.basename);
  if (legacy === null) return null;
  return { createdAt: Number(legacy[1]), processId: null, state: 'closed' };
}

function compareSegments(left: AuditSegment, right: AuditSegment): number {
  if (left.createdAt !== right.createdAt) return left.createdAt - right.createdAt;
  if (left.processId === null && right.processId !== null) return -1;
  if (left.processId !== null && right.processId === null) return 1;
  return left.name.localeCompare(right.name);
}

function withSegmentState(path: AbsolutePath, state: 'open' | 'closed'): AbsolutePath {
  return path.parent.join(path.basename.replace(/\.(open|closed)\.jsonl$/, `.${state}.jsonl`));
}

function timestamp(value: Date): number {
  const milliseconds = value.getTime();
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0 || milliseconds > 9_999_999_999_999) {
    throw new Error('Audit clock returned an invalid timestamp');
  }
  return milliseconds;
}

function processIsAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch (cause) {
    const code =
      typeof cause === 'object' && cause !== null && 'code' in cause
        ? (cause as { readonly code?: unknown }).code
        : null;
    return code === 'EPERM';
  }
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
