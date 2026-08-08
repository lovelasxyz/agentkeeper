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
    const document = await this.document.load();
    await this.document.save({
      version: SCHEMA_VERSION,
      decisions: {
        ...document.decisions,
        [decision.key]: {
          verdict: decision.verdict,
          subject: decision.subject,
          ruleIds: decision.ruleIds,
          decidedAt: decision.decidedAt.toISOString(),
        },
      },
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

/**
 * `audit.log` — append-only JSON Lines.
 *
 * Records paths, hashes and rule ids and never file contents (spec §10.4). A
 * log of what a security tool protected must not become the one place all of it
 * is written down in the clear.
 */
export class JsonlAuditLog implements AuditLog {
  private readonly path: AbsolutePath;

  constructor(
    private readonly files: FileSystem,
    stateDir: AbsolutePath,
  ) {
    this.path = stateDir.join('audit.log');
  }

  async append(entry: AuditEntry): Promise<void> {
    const line = JSON.stringify({
      at: entry.at.toISOString(),
      event: entry.event,
      ...entry.details,
    });
    await this.files.append(this.path, `${line}\n`);
  }

  async since(moment: Date): Promise<readonly AuditEntry[]> {
    const raw = await this.files.read(this.path);
    if (raw === null) return [];

    const entries: AuditEntry[] = [];
    for (const line of raw.split('\n')) {
      if (line.trim().length === 0) continue;
      try {
        const { at, event, ...details } = JSON.parse(line) as {
          at: string;
          event: string;
        } & Record<string, unknown>;
        const when = new Date(at);
        if (when >= moment) entries.push({ at: when, event, details });
      } catch {
        // A truncated final line after a crash is not a reason to lose the rest.
        continue;
      }
    }
    return entries;
  }

  get location(): AbsolutePath {
    return this.path;
  }
}
