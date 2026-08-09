import type { FileSystem } from '../../application/ports/index.js';
import type {
  PersistenceIncident,
  PersistenceIncidentState,
  PersistencePendingStore,
} from '../../application/ports/PersistenceMonitor.js';
import type { SeverityName } from '../../domain/value-objects/Severity.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { CorruptStoreError, JsonDocument } from './JsonDocument.js';

const SCHEMA_VERSION = 1;
const MAX_PENDING_BYTES = 2 * 1024 * 1024;
const MAX_INCIDENTS = 2_048;
const SEVERITIES = new Set<SeverityName>(['low', 'medium', 'high', 'critical']);
const STATES = new Set<PersistenceIncidentState>(['pending', 'quarantined']);

interface StoredIncident {
  readonly id: string;
  readonly decisionKey: string;
  readonly subject: string;
  readonly ruleIds: readonly string[];
  readonly severity: SeverityName;
  readonly state: PersistenceIncidentState;
  readonly previousHash: string | null;
  readonly currentHash: string | null;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly occurrences: number;
}

interface PendingDocument {
  readonly version: number;
  readonly incidents: readonly StoredIncident[];
}

/** Atomic metadata store for drift that must not be learned into the baseline. */
export class JsonPersistencePendingStore implements PersistencePendingStore {
  private readonly document: JsonDocument<PendingDocument>;
  private readonly path: AbsolutePath;

  constructor(
    private readonly files: FileSystem,
    stateDir: AbsolutePath,
  ) {
    this.path = stateDir.join('persistence-pending.json');
    this.document = new JsonDocument(files, this.path, SCHEMA_VERSION, () => ({
      version: SCHEMA_VERSION,
      incidents: [],
    }));
  }

  async load(): Promise<readonly PersistenceIncident[]> {
    const info = await this.files.stat(this.path);
    if (info !== null && (info.isDirectory || info.size > MAX_PENDING_BYTES)) {
      throw new CorruptStoreError(this.path, 'pending incident store exceeds its bounded schema');
    }
    const raw = await this.document.load();
    if (!Array.isArray(raw.incidents)) {
      throw new CorruptStoreError(this.document.location, 'incidents must be an array');
    }
    if (raw.incidents.length > MAX_INCIDENTS) {
      throw new CorruptStoreError(this.path, `more than ${MAX_INCIDENTS} pending incidents`);
    }
    return raw.incidents.map((incident, index) => this.parse(incident, index));
  }

  async save(incidents: readonly PersistenceIncident[]): Promise<void> {
    if (incidents.length > MAX_INCIDENTS) {
      throw new Error(`Refusing to store more than ${MAX_INCIDENTS} pending incidents`);
    }
    await this.document.save({
      version: SCHEMA_VERSION,
      incidents: incidents.map((incident) => ({
        ...incident,
        firstSeenAt: incident.firstSeenAt.toISOString(),
        lastSeenAt: incident.lastSeenAt.toISOString(),
      })),
    });
  }

  get location(): AbsolutePath {
    return this.document.location;
  }

  private parse(value: unknown, index: number): PersistenceIncident {
    if (!isObject(value)) throw this.corrupt(index, 'expected an object');
    const id = string(value, 'id', index, this.document.location);
    const decisionKey = string(value, 'decisionKey', index, this.document.location);
    const subject = string(value, 'subject', index, this.document.location);
    const ruleIds = value['ruleIds'];
    const severity = value['severity'];
    const state = value['state'];
    const occurrences = value['occurrences'];
    if (!Array.isArray(ruleIds) || !ruleIds.every((rule): rule is string => typeof rule === 'string')) {
      throw this.corrupt(index, 'ruleIds must be strings');
    }
    if (typeof severity !== 'string' || !SEVERITIES.has(severity as SeverityName)) {
      throw this.corrupt(index, 'unknown severity');
    }
    if (typeof state !== 'string' || !STATES.has(state as PersistenceIncidentState)) {
      throw this.corrupt(index, 'unknown state');
    }
    if (!Number.isSafeInteger(occurrences) || (occurrences as number) < 1) {
      throw this.corrupt(index, 'occurrences must be a positive integer');
    }
    const firstSeenAt = date(value, 'firstSeenAt', index, this.document.location);
    const lastSeenAt = date(value, 'lastSeenAt', index, this.document.location);
    return {
      id,
      decisionKey,
      subject,
      ruleIds,
      severity: severity as SeverityName,
      state: state as PersistenceIncidentState,
      previousHash: nullableString(value, 'previousHash', index, this.document.location),
      currentHash: nullableString(value, 'currentHash', index, this.document.location),
      firstSeenAt,
      lastSeenAt,
      occurrences: occurrences as number,
    };
  }

  private corrupt(index: number, reason: string): CorruptStoreError {
    return new CorruptStoreError(this.document.location, `incident ${index}: ${reason}`);
  }
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function string(
  value: Readonly<Record<string, unknown>>,
  key: string,
  index: number,
  path: AbsolutePath,
): string {
  const candidate = value[key];
  if (typeof candidate !== 'string' || candidate.length === 0) {
    throw new CorruptStoreError(path, `incident ${index}: ${key} must be a non-empty string`);
  }
  return candidate;
}

function nullableString(
  value: Readonly<Record<string, unknown>>,
  key: string,
  index: number,
  path: AbsolutePath,
): string | null {
  const candidate = value[key];
  if (candidate !== null && typeof candidate !== 'string') {
    throw new CorruptStoreError(path, `incident ${index}: ${key} must be a string or null`);
  }
  return candidate;
}

function date(
  value: Readonly<Record<string, unknown>>,
  key: string,
  index: number,
  path: AbsolutePath,
): Date {
  const candidate = string(value, key, index, path);
  const parsed = new Date(candidate);
  if (!Number.isFinite(parsed.getTime())) {
    throw new CorruptStoreError(path, `incident ${index}: ${key} must be a timestamp`);
  }
  return parsed;
}
