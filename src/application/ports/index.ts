import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import type { Finding } from '../../domain/entities/Finding.js';
import type { Grant } from '../../domain/entities/Grant.js';
import type { ContentHash } from '../../domain/value-objects/ContentHash.js';

/**
 * Ports (spec §8.1). The application states what it needs; `infrastructure`
 * decides how. Everything the outside world can do to this program passes
 * through one of these, which is what keeps the use cases testable with plain
 * in-memory objects instead of a mocked filesystem.
 */

export interface FileStat {
  readonly isDirectory: boolean;
  readonly size: number;
  readonly modifiedAt: Date;
}

export interface FileSystem {
  /** Returns null only when the path does not exist; I/O/access failures reject. */
  read(path: AbsolutePath): Promise<string | null>;
  /** Atomic: writes to a temporary file and renames (spec §10.4). */
  write(path: AbsolutePath, content: string, mode?: number): Promise<void>;
  append(path: AbsolutePath, content: string): Promise<void>;
  /** Atomic when source and destination are on the same filesystem. */
  move(source: AbsolutePath, destination: AbsolutePath): Promise<void>;
  exists(path: AbsolutePath): Promise<boolean>;
  /** Returns null only when the path does not exist; I/O/access failures reject. */
  stat(path: AbsolutePath): Promise<FileStat | null>;
  makeDirectory(path: AbsolutePath): Promise<void>;
  /** Creates a private, collision-resistant directory directly below `parent`. */
  makeTemporaryDirectory(parent: AbsolutePath, prefix: string): Promise<AbsolutePath>;
  remove(path: AbsolutePath): Promise<void>;
  /** Workspace-relative paths of every file under `root`, respecting `ignore`. */
  list(root: AbsolutePath, options?: ListOptions): Promise<readonly AbsolutePath[]>;
  realPath(path: AbsolutePath): AbsolutePath;
}

export interface ListOptions {
  readonly maxEntries?: number;
  readonly maxDepth?: number;
  readonly ignoreDirectories?: readonly string[];
  readonly includeFile?: (path: AbsolutePath) => boolean;
  readonly shouldDescend?: (path: AbsolutePath) => boolean;
  /** Security scans prefer a loud failure to a clean-looking partial result. */
  readonly failOnLimit?: boolean;
  /** Control-plane callers must not mistake EACCES/EIO for an empty directory. */
  readonly failOnError?: boolean;
}

export interface Clock {
  now(): Date;
}

export interface Environment {
  /** Home selected by the caller; used only for host-side state compatibility. */
  readonly home: AbsolutePath;
  /** Canonical home of the effective OS identity; owns every security boundary. */
  readonly identityHome: AbsolutePath;
  readonly cwd: AbsolutePath;
  readonly platform: Platform;
  readonly tempDir: AbsolutePath;
  readonly variables: Readonly<Record<string, string>>;
  /** Where node and version managers live — readable inside the sandbox. */
  toolchainRoots(): readonly AbsolutePath[];
}

export type AnswerChoice = 'allow-once' | 'allow-forever' | 'deny' | 'deny-forever';

export interface Prompter {
  /** Returns null when nobody can answer (no TTY, CI). */
  ask(finding: Finding): Promise<AnswerChoice | null>;
  confirm(question: string): Promise<boolean>;
}

export interface Notifier {
  notify(finding: Finding): Promise<void>;
}

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface AuditEntry {
  readonly at: Date;
  readonly event: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export interface AuditLog {
  append(entry: AuditEntry): Promise<void>;
  since(moment: Date): Promise<readonly AuditEntry[]>;
}

export interface GrantStore {
  all(): Promise<readonly Grant[]>;
  add(grant: Grant): Promise<void>;
  revoke(id: string): Promise<boolean>;
}

export type Verdict = 'allow' | 'deny';

export interface Decision {
  readonly key: string;
  readonly verdict: Verdict;
  readonly subject: string;
  readonly ruleIds: readonly string[];
  readonly decidedAt: Date;
}

export interface DecisionStore {
  find(key: string): Promise<Decision | null>;
  record(decision: Decision): Promise<void>;
  /** Merges a bounded use-case batch with one store update; duplicate keys use the last value. */
  recordMany(decisions: readonly Decision[]): Promise<void>;
  all(): Promise<readonly Decision[]>;
}

export interface BaselineEntry {
  readonly path: AbsolutePath;
  readonly hash: ContentHash;
  readonly recordedAt: Date;
}

export interface BaselineStore {
  load(): Promise<readonly BaselineEntry[]>;
  save(entries: readonly BaselineEntry[]): Promise<void>;
}

export type { SandboxRunner, SandboxCommand, SandboxCapabilities, SandboxMechanism, SandboxRunResult } from './SandboxRunner.js';
export type {
  DestinationBroker,
  DestinationBrokerSession,
  DestinationBrokerStartRequest,
} from './NetworkBroker.js';
