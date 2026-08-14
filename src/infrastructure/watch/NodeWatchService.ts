import { watch } from 'node:fs';
import { lstat, readdir } from 'node:fs/promises';
import type { WatchTarget } from '../../application/ports/PersistenceMonitor.js';
import { SingleFlightScheduler } from '../../application/services/SingleFlightScheduler.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

const WATCH_STARTUP_SETTLE_MS = 25;

export type WatchCoverageStatus = 'protected' | 'degraded' | 'failed';

export interface WatchCoverage {
  readonly status: WatchCoverageStatus;
  readonly requestedTargets: number;
  readonly watchedDirectories: number;
  readonly reasons: readonly string[];
}

export interface WatchEvent {
  readonly type: 'change' | 'rename';
  readonly path: AbsolutePath | null;
}

export interface WatchFault {
  readonly path: AbsolutePath;
  readonly reason: string;
}

export interface WatchSession {
  close(): void;
}

export interface WatchStartResult {
  readonly coverage: WatchCoverage;
  readonly session: WatchSession;
}

export interface NodeWatchServiceOptions {
  readonly maxDirectories?: number;
  readonly persistent?: boolean;
  /** Injectable only to contract-test platform-independent orchestration. */
  readonly watchDirectory?: WatchDirectory;
}

export type WatchChangeHandler = (event: WatchEvent) => void;
export type WatchFaultHandler = (fault: WatchFault) => void;

export interface DirectoryWatcher {
  close(): void;
  on(event: 'error', listener: (error: Error) => void): this;
}

export type WatchDirectory = (
  path: string,
  options: { readonly persistent: boolean; readonly recursive: false },
  listener: (eventType: string, filename: string | Buffer | null) => void,
) => DirectoryWatcher;

/**
 * Portable directory watcher.
 *
 * It does not rely on `fs.watch({recursive:true})`, whose availability and
 * behaviour vary by OS/filesystem. Existing trees receive one bounded watcher
 * per directory; missing targets are watched through the closest existing
 * ancestor and are explicitly reported as degraded until they appear.
 */
export class NodeWatchService {
  private readonly maxDirectories: number;
  private readonly persistent: boolean;
  private readonly watchDirectory: WatchDirectory;

  constructor(options: NodeWatchServiceOptions = {}) {
    this.maxDirectories = options.maxDirectories ?? 512;
    this.persistent = options.persistent ?? true;
    this.watchDirectory = options.watchDirectory ?? watch;
    if (!Number.isSafeInteger(this.maxDirectories) || this.maxDirectories < 1) {
      throw new Error('Watcher directory limit must be a positive integer');
    }
  }

  async start(
    targets: readonly WatchTarget[],
    onChange: WatchChangeHandler,
    onFault: WatchFaultHandler,
  ): Promise<WatchStartResult> {
    const session = new ActiveNodeWatchSession(
      uniqueTargets(targets),
      this.maxDirectories,
      this.persistent,
      this.watchDirectory,
      onChange,
      onFault,
    );
    const coverage = await session.initialise();
    return { coverage, session };
  }
}

interface Registration {
  readonly path: AbsolutePath;
  readonly scopes: Set<string>;
  readonly watcher: DirectoryWatcher;
}

class ActiveNodeWatchSession implements WatchSession {
  private readonly registrations = new Map<string, Registration>();
  private readonly issues = new Set<string>();
  private closed = false;
  private readonly refresh: SingleFlightScheduler;

  constructor(
    private readonly targets: readonly WatchTarget[],
    private readonly maxDirectories: number,
    private readonly persistent: boolean,
    private readonly watchDirectory: WatchDirectory,
    private readonly onChange: WatchChangeHandler,
    private readonly onFault: WatchFaultHandler,
  ) {
    this.refresh = new SingleFlightScheduler(
      async () => this.refreshCoverage(),
      async (error) =>
        this.reportFault(
          this.targets[0]?.path ?? AbsolutePath.of('/'),
          `watch refresh failed: ${error.message}`,
        ),
    );
  }

  async initialise(): Promise<WatchCoverage> {
    if (this.targets.length === 0) this.issues.add('no watch targets were configured');
    for (const target of this.targets) await this.expandTarget(target, true);
    // `fs.watch` reports some startup failures asynchronously (notably EMFILE
    // and backend permission failures). Let that first error turn coverage into
    // an explicit failed/degraded result instead of returning a false green.
    await new Promise<void>((resolve) => setTimeout(resolve, WATCH_STARTUP_SETTLE_MS));

    const status: WatchCoverageStatus =
      this.registrations.size === 0
        ? 'failed'
        : this.issues.size > 0
          ? 'degraded'
          : 'protected';
    return Object.freeze({
      status,
      requestedTargets: this.targets.length,
      watchedDirectories: this.registrations.size,
      reasons: Object.freeze([...this.issues]),
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const registration of this.registrations.values()) registration.watcher.close();
    this.registrations.clear();
  }

  private async refreshCoverage(): Promise<void> {
    if (this.closed) return;
    for (const registration of [...this.registrations.values()]) {
      if (await isDirectory(registration.path)) continue;
      registration.watcher.close();
      this.registrations.delete(registration.path.value);
    }
    for (const target of this.targets) await this.expandTarget(target, false);
  }

  private async expandTarget(target: WatchTarget, initial: boolean): Promise<void> {
    const { path, recursive } = target;
    const targetKind = await pathKind(path);
    if (targetKind === 'directory') {
      // A non-recursive target still needs its own directory watched: that is
      // where creations and renames of the files it covers are observed.
      if (recursive) await this.expandDirectory(path, path);
      else this.register(path, path);
      return;
    }
    if (targetKind === 'file') {
      this.register(path.parent, path);
      return;
    }

    const ancestor = await closestExistingDirectory(path.parent);
    if (ancestor === null) {
      const reason = `${path.value} cannot be watched: no readable ancestor exists`;
      this.issues.add(reason);
      if (!initial) this.reportFault(path, reason);
      return;
    }
    const reason = `${path.value} does not exist; watching ancestor ${ancestor.value}`;
    this.issues.add(reason);
    this.register(ancestor, path);
  }

  private async expandDirectory(directory: AbsolutePath, scope: AbsolutePath): Promise<void> {
    if (!this.register(directory, scope)) return;

    let entries;
    try {
      entries = await readdir(directory.value, { withFileTypes: true });
    } catch (cause) {
      this.recordIssue(
        directory,
        `${directory.value} could not be enumerated: ${message(cause)}`,
      );
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (this.registrations.size >= this.maxDirectories) {
        this.recordIssue(
          scope,
          `${scope.value} recursive coverage exceeded directory limit ${this.maxDirectories}`,
        );
        return;
      }
      await this.expandDirectory(directory.join(entry.name), scope);
    }
  }

  private register(directory: AbsolutePath, scope: AbsolutePath): boolean {
    const existing = this.registrations.get(directory.value);
    if (existing !== undefined) {
      existing.scopes.add(scope.value);
      return true;
    }
    if (this.registrations.size >= this.maxDirectories) {
      this.recordIssue(
        scope,
        `${scope.value} recursive coverage exceeded directory limit ${this.maxDirectories}`,
      );
      return false;
    }

    try {
      const watcher = this.watchDirectory(
        directory.value,
        { persistent: this.persistent, recursive: false },
        (eventType, filename) => this.handleEvent(directory, eventType, filename),
      );
      const registration: Registration = { path: directory, scopes: new Set([scope.value]), watcher };
      this.registrations.set(directory.value, registration);
      watcher.on('error', (error) => {
        watcher.close();
        this.registrations.delete(directory.value);
        this.recordIssue(directory, `${directory.value} watcher failed: ${error.message}`);
      });
      return true;
    } catch (cause) {
      // Through `recordIssue`, not `reportFault`: a refresh retries every
      // uncovered directory, so reporting per attempt turns a permanently
      // unreadable surface into an endless stream of identical log lines.
      this.recordIssue(directory, `${directory.value} could not be watched: ${message(cause)}`);
      return false;
    }
  }

  private handleEvent(
    directory: AbsolutePath,
    eventType: string,
    filename: string | Buffer | null,
  ): void {
    if (this.closed) return;
    const registration = this.registrations.get(directory.value);
    if (registration === undefined) return;
    const path = eventPath(directory, filename);
    if (path !== null && !isRelevantToAnyScope(path, registration.scopes)) return;

    try {
      this.onChange({ type: eventType === 'rename' ? 'rename' : 'change', path });
    } catch (cause) {
      this.reportFault(directory, `watch callback failed: ${message(cause)}`);
    }
    if (eventType === 'rename') void this.refresh.request();
  }

  private reportFault(path: AbsolutePath, reason: string): void {
    if (this.closed) return;
    try {
      this.onFault({ path, reason });
    } catch {
      // Watch coverage remains degraded even if its observer is unavailable.
    }
  }

  private recordIssue(path: AbsolutePath, reason: string): void {
    if (this.issues.has(reason)) return;
    this.issues.add(reason);
    this.reportFault(path, reason);
  }
}

async function pathKind(path: AbsolutePath): Promise<'file' | 'directory' | 'missing'> {
  try {
    const info = await lstat(path.value);
    if (info.isDirectory()) return 'directory';
    if (info.isFile()) return 'file';
    return 'missing';
  } catch {
    return 'missing';
  }
}

async function isDirectory(path: AbsolutePath): Promise<boolean> {
  return (await pathKind(path)) === 'directory';
}

async function closestExistingDirectory(start: AbsolutePath): Promise<AbsolutePath | null> {
  let candidate = start;
  for (;;) {
    if (await isDirectory(candidate)) return candidate;
    if (candidate.equals(candidate.parent)) return null;
    candidate = candidate.parent;
  }
}

function eventPath(directory: AbsolutePath, filename: string | Buffer | null): AbsolutePath | null {
  if (filename === null) return null;
  const name = filename.toString();
  if (name.length === 0 || /[\\/\0]/.test(name)) return null;
  try {
    return directory.join(name);
  } catch {
    return null;
  }
}

function isRelevantToAnyScope(path: AbsolutePath, scopes: ReadonlySet<string>): boolean {
  for (const raw of scopes) {
    const scope = AbsolutePath.of(raw);
    if (scope.contains(path) || path.contains(scope)) return true;
  }
  return false;
}

function uniqueTargets(targets: readonly WatchTarget[]): readonly WatchTarget[] {
  const merged = new Map<string, WatchTarget>();
  for (const target of targets) {
    const existing = merged.get(target.path.value);
    // The same path can arrive twice with different intents. Recursion wins:
    // dropping it would leave the deeper entry that asked for it uncovered.
    merged.set(target.path.value, {
      path: target.path,
      recursive: (existing?.recursive ?? false) || target.recursive,
    });
  }
  return [...merged.values()];
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
