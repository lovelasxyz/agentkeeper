import type { FileSystem } from '../../application/ports/index.js';
import type {
  InstallationChange,
  InstallationConflict,
  InstallationConflictCode,
  InstallationOperation,
  InstallationPlan,
} from '../../application/ports/InstallationLifecycle.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { ContentHash } from '../../domain/value-objects/ContentHash.js';

export const MANAGED_AGENTS = ['claude', 'codex', 'gemini', 'opencode'] as const;
export type ManagedAgent = (typeof MANAGED_AGENTS)[number];

/** Checksum-managed extension point for daemon and git protection artifacts. */
export interface ManagedOwnedArtifact {
  readonly id: string;
  readonly path: AbsolutePath;
  readonly content: string;
  readonly mode?: number;
}

export interface ManagedInstallationOptions {
  readonly home: AbsolutePath;
  readonly stateDir: AbsolutePath;
  readonly shell: 'posix' | 'powershell';
  /** Trusted JavaScript runtime, normally the absolute `process.execPath`. */
  readonly runtimeExecutable: AbsolutePath;
  /** Absolute npm-installed `dist/cli.js`, always invoked through the trusted runtime. */
  readonly agentkeeperEntrypoint: AbsolutePath;
  /** Absolute original executables, resolved before shim directories enter PATH. */
  readonly agentExecutables: Readonly<Partial<Record<ManagedAgent, AbsolutePath>>>;
  readonly profiles: readonly AbsolutePath[];
  readonly claudeSettings: AbsolutePath;
  readonly additionalOwnedArtifacts?: readonly ManagedOwnedArtifact[];
}

type Ownership = 'owned' | 'shared';

interface DesiredArtifact {
  readonly id: string;
  readonly path: AbsolutePath;
  readonly ownership: Ownership;
  readonly content: string;
  readonly mode: number | null;
}

interface CandidateArtifact extends DesiredArtifact {
  readonly before: string | null;
}

interface ManifestEntry {
  readonly id: string;
  readonly path: string;
  readonly ownership: Ownership;
  readonly installedChecksum: string;
  readonly originalChecksum: string | null;
  readonly backupPath: string | null;
  readonly mode: number | null;
}

interface ManifestPayload {
  readonly schema: 'dev.agentkeeper.managed-installation';
  readonly version: 2;
  readonly shell: 'posix' | 'powershell';
  readonly runtimeExecutable: string;
  readonly agentkeeperEntrypoint: string;
  readonly configurationChecksum: string;
  readonly entries: readonly ManifestEntry[];
}

interface ManifestEnvelope {
  readonly checksum: string;
  readonly payload: ManifestPayload;
}

type LoadedManifest =
  | { readonly kind: 'absent' }
  | { readonly kind: 'invalid'; readonly message: string }
  | { readonly kind: 'valid'; readonly raw: string; readonly payload: ManifestPayload };

const MANAGED_MARKER_START = '# >>> agentkeeper managed >>>';
const MANAGED_MARKER_END = '# <<< agentkeeper managed <<<';
const MANIFEST_SCHEMA = 'dev.agentkeeper.managed-installation';
const MANIFEST_VERSION = 2;

/**
 * Purely filesystem-backed install-once lifecycle.
 *
 * It performs no process discovery, service registration or package-manager
 * calls. Composition is expected to resolve the real binaries once and pass
 * them in; this class then produces an inspectable, deterministic plan.
 */
export class ManagedInstallationPlanner {
  constructor(
    private readonly files: FileSystem,
    private readonly options: ManagedInstallationOptions,
  ) {}

  get manifestPath(): AbsolutePath {
    return this.options.stateDir.join('installation/manifest.json');
  }

  async plan(operation: InstallationOperation): Promise<InstallationPlan> {
    const loaded = await this.loadManifest();
    if (loaded.kind === 'invalid') {
      return this.failedPlan(operation, [
        this.conflict('invalid-manifest', this.manifestPath, loaded.message),
      ]);
    }
    if (loaded.kind === 'absent') {
      if (operation !== 'activate') return this.successfulPlan(operation, []);
      return this.planFirstActivation();
    }

    const validation = this.validateManifest(loaded.payload, operation);
    if (validation !== null) {
      return this.failedPlan(operation, [
        this.conflict('configuration-mismatch', this.manifestPath, validation),
      ]);
    }

    if (operation === 'deactivate') return this.planDeactivation(loaded);
    return this.planInstalled(operation, loaded.payload);
  }

  private async planFirstActivation(): Promise<InstallationPlan> {
    const conflicts = this.configurationConflicts();
    if (conflicts.length > 0) return this.failedPlan('activate', conflicts);

    const candidates: CandidateArtifact[] = [];
    const owned = this.ownedArtifacts();
    const [ownedBefore, profileBefore, settingsBefore] = await Promise.all([
      Promise.all(owned.map((artifact) => this.files.read(artifact.path))),
      Promise.all(this.options.profiles.map((path) => this.files.read(path))),
      this.files.read(this.options.claudeSettings),
    ]);

    for (const [index, artifact] of owned.entries()) {
      const before = ownedBefore[index] as string | null;
      if (before !== null) {
        conflicts.push(
          this.conflict(
            'owned-path-exists',
            artifact.path,
            'The path existed before agentkeeper had a manifest; it will not be claimed or overwritten',
          ),
        );
        continue;
      }
      candidates.push({ ...artifact, before });
    }

    for (const [index, path] of this.options.profiles.entries()) {
      const before = profileBefore[index] as string | null;
      // POSIX users commonly have only one of .zshrc/.bashrc. Do not create an
      // unused profile. PowerShell has one canonical profile and may need it.
      if (before === null && this.options.shell === 'posix') continue;
      if (before !== null && hasAnyManagedMarker(before)) {
        conflicts.push(
          this.conflict(
            'managed-marker-collision',
            path,
            'A managed marker exists without a valid manifest; ownership is ambiguous',
          ),
        );
        continue;
      }
      candidates.push({
        id: `profile:${this.options.shell}:${index}`,
        path,
        ownership: 'shared',
        before,
        content: appendProfileBlock(before, this.profileBlock(path)),
        mode: null,
      });
    }

    const renderedSettings = this.renderClaudeSettings(settingsBefore);
    if (typeof renderedSettings === 'string') {
      conflicts.push(
        this.conflict('invalid-shared-config', this.options.claudeSettings, renderedSettings),
      );
    } else {
      candidates.push({
        id: 'claude-settings',
        path: this.options.claudeSettings,
        ownership: 'shared',
        before: settingsBefore,
        content: renderedSettings.content,
        mode: null,
      });
    }

    conflicts.push(...this.duplicatePathConflicts(candidates));

    const backupChanges: InstallationChange[] = [];
    const targetChanges: InstallationChange[] = [];
    const entries: ManifestEntry[] = [];
    const existingBackups = await Promise.all(
      candidates.map((candidate) =>
        candidate.before === null
          ? Promise.resolve(null)
          : this.files.read(this.backupPath(candidate.path)),
      ),
    );
    for (const [index, candidate] of candidates.entries()) {
      let backupPath: AbsolutePath | null = null;
      let originalChecksum: string | null = null;
      if (candidate.before !== null) {
        backupPath = this.backupPath(candidate.path);
        const existingBackup = existingBackups[index] as string | null;
        if (existingBackup !== null) {
          conflicts.push(
            this.conflict(
              'owned-path-exists',
              backupPath,
              'The deterministic backup path already exists without a valid manifest',
            ),
          );
        } else {
          backupChanges.push(
            change(
              backupPath,
              null,
              candidate.before,
              `Back up ${candidate.path.value} byte-for-byte`,
              0o600,
            ),
          );
        }
        originalChecksum = checksum(candidate.before);
      }

      targetChanges.push(
        change(
          candidate.path,
          candidate.before,
          candidate.content,
          `Install managed artifact ${candidate.id}`,
          candidate.mode,
        ),
      );
      entries.push({
        id: candidate.id,
        path: candidate.path.value,
        ownership: candidate.ownership,
        installedChecksum: checksum(candidate.content),
        originalChecksum,
        backupPath: backupPath?.value ?? null,
        mode: candidate.mode,
      });
    }

    conflicts.push(
      ...this.duplicateChangePathConflicts([
        ...backupChanges,
        ...targetChanges,
        change(this.manifestPath, null, '', 'manifest placeholder', null),
      ]),
    );

    if (conflicts.length > 0) return this.failedPlan('activate', conflicts);

    const payload: ManifestPayload = {
      schema: MANIFEST_SCHEMA,
      version: MANIFEST_VERSION,
      shell: this.options.shell,
      runtimeExecutable: this.options.runtimeExecutable.value,
      agentkeeperEntrypoint: this.options.agentkeeperEntrypoint.value,
      configurationChecksum: this.configurationChecksum(),
      entries,
    };
    const manifest = serialiseManifest(payload);
    const manifestChange = change(
      this.manifestPath,
      null,
      manifest,
      'Commit the managed installation manifest and content checksums',
      0o600,
    );

    return this.successfulPlan('activate', [...backupChanges, ...targetChanges, manifestChange]);
  }

  private async planInstalled(
    operation: 'activate' | 'repair',
    payload: ManifestPayload,
  ): Promise<InstallationPlan> {
    const [conflicts, currentFiles] = await Promise.all([
      this.backupConflicts(payload),
      Promise.all(payload.entries.map((entry) => this.files.read(AbsolutePath.of(entry.path)))),
    ]);
    const repairs: InstallationChange[] = [];
    const desiredOwned = new Map(this.ownedArtifacts().map((artifact) => [artifact.id, artifact]));

    for (const [index, entry] of payload.entries.entries()) {
      const path = AbsolutePath.of(entry.path);
      const before = currentFiles[index] as string | null;
      if (before !== null && checksum(before) === entry.installedChecksum) continue;

      if (operation === 'activate') {
        conflicts.push(this.driftConflict(entry, path));
        continue;
      }
      if (entry.ownership === 'shared') {
        conflicts.push(this.driftConflict(entry, path));
        continue;
      }

      const desired = desiredOwned.get(entry.id);
      if (desired === undefined || checksum(desired.content) !== entry.installedChecksum) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            path,
            'The currently configured artifact does not match the installed manifest',
          ),
        );
        continue;
      }
      repairs.push(
        change(path, before, desired.content, `Repair managed artifact ${entry.id}`, desired.mode),
      );
    }

    if (conflicts.length > 0) return this.failedPlan(operation, conflicts);
    return this.successfulPlan(operation, repairs);
  }

  private async planDeactivation(loaded: Extract<LoadedManifest, { kind: 'valid' }>): Promise<InstallationPlan> {
    const snapshots = await Promise.all(
      loaded.payload.entries.map(async (entry) => ({
        entry,
        current: await this.files.read(AbsolutePath.of(entry.path)),
        backup:
          entry.backupPath === null
            ? null
            : await this.files.read(AbsolutePath.of(entry.backupPath)),
      })),
    );
    const conflicts: InstallationConflict[] = [];

    for (const { entry, current, backup } of snapshots) {
      const path = AbsolutePath.of(entry.path);
      if (current === null || checksum(current) !== entry.installedChecksum) {
        conflicts.push(this.driftConflict(entry, path));
      }
      if (
        entry.backupPath !== null &&
        (backup === null || checksum(backup) !== entry.originalChecksum)
      ) {
        conflicts.push(
          this.conflict(
            'backup-drift',
            AbsolutePath.of(entry.backupPath),
            `The byte-exact backup for ${entry.id} is missing or has changed`,
          ),
        );
      }
    }

    if (conflicts.length > 0) return this.failedPlan('deactivate', conflicts);

    const targetChanges = [...snapshots].reverse().map(({ entry, current, backup }) => {
      return change(
        AbsolutePath.of(entry.path),
        current,
        backup,
        `Remove managed artifact ${entry.id}`,
        null,
      );
    });

    const backupChanges: InstallationChange[] = [];
    for (const { entry, backup } of [...snapshots].reverse()) {
      if (entry.backupPath === null) continue;
      const path = AbsolutePath.of(entry.backupPath);
      backupChanges.push(
        change(path, backup, null, `Remove backup for ${entry.id}`, null),
      );
    }

    return this.successfulPlan('deactivate', [
      ...targetChanges,
      ...backupChanges,
      change(this.manifestPath, loaded.raw, null, 'Remove managed installation manifest', null),
    ]);
  }

  private ownedArtifacts(): readonly DesiredArtifact[] {
    const shellExtension = this.options.shell === 'posix' ? 'sh' : 'ps1';
    const shimDirectory = this.options.stateDir.join(`shims/${this.options.shell}`);
    const artifacts: DesiredArtifact[] = [
      {
        id: `shell-init:${this.options.shell}`,
        path: this.options.stateDir.join(`shell/agentkeeper.${shellExtension}`),
        ownership: 'owned',
        content:
          this.options.shell === 'posix'
            ? renderPosixShellInit(shimDirectory)
            : renderPowerShellInit(shimDirectory),
        mode: 0o600,
      },
    ];

    for (const [agent, target] of this.agentTargets()) {
      artifacts.push({
        id: `shim:${this.options.shell}:${agent}`,
        path: shimDirectory.join(`${agent}${this.options.shell === 'posix' ? '' : '.ps1'}`),
        ownership: 'owned',
        content:
          this.options.shell === 'posix'
            ? renderPosixShim(
                this.options.runtimeExecutable,
                this.options.agentkeeperEntrypoint,
                target,
              )
            : renderPowerShellShim(
                this.options.runtimeExecutable,
                this.options.agentkeeperEntrypoint,
                target,
              ),
        mode: this.options.shell === 'posix' ? 0o700 : 0o600,
      });
      if (this.options.shell === 'powershell') {
        artifacts.push({
          id: `shim:cmd:${agent}`,
          path: shimDirectory.join(`${agent}.cmd`),
          ownership: 'owned',
          content: renderWindowsCommandShim(
            this.options.runtimeExecutable,
            this.options.agentkeeperEntrypoint,
            target,
          ),
          mode: 0o600,
        });
      }
    }
    for (const artifact of this.options.additionalOwnedArtifacts ?? []) {
      artifacts.push({
        ...artifact,
        ownership: 'owned',
        mode: artifact.mode ?? 0o600,
      });
    }
    return artifacts;
  }

  private profileBlock(_profile: AbsolutePath): string {
    const init = this.options.stateDir.join(
      `shell/agentkeeper.${this.options.shell === 'posix' ? 'sh' : 'ps1'}`,
    );
    const source =
      this.options.shell === 'posix'
        ? `[ -f ${posixQuote(init.value)} ] && . ${posixQuote(init.value)}`
        : `if (Test-Path -LiteralPath ${powerShellQuote(init.value)}) { . ${powerShellQuote(init.value)} }`;
    return `${MANAGED_MARKER_START}\n${source}\n${MANAGED_MARKER_END}\n`;
  }

  private renderClaudeSettings(raw: string | null): { readonly content: string } | string {
    let settings: Record<string, unknown>;
    if (raw === null) {
      settings = {};
    } else {
      try {
        const parsed: unknown = JSON.parse(raw);
        if (!isRecord(parsed)) return 'Claude settings must be a JSON object';
        settings = parsed;
      } catch {
        return 'Claude settings are not valid JSON; refusing to replace or repair them';
      }
    }

    const existingHooks = settings['hooks'];
    if (existingHooks !== undefined && !isRecord(existingHooks)) {
      return 'Claude settings.hooks must be an object';
    }
    const hooks: Record<string, unknown> = { ...(existingHooks ?? {}) };
    const existingPreToolUse = hooks['PreToolUse'];
    if (existingPreToolUse !== undefined && !Array.isArray(existingPreToolUse)) {
      return 'Claude hooks.PreToolUse must be an array';
    }

    const preToolUse = [...(existingPreToolUse ?? [])];
    if (preToolUse.some((entry) => containsManagedHook(entry))) {
      return 'An agentkeeper PreToolUse hook exists without a valid manifest; ownership is ambiguous';
    }

    const command = `${hookCommandPrefix(
      this.options.runtimeExecutable,
      this.options.agentkeeperEntrypoint,
      this.options.shell,
    )} hook pretooluse`;
    const managedHook = {
      matcher: '*',
      hooks: [{ type: 'command', command }],
    };

    if (raw === null) {
      hooks['PreToolUse'] = [managedHook];
      return { content: `${JSON.stringify({ ...settings, hooks }, null, 2)}\n` };
    }

    // Do not serialise the user's settings object. A span-aware insertion
    // leaves every pre-existing byte (including whitespace and hook commands)
    // untouched and adds exactly one property/array element.
    try {
      return { content: insertClaudeHook(raw, managedHook) };
    } catch (error) {
      return error instanceof Error
        ? `Claude settings cannot be merged safely: ${error.message}`
        : 'Claude settings cannot be merged safely';
    }
  }

  private async loadManifest(): Promise<LoadedManifest> {
    const raw = await this.files.read(this.manifestPath);
    if (raw === null) return { kind: 'absent' };
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!isRecord(parsed) || typeof parsed['checksum'] !== 'string' || !isRecord(parsed['payload'])) {
        return { kind: 'invalid', message: 'Managed manifest has an invalid envelope' };
      }
      const payloadUnknown = parsed['payload'];
      const expected = checksum(JSON.stringify(payloadUnknown));
      if (parsed['checksum'] !== expected) {
        return { kind: 'invalid', message: 'Managed manifest checksum does not match its payload' };
      }
      const payload = parsePayload(payloadUnknown);
      if (typeof payload === 'string') return { kind: 'invalid', message: payload };
      return { kind: 'valid', raw, payload };
    } catch {
      return { kind: 'invalid', message: 'Managed manifest is not valid JSON' };
    }
  }

  private validateManifest(
    payload: ManifestPayload,
    operation: InstallationOperation,
  ): string | null {
    if (payload.shell !== this.options.shell) {
      return 'Manifest shell does not match the configured installation shell';
    }
    if (
      operation !== 'deactivate' &&
      (payload.runtimeExecutable !== this.options.runtimeExecutable.value ||
        payload.agentkeeperEntrypoint !== this.options.agentkeeperEntrypoint.value)
    ) {
      return 'Manifest command pair does not match the trusted runtime and CLI entrypoint';
    }
    // `repair` is excluded on purpose: reconciling managed state with the
    // installed configuration is precisely its job, and every release that
    // changes a hook or shim body changes this checksum. Refusing here left
    // `deactivate` + `activate` as the only way forward — the same end state
    // reached through a window with no protection at all, so the refusal made
    // the safe path harder than the unsafe one while preventing nothing. The
    // command pair above stays strict: which binary is trusted is not
    // something repair may quietly redefine.
    if (
      operation !== 'deactivate' &&
      operation !== 'repair' &&
      payload.configurationChecksum !== this.configurationChecksum()
    ) {
      return 'Installation options differ from the options recorded by the manifest; run `agentkeeper repair` to reconcile them';
    }

    const expected =
      operation === 'deactivate' ? this.allowedArtifacts() : this.expectedArtifacts();
    const seen = new Set<string>();
    for (const entry of payload.entries) {
      if (seen.has(entry.id)) return `Duplicate manifest entry ${JSON.stringify(entry.id)}`;
      seen.add(entry.id);
      const artifact = expected.get(entry.id);
      if (artifact === undefined) return `Unknown manifest artifact ${JSON.stringify(entry.id)}`;
      if (artifact.path.value !== entry.path || artifact.ownership !== entry.ownership) {
        return `Manifest artifact ${JSON.stringify(entry.id)} points outside its configured path`;
      }
      if (entry.mode !== artifact.mode) {
        return `Manifest artifact ${JSON.stringify(entry.id)} has an unexpected file mode`;
      }
      if (!isChecksum(entry.installedChecksum)) {
        return `Manifest artifact ${JSON.stringify(entry.id)} has an invalid installed checksum`;
      }
      if (entry.originalChecksum !== null && !isChecksum(entry.originalChecksum)) {
        return `Manifest artifact ${JSON.stringify(entry.id)} has an invalid original checksum`;
      }
      if ((entry.originalChecksum === null) !== (entry.backupPath === null)) {
        return `Manifest artifact ${JSON.stringify(entry.id)} has an incomplete backup reference`;
      }
      if (entry.backupPath !== null && entry.backupPath !== this.backupPath(artifact.path).value) {
        return `Manifest artifact ${JSON.stringify(entry.id)} has an unexpected backup path`;
      }
      if (artifact.ownership === 'owned' && operation !== 'deactivate') {
        if (entry.originalChecksum !== null || entry.backupPath !== null) {
          return `Owned artifact ${JSON.stringify(entry.id)} unexpectedly claims an original file`;
        }
        // Not a tamper signal: this compares what the manifest recorded with
        // what *this build* generates, so any release that edits a hook or
        // shim body lands here. Repair reconciles it; whether the file on disk
        // still matches the manifest is a separate check, and stays strict.
        if (
          operation !== 'repair' &&
          (checksum(artifact.content) !== entry.installedChecksum || artifact.mode !== entry.mode)
        ) {
          return `Owned artifact ${JSON.stringify(entry.id)} does not match current generated content`;
        }
      }
    }

    if (operation !== 'deactivate') {
      for (const artifact of this.ownedArtifacts()) {
        // A release that introduces a managed artifact leaves every existing
        // manifest without it. Installing what is missing is repair's job.
        if (!seen.has(artifact.id) && operation !== 'repair') {
          return `Manifest is missing owned artifact ${JSON.stringify(artifact.id)}`;
        }
      }
    } else if (!seen.has(`shell-init:${this.options.shell}`)) {
      return 'Manifest is missing the managed shell initialisation artifact';
    }
    if (!seen.has('claude-settings')) return 'Manifest is missing the Claude settings integration';
    return null;
  }

  private expectedArtifacts(): ReadonlyMap<string, DesiredArtifact> {
    const artifacts = new Map(this.ownedArtifacts().map((artifact) => [artifact.id, artifact]));
    for (const [index, path] of this.options.profiles.entries()) {
      artifacts.set(`profile:${this.options.shell}:${index}`, {
        id: `profile:${this.options.shell}:${index}`,
        path,
        ownership: 'shared',
        content: '',
        mode: null,
      });
    }
    artifacts.set('claude-settings', {
      id: 'claude-settings',
      path: this.options.claudeSettings,
      ownership: 'shared',
      content: '',
      mode: null,
    });
    return artifacts;
  }

  /** Safe path vocabulary used when original agent binaries no longer exist. */
  private allowedArtifacts(): ReadonlyMap<string, DesiredArtifact> {
    const shimDirectory = this.options.stateDir.join(`shims/${this.options.shell}`);
    const shellExtension = this.options.shell === 'posix' ? 'sh' : 'ps1';
    const artifacts = new Map<string, DesiredArtifact>();
    artifacts.set(`shell-init:${this.options.shell}`, {
      id: `shell-init:${this.options.shell}`,
      path: this.options.stateDir.join(`shell/agentkeeper.${shellExtension}`),
      ownership: 'owned',
      content: '',
      mode: 0o600,
    });
    for (const agent of MANAGED_AGENTS) {
      artifacts.set(`shim:${this.options.shell}:${agent}`, {
        id: `shim:${this.options.shell}:${agent}`,
        path: shimDirectory.join(`${agent}${this.options.shell === 'posix' ? '' : '.ps1'}`),
        ownership: 'owned',
        content: '',
        mode: this.options.shell === 'posix' ? 0o700 : 0o600,
      });
      if (this.options.shell === 'powershell') {
        artifacts.set(`shim:cmd:${agent}`, {
          id: `shim:cmd:${agent}`,
          path: shimDirectory.join(`${agent}.cmd`),
          ownership: 'owned',
          content: '',
          mode: 0o600,
        });
      }
    }
    for (const artifact of this.options.additionalOwnedArtifacts ?? []) {
      artifacts.set(artifact.id, {
        id: artifact.id,
        path: artifact.path,
        ownership: 'owned',
        content: '',
        mode: artifact.mode ?? 0o600,
      });
    }
    for (const [index, path] of this.options.profiles.entries()) {
      artifacts.set(`profile:${this.options.shell}:${index}`, {
        id: `profile:${this.options.shell}:${index}`,
        path,
        ownership: 'shared',
        content: '',
        mode: null,
      });
    }
    artifacts.set('claude-settings', {
      id: 'claude-settings',
      path: this.options.claudeSettings,
      ownership: 'shared',
      content: '',
      mode: null,
    });
    return artifacts;
  }

  private async backupConflicts(payload: ManifestPayload): Promise<InstallationConflict[]> {
    const backedUpEntries = payload.entries.filter(
      (entry): entry is ManifestEntry & { backupPath: string; originalChecksum: string } =>
        entry.backupPath !== null && entry.originalChecksum !== null,
    );
    const contents = await Promise.all(
      backedUpEntries.map((entry) => this.files.read(AbsolutePath.of(entry.backupPath))),
    );
    return backedUpEntries.flatMap((entry, index) => {
      const content = contents[index] as string | null;
      if (content !== null && checksum(content) === entry.originalChecksum) return [];
      const path = AbsolutePath.of(entry.backupPath);
      return [
        this.conflict(
          'backup-drift',
          path,
          `The byte-exact backup for ${entry.id} is missing or has changed`,
        ),
      ];
    });
  }

  private duplicatePathConflicts(candidates: readonly CandidateArtifact[]): InstallationConflict[] {
    const conflicts: InstallationConflict[] = [];
    const seen = new Set<string>();
    for (const candidate of candidates) {
      if (seen.has(candidate.path.value)) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            candidate.path,
            'Two managed artifacts were configured for the same path',
          ),
        );
      }
      seen.add(candidate.path.value);
    }
    return conflicts;
  }

  private duplicateChangePathConflicts(
    changes: readonly InstallationChange[],
  ): InstallationConflict[] {
    const conflicts: InstallationConflict[] = [];
    const seen = new Set<string>();
    for (const planned of changes) {
      if (seen.has(planned.path.value)) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            planned.path,
            'A managed target, backup, or manifest resolves to the same path as another artifact',
          ),
        );
      }
      seen.add(planned.path.value);
    }
    return conflicts;
  }

  private configurationConflicts(): InstallationConflict[] {
    const shimDirectory = this.options.stateDir.join(`shims/${this.options.shell}`);
    const conflicts: InstallationConflict[] = [];
    const executables = [
      this.options.runtimeExecutable,
      this.options.agentkeeperEntrypoint,
      ...this.agentTargets().map(([, target]) => target),
    ];
    if (this.agentTargets().length === 0) {
      conflicts.push(
        this.conflict(
          'configuration-mismatch',
          this.options.stateDir,
          'No supported agent executable was found before the shim directory entered PATH',
        ),
      );
    }
    for (const managedPath of [
      this.options.stateDir,
      ...this.options.profiles,
      this.options.claudeSettings,
      ...(this.options.additionalOwnedArtifacts ?? []).map((artifact) => artifact.path),
    ]) {
      if (!this.options.home.contains(managedPath)) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            managedPath,
            'Install-once state and shared integrations must stay inside the configured user home',
          ),
        );
      }
    }
    const artifactIds = new Set<string>();
    for (const artifact of this.ownedArtifacts()) {
      if (artifactIds.has(artifact.id)) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            artifact.path,
            `Duplicate managed artifact id ${JSON.stringify(artifact.id)}`,
          ),
        );
      }
      artifactIds.add(artifact.id);
    }
    for (const executable of executables) {
      if (shimDirectory.contains(executable)) {
        conflicts.push(
          this.conflict(
            'configuration-mismatch',
            executable,
            'A resolved executable points inside the managed shim directory and would recurse',
          ),
        );
      }
    }
    return conflicts;
  }

  private driftConflict(entry: ManifestEntry, path: AbsolutePath): InstallationConflict {
    return this.conflict(
      entry.ownership === 'shared' ? 'shared-file-drift' : 'managed-file-drift',
      path,
      entry.ownership === 'shared'
        ? 'A user-owned shared file changed after activation; it will not be overwritten automatically'
        : 'A managed artifact changed after activation; use the repair operation',
    );
  }

  private backupPath(path: AbsolutePath): AbsolutePath {
    const digest = checksum(`agentkeeper-original\0${path.value}`).slice('sha256:'.length);
    return this.options.stateDir.join(`installation/backups/${digest}.original`);
  }

  private configurationChecksum(): string {
    const extensions = (this.options.additionalOwnedArtifacts ?? []).map((artifact) => ({
      id: artifact.id,
      path: artifact.path.value,
      contentChecksum: checksum(artifact.content),
      mode: artifact.mode ?? 0o600,
    }));
    return checksum(
      JSON.stringify({
        shell: this.options.shell,
        stateDir: this.options.stateDir.value,
        runtimeExecutable: this.options.runtimeExecutable.value,
        agentkeeperEntrypoint: this.options.agentkeeperEntrypoint.value,
        agentExecutables: Object.fromEntries(
          this.agentTargets().map(([agent, target]) => [agent, target.value]),
        ),
        profiles: this.options.profiles.map((path) => path.value),
        claudeSettings: this.options.claudeSettings.value,
        ...(extensions.length === 0 ? {} : { extensions }),
      }),
    );
  }

  private agentTargets(): readonly [ManagedAgent, AbsolutePath][] {
    return MANAGED_AGENTS.flatMap((agent) => {
      const target = this.options.agentExecutables[agent];
      return target === undefined ? [] : [[agent, target] as [ManagedAgent, AbsolutePath]];
    });
  }

  private conflict(
    code: InstallationConflictCode,
    path: AbsolutePath,
    message: string,
  ): InstallationConflict {
    return { code, path, message };
  }

  private successfulPlan(
    operation: InstallationOperation,
    changes: readonly InstallationChange[],
  ): InstallationPlan {
    return { operation, changes, conflicts: [] };
  }

  private failedPlan(
    operation: InstallationOperation,
    conflicts: readonly InstallationConflict[],
  ): InstallationPlan {
    // All-or-nothing starts at planning: a conflicted plan never contains a
    // tempting safe-looking subset that a caller could accidentally execute.
    return { operation, changes: [], conflicts };
  }
}

function change(
  path: AbsolutePath,
  before: string | null,
  after: string | null,
  summary: string,
  mode: number | null,
): InstallationChange {
  return mode === null
    ? { path, before, after, summary }
    : { path, before, after, summary, mode };
}

function checksum(content: string): string {
  return ContentHash.fromContent(content).toString();
}

function isChecksum(value: string): boolean {
  try {
    ContentHash.parse(value);
    return true;
  } catch {
    return false;
  }
}

function serialiseManifest(payload: ManifestPayload): string {
  const envelope: ManifestEnvelope = {
    checksum: checksum(JSON.stringify(payload)),
    payload,
  };
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

function parsePayload(raw: Record<string, unknown>): ManifestPayload | string {
  if (
    raw['schema'] !== MANIFEST_SCHEMA ||
    raw['version'] !== MANIFEST_VERSION ||
    (raw['shell'] !== 'posix' && raw['shell'] !== 'powershell') ||
    typeof raw['runtimeExecutable'] !== 'string' ||
    typeof raw['agentkeeperEntrypoint'] !== 'string' ||
    typeof raw['configurationChecksum'] !== 'string' ||
    !isChecksum(raw['configurationChecksum']) ||
    !Array.isArray(raw['entries'])
  ) {
    return 'Managed manifest payload has an unsupported schema';
  }

  const entries: ManifestEntry[] = [];
  for (const item of raw['entries']) {
    if (
      !isRecord(item) ||
      typeof item['id'] !== 'string' ||
      typeof item['path'] !== 'string' ||
      (item['ownership'] !== 'owned' && item['ownership'] !== 'shared') ||
      typeof item['installedChecksum'] !== 'string' ||
      (item['originalChecksum'] !== null && typeof item['originalChecksum'] !== 'string') ||
      (item['backupPath'] !== null && typeof item['backupPath'] !== 'string') ||
      (item['mode'] !== null && typeof item['mode'] !== 'number')
    ) {
      return 'Managed manifest contains a malformed entry';
    }
    entries.push({
      id: item['id'],
      path: item['path'],
      ownership: item['ownership'],
      installedChecksum: item['installedChecksum'],
      originalChecksum: item['originalChecksum'],
      backupPath: item['backupPath'],
      mode: item['mode'],
    });
  }

  return {
    schema: MANIFEST_SCHEMA,
    version: MANIFEST_VERSION,
    shell: raw['shell'],
    runtimeExecutable: raw['runtimeExecutable'],
    agentkeeperEntrypoint: raw['agentkeeperEntrypoint'],
    configurationChecksum: raw['configurationChecksum'],
    entries,
  };
}

function renderPosixShim(
  runtime: AbsolutePath,
  entrypoint: AbsolutePath,
  target: AbsolutePath,
): string {
  return [
    '#!/bin/sh',
    '# Generated and checksum-managed by agentkeeper.',
    'set -eu',
    `exec ${posixQuote(runtime.value)} ${posixQuote(entrypoint.value)} run -- ${posixQuote(target.value)} "$@"`,
    '',
  ].join('\n');
}

function renderPowerShellShim(
  runtime: AbsolutePath,
  entrypoint: AbsolutePath,
  target: AbsolutePath,
): string {
  return [
    '# Generated and checksum-managed by agentkeeper.',
    "$ErrorActionPreference = 'Stop'",
    `& ${powerShellQuote(runtime.value)} ${powerShellQuote(entrypoint.value)} run -- ${powerShellQuote(target.value)} @args`,
    'exit $LASTEXITCODE',
    '',
  ].join('\r\n');
}

/** `.cmd` is on Windows PATHEXT, so interception does not depend on .ps1 policy. */
function renderWindowsCommandShim(
  runtime: AbsolutePath,
  entrypoint: AbsolutePath,
  target: AbsolutePath,
): string {
  return [
    '@echo off',
    'setlocal DisableDelayedExpansion',
    'rem Generated and checksum-managed by agentkeeper.',
    `${windowsBatchQuote(runtime.value)} ${windowsBatchQuote(entrypoint.value)} run -- ${windowsBatchQuote(target.value)} %*`,
    'exit /b %ERRORLEVEL%',
    '',
  ].join('\r\n');
}

function renderPosixShellInit(shimDirectory: AbsolutePath): string {
  const directory = posixQuote(shimDirectory.value);
  return [
    '# Generated and checksum-managed by agentkeeper.',
    `_agentkeeper_shim_directory=${directory}`,
    `case ":\${PATH}:" in`,
    '  *":${_agentkeeper_shim_directory}:"*) ;;',
    '  *) export PATH="${_agentkeeper_shim_directory}:${PATH}" ;;',
    'esac',
    'unset _agentkeeper_shim_directory',
    '',
  ].join('\n');
}

function renderPowerShellInit(shimDirectory: AbsolutePath): string {
  return [
    '# Generated and checksum-managed by agentkeeper.',
    `$agentkeeperShimDirectory = ${powerShellQuote(shimDirectory.value)}`,
    "$agentkeeperPathEntries = $env:PATH -split [IO.Path]::PathSeparator",
    'if ($agentkeeperPathEntries -notcontains $agentkeeperShimDirectory) {',
    '  $env:PATH = $agentkeeperShimDirectory + [IO.Path]::PathSeparator + $env:PATH',
    '}',
    'Remove-Variable agentkeeperPathEntries, agentkeeperShimDirectory -ErrorAction SilentlyContinue',
    '',
  ].join('\r\n');
}

function appendProfileBlock(before: string | null, block: string): string {
  if (before === null || before.length === 0) return block;
  const newline = before.includes('\r\n') ? '\r\n' : '\n';
  const normalisedBlock = newline === '\n' ? block : block.replace(/\n/g, '\r\n');
  return `${before}${before.endsWith('\n') ? '' : newline}${normalisedBlock}`;
}

function hasAnyManagedMarker(content: string): boolean {
  return content.includes(MANAGED_MARKER_START) || content.includes(MANAGED_MARKER_END);
}

function containsManagedHook(value: unknown): boolean {
  if (Array.isArray(value)) return value.some((entry) => containsManagedHook(entry));
  if (!isRecord(value)) return false;
  if (
    typeof value['command'] === 'string' &&
    /(?:^|\s)hook\s+pretooluse(?:\s|$)/i.test(value['command'])
  ) {
    return true;
  }
  return Object.values(value).some((entry) => containsManagedHook(entry));
}

function posixQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function powerShellQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function windowsBatchQuote(value: string): string {
  return `"${value.replace(/%/g, '%%')}"`;
}

function hookCommandPrefix(
  runtime: AbsolutePath,
  entrypoint: AbsolutePath,
  shell: 'posix' | 'powershell',
): string {
  return shell === 'posix'
    ? `${posixQuote(runtime.value)} ${posixQuote(entrypoint.value)}`
    : `& ${powerShellQuote(runtime.value)} ${powerShellQuote(entrypoint.value)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface JsonPropertySpan {
  readonly key: string;
  readonly value: JsonSpan;
}

type JsonSpan =
  | {
      readonly kind: 'object';
      readonly start: number;
      readonly end: number;
      readonly properties: readonly JsonPropertySpan[];
    }
  | {
      readonly kind: 'array';
      readonly start: number;
      readonly end: number;
      readonly items: readonly JsonSpan[];
    }
  | { readonly kind: 'scalar'; readonly start: number; readonly end: number };

/** Minimal location-preserving JSON parser used only to find safe insertion points. */
class JsonSpanParser {
  private offset = 0;

  private constructor(private readonly source: string) {}

  static parse(source: string): JsonSpan {
    const parser = new JsonSpanParser(source);
    const root = parser.value();
    parser.whitespace();
    if (parser.offset !== source.length) throw new Error('unexpected data after the root value');
    return root;
  }

  private value(): JsonSpan {
    this.whitespace();
    const start = this.offset;
    const token = this.source[this.offset];
    if (token === '{') return this.object();
    if (token === '[') return this.array();
    if (token === '"') {
      this.string();
      return { kind: 'scalar', start, end: this.offset };
    }

    while (this.offset < this.source.length && !/[\s,}\]]/.test(this.source[this.offset] as string)) {
      this.offset += 1;
    }
    if (this.offset === start) throw new Error(`unexpected token at byte ${start}`);
    // JSON.parse already validated the document; parsing the token here keeps
    // this scanner defensive if it is ever reused independently.
    JSON.parse(this.source.slice(start, this.offset)) as unknown;
    return { kind: 'scalar', start, end: this.offset };
  }

  private object(): Extract<JsonSpan, { kind: 'object' }> {
    const start = this.offset;
    this.offset += 1;
    this.whitespace();
    const properties: JsonPropertySpan[] = [];
    if (this.source[this.offset] === '}') {
      this.offset += 1;
      return { kind: 'object', start, end: this.offset, properties };
    }

    while (this.offset < this.source.length) {
      this.whitespace();
      const key = this.string();
      this.whitespace();
      this.expect(':');
      const value = this.value();
      properties.push({ key, value });
      this.whitespace();
      if (this.source[this.offset] === '}') {
        this.offset += 1;
        return { kind: 'object', start, end: this.offset, properties };
      }
      this.expect(',');
    }
    throw new Error('unterminated object');
  }

  private array(): Extract<JsonSpan, { kind: 'array' }> {
    const start = this.offset;
    this.offset += 1;
    this.whitespace();
    const items: JsonSpan[] = [];
    if (this.source[this.offset] === ']') {
      this.offset += 1;
      return { kind: 'array', start, end: this.offset, items };
    }

    while (this.offset < this.source.length) {
      items.push(this.value());
      this.whitespace();
      if (this.source[this.offset] === ']') {
        this.offset += 1;
        return { kind: 'array', start, end: this.offset, items };
      }
      this.expect(',');
    }
    throw new Error('unterminated array');
  }

  private string(): string {
    const start = this.offset;
    this.expect('"');
    while (this.offset < this.source.length) {
      const token = this.source[this.offset];
      if (token === '"') {
        this.offset += 1;
        return JSON.parse(this.source.slice(start, this.offset)) as string;
      }
      if (token === '\\') this.offset += 1;
      this.offset += 1;
    }
    throw new Error('unterminated string');
  }

  private expect(token: string): void {
    if (this.source[this.offset] !== token) {
      throw new Error(`expected ${JSON.stringify(token)} at byte ${this.offset}`);
    }
    this.offset += 1;
  }

  private whitespace(): void {
    while (/\s/.test(this.source[this.offset] ?? '')) this.offset += 1;
  }
}

function insertClaudeHook(raw: string, managedHook: Readonly<Record<string, unknown>>): string {
  const root = JsonSpanParser.parse(raw);
  if (root.kind !== 'object') throw new Error('root is not an object');
  const hooksProperties = root.properties.filter((property) => property.key === 'hooks');
  if (hooksProperties.length > 1) throw new Error('duplicate hooks properties are ambiguous');

  const hookJson = JSON.stringify(managedHook);
  const hooksProperty = hooksProperties[0];
  if (hooksProperty === undefined) {
    const addition = `${root.properties.length === 0 ? '' : ','}"hooks":{"PreToolUse":[${hookJson}]}`;
    return insertAt(raw, root.end - 1, addition);
  }
  if (hooksProperty.value.kind !== 'object') throw new Error('hooks is not an object');

  const preToolUseProperties = hooksProperty.value.properties.filter(
    (property) => property.key === 'PreToolUse',
  );
  if (preToolUseProperties.length > 1) {
    throw new Error('duplicate PreToolUse properties are ambiguous');
  }
  const preToolUse = preToolUseProperties[0];
  if (preToolUse === undefined) {
    const addition = `${hooksProperty.value.properties.length === 0 ? '' : ','}"PreToolUse":[${hookJson}]`;
    return insertAt(raw, hooksProperty.value.end - 1, addition);
  }
  if (preToolUse.value.kind !== 'array') throw new Error('PreToolUse is not an array');

  const addition = `${preToolUse.value.items.length === 0 ? '' : ','}${hookJson}`;
  return insertAt(raw, preToolUse.value.end - 1, addition);
}

function insertAt(source: string, offset: number, addition: string): string {
  return `${source.slice(0, offset)}${addition}${source.slice(offset)}`;
}
