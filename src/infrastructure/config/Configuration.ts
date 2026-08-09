import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import type { FileSystem } from '../../application/ports/index.js';

export interface ConfigurationDocument {
  readonly version: number;
  readonly sandbox: {
    readonly enabled: boolean;
    readonly starterProfile: string;
    readonly onUnavailable: 'warn' | 'fail';
  };
  readonly watchRoots: readonly string[];
  readonly watchHome: boolean;
  readonly strictMode: boolean;
  readonly notifications: 'native' | 'terminal' | 'none';
  readonly rules: Readonly<Record<string, { enabled: boolean }>>;
  readonly logRetentionDays: number;
}

const DEFAULTS: ConfigurationDocument = {
  version: 1,
  sandbox: { enabled: true, starterProfile: 'web', onUnavailable: 'fail' },
  watchRoots: [],
  watchHome: true,
  strictMode: false,
  notifications: 'native',
  // Family A is off by default (spec §6.7). The conflict with the interruption
  // budget of §1.5 is real, and it is stated rather than resolved by wishing.
  rules: { categoryA: { enabled: false } },
  logRetentionDays: 90,
};

const NOTIFICATIONS = new Set<ConfigurationDocument['notifications']>([
  'native',
  'terminal',
  'none',
]);

type JsonObject = Readonly<Record<string, unknown>>;

/**
 * `~/.agentkeeper/config.json`, optional (spec §10.3).
 *
 * Two things configuration is structurally incapable of doing: granting tier 2
 * access, and switching off a blocking rule. Both are enforced elsewhere —
 * `AccessTierResolver` and `RuleRegistry.enabled` — so a hand-edited config,
 * however creative, cannot widen the security model.
 */
export class Configuration implements RuleSwitches {
  private constructor(readonly document: ConfigurationDocument) {
    Object.freeze(this);
  }

  static defaults(): Configuration {
    return new Configuration(defaultDocument());
  }

  static async load(files: FileSystem, stateDir: AbsolutePath): Promise<Configuration> {
    const raw = await files.read(stateDir.join('config.json'));
    if (raw === null) return Configuration.defaults();

    try {
      return new Configuration(parseDocument(JSON.parse(raw) as unknown));
    } catch {
      // An unreadable config falls back to the defaults, which are the strict
      // ones. The alternative — refusing to start — would make a typo in an
      // optional file lock the user out of their own agent.
      return Configuration.defaults();
    }
  }

  isEnabled(ruleId: string): boolean {
    const explicit = this.document.rules[ruleId];
    if (explicit !== undefined) return explicit.enabled;

    const family = this.document.rules[`category${ruleId.charAt(3)}`];
    return family?.enabled ?? true;
  }

  get starterProfile(): string {
    return this.document.sandbox.starterProfile;
  }

  get onUnavailable(): 'warn' | 'fail' {
    return this.document.sandbox.onUnavailable;
  }

  get sandboxEnabled(): boolean {
    return this.document.sandbox.enabled;
  }

  get strictMode(): boolean {
    return this.document.strictMode;
  }

  watchRoots(home: AbsolutePath): readonly AbsolutePath[] {
    const roots: AbsolutePath[] = [];
    for (const raw of this.document.watchRoots) {
      try {
        roots.push(AbsolutePath.fromUserPath(raw, home));
      } catch {
        // A malformed optional watch root must not take down the daemon. It is
        // ignored here rather than guessed into a broader path.
      }
    }
    return roots;
  }
}

/**
 * Runtime validation for the hand-edited JSON boundary.
 *
 * TypeScript types disappear at runtime. Treating `JSON.parse()` as a
 * `ConfigurationDocument` allowed strings such as `"continue-anyway"` to
 * reach a fail-closed branch and select the unconfined runner. Every field is
 * therefore copied only after its shape and value have been checked; an
 * unknown value receives the narrower default, never a permissive guess.
 */
function parseDocument(value: unknown): ConfigurationDocument {
  if (!isObject(value) || value['version'] !== DEFAULTS.version) return defaultDocument();

  const sandbox = isObject(value['sandbox']) ? value['sandbox'] : {};
  const rules = parseRules(value['rules']);
  const watchRoots = Array.isArray(value['watchRoots'])
    ? value['watchRoots'].filter((entry): entry is string => typeof entry === 'string')
    : DEFAULTS.watchRoots;
  const notifications = value['notifications'];
  const retention = value['logRetentionDays'];

  return {
    version: DEFAULTS.version,
    sandbox: {
      enabled:
        typeof sandbox['enabled'] === 'boolean'
          ? sandbox['enabled']
          : DEFAULTS.sandbox.enabled,
      starterProfile:
        typeof sandbox['starterProfile'] === 'string' &&
        /^[a-z0-9][a-z0-9-]{0,63}$/i.test(sandbox['starterProfile'])
          ? sandbox['starterProfile']
          : DEFAULTS.sandbox.starterProfile,
      onUnavailable:
        sandbox['onUnavailable'] === 'warn' || sandbox['onUnavailable'] === 'fail'
          ? sandbox['onUnavailable']
          : DEFAULTS.sandbox.onUnavailable,
    },
    watchRoots: Object.freeze([...watchRoots]),
    watchHome:
      typeof value['watchHome'] === 'boolean' ? value['watchHome'] : DEFAULTS.watchHome,
    strictMode:
      typeof value['strictMode'] === 'boolean' ? value['strictMode'] : DEFAULTS.strictMode,
    notifications:
      typeof notifications === 'string' &&
      NOTIFICATIONS.has(notifications as ConfigurationDocument['notifications'])
        ? (notifications as ConfigurationDocument['notifications'])
        : DEFAULTS.notifications,
    rules,
    logRetentionDays:
      typeof retention === 'number' &&
      Number.isSafeInteger(retention) &&
      retention >= 1 &&
      retention <= 3_650
        ? retention
        : DEFAULTS.logRetentionDays,
  };
}

function parseRules(value: unknown): Readonly<Record<string, { enabled: boolean }>> {
  const parsed: Record<string, { enabled: boolean }> = {
    categoryA: { enabled: false },
  };
  if (!isObject(value)) return Object.freeze(parsed);

  for (const [id, candidate] of Object.entries(value)) {
    if (!isObject(candidate) || typeof candidate['enabled'] !== 'boolean') continue;
    parsed[id] = Object.freeze({ enabled: candidate['enabled'] });
  }
  return Object.freeze(parsed);
}

function defaultDocument(): ConfigurationDocument {
  return {
    ...DEFAULTS,
    sandbox: Object.freeze({ ...DEFAULTS.sandbox }),
    watchRoots: Object.freeze([...DEFAULTS.watchRoots]),
    rules: parseRules(DEFAULTS.rules),
  };
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
