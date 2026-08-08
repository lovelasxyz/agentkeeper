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

/**
 * `~/.agent-guard/config.json`, optional (spec §10.3).
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
    return new Configuration(DEFAULTS);
  }

  static async load(files: FileSystem, stateDir: AbsolutePath): Promise<Configuration> {
    const raw = await files.read(stateDir.join('config.json'));
    if (raw === null) return Configuration.defaults();

    try {
      const parsed = JSON.parse(raw) as Partial<ConfigurationDocument>;
      return new Configuration({
        ...DEFAULTS,
        ...parsed,
        sandbox: { ...DEFAULTS.sandbox, ...parsed.sandbox },
        rules: { ...DEFAULTS.rules, ...parsed.rules },
      });
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
    return this.document.watchRoots.map((raw) => AbsolutePath.fromUserPath(raw, home));
  }
}
