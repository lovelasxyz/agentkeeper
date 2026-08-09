import type { EnvironmentPolicy } from './EnvironmentPolicy.js';

/** Immutable output of the environment boundary. */
export class EnvironmentSanitizationResult {
  readonly environment: Readonly<Record<string, string>>;
  readonly removedNames: readonly string[];
  readonly removedCount: number;

  constructor(environment: Record<string, string>, removedNames: readonly string[]) {
    this.environment = Object.freeze({ ...environment });
    this.removedNames = Object.freeze([...removedNames]);
    this.removedCount = this.removedNames.length;
    Object.freeze(this);
  }
}

/**
 * Removes ambient authority before a command reaches any sandbox backend.
 *
 * It is deliberately a pure transformation: the caller's environment is not
 * mutated, output order is deterministic, and neither names nor values are
 * logged here. The application layer may audit removed names, never values.
 */
export class EnvironmentSanitizer {
  sanitize(
    source: Readonly<Record<string, string>>,
    policy: EnvironmentPolicy,
  ): EnvironmentSanitizationResult {
    const environment: Record<string, string> = {};
    const removedNames: string[] = [];

    for (const name of Object.keys(source).sort()) {
      const value = source[name];
      if (!policy.allows(name) || typeof value !== 'string') {
        removedNames.push(name);
        continue;
      }
      environment[name] = value;
    }

    return new EnvironmentSanitizationResult(environment, removedNames);
  }
}
