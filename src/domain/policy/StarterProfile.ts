import { NetworkRule } from '../value-objects/NetworkRule.js';
import { ResourceRef } from '../value-objects/ResourceRef.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';

/** Plain shape of a `profiles/<id>.json` document. */
export interface StarterProfileSpec {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly reads: readonly string[];
  readonly writes: readonly string[];
  readonly network: readonly string[];
}

/**
 * A pre-filled allowlist for a common kind of work (spec §4.4), so the first
 * week is a handful of questions rather than a hundred.
 *
 * Profiles are data shipped with the package and extended by pull request —
 * never generated at runtime, never fetched.
 */
export class StarterProfile {
  private constructor(
    readonly id: string,
    readonly name: string,
    readonly description: string,
    private readonly readSpecs: readonly string[],
    private readonly writeSpecs: readonly string[],
    readonly network: readonly NetworkRule[],
  ) {
    Object.freeze(this);
  }

  static fromSpec(spec: StarterProfileSpec): StarterProfile {
    if (spec.id.trim().length === 0) throw new Error('A starter profile needs an id');
    return new StarterProfile(
      spec.id,
      spec.name,
      spec.description,
      Object.freeze([...spec.reads]),
      Object.freeze([...spec.writes]),
      Object.freeze(spec.network.map((raw) => parseNetwork(raw))),
    );
  }

  reads(home: AbsolutePath): readonly ResourceRef[] {
    return this.readSpecs.map((raw) => ResourceRef.parse(raw, home));
  }

  writes(home: AbsolutePath): readonly ResourceRef[] {
    return this.writeSpecs.map((raw) => ResourceRef.parse(raw, home));
  }
}

function parseNetwork(raw: string): NetworkRule {
  if (raw === 'loopback') return NetworkRule.loopback();
  const [protocol, port] = raw.split(':');
  const parsed = port === '*' ? '*' : Number(port);
  if (protocol === 'tcp') return NetworkRule.tcp(parsed);
  if (protocol === 'udp') return NetworkRule.udp(parsed);
  throw new Error(`Unknown network rule: ${JSON.stringify(raw)}`);
}
