export type NetworkProtocol = 'tcp' | 'udp' | 'ip';
export type NetworkHost = 'any' | 'loopback';
export type NetworkPort = number | '*';

/**
 * Outbound network permission.
 *
 * Host granularity is intentionally limited to `any` / `loopback`. Measured on
 * macOS 26: Seatbelt rejects a hostname in a network address outright
 * ("host must be * or localhost"), so a per-domain allowlist is not something
 * this layer can honestly express. Domain-level filtering needs a proxy and is
 * out of scope for 1.0 — see README, "Honest limits".
 */
export class NetworkRule {
  private constructor(
    readonly protocol: NetworkProtocol,
    readonly host: NetworkHost,
    readonly port: NetworkPort,
  ) {
    Object.freeze(this);
  }

  static tcp(port: NetworkPort): NetworkRule {
    return new NetworkRule('tcp', 'any', assertPort(port));
  }

  static udp(port: NetworkPort): NetworkRule {
    return new NetworkRule('udp', 'any', assertPort(port));
  }

  /** Everything on the loopback interface — local MCP servers, dev servers. */
  static loopback(): NetworkRule {
    return new NetworkRule('ip', 'loopback', '*');
  }

  equals(other: NetworkRule): boolean {
    return (
      this.protocol === other.protocol && this.host === other.host && this.port === other.port
    );
  }

  toString(): string {
    const host = this.host === 'loopback' ? 'localhost' : '*';
    return `${this.protocol}://${host}:${this.port}`;
  }
}

function assertPort(port: NetworkPort): NetworkPort {
  if (port === '*') return port;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Invalid port: ${JSON.stringify(port)}`);
  }
  return port;
}
