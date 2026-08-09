export type NetworkProtocol = 'tcp' | 'udp' | 'ip';
export type NetworkHost = 'any' | 'loopback' | string;
export type NetworkPort = number | '*';

/**
 * Outbound network permission.
 *
 * A destination capability, independent from the platform transport used to
 * enforce it. Exact and explicit wildcard hostnames are consumed by the
 * destination broker; `any` exists only to parse legacy profiles and is never
 * brokerable. Seatbelt/bubblewrap receive a separate, launcher-owned broker
 * transport, never these hostnames directly.
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

  /** Exact or `*.`-prefixed DNS destination. IP literals are deliberately not accepted. */
  static destination(host: string, port: number): NetworkRule {
    return new NetworkRule('tcp', normalizeDestinationHost(host), assertPort(port));
  }

  get isExplicitDestination(): boolean {
    return this.protocol === 'tcp' && this.host !== 'any' && this.host !== 'loopback';
  }

  get allowsLoopback(): boolean {
    return this.host === 'loopback';
  }

  matches(host: string, port: number): boolean {
    if (this.host === 'any') return this.protocol === 'tcp' && this.port === port;
    if (this.host === 'loopback') {
      return isLoopbackName(host) && (this.port === '*' || this.port === port);
    }
    if (this.protocol !== 'tcp' || this.port !== port) return false;

    let candidate: string;
    try {
      candidate = normalizeCandidateHost(host);
    } catch {
      return false;
    }
    if (!this.host.startsWith('*.')) return candidate === this.host;
    const suffix = this.host.slice(1); // includes the label-boundary dot
    return candidate.endsWith(suffix) && candidate.length > suffix.length;
  }

  equals(other: NetworkRule): boolean {
    return (
      this.protocol === other.protocol && this.host === other.host && this.port === other.port
    );
  }

  toString(): string {
    const host = this.host === 'loopback' ? 'localhost' : this.host === 'any' ? '*' : this.host;
    return `${this.protocol}://${host}:${this.port}`;
  }
}

function normalizeDestinationHost(raw: string): string {
  const wildcard = raw.startsWith('*.');
  if (raw.includes('*') && !wildcard) {
    throw new Error('A destination wildcard must occupy the complete left-most label (`*.`)');
  }
  const candidate = wildcard ? raw.slice(2) : raw;
  const normalized = normalizeCandidateHost(candidate);
  // `*.com` and similar public-suffix-wide rules are far too broad even when
  // written explicitly. Requiring at least two labels also catches typos.
  if (wildcard && !normalized.includes('.')) {
    throw new Error('A destination wildcard needs a registrable suffix, not a top-level domain');
  }
  return wildcard ? `*.${normalized}` : normalized;
}

function normalizeCandidateHost(raw: string): string {
  const normalized = raw.toLowerCase().replace(/\.$/, '');
  if (normalized.length === 0 || normalized.length > 253) {
    throw new Error('A network destination needs a valid DNS hostname');
  }
  if (!/^[\x00-\x7f]+$/.test(normalized)) {
    throw new Error('Use the ASCII/Punycode form of an internationalised hostname');
  }
  if (/[:/@\s\\]/.test(normalized) || /^\d+(?:\.\d+){3}$/.test(normalized)) {
    throw new Error('A network destination must be a DNS hostname, not a URL or IP literal');
  }
  const labels = normalized.split('.');
  if (
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new Error(`Invalid network destination hostname: ${JSON.stringify(raw)}`);
  }
  return normalized;
}

function isLoopbackName(raw: string): boolean {
  const normalized = raw.toLowerCase().replace(/\.$/, '');
  return normalized === 'localhost' || normalized.endsWith('.localhost');
}

function assertPort(port: NetworkPort): NetworkPort {
  if (port === '*') return port;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Invalid port: ${JSON.stringify(port)}`);
  }
  return port;
}
