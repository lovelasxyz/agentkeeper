import { isIP } from 'node:net';
import type { NetworkRule } from '../../domain/value-objects/NetworkRule.js';

export interface ResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export type DestinationDenialReason =
  | 'destination-not-allowed'
  | 'dns-empty'
  | 'non-public-address'
  | 'loopback-resolution-mismatch';

export type DestinationAuthorization =
  | {
      readonly allowed: true;
      readonly pinnedAddress: string;
      readonly family: 4 | 6;
    }
  | { readonly allowed: false; readonly reason: DestinationDenialReason };

/**
 * Performs the security decision after DNS and before connect(2).
 *
 * Every answer is validated, not just the address selected for the socket. A
 * hostname that returns one public address and one metadata/private address is
 * rejected as a whole; the chosen public IP is then pinned into connect(2), so
 * a second resolver lookup cannot rebind the request after the check.
 */
export class DestinationGuard {
  authorize(
    host: string,
    port: number,
    rules: readonly NetworkRule[],
    addresses: readonly ResolvedAddress[],
  ): DestinationAuthorization {
    const loopbackRule = rules.find((rule) => rule.allowsLoopback && loopbackHost(host));
    const exactRule = rules.find(
      (rule) => rule.isExplicitDestination && rule.matches(host, port),
    );
    if (loopbackRule === undefined && exactRule === undefined) {
      return { allowed: false, reason: 'destination-not-allowed' };
    }
    if (addresses.length === 0) return { allowed: false, reason: 'dns-empty' };

    if (loopbackRule !== undefined) {
      if (!addresses.every((address) => isLoopbackAddress(address.address))) {
        return { allowed: false, reason: 'loopback-resolution-mismatch' };
      }
    } else if (!addresses.every((address) => isPublicAddress(address.address))) {
      return { allowed: false, reason: 'non-public-address' };
    }

    const selected = addresses[0] as ResolvedAddress;
    return { allowed: true, pinnedAddress: selected.address, family: selected.family };
  }
}

/** Strict CONNECT authority parser: no URLs, userinfo, paths or implicit ports. */
export function parseConnectAuthority(authority: string): { readonly host: string; readonly port: number } {
  if (
    authority.length === 0 ||
    authority.length > 512 ||
    /[\u0000-\u0020\u007f/@\\]/.test(authority)
  ) {
    throw new Error('Invalid CONNECT authority');
  }

  let host: string;
  let rawPort: string;
  if (authority.startsWith('[')) {
    const match = /^\[([^\]]+)]:(\d{1,5})$/.exec(authority);
    if (match === null || isIP(match[1] as string) !== 6) {
      throw new Error('Invalid bracketed IPv6 CONNECT authority');
    }
    host = match[1] as string;
    rawPort = match[2] as string;
  } else {
    const separator = authority.lastIndexOf(':');
    if (separator <= 0 || authority.indexOf(':') !== separator) {
      throw new Error('CONNECT authority must contain one explicit port');
    }
    host = authority.slice(0, separator).toLowerCase().replace(/\.$/, '');
    rawPort = authority.slice(separator + 1);
    if (!/^\d{1,5}$/.test(rawPort)) throw new Error('Invalid CONNECT port');
  }

  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('CONNECT port is outside 1..65535');
  }
  return { host, port };
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family !== 6) return false;

  const words = ipv6Words(address);
  if (words === null) return false;
  if (isIpv4Mapped(words)) {
    const ipv4 = `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
    return isPublicIpv4(ipv4);
  }
  // Global unicast is 2000::/3. Known special-purpose ranges inside it are
  // denied explicitly; everything outside global unicast is denied by default.
  if ((words[0] & 0xe000) !== 0x2000) return false;
  if (words[0] === 0x2001 && words[1] === 0x0db8) return false; // documentation
  if (words[0] === 0x2001 && words[1] === 0x0000) return false; // Teredo
  if (words[0] === 0x2001 && words[1] === 0x0002) return false; // benchmarking
  return true;
}

function isPublicIpv4(address: string): boolean {
  const octets = parseIpv4(address);
  if (octets === null) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
  if (a === 169 && b === 254) return false; // link-local and cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function isLoopbackAddress(address: string): boolean {
  if (isIP(address) === 4) return parseIpv4(address)?.[0] === 127;
  const words = ipv6Words(address);
  if (words === null) return false;
  if (words.slice(0, 7).every((word) => word === 0) && words[7] === 1) return true;
  if (!isIpv4Mapped(words)) return false;
  return words[6] >> 8 === 127;
}

function loopbackHost(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  return (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    isLoopbackAddress(normalized)
  );
}

function parseIpv4(address: string): [number, number, number, number] | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const values = parts.map(Number);
  if (values.some((value, index) => !/^\d{1,3}$/.test(parts[index] as string) || value < 0 || value > 255)) {
    return null;
  }
  return values as [number, number, number, number];
}

type Ipv6Words = readonly [number, number, number, number, number, number, number, number];

function ipv6Words(address: string): Ipv6Words | null {
  const normalized = address.toLowerCase();
  if (normalized.includes('%') || normalized.split('::').length > 2) return null;
  const [headRaw, tailRaw] = normalized.split('::');
  const head = parseIpv6Part(headRaw ?? '');
  const tail = parseIpv6Part(tailRaw ?? '');
  if (head === null || tail === null) return null;
  if (!normalized.includes('::')) return head.length === 8 ? (head as unknown as Ipv6Words) : null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return [...head, ...new Array<number>(missing).fill(0), ...tail] as unknown as Ipv6Words;
}

function parseIpv6Part(raw: string): number[] | null {
  if (raw.length === 0) return [];
  const tokens = raw.split(':');
  const words: number[] = [];
  for (const token of tokens) {
    if (token.includes('.')) {
      const ipv4 = parseIpv4(token);
      if (ipv4 === null || token !== tokens.at(-1)) return null;
      words.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
    words.push(Number.parseInt(token, 16));
  }
  return words;
}

function isIpv4Mapped(words: readonly number[]): boolean {
  return words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff;
}
