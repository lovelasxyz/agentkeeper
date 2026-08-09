import { describe, expect, it } from 'vitest';
import { NetworkRule } from '../../../../src/domain/value-objects/NetworkRule.js';
import {
  DestinationGuard,
  parseConnectAuthority,
} from '../../../../src/infrastructure/network/DestinationGuard.js';

describe('DestinationGuard', () => {
  const guard = new DestinationGuard();
  const providers = [
    NetworkRule.destination('api.openai.com', 443),
    NetworkRule.destination('*.anthropic.com', 443),
  ];

  it('authorises only a configured host and port after DNS validation', () => {
    expect(
      guard.authorize('api.openai.com', 443, providers, [
        { address: '104.18.7.192', family: 4 },
        { address: '2606:4700::6812:7c0', family: 6 },
      ]),
    ).toMatchObject({ allowed: true, pinnedAddress: '104.18.7.192' });
    expect(
      guard.authorize('api.openai.com', 80, providers, [
        { address: '104.18.7.192', family: 4 },
      ]),
    ).toMatchObject({ allowed: false, reason: 'destination-not-allowed' });
  });

  it.each([
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '192.168.1.1',
    '198.18.0.1',
    '224.0.0.1',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
    'ff02::1',
  ])('blocks private, local, metadata and reserved address %s', (address) => {
    expect(
      guard.authorize('api.openai.com', 443, providers, [
        { address, family: address.includes(':') ? 6 : 4 },
      ]),
    ).toMatchObject({ allowed: false, reason: 'non-public-address' });
  });

  it('rejects the whole answer set when one DNS answer is private (rebinding defense)', () => {
    expect(
      guard.authorize('api.openai.com', 443, providers, [
        { address: '104.18.7.192', family: 4 },
        { address: '169.254.169.254', family: 4 },
      ]),
    ).toMatchObject({ allowed: false, reason: 'non-public-address' });
  });

  it('permits loopback only through an explicit loopback capability', () => {
    expect(
      guard.authorize('localhost', 3000, [NetworkRule.loopback()], [
        { address: '127.0.0.1', family: 4 },
      ]),
    ).toMatchObject({ allowed: true, pinnedAddress: '127.0.0.1' });
    expect(
      guard.authorize('localhost', 3000, providers, [
        { address: '127.0.0.1', family: 4 },
      ]),
    ).toMatchObject({ allowed: false });
  });

  it('parses CONNECT authority without accepting URL/userinfo/path ambiguity', () => {
    expect(parseConnectAuthority('api.openai.com:443')).toEqual({
      host: 'api.openai.com',
      port: 443,
    });
    expect(parseConnectAuthority('[2606:4700::6812:7c0]:443')).toEqual({
      host: '2606:4700::6812:7c0',
      port: 443,
    });
    for (const value of ['api.openai.com', 'https://api.openai.com:443', 'u@h:443',
      'h:0', 'h:65536', 'h:443/path', 'h:443 extra']) {
      expect(() => parseConnectAuthority(value), value).toThrow();
    }
  });
});
