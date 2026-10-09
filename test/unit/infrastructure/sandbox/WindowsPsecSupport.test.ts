import { describe, expect, it } from 'vitest';
import { assessWindowsPsecHost } from '../../../../src/infrastructure/sandbox/WindowsPsecSupport.js';

const host = {
  kind: 'agentkeeper.psec-host.v1',
  os: { build: 26100, revision: 9550, workstation: true },
  psec: {
    exportsAvailable: true,
    versionQuerySucceeded: true,
    supportQuerySucceeded: true,
    available: true,
    major: 1,
    minor: 1,
    supportFlags: '0xd',
  },
};

describe('Windows PSEC host prerequisites', () => {
  it('qualifies the API contract and all required rights, rather than the Windows version alone', () => {
    expect(assessWindowsPsecHost(host)).toEqual({ supported: true });
  });

  it('does not qualify an updated Windows version with an incomplete native policy contract', () => {
    expect(assessWindowsPsecHost({ ...host, psec: { ...host.psec, minor: 0 } })).toMatchObject({
      supported: false, code: 'windows.psec-contract-unsupported',
    });
  });

  it.each([
    ['0xc', 'windows.psec-filesystem-deny-unavailable'],
    ['0x9', 'windows.psec-enumeration-unavailable'],
    ['0x5', 'windows.psec-ingress-unavailable'],
  ])('refuses missing required feature flags %s', (supportFlags, code) => {
    expect(assessWindowsPsecHost({ ...host, psec: { ...host.psec, supportFlags } })).toMatchObject({
      supported: false, code,
    });
  });

  it.each(['exportsAvailable', 'versionQuerySucceeded', 'supportQuerySucceeded', 'available']) (
    'refuses failed %s before any workload can run', (field) => {
      expect(assessWindowsPsecHost({ ...host, psec: { ...host.psec, [field]: false } })).toMatchObject({
        supported: false, code: 'windows.psec-api-unavailable',
      });
    },
  );

  it('does not classify Windows Server as the approved Windows 11 workstation target', () => {
    expect(assessWindowsPsecHost({ ...host, os: { ...host.os, workstation: false } })).toMatchObject({
      supported: false, code: 'windows.psec-platform-unsupported',
    });
  });

  it.each([null, {}, { ...host, kind: 'future-protocol' },
    { ...host, psec: { ...host.psec, supportFlags: '0x10000000000000000' } },
    { ...host, psec: { ...host.psec, minor: '1' } },
    { ...host, os: { ...host.os, build: -1 } },
  ])('fails closed on malformed native reports %#', (report) => {
    expect(assessWindowsPsecHost(report)).toMatchObject({
      supported: false, code: 'windows.psec-probe-invalid',
    });
  });

  it('preserves all 64 capability bits without lossy Number conversion', () => {
    expect(assessWindowsPsecHost({ ...host, psec: { ...host.psec, supportFlags: '0x800000000000000d' } }))
      .toEqual({ supported: true });
  });
});
