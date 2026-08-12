import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  join(process.cwd(), 'native', 'windows', 'agentkeeper-sandbox.cpp'),
  'utf8',
);

describe('Windows native isolation contract (portable source audit)', () => {
  it('suppresses the windows.h min/max macros before including it', () => {
    // Without NOMINMAX, `windows.h` defines a function-like `max` macro that
    // breaks `std::numeric_limits<int>::max()` and fails the whole build.
    expect(source).toMatch(/#define\s+NOMINMAX/);
    expect(source.indexOf('#define NOMINMAX')).toBeLessThan(
      source.indexOf('#include <windows.h>'),
    );
  });

  it('has exactly one launch path and that path requires an AppContainer token', () => {
    expect(source.match(/\bCreateProcessW\s*\(/g)).toHaveLength(1);
    expect(source).toMatch(/SECURITY_CAPABILITIES\s+capabilities/);
    expect(source).toMatch(/PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES/);
    expect(source).toMatch(/capabilities\.AppContainerSid\s*=\s*sid\.get\(\)/);
    expect(source).not.toMatch(/ShellExecute|WinExec|\bsystem\s*\(/);
  });

  it('closes broad handle inheritance and grants no network capability', () => {
    expect(source).toMatch(
      /CreateProcessW\([\s\S]*?nullptr, nullptr, FALSE,[\s\S]*?EXTENDED_STARTUPINFO_PRESENT/,
    );
    expect(source).toMatch(/capabilities\.Capabilities\s*=\s*nullptr/);
    expect(source).toMatch(/capabilities\.CapabilityCount\s*=\s*0/);
    expect(source).not.toMatch(/L"(?:internetClient|privateNetworkClientServer)"/);
  });

  it('uses Job Object only to bind the already-suspended AppContainer process tree', () => {
    expect(source).toMatch(/CREATE_SUSPENDED/);
    expect(source).toMatch(/AssignProcessToJobObject/);
    expect(source).toMatch(/JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE/);
    expect(source.indexOf('AssignProcessToJobObject')).toBeGreaterThan(
      source.indexOf('CreateProcessW'),
    );
    expect(source.indexOf('ResumeThread')).toBeGreaterThan(
      source.indexOf('AssignProcessToJobObject'),
    );
  });

  it('treats every profile, ACL, Job and process setup failure as a native error', () => {
    for (const code of [
      'kProfileFailed',
      'kSidFailed',
      'kAclFailed',
      'kJobFailed',
      'kProcessFailed',
      'kCleanupFailed',
    ]) {
      expect(source).toContain(code);
    }
  });

  it('parses protocol v2 exact denies and installs them after allow capabilities', () => {
    expect(source).toMatch(/kRequestVersion\s*=\s*2/);
    expect(source).toMatch(/DeniedResources\(&request->denies\)/);
    expect(source).toMatch(/desired_grants[\s\S]*?GRANT_ACCESS[\s\S]*?desired_denies[\s\S]*?DENY_ACCESS/);
    expect(source.indexOf('DENY_ACCESS')).toBeGreaterThan(source.indexOf('GRANT_ACCESS'));
  });

  it('rolls back both allow and deny ACE mutations before deleting the ephemeral profile', () => {
    expect(source).toMatch(/applied_changes/);
    expect(source).toMatch(/RevokeAclChanges\(changes, sid\)/);
    expect(source).toMatch(/REVOKE_ACCESS/);
    expect(source.indexOf('RevokeAclChanges(changes, sid)')).toBeLessThan(
      source.indexOf('DeleteAppContainerProfile(profile_name.c_str())'),
    );
  });
});
