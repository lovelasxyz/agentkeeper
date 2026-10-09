/** Prerequisites for the selected native Windows backend, not launch proof. */
export type WindowsPsecHostAssessment =
  | { readonly supported: true }
  | {
      readonly supported: false;
      readonly code:
        | 'windows.psec-probe-invalid'
        | 'windows.psec-platform-unsupported'
        | 'windows.psec-api-unavailable'
        | 'windows.psec-contract-unsupported'
        | 'windows.psec-filesystem-deny-unavailable'
        | 'windows.psec-enumeration-unavailable'
        | 'windows.psec-ingress-unavailable';
      readonly message: string;
    };

/**
 * Require the OS policy primitives before attempting a native launch.
 * PSEC 1.1 enumeration permits directory metadata without a recursive content
 * read grant; ingress support is needed for the selected network boundary.
 * Unknown capability bits are preserved; missing required bits never qualify.
 */
export function assessWindowsPsecHost(report: unknown): WindowsPsecHostAssessment {
  if (!record(report)) return invalid();
  const { kind, os, psec } = report;
  if (kind !== 'agentkeeper.psec-host.v1' || !record(os) || !record(psec)) return invalid();
  const { build, revision, workstation } = os;
  const { major, minor, supportFlags, exportsAvailable, versionQuerySucceeded,
    supportQuerySucceeded, available } = psec;
  if (!uint32(build) || !uint32(revision) || typeof workstation !== 'boolean' ||
      !uint32(major) || !uint32(minor) ||
      typeof supportFlags !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(supportFlags) ||
      [exportsAvailable, versionQuerySucceeded, supportQuerySucceeded, available]
        .some((value) => typeof value !== 'boolean')) return invalid();

  if (!workstation || build < 22000) {
    return unsupported('windows.psec-platform-unsupported', 'The native backend requires Windows 11 or a later workstation release.');
  }
  if (!exportsAvailable || !versionQuerySucceeded || !supportQuerySucceeded || !available) {
    return unsupported('windows.psec-api-unavailable', 'The required Windows PSEC APIs are unavailable or their queries failed.');
  }
  if (major !== 1 || minor < 1) {
    return unsupported('windows.psec-contract-unsupported', 'The native backend requires PSEC contract 1.1 with enumeration and ingress support.');
  }
  const flags = BigInt(supportFlags);
  if ((flags & 0x1n) === 0n) {
    return unsupported('windows.psec-filesystem-deny-unavailable', 'This Windows build cannot enforce native filesystem denies.');
  }
  if ((flags & 0x4n) === 0n) {
    return unsupported('windows.psec-enumeration-unavailable', 'This Windows build cannot provide enumeration-only filesystem access required by the sandbox.');
  }
  if ((flags & 0x8n) === 0n) {
    return unsupported('windows.psec-ingress-unavailable', 'This Windows build cannot enforce the required native ingress policy.');
  }
  return { supported: true };
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function uint32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

function invalid(): WindowsPsecHostAssessment {
  return unsupported('windows.psec-probe-invalid', 'The native Windows PSEC diagnostic report is invalid.');
}

function unsupported(
  code: Extract<WindowsPsecHostAssessment, { supported: false }>['code'],
  message: string,
): WindowsPsecHostAssessment {
  return { supported: false, code, message };
}
