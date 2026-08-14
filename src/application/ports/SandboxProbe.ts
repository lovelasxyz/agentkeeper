import type { SandboxRunner } from './SandboxRunner.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

export type SandboxProbeCode =
  | 'passed'
  | 'deny-canary-readable'
  | 'child-deny-canary-readable'
  | 'workspace-unreadable'
  | 'child-probe-failed'
  | 'runner-failed'
  /** The canary never finished, so the boundary is unverified rather than proven. */
  | 'canary-timed-out'
  | 'unexpected-exit';

export interface SandboxProbeChecks {
  readonly runnerStarted: boolean;
  readonly workspaceReadAllowed: boolean;
  readonly outsideReadDenied: boolean;
  readonly childOutsideReadDenied: boolean;
}

export interface SandboxProbeResult {
  readonly passed: boolean;
  readonly code: SandboxProbeCode;
  readonly checks: SandboxProbeChecks;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  /**
   * The furthest canary stage observed on failure, when known. A timeout with
   * no stage means the child never initialized; one after `child-returned`
   * means the boundary itself is fine and the bug is in the launcher's wait.
   */
  readonly detail?: string;
}

export interface SandboxProbeRequest {
  readonly runner: SandboxRunner;
  readonly platform: Platform;
}

/** Executes a fresh canary through the same runner used for protected commands. */
export interface SandboxProbe {
  probe(request: SandboxProbeRequest): Promise<SandboxProbeResult>;
}
