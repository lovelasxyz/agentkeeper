import {
  ClonedGitHookRule,
  DevcontainerLifecycleRule,
  DirenvRule,
  FolderOpenTaskRule,
  RepositoryHookRule,
  SessionStartHookRule,
} from './hooks.js';
import {
  EndpointOverrideRule,
  GeminiEnvRule,
  McpAutoApprovalRule,
  McpServerRule,
  UnpinnedMcpServerRule,
} from './env.js';
import {
  ExecutionImperativeRule,
  HiddenInstructionRule,
  InstructionDriftRule,
} from './instructions.js';
import {
  AgentStepNotLastRule,
  DoublePassRule,
  PermissionSkipFlagRule,
  UntrustedTriggerRule,
  VulnerableCliVersionRule,
} from './ci.js';
import type { ArtifactRule } from './ArtifactRule.js';

/** Layer 2, repository side. Ordered by rule id so output is stable. */
export const ARTIFACT_RULES: readonly ArtifactRule[] = Object.freeze([
  new RepositoryHookRule(),
  new SessionStartHookRule(),
  new FolderOpenTaskRule(),
  new DevcontainerLifecycleRule(),
  new ClonedGitHookRule(),
  new DirenvRule(),

  new GeminiEnvRule(),
  new McpServerRule(),
  new UnpinnedMcpServerRule(),
  new EndpointOverrideRule(),
  new McpAutoApprovalRule(),

  new ExecutionImperativeRule(),
  new HiddenInstructionRule(),
  new InstructionDriftRule(),

  new VulnerableCliVersionRule(),
  new PermissionSkipFlagRule(),
  new AgentStepNotLastRule(),
  new DoublePassRule(),
  new UntrustedTriggerRule(),
]);

export { ArtifactRule } from './ArtifactRule.js';
