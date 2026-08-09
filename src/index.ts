/**
 * Public API.
 *
 * agentkeeper is primarily a command-line tool, but the policy model and the
 * rule engine are useful on their own — for a custom scanner, a CI check, or a
 * different front end. Only the pure parts are exported: everything here can be
 * used without touching the filesystem.
 */

export { AbsolutePath } from './domain/value-objects/AbsolutePath.js';
export { PathPattern } from './domain/value-objects/PathPattern.js';
export { ResourceRef } from './domain/value-objects/ResourceRef.js';
export { NetworkRule } from './domain/value-objects/NetworkRule.js';
export { ContentHash } from './domain/value-objects/ContentHash.js';
export { RuleId } from './domain/value-objects/RuleId.js';
export { Severity } from './domain/value-objects/Severity.js';
export { Disposition } from './domain/value-objects/Disposition.js';
export { AccessTier } from './domain/value-objects/AccessTier.js';
export { GrantScope } from './domain/value-objects/GrantScope.js';
export { WorkspaceId } from './domain/value-objects/WorkspaceId.js';
export { ShellCommand, ShellSegment } from './domain/value-objects/ShellCommand.js';
export type { Platform } from './domain/value-objects/Platform.js';

export { Artifact } from './domain/entities/Artifact.js';
export { ToolCall } from './domain/entities/ToolCall.js';
export { BaselineChange } from './domain/entities/BaselineChange.js';
export { Finding } from './domain/entities/Finding.js';
export { ScanReport } from './domain/entities/ScanReport.js';
export { Grant } from './domain/entities/Grant.js';

export { SensitivePath } from './domain/paths/SensitivePath.js';
export { SensitivePathRegistry } from './domain/paths/SensitivePathRegistry.js';
export { SENSITIVE_PATHS } from './domain/paths/registry.js';
export type { PathContext } from './domain/paths/PathContext.js';

export { SandboxPolicy } from './domain/policy/SandboxPolicy.js';
export { PolicyBuilder, UnsafeWorkspaceError } from './domain/policy/PolicyBuilder.js';
export { AccessTierResolver } from './domain/policy/AccessTierResolver.js';
export { StarterProfile } from './domain/policy/StarterProfile.js';
export { DenyRule } from './domain/policy/DenyRule.js';
export {
  EnvironmentPolicy,
  PROVIDER_API_KEYS,
  type ProviderApiKey,
} from './domain/policy/EnvironmentPolicy.js';
export {
  EnvironmentSanitizer,
  EnvironmentSanitizationResult,
} from './domain/policy/EnvironmentSanitizer.js';

export { Rule } from './domain/rules/Rule.js';
export { RuleRegistry, ALL_RULES_ENABLED } from './domain/rules/RuleRegistry.js';
export { ARTIFACT_RULES } from './domain/rules/artifact/index.js';
export { actionRules, blockingRules } from './domain/rules/toolcall/index.js';
export { PERSISTENCE_RULES } from './domain/rules/persistence/index.js';
export { ScanEngine } from './domain/services/ScanEngine.js';
