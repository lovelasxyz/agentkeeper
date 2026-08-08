import {
  AgentConfigWriteRule,
  BypassEnvironmentRule,
  ForeignEnvFileRule,
  GitHooksPathRule,
  SelfProtectionRule,
  SensitivePathAccessRule,
  ToolCallRule,
} from './blocking.js';
import {
  DockerEscapeRule,
  ForcePushRule,
  InfrastructureMutationRule,
  OutboundMessageRule,
  PublishRule,
  RecursiveDeleteRule,
  WorkflowEditRule,
} from './actions.js';
import type { AccessTierResolver } from '../../policy/AccessTierResolver.js';

/** Family B — refusals. Never disabled by configuration (spec §10.3). */
export function blockingRules(tiers: AccessTierResolver): readonly ToolCallRule[] {
  return Object.freeze([
    new SensitivePathAccessRule(tiers),
    new ForeignEnvFileRule(),
    new AgentConfigWriteRule(),
    new GitHooksPathRule(),
    new SelfProtectionRule(),
    new BypassEnvironmentRule(),
  ]);
}

/** Family A — irreversible actions. Off unless the user turns them on (spec §6.7). */
export function actionRules(): readonly ToolCallRule[] {
  return Object.freeze([
    new ForcePushRule(),
    new PublishRule(),
    new RecursiveDeleteRule(),
    new InfrastructureMutationRule(),
    new DockerEscapeRule(),
    new WorkflowEditRule(),
    new OutboundMessageRule(),
  ]);
}

export { ToolCallRule } from './blocking.js';
