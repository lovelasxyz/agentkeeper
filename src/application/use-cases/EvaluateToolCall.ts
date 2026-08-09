import { Disposition } from '../../domain/value-objects/Disposition.js';
import type { Finding } from '../../domain/entities/Finding.js';
import type { ToolCall } from '../../domain/entities/ToolCall.js';
import type { ScanEngine } from '../../domain/services/ScanEngine.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import type { AuditLog, Clock, DecisionStore } from '../ports/index.js';

export interface ToolCallVerdict {
  readonly decision: 'allow' | 'deny' | 'ask';
  readonly reason: string;
  readonly findings: readonly Finding[];
}

/**
 * `PreToolUse` (entry point E3, spec §5).
 *
 * Runs on the critical path of every tool call with a 50 ms budget, so it does
 * exactly two pieces of I/O: read the decision store, append to the log. Its
 * job changed with layer 1 — it is no longer the only line of defence, it
 * watches what happens with resources isolation already allowed (spec §4.8).
 */
export class EvaluateToolCall {
  constructor(
    private readonly engine: ScanEngine<ToolCall>,
    private readonly decisions: DecisionStore,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
    private readonly switches: RuleSwitches,
  ) {}

  async execute(call: ToolCall): Promise<ToolCallVerdict> {
    const report = this.engine.scan([call], this.switches);
    if (report.isClean) return { decision: 'allow', reason: 'no rule matched', findings: [] };

    const blocking = report.blocking();
    if (blocking.length > 0) {
      await this.record('toolcall.blocked', call, blocking);
      return {
        decision: 'deny',
        reason: blocking.map((finding) => finding.detail).join(' '),
        findings: blocking,
      };
    }

    const asking = report.interrupting();
    const stored = new Map(
      (await this.decisions.all()).map((decision) => [decision.key, decision]),
    );
    const undecided: Finding[] = [];
    for (const finding of asking) {
      const previous = stored.get(finding.decisionKey);
      if (previous === undefined) undecided.push(finding);
      else if (previous.verdict === 'deny') {
        await this.record('toolcall.denied-by-decision', call, [finding]);
        return { decision: 'deny', reason: finding.detail, findings: [finding] };
      }
    }

    if (undecided.length === 0) {
      return { decision: 'allow', reason: 'previously approved', findings: report.findings };
    }

    await this.record('toolcall.ask', call, undecided);
    return {
      decision: 'ask',
      reason: undecided.map((finding) => finding.detail).join(' '),
      findings: undecided,
    };
  }

  private async record(
    event: string,
    call: ToolCall,
    findings: readonly Finding[],
  ): Promise<void> {
    try {
      await this.audit.append({
        at: this.clock.now(),
        event,
        details: {
          tool: call.tool,
          rules: findings.map((finding) => finding.ruleId.toString()),
          subjects: findings.map((finding) => finding.subject),
          disposition: Disposition.strictest(findings.map((finding) => finding.disposition)).name,
        },
      });
    } catch {
      // Audit is evidence, not authority. A full disk, a truncated log, or the
      // deliberately read-only in-sandbox control plane must never turn a deny
      // into HookCommand's fail-open error path.
    }
  }
}
