import type { BaselineChange } from '../../domain/entities/BaselineChange.js';
import type { ScanReport } from '../../domain/entities/ScanReport.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import type { SeverityName } from '../../domain/value-objects/Severity.js';
import type { BaselineEntry } from './index.js';

export interface BaselineSnapshotter {
  collect(context: PathContext): Promise<readonly BaselineEntry[]>;
}

export interface PersistenceScanner {
  scan(changes: readonly BaselineChange[], switches: RuleSwitches): ScanReport;
}

export type PauseState =
  | { readonly status: 'inactive'; readonly until: null }
  | { readonly status: 'active'; readonly until: Date }
  | { readonly status: 'expired'; readonly until: Date }
  | { readonly status: 'invalid'; readonly until: null; readonly reason: string };

export interface PauseStateReader {
  read(): Promise<PauseState>;
}

export type PersistenceIncidentState = 'pending' | 'quarantined';

/** Metadata only: persistence contents and secrets never enter this store. */
export interface PersistenceIncident {
  readonly id: string;
  readonly decisionKey: string;
  readonly subject: string;
  readonly ruleIds: readonly string[];
  readonly severity: SeverityName;
  readonly state: PersistenceIncidentState;
  readonly previousHash: string | null;
  readonly currentHash: string | null;
  readonly firstSeenAt: Date;
  readonly lastSeenAt: Date;
  readonly occurrences: number;
}

export interface PersistencePendingStore {
  load(): Promise<readonly PersistenceIncident[]>;
  save(incidents: readonly PersistenceIncident[]): Promise<void>;
}
