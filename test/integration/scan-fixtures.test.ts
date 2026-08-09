import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  buildFixture,
  FALSE_POSITIVE_CORPUS,
  FIXTURES,
  type Fixture,
} from '../fixtures/build.js';
import { ScanWorkspace } from '../../src/application/use-cases/ScanWorkspace.js';
import { NodeFileSystem } from '../../src/infrastructure/fs/NodeFileSystem.js';
import { ScanEngine } from '../../src/domain/services/ScanEngine.js';
import { RuleRegistry, ALL_RULES_ENABLED } from '../../src/domain/rules/RuleRegistry.js';
import { ARTIFACT_RULES } from '../../src/domain/rules/artifact/index.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type { Decision, DecisionStore } from '../../src/application/ports/index.js';

/** No decisions recorded: every fixture is seen for the first time. */
class EmptyDecisions implements DecisionStore {
  async find(): Promise<Decision | null> {
    return null;
  }
  async record(): Promise<void> {}
  async recordMany(): Promise<void> {}
  async all(): Promise<readonly Decision[]> {
    return [];
  }
}

const files = new NodeFileSystem();
const scanner = new ScanWorkspace(
  files,
  new ScanEngine(RuleRegistry.of(ARTIFACT_RULES)),
  new EmptyDecisions(),
  ALL_RULES_ENABLED,
  { now: () => new Date(0) },
);

let root: string;

const scan = async (fixture: Fixture): Promise<string[]> => {
  const directory = buildFixture(fixture, join(root, fixture.name));
  const { report } = await scanner.execute(files.realPath(AbsolutePath.of(directory)));
  return report.findings.map((finding) => finding.ruleId.toString());
};

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'agentkeeper-fixtures-'));
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describe('hostile fixtures (spec §9.4)', () => {
  it.each(FIXTURES.map((fixture) => [fixture.name, fixture] as const))(
    '%s triggers the rules it was built for',
    async (_name, fixture) => {
      const found = await scan(fixture);
      for (const expected of fixture.expects) {
        expect(found, `${fixture.name} should trigger ${expected}`).toContain(expected);
      }
    },
  );

  it('the clean fixture is the most important test in the suite', async () => {
    const clean = FIXTURES.find((fixture) => fixture.name === 'clean') as Fixture;
    expect(await scan(clean)).toEqual([]);
  });
});

describe('false-positive corpus (spec §9.4)', () => {
  it.each(FALSE_POSITIVE_CORPUS.map((fixture) => [fixture.name, fixture] as const))(
    '%s reports exactly what it should and nothing more',
    async (_name, fixture) => {
      // Golden: the set of findings on legitimate configuration is fixed. Any
      // growth is a regression against the interruption budget of spec §1.5,
      // not a "more thorough" scanner.
      expect(new Set(await scan(fixture))).toEqual(new Set(fixture.expects));
    },
  );

  it('keeps the total number of interruptions across the corpus at the golden value', async () => {
    let interruptions = 0;
    for (const fixture of FALSE_POSITIVE_CORPUS) {
      const directory = buildFixture(fixture, join(root, `count-${fixture.name}`));
      const { report } = await scanner.execute(files.realPath(AbsolutePath.of(directory)));
      interruptions += report.interrupting().length;
    }
    expect(interruptions).toBe(1); // the pinned MCP server, which is worth one question
  });
});
