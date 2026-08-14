import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { budgetViolations } from './perf-budgets.mjs';

/**
 * Measures the performance budgets of spec §12, in a clean process.
 *
 * Two decisions about method, both of which changed the answer materially:
 *
 * 1. **Not run inside the test runner.** Vitest holds a large heap and competes
 *    for CPU; every figure came out roughly four times higher there. That
 *    number describes the runner, not the product.
 *
 * 2. **Minimum, not p95.** `p95(A) - p95(B)` across two separate batches is not
 *    the p95 of the difference — under load it produced readings that swung
 *    between 6 ms and 200 ms for the same code. The minimum of many runs is the
 *    standard robust estimator for "what does this cost without contention",
 *    which is what a budget about our code should measure.
 *
 * Usage: node bench.mjs <path-to-cli> [--enforce] → one line of JSON on stdout.
 * With --enforce the run doubles as the CI gate: any measured figure over its
 * budget in perf-budgets.mjs is reported on stderr and exits 1, so a hot-path
 * regression fails the build instead of shipping silently.
 */

// Absolute: the wrapper runs with the workspace as its cwd, so a relative
// path would resolve against the wrong directory.
const BIN = process.argv[2] === undefined ? undefined : resolve(process.argv[2]);
const enforce = process.argv.includes('--enforce');
if (BIN === undefined) {
  process.stderr.write('usage: node bench.mjs <path-to-cli> [--enforce]\n');
  process.exit(2);
}

const SAMPLES = 41;

const root = realpathSync(mkdtempSync(join(tmpdir(), 'agentkeeper-bench-')));
const home = join(root, 'home');
const workspace = join(home, 'projects/app');
mkdirSync(workspace, { recursive: true });
mkdirSync(join(root, 'tmp'), { recursive: true });
writeFileSync(join(workspace, 'README.md'), '# app\n');
mkdirSync(join(workspace, '.claude'), { recursive: true });
writeFileSync(join(workspace, '.claude/settings.json'), '{"model":"opus"}');
for (let i = 0; i < 200; i += 1) {
  writeFileSync(join(workspace, `file-${i}.ts`), `export const n${i} = ${i};\n`);
}

// A profile that permits everything: this measures what `sandbox-exec` costs to
// start, not what any particular policy costs to enforce.
const nullProfile = join(root, 'null.sb');
writeFileSync(nullProfile, '(version 1)\n(allow default)\n');

const env = { ...process.env, HOME: home, TMPDIR: join(root, 'tmp'), CI: '1' };

const time = (run) => {
  const started = performance.now();
  run();
  return performance.now() - started;
};

function fastest(run) {
  run(); // warm-up: the first run fills the OS page cache
  let best = Infinity;
  for (let i = 0; i < SAMPLES; i += 1) best = Math.min(best, time(run));
  return best;
}

const payload = JSON.stringify({
  tool_name: 'Read',
  tool_input: { file_path: join(workspace, 'README.md') },
  cwd: workspace,
});

try {
  const bareNode = fastest(() =>
    execFileSync(process.execPath, ['-e', '0'], { stdio: 'ignore' }),
  );

  // What any wrapper that spawns a sandboxed command pays before doing anything
  // of its own: one interpreter start-up plus the platform mechanism. Only
  // macOS has `sandbox-exec`; measuring it elsewhere just crashes the run.
  const spawnFloor =
    process.platform === 'darwin'
      ? bareNode +
        fastest(() =>
          execFileSync('/usr/bin/sandbox-exec', ['-f', nullProfile, process.execPath, '-e', '0'], {
            stdio: 'ignore',
          }),
        )
      : 2 * bareNode;

  const hook = fastest(() =>
    execFileSync(process.execPath, [BIN, 'hook', 'pretooluse'], {
      input: payload,
      stdio: ['pipe', 'ignore', 'ignore'],
      env,
    }),
  );

  const scan = fastest(() =>
    execFileSync(process.execPath, [BIN, 'scan', workspace, '--quiet'], {
      stdio: 'ignore',
      env,
    }),
  );

  const wrapper = fastest(() =>
    execFileSync(
      process.execPath,
      [BIN, 'run', '--profile', 'minimal', '--', process.execPath, '-e', '0'],
      { cwd: workspace, stdio: 'ignore', env },
    ),
  );

  const measured = {
    bareNodeStartup: round(bareNode),
    // `spawnFloor` is one bare start-up plus one sandboxed one, so what the
    // sandbox binary itself adds is the floor minus two bare start-ups.
    // Zero where no such binary exists, which is the honest figure there.
    sandboxExecCost: round(spawnFloor - 2 * bareNode),
    // Everything above one interpreter start-up: our modules, our I/O, our
    // policy build. Node's own start-up is charged to any hook that is not a
    // compiled binary and is reported separately rather than hidden.
    hookOwnCost: round(hook - bareNode),
    scanOwnCost: round(scan - bareNode),
    // What the user feels in total when running an agent through the wrapper.
    wrapperTotalOverhead: round(wrapper - bareNode),
    // Of that, the part this project can actually do something about.
    wrapperOwnCost: round(wrapper - spawnFloor),
  };
  process.stdout.write(`${JSON.stringify(measured)}\n`);

  const violations = budgetViolations(measured);
  if (enforce && violations.length > 0) {
    process.stderr.write(`performance budgets exceeded:\n  ${violations.join('\n  ')}\n`);
    process.exit(1);
  }
  if (violations.length > 0) {
    process.stderr.write(`note: outside budget: ${violations.join('; ')}\n`);
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

function round(value) {
  return Math.round(value * 10) / 10;
}
