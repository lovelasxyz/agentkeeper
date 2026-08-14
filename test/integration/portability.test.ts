import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

const repository = process.cwd();
const temporaryRoots: string[] = [];

afterAll(() => {
  for (const root of temporaryRoots) rmSync(root, { recursive: true, force: true });
});

describe('build and CI portability', () => {
  it('uses a Node clean script instead of a POSIX-only shell command', () => {
    const packageDocument = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };

    expect(packageDocument.scripts['clean']).toBe('node scripts/clean.mjs');
    expect(packageDocument.scripts['clean']).not.toMatch(/\brm\b|rmdir|del\s/i);
  });

  it('the clean script removes only generated targets from an arbitrary cwd', () => {
    const root = mkdtempSync(join(tmpdir(), 'agentkeeper-clean-'));
    temporaryRoots.push(root);
    mkdirSync(join(root, 'dist'), { recursive: true });
    mkdirSync(join(root, 'coverage'), { recursive: true });
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'dist/output.js'), 'generated');
    writeFileSync(join(root, 'coverage/lcov.info'), 'generated');
    writeFileSync(join(root, 'src/keep.ts'), 'source');

    execFileSync(process.execPath, [join(repository, 'scripts/clean.mjs')], { cwd: root });

    expect(existsSync(join(root, 'dist'))).toBe(false);
    expect(existsSync(join(root, 'coverage'))).toBe(false);
    expect(readFileSync(join(root, 'src/keep.ts'), 'utf8')).toBe('source');
  });

  it('verifies a release on the same toolchain CI verified', () => {
    // A release pinned to a different Node patch than CI is a release nobody
    // tested: the pin drifted out of `npm@latest`'s supported range and the
    // publish job died before it reached a single check.
    const versions = new Set(
      ['.github/workflows/ci.yml', '.github/workflows/publish.yml'].flatMap((relative) =>
        [...readFileSync(join(repository, relative), 'utf8').matchAll(/node-version: '([^']+)'/g)].map(
          (match) => match[1] as string,
        ),
      ),
    );

    expect([...versions]).toEqual(['22']);
  });

  it('keeps every workflow trigger key well formed', () => {
    // A stray second colon makes the key `workflow_dispatch:` rather than the
    // event, and GitHub then rejects the whole file: the run reports failure
    // with zero jobs, which reads like a broken build rather than bad YAML.
    for (const relative of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const workflow = readFileSync(join(repository, relative), 'utf8');
      expect(workflow, `${relative} has a malformed key`).not.toMatch(/^\s*[\w-]+::/m);
    }
    expect(readFileSync(join(repository, '.github/workflows/ci.yml'), 'utf8')).toMatch(
      /^\s{2}workflow_dispatch:\s*$/m,
    );
  });

  it('keeps Windows CI to the portable verification surface: build and tests, no backend', () => {
    // The AppContainer backend is not shipped (production-readiness P0.1), so
    // there is nothing to compile and nothing to run a sandbox suite against.
    // Windows CI still earns its place: typecheck, architecture, the unit and
    // integration suites, and a clean build — the cross-platform parts.
    const workflow = readFileSync(join(repository, '.github/workflows/ci.yml'), 'utf8');

    expect(workflow).toMatch(/windows-latest/);
    expect(workflow).toMatch(/npm run clean/);
    expect(workflow).toMatch(/npm run build/);
    expect(workflow).not.toMatch(/msvc-dev-cmd/);

    // No step anywhere may be advisory: a continue-on-error is a gate that
    // does not gate, and on a security product that is how a platform ships
    // broken while looking green.
    for (const relative of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const text = readFileSync(join(repository, relative), 'utf8');
      expect(text.match(/continue-on-error: true/g) ?? [], relative).toHaveLength(0);
    }
  });

  it('refuses to package a native Windows backend', () => {
    // Shipping the helper while its canary never completes would let the
    // platform claim a boundary it cannot prove. The package gate rejects any
    // native artifact, and no workflow assembles one anymore.
    const verifier = readFileSync(join(repository, 'scripts/verify-package.mjs'), 'utf8');
    expect(verifier).toMatch(/dist\/native/);

    for (const relative of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const workflow = readFileSync(join(repository, relative), 'utf8');
      expect(workflow, relative).not.toMatch(/agentkeeper-sandbox\.exe/);
      expect(workflow, relative).not.toMatch(/win32-arm64/);
      expect(workflow, relative).not.toMatch(/msvc-dev-cmd/);
    }
    // Packing must not re-run prepack: a rebuild after verification would
    // decide the tarball contents from a different tree than the one verified.
    // The verifier owns that flag now, so assert it where it actually lives.
    expect(readFileSync(join(repository, 'scripts/verify-tarball.mjs'), 'utf8')).toMatch(
      /'--ignore-scripts'/,
    );
  });

  it('proves the assembled tarball itself, not npm output', () => {
    for (const relative of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const workflow = readFileSync(join(repository, relative), 'utf8');
      expect(workflow, relative).toMatch(/verify-tarball\.mjs/);
    }
  });

  it('reads a real archive rather than an npm output format', async () => {
    // The previous verifier parsed `npm pack --json` and reported every
    // artifact missing the day npm changed that undocumented shape. Reading
    // the actual tarball is what the gate was always supposed to do.
    // Computed specifier on purpose: the build scripts are plain ESM with no
    // declarations, and a literal path would need a `.d.ts` that exists only
    // to satisfy the type checker.
    const verifier: {
      listTarEntries: (gzipped: Buffer) => string[];
      missingArtifacts: (entries: readonly string[]) => string[];
    } = await import(new URL('../../scripts/verify-tarball.mjs', import.meta.url).href);
    const { listTarEntries, missingArtifacts } = verifier;

    const root = mkdtempSync(join(tmpdir(), 'agentkeeper-tar-'));
    temporaryRoots.push(root);
    mkdirSync(join(root, 'package/dist'), { recursive: true });
    writeFileSync(join(root, 'package/dist/cli.js'), '#!/usr/bin/env node\n');
    writeFileSync(join(root, 'package/README.md'), '# hi\n');
    execFileSync('tar', ['-czf', join(root, 'sample.tgz'), '-C', root, 'package']);

    const entries = listTarEntries(readFileSync(join(root, 'sample.tgz')) as Buffer);
    expect(entries).toContain('package/README.md');
    expect(entries).toContain('package/dist/cli.js');

    // The `package/` prefix must not hide a required path, and a genuinely
    // absent artifact must still be reported.
    const missing = missingArtifacts(entries);
    expect(missing).not.toContain('README.md');
    expect(missing).not.toContain('dist/cli.js');
    expect(missing).toContain('dist/index.js');
    expect(missingArtifacts([])).toHaveLength(7);
  });

  it('ships the documentation set the spec requires, linked from the README', () => {
    const readme = readFileSync(join(repository, 'README.md'), 'utf8');

    for (const page of [
      'architecture',
      'threat-model',
      'security-boundary',
      'network-model',
      'platform-support',
      'agent-compatibility',
      'policy',
      'rules',
      'threat-coverage',
      'troubleshooting',
    ]) {
      const path = join(repository, 'docs', `${page}.md`);
      expect(existsSync(path), `docs/${page}.md is missing`).toBe(true);
      expect(readFileSync(path, 'utf8').length, `docs/${page}.md is empty`).toBeGreaterThan(400);
      expect(readme, `README does not link docs/${page}.md`).toContain(`docs/${page}.md`);
    }
  });

  it('documents the install verb the CLI actually offers', () => {
    const readme = readFileSync(join(repository, 'README.md'), 'utf8');
    const router = readFileSync(join(repository, 'src/presentation/cli/CommandRouter.ts'), 'utf8');

    // A README that teaches a verb the router dropped is worse than no README.
    for (const verb of ['activate', 'doctor', 'policy', 'integrations', 'allow', 'revoke']) {
      expect(router, `router lost the ${verb} verb`).toContain(`name: '${verb}'`);
      expect(readme, `README does not mention ${verb}`).toContain(`agentkeeper ${verb}`);
    }
  });
});
