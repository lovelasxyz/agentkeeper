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

  it('runs the portable verification surface on Windows CI', () => {
    const workflow = readFileSync(join(repository, '.github/workflows/ci.yml'), 'utf8');

    expect(workflow).toMatch(/windows-latest/);
    expect(workflow).toMatch(/npm run clean/);
    expect(workflow).toMatch(/npm run build/);
    expect(workflow).toMatch(/msvc-dev-cmd/);
    expect(workflow).toMatch(/name: Sandbox isolation tests\s+run: npm run test:sandbox/);
  });

  it('places the Windows native sandbox helper in the package assembled on Linux', () => {
    const workflow = readFileSync(join(repository, '.github/workflows/ci.yml'), 'utf8');

    expect(workflow).toMatch(/upload-artifact/);
    expect(workflow).toMatch(/download-artifact/);
    expect(workflow).toMatch(/agentkeeper-sandbox\.exe/);
    expect(workflow).toMatch(/win32-arm64/);
    // Packing must not re-run prepack: a rebuild after the download would
    // decide the tarball contents from a different tree than the one verified.
    expect(workflow).toMatch(/npm pack --dry-run --ignore-scripts/);
  });

  it('proves the assembled tarball itself carries both Windows helpers', () => {
    for (const relative of ['.github/workflows/ci.yml', '.github/workflows/publish.yml']) {
      const workflow = readFileSync(join(repository, relative), 'utf8');
      expect(workflow, relative).toMatch(/verify-tarball\.mjs/);
    }
  });

  it('the tarball verifier rejects a listing without the native helpers', () => {
    const verifier = join(repository, 'scripts/verify-tarball.mjs');
    const listing = (files: readonly string[]): string =>
      JSON.stringify([{ files: files.map((path) => ({ path })) }]);

    expect(() =>
      execFileSync(process.execPath, [verifier], {
        input: listing(['dist/cli.js', 'dist/index.js']),
        stdio: 'pipe',
      }),
    ).toThrow();

    const accepted = execFileSync(process.execPath, [verifier], {
      input: listing([
        'dist/cli.js',
        'dist/index.js',
        'dist/index.d.ts',
        'dist/native/win32-x64/agentkeeper-sandbox.exe',
        'dist/native/win32-arm64/agentkeeper-sandbox.exe',
        'profiles/minimal.json',
        'README.md',
        'LICENSE',
        'SECURITY.md',
      ]),
      stdio: 'pipe',
    });
    expect(accepted.toString()).toMatch(/tarball verification/);
  });

  it('keeps the compiler intermediate out of the packaged native directory', () => {
    const builder = readFileSync(join(repository, 'scripts/build-windows-sandbox.mjs'), 'utf8');

    // /Fo next to /Fe would leave an .obj inside dist/native, which the package
    // gate rejects as an unexpected artifact — a Windows `npm pack` would fail.
    expect(builder).toMatch(/objectDirectory/);
    expect(builder).not.toMatch(/`\/Fo\$\{join\(outputDirectory/);
    expect(readFileSync(join(repository, 'scripts/clean.mjs'), 'utf8')).toMatch(/'build'/);
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

  it('does not chmod the Windows build artifact', () => {
    const postbuild = readFileSync(join(repository, 'scripts/postbuild.mjs'), 'utf8');
    expect(postbuild).toMatch(/process\.platform\s*!==\s*['"]win32['"]/);
  });
});
