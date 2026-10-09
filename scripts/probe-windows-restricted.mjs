// Developer-only: a full restricting-SID token compatibility experiment.
// No account, service, firewall rule or production artifact is installed.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { cp, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

if (process.platform !== 'win32') throw new Error('The restricted-token experiment requires Windows');
const execute = promisify(execFile);
const repository = fileURLToPath(new URL('../', import.meta.url));
const root = await realpath(await mkdtemp(join(tmpdir(), 'agentkeeper-restricted-proof-')));
try {
  const output = join(root, 'restricted-proof.exe');
  const compiled = await execute('cl.exe', ['/nologo', '/std:c++20', '/EHsc', '/W4', '/O2', '/MT',
    join(repository, 'test/native/windows-restricted-compat.cpp'),
    `/Fo${join(root, 'restricted-proof.obj')}`, `/Fe${output}`],
  { cwd: root, timeout: 60_000, maxBuffer: 1024 * 1024 });
  report('Restricted token compile', compiled.stdout + compiled.stderr);
  const workspace = join(root, 'workspace');
  const outside = join(root, 'outside.secret');
  await mkdir(workspace);
  await writeFile(outside, 'restricted-token outside canary');
  await writeFile(join(workspace, 'qualification.cjs'),
    await readFile(new URL('../test/native/windows-restricted-workload.cjs', import.meta.url)));
  await writeFile(join(workspace, 'module.cjs'), 'module.exports=42;');
  await writeFile(join(workspace, 'module.mjs'), 'export default 43;');
  const installedGit = (await execute('where.exe', ['git'])).stdout.trim().split(/\r?\n/)[0];
  if (!installedGit) throw new Error('Git must be installed for the compatibility proof');
  // Git for Windows contains intentional executable hardlinks. Use ordinary
  // copies for this experiment, retaining the alias guard unchanged. A future
  // backend must explicitly qualify how it handles the installed toolchain.
  const gitRoot = resolve(dirname(installedGit), '..');
  const copiedGitRoot = join(root, 'toolchain/Git');
  await mkdir(join(copiedGitRoot, 'bin'), { recursive: true });
  await cp(installedGit, join(copiedGitRoot, 'bin/git.exe'));
  await cp(join(gitRoot, 'mingw64/bin'), join(copiedGitRoot, 'mingw64/bin'), { recursive: true });
  const git = join(copiedGitRoot, 'bin/git.exe');
  // Only disposable fixtures receive low-integrity labels. Host projects and
  // toolchain integrity labels are never changed by this experiment.
  await execute('icacls.exe', [workspace, '/setintegritylevel', '(OI)(CI)L', '/T', '/Q'], { timeout: 15_000 });
  const args = [process.execPath, git, workspace, outside, String(process.pid)];
  const acl = async (path) => (await execute('icacls.exe', [path], { timeout: 15_000 })).stdout;
  const before = await acl(workspace);
  // Red controls: the real workload must reject an unrestricted process, not
  // pass because its canary or subprocess assertions accidentally do nothing.
  const hostControl = await execute(process.execPath,
    [join(workspace, 'qualification.cjs'), outside, git, String(process.pid)],
    { cwd: workspace, timeout: 30_000 }).then(() => null, (error) => error);
  assert.notEqual(hostControl, null, 'unrestricted negative control unexpectedly passed');
  const controlRows = hostControl.stdout.split(/\r?\n/).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
  assert.equal(controlRows.find((row) => row.name === 'default-deny outside read')?.passed, false);
  assert.equal(controlRows.find((row) => row.name === 'default-deny outside write')?.passed, false);
  // The negative control intentionally modified its temporary canary and
  // created an alias. Restore both before evaluating the actual boundary.
  await rm(join(workspace, 'outside-alias'), { force: true });
  await rm(join(workspace, '.git'), { recursive: true, force: true });
  await writeFile(outside, 'restricted-token outside canary');
  report('Restricted token negative controls', 'Unrestricted read/write canaries correctly failed.');
  for (const kind of ['hardlink', 'junction']) {
    const alias = join(workspace, 'unsafe-alias');
    if (kind === 'hardlink') await link(outside, alias);
    else await symlink(root, alias, 'junction');
    try {
      const rejected = await execute(output, args, { timeout: 40_000 })
        .then(() => null, (error) => error);
      assert.equal(rejected?.code, 210, `existing ${kind} must be rejected before ACL changes`);
      assert.equal(await acl(workspace), before);
      assert.equal(await readFile(outside, 'utf8'), 'restricted-token outside canary');
      report('Restricted token alias refusal', `${kind}: refused before launch, canary and workspace ACL unchanged`);
    } finally { await rm(alias, { force: true }); }
  }
  const env = { ...process.env, HOME: join(workspace, 'home'), USERPROFILE: join(workspace, 'home'),
    APPDATA: join(workspace, 'home/AppData/Roaming'), LOCALAPPDATA: join(workspace, 'home/AppData/Local'),
    TMP: join(workspace, 'tmp'), TEMP: join(workspace, 'tmp') };
  await Promise.all([env.APPDATA, env.LOCALAPPDATA, env.TMP].map((path) => mkdir(path, { recursive: true })));
  let failure;
  try {
    const result = await execute(output, args, { cwd: workspace, env, timeout: 40_000, maxBuffer: 256 * 1024 });
    report('Restricted token compatibility', result.stdout + result.stderr);
    assert.equal(result.stdout.includes('"networkQualified":false'), true);
  } catch (error) {
    report('Restricted token compatibility failed',
      String(error.stdout ?? '') + String(error.stderr ?? '') + '\n' + `native exit: ${error.code}\n` + error.message);
    failure = error;
  }
  assert.equal(await readFile(outside, 'utf8'), 'restricted-token outside canary');
  assert.equal(await acl(workspace), before, 'workspace ACL must be restored after the proof');
  if (failure) throw failure;
  report('Restricted token scope', 'Compatibility proof only: network, service lifecycle and production integration remain unqualified.');
} catch (error) {
  report('Restricted token proof failed', String(error.stdout ?? '') + String(error.stderr ?? '') + '\n' + error.message);
  throw error;
} finally {
  await rm(root, { recursive: true, force: true });
}

function report(title, details) {
  console.log(details);
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escaped = details.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.log(`::notice title=${title} (${process.arch})::${escaped}`);
  }
}
