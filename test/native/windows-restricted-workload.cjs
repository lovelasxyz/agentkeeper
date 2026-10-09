// Developer proof: passing this file alone never qualifies a production backend.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const cp = require('node:child_process');
const path = require('node:path');
const [outside, git, parent] = process.argv.slice(2);
const failures = [];
function check(name, action) {
  try { action(); console.log(JSON.stringify({ name, passed: true })); }
  catch (error) {
    failures.push(name);
    console.log(JSON.stringify({ name, passed: false, error: error.message }));
  }
}
check('default-deny outside read', () => assert.throws(() => fs.readFileSync(outside)));
check('default-deny outside write', () => assert.throws(() => fs.writeFileSync(outside, 'escaped')));
check('workspace CRUD', () => {
  fs.writeFileSync('edit.tmp', 'ok');
  fs.renameSync('edit.tmp', 'edit.txt');
  assert.equal(fs.readFileSync('edit.txt', 'utf8'), 'ok');
  fs.unlinkSync('edit.txt');
});
check('CommonJS and ESM loading', () => {
  assert.equal(require('./module.cjs'), 42);
  const result = cp.spawnSync(process.execPath,
    ['--input-type=module', '-e', "import value from './module.mjs'; if(value!==43)process.exit(42)"],
    { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 0, JSON.stringify({ error: result.error?.code, stderr: result.stderr }));
});
for (const stdio of ['inherit', 'pipe', 'ignore']) {
  check(`confined descendant stdio:${stdio}`, () => {
    const code = `try{require('node:fs').readFileSync(${JSON.stringify(outside)});process.exit(42)}catch{process.exit(0)}`;
    const result = cp.spawnSync(process.execPath, ['-e', code], { stdio, timeout: 5000 });
    assert.equal(result.status, 0, JSON.stringify({ error: result.error?.code, stderr: result.stderr?.toString() }));
  });
}
check('outside hardlink creation denied', () => {
  assert.throws(() => fs.linkSync(outside, path.resolve('outside-alias')));
});
check('Git init and status', () => {
  for (const args of [['init', '--quiet'], ['status', '--porcelain']]) {
    const result = cp.spawnSync(git, args, { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, JSON.stringify({ error: result.error?.code, stderr: result.stderr }));
  }
});
// The native executable tests token properties and host-process access itself.
console.log(JSON.stringify({ kind: 'agentkeeper.restricted-token-workload.v1',
  parent: Number(parent), failures, networkQualified: false }));
process.exitCode = failures.length === 0 ? 0 : 1;
