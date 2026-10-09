// Executed by the real Windows PSEC qualification, never by a mocked runner.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const cp = require('node:child_process');
const net = require('node:net');

const [outside, hostPort, pipePath, pipeAllowed, git] = process.argv.slice(2);
const failures = [];

async function check(name, run) {
  try {
    await run();
    console.log(`${name}: passed`);
  } catch (error) {
    failures.push(name);
    console.error(name, error);
  }
}

async function roundTrip(address) {
  return new Promise((resolve) => {
    const socket = typeof address === 'string'
      ? net.connect(address)
      : net.connect({ host: '127.0.0.1', port: address });
    let reply = '';
    const finish = (result) => { socket.destroy(); resolve(result); };
    socket.setTimeout(2000, () => finish(false));
    socket.once('error', () => finish(false));
    socket.once('connect', () => socket.write('canary'));
    socket.on('data', (data) => {
      reply += data.toString();
      if (reply.length >= 6) finish(reply === 'canary');
    });
    socket.once('end', () => finish(reply === 'canary'));
  });
}

async function main() {
  await check('filesystem, CommonJS and ESM', async () => {
    assert.throws(() => fs.readFileSync(outside), { code: /^(EPERM|EACCES)$/ });
    fs.writeFileSync('inside.txt', 'ok');
    fs.renameSync('inside.txt', 'renamed.txt');
    assert.equal(fs.readFileSync('renamed.txt', 'utf8'), 'ok');
    fs.unlinkSync('renamed.txt');
    assert.equal(require('./module.cjs'), 42);
    assert.equal((await import('./module.mjs')).default, 43);
  });

  await check('creating a hardlink to an outside object', () => {
    assert.throws(() => fs.linkSync(outside, 'new-outside-link'), { code: /^(EPERM|EACCES)$/ });
  });

  for (const stdio of ['inherit', 'ignore', 'pipe']) {
    await check(`descendant ${stdio}`, () => {
      const code = "try{require('node:fs').readFileSync(process.argv[1]);process.exit(42)}catch(e){process.exit(/^(EPERM|EACCES)$/.test(e.code)?0:43)}";
      const child = cp.spawnSync(process.execPath, ['-e', code, outside],
        { stdio, timeout: 5000, killSignal: 'SIGKILL' });
      console.log(JSON.stringify({ stdio, status: child.status, signal: child.signal, error: child.error?.code }));
      assert.equal(child.status, 0);
    });
  }

  for (const args of [['--version'], ['init', '--quiet'], ['status', '--porcelain']]) {
    await check(`git ${args.join(' ')}`, () => {
      const child = cp.spawnSync(git, args, { encoding: 'utf8', timeout: 5000 });
      console.log(JSON.stringify({ git: args, status: child.status, error: child.error?.code, stderr: child.stderr }));
      assert.equal(child.status, 0);
    });
  }

  await check('host TCP denial', async () => {
    assert.equal(await roundTrip(Number(hostPort)), false, 'Host TCP must remain denied');
  });
  await check('scoped host IPC', async () => {
    const pipeReached = await roundTrip(pipePath);
    console.log(JSON.stringify({ hostTcpDenied: true, hostPipeReached: pipeReached, pipeAllowed }));
    assert.equal(pipeReached, pipeAllowed === 'true', 'Only the explicitly granted IPC endpoint may be used');
  });
  if (failures.length > 0) throw new Error(`Qualification failed: ${failures.join(', ')}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
