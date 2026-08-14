import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * A deterministic, file-backed fake of the user-level service manager.
 *
 * State lives in AGENTKEEPER_E2E_SERVICE_STATE so it survives across the many
 * short-lived CLI processes of the lifecycle suite, and the answers mirror
 * what the real managers print closely enough for the production parsers:
 * launchd's `state = running`, systemctl's plain-word states, and the
 * PowerShell probe's machine tokens.
 *
 * This is test infrastructure. It exists because the e2e suite must prove the
 * install lifecycle on machines where a real agentkeeper registration may
 * already exist — the fake answers instead of the real manager, never in
 * addition to it.
 */

const [executable, ...args] = process.argv.slice(2);
const stateDir = process.env['AGENTKEEPER_E2E_SERVICE_STATE'];
if (stateDir === undefined || executable === undefined) {
  process.stderr.write('fake-service-manager: AGENTKEEPER_E2E_SERVICE_STATE and a backend are required\n');
  process.exit(2);
}

const backend = executable.includes('launchctl')
  ? 'launchd'
  : executable.includes('systemctl')
    ? 'systemd'
    : 'schtasks';
const statePath = join(stateDir, `${backend}.json`);

function readState() {
  try {
    return JSON.parse(readFileSync(statePath, 'utf8'));
  } catch {
    return {};
  }
}

function writeState(state) {
  mkdirSync(dirname(statePath), { recursive: true });
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
}

const targetId = (target) => target.split('/').at(-1);

function launchd(args) {
  const state = readState();
  const verb = args[0];
  if (verb === 'print') {
    const entry = state[targetId(args[1])];
    if (entry === undefined) {
      process.stderr.write('Could not find service\n');
      process.exit(36);
    }
    process.stdout.write(`state = ${entry.running ? 'running' : 'waiting'}\n`);
    process.exit(0);
  }
  if (verb === 'bootstrap') {
    // RunAtLoad starts a freshly bootstrapped job, as the managed plist says.
    state['dev.agentkeeper.watcher'] = { registered: true, running: true };
    writeState(state);
    process.exit(0);
  }
  if (verb === 'bootout') {
    delete state[targetId(args[1])];
    writeState(state);
    process.exit(0);
  }
  if (verb === 'kickstart') {
    const id = targetId(args.at(-1));
    if (state[id] !== undefined) state[id] = { registered: true, running: true };
    writeState(state);
    process.exit(0);
  }
  if (verb === 'kill') {
    const id = targetId(args.at(-1));
    if (state[id] !== undefined) state[id] = { registered: true, running: false };
    writeState(state);
    process.exit(0);
  }
  process.stderr.write(`fake launchd: unsupported verb ${String(verb)}\n`);
  process.exit(1);
}

function systemd(args) {
  const state = readState();
  const id = args.at(-1);
  const verb = args.filter((arg) => arg !== '--user' && arg !== '--now' && arg !== id)[0];
  if (verb === 'is-enabled') {
    if (state[id] === undefined) {
      process.stderr.write('Failed to get unit file state\n');
      process.exit(1);
    }
    process.stdout.write('enabled\n');
    process.exit(0);
  }
  if (verb === 'is-active') {
    const running = state[id]?.running === true;
    process.stdout.write(`${running ? 'active' : 'inactive'}\n`);
    process.exit(running ? 0 : 3);
  }
  if (verb === 'daemon-reload') process.exit(0);
  if (verb === 'enable') state[id] = { registered: true, running: true };
  else if (verb === 'disable') delete state[id];
  else if (verb === 'stop') {
    if (state[id] !== undefined) state[id] = { registered: true, running: false };
  } else if (verb === 'restart') {
    if (state[id] !== undefined) state[id] = { registered: true, running: true };
  } else {
    process.stderr.write(`fake systemd: unsupported verb ${String(verb)}\n`);
    process.exit(1);
  }
  writeState(state);
  process.exit(0);
}

function schtasks(args) {
  const state = readState();
  const tnAt = args.indexOf('/TN');
  const id = tnAt === -1 ? undefined : args[tnAt + 1];
  const verb = args[0];
  if (verb === '/Query') {
    if (id === undefined || state[id] === undefined) {
      process.stderr.write('ERROR: The system cannot find the file specified.\n');
      process.exit(1);
    }
    process.stdout.write('<?xml version="1.0"?><Task/>\n');
    process.exit(0);
  }
  if (verb === '/Create') {
    if (id !== undefined) state[id] = { registered: true, running: state[id]?.running === true };
  } else if (verb === '/Run') {
    if (id !== undefined && state[id] !== undefined) state[id] = { registered: true, running: true };
  } else if (verb === '/End') {
    if (id !== undefined && state[id] !== undefined) state[id] = { registered: true, running: false };
  } else if (verb === '/Delete') {
    if (id !== undefined) delete state[id];
  } else {
    process.stderr.write(`fake schtasks: unsupported verb ${String(verb)}\n`);
    process.exit(1);
  }
  writeState(state);
  process.exit(0);
}

function powershell(args) {
  // The production probe is an encoded script emitting one machine token;
  // the fake answers with the token matching its own recorded state.
  const encodedAt = args.indexOf('-EncodedCommand');
  const script = encodedAt === -1 ? '' : Buffer.from(args[encodedAt + 1], 'base64').toString('utf16le');
  const match = /\$taskName = '((?:[^']|'')*)'/.exec(script);
  const id = match?.[1]?.replace(/''/g, "'");
  const state = readState();
  const running = id !== undefined && state[id]?.running === true;
  process.stdout.write(`agentkeeper-task-state:${running ? 'running' : 'stopped'}`);
  process.exit(0);
}

if (backend === 'launchd') launchd(args);
else if (backend === 'systemd') systemd(args);
else if (executable.includes('powershell')) powershell(args);
else schtasks(args);
