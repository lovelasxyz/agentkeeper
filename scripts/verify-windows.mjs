import { execFileSync } from 'node:child_process';
import { buildWindowsSandbox } from './build-windows-sandbox.mjs';

if (process.platform !== 'win32') {
  throw new Error('Windows qualification must run on Windows. Portable tests cannot verify AppContainer enforcement.');
}
const npmCli = process.env.npm_execpath;
if (npmCli === undefined) throw new Error('Run this gate through npm run verify:windows.');
for (const step of ['typecheck', 'lint:arch', 'test:windows-native', 'coverage', 'build']) {
  execFileSync(process.execPath, [npmCli, 'run', step], { stdio: 'inherit' });
}
await buildWindowsSandbox();
// No continue-on-error here: a hung canary or a link escape fails qualification.
execFileSync(process.execPath, [npmCli, 'run', 'test:sandbox'], { stdio: 'inherit' });
console.log('Windows candidate qualification passed; network/agent compatibility and release packaging still require review.');
