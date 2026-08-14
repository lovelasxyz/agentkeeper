import { spawn } from 'node:child_process';
import type {
  InstallationProcessExecutor,
  InstallationProcessResult,
} from '../../application/ports/SystemIntegration.js';

const MAX_CAPTURE_BYTES = 1024 * 1024;

/** Production no-shell adapter; output is bounded so a child cannot exhaust memory. */
export class NodeInstallationProcessExecutor implements InstallationProcessExecutor {
  constructor(private readonly timeoutMilliseconds = 15_000) {}

  execute(executable: string, args: readonly string[]): Promise<InstallationProcessResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        stdout = appendBounded(stdout, chunk);
      });
      child.stderr.on('data', (chunk: string) => {
        stderr = appendBounded(stderr, chunk);
      });
      const timeout = setTimeout(() => {
        child.kill();
        reject(new Error(`${executable} timed out after ${this.timeoutMilliseconds} ms`));
      }, this.timeoutMilliseconds);
      timeout.unref();
      child.once('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once('close', (exitCode) => {
        clearTimeout(timeout);
        resolve({ exitCode: exitCode ?? 1, stdout, stderr });
      });
    });
  }
}

function appendBounded(current: string, chunk: string): string {
  if (current.length >= MAX_CAPTURE_BYTES) return current;
  return `${current}${chunk}`.slice(0, MAX_CAPTURE_BYTES);
}
