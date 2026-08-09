import { connect, createServer, type Socket } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { NetworkRule } from '../../src/domain/value-objects/NetworkRule.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { NodeDestinationBroker } from '../../src/infrastructure/network/NodeDestinationBroker.js';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function exchange(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1');
    let response = '';
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.write(request));
    socket.on('data', (chunk: string) => {
      response += chunk;
      if (response.includes('\r\n\r\n')) {
        socket.destroy();
        resolve(response);
      }
    });
    socket.once('error', reject);
  });
}

describe('NodeDestinationBroker', () => {
  it('denies a CONNECT outside the destination allowlist before dialing', async () => {
    let dialled = false;
    const broker = new NodeDestinationBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      dial: async () => {
        dialled = true;
        throw new Error('must not dial');
      },
    });
    const scratch = await mkdtemp(join(tmpdir(), 'agentkeeper-broker-test-'));
    const session = await broker.start({
      destinations: [NetworkRule.destination('api.openai.com', 443)],
      platform: 'darwin',
      scratch: AbsolutePath.of(scratch),
    });
    cleanups.push(async () => {
      await session.close();
      await rm(scratch, { recursive: true, force: true });
    });

    expect(session.proxyUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const port = Number(new URL(session.proxyUrl).port);
    const response = await exchange(
      port,
      'CONNECT collector.invalid:443 HTTP/1.1\r\nHost: collector.invalid:443\r\n\r\n',
    );
    expect(response).toContain('403 Forbidden');
    expect(dialled).toBe(false);
  });

  it('fails closed on an oversized or non-CONNECT proxy preface', async () => {
    const broker = new NodeDestinationBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      dial: async () => new Promise<Socket>(() => undefined),
      maxHeaderBytes: 128,
    });
    const scratch = await mkdtemp(join(tmpdir(), 'agentkeeper-broker-test-'));
    const session = await broker.start({
      destinations: [NetworkRule.destination('api.openai.com', 443)],
      platform: 'darwin',
      scratch: AbsolutePath.of(scratch),
    });
    cleanups.push(async () => {
      await session.close();
      await rm(scratch, { recursive: true, force: true });
    });
    const port = Number(new URL(session.proxyUrl).port);

    expect(await exchange(port, 'GET http://api.openai.com/ HTTP/1.1\r\n\r\n')).toContain(
      '405 Method Not Allowed',
    );
    expect(
      await exchange(port, `CONNECT api.openai.com:443 HTTP/1.1\r\nX:${'x'.repeat(200)}\r\n\r\n`),
    ).toContain('431 Request Header Fields Too Large');
  });

  it('uses a private Unix socket transport for an isolated Linux namespace', async () => {
    const broker = new NodeDestinationBroker();
    const scratch = await mkdtemp(join(tmpdir(), 'agentkeeper-broker-test-'));
    const session = await broker.start({
      destinations: [NetworkRule.destination('registry.npmjs.org', 443)],
      platform: 'linux',
      scratch: AbsolutePath.of(scratch),
    });
    cleanups.push(async () => {
      await session.close();
      await rm(scratch, { recursive: true, force: true });
    });

    expect(session.enforcement).toMatchObject({
      kind: 'brokered',
      transport: { kind: 'unix-socket-relay' },
    });
    expect(session.proxyUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it('refuses legacy any-host and UDP rules instead of silently weakening them', async () => {
    const broker = new NodeDestinationBroker();
    const scratch = AbsolutePath.of('/tmp/agentkeeper-test');
    await expect(
      broker.start({ destinations: [NetworkRule.tcp(443)], platform: 'darwin', scratch }),
    ).rejects.toThrow(/destination|any host|explicit/i);
    await expect(
      broker.start({ destinations: [NetworkRule.udp(53)], platform: 'linux', scratch }),
    ).rejects.toThrow(/TCP|UDP|broker/i);
  });
});
