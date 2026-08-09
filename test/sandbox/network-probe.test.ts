import { createServer, type Server } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { NetworkProbeCode } from '../../src/application/ports/NetworkProbe.js';
import { NetworkRule } from '../../src/domain/value-objects/NetworkRule.js';
import { NodeNetworkProbe } from '../../src/infrastructure/network/NodeNetworkProbe.js';

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

/** Stands in for an approved destination, so the canary needs no real internet. */
function sink(): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = createServer((socket) => socket.pipe(socket));
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      cleanups.push(
        () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      );
      resolve(server);
    });
  });
}

describe('NodeNetworkProbe', () => {
  it('passes only after an approved tunnel carries bytes and unapproved ones are refused', async () => {
    await sink();

    const result = await new NodeNetworkProbe().probe({
      destinations: [NetworkRule.destination('api.anthropic.com', 443)],
      platform: process.platform === 'linux' ? 'linux' : 'darwin',
    });

    expect(result.code).toBe<NetworkProbeCode>('passed');
    expect(result.passed).toBe(true);
    expect(result.enforcement).toMatchObject({ kind: 'brokered' });
  });

  it('refuses to call a policy brokered when no destination is expressible', async () => {
    const result = await new NodeNetworkProbe().probe({
      // A legacy any-host rule cannot be brokered, so the canary must not start.
      destinations: [NetworkRule.tcp(443)],
      platform: 'darwin',
    });

    expect(result.passed).toBe(false);
    expect(result.code).toBe<NetworkProbeCode>('broker-unavailable');
  });

  it('reports an unconfined broker rather than a passing canary', async () => {
    // A broker that answers 200 to everything is exactly the failure the canary
    // exists to catch; the probe must name it instead of reporting success.
    const result = await new NodeNetworkProbe({
      brokerFactory: () => new PermissiveBroker(),
    }).probe({
      destinations: [NetworkRule.destination('api.anthropic.com', 443)],
      platform: 'darwin',
    });

    expect(result.passed).toBe(false);
    expect(result.code).toBe<NetworkProbeCode>('arbitrary-destination-allowed');
  });
});

/** Minimal CONNECT server that approves every authority. */
class PermissiveBroker {
  async start(): Promise<{
    proxyUrl: string;
    enforcement: { kind: 'brokered'; transport: { kind: 'tcp-loopback'; port: number } };
    close(): Promise<void>;
  }> {
    const server = createServer((socket) => {
      socket.once('data', () => socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'));
    });
    const port = await new Promise<number>((resolve, reject) => {
      server.once('error', reject);
      server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
        const address = server.address();
        resolve(typeof address === 'object' && address !== null ? address.port : 0);
      });
    });
    return {
      proxyUrl: `http://127.0.0.1:${port}`,
      enforcement: { kind: 'brokered', transport: { kind: 'tcp-loopback', port } },
      close: () =>
        new Promise<void>((done) => {
          server.close(() => done());
        }),
    };
  }
}
