import { randomBytes } from 'node:crypto';
import { createServer, connect, type Server, type Socket } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  DestinationBroker,
  DestinationBrokerSession,
} from '../../application/ports/NetworkBroker.js';
import type {
  NetworkProbe,
  NetworkProbeCode,
  NetworkProbeRequest,
  NetworkProbeResult,
} from '../../application/ports/NetworkProbe.js';
import type { NetworkBrokerTransport } from '../../domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../domain/value-objects/NetworkRule.js';
import { NodeDestinationBroker } from './NodeDestinationBroker.js';

export interface NodeNetworkProbeDependencies {
  readonly brokerFactory?: () => DestinationBroker;
  readonly timeoutMs?: number;
}

/** Never resolvable and never expressible as an allowlist entry, by construction. */
const CANARY_SUFFIX = 'agentkeeper-egress-canary.invalid';
/** Reachable from most clouds and never legitimately part of an agent's world. */
const METADATA_AUTHORITY = '169.254.169.254:80';
const DEFAULT_TIMEOUT = 2_000;

/**
 * Black-box canary for the destination broker.
 *
 * It answers the question `doctor` must not guess at: does the broker running
 * on this machine, right now, pass an approved destination and refuse an
 * unapproved one. Both halves matter — a broker that denies everything is as
 * broken as one that allows everything, just in the direction users notice.
 *
 * The approved half runs against a local sink instead of a provider, so the
 * result reports enforcement rather than whether the user is online.
 */
export class NodeNetworkProbe implements NetworkProbe {
  private readonly brokerFactory: () => DestinationBroker;
  private readonly timeoutMs: number;

  constructor(dependencies: NodeNetworkProbeDependencies = {}) {
    this.timeoutMs = dependencies.timeoutMs ?? DEFAULT_TIMEOUT;
    this.brokerFactory =
      dependencies.brokerFactory ??
      (() =>
        new NodeDestinationBroker({
          handshakeTimeoutMs: this.timeoutMs,
          idleTimeoutMs: this.timeoutMs,
        }));
  }

  async probe(request: NetworkProbeRequest): Promise<NetworkProbeResult> {
    const scratch = await mkdtemp(join(tmpdir(), 'agentkeeper-netprobe-'));
    let session: DestinationBrokerSession;
    try {
      session = await this.brokerFactory().start({
        destinations: request.destinations,
        platform: request.platform,
        scratch: AbsolutePath.of(scratch),
      });
    } catch {
      await rm(scratch, { recursive: true, force: true });
      return { passed: false, code: 'broker-unavailable' };
    }

    try {
      const denial = await this.checkDenials(session.enforcement.transport);
      if (denial !== null) return { passed: false, code: denial };

      const allowance = await this.checkApprovedTunnel(request);
      if (allowance !== null) return { passed: false, code: allowance };

      return { passed: true, code: 'passed', enforcement: session.enforcement };
    } finally {
      await session.close();
      await rm(scratch, { recursive: true, force: true });
    }
  }

  /** Destinations that must be refused whatever the session allowlist contains. */
  private async checkDenials(
    transport: NetworkBrokerTransport,
  ): Promise<NetworkProbeCode | null> {
    const arbitrary = `${randomBytes(8).toString('hex')}.${CANARY_SUFFIX}:443`;
    const [arbitraryAccepted, metadataAccepted] = await Promise.all([
      this.connectAccepted(transport, arbitrary),
      this.connectAccepted(transport, METADATA_AUTHORITY),
    ]);
    if (arbitraryAccepted) return 'arbitrary-destination-allowed';
    if (metadataAccepted) return 'metadata-destination-allowed';
    return null;
  }

  /**
   * Proves the approved path end to end against a local sink.
   *
   * A separate broker instance is used so the session's own allowlist is never
   * widened to make the canary pass.
   */
  private async checkApprovedTunnel(
    request: NetworkProbeRequest,
  ): Promise<NetworkProbeCode | null> {
    const scratch = await mkdtemp(join(tmpdir(), 'agentkeeper-netprobe-allow-'));
    let sink: EchoSink;
    let session: DestinationBrokerSession;
    try {
      sink = await EchoSink.start();
    } catch {
      await rm(scratch, { recursive: true, force: true });
      return 'allowed-destination-refused';
    }
    try {
      session = await this.brokerFactory().start({
        destinations: [NetworkRule.loopback()],
        platform: request.platform,
        scratch: AbsolutePath.of(scratch),
      });
    } catch {
      await sink.close();
      await rm(scratch, { recursive: true, force: true });
      return 'broker-unavailable';
    }

    try {
      return await this.relayCheck(session.enforcement.transport, `127.0.0.1:${sink.port}`);
    } finally {
      await session.close();
      await sink.close();
      await rm(scratch, { recursive: true, force: true });
    }
  }

  private async relayCheck(
    transport: NetworkBrokerTransport,
    authority: string,
  ): Promise<NetworkProbeCode | null> {
    const payload = randomBytes(16).toString('hex');
    let socket: Socket;
    try {
      socket = await this.dial(transport);
    } catch {
      return 'allowed-destination-refused';
    }
    try {
      const established = await this.handshake(socket, authority);
      if (!established) return 'allowed-destination-refused';
      const echoed = await readExactly(socket, payload.length, this.timeoutMs, () =>
        socket.write(payload),
      );
      return echoed === payload ? null : 'relay-failed';
    } catch {
      return 'relay-failed';
    } finally {
      socket.destroy();
    }
  }

  private async connectAccepted(
    transport: NetworkBrokerTransport,
    authority: string,
  ): Promise<boolean> {
    let socket: Socket;
    try {
      socket = await this.dial(transport);
    } catch {
      // No reachable broker means no egress, which is not an acceptance.
      return false;
    }
    try {
      return await this.handshake(socket, authority);
    } catch {
      return false;
    } finally {
      socket.destroy();
    }
  }

  private async handshake(socket: Socket, authority: string): Promise<boolean> {
    const preface = await readUntilHeaderEnd(socket, this.timeoutMs, () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    return /^HTTP\/1\.[01] 200\b/.test(preface);
  }

  private dial(transport: NetworkBrokerTransport): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket =
        transport.kind === 'unix-socket-relay'
          ? connect({ path: transport.socketPath.value })
          : connect({ host: '127.0.0.1', port: transport.port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('Broker transport did not accept a connection'));
      }, this.timeoutMs);
      timer.unref();
      socket.once('connect', () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }
}

/**
 * Local stand-in for an approved destination.
 *
 * It owns its connections so shutdown is immediate: waiting for peers to time
 * out would put seconds of dead time into every `doctor` run.
 */
class EchoSink {
  private constructor(
    private readonly server: Server,
    private readonly connections: Set<Socket>,
    readonly port: number,
  ) {}

  static start(): Promise<EchoSink> {
    return new Promise((resolve, reject) => {
      const connections = new Set<Socket>();
      const server = createServer((socket) => {
        connections.add(socket);
        socket.once('close', () => connections.delete(socket));
        socket.pipe(socket);
      });
      server.once('error', reject);
      server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
        server.off('error', reject);
        const address = server.address();
        if (typeof address !== 'object' || address === null) {
          reject(new Error('The canary sink did not receive a port'));
          return;
        }
        resolve(new EchoSink(server, connections, address.port));
      });
    });
  }

  close(): Promise<void> {
    for (const socket of this.connections) socket.destroy();
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }
}

function readUntilHeaderEnd(
  socket: Socket,
  timeoutMs: number,
  send: () => void,
): Promise<string> {
  return collect(socket, timeoutMs, send, (buffer) => {
    const boundary = buffer.indexOf('\r\n\r\n');
    return boundary === -1 ? null : buffer.subarray(0, boundary).toString('latin1');
  });
}

function readExactly(
  socket: Socket,
  bytes: number,
  timeoutMs: number,
  send: () => void,
): Promise<string> {
  return collect(socket, timeoutMs, send, (buffer) =>
    buffer.length < bytes ? null : buffer.subarray(0, bytes).toString('latin1'),
  );
}

function collect(
  socket: Socket,
  timeoutMs: number,
  send: () => void,
  complete: (buffer: Buffer) => string | null,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Broker canary timed out'));
    }, timeoutMs);
    timer.unref();

    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk], buffer.length + chunk.length);
      const finished = complete(buffer);
      if (finished === null) return;
      cleanup();
      resolve(finished);
    };
    const onEnd = (): void => {
      cleanup();
      reject(new Error('Broker canary connection closed early'));
    };
    const cleanup = (): void => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('close', onEnd);
      socket.off('error', onError);
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };

    socket.on('data', onData);
    socket.once('close', onEnd);
    socket.once('error', onError);
    send();
  });
}
