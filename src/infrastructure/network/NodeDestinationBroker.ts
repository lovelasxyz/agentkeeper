import { lookup } from 'node:dns/promises';
import { randomInt } from 'node:crypto';
import { createServer, connect, isIP, type Server, type Socket } from 'node:net';
import { rm, writeFile } from 'node:fs/promises';
import type {
  DestinationBroker,
  DestinationBrokerSession,
  DestinationBrokerStartRequest,
} from '../../application/ports/NetworkBroker.js';
import type { NetworkRule } from '../../domain/value-objects/NetworkRule.js';
import {
  DestinationGuard,
  parseConnectAuthority,
  type ResolvedAddress,
} from './DestinationGuard.js';

export interface DestinationBrokerDependencies {
  readonly resolve?: (host: string) => Promise<readonly ResolvedAddress[]>;
  readonly dial?: (address: string, port: number, family: 4 | 6) => Promise<Socket>;
  readonly maxHeaderBytes?: number;
  readonly maxConnections?: number;
  readonly handshakeTimeoutMs?: number;
  readonly idleTimeoutMs?: number;
}

const DEFAULT_MAX_HEADER = 16 * 1024;
const DEFAULT_MAX_CONNECTIONS = 64;
const DEFAULT_HANDSHAKE_TIMEOUT = 10_000;
const DEFAULT_IDLE_TIMEOUT = 5 * 60_000;

/**
 * Local, body-blind HTTP CONNECT broker.
 *
 * It resolves and validates the destination on the host, pins the accepted IP
 * into the outbound socket, and then becomes a byte tunnel. TLS stays end to
 * end between the agent SDK and provider; this process never parses request
 * headers beyond the CONNECT preface and never logs traffic or credentials.
 */
export class NodeDestinationBroker implements DestinationBroker {
  private readonly guard = new DestinationGuard();
  private readonly resolveHost: (host: string) => Promise<readonly ResolvedAddress[]>;
  private readonly dialAddress: (
    address: string,
    port: number,
    family: 4 | 6,
  ) => Promise<Socket>;
  private readonly maxHeaderBytes: number;
  private readonly maxConnections: number;
  private readonly handshakeTimeoutMs: number;
  private readonly idleTimeoutMs: number;

  constructor(dependencies: DestinationBrokerDependencies = {}) {
    this.resolveHost = dependencies.resolve ?? resolveHost;
    this.dialAddress = dependencies.dial ?? dialAddress;
    this.maxHeaderBytes = positiveInteger(
      dependencies.maxHeaderBytes ?? DEFAULT_MAX_HEADER,
      'maxHeaderBytes',
    );
    this.maxConnections = positiveInteger(
      dependencies.maxConnections ?? DEFAULT_MAX_CONNECTIONS,
      'maxConnections',
    );
    this.handshakeTimeoutMs = positiveInteger(
      dependencies.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT,
      'handshakeTimeoutMs',
    );
    this.idleTimeoutMs = positiveInteger(
      dependencies.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT,
      'idleTimeoutMs',
    );
  }

  async start(request: DestinationBrokerStartRequest): Promise<DestinationBrokerSession> {
    this.validateRules(request.destinations);
    const server = createServer();
    const sockets = new Set<Socket>();
    server.maxConnections = this.maxConnections;
    server.on('connection', (socket) => {
      if (sockets.size >= this.maxConnections) {
        reject(socket, 503, 'Service Unavailable');
        return;
      }
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
      this.accept(socket, request.destinations, sockets).catch(() => {
        if (!socket.destroyed) reject(socket, 502, 'Bad Gateway');
      });
    });

    try {
      if (request.platform === 'linux') {
        const socketPath = request.scratch.join('broker.sock');
        const relayScript = request.scratch.join('network-relay.mjs');
        if (Buffer.byteLength(socketPath.value) > 100) {
          throw new Error('The Linux broker Unix-socket path exceeds the portable 100-byte limit');
        }
        await writeFile(relayScript.value, RELAY_SOURCE, { mode: 0o600, flag: 'wx' });
        await listenUnix(server, socketPath.value);
        const port = randomInt(20_000, 60_000);
        return this.session(
          server,
          sockets,
          `http://127.0.0.1:${port}`,
          {
            kind: 'brokered',
            transport: { kind: 'unix-socket-relay', socketPath, relayScript, port },
          },
          socketPath.value,
        );
      }

      const port = await listenTcp(server);
      return this.session(server, sockets, `http://127.0.0.1:${port}`, {
        kind: 'brokered',
        transport: { kind: 'tcp-loopback', port },
      });
    } catch (error) {
      for (const socket of sockets) socket.destroy();
      server.close();
      throw error;
    }
  }

  private validateRules(rules: readonly NetworkRule[]): void {
    if (rules.length === 0) throw new Error('A destination broker needs at least one destination');
    for (const rule of rules) {
      if (rule.allowsLoopback) continue;
      if (rule.protocol !== 'tcp') {
        throw new Error(`The destination broker supports CONNECT/TCP, not ${rule.protocol.toUpperCase()}`);
      }
      if (!rule.isExplicitDestination) {
        throw new Error(
          'An any-host network rule has no explicit destination and cannot enter protected mode',
        );
      }
    }
  }

  private async accept(
    client: Socket,
    rules: readonly NetworkRule[],
    open: Set<Socket>,
  ): Promise<void> {
    client.setTimeout(this.handshakeTimeoutMs, () => reject(client, 408, 'Request Timeout'));
    client.setNoDelay(true);
    let header = Buffer.alloc(0);

    const onData = async (chunk: Buffer): Promise<void> => {
      header = Buffer.concat([header, chunk], header.length + chunk.length);
      const boundary = header.indexOf('\r\n\r\n');
      if (header.length > this.maxHeaderBytes) {
        client.off('data', listener);
        reject(client, 431, 'Request Header Fields Too Large');
        return;
      }
      if (boundary === -1) return;

      client.off('data', listener);
      client.pause();
      const preface = header.subarray(0, boundary + 4).toString('latin1');
      const remainder = header.subarray(boundary + 4);
      const firstLine = preface.slice(0, preface.indexOf('\r\n'));
      const match = /^CONNECT ([^ ]+) HTTP\/1\.[01]$/.exec(firstLine);
      if (match === null) {
        reject(client, 405, 'Method Not Allowed');
        return;
      }

      let authority: { readonly host: string; readonly port: number };
      try {
        authority = parseConnectAuthority(match[1] as string);
      } catch {
        reject(client, 400, 'Bad Request');
        return;
      }

      // Refuse before DNS when the authority is not configured. Apart from
      // being faster, this avoids turning the broker into a DNS oracle.
      if (!authorityAllowed(authority.host, authority.port, rules)) {
        reject(client, 403, 'Forbidden');
        return;
      }

      let addresses: readonly ResolvedAddress[];
      try {
        addresses = await withTimeout(
          this.resolveHost(authority.host),
          this.handshakeTimeoutMs,
          'DNS resolution timed out',
        );
      } catch {
        reject(client, 502, 'Bad Gateway');
        return;
      }
      const authorization = this.guard.authorize(
        authority.host,
        authority.port,
        rules,
        addresses,
      );
      if (!authorization.allowed) {
        reject(client, 403, 'Forbidden');
        return;
      }

      let upstream: Socket;
      try {
        upstream = await withTimeout(
          this.dialAddress(
            authorization.pinnedAddress,
            authority.port,
            authorization.family,
          ),
          this.handshakeTimeoutMs,
          'Destination connect timed out',
        );
      } catch {
        reject(client, 502, 'Bad Gateway');
        return;
      }

      // The upstream half is tracked too. Without it `close()` leaves live
      // sockets behind, and the CLI keeps the event loop alive for a whole
      // idle timeout after the agent has already exited.
      open.add(upstream);
      upstream.once('close', () => open.delete(upstream));
      client.setTimeout(this.idleTimeoutMs, () => client.destroy());
      upstream.setTimeout(this.idleTimeoutMs, () => upstream.destroy());
      const destroyBoth = (): void => {
        client.destroy();
        upstream.destroy();
      };
      client.once('error', destroyBoth);
      upstream.once('error', destroyBoth);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (remainder.length > 0) upstream.write(remainder);
      client.pipe(upstream);
      upstream.pipe(client);
      client.resume();
    };
    const listener = (chunk: Buffer): void => {
      void onData(chunk).catch(() => {
        if (!client.destroyed) reject(client, 502, 'Bad Gateway');
      });
    };
    client.on('data', listener);
  }

  private session(
    server: Server,
    sockets: Set<Socket>,
    proxyUrl: string,
    enforcement: DestinationBrokerSession['enforcement'],
    unixSocketPath?: string,
  ): DestinationBrokerSession {
    let closed = false;
    return {
      proxyUrl,
      enforcement,
      close: async (): Promise<void> => {
        if (closed) return;
        closed = true;
        for (const socket of sockets) socket.destroy();
        await closeServer(server);
        if (unixSocketPath !== undefined) await rm(unixSocketPath, { force: true });
      },
    };
  }
}

function authorityAllowed(host: string, port: number, rules: readonly NetworkRule[]): boolean {
  return rules.some(
    (rule) =>
      (rule.isExplicitDestination && rule.matches(host, port)) ||
      (rule.allowsLoopback && isLoopbackAuthority(host)),
  );
}

function isLoopbackAuthority(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  if (isIP(normalized) === 4) return normalized.split('.')[0] === '127';
  return normalized === '::1' || normalized.toLowerCase().startsWith('::ffff:127.');
}

async function resolveHost(host: string): Promise<readonly ResolvedAddress[]> {
  const family = isIP(host);
  if (family === 4 || family === 6) return [{ address: host, family }];
  const addresses = await lookup(host, { all: true, verbatim: true });
  return addresses.flatMap((entry) =>
    entry.family === 4 || entry.family === 6
      ? [{ address: entry.address, family: entry.family }]
      : [],
  );
}

function dialAddress(address: string, port: number, family: 4 | 6): Promise<Socket> {
  return new Promise((resolve, rejectPromise) => {
    const socket = connect({ host: address, port, family });
    socket.once('connect', () => resolve(socket));
    socket.once('error', rejectPromise);
  });
}

function listenTcp(server: Server): Promise<number> {
  return new Promise((resolve, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      server.off('error', rejectPromise);
      const address = server.address();
      if (address === null || typeof address === 'string') {
        rejectPromise(new Error('Destination broker did not receive a TCP port'));
        return;
      }
      resolve(address.port);
    });
  });
}

function listenUnix(server: Server, path: string): Promise<void> {
  return new Promise((resolve, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen({ path, exclusive: true }, () => {
      server.off('error', rejectPromise);
      resolve();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function reject(socket: Socket, status: number, reason: string): void {
  if (socket.destroyed) return;
  socket.end(
    `HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`,
  );
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

async function withTimeout<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, rejectPromise) => {
        timer = setTimeout(() => rejectPromise(new Error(message)), milliseconds);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Runs as PID 1 inside bubblewrap's isolated network namespace. It exposes a
 * loopback TCP proxy and byte-for-byte relays each connection to the host-side
 * policy broker through the mounted Unix socket. The child never receives a
 * route to the host network.
 */
const RELAY_SOURCE = `import { createServer, connect } from 'node:net';
import { spawn } from 'node:child_process';

const [socketPath, rawPort, executable, ...args] = process.argv.slice(2);
if (!socketPath || !rawPort || !executable) process.exit(78);
const port = Number(rawPort);
const sockets = new Set();
const server = createServer((client) => {
  sockets.add(client);
  const upstream = connect({ path: socketPath });
  sockets.add(upstream);
  const close = () => { client.destroy(); upstream.destroy(); };
  client.once('error', close); upstream.once('error', close);
  client.once('close', () => sockets.delete(client));
  upstream.once('close', () => sockets.delete(upstream));
  client.pipe(upstream); upstream.pipe(client);
});
server.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
  delete process.env.AGENTKEEPER_INTERNAL_BROKER_SOCKET;
  delete process.env.AGENTKEEPER_INTERNAL_RELAY_SCRIPT;
  delete process.env.AGENTKEEPER_INTERNAL_RELAY_PORT;
  const child = spawn(executable, args, { cwd: process.cwd(), env: process.env, stdio: 'inherit' });
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'];
  for (const signal of signals) process.on(signal, () => child.kill(signal));
  child.once('error', () => process.exit(1));
  child.once('exit', (code, signal) => {
    for (const socket of sockets) socket.destroy();
    server.close(() => process.exit(code ?? (signal ? 128 : 1)));
  });
});
`;
