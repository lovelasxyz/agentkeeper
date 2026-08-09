# Network model

Egress is a capability with a destination, not a port number.

## Default

Deny. A policy with no destinations produces a sandbox with no outbound
network at all.

## The broker

```
sandboxed process
      │  (the only egress the OS profile permits)
      ▼
launcher-owned destination broker
      │  allowlist → DNS → address validation → pinned connect
      ▼
        the destination, or 403
```

The broker is a local, body-blind HTTP `CONNECT` proxy started by the
launcher. It resolves and validates the destination on the host side, pins the
accepted IP into the outbound socket, and then becomes a byte tunnel. TLS stays
end to end between the agent and the provider: the broker never terminates it,
never parses request headers beyond the `CONNECT` line, and never logs traffic,
bodies or credentials.

The child receives the proxy through launcher-owned variables (`HTTPS_PROXY`,
`npm_config_proxy`, `NODE_USE_ENV_PROXY=1`, …), which it cannot forge because
the sanitizer strips any inherited value first. A client that ignores those
variables does not escape — it loses connectivity, because direct egress is
closed by the OS backend.

## Policy shape

```jsonc
{
  "network": {
    "default": "deny",
    "allow": [
      "api.anthropic.com:443",
      "*.openai.com:443",
      "registry.npmjs.org:443",
      "github.com:443"
    ]
  }
}
```

- Destinations are DNS names with an explicit port. IP literals are rejected.
- A wildcard must occupy the whole left-most label (`*.example.com`) and needs
  a registrable suffix — `*.com` is refused.
- A legacy any-host rule (`tcp:443`) is still parsed so old profiles load, but
  it **cannot enter protected mode**: it has no destination to enforce, so the
  broker refuses to start and the run fails closed.
- `localhost` is a separate capability for local dev servers and MCP, never
  implied by an internet destination.

## What is refused after DNS

The decision happens between resolution and `connect(2)`, and it inspects
**every** address in the answer, not just the one that would be used:

| Refused | Why |
|---|---|
| `169.254.0.0/16` | Link-local, including cloud metadata (`169.254.169.254`) |
| `127.0.0.0/8`, `::1` | Loopback, unless a loopback rule was granted explicitly |
| `10/8`, `172.16/12`, `192.168/16`, CGNAT | Private networks and the LAN |
| Anything outside global unicast for IPv6 | Including IPv4-mapped forms of the above |
| A mixed answer | One public and one private address rejects the hostname as a whole |

The accepted address is then **pinned** into the socket, so a second resolver
lookup cannot rebind the request after it was checked.

## Transports per platform

The destination policy is identical everywhere; only the pipe differs.

| Platform | Transport | Note |
|---|---|---|
| macOS | Loopback TCP to the broker | The Seatbelt profile permits that one loopback port and nothing else. DNS is allowed only through the system `mDNSResponder` socket, not through arbitrary Unix sockets. |
| Linux | Unix socket relay into an isolated network namespace | The sandbox has no route to the host network. A relay inside the namespace forwards loopback connections to the mounted socket. |
| Windows | None yet | AppContainer starts with zero network capability; requested egress stays denied and is reported as such. |

## Proving it

`agentkeeper doctor` runs a network canary before reporting anything as
`brokered`:

1. an approved tunnel is driven end to end against a local sink, and bytes must
   survive the round trip;
2. a random unapproved authority must be refused;
3. the cloud metadata endpoint must be refused.

Failures are reported by name — `network.arbitrary-destination-allowed`,
`network.metadata-destination-allowed`, `network.relay-failed`,
`network.allowed-destination-refused`, `network.broker-unavailable` — and any
of them keeps the status out of `PROTECTED`.

The sandbox conformance suite additionally checks the real thing on a real
process: an allowed host succeeds, another host on the same port gets 403, a
direct connection that bypasses the broker fails, and a local credential-like
Unix socket is unreachable.

## What is not promised

Nothing inside an allowed destination is inspected. A key leaked through
`api.anthropic.com` is [T9](threat-model.md), and no packet-content DLP is
attempted. The mitigation is a narrow allowlist, not traffic analysis.
