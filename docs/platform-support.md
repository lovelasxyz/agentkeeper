# Platform support

What each backend actually enforces, and the highest status it can honestly
report today.

## Matrix

| Platform | Backend | Requirement | Best status today |
|---|---|---|---|
| Linux x64 / arm64 | bubblewrap + Unix-socket broker | `bwrap` installed, user namespaces permitted | `PROTECTED` |
| macOS (Apple Silicon and x64) | Seatbelt (`sandbox-exec`) + loopback broker | Built in | `DEGRADED` — see below |
| Windows 10/11 x64 / arm64 | AppContainer via the bundled native helper | Helper present in the package | `DEGRADED` — see below |
| Anything else | none | — | `UNPROTECTED`, and protected launches refuse to start |

Node ≥ 22.21.0 is required. That is the floor where Node's built-in HTTP
client honours the launcher-owned proxy variables; below it, an agent would be
safely confined but unable to reach the network at all.

## Linux — bubblewrap

Enforces:

- user and mount namespaces; the home directory is empty except for what the
  policy mounted
- read-only and read-write policy mounts, inherited by every descendant
- an isolated network namespace with **no route to the host**, and egress only
  through a relay bound to the broker's Unix socket

Refuses (rather than weakening) when:

- a deny rule has no fixed anchor and a broad runtime grant would make the
  wildcard refusal inexpressible in a mount namespace
- a network policy is requested without a verified Unix-relay broker

Without `bwrap`, there is no layer 1: `agentkeeper run` refuses to start the
command instead of running it unprotected.

## macOS — Seatbelt

Enforces:

- filesystem read/write restrictions covering the user's home, including every
  tier 2 path
- process-tree inheritance, verified by a child canary
- egress limited to the single loopback port of the launcher-owned broker
- DNS through the system resolver socket only — arbitrary Unix sockets are
  refused, so a local Docker, SSH agent or database socket is not a way around
  the file rules

**Why macOS reports `DEGRADED`, deliberately.** The current profile denies the
sensitive parts of the home directory but still permits broad reads *outside*
it — system and toolchain locations are allowed as a class rather than
enumerated. An enumerated read allowlist was attempted and reverted: on current
macOS it crashes the runtime before `main()` even with system roots included,
which would be a boundary that does not run rather than a boundary that holds.
The reason is reported as `seatbelt.broad-system-read` on every run, so the gap
is visible instead of hidden inside a green checkmark.

Credential, persistence, history and cross-project reads *are* denied, and the
sandbox conformance suite proves it against real processes.

**`sandbox-exec` is deprecated by Apple.** It is still the built-in mechanism
and still works. The backend is replaceable without touching the policy domain.

## Windows — AppContainer

A small native helper (`agentkeeper-sandbox.exe`, compiled in CI for x64 and
arm64 and shipped inside the package) creates an ephemeral AppContainer
profile, applies the allow and deny ACEs the policy asks for, binds the process
tree to a Job Object with kill-on-close, and rolls every ACL change back before
deleting the profile.

Enforces:

- an AppContainer SID with **zero capabilities** — including no network
- explicit grants for the workspace and the toolchain, explicit denies for
  protected paths
- process-tree containment through the Job Object
- one launch path only, and no handle inheritance

Reports `DEGRADED` because AppContainer keeps a documented common-system
compatibility surface, and because network egress stays denied: an AppContainer
cannot reach a loopback broker without an exemption this project does not grant.
Requested destinations are refused rather than silently opened.

Nothing is compiled on the user's machine, and nothing is downloaded at
install time. The release gate refuses to publish a tarball that does not
contain both helper binaries.

## Degradation is always named

No platform silently falls back to running the command unconfined. When a
mechanism is missing, `agentkeeper run` fails closed, and `doctor` explains
which component is unavailable with a stable reason code.
