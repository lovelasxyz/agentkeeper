# Platform support

What each backend actually enforces, and the highest status it can honestly
report today.

## Matrix

| Platform | Backend | Requirement | Best status today |
|---|---|---|---|
| Linux x64 / arm64 | bubblewrap + Unix-socket broker | `bwrap` installed, user namespaces permitted | `PROTECTED` |
| macOS (Apple Silicon and x64) | Seatbelt (`sandbox-exec`) + loopback broker | Built in | `DEGRADED` — see below |
| Windows | — none shipped | — | `UNPROTECTED`, and protected launches refuse to start |
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
sensitive parts of the home directory, and the credential stores outside it —
the machine keychain under `/Library/Keychains` and the SSH host keys under
`/private/etc/ssh` — but it still permits broad reads elsewhere outside home:
system and toolchain locations are allowed as a class rather than enumerated. An enumerated read allowlist was attempted and reverted: on current
macOS it crashes the runtime before `main()` even with system roots included,
which would be a boundary that does not run rather than a boundary that holds.
The reason is reported as `seatbelt.broad-system-read` on every run, so the gap
is visible instead of hidden inside a green checkmark.

Credential, persistence, history and cross-project reads *are* denied, and the
sandbox conformance suite proves it against real processes.

**`sandbox-exec` is deprecated by Apple.** It is still the built-in mechanism
and still works. The backend is replaceable without touching the policy domain.

## Windows — sandbox development frozen

Windows sandbox development was frozen on October 10, 2026. No native backend
ships: the package gate rejects `dist/native/`, `doctor` reports `UNPROTECTED`
with `platform.windows-runner-unavailable`, and protected launches refuse to
start. Freezing development does not establish Windows isolation.

The file-watch detection layer, PreToolUse rules and Git hook integration remain
available. Ordinary Windows portability and detection tests still run in CI.

Experimental AppContainer, PSEC and restricted-token sources and tests are
retained for future investigation. Their qualification is no longer automatic
or a prerequisite for macOS/Linux releases. The PSEC, restricted-token and host
inventory workflows require an explicit manual run. See
[the frozen Windows investigation](windows-validation.md) for known failures,
including incomplete registry ACL restoration in the restricted-token proof.
Native artifacts remain excluded until a future backend has completed real
isolation, toolchain, network and lifecycle qualification.

## Degradation is always named

No platform silently falls back to running the command unconfined. When a
mechanism is missing, `agentkeeper run` fails closed, and `doctor` explains
which component is unavailable with a stable reason code.

## Narrowing the gaps (roadmap, not blockers)

The `DEGRADED` states above are deliberate, not unfinished work: a boundary
that fails to launch protects nothing, and a false green is worse than an
honest yellow. The residual gap on macOS is narrow — system files outside home are
readable but not writable, tier 2 stays fully denied, and egress is brokered.
Possible future narrowing, in order of increasing cost:

- **macOS, more targeted denies outside home.** The credential stores are done:
  `/Library/Keychains` and `/private/etc/ssh` are tier 2 denies, verified
  against a live sandbox. `/var/root` and the local account database are closed
  by file permissions rather than by the profile, so an agent running as an
  administrator would still reach them. Each further deny shrinks
  `seatbelt.broad-system-read` without the enumerated allowlist that crashes
  the runtime.
- **macOS, Endpoint Security system extension**: Apple entitlement,
  notarization and user consent — a different class of product, not a profile
  change.
