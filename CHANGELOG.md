# Changelog

## 1.0.3

### Fixed

- **The machine keychain left with the agent (macOS).** `/Library/Keychains`
  sits outside the home directory, where the Seatbelt profile still permits
  broad reads, and `System.keychain` is world-readable — so a confined agent
  could copy the machine's Wi-Fi and 802.1X secrets and its certificate store
  and attack them offline. It and the SSH host keys under `/private/etc/ssh`
  are now tier 2 denies, verified against a live sandbox directly, through the
  `/etc` symlink, through the `/System/Volumes/Data` firmlink, and from a child
  process. Found by attacking the shipped package, not by reading the tests.

### Changed

- The Windows launcher is unchanged from 1.0.2. Detaching the AppContainer
  child was tried and did not move the canary, so the guess was reverted rather
  than shipped; see `docs/platform-support.md`.

## 1.0.2

### Fixed

- Signals reach the confined process instead of only the sandbox helper, so
  Ctrl-C ends the agent rather than orphaning it. On Linux the whole confined
  tree is signalled and given a grace period before bubblewrap is torn down.

## 1.0.1

### Fixed

- The CLI reported a placeholder version; the published version is now injected
  at build time.
- Abandoned sandboxed runs are terminated, and drift records are scoped to the
  workspace that produced them.
- Releases publish over OIDC without a stored credential.

## 1.0.0

First public release.

agentkeeper puts an AI coding agent inside an OS-level sandbox and keeps it
there. Credentials, persistence surfaces, shell history and other projects are
not hidden from the agent — they are absent from the world it runs in. The
network is a destination allowlist rather than a port filter, and everything
the agent starts inherits the boundary, because the OS enforces it rather than
a tool-call hook.

### What the boundary covers

- **Transparent launch.** After `agentkeeper activate` you keep typing
  `claude`, `codex`, `gemini`, `opencode`. The agent binary is never patched.
- **Non-promptable tier 2.** `~/.ssh`, `~/.aws`, keychains, browser profiles,
  shell history and every persistence surface have no "allow" button anywhere.
  Granting one means editing `~/.agentkeeper/allowlist.json` yourself, outside
  any agent session.
- **Inheritance.** MCP servers, `npm` lifecycle scripts, subprocesses and
  nested agents all run inside the same boundary.
- **Destination-controlled network.** A local, body-blind CONNECT broker
  validates every DNS answer, refuses loopback, RFC1918, link-local and cloud
  metadata, and pins the accepted address into the socket.
- **Truthful status.** `PROTECTED` is only reported after a live deny canary
  passes in a process *and its child*, and after the broker has been proven to
  allow an approved destination and refuse an unapproved one.
- **Workspace guard.** Autorun artifacts and injected instructions are flagged
  with content-addressed approvals, so a rug-pull becomes a new decision.

### Platform state, stated plainly

| Platform | Backend | Best status |
|---|---|---|
| Linux (bubblewrap) | user + mount + network namespaces, Unix-socket broker | `PROTECTED` |
| macOS (Seatbelt) | filesystem + process tree, loopback broker | `DEGRADED` |
| Windows (AppContainer) | filesystem + process tree, no egress | `DEGRADED` |

macOS reports `DEGRADED` on every run because the profile still permits broad
reads *outside* the home directory. Credentials, persistence, history and
cross-project reads are denied and proven by the conformance suite; the
remaining gap is named `seatbelt.broad-system-read` rather than hidden.

The Windows AppContainer backend builds, translates policy and passes its unit
and integration suites, but a real confined canary does not complete yet. It is
scoped as post-1.0 and its sandbox suite is reported without gating the release.

### Supply chain

- Published from CI with provenance (SLSA) and an SBOM.
- Zero runtime dependencies, no `postinstall` script, no network at runtime.
- The release gate refuses to publish a tarball missing either Windows helper,
  verified by reading the packed archive itself.

### Known gaps

Tracked openly rather than implied away:

- Windows: the AppContainer canary does not complete.
- Linux: `SIGTERM` reaches the sandbox but not the agent, so the process tree
  is terminated instead of shutting down cleanly.
- macOS: `seatbelt.broad-system-read` has not been narrowed.
- Exfiltration through an *allowed* destination is not detected, by design.
