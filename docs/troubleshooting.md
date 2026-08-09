# Troubleshooting

Start here:

```sh
agentkeeper doctor
```

It runs fresh canaries rather than reading configuration, so its answer
describes this machine right now.

## Exit codes

| Command | Code | Meaning |
|---|---|---|
| `doctor`, `status` | 0 | `PROTECTED` and the installation is healthy |
| | 2 | `DEGRADED` — protection is up, gaps are named |
| | 3 | `UNPROTECTED` or `BYPASSED` |
| `integrations` | 0 / 2 | 2 when a shim exists but needs repair |
| `activate`, `repair`, `deactivate` | 0 / 2 / 3 | 2 = conflicts found, 3 = refused to proceed |
| `run` | *passthrough* | The command's own exit code |
| | 78 | The policy cannot be enforced; nothing was started |
| `allow`, `revoke` | 0 / 1 | 1 = refused, or no grant with that id |

## `doctor` says DEGRADED

That is the expected steady state on macOS and Windows — see
[platform support](platform-support.md). Read the reason codes:

| Code | Meaning | What to do |
|---|---|---|
| `seatbelt.broad-system-read` | macOS profile allows broad reads outside home | Expected today; credential and persistence paths are still denied |
| `appcontainer.compatibility-surface` | Windows keeps a common-system surface | Expected today |
| `network.broker-required` | Destinations requested, no verified broker | Check that nothing blocks loopback; on Linux confirm the relay script can be written to the scratch directory |
| `network.arbitrary-destination-allowed` | The broker accepted an unapproved host | Treat as a defect — please [report it](../SECURITY.md) |
| `process.child-boundary-unverified` | The child canary did not complete | Usually a runtime restriction on spawning; re-run `doctor` with the agent closed |
| `policy.unenforceable` | The backend cannot express part of the policy | Narrow the grant it names; broad wildcard grants are the usual cause |

## `run` refuses to start (exit 78)

By design. The policy could not be enforced, so nothing was launched. The
message names the gap. Common causes:

- **Linux without `bwrap`.** Install `bubblewrap`.
- **A legacy any-host network rule** (`tcp:443`) in a hand-edited profile. It
  has no destination to enforce; replace it with explicit destinations.
- **A broad runtime grant** that makes a wildcard deny inexpressible in a mount
  namespace. Grant a narrower subtree.

## The agent cannot reach the network

1. `agentkeeper policy` — is the destination in the list?
2. Destinations need an explicit port: `api.example.com:443`, not
   `api.example.com`.
3. Wildcards must be a full left-most label with a registrable suffix:
   `*.example.com` works, `*.com` and `api.*.com` are refused.
4. IP literals are refused on purpose; use the DNS name.
5. A client that ignores `HTTPS_PROXY` will fail rather than escape — that is
   the boundary working. Node ≥ 22.21.0 is required for the built-in client to
   honour it.

## `claude` still runs unprotected

```sh
agentkeeper integrations
```

- *unprotected* — run `agentkeeper activate`.
- *needs repair* — run `agentkeeper repair`.
- Open a new shell, or `source` your startup file: the managed line adds the
  shim directory to `PATH` at shell start.
- Check you are not in a shell where `AGENTKEEPER_BYPASS` is set.

## The agent cannot read a file it needs

If it is tier 1 — a neighbouring project, a shared cache:

```sh
agentkeeper allow ~/projects/shared --read
```

The grant applies to the **next** run.

If it is tier 2 — `~/.ssh`, `~/.aws`, a keychain, shell history — there is no
command, by design. Edit `~/.agentkeeper/allowlist.json` yourself, outside the
agent session. See [the boundary](security-boundary.md).

## A scan reports something I know is fine

Approvals are keyed by file content, so approving once is enough until the file
changes. If a rule is wrong for your project, its id is stable and listed in
[rules.md](rules.md); family A is off by default and the others can be narrowed
in `~/.agentkeeper/config.json` — except blocking rules, which are not
configurable.

## Undoing everything

```sh
agentkeeper deactivate          # or: agentkeeper uninstall
agentkeeper deactivate --purge  # also removes ~/.agentkeeper
```

Shims are removed, the one managed line in your startup file is removed, and
any file agentkeeper replaced is restored byte for byte from its backup. A
test asserts exactly that.

## Reporting a problem

`agentkeeper doctor --json` and `agentkeeper policy --json` produce
machine-readable output with no file contents, secrets or environment values in
it. Paths are shown home-relative. Security issues: [SECURITY.md](../SECURITY.md).
