# agentkeeper

**English** · [Русский](README.ru.md)

Confine an AI coding agent to what it needs, using the sandboxing your operating
system already has. No Docker, no containers, no cloud service, no telemetry —
and no change to how you work: you keep typing `claude`, `gemini`, `codex`.

It protects your machine, your keys and your API tokens in both directions:
from what a compromised or injected agent might *do* (read `~/.ssh`, harvest
`.env` files, exfiltrate), and from who the agent *talks to* — including
"free proxy providers" whose business model is reselling access to new models
while your conversation, your key and your workspace secrets flow through
their server.

```sh
npm i -g agentkeeper
agentkeeper activate
```

Once. Then keep typing `claude`, `codex`, `gemini`, `opencode` exactly as
before.

---

## The idea

> Rules have to guess what is bad. A sandbox simply does not offer the option.

A prompt injection controls the agent's *intent*, not what the agent can
physically reach. A poisoned `CLAUDE.md` can tell the agent to read
`~/.ssh/id_rsa` — the agent will try, and the file will not exist in its world.
The attack fired, nothing happened, nobody was interrupted.

So isolation comes first here, and detection is the backup for the places
isolation cannot reach.

**agentkeeper limits what the agent can do, and records what it does. It is
weaker than full container isolation and stronger than any set of rules.**

---

## What it actually does

Two layers, which do not duplicate each other.

**Layer 1 — the sandbox.** The agent starts inside an OS isolation profile:
`sandbox-exec` (Seatbelt) on macOS, `bubblewrap` on Linux, AppContainer on
Windows. This decides what exists at all. Outbound traffic goes through a
destination broker that allows named hosts and refuses everything else.

**Layer 2 — the rules.** A `PreToolUse` hook, a global git hook and a small
resident watcher observe what happens *inside* that boundary — the things
isolation cannot see, because they involve resources the agent is allowed to
touch.

### Threat coverage

Reproduced without softening. "No" means no.

| Vector | Layer | Prevented | Detected |
|---|---|---|---|
| V1–V3 (autorun artifacts in a repository) | 2 | Yes | Yes |
| V4 (environment config, CVE-2026-21852) | 1 + 2 | Yes | Yes |
| V5 (side-channel exfiltration) | 1 | Partly (destination allowlist) | **No** |
| V6 (untrusted input in CI) | 2 | Yes | Yes |
| V7 (rug-pull) | 2 | Yes | Yes |
| V8 (MCP server swap) | 1 + 2 | Yes | Yes |
| V9 (persistence outside the repo) | 1 | **Yes** | Yes |
| V10 (credential harvesting) | 1 | **Yes** | Partly |
| V11 (irreversible actions) | 1 + 2 | Yes | Yes |
| V12 (escaping observation) | 1 | **Yes** | **No** |

The bold cells became possible only with layer 1. A rules-only tool answers "no"
in every one of them, because a subprocess of an approved command, or an MCP
server, or a second agent, never passes through a tool-call hook at all.

**On exfiltration, plainly.** Promising to spot a leak in outbound traffic is
not something this project can honestly do. CVE-2026-54316 leaked an API key one
character at a time through a Hugging Face download counter; there was nothing
recognisable in the traffic. The position taken here is: **restrict which
destinations exist, do not promise to detect what leaves through an allowed
one.**

---

## The two tiers

This is the part that decides whether the permission model means anything.

If a permission can be requested at the moment of the attack, the whole thing
collapses: an injection waits for a distracted moment and asks. So resources are
split, and the two halves are granted in genuinely different ways.

**Tier 1 — everyday. Asked about while the agent runs.**
A neighbouring project directory, `~/.gitconfig` (read), package manager caches,
editor configuration. A wrong "yes" costs little.

**Tier 2 — dangerous. Never asked about. Ever.**
`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.netrc`,
`~/.npmrc`, `~/.config/gh`, the macOS keychain, browser profiles, shell history,
every persistence surface, and every agent settings file.

These have **no "allow" button anywhere in the interface**. Not "are you sure",
not "requires confirmation" — absent. The refusal is silent and the event is
logged.

The only way to grant tier 2 access is to open `~/.agentkeeper/allowlist.json`
in a text editor yourself:

```jsonc
{
  "version": 1,
  "grants": [
    {
      "resource": "file:~/.ssh/deploy_key",
      "access": "read",
      "scope": "global",
      "reason": "the build signs artifacts with this key"
    }
  ]
}
```

An injection can phrase any request. It cannot open your editor at a different
moment in time. That gap between *asking* and *receiving* is what makes the
model hold — and it is enforced structurally, not by trust: the sandbox never
makes `~/.agentkeeper` writable, and rule AG-B005 refuses tool calls that reach
for it.

---

## Honest limits

| Limit | What follows |
|---|---|
| The profile is fixed when the process starts | A new grant applies to the **next** run. The tool says so instead of pretending otherwise. |
| Nothing inside an allowed destination is inspected | Once `api.anthropic.com:443` is allowed, what travels inside that TLS session is not examined. The alternative is terminating the agent's TLS, which is worse. |
| macOS reports `DEGRADED`, not `PROTECTED` | The Seatbelt profile denies every credential, persistence and history path but still permits broad reads *outside* home. An enumerated read allowlist crashes the runtime on current macOS, so the gap is reported on every run instead of hidden. |
| Windows reports `DEGRADED` | AppContainer confines the filesystem and the process tree, but keeps a documented common-system surface, and its egress stays denied rather than brokered. |
| `sandbox-exec` is deprecated by Apple | Still the built-in mechanism, still working in current macOS. The risk is stated here rather than hidden. |
| `bwrap` is not installed everywhere | Without it, layer 1 is unavailable and `run` refuses to start rather than run unprotected. |
| Weaker than a container | Shared kernel. |
| The agent can still wreck the workspace | Isolation protects the system, not your working tree — that is what git is for. |
| The wrapper costs more than the design's 100 ms | Measured: a Node process plus `sandbox-exec` is a ~95 ms floor before agentkeeper does anything. Our own share is ~60 ms; the total a user feels is ~155 ms on a busy machine, less on an idle one. The number in the design brief was written without measuring that floor. |

**When no mechanism is available, `agentkeeper run` refuses to start the
command.** A quiet unprotected launch is worse than no tool at all, because you
would believe you were covered.

---

## What this is not

| Not | Why |
|---|---|
| A general antivirus | No signatures, no interest in processes outside the agent |
| A GitHub Actions linter | [`zizmor`](https://github.com/woodruffw/zizmor) and `actionlint` do that better |
| A secret scanner | `gitleaks` and `trufflehog` exist |
| An MCP static analyser | Different class of product |
| A cloud service | No backend, no telemetry, no accounts |
| A replacement for containers | Weaker guarantees, better ergonomics — see above |

### agentkeeper and zizmor

| | zizmor | agentkeeper |
|---|---|---|
| Workflow structure, permissions, injection sinks | Thorough, structural | Not attempted |
| Agent-specific CI delta (vulnerable CLI versions, `--yolo`, two passes over one checkout, untrusted trigger + secrets) | — | Yes |
| Everything outside CI | — | The actual product |

Run both. The CI rules here are a small delta, and they read the workflow as
text rather than parsing YAML — deliberately, so as not to reimplement a job
somebody else does properly.

---

## Usage

```sh
agentkeeper activate              # set up once, showing a diff of every change
agentkeeper doctor                # probe the real sandbox; explain every gap
agentkeeper status                # the same answer, briefly
agentkeeper policy                # the effective boundary here, and its hash
agentkeeper integrations          # which agents actually launch through the guard
agentkeeper allow <path> --read   # open one tier 1 path; --workspace to scope it
agentkeeper revoke <id>           # close it again
agentkeeper scan [path]           # inspect a repository (also runs as a git hook)
agentkeeper log --since 7d        # what was recorded
agentkeeper pause 1h              # silence notifications (isolation stays on)
agentkeeper repair                # restore managed files after drift
agentkeeper run -- <cmd>          # advanced: run anything inside the profile
agentkeeper deactivate            # remove everything, restore the originals
```

After `activate` you keep typing `claude` — a shim on `PATH` routes it through
the boundary.

**There is no environment variable that switches the shim off.** An
interception any variable can disable is not interception, and a poisoned
context can produce a variable. If you need to run an agent unconfined, do it
deliberately: invoke the real binary by its own path, or run
`agentkeeper deactivate`. A session that ran outside the boundary is reported
as `BYPASSED`, never as protection.

### Documentation

[Architecture](docs/architecture.md) ·
[Threat model](docs/threat-model.md) ·
[Security boundary](docs/security-boundary.md) ·
[Network model](docs/network-model.md) ·
[Platform support](docs/platform-support.md) ·
[Agent compatibility](docs/agent-compatibility.md) ·
[Policy](docs/policy.md) ·
[Rules](docs/rules.md) ·
[Threat coverage](docs/threat-coverage.md) ·
[Troubleshooting](docs/troubleshooting.md)

### Starter profiles

`activate` offers a pre-filled allowlist so the first week is a handful of questions
rather than a hundred: `web`, `python`, `infra`, `minimal`. They are data files
under [`profiles/`](profiles/) — pull requests welcome.

---

## Installing agentkeeper does not run any code

There is **no `postinstall` script** in this package. A dependency that writes
itself into your configuration at install time is indistinguishable from
malware, and that is precisely the ChainDrop signature this tool watches for.
Nothing happens until you run `agentkeeper activate`, and it shows you a diff of
every file it wants to touch.

The same applies to the shell integration. Writing to `~/.zshrc` *is* vector V9.
So: explicit consent, the exact text shown first, one line pointing at a
separate file, and `uninstall` verified by a test to restore the original byte
for byte.

Other properties, all checkable in a minute:

- **No network at runtime.** Nothing in this package makes an outbound request.
- **No telemetry.** There is nowhere for data to go.
- **Zero runtime dependencies.** Nothing but the Node standard library.
- **The audit log holds paths, hashes and rule ids — never file contents.** A
  log of what was protected must not become the one place all of it is written
  down in the clear.

---

## Rules

Identifiers are stable. Full catalogue in [`docs/rules.md`](docs/rules.md).

| Family | Covers | Default |
|---|---|---|
| H | Autorun artifacts: hooks, `folderOpen` tasks, devcontainer lifecycle, git hooks | on |
| E | Environment and MCP: `.gemini/.env`, MCP servers, endpoint overrides, auto-approval | on |
| I | Instruction files: fetch-and-execute imperatives, invisible text, drift | on |
| B | Refusals inside the sandbox: protected paths, agent config, `core.hooksPath`, self-protection | on, **not disableable** |
| P | Persistence outside the sandbox, compared against a trusted baseline | on |
| C | CI delta for agent workflows | on |
| A | Irreversible actions: force push, publish, `rm -rf`, infrastructure, outbound MCP | **off** |

**Family A is off by default and that is a real trade-off, not a hedge.**
Turning it on for someone actively writing code produces several questions a
day, which directly contradicts the design budget of fewer than one question per
week. Turn it on if you run an agent unattended:

```jsonc
// ~/.agentkeeper/config.json
{ "version": 1, "rules": { "categoryA": { "enabled": true } } }
```

Configuration **cannot** grant tier 2 access and **cannot** disable a blocking
rule. Those are enforced in code, not by convention.

---

## Development

```sh
npm install
npm test              # unit + integration
npm run bench         # the performance budgets, measured in a clean process
npm run test:sandbox  # real isolation, real refusals — the tests that matter
npm run test:e2e      # install → use → uninstall against the built package
npm run verify        # everything, plus architecture boundaries and coverage
```

Strict TDD: every detection rule starts with a fixture and a failing test.
Hostile fixtures are built by a script into a temporary directory, never
committed — a repository carrying a live `folderOpen` task would execute it on
whoever opened the project.

Architecture is layered (`domain` → `application` → `infrastructure` /
`presentation`) with dependencies pointing inwards only, checked by
`dependency-cruiser` in CI. `domain` performs no I/O, which is why every rule is
tested with a string in and an array out.

Coverage floors: `domain` 100%, `application` 95%, overall 85%. The
false-positive corpus has a golden finding count; any increase is a red build.

Performance is measured, not asserted. `npm run bench` reports each figure
against the budget it belongs to, in a clean process — measuring inside the test
runner inflated everything about fourfold, and `p95(A) - p95(B)` across separate
batches turned out to be noise rather than a difference.

### Releasing (maintainers)

Releases are published by CI through
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC +
provenance). There is no npm token anywhere; a release is a tag push.

One-time setup:

1. Create the `agentkeeper` package on npmjs.com (publish a placeholder or
   reserve the name via your account).
2. In the package settings add a trusted publisher: this repository, workflow
   `.github/workflows/publish.yml`, environment left empty.

Cutting a release:

```sh
npm version 1.0.x          # bumps package.json + lockfile, commits, tags v1.0.x
git push --follow-tags     # the tag triggers publish.yml
```

The pipeline verifies on macOS, Linux and Windows, cross-compiles the Windows
AppContainer helpers, assembles the tarball, refuses it if anything is missing,
and only then runs `npm publish --provenance --access public`.

A local `npm publish` is deliberately awkward: `prepack` requires the Windows
helper binaries, which exist only as CI artifacts. Publishing is a pipeline
decision, not a laptop decision.

---

## Licence

MIT. See [SECURITY.md](SECURITY.md) for the disclosure policy.
