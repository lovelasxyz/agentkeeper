# agent-guard

Confine an AI coding agent to what it needs, using the sandboxing your operating
system already has. No Docker, no containers, no cloud service, no telemetry —
and no change to how you work: you keep typing `claude`, `gemini`, `codex`.

```sh
npm i -g agent-guard
agent-guard init
```

---

## The idea

> Rules have to guess what is bad. A sandbox simply does not offer the option.

A prompt injection controls the agent's *intent*, not what the agent can
physically reach. A poisoned `CLAUDE.md` can tell the agent to read
`~/.ssh/id_rsa` — the agent will try, and the file will not exist in its world.
The attack fired, nothing happened, nobody was interrupted.

So isolation comes first here, and detection is the backup for the places
isolation cannot reach.

**agent-guard limits what the agent can do, and records what it does. It is
weaker than full container isolation and stronger than any set of rules.**

---

## What it actually does

Two layers, which do not duplicate each other.

**Layer 1 — the sandbox.** The agent starts inside an OS isolation profile:
`sandbox-exec` (Seatbelt) on macOS, `bubblewrap` on Linux. This decides what
exists at all.

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
| V5 (side-channel exfiltration) | 1 | Partly (network profile) | **No** |
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
recognisable in the traffic. The position taken here is: **restrict the network
with a profile, do not promise to detect what leaves.**

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

The only way to grant tier 2 access is to open `~/.agent-guard/allowlist.json`
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
makes `~/.agent-guard` writable, and rule AG-B005 refuses tool calls that reach
for it.

---

## Honest limits

| Limit | What follows |
|---|---|
| The profile is fixed when the process starts | A new grant applies to the **next** run. The tool says so instead of pretending otherwise. |
| Network filtering is per **port**, not per host | Measured, not assumed: Seatbelt rejects a hostname in a network rule outright (`host must be * or localhost`). A per-domain allowlist needs a proxy and is out of scope for 1.0. |
| On Linux, network is on or off | `bubblewrap` has no per-port control. `agent-guard status` says so. |
| `sandbox-exec` is deprecated by Apple | Still the only built-in mechanism, still working in current macOS. The risk is stated here rather than hidden. |
| `bwrap` is not installed everywhere | Without it, layer 1 is unavailable and `run` refuses to start rather than run unprotected. |
| Weaker than a container | Shared kernel, shared network stack. |
| The agent can still wreck the workspace | Isolation protects the system, not your working tree — that is what git is for. |
| Windows | Layer 2 only in 1.0. |

**When no mechanism is available, `agent-guard run` refuses to start the
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

### agent-guard and zizmor

| | zizmor | agent-guard |
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
agent-guard init                  # set up, showing a diff of every change
agent-guard run -- claude         # run inside the isolation profile
agent-guard status                # what is active, and what is not enforced
agent-guard scan [path]           # inspect a repository (also runs as a git hook)
agent-guard grants                # what is open; --add, --revoke
agent-guard log --since 7d        # what was recorded
agent-guard pause 1h              # silence notifications (isolation stays on)
agent-guard uninstall             # remove everything, restore the originals
```

After `init` you keep typing `claude` — a shell function routes it through the
wrapper. `AGENT_GUARD_BYPASS=1 claude` skips it for one command, from *your*
shell; the same variable coming from inside the agent is refused (AG-B006).

### Starter profiles

`init` offers a pre-filled allowlist so the first week is a handful of questions
rather than a hundred: `web`, `python`, `infra`, `minimal`. They are data files
under [`profiles/`](profiles/) — pull requests welcome.

---

## Installing agent-guard does not run any code

There is **no `postinstall` script** in this package. A dependency that writes
itself into your configuration at install time is indistinguishable from
malware, and that is precisely the ChainDrop signature this tool watches for.
Nothing happens until you run `agent-guard init`, and `init` shows you a diff of
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
// ~/.agent-guard/config.json
{ "version": 1, "rules": { "categoryA": { "enabled": true } } }
```

Configuration **cannot** grant tier 2 access and **cannot** disable a blocking
rule. Those are enforced in code, not by convention.

---

## Development

```sh
npm install
npm test              # unit + integration
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

---

## Licence

MIT. See [SECURITY.md](SECURITY.md) for the disclosure policy.
