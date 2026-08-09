# Agent compatibility

`claude` stays `claude`. The zero-workflow-change invariant is the whole point
of the launch layer.

## Supported agents

| Agent | Command | Interception |
|---|---|---|
| Claude Code | `claude` | Managed shim |
| OpenAI Codex CLI | `codex` | Managed shim |
| Gemini CLI | `gemini` | Managed shim |
| OpenCode | `opencode` | Managed shim |

`agentkeeper integrations` shows the effective state of each one — installed
and intercepted, installed but unprotected, needing repair, or not present on
this machine.

A GUI agent, or any agent without a stable command-line launch path, is **not**
protected and is never counted as protected.

## How interception works

`agentkeeper activate` writes one shim per agent into
`~/.agentkeeper/shims/<shell>/` and adds a single managed line to your shell
startup file that puts that directory on `PATH`. The shim:

1. refuses to recurse into itself;
2. resolves the real agent binary **with the shim directory excluded** from
   `PATH`, so an agent update does not break it;
3. keeps your working directory;
4. re-executes the agent through the policy engine.

The real agent binary is never patched, moved or wrapped on disk. Removing
agentkeeper removes the shims and the one marked line, and restores any file it
replaced byte for byte.

Installation does not require every agent to be present, and deactivation works
even if an agent was uninstalled in the meantime.

## What inherits the boundary

Everything the agent starts, because inheritance is a property of the OS
mechanism rather than of a tool-call hook:

- the agent's own shell commands
- MCP servers, including ones added mid-session
- `npm`/`pip`/`cargo` lifecycle scripts
- any subprocess, and any second agent launched from inside the first

This is the part a rules-only tool cannot answer: a subprocess of an approved
command never passes through a `PreToolUse` hook at all.

## Terminal behaviour

| Property | Guarantee |
|---|---|
| TTY | Preserved — interactive prompts, colours and progress rendering work |
| Signals | macOS and Linux forward `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT` to the agent. On Windows the Job Object terminates the whole process tree when the launcher exits. |
| Exit code | Passed through unchanged |
| stdout/stderr | Not buffered or rewritten by agentkeeper |

## An agent's own sandbox

If Claude or Gemini enables its internal sandbox, that is defence in depth and
changes nothing here. Where the two disagree, the stricter one wins: if the
internal sandbox allows a capability and agentkeeper denies it, the result is
`DENY`. The external policy belongs to you rather than to an AI vendor.

## Advanced launch

```sh
agentkeeper run -- <command>
```

Runs any command inside the profile. It is a debugging and scripting entry
point, not the normal workflow — after `activate` you simply keep typing
`claude`.

## Bypassing, deliberately

The managed shim has **no environment escape hatch**. That is a deliberate
reversal of an earlier design: an interception that any variable can switch off
is not interception, and an injected instruction can set a variable.

To run an agent outside the boundary, do it explicitly:

- invoke the real binary by its own path — the shim is only a `PATH` entry and
  the agent binary is never patched or moved; or
- run `agentkeeper deactivate` to remove the interception entirely.

Rule AG-B006 still refuses tool calls that try to set `AGENTKEEPER_BYPASS`, so
an agent cannot even attempt the older escape from inside a session. Any
session that ran outside the boundary is reported as `BYPASSED`, never as
protection.
