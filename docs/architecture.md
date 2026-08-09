# Architecture

How the pieces fit, and why the boundaries sit where they do.

## The shape

```
claude / codex / gemini / opencode
            │
            ▼
   transparent shim  (~/.agentkeeper/shims/<shell>/<agent>)
            │
            ▼
      policy engine  (domain: tiers, registry, grants, profile)
            │
   ┌────────┼─────────────────┐
   ▼        ▼                 ▼
OS sandbox  destination broker  workspace guard
   │        │                 │
   └────────┴─────────────────┘
            ▼
        the agent, its shell, its MCP servers,
        its package scripts, its subprocesses
```

The sandbox is the product. The workspace guard is a second layer for
dangerous artifacts *inside* the directory the agent is allowed to write, and
it never justifies loosening the first layer.

## Layers

Dependencies point inwards only. `dependency-cruiser` fails the build on any
edge that goes the other way (`npm run lint:arch`).

| Layer | Holds | May import |
|---|---|---|
| `domain/` | Policy, tiers, sensitive-path registry, rules, value objects | `domain/` only, plus `node:crypto`, `node:path`, `node:assert` |
| `application/` | Use cases and the ports they need | `domain/`, `application/` |
| `infrastructure/` | Adapters: Seatbelt, bubblewrap, AppContainer, stores, broker, installer | `domain/`, `application/` |
| `presentation/` | CLI commands, rendering, daemon entry point | everything except other presentation internals |
| `composition/` | `Container` — the only place adapters are chosen | everything |

`domain/` performs no I/O. That is why every rule is tested with a string in
and an array out, and why the whole policy can be exercised without spawning a
process. `node:crypto` and `node:path` are allowed by name because they are
pure functions; putting them behind a port would produce an interface with one
implementation that never varies.

## The path a protected launch takes

1. **Shim.** `~/.agentkeeper/shims/<shell>/claude` runs, resolves the real
   `claude` while excluding the shim directory from `PATH`, and re-executes
   through the CLI. The agent binary is never patched.
2. **Policy build.** `PolicyBuilder` merges the starter profile, the sensitive
   path registry, stored grants and the workspace identity into one
   `SandboxPolicy`. Grants that reach for tier 2 are rejected here, not later.
3. **Hard-invariant check.** A tier 1 grant cannot open a tier 2 resource; a
   `..` cannot leave the workspace; an unknown configuration key cannot weaken
   anything. Violations are refusals, never warnings.
4. **Broker.** If the policy allows destinations, the launcher starts a local
   destination broker and attaches its transport to the policy. Without a
   broker the run fails closed.
5. **Environment.** `EnvironmentSanitizer` removes inherited secrets and
   ambient authority, then the launcher sets the few variables it owns —
   `HOME`, `TMPDIR`, proxy variables, `AGENTKEEPER_ACTIVE`.
6. **Backend compile.** The platform runner turns the policy into a Seatbelt
   profile, bubblewrap arguments, or an AppContainer request. Anything the
   backend cannot express is reported by `unenforceable()` and refuses the run.
7. **Execute.** The agent starts inside the boundary. Its shell, MCP servers,
   `npm` lifecycle scripts and subprocesses inherit it, because inheritance is
   a property of the OS mechanism rather than of a hook.

## Ports and adapters

Every OS-facing capability is a port in `application/ports/`:

| Port | Adapter |
|---|---|
| `SandboxRunner` | `SeatbeltRunner`, `BubblewrapRunner`, `WindowsSandboxRunner` |
| `SandboxProbe` | `NodeSandboxProbe` — runs the deny canary for real |
| `NetworkBroker` | `NodeDestinationBroker` |
| `NetworkProbe` | `NodeNetworkProbe` — proves the broker allows and refuses |
| `InstallationLifecycle`, `SystemIntegration` | `ManagedInstallation`, `ProtectionInstallation`, `SystemIntegrationAdapters` |
| `FileSystem`, `Clock`, `Logger`, `AuditLog` | `infrastructure/adapters.ts`, `infrastructure/store/` |

The two probe ports are what keep [status honest](security-boundary.md): they
answer *is this enforced right now*, so no code path can turn an installed
binary into a reassuring message.

## Double validation

The TypeScript control plane validates hard invariants, and the platform
backend validates them again before it acts. On Windows the native helper
re-parses the request and refuses anything that does not match the AppContainer
model it is willing to build. A bug in the control plane must not be able to
widen tier 2.

## The CLI

`CommandRouter` is a lookup table, not a switch, and every verb is imported
lazily. That is a measured decision: importing all verbs eagerly pulled the
installer, daemon and every rule family into a process whose entire budget is
50 ms. Argument parsing stays hand-rolled — a dozen verbs and a handful of
flags do not justify a third of the package's dependency budget, and the
package ships with zero runtime dependencies.

## Related

- [Security boundary](security-boundary.md) — what each status means
- [Network model](network-model.md) — how egress is decided
- [Policy](policy.md) — how a policy is assembled
- [Platform support](platform-support.md) — what each backend enforces
