# Policy

How the boundary for one launch is assembled, and what you can change.

Run `agentkeeper policy` to see the effective result for the current
directory, including its identity hash.

## Hierarchy

```
hard invariants          ← cannot be weakened by anything below
  ↓ built-in baseline    ← the sensitive path registry
  ↓ user policy          ← ~/.agentkeeper/config.json
  ↓ workspace policy
  ↓ session grants       ← ~/.agentkeeper/allowlist.json
```

A lower layer may narrow the boundary. It can never widen a hard invariant —
that is enforced in code, not by convention, and re-checked by the platform
backend before it acts.

## What goes into one policy

| Input | Source |
|---|---|
| Workspace | The directory the agent was started in |
| Toolchain roots | Detected language runtimes and package caches |
| Starter profile | `profiles/*.json`, chosen once at activation |
| Sensitive path registry | Built in; produces the tier 2 deny rules |
| Grants | `~/.agentkeeper/allowlist.json` |
| Destinations | The profile's `network` list |

## Starter profiles

`web`, `python`, `infra`, `minimal` — data files under [`profiles/`](../profiles/),
so the first week is a handful of questions rather than a hundred. They differ
only in tier 0/1 conveniences and the destination allowlist; none of them can
grant tier 2.

```jsonc
// ~/.agentkeeper/config.json
{
  "version": 1,
  "sandbox": { "enabled": true, "starterProfile": "web", "onUnavailable": "fail" },
  "rules": { "categoryA": { "enabled": false } }
}
```

Unknown keys never weaken enforcement: a malformed or unrecognised
configuration falls back to the safe default rather than to permissiveness.

## Grants

```sh
agentkeeper allow ~/projects/shared --read --workspace
agentkeeper allow /srv/data --write
agentkeeper revoke <id>
agentkeeper grants                     # list
```

- **Tier 1 only.** A grant that reaches tier 2 is rejected at build time and
  the reason is printed.
- **`--workspace`** limits the grant to the current workspace; the default is
  global.
- **A grant applies to the next run.** The profile is fixed when the process
  starts, and the CLI says so rather than pretending otherwise.

Tier 2 is granted only by editing `~/.agentkeeper/allowlist.json` yourself,
outside any agent session:

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

## Policy identity

Every policy carries a `policyHash` — a SHA-256 over its workspace, readable
and writable roots, deny rules, overrides, destinations and runtime grants.

- It **changes** whenever the boundary changes.
- It is **stable** across the order rules were assembled in.
- It is **unaffected** by the launch-time broker port, so two identical
  sessions do not look like two different policies.

Audit entries and session records name a policy by this hash.

## Evaluation order

`allow → deny → override`, mirroring exactly how the generated profiles behave
at runtime. Overrides exist only for hand-written grants; a runtime grant can
never produce one.

## Content-addressed workspace decisions

Approvals for workspace artifacts are keyed by the SHA-256 of the file's
*content*, not its path. An approved `.claude/settings.json` that changes under
a `git pull` is simply a different artifact and is asked about again. That is
what closes the rug-pull vector.

## Rule configuration

The rule catalogue is in [rules.md](rules.md). Configuration can turn family A
on, and can narrow other families — it **cannot** disable a blocking rule and
**cannot** grant tier 2.

## Related

- [Security boundary](security-boundary.md) — the tier model
- [Network model](network-model.md) — destination policy
