# Security boundary

What is guaranteed, what is merely configured, and how to tell the difference.

## The four statuses

`agentkeeper doctor` and `agentkeeper status` report one of these. They are
produced by a domain object that **refuses to construct a false `PROTECTED`**,
so no adapter or CLI can upgrade a status it did not earn.

| Status | Meaning |
|---|---|
| `PROTECTED` | Every mandatory component is active *and was just verified by a canary*. No degradation reason remains. |
| `DEGRADED` | The boundary is up, but part of the protection is unavailable — and the missing part is named. |
| `UNPROTECTED` | No primary sandbox is applied. Protected launches fail closed. |
| `BYPASSED` | You explicitly disabled enforcement. Never reported as protection. |

`PROTECTED` requires all of: a mechanism other than `none`, a **passed** deny
canary, complete filesystem enforcement, complete process-tree enforcement,
network either `denied` or `brokered`, and an empty reason list.

## Verified, not assumed

Two things are re-derived every time status is asked for:

- **Deny canary.** A real process is started through the real runner. It must
  read the workspace and must fail to read a file outside it — and a *child*
  of that process must fail too, which is what proves inheritance.
- **Network canary.** A destination broker is started, an approved tunnel is
  driven end to end against a local sink, and an unapproved authority plus the
  cloud metadata address are confirmed to be refused. Only then is egress
  reported as `brokered`.

A broker that allows everything and a broker that allows nothing are both
failures, and the canary distinguishes them. Neither the presence of
`sandbox-exec` nor the existence of broker code in the package is ever
sufficient evidence.

## The two tiers

| Tier | Meaning | Examples |
|---|---|---|
| 0 | Baseline | Workspace, temp, language runtimes and system libraries |
| 1 | Grantable | A shared project directory, a package cache, an SDK, a documentation domain |
| 2 | Protected, **non-promptable** | SSH, cloud and registry credentials, browsers, keychains, shell history, every persistence surface, agentkeeper's own state |

**Tier 2 has no allow button anywhere.** Not a confirmation, not an "are you
sure" — the affordance is absent. If a permission can be requested at the
moment of the attack, an injection simply waits for a distracted moment and
asks for it.

The only way to grant a tier 2 path is to open `~/.agentkeeper/allowlist.json`
in an editor yourself, outside any agent session. An injection can phrase any
request; it cannot open your editor at a different moment in time.

This is structural, not a convention:

- The sandbox never makes `~/.agentkeeper` writable.
- `PolicyBuilder` rejects runtime grants that reach tier 2, before any backend
  sees them.
- Rule AG-B005 refuses tool calls that reach for agentkeeper's own state.
- A property test asserts, over generated grant sets, that no tier 1 grant
  opens a tier 2 resource.

## Self-protection

Inside the boundary the agent tree cannot:

- write `~/.agentkeeper/**` — shims, policy, grants, audit
- change where git looks for hooks (AG-B004)
- turn the wrapper off from a subprocess (AG-B006)
- widen its own capabilities by invoking the platform helper directly, because
  the helper re-validates the request

The managed shim honours no environment variable that would switch it off, and
rule AG-B006 refuses a tool call that tries to set `AGENTKEEPER_BYPASS` — the
older escape hatch — from inside a session. Running unconfined is done
explicitly, by invoking the real binary by path or by deactivating.

## Fail closed

If the primary sandbox cannot be created, or the policy contains something the
backend cannot express, the protected launch does not happen. A quiet
unprotected launch is worse than no tool at all, because you would believe you
were covered.

The same applies to partial expressiveness. Each backend reports what it
cannot enforce through `unenforceable()`, and a non-empty answer refuses the
run rather than shrinking the policy to fit.

## What the audit log holds

Metadata only: timestamp, session, agent, event, resource *class*, path
*class*, and the policy that decided. Never file contents, prompt contents, API
keys or environment values. A log of what was protected must not become the one
place all of it is written down in the clear.

## What this is not

- Not a VM. Shared kernel, shared network stack.
- Not a guarantee your working tree survives the agent.
- Not covert-channel detection ([T9](threat-model.md)).
- Not protection for a GUI agent that has no supported launch path.

## Related

- [Threat model](threat-model.md)
- [Network model](network-model.md)
- [Platform support](platform-support.md) — which guarantees hold where
