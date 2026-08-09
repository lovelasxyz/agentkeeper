# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository
("Security" → "Report a vulnerability"). Please do not open a public issue for
anything that would let somebody reach a user's credentials.

Expect an acknowledgement within 72 hours and an assessment within seven days.
Coordinated disclosure with a 90-day default window; shorter if a fix ships
sooner, longer only by mutual agreement.

## What counts as a vulnerability here

Anything that breaks one of these properties:

1. **Tier 2 is unreachable at runtime.** Any path that lets a prompt, a tool
   call or a configuration file obtain read or write access to a tier 2
   resource without a human editing `~/.agentkeeper/allowlist.json`.
2. **The sandbox holds.** Any way for a command started by `agentkeeper run` to
   read or write outside its policy.
3. **Self-protection.** Any way for the agent to modify `~/.agentkeeper`, its
   own hook registration, or `core.hooksPath`.
4. **Fail-closed on isolation.** Any path where `agentkeeper run` starts a
   command unconfined without the user having explicitly configured
   `sandbox.onUnavailable: "warn"`.
5. **The audit log stays clean.** Any case where file contents reach
   `audit.log`.
6. **Uninstall is exact.** Any state `init` creates that `uninstall` leaves
   behind.

## What does not count

- Bypasses that require an already-compromised kernel, Node.js runtime, or root.
- The documented limits in the README: per-host network filtering, exfiltration
  detection, workspace damage, Windows layer 1. These are stated openly rather
  than claimed and quietly missing.
- A rule failing to detect a novel attack pattern. Layer 2 is insurance, not a
  guarantee — though a report is still welcome as a feature request with a
  fixture.

## Supply chain

- No `postinstall` script, ever.
- Published from CI with npm trusted publishing (OIDC) and provenance; no
  long-lived tokens, no local `npm publish` after the first release.
- Zero runtime dependencies.
- Dependencies pinned by lockfile, updated through reviewed pull requests.
