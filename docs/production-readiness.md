# Production readiness

An honest account of what is finished, what is not, and what would have to be
true before the word "finished" is fair. Written against the unreleased tree
after the 1.0.4 hardening cycle.

## The verdict

| Platform | State | What that means |
|---|---|---|
| macOS | **Production-ready, with named gaps** | The boundary holds against the adversarial suite run against the published package. Tier 2 is denied and proven denied. Gaps are reported on every run and carry stable reason codes. |
| Linux | **Credible, under-verified** | The design is stronger than macOS — empty home, explicit mounts, no route to the host. But it has only ever been exercised in CI, never driven by hand on a real desktop under a real agent. |
| Windows | **Unprotected, honestly** | No sandbox backend ships. The AppContainer child never exited and its canary never passed; without a Windows machine with a debugger the cause could not be found, and a boundary nobody has observed holding is not shipped. The package gate refuses any native helper. The detection layer — hook rules, the git chain, the watcher — works there. |

What changed since 1.0.4, in one paragraph: an upgrade now reaches the watcher
on its own (`activate`/`repair` restart a stale daemon, and the daemon reads
the installed manifest once a minute and hands itself to the service manager);
the service controller is three platform strategies with contract tests; the
lifecycle e2e runs hermetically through a module-hook service fake, on a clean
runner and on a maintainer's machine alike; performance budgets are enforced in
CI rather than measured advisedly; registry invariants are enforced by the
constructors rather than by after-the-fact tests; and the pattern of "the code
asserts what it should observe" found in this document is closed where code
could close it.

### Where the gaps land on the threat model

| Threat | macOS | Linux | Windows |
|---|---|---|---|
| T3 MCP servers, T4 supply chain (inheritance) | enforced | enforced | detection layer only |
| T5 credential theft | enforced, incl. the machine keychain | enforced | detection layer only |
| T6 persistence | enforced + resident watcher | enforced + watcher | detection + watcher |
| T8 network exfiltration | brokered | brokered | no boundary to broker through |
| T9 covert channels | not detected, by design | not detected | not detected |

On Windows the honest word for layer 1 is absent, and `doctor` says so with
`platform.windows-runner-unavailable`. The day a backend returns, it returns
gated by the same canary the other two platforms pass.

### What is already closed, and should not be reopened

- Supply chain of the package itself: OIDC trusted publishing with SLSA
  provenance, an SBOM, one package contract read by both gates, a tarball
  verifier that reads the archive, and a package gate that *refuses* a native
  helper rather than requiring one.
- A private disclosure path with stated timelines (`SECURITY.md`).
- A threat model that names T9 and T10 as uncovered (`docs/threat-model.md`).
- Uninstall that restores the shell file byte for byte, proven by e2e.
- Status that cannot lie: `ProtectionStatus` refuses to construct a false
  `PROTECTED`, every gap carries a stable reason code, and the watcher reports
  the version it is actually running.
- An upgrade is sufficient on its own: the running watcher becomes the
  installed watcher without the user reading anything — by restart on
  `activate`/`repair`, or by the daemon observing the install itself.
- The performance budgets of spec §12 are enforced: `bench.mjs --enforce`
  gates CI and the release pipeline on both full-support platforms.
- The lifecycle e2e is hermetic: identity home and the service manager arrive
  through module resolution hooks that only `NODE_OPTIONS` can install, so a
  compromised agent cannot fake them, and the suite proves the seam by reading
  the fake's recorded state.

---

## What remains open, and why

| # | Item | State | Honest weight |
|---|---|---|---|
| 1 | AppContainer child never exits | **Blocked on hardware** | Windows keeps reporting `UNPROTECTED` until a backend passes its own canary on real Windows 10/11, x64 and arm64, with a debugger attached. No further guess ships. |
| 2 | Linux never driven by hand | **Open** | Everything known about the Linux backend comes from CI. Before claiming production readiness there it needs the adversarial session macOS got, on a real desktop, with a real agent. |
| 3 | `/private/var/at/tabs` unwatched without Full Disk Access | **Named, and shown** | A platform limit, not a defect: the directory is root-only. Reported as `daemon.watch.degraded` by the daemon and *quoted by `doctor`* from the watcher's self-report, so the gap is visible without reading the audit log. |
| 4 | Narrowing `seatbelt.broad-system-read` | **Deliberate, shrunk** | The machine keychain, SSH host keys, `/var/root` and the local account database are explicit tier 2 denies — the two system stores probed live in the isolation suite, directly and through the firmlink. What remains readable is system-owned and world-readable; the enumerated allowlist is a dead end (it crashes the runtime before `main()`). |

Everything from the 1.0.4 list that code could close, code closed: the stale
watcher restarts itself into the installed version, the lifecycle e2e is
hermetic, the performance budgets gate CI, each platform runs its own service
strategy with a contract test, the hot question is asked once per decision,
registry invariants are construction-time, the notification policy is a domain
value, and a degraded watcher is quoted by `doctor` rather than buried in the
log. What is left is hardware (Windows), a platform permission (crontab,
shown), and a manual session on a real Linux desktop.

The pattern from 1.0.4's breakages — *asserting a fact about the outside world
instead of observing it* — now has its mechanical rule applied at the seams
that produced it: launchd release is awaited, the running watcher is compared
against the installed package, the tarball is read rather than `npm pack`'s
JSON, line endings are not assumed, the watcher's handle budget is spent only
where patterns actually descend, and the service manager is observed through
a contract-tested strategy per platform.

> At every boundary with the OS or another tool: **observe, bound, verify,
> report.** Never assume a state transition completed, never parse another
> tool's output without a contract test, never enumerate an unbounded thing,
> never let one consumer drain a shared budget.

## Code health, measured rather than asserted

- No `eslint-disable`, no `@ts-ignore`, no `@ts-expect-error` in `src/`.
- No `TODO`, `FIXME` or `HACK` in the source.
- No swallowed errors, no stray `any`; the grep hits for both live in the
  canary's source string and in comments.
- The only synchronous I/O outside the canary is `existsSync` in the profile
  loader and one `/proc/<pid>/stat` read in the Linux signal handler.
- Audit retention works as designed: 32 segments and a byte ceiling, pruned.
- Registry invariants are construction-time: a credential row with tier 1
  cannot be written, so the forbidden shape is unrepresentable, not merely
  tested against.
- One question about one path is answered once: tier, disposition and
  explanation derive from a single registry walk, proven by a counting test.

## Definition of done

The project may be called finished when all of the following are true, and the
first two are the ones that matter:

1. **macOS and Linux gate the release with passing deny canaries, in a process
   and its child — and Windows either joins them or ships no backend.** ✔ Held:
   macOS/Linux gate; Windows ships nothing and reports `UNPROTECTED`.
2. **An upgrade is sufficient on its own.** ✔ Held: restart on `activate` and
   `repair`, plus the daemon's own observation of the installed manifest.
3. **Every OS boundary observes rather than assumes.** Launchd release is
   awaited; service transitions are optimistic-concurrency checked; the watcher
   is observed through its self-report; the e2e proves the service seam by
   reading the fake's state. ✔ Held at the boundaries known today.
4. **The e2e suite runs identically on a clean CI runner and on a developer
   machine with the product installed.** ✔ Held: the service manager is faked
   through a module hook, and the precondition check is gone.
5. **Each platform's service integration is its own strategy with its own
   contract test.** ✔ Held: launchd, systemd, Task Scheduler.
6. **Every gap the product cannot close is named in output with a stable
   reason code, and no green status is produced without a live proof.** ✔ Held:
   `doctor` quotes the watcher's degraded coverage from its self-report, so no
   known gap lives only in the audit log anymore.

Points 3 and 6 are the ones to keep proving. The first is what keeps it from
breaking; the second is what makes it trustworthy when it does.

## Repository readiness, and the part that is not code

Done locally: `CODE_OF_CONDUCT.md` exists; the open items above are the issue
list. Still outstanding on the GitHub side (needs a maintainer with `gh` or the
web UI, none of it is a code change):

- Description and topics (`sandbox`, `ai-agent`, `prompt-injection`,
  `seatbelt`, `bubblewrap`): a security tool nobody can find is a tool nobody
  adopts.
- Releases published from the existing tags, with notes — the tags carry
  provenance; the notes are what people read.
- Branch protection on `main`.
- The open items 1 and 2 above filed as issues, so they stop being silent.

## When to re-read this

A readiness document rots faster than the code it describes. Re-read it when a
platform backend changes or returns, when a release fails, when a defect is
found outside the test suite, and otherwise at every minor version. If nothing
in it has changed in two releases, either the work stopped or the document did.
