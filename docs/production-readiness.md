# Production readiness

An honest account of what is finished, what is not, and what would have to be
true before the word "finished" is fair. Written against 1.0.4.

## The verdict

| Platform | State | What that means |
|---|---|---|
| macOS | **Production-ready, with one named gap** | The boundary holds against a 34-vector adversarial suite run against the published package. Tier 2 is denied and proven denied. The one gap is reported on every run. |
| Linux | **Credible, under-verified** | The design is stronger than macOS — empty home, explicit mounts, no route to the host. But it has only ever been exercised in CI, never driven by hand on a real desktop under a real agent. |
| Windows | **Not ready** | The deny canary does not pass. It reports `windows.child-timed-out`, the suite is excluded from the release gate, and network egress is refused outright rather than brokered. |

So: better than a thesis, not yet finished. The parts that are done are done
properly — the boundary is enforced by the OS, the status object refuses to
report a protection it has not just proven, and the release pipeline will not
publish a tarball missing an artifact. What is missing is not polish. It is one
platform that does not work, one class of self-repair that is reported but not
performed, and a set of seams where the code asserts facts about the outside
world instead of observing them.

Current state: 872 tests across 49 files, 89.8% statements / 88.41% branches,
127 modules with no layering violation, 9 ports.

---

## The pattern behind the breakages

Nine separate failures during development had one shape. Naming it is worth
more than fixing them one at a time.

**The code asserted a fact about the outside world instead of observing it.**

- `launchctl bootout` was assumed synchronous. It is not — an `activate` right
  after a `deactivate` hit `service-id-collision`, with the machine unprotected
  in between.
- The entrypoint on disk was assumed to be the code that is running. After an
  upgrade it is not, so a shipped security fix sat inert behind a green report.
- The developer's machine was assumed clean. It was not, and five e2e tests
  failed for a reason none of them named.
- `npm pack --json` was assumed to keep its shape. npm 12 changed it, and the
  gate reported nine missing artifacts that were all present.
- Text files were assumed to use LF. A Windows checkout does not.
- `~/.claude` was assumed small. It holds thousands of directories, which
  exhausted the watcher's handle budget and silently unwatched every target
  registered after it.

Every one of those was cheap to fix and expensive to find, because the failure
surfaced far from its cause. The production-grade rule is narrow and
mechanical:

> At every boundary with the OS or another tool: **observe, bound, verify,
> report.** Never assume a state transition completed, never parse another
> tool's output without a contract test, never enumerate an unbounded thing,
> never let one consumer drain a shared budget.

Most of what follows is that rule applied to the places it is not yet applied.

---

## P0 — until these close, "finished" is not true

### 1. Windows AppContainer never releases the child

The confined process starts and does not exit; the canary reaches its deadline.
Detaching the child and giving it the null device on explicit handles was tried
and did not move the timing by a second, so the console theory is dead. No
further guess should be committed.

**Done looks like:** the deny canary passes in a process and its child on
Windows 10 and 11, x64 and arm64, and `test:sandbox` becomes a release gate
there instead of `continue-on-error: true`.

**What it needs:** a real Windows machine with a debugger. This cannot be
closed by reasoning about the source, and two attempts have now proven that.
Until then Windows must keep reporting `DEGRADED` and refusing to pretend.

### 2. A stale watcher is reported but not repaired

1.0.4 made the problem visible: `doctor` now says when the running daemon is
older than the installed one. It does not fix it. `activate` still answers
"already active" and leaves the old process running, so a user who upgrades
keeps the old boundary until they happen to read `doctor` or reboot.

**Done looks like:** `activate` compares the running version to the installed
one and restarts the service when they differ, and the npm lifecycle does the
same so an upgrade is sufficient on its own. Visibility was the honest first
half; it is not the whole fix.

### 3. Windows ships without a gate

`verify:package` cannot run locally — the native helpers only exist after a CI
build — and the Windows sandbox suite is advisory. The release therefore has
one platform whose binaries are shipped but whose behaviour is never asserted.

**Done looks like:** either the Windows suite gates the release, or the package
stops shipping a Windows backend and the platform reports `UNPROTECTED`
honestly. Shipping a backend that is known not to pass its own canary is the
one place the project currently violates its own principle.

---

## P1 — the coupling that will cause the frequent breakages

This is the section about fragility. The domain is clean and the layering is
machine-enforced; none of the following is a layering violation. They are
places where a change in one file will break something in another for reasons
that are not visible from either.

### 1. Platform branching inside the service controller

`PlatformServiceController` (`src/infrastructure/install/SystemIntegrationAdapters.ts`)
switches on platform inside four methods. launchd, systemd and Task Scheduler
have genuinely different semantics — bootout is asynchronous, `systemctl` is
not, `schtasks` is different again — and interleaving them in one class is
exactly where the release race hid for three versions.

**Done looks like:** one strategy per platform behind the existing
`ServiceController` port, each owning its own settle semantics, each with its
own contract test. The port already exists; only the implementation is fused.

### 2. `SystemIntegrationAdapters.ts` is a grab bag

407 lines holding the git configuration controller, the service controller and
the shared error type. Three reasons to change one file.

**Done looks like:** one file per adapter. Mechanical, low risk, and it makes
the strategy split above obvious rather than daring.

### 3. Presentation depends on an infrastructure type

`BaselineCollector` imports `WatchTarget` from `NodeWatchService`. The daemon's
*policy* about what to watch is now typed by a specific watcher implementation,
so replacing the watcher touches the collector.

**Done looks like:** `WatchTarget` moves to a port, and the watcher implements
it. It is one interface with two fields.

### 4. Process liveness has no port

`DoctorCommand` calls `process.kill(pid, 0)` inline. An OS capability living in
a presentation class cannot be faked, so the "is the watcher alive" branch is
only unit-tested through the pure helper, never through the command.

**Done looks like:** a `ProcessLiveness` port on the container, like every
other OS capability in the codebase.

### 5. Notification policy lives inside a use case

`MonitorPersistence` is 452 lines and carries `NotificationBudget`, the
suppression rules, the resolution mapping and the audit calls. The budget is a
policy object — rate, cooldown, fairness — and policy belongs in the domain
where it can be reasoned about without a file system.

**Done looks like:** the budget and suppression decision move to the domain as
a value object with its own tests; the use case orchestrates and no longer
decides.

### 6. The version constant exists twice

`CommandRouter` and `Container` both declare `__AGENTKEEPER_VERSION__` for a
defensible reason — the router must answer `--version` without building a
container — but two declarations of one build-time fact will drift.

**Done looks like:** one tiny module that both import, still tree-shaken off
the hook path.

### 7. The test suite is coupled to the host machine

The lifecycle e2e cannot run on a machine where agentkeeper is actually
installed, because a service manager is machine-wide and a throwaway home
cannot fake it. It now says so clearly instead of failing in five confusing
ways, but "clearly blocked" is not "hermetic".

**Done looks like:** the service manager reachable through a stub that the e2e
supplies. The seam must not be an environment variable a compromised agent
could set to fake a healthy watcher — that is why it was not done the easy way.

### 8. Registry invariants are enforced by tests, not by construction

Nothing stops a contributor writing a `credential` entry with `readTier: 1`
except a test that would fail afterwards. For the single most
security-sensitive data structure in the project, the type should make the
mistake unrepresentable.

**Done looks like:** category-specific constructors where tier and disposition
are implied rather than typed by hand.

---

## P2 — hardening, in order of value

- **Narrow `seatbelt.broad-system-read` further.** The credential stores outside
  home are closed. What remains readable is genuinely system-owned and mostly
  world-readable anyway, but each targeted deny shrinks the gap. The enumerated
  allowlist is a dead end: it crashes the runtime before `main()`.
- **Drive Linux by hand.** Everything known about the Linux backend comes from
  CI. Before claiming production readiness there, it needs the same adversarial
  session macOS got, on a real desktop, with a real agent.
- **Exercise `repair`.** The command exists and is referenced in remediation
  text; this project has never watched it fix a genuinely damaged install.
- **Audit retention.** 32 segments accumulated during development with no
  pruning observed. A security log that grows without bound eventually becomes
  the incident.
- **Workflow lint.** A malformed `workflow_dispatch::` silently produced a run
  with zero jobs. Any YAML that gates a release deserves schema validation in
  CI.
- **Single source for CI configuration.** The Node version was pinned in two
  workflows and drifted, which killed a release at step one while CI was green.

---

## What will never close, and why that is correct

A product that claims these are solved is lying, and saying so plainly is part
of the design.

- **Exfiltration through an allowed destination.** The broker is body-blind by
  deliberate choice. An agent that may reach `api.anthropic.com` may put
  anything in that request. Detecting it means terminating TLS and reading the
  user's traffic, which is a worse product than the problem it solves.
- **Kernel, root, or hypervisor compromise.** Every sandbox on this list runs
  above the kernel and inherits its integrity.
- **The workspace itself.** The agent is *meant* to write there. Version control
  is the boundary for that, not this.
- **A user who hand-edits the allowlist.** Tier 2 has no allow button anywhere
  precisely so that granting it is a deliberate act outside any agent session.
  Having taken that act, the user owns the result.

---

## Definition of done

The project may be called finished when all of the following are true:

1. The deny canary passes on macOS, Linux **and** Windows, in a process and its
   child, and all three suites gate the release.
2. An upgrade is sufficient on its own: the running watcher is the installed
   watcher, without the user reading anything.
3. Every OS boundary observes rather than assumes — no state transition is
   reported complete before it is verified complete.
4. The e2e suite runs identically on a clean CI runner and on a developer
   machine with the product installed.
5. Each platform's service integration is its own strategy with its own
   contract test.
6. Every gap the product cannot close is named in `doctor` output with a stable
   reason code, and no green status can be produced without a live proof.

Points 3 and 6 are the ones that matter. The first is what keeps it from
breaking; the second is what makes it trustworthy when it does.
