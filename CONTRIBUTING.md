# Contributing

## The rule that matters

**Every new detection rule starts with a fixture and a failing test.** In that
order. A rule written before its fixture tends to describe the code that was
easy to write rather than the attack it was meant to catch.

1. Add the hostile repository to `test/fixtures/build.ts`, with a harmless
   canary payload (`touch /tmp/agent-guard-canary-<ruleId>`).
2. Add it to the expectation table. Watch it fail.
3. Write the rule.
4. Add the legitimate counter-example to `FALSE_POSITIVE_CORPUS` and confirm the
   golden count did not move.

Step 4 is not optional. The design budget is fewer than one question per week
after the first, and a rule that fires on ordinary repositories spends that
budget for everyone.

## Fixtures are never committed as files

They are built into a temporary directory by a script. A repository carrying a
live `.vscode/tasks.json` with `runOn: folderOpen` would execute it on whoever
opened the project, and third-party scanners would — correctly — flag the
repository as malicious.

## Architecture

```
presentation/     cli, hooks, daemon
       ↓
application/      use cases, ports
       ↓
domain/           entities, value objects, rules, policy, paths
                  (zero I/O, zero external dependencies)

infrastructure/   implements the ports
```

Dependencies point inwards only, checked by `dependency-cruiser` in CI. A
violation is a red build.

`domain` performs no I/O. A `Rule` receives an `Artifact` — path, content, hash
— and returns findings. That is why every rule is tested with a string in and an
array out, with no filesystem and no mocks.

Two stdlib modules are allowed inside `domain`: `crypto` for SHA-256 and `path`
for string normalisation. Both are pure functions. Putting them behind a port
would create an interface with exactly one implementation that never varies.

## Things not to do

- No dependency-injection framework. Wiring is by hand in
  `composition/Container.ts`; the hook has a 50 ms cold-start budget and
  reflection-based containers eat a meaningful part of it.
- No interface for a class with one implementation that does not cross a layer
  boundary.
- No `any` in `domain` or `application`.
- No `postinstall`. Not now, not later.
- No network calls at runtime. Anywhere.

## Adding a sensitive path

Edit `src/domain/paths/registry.ts`. It is data, not code. Every entry needs a
`rationale` a stranger can evaluate, correct `platforms`, and separate
`readTier` / `writeTier` — the two genuinely differ (`~/.gitconfig` must be
readable for git to work at all, and must never be writable, because that is
where `core.hooksPath` lives).

The registry has its own test asserting that tier 2 always implies a blocking
disposition, that no pattern overlaps a normal workspace, and that every
platform variant is present.

## Before opening a pull request

```sh
npm run verify        # typecheck, boundaries, coverage thresholds, sandbox tests
npm run test:e2e      # install → use → uninstall
```

Coverage floors are enforced: `domain` 100%, `application` 95%, overall 85%.
