# Threat coverage

Which vector each rule and mechanism answers, and where the gaps are. Every CVE
that motivated a rule has a fixture and a test; the table is the map between
them (spec §9.7).

## Vectors → mechanism

| Vector | What it is | Layer 1 | Layer 2 | Fixture |
|---|---|---|---|---|
| V1 | Autorun on opening a workspace (`folderOpen`, devcontainer, `.envrc`, git hooks) | — | AG-H003, AG-H004, AG-H005, AG-H006 | `vscode-folderopen-task`, `devcontainer-lifecycle`, `cloned-git-hook` |
| V2 | Autorun on agent start (`SessionStart`, `PreToolUse`) | write to `~/.claude/settings*.json` denied | AG-H001, AG-H002, AG-B003 | `chaindrop-session-hook` |
| V3 | Injection through instruction files | — | AG-I001, AG-I002, AG-I003 | `instruction-injection-base64`, `instruction-hidden-unicode` |
| V4 | Environment configuration (CVE-2026-12537, CVE-2026-21852) | endpoint variables are not readable from a repo-scoped env the sandbox does not open | AG-E001, AG-E004 | `gemini-env-cve-2026-12537`, `baseurl-override` |
| V5 | Side-channel exfiltration (CVE-2026-54316) | network profile (ports) | — | — |
| V6 | Untrusted input in CI | — | AG-C003, AG-C004, AG-C005 | `codex-double-pass-workflow`, `untrusted-trigger-workflow` |
| V7 | Rug-pull: approved config changes later | — | TOFU by content hash, AG-I003, AG-E003 | covered by `ScanWorkspace` integration tests |
| V8 | MCP server swap | server command runs inside the same profile | AG-E002, AG-E005 | `mcp-server-swap`, `mcp-auto-approve` |
| V9 | Persistence outside the repository | **writes denied** | AG-P001…AG-P006, AG-B004 | persistence rule tests |
| V10 | Credential harvesting | **reads denied** | AG-B001, AG-B002 | sandbox isolation tests |
| V11 | Irreversible actions | infrastructure credentials unreachable | AG-A001…AG-A007 (off by default) | action rule tests |
| V12 | Escaping observation (subprocesses, MCP processes, other agents) | **inherited profile** | — | sandbox isolation tests |

## CVE → rule → fixture → test

| CVE | Rule | Fixture | Test |
|---|---|---|---|
| CVE-2026-12537 (Gemini CLI, CVSS 10.0) | AG-E001, AG-C001 | `gemini-env-cve-2026-12537`, `vulnerable-cli-version-workflow` | `artifact-rules.test.ts`, `scan-fixtures.test.ts` |
| CVE-2026-21852 (`ANTHROPIC_BASE_URL` override) | AG-E004 | `baseurl-override` | `artifact-rules.test.ts`, `lifecycle.test.ts` |
| CVE-2026-54316 (download-counter exfiltration) | AG-C001 (version floor only) | `vulnerable-cli-version-workflow` | `artifact-rules.test.ts` |
| ChainDrop (npm → `SessionStart` hook) | AG-H002 | `chaindrop-session-hook` | `artifact-rules.test.ts`, `lifecycle.test.ts` |
| Codex double-pass over one checkout | AG-C004 | `codex-double-pass-workflow` | `artifact-rules.test.ts` |

## Where the gaps are

- **V5 detection.** Not attempted. A one-bit channel is enough to leak a key,
  and there is nothing recognisable in the traffic. The mitigation is the
  network profile, and the README says so rather than implying coverage.
- **V12 detection.** A subprocess is confined but not individually reported;
  there is no per-process attribution in zone B (`fs.watch` gives no PID).
- **Per-host network policy.** Not expressible in either mechanism without a
  proxy. Ports only on macOS, on/off on Linux.
- **Windows.** Layer 2 only in 1.0.

Adding a new CVE means: a fixture in `test/fixtures/build.ts`, a failing test,
then the rule — in that order.
