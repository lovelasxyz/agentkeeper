# Threat model

What agentkeeper treats as hostile, what it defends, and what it does not.

**The invariant:** compromise of the agent must not imply compromise of the
workstation.

## Untrusted by default

The agent, its prompt and context, its MCP servers, the workspace it is
pointed at, and every dependency it installs. None of these are assumed
benign, and none of the defences depend on recognising malicious intent.

## Threats in scope

| ID | Threat | Answer |
|---|---|---|
| T1 | **Prompt injection.** Text in the context tells the agent to read credentials or run something destructive. | Policy is independent of the prompt. The agent can be persuaded to try; the resource is not in its world. |
| T2 | **Repository instructions.** `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules` are attacker-controlled input. | Treated as untrusted data. Rules AG-I001…I003 flag fetch-and-execute imperatives, invisible text and drift. |
| T3 | **Malicious MCP server.** An MCP server is a program the agent starts. | It starts inside the same boundary, because inheritance is enforced by the OS, not by a hook. |
| T4 | **Supply chain.** `npm`/`pip`/`cargo` lifecycle scripts run arbitrary code. | Same boundary. A `postinstall` cannot read `~/.ssh` or write a LaunchAgent. |
| T5 | **Credential theft.** SSH, cloud, kube, registry, GitHub, browsers, keychains, shell history, other projects' `.env`. | Tier 2: denied by the sandbox, and non-promptable — no dialog exists that can open them. |
| T6 | **Persistence.** Shell startup files, LaunchAgents, systemd user units, cron, `authorized_keys`, global agent configuration. | Writes denied by the sandbox; a resident baseline watcher reports tampering from outside it. |
| T7 | **Workspace-to-host escape.** The agent writes a file the *host* later executes — a `folderOpen` task, a devcontainer lifecycle hook, an `.envrc`. | Workspace guard, rules AG-H001…H006 and AG-E001…E005, with content-addressed approvals. |
| T8 | **Network exfiltration to unexpected destinations.** | Destination broker: default deny, explicit allowlist, validated after DNS. See [network model](network-model.md). |
| T9 | **Covert channels.** A key leaked one bit at a time through an *allowed* endpoint. | **Not detected.** Stated plainly rather than implied away. The mitigation is a narrow destination allowlist. |
| T10 | **Workspace destruction.** The agent ruins the repository it is working in. | Residual risk. Isolation protects the system, not your working tree — that is what version control is for. |

## Explicitly out of scope

- Root, kernel or hypervisor compromise
- Physical access
- An already-compromised operating system
- A user who deliberately bypasses the boundary from their own shell
- Guaranteed preservation of the workspace
- A fully malicious insider
- Detecting exfiltration through an allowed destination (T9)

## Why not a prompt-injection classifier

A classifier has to guess what is bad, and it is asked to do so on input the
attacker writes. It also fails open: an unrecognised attack proceeds. A
capability boundary fails closed and does not need to recognise anything —
which is why detection here is the second layer, not the first.

## Residual risks, stated

- **`sandbox-exec` is deprecated by Apple.** It remains the built-in
  mechanism and it works on current macOS. The backend is replaceable without
  touching a line of policy.
- **Shared kernel.** Weaker than a VM by construction. A kernel vulnerability
  is outside the boundary.
- **The workspace is writable.** Anything the agent may legitimately change,
  it may also break.
- **Allowed destinations are trusted.** Once `api.anthropic.com:443` is in the
  allowlist, what travels inside that TLS session is not inspected — by
  design, since the alternative is terminating the agent's TLS.

## Vector-by-vector coverage

Threat → mechanism → rule → fixture → test is tabulated in
[threat-coverage.md](threat-coverage.md). Every CVE that motivated a rule has a
fixture and a test.
