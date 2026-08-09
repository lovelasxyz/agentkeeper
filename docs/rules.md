# Rule catalogue

Generated from the code, so the table cannot drift from what actually runs.

| ID | Check | Severity | Default |
|---|---|---|---|
| AG-H001 | Repository settings define an agent hook | high | ask |
| AG-H002 | Hook runs at session start | critical | ask |
| AG-H003 | VS Code task runs on folder open | critical | ask |
| AG-H004 | Dev container runs a lifecycle command | high | ask |
| AG-H005 | Repository carries a git hook | high | ask |
| AG-H006 | Repository carries a .envrc | medium | observe |
| AG-E001 | Repository ships a .gemini/.env | critical | ask |
| AG-E002 | Repository defines an MCP server | critical | ask |
| AG-E003 | MCP server is fetched without a pinned version | medium | observe |
| AG-E004 | Repository redirects the model endpoint | critical | block |
| AG-E005 | Repository pre-approves its own MCP servers | high | ask |
| AG-I001 | Instruction file tells the agent to execute remote content | high | ask |
| AG-I002 | Instruction file contains text you cannot see | high | ask |
| AG-I003 | Instruction file changed since the last run | medium | observe |
| AG-C001 | Workflow pins a known-vulnerable agent CLI | critical | block |
| AG-C002 | Workflow disables the agent permission prompt | high | ask |
| AG-C003 | Steps run after the agent step | medium | observe |
| AG-C004 | Two agent passes share one checkout | high | ask |
| AG-C005 | Agent job reachable by an untrusted trigger holds secrets | critical | ask |
| AG-B001 | Tool call reaches for a protected path | critical | block |
| AG-B002 | Tool call reads an environment file outside the workspace | critical | block |
| AG-B003 | Tool call writes agent configuration | critical | block |
| AG-B004 | Tool call changes where git looks for hooks | critical | block |
| AG-B005 | Tool call modifies agentkeeper itself | critical | block |
| AG-B006 | Tool call tries to start a command with isolation disabled | critical | block |
| AG-A001 | Force push to a protected branch | high | ask |
| AG-A002 | Package publication | critical | ask |
| AG-A003 | Recursive delete outside the workspace | critical | ask |
| AG-A004 | Infrastructure change | critical | ask |
| AG-A005 | Container mounts the host filesystem or the Docker socket | high | ask |
| AG-A006 | CI workflow modified | high | ask |
| AG-A007 | Outbound message through an MCP server | high | ask |
| AG-P001 | ~/.zshenv changed | critical | ask |
| AG-P002 | A shell startup file changed | high | ask |
| AG-P003 | Global git configuration gained an executable setting | critical | ask |
| AG-P004 | A login-time service appeared or changed | critical | ask |
| AG-P005 | Scheduled tasks changed | critical | ask |
| AG-P006 | SSH access or configuration changed | critical | ask |
| AG-P007 | ~/.npmrc registry or token changed | high | ask |
| AG-P008 | Agent configuration changed outside agentkeeper | high | ask |

Family B is never disabled by configuration. Family A is off by default — see the README for why.
