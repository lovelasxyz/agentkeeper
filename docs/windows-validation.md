# Windows candidate: implementation and qualification

The native AppContainer launcher remains an **unreleased candidate**. These
changes harden it; they do not establish Windows production support. The
package still refuses `dist/native`, and Windows installations still report
`UNPROTECTED` when the helper is absent.

## Architecture

The selected release target is **Windows 11 with current updates**. Windows 10
support is outside this release. The production direction is an OS-managed
process security environment (PSEC/BaseContainer); the legacy AppContainer
launcher below remains a qualification candidate, not an approved fallback.
Runtime capability checks must reject unsupported hosts and policies before
starting an agent. A Windows version string alone does not establish support.

The developer-only `probe:windows-mxc` command evaluates Microsoft's pinned
MXC 1.0.0 native executor without adding a runtime dependency or packaging it.
CI probes found BaseContainer and native filesystem denies on Windows 11 ARM64;
the Windows Server x64 runner has only the legacy AppContainer tier. These are
capability observations, not completed end-to-end qualification.

On Windows 11 ARM64, the pinned PSEC executor has now passed workspace writes
and direct/descendant file denies with Node 22 for inherited, ignored and piped
stdio. Node's `--preserve-symlinks-main` entrypoint option was necessary to avoid
an ungranted drive-root metadata query. Module loading, Git, external IPC,
network brokering and adversarial filesystem aliases require further tests;
this result alone does not qualify the backend for release.

Actual legacy tests now show working direct isolation, workspace edits,
concurrency, hardlink/junction refusals and ACL rollback. Inherited descendant
stdio works on both runners. Node 22 pipe-based descendants hang on both;
ignored stdio fails with EPERM on the Server runner and succeeds on Windows 11.
The required gate stays red until agent subprocess compatibility is resolved.

References:

- [Microsoft MXC release announcement, October 7, 2026](https://blogs.windows.com/windowsdeveloper/2026/10/07/microsoft-execution-containers-policy-driven-containment-for-ai-agents/)
- [PSEC network policy and capability limits](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/networking.md)

Keep the separate C++ executable. It uses Win32 security capabilities and a
kill-on-close Job Object without loading native code into the Node process or
requiring a Node ABI-specific addon. A future release can bundle precompiled
x64 and ARM64 helpers, so end users need no compiler or extra launch commands.

The candidate uses regular AppContainer with zero network capabilities.
LPAC is a possible stricter backend, but requires its own runtime/registry
compatibility tests; it has not been implemented or qualified here. Neither
`internetClient` nor a general loopback exemption is a domain allowlist.

Microsoft references:

- [Launching AppContainer and LPAC](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Explicit handle inheritance](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)

## What changed

- Reject ambiguous Win32 paths, including dot segments, alternate data streams,
  device names and trailing-dot/space aliases before any ACL mutation.
- Inspect granted subtrees and their ancestors through non-following handles.
  Refuse reparse points and multiply linked files before recursive grants.
  This also refuses internal hardlinks and junction-based toolchains: it is a
  conservative compatibility limit, not transparent support for every repo.
- Pin discovered objects during ACL setup. Use handles for ACL mutation and
  rollback; retain grant/deny roots until cleanup, and release descendant locks
  before running the child so ordinary file rename/delete remains possible.
- Serialize launcher ACL read/modify/write transactions with a session-scoped
  mutex, while permitting agent sessions themselves to run concurrently.
- Avoid changing ancestor ACLs. Skip redundant read grants when a simple
  existing `ALL APPLICATION PACKAGES` ACE already supplies those rights. Other
  missing permissions fail closed rather than requesting elevation implicitly.
- Pass only three explicitly listed standard stream handles. Result, request,
  ACL and Job handles are not inherited. This covers redirected/CI stdio as well
  as a console; the actual Windows behaviour still needs qualification.
- Separate launcher errors from child exits using a fixed-size `AKSRES01`
  result. Create the result file exclusively and hold it without write/delete
  sharing while the sandbox runs, with its ancestor namespace pinned too.
  Missing/malformed results fail closed.
- Set `SystemRoot`/`WINDIR` from Win32. Redirect HOME, USERPROFILE, APPDATA,
  LOCALAPPDATA and temporary paths to disposable state, removing case aliases.
- Give the child canary a shorter deadline than the outer watchdog. Bound its
  nested child too; refuse Win32's `INFINITE` value as a probe deadline.

Discovery is bounded to 100,000 distinct objects and depth 128. Oversized or
uninspectable trees refuse to launch. These checks are not a filesystem
virtualization layer and do not protect against a separate unsandboxed process
under the same user concurrently changing the workspace or ACLs.

## Developer verification

Portable checks, including an actually compiled C++ path-validator executable:

```sh
npm run typecheck
npm run lint:arch
npm run coverage
npm run test:windows-native
```

On Windows, in an MSVC developer environment with Node installed:

```sh
npm ci
npm run verify:windows
```

That command builds the actual helper and runs the real isolation suite as a
mandatory gate. It deliberately refuses to run on another OS. The Windows
suite exercises direct/descendant deny canaries, ordinary workspace edits,
stdio, reserved child exit codes, timeout followed by a fresh launch,
concurrent sessions, pre-existing hardlinks, junctions and denied loopback.
Portable tests and source assertions cannot substitute for these OS tests.

## Still required before shipping

1. Compile and execute the selected native backend on supported Windows 11 x64/ARM64,
   including a standard-user installation of Node under Program Files. Verify
   ACLs and profiles after normal exit, failure, cancellation and timeout.
2. Implement and qualify a destination-controlled Windows egress transport.
   The current translator rejects every nonempty network policy; an online
   coding agent therefore cannot use this candidate yet. Broad loopback/network
   capabilities must not replace that boundary.
3. Validate authentication, Node/native agent binaries and interactive terminal
   behaviour with supported agents. Empty disposable state does not preserve
   the user's login automatically.
4. Design durable recovery for forced helper termination/crashes. Kill-on-close
   stops the Job, but cannot execute ACL/profile rollback in a dead helper.
   The shorter canary deadline reduces this risk; it does not solve it.
5. Make Windows isolation a required CI/release gate, produce and verify both
   helper artifacts, then change the package contract. Do not remove the
   packaging refusal merely because the portable tests passed.

No promise of universal isolation or a sub-50-ms launch is made. Runtime and
filesystem compatibility, throughput and the security boundary require Windows
measurements before they can be stated as product guarantees.
