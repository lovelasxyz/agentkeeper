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
The selected contract requires PSEC 1.1 and native filesystem deny,
enumeration-only metadata and ingress support (support bits `0x1`, `0x4`,
`0x8`). The developer qualification validates the actual Win32 version/support
queries with the same typed prerequisite assessor covered by regression tests.

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

Further real tests passed CommonJS/ESM loading, refusal to create an outside
hardlink, a pre-opened host IPC handle and deny-default reads of an outside
file with no explicit deny entry. They found these remaining incompatibilities:

- Git `init`/`status` cannot query the working directory. A native x64 Win32
  probe confirms `GetFinalPathNameByHandleW` fails with `ERROR_ACCESS_DENIED`
  for both normalized and opened names, even with canonical long paths.
- The tested host does not advertise enumeration-only metadata or native
  ingress support. Recursive read access to a drive root is not an acceptable
  substitute for enumeration-only access.
- An ungranted host named pipe is denied. Granting its path still does not make
  it usable; an IPC broker design cannot assume filesystem grants authorize
  named pipes.
- Deny-default network policy blocks an echo connection even within the same
  sandbox process. A TCP relay needs its own demonstrated policy; a Linux-style
  localhost relay cannot be assumed to work unchanged.
- Pre-existing hardlinks inside the writable workspace bypass both an explicit
  outside-path deny and the default deny. The host verified that the confined
  child read and modified the same outside test objects through these aliases.
  Junction reads/writes were denied. Native PSEC path policy therefore cannot
  replace filesystem-topology validation; a future PSEC launcher must reject
  multiply linked files before launch and qualify the lifetime of its object
  pins. The legacy launcher already rejects such files; the developer MXC
  executor deliberately bypasses that guard to characterize the native policy.

The hardlink reproduction was executed against the integrity-pinned MXC 1.0.0
executor on the PSEC 1.0 host, with temporary canary files only:
[native Windows alias qualification](https://github.com/lovelasxyz/agentkeeper/actions/runs/37974861151/job/113970469855).
It remains a failing regression requirement. It is not a result for PSEC 1.1,
nor a shipped agentkeeper backend; the production candidate needs its own
pre-launch alias refusal tests before these raw OS tests can qualify a release.

The separate `windows-psec` CI job runs these native tests independently of the
dependency install and legacy launcher. CI packaging and npm publication both
depend on the same reusable `.github/workflows/windows-psec.yml` gate, at the
caller's commit. A release tag cannot bypass a failed native qualification.
On a host
that qualifies for PSEC 1.1, the proof requests enumeration-only drive metadata
and tests ordinary Node entrypoint/module resolution without symlink flags.
Passing host prerequisites alone still does not qualify the product.

The observed GitHub Windows 11 host is build **26200.9457**, with PSEC **1.0**
and support mask **`0x3`**. It cannot qualify the selected 1.1 contract. To
check another Windows machine without Node, MSVC, installation or ACL changes:

```powershell
powershell.exe -NoProfile -File .\scripts\probe-windows-psec-host.ps1
```

This reports native API availability, contract version and capabilities as
JSON. The full qualification cross-checks this report against independently
compiled C++ Win32 calls before using its prerequisites. A supported report is
only the prerequisite to run the actual sandbox tests.

On October 10, 2026, the read-only
[hosted runner inventory](https://github.com/lovelasxyz/agentkeeper/actions/runs/37995156205)
confirmed that **both `windows-11-arm` and `windows-11-vs2026-arm`** expose
build **26200.9457**, PSEC **1.0** and support mask **`0x3`**. Changing between
these labels does not supply the selected prerequisites. The successful
inventory workflow does not qualify Windows support. With hosted CI as the
only available Windows test environment, the PSEC candidate remains
unfinished and unreleased; development of a separate service backend is deferred.

Actual legacy tests now show working direct isolation, workspace edits,
concurrency, hardlink/junction refusals and ACL rollback. Inherited descendant
stdio works on both runners. Node 22 pipe-based descendants hang on both;
ignored stdio fails with EPERM on the Server runner and succeeds on Windows 11.
The required gate stays red until agent subprocess compatibility is resolved.

The separate `windows-restricted-proof.yml` experiment reached process
creation on both hosted runners, then exited before the Node workload with
`STATUS_DLL_NOT_FOUND` (`0xC0000135`). It now tests disposable, ordinary copies
of the OS DLLs used by the host runtimes.
Node and Git are inventoried separately because their architectures can differ;
Git must answer a `cat-file --batch` request before its modules are recorded.
System-file ACLs are not changed. Four portable regressions cover separate
inventories, independent copies, trusted-path boundaries and DLL collisions.
These checks validate fixture preparation, not Windows loader compatibility.
[Run 37999427949](https://github.com/lovelasxyz/agentkeeper/actions/runs/37999427949)
passed DLL loading on x64 and reached a later Node startup failure:
`WSAStartup: (10107)`. ARM64 stopped earlier because native Git rejected `NUL`
as its global config path. The next revision uses an ordinary empty config
file, with a real Git regression test, and reports restricted-token read access
to Winsock registry keys and system DLLs. It does not broaden those permissions
or claim the Winsock failure is fixed. This experiment is not a production backend,
does not restrict network access, and does not replace either release gate.

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
npm run probe:windows-mxc
```

That command builds the actual helper and runs the real isolation suite as a
mandatory gate. It deliberately refuses to run on another OS. The Windows
suite exercises direct/descendant deny canaries, ordinary workspace edits,
stdio, reserved child exit codes, timeout followed by a fresh launch,
concurrent sessions, pre-existing hardlinks, junctions and denied loopback.
Portable tests and source assertions cannot substitute for these OS tests.

`probe:windows-mxc` compiles the developer-only Win32 diagnostic using the
configured MSVC target before exercising the pinned executor. CI targets x64
for this diagnostic on Windows 11 ARM64, matching Git's emulated x64 ABI. This
does not substitute for qualification on a physical Windows 11 x64 host.

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
