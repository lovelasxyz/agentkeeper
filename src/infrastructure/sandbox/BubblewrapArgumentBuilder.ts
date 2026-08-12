import type { SandboxCommand } from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

/** System trees a process needs mounted before it can execute anything. */
const SYSTEM_ROOTS = ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc', '/opt', '/nix', '/var/lib'];

/**
 * Translates a policy into `bwrap` arguments.
 *
 * Separated from the runner for the same reason as the Seatbelt compiler: the
 * translation is where isolation is won or lost, and it should be assertable
 * without a Linux box in the loop.
 */
export class BubblewrapArgumentBuilder {
  build(policy: SandboxPolicy, context: PathContext, command: SandboxCommand): string[] {
    const args: string[] = [
      '--die-with-parent',
      '--unshare-user',
      '--unshare-net',
      '--unshare-pid',
      '--unshare-uts',
      '--unshare-ipc',
      '--unshare-cgroup-try',
      '--new-session',
      '--proc',
      '/proc',
      '--dev',
      '/dev',
    ];

    for (const root of SYSTEM_ROOTS) args.push('--ro-bind-try', root, root);

    // An empty home, so the agent's world starts without the user's dotfiles
    // rather than with them hidden one by one.
    args.push('--tmpfs', context.home.value);

    for (const ref of policy.reads) {
      if (this.isCoveredBySystem(ref.path)) continue;
      args.push('--ro-bind-try', ref.path.value, ref.path.value);
    }
    for (const ref of policy.writes) {
      args.push('--bind-try', ref.path.value, ref.path.value);
    }

    // Anchored refusals: shadow the location with an empty read-only tmpfs so
    // the path exists but holds nothing.
    for (const deny of policy.denies) {
      const anchor = deny.pattern.literalPrefix(context.home);
      if (anchor === null) continue;
      if (deny.exceptWithin?.contains(anchor) === true) continue;
      if (policy.overrides.some((override) => override.ref.covers(anchor))) continue;
      // A tmpfs mount point has to be a directory, so shadowing a readable
      // *file* makes bwrap mkdir over the bind it just created and abort the
      // whole launch with ENOTDIR. It is also unnecessary: the file is bound
      // read-only, which is exactly what refusing the write means.
      if (deny.access === 'write' && this.isReadOnlyFile(policy, anchor)) continue;
      args.push('--tmpfs', anchor.value);
    }

    // Hand-written grants are mounted last so they survive the shadowing above.
    for (const override of policy.overrides) {
      const flag = override.access === 'read' ? '--ro-bind-try' : '--bind-try';
      args.push(flag, override.ref.path.value, override.ref.path.value);
    }

    args.push('--chdir', command.cwd.value, '--', command.executable, ...command.args);
    return args;
  }

  /** Bound read-only as a single file, and never made writable elsewhere. */
  private isReadOnlyFile(policy: SandboxPolicy, anchor: AbsolutePath): boolean {
    const readable = policy.reads.some(
      (ref) => ref.scope === 'file' && ref.path.equals(anchor),
    );
    return readable && !policy.writes.some((ref) => ref.covers(anchor));
  }

  private isCoveredBySystem(path: AbsolutePath): boolean {
    return SYSTEM_ROOTS.some((root) => path.value === root || path.value.startsWith(`${root}/`));
  }
}
