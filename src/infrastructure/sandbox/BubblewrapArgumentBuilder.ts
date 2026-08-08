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

    if (policy.network.length === 0) args.push('--unshare-net');

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

  private isCoveredBySystem(path: AbsolutePath): boolean {
    return SYSTEM_ROOTS.some((root) => path.value === root || path.value.startsWith(`${root}/`));
  }
}
