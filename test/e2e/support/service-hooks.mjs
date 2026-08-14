const shim = new URL('./child-process-services.mjs', import.meta.url).href;

/**
 * Redirects `node:child_process` to the service-manager shim.
 *
 * The same mechanism as the identity-home hook: a module-resolution seam that
 * exists only because NODE_OPTIONS carried it into the process. A compromised
 * agent cannot set that up for processes launched outside its sandbox, which
 * is exactly why the seam is safe to exist at all.
 */
export async function resolve(specifier, context, next) {
  if (
    (specifier === 'node:child_process' || specifier === 'child_process') &&
    context.parentURL !== shim
  ) {
    return { url: shim, shortCircuit: true };
  }
  return next(specifier, context);
}
