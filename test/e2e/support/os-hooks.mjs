const shim = new URL('./os-identity.mjs', import.meta.url).href;

/**
 * Redirects `node:os` to the identity shim.
 *
 * A module-resolution hook rather than a monkey patch: `import { userInfo }
 * from 'node:os'` binds the builtin's named export when the module is
 * instantiated, so reassigning `os.userInfo` afterwards is not observed by the
 * bundle under test.
 */
export async function resolve(specifier, context, next) {
  if ((specifier === 'node:os' || specifier === 'os') && context.parentURL !== shim) {
    return { url: shim, shortCircuit: true };
  }
  return next(specifier, context);
}
