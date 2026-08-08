/**
 * Architecture boundaries (spec §8.1). Dependencies point inwards only.
 * A violation is a red build, not a warning.
 */
module.exports = {
  forbidden: [
    {
      name: 'domain-is-pure',
      severity: 'error',
      comment:
        'domain/ may only import domain/. Zero I/O, zero external dependencies. ' +
        'Two stdlib modules are allowed by name: `crypto` for SHA-256 and `path` for ' +
        'string normalisation. Both are pure functions with no I/O and no state — ' +
        'putting them behind a port would produce an interface with one implementation ' +
        'that never varies, which is the ceremony spec §8.3 explicitly forbids.',
      from: { path: '^src/domain' },
      to: { pathNot: '^src/domain|^(node:)?(assert|crypto|path)$' },
    },
    {
      name: 'application-not-infrastructure',
      severity: 'error',
      comment: 'application/ talks to ports, never to concrete adapters.',
      from: { path: '^src/application' },
      to: { path: '^src/infrastructure|^src/presentation' },
    },
    {
      name: 'infrastructure-not-presentation',
      severity: 'error',
      from: { path: '^src/infrastructure' },
      to: { path: '^src/presentation' },
    },
    {
      name: 'no-circular',
      severity: 'error',
      from: {},
      to: { circular: true },
    },
    {
      name: 'no-orphans',
      severity: 'warn',
      from: { orphan: true, pathNot: '(^src/index\\.ts$)' },
      to: {},
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsConfig: { fileName: 'tsconfig.json' },
    tsPreCompilationDeps: true,
    enhancedResolveOptions: { exportsFields: ['exports'], conditionNames: ['import', 'require'] },
    reporterOptions: { text: { highlightFocused: true } },
  },
};
