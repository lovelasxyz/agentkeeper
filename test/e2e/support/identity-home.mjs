import { register } from 'node:module';

// The identity seam and the service-manager seam. Both arrive only through
// NODE_OPTIONS, so only whoever controls how the process is launched — the
// test suite, never the agent — can install them.
register('./os-hooks.mjs', import.meta.url);
register('./service-hooks.mjs', import.meta.url);
