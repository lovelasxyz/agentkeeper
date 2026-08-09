#!/usr/bin/env node
import { CommandRouter } from './CommandRouter.js';
import { describeFailure } from '../messages/render.js';

/**
 * Entry point. Deliberately thin: everything testable lives one level down, and
 * this file only decides the exit code.
 */
const router = new CommandRouter();

router
  .run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(`agentkeeper: ${describeFailure(error)}\n`);
    process.exitCode = 1;
  });
