import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import {
  FORBIDDEN_PACKAGE_PATH_PREFIXES,
  REQUIRED_PACKAGE_PATHS,
} from './package-contract.mjs';

const repository = resolve(import.meta.dirname, '..');
const packageDocument = JSON.parse(
  await readFile(resolve(repository, 'package.json'), 'utf8'),
);

if (packageDocument.name !== 'agentkeeper') {
  throw new Error(`Refusing to package unexpected npm name ${JSON.stringify(packageDocument.name)}`);
}
if (packageDocument.scripts?.postinstall !== undefined) {
  throw new Error('Refusing to package a postinstall script');
}
const runtimeDependencies = Object.keys(packageDocument.dependencies ?? {});
if (runtimeDependencies.length !== 0) {
  throw new Error(`Runtime dependencies are forbidden: ${runtimeDependencies.join(', ')}`);
}

await Promise.all(
  REQUIRED_PACKAGE_PATHS.map(async (relative) => {
    try {
      await access(resolve(repository, relative), constants.R_OK);
    } catch {
      throw new Error(`Required package artifact is missing: ${relative}`);
    }
  }),
);

// A native helper under dist/native would mean the unproven Windows
// AppContainer backend snuck back into the release. The platform must report
// UNPROTECTED until a backend passes its own deny canary on real hardware.
for (const prefix of FORBIDDEN_PACKAGE_PATH_PREFIXES) {
  const exists = await access(resolve(repository, prefix), constants.R_OK).then(
    () => true,
    () => false,
  );
  if (exists) {
    throw new Error(
      `Refusing to package a native Windows backend: ${prefix} exists. The AppContainer ` +
        'backend is not shipped while its deny canary has never completed; the platform ' +
        'reports UNPROTECTED instead.',
    );
  }
}

const tag = process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : undefined;
if (tag !== undefined && tag !== `v${packageDocument.version}`) {
  throw new Error(`Release tag ${tag} does not match package version v${packageDocument.version}`);
}

process.stdout.write(`package verification: agentkeeper ${packageDocument.version} is complete\n`);
