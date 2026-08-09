import { access, readdir, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import {
  NATIVE_ARCHITECTURES,
  NATIVE_HELPER,
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

for (const architecture of NATIVE_ARCHITECTURES) {
  const entries = await readdir(resolve(repository, 'dist/native', architecture));
  const unexpected = entries.filter((entry) => entry !== NATIVE_HELPER);
  if (unexpected.length > 0) {
    throw new Error(`Unexpected native build artifacts for ${architecture}: ${unexpected.join(', ')}`);
  }
}

const tag = process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : undefined;
if (tag !== undefined && tag !== `v${packageDocument.version}`) {
  throw new Error(`Release tag ${tag} does not match package version v${packageDocument.version}`);
}

process.stdout.write(`package verification: agentkeeper ${packageDocument.version} is complete\n`);
