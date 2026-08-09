import { rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const GENERATED_DIRECTORIES = Object.freeze(['dist', 'coverage', 'build']);

await Promise.all(
  GENERATED_DIRECTORIES.map((directory) =>
    rm(resolve(process.cwd(), directory), { recursive: true, force: true }),
  ),
);
