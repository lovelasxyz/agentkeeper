/**
 * Verifies the archive npm actually assembled, by reading the archive.
 *
 * An earlier version parsed `npm pack --json`. That was wrong twice over: it
 * trusted an undocumented internal shape, which changed between npm majors and
 * silently reported every artifact as missing, and it never looked at the file
 * that ships. This opens the tarball instead — no npm output format, no `tar`
 * binary, no dependencies.
 *
 * Usage: node scripts/verify-tarball.mjs [path/to/package.tgz]
 * With no argument it packs the current project into a temporary directory.
 */
import { execFileSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REQUIRED_PACKAGE_PATHS } from './package-contract.mjs';

const BLOCK = 512;

/** Entry names inside a gzipped tar, without the leading `package/`. */
export function listTarEntries(gzipped) {
  const archive = gunzipSync(gzipped);
  const names = [];

  for (let offset = 0; offset + BLOCK <= archive.length; ) {
    const header = archive.subarray(offset, offset + BLOCK);
    if (header.every((byte) => byte === 0)) break; // end-of-archive marker

    const name = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const size = Number.parseInt(readString(header, 124, 12).trim() || '0', 8);
    const type = String.fromCharCode(header[156]);
    const full = prefix.length > 0 ? `${prefix}/${name}` : name;

    // `x`/`g` are PAX metadata, `L`/`K` are GNU long-name records: payload
    // describing the *next* entry, never a packaged file themselves.
    if (!['x', 'g', 'L', 'K'].includes(type) && full.length > 0) names.push(full);

    offset += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
  }
  return names;
}

/** Required artifacts absent from the packed entry list. */
export function missingArtifacts(entries) {
  const packed = new Set(
    entries.map((entry) => entry.replace(/\\/g, '/').replace(/^package\//, '')),
  );
  return REQUIRED_PACKAGE_PATHS.filter((path) => !packed.has(path));
}

function readString(header, start, length) {
  const slice = header.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
}

function packInto(directory) {
  // `--ignore-scripts`: prepack would rebuild dist after the cross-compiled
  // helpers landed, deciding the tarball from a different tree than the one
  // just verified.
  execFileSync(
    'npm',
    ['pack', '--ignore-scripts', '--silent', '--pack-destination', directory],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  const packed = readdirSync(directory).filter((entry) => entry.endsWith('.tgz'));
  if (packed.length !== 1) {
    throw new Error(`Expected exactly one packed tarball, got ${packed.length}`);
  }
  return join(directory, packed[0]);
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const supplied = process.argv[2];
  const scratch = supplied === undefined ? mkdtempSync(join(tmpdir(), 'agentkeeper-pack-')) : null;
  try {
    const tarball = supplied === undefined ? packInto(scratch) : resolve(supplied);
    const entries = listTarEntries(readFileSync(tarball));
    const missing = missingArtifacts(entries);
    if (missing.length > 0) {
      throw new Error(`Tarball is missing required artifacts:\n  ${missing.join('\n  ')}`);
    }
    process.stdout.write(
      `tarball verification: ${entries.length} entries, all ${REQUIRED_PACKAGE_PATHS.length} required artifacts present\n`,
    );
  } finally {
    if (scratch !== null) rmSync(scratch, { recursive: true, force: true });
  }
}
