#!/usr/bin/env node
// Writes the LICENSE file that each platform sub-package ships.
//
// Why this exists instead of just listing the license files in "files":
//
//   * `napi create-npm-dirs` regenerates `npm/<target>/package.json` during the
//     publish job and hard-codes `files: [binaryFileName]`, so the "files" array
//     of a platform package cannot be relied on to ship anything else. Any extra
//     entry is discarded at release time.
//   * npm does always include a file whose basename is LICENSE, LICENCE,
//     LICENCE.* or COPYING, regardless of "files".
//
// So the durable mechanism is a single file named `LICENSE` in each platform
// directory, and it has to carry both license texts because the per-license
// files cannot travel with the package.
//
// Usage:
//   node scripts/platform-licenses.mjs          # write the files
//   node scripts/platform-licenses.mjs --check  # fail if out of date
import { readFile, writeFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const NPM_DIR = "npm";

const HEADER = (packageName) => `\`${packageName}\` is part of the YARA-X Node.js bindings and is
distributed under two licenses:

  * MIT License - the Node.js bindings and project code.
  * BSD 3-Clause License - the bundled YARA-X library code.

Both are reproduced in full below. The same licenses are also available as
LICENSE-MIT and LICENSE-BSD-3-Clause in the project repository:
https://github.com/cawalch/node-yara-x
`;

const RULE = "-".repeat(79);

function compose(packageName, mit, bsd) {
  return [
    HEADER(packageName).trimEnd(),
    "",
    RULE,
    "MIT License",
    RULE,
    "",
    mit.trimEnd(),
    "",
    RULE,
    "BSD 3-Clause License",
    RULE,
    "",
    bsd.trimEnd(),
    "",
  ].join("\n");
}

/** Maps a platform directory to its package name, or null if not managed here. */
async function managedPackages(root) {
  const npmDir = join(root, NPM_DIR);
  const entries = existsSync(npmDir) ? await readdir(npmDir, { withFileTypes: true }) : [];
  const packages = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const manifestPath = join(npmDir, entry.name, "package.json");
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (typeof manifest.name !== "string") continue;
    packages.push({ dir: join(npmDir, entry.name), name: manifest.name });
  }
  return packages.sort((a, b) => a.dir.localeCompare(b.dir));
}

export async function stampPlatformLicenses(root, { check = false } = {}) {
  const mit = await readFile(join(root, "LICENSE-MIT"), "utf8");
  const bsd = await readFile(join(root, "LICENSE-BSD-3-Clause"), "utf8");
  const packages = await managedPackages(root);
  const stale = [];

  for (const pkg of packages) {
    const target = join(pkg.dir, "LICENSE");
    const expected = compose(pkg.name, mit, bsd);
    if (check) {
      const actual = existsSync(target) ? await readFile(target, "utf8") : null;
      if (actual !== expected) stale.push(target);
      continue;
    }
    await writeFile(target, expected);
  }

  return { packages, stale };
}

// Only run the CLI when this file is the entry point, not when prepare-release.mjs
// imports it.
const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const check = process.argv.includes("--check");
  const { packages, stale } = await stampPlatformLicenses(process.cwd(), { check });

  if (check && stale.length > 0) {
    console.error(`Platform LICENSE files are out of date. Run: node scripts/platform-licenses.mjs`);
    for (const file of stale) console.error(`  ${file}`);
    process.exit(1);
  }

  console.log(
    check
      ? `${packages.length} platform LICENSE file(s) up to date`
      : `Wrote LICENSE for ${packages.length} platform package(s)`,
  );
}
