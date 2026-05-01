#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const releaseType = process.argv[2] ?? "patch";
const allowedReleaseTypes = new Set(["patch", "minor"]);

if (!allowedReleaseTypes.has(releaseType)) {
  console.error(
    `Expected release type to be one of: ${[...allowedReleaseTypes].join(", ")}`,
  );
  process.exit(1);
}

function bumpVersion(version, type) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) {
    throw new Error(`Unsupported version format: ${version}`);
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);

  if (type === "minor") {
    return `${major}.${minor + 1}.0`;
  }

  return `${major}.${minor}.${patch + 1}`;
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

const root = process.cwd();
const packageJsonPath = join(root, "package.json");
const packageJson = await readJson(packageJsonPath);
const nextVersion = bumpVersion(packageJson.version, releaseType);

packageJson.version = nextVersion;

await writeJson(packageJsonPath, packageJson);

const npmPackageDirs = [
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64-gnu",
  "linux-x64-gnu",
  "win32-arm64-msvc",
  "win32-x64-msvc",
];

for (const packageDir of npmPackageDirs) {
  const npmPackageJsonPath = join(root, "npm", packageDir, "package.json");
  const npmPackageJson = await readJson(npmPackageJsonPath);
  npmPackageJson.version = nextVersion;
  await writeJson(npmPackageJsonPath, npmPackageJson);
}

console.log(nextVersion);
