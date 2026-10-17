# Release Process

Release publishing is intentionally semi-automated. Dependency bots may prepare changes, but npm publishing remains gated by a maintainer-reviewed version PR and a manually created GitHub release.

## Monthly Maintenance Release

The `Prepare Release` workflow runs monthly and can also be started manually. It:

1. Checks whether `main` has commits after the current `vX.Y.Z` tag.
2. Opens or updates a release PR for a patch or minor version bump.
3. Updates the root package version and generated platform package manifests.
4. Verifies the lockfiles and test suite before opening the PR.

The workflow does not publish to npm.

The release PR intentionally does not update root `optionalDependencies` to the future version. Those platform packages do not exist on npm until the release job publishes them, and pointing to unpublished optional packages would break frozen lockfile installs. `napi prepublish` synchronizes `optionalDependencies`, generated package metadata, and native package versions during the trusted publish job before npm packs the release.

## Publishing

After the release PR is reviewed and merged, run the `Create Release` workflow from `main`. It creates the matching GitHub release for the version in `package.json`.

The existing CI release workflow publishes to npm only after GitHub emits the release `published` event. Publishing uses npm Trusted Publishing and provenance; no long-lived npm publish token is required.

## Platform package licenses

Each platform sub-package ships a single `LICENSE` file committed under `npm/<target>/`. This is deliberate rather than a style choice: `napi create-npm-dirs` regenerates the platform manifests during the publish job and rewrites their `files` array to the native binary alone, so a license cannot travel with those packages by listing it in `files`. npm always includes a file named `LICENSE`, `LICENCE`, `COPYING` or `README` regardless of `files`, which is the mechanism that actually works.

`node scripts/platform-licenses.mjs` rewrites those files from the root `LICENSE-MIT` and `LICENSE-BSD-3-Clause` (it runs as part of `Prepare Release`), and `node scripts/platform-licenses.mjs --check` fails if they drift. CI runs the check on every pull request and, before publishing, asserts with `npm pack` that each package really would include a license.

## Platform targets

Root `optionalDependencies` are discovered from the `npm/` directories during the publish job rather than committed, because a platform package that does not exist on the registry yet would make `pnpm install --frozen-lockfile` unresolvable. Adding a target therefore means adding it to `napi.targets`, running `napi create-npm-dirs`, and letting the publish job pick it up.

When adding a Linux target, note that `--use-napi-cross` only provides glibc toolchains; a musl target needs `cargo-zigbuild` with zig installed on the runner, and a glibc Node.js cannot load a musl addon, so the musl artifact can only be exercised inside an Alpine container.

## Bootstrapping a new platform package

Adding a platform target adds a package name, and a name that has never been published cannot be created by this pipeline. This is verified against the registry, not assumed: an OIDC publish of a new name authenticates successfully — the run signs a provenance statement and publishes it to the transparency log — and then fails with

```
npm error code E404
npm error 404 Not Found - PUT https://registry.npmjs.org/@litko%2fyara-x-linux-arm64-musl - Not found
```

The 404 rather than a 403 is npm reporting that the name is not among the packages the workflow is trusted for. Trusted publishers are configured per package, and only from the settings page of a package that already exists, so there is no OIDC path to the first version of a new name. Publishing one requires a local session or a granular access token:

```sh
# from the platform package directory, after its native binary has been placed there
cd npm/linux-x64-musl
npm stage publish          # staging does not need 2FA; creates the package behind a 0.0.0-stage placeholder
npm stage list             # find the stage id
npm stage approve <id>     # approve with 2FA to publish the real version
```

`npm stage publish` needs npm CLI 11.15.0 or later and Node 22.14.0 or higher. Approving publishes the version, so bootstrap at the version you are about to release; the publish job skips packages whose version is already on the registry, which makes the re-run a no-op for them.

Afterwards add a trusted publisher for the new package name (package settings → Trusted publishing) and **select "allow npm publish"**. Configurations created after September 3 2026 default to staged-only and this workflow uses direct `npm publish`. New configurations must complete a first successful publish within 48 hours or they expire.

The publish job checks for this case before it publishes anything and refuses to publish, naming the packages and the commands above, rather than publishing some platform packages and then stopping partway through. To attempt it anyway (for example to test whether a trusted publisher configuration was accepted for a name that is not on the registry yet), dispatch the `CI` workflow on `main` with `allow_new_platform_packages` set to true.

The same applies when renaming a package: a package name that has never existed cannot be published by OIDC.

## Version Policy

- Use a patch release for dependency-only updates, release hardening, documentation corrections, and compatible fixes.
- Use a minor release when native bindings, YARA-X behavior, supported platforms, or public APIs change.
- Use an immediate patch release for high or critical security fixes.

Do not publish directly from Dependabot PRs. Let Dependabot update dependencies, let CI and review absorb the risk, then publish through the release workflow.
