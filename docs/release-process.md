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

The Linux musl targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) are cross-compiled on `ubuntu-latest` with `cargo-zigbuild` and a pinned zig, because `--use-napi-cross` only provides glibc toolchains. Both zig and cargo-zigbuild are pinned in `CI.yml` so a toolchain release cannot change a release artifact. The x64 musl build is executed in an Alpine container as part of the test matrix; the arm64 musl build is built but not executed, matching the existing treatment of `aarch64-unknown-linux-gnu`.

Root `optionalDependencies` are discovered from the `npm/` directories during the publish job rather than committed, because a platform package that does not exist on the registry yet would make `pnpm install --frozen-lockfile` unresolvable. Adding a target therefore means adding it to `napi.targets`, running `napi create-npm-dirs`, and letting the publish job pick it up.

## Version Policy

- Use a patch release for dependency-only updates, release hardening, documentation corrections, and compatible fixes.
- Use a minor release when native bindings, YARA-X behavior, supported platforms, or public APIs change.
- Use an immediate patch release for high or critical security fixes.

Do not publish directly from Dependabot PRs. Let Dependabot update dependencies, let CI and review absorb the risk, then publish through the release workflow.
