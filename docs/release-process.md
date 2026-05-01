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

## Version Policy

- Use a patch release for dependency-only updates, release hardening, documentation corrections, and compatible fixes.
- Use a minor release when native bindings, YARA-X behavior, supported platforms, or public APIs change.
- Use an immediate patch release for high or critical security fixes.

Do not publish directly from Dependabot PRs. Let Dependabot update dependencies, let CI and review absorb the risk, then publish through the release workflow.
