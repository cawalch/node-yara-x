# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories for this repository.

Do not open a public issue for a suspected vulnerability. Include the affected version, a minimal reproduction if possible, and any relevant crash output or rule input.

## Supply Chain Controls

`@litko/yara-x` is a native Node.js package, so releases are treated as supply-chain sensitive artifacts.

- Release builds run in GitHub Actions on GitHub-hosted runners.
- npm packages are published with npm Trusted Publishing and provenance, backed by GitHub OIDC and Sigstore transparency logs.
- Native `.node` artifacts are attested with GitHub artifact attestations.
- Release dependencies are installed with frozen lockfiles.
- Commits to protected branches are required to be signed.
- Pull requests that change dependency manifests or lockfiles run GitHub Dependency Review.
- Release publishing does not require a long-lived npm publish token.
- Dependabot tracks npm, Cargo, and GitHub Actions dependencies.

## Verifying a Release

Consumers can verify npm registry signatures and provenance attestations for installed dependencies:

```sh
npm audit signatures
```

Downloaded native artifacts can be verified against GitHub artifact attestations:

```sh
gh attestation verify path/to/yara-x.*.node -R cawalch/node-yara-x
```

## Supported Versions

Security fixes are released in the latest published version. If a fix cannot be safely backported, the advisory will state the affected versions and recommended upgrade path.
