# Contributing to AXIS

AXIS is a security-sensitive sandbox runtime. Changes should preserve
explicit policy semantics across supported platforms and fail closed when a
requested control cannot be enforced.

## Development Setup

Install the Rust toolchain declared by `rust-toolchain.toml`, then build the
workspace:

```bash
cargo build --locked
```

Platform-specific runtime dependencies and optional privileged test tiers are
documented in [Setup and Install](docs/setup-and-install.md) and
[Security Test Tiers](docs/security-test-tiers.md). Ordinary unit and
integration tests must not depend on installing locally built artifacts with
elevated privileges.

The shared desktop UI is built separately:

```bash
cd gui/shared
npm ci
npm run typecheck
npm run build
```

## Submitting Changes

Branches, commit messages, pull requests, local checks, CI and releases are
described in [Development Guidelines](DEVELOPMENT.md). Keep changes focused and
include tests for intended behavior, edge cases, error paths, and security
boundaries.

Changes to policy translation, process
launch, filesystem controls, network enforcement, credentials, or release
workflows require especially defensive review. Reviewers should question
whether the change can weaken isolation, cross platform boundaries, expose
host state, or turn an enforcement failure into permissive behavior.

## Reporting Security Issues

Do not open a public issue for a vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.
