# AGENTS.md

Instructions for AI coding agents working in this repository. Everything in
[DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) applies
to you too; this file covers what agents most often get wrong here.

AXIS runs AI agents inside OS-level sandboxes driven by a declarative policy
(`policies/*.yaml`). It is security software: a change that quietly weakens
enforcement is worse than a change that fails.

## Commands

Rust 1.95.0 (pinned in `rust-toolchain.toml`), edition 2024.

The local checks from [DEVELOPMENT.md](DEVELOPMENT.md#local-checks); run them
before you say a change is done:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/test_security_tier0.sh
```

For GUI changes, also run `npm ci`, `npm run typecheck`, `npm run build`, and
`npm audit` from `gui/shared`.

Also useful:

```bash
cargo test --locked -p axis-core capability              # one crate, filtered
python3 -m unittest discover -s scripts -p 'test_*.py'   # changes under scripts/
python3 scripts/verify_workflow_structure.py .           # changes under .github/workflows/
```

## Layout

| Path | Responsibility |
|---|---|
| `crates/axis-core` | Policy model, capability maps and planner (`capability_map.rs`, `capability.rs`), OPA engine, audit events |
| `crates/axis-sandbox` | OS isolation backends: `linux/` (Landlock, seccomp, bubblewrap, netns, MXC), `macos/`, `windows/` |
| `crates/axis-proxy` | HTTP CONNECT proxy that enforces network policy |
| `crates/axis-daemon` | `axisd`, sandbox lifecycle |
| `crates/axis-cli` | `axis` command line |
| `crates/axis-gateway` | HTTP/WebSocket API for the GUI and clients |
| `crates/axis-router` | Inference routing and model registry |
| `crates/axis-gpu` | HIP Remote GPU isolation |
| `crates/axis-safety` | Credential leak detection, input validation |
| `crates/axis-pty` | Pseudoterminal allocation |
| `docs/axis-isolation-contract.md` | What every policy field must mean on every backend |
| `docs/security-test-tiers.md` | Test tiers and when a test may skip |
| `scripts/` | Release tooling and its tests |

## Fail closed

- If a backend cannot enforce a requested control exactly, the launch fails
  before user code runs, or the planner reports `WeakerOnly` or `Unsupported`.
- Never report weaker behavior as exact enforcement. Never turn an enforcement
  error into a warning, a skip, or a permissive default.
- If you cannot tell whether something is enforced, treat it as not enforced
  and say so.

## Changing policy semantics

A policy field must mean the same thing on every backend. When you add or
change one:

1. Implement it in every backend that accepts it, or mark it `Unsupported` in
   that backend's entry in `crates/axis-core/src/capability_map.rs`.
2. Update `docs/axis-isolation-contract.md` and any backend matrix in `docs/`.
3. Test the denied case on each backend (the forbidden action is refused), not
   only the allowed case.

Changes to policy semantics, backend defaults, or new backends start with a
design document in `docs/` (see DEVELOPMENT.md).

## Tests

- A skipped test is not a passing test. Tier 2–4 tests skip on hosts without
  the runtime, kernel feature, or privilege they need; real-runtime tests are
  named `gated_*`. A PR in these areas includes a run on a capable host in its
  Test Result ([Security Test Tiers](docs/security-test-tiers.md)).
- A PR that changes a backend default, the launch path, or the proxy includes
  runtime benchmark numbers
  ([Runtime Performance Benchmarks](docs/runtime-performance-benchmarks.md)).
- Do not weaken an assertion, delete a test, or add `#[ignore]` to get CI
  green. Fix the code, or stop and explain the failure.

## Code conventions

- New source files start with the SPDX header:
  `// Copyright 2026 Advanced Micro Devices, Inc.` and
  `// SPDX-License-Identifier: Apache-2.0`.
- New `unsafe` blocks get a `// SAFETY:` comment stating the invariant.
- Match the surrounding code; do not reformat files you did not change.

## Boundaries

**Always**
- Follow DEVELOPMENT.md for branches, commits, and pull requests: a
  `<type>/<topic>` branch from `main`, Conventional Commits under 72
  characters with a body that explains why, one purpose per PR.
- Fill in every section of the
  [PR template](.github/pull_request_template.md): Motivation, Technical
  Details with **Security impact**, Test Plan (including platforms), and Test
  Result (including what skipped and why).

**Ask first**
- Adding a dependency or changing `Cargo.lock` beyond what the change needs.
- Changing a backend default or a bundled policy in `policies/`.
- Editing `.github/workflows/`, `scripts/verify_workflow_structure.py`, or
  `scripts/release_tools.py`. If a release or nightly job changes, update its
  pinned digest in the same PR and explain why the job changed; never update a
  digest only to make the verifier pass.

**Never**
- Relax required checks, environments, workflow permissions, or the verifier.
- Commit secrets, tokens, or credentials.
- Disclose a vulnerability in a public issue, PR, or commit message; follow
  [SECURITY.md](SECURITY.md).
