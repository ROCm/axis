# AGENTS.md

Instructions for AI coding agents working in this repository. Everything in
[DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) applies
to you too; this file covers what agents most often get wrong here.

AXIS runs AI agents inside OS-level sandboxes driven by a declarative policy
(`policies/*.yaml`). It is security software: a change that quietly weakens
enforcement is worse than a change that fails.

## Commands

Use the Rust toolchain pinned in `rust-toolchain.toml` (edition 2024).

Before you say a change is done, read and run the
[local checks in DEVELOPMENT.md](DEVELOPMENT.md#local-checks): the first block
for every change, plus the checks for each area you changed. CI runs them on
every PR, but it does not validate every bundled policy, so validate each
policy you change. The publication gates described under
[CI/CD](DEVELOPMENT.md#cicd) include the macOS and Windows tests, so a change
that passes only on your platform does not merge; state the platforms you
tested on in the PR's Test Plan.

To iterate on one crate: `cargo test --locked -p axis-core capability`.

## Layout

| Path | Responsibility |
|---|---|
| `crates/axis-core` | Policy model, capability maps and planner (`capability_map.rs`, `capability.rs`), OPA engine, audit events |
| `crates/axis-sandbox` | OS isolation backends: `linux/` (Landlock, seccomp, bubblewrap, netns, MXC, vxn), `macos/`, `windows/` |
| `crates/axis-proxy` | HTTP proxy (CONNECT tunnels and forwarded `http://` requests) that enforces network policy |
| `crates/axis-daemon` | `axisd`, sandbox lifecycle |
| `crates/axis-cli` | `axis` command line |
| `crates/axis-gateway` | HTTP/WebSocket API for the GUI and clients |
| `crates/axis-router` | Inference routing and model registry |
| `crates/axis-gpu` | HIP Remote GPU isolation |
| `crates/axis-safety` | Credential leak detection, input validation |
| `crates/axis-pty` | Pseudoterminal allocation |
| `benches/` | `axis-bench`: backend defaults, evidence and runtime benchmarks |
| `policies/` | Bundled policies |
| `e2e/` | Per-platform end-to-end scripts |
| `gui/` | Desktop app: `shared/` (TypeScript), `linux/`, `macos/`, `windows/` |
| `docs/axis-isolation-contract.md` | What every policy field must mean on every backend |
| `docs/security-test-tiers.md` | Test tiers and when a test may skip |
| `scripts/` | Release tooling and its tests |
| `.agents/skills/` | Skills for agents working on this repository (see [Skills](#skills)) |

## Fail closed

- If a backend cannot enforce a requested control exactly, the launch must fail
  before user code runs, unless the policy accepts the weaker behavior
  (`network.bypass_audit: best_effort`, the default, does so for the bypass
  audit trail; see `docs/axis-isolation-contract.md`). On MXC the planner is
  how that is decided: `Unsupported` always refuses, and `WeakerOnly` refuses
  unless accepted. Other backends never consult the planner, so their own code
  must refuse.
- Never report weaker behavior as exact enforcement. Never turn an enforcement
  error into a warning, a skip, or a permissive default; the one accepted
  weaker behavior above is reported as weaker, not hidden.
- If you cannot tell whether something is enforced, treat it as not enforced
  and say so.

## Changing policy semantics

A policy field must mean the same thing on every backend. When you add or
change one:

1. Make the code of every runtime backend enforce it, or reject it before user
   code starts; `crates/axis-sandbox/src/sandbox.rs` selects the backend.
   Wiring a new field only into the backend you test on is fail-open: the
   other backends would accept the policy and ignore the field.
2. Make the planner see it: add its requirement in `requirements_for_policy`
   in `crates/axis-core/src/capability.rs` and record the support of every backend
   that has an entry in `crates/axis-core/src/capability_map.rs`, using the outcomes defined in
   `docs/axis-isolation-contract.md`. Only the MXC launch paths consult the
   planner, so a map entry rejects nothing on any other backend; that
   rejection belongs in the backend's code (step 1). A field a backend ignores
   is `Unsupported`, never `WeakerOnly`.
3. Update `docs/axis-isolation-contract.md` and any backend matrix in `docs/`.
4. Test the denied case on each backend (the forbidden action is refused), not
   only the allowed case.

Changes to policy semantics, backend defaults, or new backends start with a
design document in `docs/` (see DEVELOPMENT.md).

## Tests

- A skipped test is not a passing test. Tier 2–4 tests skip on hosts without
  the runtime, kernel feature, or privilege they need; real-runtime tests are
  named `gated_*`. A PR in these areas includes a run on a capable host in its
  Test Result ([Security Test Tiers](docs/security-test-tiers.md)); the
  `axis-e2e` skill covers how to run one.
- A PR that changes a backend default, the launch path, or the proxy includes
  runtime benchmark numbers
  ([Runtime Performance Benchmarks](docs/runtime-performance-benchmarks.md)).
- Do not weaken an assertion, delete a test, or add `#[ignore]` to get CI
  green. Fix the code, or stop and explain the failure.

## Skills

`.agents/skills/` holds skills for working on AXIS: `axis-e2e` (running AXIS on
a real host and reporting the result). Cursor loads them from there, and
`.claude/skills` links to the same folder for Claude Code. On Windows, git
checks the link out as a plain file unless `core.symlinks` is on.

- A skill records what the code and docs do not show, such as what only a run
  on a real host reveals. Link to `docs/` for the rest instead of copying it.
- When a change alters what a skill describes (a command, a flag, a path, a
  default), update the skill in the same PR.
- This repository is public: no host names, accounts, or internal details.

## Code conventions

- New source files start with the SPDX header from DEVELOPMENT.md, in the
  file's comment syntax (`//` for Rust and TypeScript, `#` for shell, Python and
  PowerShell), after the shebang line if there is one.
- Match the surrounding code; do not reformat files you did not change.
- Fix a lint finding in shell, Python, or PowerShell code. Where the code is
  right, suppress that one finding with a stated reason (`# shellcheck disable=`,
  `# noqa:`, `SuppressMessage` with a justification). Where a rule is wrong for
  a whole class of files, not just for the file in front of you, the only other
  route is excluding that rule in the lint config (see **Ask first**). Never
  exclude a file, and never turn a rule off only to make a finding go away.
- When the `node_modules/vite` entry in `gui/shared/package-lock.json`
  changes, update its reviewed pin in `reviewedShippedDevPackages`
  (`gui/shared/scripts/generate-third-party-notices.mjs`, which checks what
  must match) in the same PR. Part of Vite ships in the GUI bundle, so the pin
  is how its license gets reviewed: read the installed license file before
  updating its hash, and say in the PR whether the text differs from the
  previously pinned one. Never update the pin only to make `npm test` pass.

## Boundaries

**Always**
- Follow DEVELOPMENT.md for branches, commits, and pull requests: a
  `<type>/<topic>` branch from `main`; commit subjects and PR titles in the form
  `<type>(<scope>): <short summary>`, imperative, under 72 characters, with a
  body that explains why; one purpose per PR.
- Fill in every section of the
  [PR template](.github/pull_request_template.md): Motivation, Technical
  Details with **Security impact**, Test Plan (including platforms), and Test
  Result (including what skipped and why).

**Ask first**
- Adding a dependency or changing `Cargo.lock` beyond what the change needs.
- Changing a backend default or a bundled policy in `policies/`.
- Adding or widening a rule exclusion in the lint config (`ruff.toml`,
  `PSScriptAnalyzerSettings.psd1`, or a ShellCheck rc file). Write the reason
  beside the exclusion, as the existing ones do, and state it in the PR.
- Editing `.github/workflows/`, `scripts/verify_workflow_structure.py`, or
  `scripts/release_tools.py`. If a release, nightly, or GUI release job
  changes, update its pinned digest in the same PR and explain why the job
  changed; never update a digest only to make the verifier pass.

**Never**
- Relax required checks, environments, workflow permissions, or the verifier.
- Commit secrets, tokens, or credentials.
- Disclose a vulnerability in a public issue, PR, or commit message; follow
  [SECURITY.md](SECURITY.md).
