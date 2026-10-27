# Development Guidelines

This document describes best practices for contributing code to AXIS. It covers
the branching model, pull request workflow, release process, code quality
standards, and CI expectations. Following these guidelines keeps the codebase
healthy and makes reviews faster. It extends [CONTRIBUTING.md](CONTRIBUTING.md),
which covers development setup.

Items marked **(planned)** are agreed direction but not yet set up in the
repository.

## Branch Strategy

We use a develop + main model with short-lived feature branches.

```
feature/xxx ─┐
fix/xxx     ─┤
docs/xxx    ─┴─► develop ─► release/vX.Y ─► main (stable releases)
                                 ▲
                   hotfix/xxx ───┘
```

| Branch | Purpose | Who merges |
|---|---|---|
| `main` | Always points to the latest release commit. Protected — no direct pushes, no force pushes, no deletion. | Maintainers only (via release PR) |
| `develop` **(planned)** | Active development branch. All features and fixes are merged here. | Maintainers via PR review |
| `release/vX.Y` | Cut from `develop` when preparing a release. Only bug fixes and release prep (version bump) go here. Once ready, merged into both `main` and back into `develop`. | Maintainers |
| `feature/<topic>` | New features, enhancements. Branch from `develop`, merge back via PR. | Opened by any contributor |
| `fix/<topic>` | Bug fixes. Branch from `develop`, merge back via PR. | Opened by any contributor |
| `docs/<topic>` | Documentation-only changes. Branch from `develop`, merge back via PR. | Opened by any contributor |
| `chore/`, `ci/`, `refactor/`, `test/<topic>` | Changes of the matching commit type: maintenance, CI, refactoring, tests. Branch from `develop`, merge back via PR. | Opened by any contributor |
| `hotfix/<topic>` | Critical fixes. Branch from a `release/*` branch and merge back into it (see Hotfixes). | Maintainers only |

Until `develop` exists, PRs target `main`.

### Rules

- Never push directly to `main` or `develop`. All changes go through pull
  requests.
- `main` is release-only — it only receives merges from `release/vX.Y`
  branches.
- Day-to-day development targets `develop`.
- Keep feature branches short-lived (< 2 weeks). Rebase onto `develop`
  frequently, and before you request review.
- Contributors without write access work from a fork.
- Delete your branch after the PR is merged.

## Pull Request Workflow

### 1. Before you start

- Check existing issues and PRs to avoid duplicate work.
- For large changes, open an issue first to discuss the design. Changes to
  policy semantics, backend defaults, or new backends and providers need a
  design document (see Design Documents).

### 2. Create your branch

```bash
git checkout main && git pull origin main   # use develop once it exists
git checkout -b feature/my-new-feature
```

### 3. Develop

- Write code following the Code Standards below.
- Add or update tests for any behavioral change.
- Run the formatter, linter, and tests locally before pushing (see Local
  Checks).

### 4. Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short summary>

<optional body>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`

Examples from the history:

```
feat(policy): add workspace_read_only to grant the sandbox cwd read-only
fix(deps): update rustls to 0.23.46
chore(ci): update actions and reviewed workflow definitions
fix(gui): preserve Windows restore targets when updating WebView2
```

- Keep the subject line under 72 characters.
- Use imperative mood ("add", not "added" or "adds").
- The body explains why the change is needed and what behavior changes.
- Reference issue numbers where applicable: `Fixes #123`.

### 5. Open a pull request

- Target branch: `develop` (unless it's a hotfix; `main` until `develop`
  exists).
- Fill in the [PR template](.github/pull_request_template.md):
  - **Motivation** — what and why (1–3 bullets).
  - **Technical Details** — what changed, and the security impact: can this
    weaken isolation, cross a platform boundary, expose host state, or turn an
    enforcement failure into permissive behavior? Write "none" when it cannot.
  - **Test Plan** — how you verified correctness, and on which platforms.
  - **Test Result** — the outcome, including any test that was skipped and why.
- Link related issues.
- Keep a PR focused on one purpose. A bug fix should not also introduce a
  feature — submit them separately so each can be reviewed, reverted, and
  release-noted independently.

### 6. Draft PRs

Use GitHub Draft PRs when your work is not yet ready for formal review:

- **When to use:** You want early feedback on an approach, need CI to run
  against your changes, or want to signal to the team that you're working on
  something.
- **How to create:** Click "Create pull request" ▸ select "Create draft pull
  request" from the dropdown.
- **Behavior:** Draft PRs cannot be merged. Reviewers can leave comments but the
  PR won't enter the formal review queue.
- **When ready:** Click "Ready for review" to convert it to a regular PR and
  notify reviewers.

> **Tip:** Opening a Draft PR early is encouraged — it's better to get feedback
> on the direction before investing days of work.

### 7. Code review

- Every PR needs 1 approving review before it can merge, preferably from a
  code owner for the changed area (see Ownership).
- Address review comments with new commits; do not force-push during review, so
  reviewers can see incremental changes. If `develop` has moved, rebase once
  after approval.
- Once approved, a maintainer merges via GitHub. Prefer **Squash and merge** for
  feature, fix, docs and chore PRs; the PR title becomes the commit subject, so
  it must follow the commit format too. Use **Create a merge commit** for
  release merges (`release/vX.Y` → `main` and `develop`), so the branches keep
  their shared history.

### 8. After merge

- Delete the feature branch.

## Ownership

[CODEOWNERS](.github/CODEOWNERS) assigns owners per area and requests their
review automatically.

## Design Documents

Changes to policy semantics, backend defaults, new backends or providers, and
cross-cutting features start with a short Markdown design document in `docs/`:
problem, options, decision, evidence. It merges via PR, so the PR review is the
design review. Existing examples:
[Backend Default Decisions](docs/backend-default-decisions.md),
[Native Backend Retention](docs/native-backend-retention.md),
[vxn Integration](docs/vxn-integration.md).

## Code Standards

- Rust code is formatted with `rustfmt` and must pass `clippy` with warnings
  denied.
- Use the Rust toolchain declared in `rust-toolchain.toml`.
- Changes fail closed: if a backend cannot enforce a requested control, the
  launch fails or the planner reports WeakerOnly or Unsupported. A weaker
  behavior must never be reported as exact enforcement.
- Tests cover the intended behavior, edge cases, error paths, and the security
  boundary (the denied case is denied, not only the allowed case allowed).

### Local Checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/test_security_tier0.sh
```

For GUI changes, also run `npm ci`, `npm run typecheck`, `npm run build`, and
`npm audit` from `gui/shared`.

## CI/CD

### PR CI (triggered on every PR to `main` and `develop`)

Every PR automatically runs the following checks:

1. **Lint & format** — `cargo fmt --all -- --check` and
   `cargo clippy --locked --all-targets -- -D warnings`.
2. **Correctness tests** — `cargo test --locked`, the security tier 0/1 tests,
   the Linux, macOS and Windows test jobs, e2e tests, and policy validation.
3. **Security checks** — dependency audit and review, secret scan, CodeQL, and
   GitHub Actions security.

Do not merge a PR unless lint and correctness checks pass. PRs that change a
backend default, the launch path, or the proxy include runtime benchmark
numbers ([Runtime Performance Benchmarks](docs/runtime-performance-benchmarks.md)).

Some tests need privileges, hardware, or kernels that hosted runners do not have
(privileged Linux tiers, Windows BaseContainer and the WFP broker, newer
Landlock ABIs, GPU, vxn). They skip on such hosts, and **a skipped test is not a
passing test**. PRs in these areas include a run on a capable host in the Test
Result ([Security Test Tiers](docs/security-test-tiers.md)).

### Scheduled CI

| Job | Frequency | Purpose |
|---|---|---|
| Nightly verification | Nightly, on the default branch | Catch regressions from merged PRs |
| Security scan | Weekly | Catch new advisories in dependencies and workflows |
| Dependabot | Weekly, grouped per ecosystem | Dependency and GitHub Actions updates |

Workflow changes are checked by `scripts/verify_workflow_structure.py`, which
pins the release and nightly job definitions; update it in the same PR.

## Release Process

AXIS follows [Semantic Versioning](https://semver.org/): `vMAJOR.MINOR.PATCH`.
The latest release is v0.3.5.

| Bump | When |
|---|---|
| MAJOR | Breaking policy schema / CLI / API changes (before 1.0, these bump MINOR) |
| MINOR | New features, backward-compatible |
| PATCH | Bug fixes, docs |

### Steps (maintainers only)

1. Cut a release branch from `develop`:

   ```bash
   git checkout -b release/v0.4 develop
   ```

2. Bump `version` under `[workspace.package]` in `Cargo.toml`.
3. Stabilize on the release branch — only bug fixes allowed, no new features.
4. Tag on the release branch once stabilization is complete:

   ```bash
   git checkout release/v0.4
   git tag -a v0.4.0 -m "Release v0.4.0"
   git push origin v0.4.0
   ```

5. Merge into `main` via PR: `release/v0.4` → `main`. Get review + merge.
6. Merge back into `develop` via PR: `release/v0.4` → `develop` (to bring in any
   release-branch fixes).
7. The `release.yml` workflow publishes the release artifacts when the `v*` tag
   is pushed. Write the release notes on the GitHub release; GitHub can
   generate them from the merged PR titles.

### Hotfixes

Hotfixes always go through the corresponding release branch, keeping the tag
workflow consistent with normal releases.

- **Latest release** (e.g., current release is v0.4):
  1. Branch `hotfix/<topic>` from `release/v0.4`, apply the fix.
  2. Merge the hotfix back into `release/v0.4`.
  3. Tag on `release/v0.4` (e.g., `v0.4.1`).
  4. Merge `release/v0.4` into `main` and `develop`.
- **Older release** (e.g., v0.3 needs a patch while latest is v0.5):
  1. Branch `hotfix/<topic>` from `release/v0.3`, apply the fix.
  2. Merge the hotfix back into `release/v0.3`.
  3. Tag on `release/v0.3` (e.g., `v0.3.6`).
  4. No need to merge into `main` or `develop` — they are already ahead.

Security fixes follow [SECURITY.md](SECURITY.md) and coordinated disclosure.

## Issue & Project Management

- Use GitHub Issues for bugs, feature requests, and tasks.
- Use GitHub Milestones to group issues by release (e.g., v0.4).
- Labels are optional. The existing ones (`bug`, `enhancement`, `documentation`,
  `dependencies`, `good first issue`, `help wanted`, …) cover most cases; the
  PR title's Conventional Commits type already records the change type.

## Security & Secrets

- Never commit API keys, tokens, or credentials.
- Use environment variables for secrets (provider keys such as
  `ANTHROPIC_API_KEY`, etc.).
- If you accidentally commit a secret, rotate it immediately and notify the
  maintainers.
- CI runs a secret scan on every PR to catch common mistakes.
- Report vulnerabilities to AMD PSIRT as described in [SECURITY.md](SECURITY.md),
  never in a public issue.

## License

All contributions must be compatible with the project's
[Apache License 2.0](LICENSE). By opening a pull request, you agree that your
contribution is licensed under the same terms.

Every new source file should include the SPDX header:

```rust
// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0
```

## Future Improvements

These are not current rules. We may adopt them as the contributor base grows:

- **Owners per area** in CODEOWNERS (Linux backends, Windows and MXC, GPU and
  HIP Remote, proxy, vxn), so reviews do not all go to one person.
- **Required status checks** in the branch ruleset for Format, Clippy, and
  Test (Linux), once CI is stable enough not to block unrelated PRs.
- **Type labels** (`feat`, `fix`, `refactor`, `docs`, `defaults`, `test`,
  `ci`, `chore`), one per PR, if release notes need finer grouping than PR
  titles give.
- **A `CHANGELOG.md`**, if generated release notes are not enough.
- **Automated benchmarks** on performance-sensitive PRs and on a schedule, with
  an issue opened on regression, once a stable self-hosted runner exists.
- **A rotating triage owner** for new PRs, issues, and Dependabot.

---

Thank you for contributing to AXIS!
