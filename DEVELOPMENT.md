# Development Guidelines

This document describes best practices for contributing code to AXIS. It covers
the branching model, pull request workflow, release process, code quality
standards, and CI expectations. Following these guidelines keeps the codebase
healthy and makes reviews faster. It extends [CONTRIBUTING.md](CONTRIBUTING.md),
which covers development setup.

## Branch Strategy

AXIS is trunk-based: `main` is the only long-lived branch. Every change merges
into `main` through a pull request, and every release is cut from a commit on
`main` that already passed CI.

```
feature/xxx ─┐
fix/xxx     ─┼─► main ─► tag vX.Y.Z (stable)
docs/xxx    ─┘     └───► nightly-<sha> (nightly prerelease)
```

| Branch | Purpose |
|---|---|
| `main` | Integration and release branch. Protected: no direct pushes, no force pushes, no deletion. |
| `feature/<topic>` | New features and enhancements. |
| `fix/<topic>` | Bug fixes. |
| `docs/<topic>` | Documentation-only changes. |
| `chore/`, `ci/`, `refactor/`, `test/<topic>` | Changes of the matching commit type: maintenance, CI, refactoring, tests. |
| `users/<name>/<topic>` | Personal work branches; CI runs on push without opening a PR. |

There are no `develop`, `release/*` or `hotfix/*` branches. Release
stabilization happens on `main`, and a fix to a released version ships as the
next patch release from `main` (see Release Process).

### Rules

- Never push directly to `main`. All changes go through pull requests.
- Branch from `main` and target `main`.
- Keep branches short-lived (< 2 weeks). Rebase onto `main` frequently, and
  before you request review.
- Do not stack PRs on each other's branches. A PR whose base is another
  feature branch merges into that branch, not into `main`. Open each PR against
  `main`, and wait for the PR it depends on to merge first.
- Contributors without write access work from a fork.
- Branches are deleted automatically when their PR merges.

## Pull Request Workflow

### 1. Before you start

- Check existing issues and PRs to avoid duplicate work.
- For large changes, open an issue first to discuss the design. Changes to
  policy semantics, backend defaults, or new backends and providers need a
  design document (see Design Documents).

### 2. Create your branch

```bash
git checkout main && git pull origin main
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

- Target branch: `main`.
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

The `main` ruleset enforces the following before a PR can merge:

- One approving review from a code owner (see Ownership), from someone other
  than the author.
- New commits dismiss earlier approvals, and the most recent push must be
  approved by someone other than the person who pushed it.
- All review threads are resolved.
- The required status checks pass (see PR CI).

Address review comments with new commits; do not force-push during review, so
reviewers can see incremental changes. If `main` has moved, rebase once after
approval, then ask for a quick re-approval.

All merge methods are enabled. Prefer **Squash and merge**: the PR title becomes
the commit subject, so it must follow the commit format too. Use a merge commit
or rebase when the individual commits are worth keeping in history.

## Ownership

[CODEOWNERS](.github/CODEOWNERS) lists the maintainers who own each path and
requests their review automatically. Today every path is owned by the same
three maintainers, who are also the `release` environment reviewers.

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

### PR CI (triggered on every PR to `main`)

Every PR automatically runs the following checks:

1. **Lint & format** — `cargo fmt --all -- --check` and
   `cargo clippy --locked --all-targets -- -D warnings`.
2. **Correctness tests** — `cargo test --locked`, the security tier 0/1 tests,
   the Linux, macOS and Windows test jobs, e2e tests, and policy validation.
3. **Security checks** — dependency audit and review, secret scan, CodeQL, and
   GitHub Actions security.

`CI publication gate` and `Security publication gate` aggregate these jobs and
are required status checks on `main`, so a PR cannot merge while any of them
fails. The same two workflows run again on the push to `main`; the release
workflows refuse to publish a commit whose `main` push runs did not succeed.

PRs that change a
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
| Nightly | Daily, on the head of `main` | Build every platform and publish a `nightly-<sha>` prerelease |
| Security scan | Weekly | Catch new advisories in dependencies and workflows |
| Dependabot | Weekly, grouped per ecosystem | Dependency and GitHub Actions updates |

Workflow changes are checked by `scripts/verify_workflow_structure.py`, which
pins the release and nightly job definitions, including the environment each
publication job runs in; update it in the same PR.

## Release Process

AXIS follows [Semantic Versioning](https://semver.org/): `vMAJOR.MINOR.PATCH`.
The latest release is v0.3.5.

| Bump | When |
|---|---|
| MAJOR | Breaking policy schema / CLI / API changes (before 1.0, these bump MINOR) |
| MINOR | New features, backward-compatible |
| PATCH | Bug fixes, docs |

### Stable release (maintainers only)

1. Open a PR that bumps `version` under `[workspace.package]` in `Cargo.toml`
   (for example `chore(release): v0.4.0`), and merge it like any other PR.
2. Wait for the `CI` and `Security` runs triggered by that merge's push to
   `main` to succeed.
3. A repository admin tags that exact commit with an annotated tag and pushes
   it:

   ```bash
   git checkout main && git pull origin main
   git tag -a v0.4.0 -m "Release v0.4.0"
   git push origin v0.4.0
   ```

4. `release.yml` builds the artifacts and their SBOMs, checksums and signed
   provenance attestations, then pauses at the
   **Create Release** job for `release` environment approval. A maintainer
   other than the one who pushed the tag reviews the run and approves it.
5. The workflow publishes the release, and GitHub makes it immutable. Edit the
   release notes afterwards if needed; GitHub can generate them from the merged
   PR titles.

The workflow refuses to publish if:

- the tag is not exactly `v` + the `Cargo.toml` workspace version, or is a
  lightweight tag;
- the tagged commit has no successful `CI` and `Security` push runs on `main`,
  so a commit that never landed on `main` cannot be released;
- the published release is not immutable.

If a release run fails before approval, fix the cause on `main` and release the
next patch version. Released tags cannot be moved or deleted, and released
versions are never reused.

### Fixes to a released version

There are no maintenance branches. A fix merges into `main` like any other PR
and ships in the next patch release (for example `v0.4.1`). Only the latest
release line receives fixes.

Security fixes follow [SECURITY.md](SECURITY.md) and coordinated disclosure.

### Nightly release

`nightly.yml` runs daily at 06:00 UTC, and maintainers can also run it by hand.
It builds the current head of `main` and publishes it as a `nightly-<sha>`
prerelease through the `nightly` environment, which only accepts runs from
`main`. It publishes only after that commit's `main` push runs of `CI` and
`Security` have succeeded.

### Repository protections

These settings back the process above. Changing them requires a repository
admin, and a change should be announced to the maintainers.

| Setting | Effect |
|---|---|
| `main` ruleset | PR required; code owner approval; stale approvals dismissed; last push approved by someone else; threads resolved; required checks `CI publication gate` and `Security publication gate`; no force push or deletion. |
| `release` environment | Required reviewers are the CODEOWNERS maintainers; the person who triggered the run cannot approve it; only `v*` tags can deploy. |
| `nightly` environment | Only `main` can deploy. |
| Tag rulesets | Only admins can create `v*` tags. Nobody can move or delete `v*` or `nightly-*` tags. |
| Immutable releases | Published releases and their assets cannot be changed. |

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

---

Thank you for contributing to AXIS!
