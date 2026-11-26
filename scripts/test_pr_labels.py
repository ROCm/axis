# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import contextlib
import io
import re
import unittest
from urllib.parse import unquote

import pr_labels


def pull_request(**overrides) -> pr_labels.PullRequest:
    fields = {
        "number": 7,
        "title": "docs: example",
        "draft": False,
        "base": "main",
        "head_sha": "a" * 40,
        "mergeable": "MERGEABLE",
        "review_decision": "APPROVED",
        "unresolved_threads": False,
        "labels": frozenset(),
        "files": (),
    }
    fields.update(overrides)
    return pr_labels.PullRequest(**fields)


def check_run(name: str, run_id: int, status="completed", conclusion="success"):
    return {"name": name, "id": run_id, "status": status, "conclusion": conclusion}


def node(number: int, labels=(), state="OPEN", **overrides) -> dict:
    fields = {
        "number": number,
        "title": "docs: example",
        "state": state,
        "isDraft": False,
        "baseRefName": "main",
        "headRefOid": "b" * 40,
        "mergeable": "MERGEABLE",
        "reviewDecision": "REVIEW_REQUIRED",
        "labels": {"nodes": [{"name": name} for name in labels]},
        "files": {
            "pageInfo": {"hasNextPage": False},
            "nodes": [{"path": "README.md", "additions": 1, "deletions": 0}],
        },
        "reviewThreads": {"pageInfo": {"hasNextPage": False}, "nodes": []},
    }
    fields.update(overrides)
    return fields


class FakeGitHub:
    def __init__(
        self, open_nodes=(), closed_nodes=(), closed_issues=(), check_runs=(), files=()
    ):
        self.open_nodes = list(open_nodes)
        self.closed_nodes = list(closed_nodes)
        self.closed_issues = list(closed_issues)
        self.check_runs = list(check_runs)
        self.files = list(files)
        self.writes: list[tuple[str, str, object]] = []
        self.failing: set[str] = set()

    def graphql(self, query, variables):
        if query is pr_labels.OPEN_PULL_REQUESTS_QUERY:
            return {
                "repository": {
                    "pullRequests": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": self.open_nodes,
                    },
                }
            }
        if query is pr_labels.PULL_REQUEST_QUERY:
            match = next(
                n
                for n in self.open_nodes + self.closed_nodes
                if n["number"] == variables["number"]
            )
            return {"repository": {"pullRequest": match}}
        raise AssertionError(f"unexpected query: {query}")

    def paginate(self, path, key=None):
        if path.endswith("/labels"):
            return [{"name": label.name} for label in pr_labels.ALL_LABELS]
        if "/rules/branches/" in path:
            return [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{"context": "CI publication gate"}]
                    },
                }
            ]
        if "/check-runs" in path:
            if any(sha in path for sha in self.failing):
                raise pr_labels.GitHubError(f"GET {path}: HTTP 502")
            return self.check_runs
        if path.endswith("/files"):
            return self.files
        if "/issues?state=closed&labels=" in path:
            label = unquote(path.rsplit("labels=", 1)[1])
            return [
                issue
                for issue in self.closed_issues
                if label in {n["name"] for n in issue["labels"]}
            ]
        raise AssertionError(f"unexpected path: {path}")

    def request(self, method, path, body=None, *, allow_missing=False):
        self.writes.append((method, path, body))


class AreaTests(unittest.TestCase):
    def test_each_file_counts_toward_the_first_area_that_covers_it(self):
        cases = {
            "crates/axis-sandbox/src/windows/appcontainer.rs": "area/sandbox",
            "crates/axis-sandbox/src/linux/netns.rs": "area/network",
            "crates/axis-sandbox/src/linux/bypass_audit.rs": "area/network",
            "crates/axis-pty/src/windows.rs": "area/sandbox",
            "third_party/mxc/README.md": "area/sandbox",
            "crates/axis-proxy/src/proxy.rs": "area/network",
            "crates/axis-router/src/providers.rs": "area/network",
            "crates/axis-core/src/policy.rs": "area/policy",
            "crates/axis-core/src/types.rs": "area/policy",
            "crates/axis-core/src/backend_defaults.rs": "area/sandbox",
            "crates/axis-core/src/capability_map.rs": "area/sandbox",
            "crates/axis-core/src/mxc_config.rs": "area/sandbox",
            "crates/axis-core/src/connect_attribution.rs": "area/network",
            "crates/axis-core/src/daemon_auth.rs": "area/cli-daemon",
            "crates/axis-daemon/src/main.rs": "area/cli-daemon",
            "crates/axis-gpu/src/vram_quota.rs": "area/gpu",
            "policies/gpu-agent.yaml": "area/gpu",
            "policies/claude-code.yaml": "area/policy",
            "e2e/linux/test_hip_sandbox.py": "area/gpu",
            "gui/shared/package.json": "area/gui",
            "install.sh": "area/release",
            "install.ps1": "area/release",
            ".github/workflows/ci.yml": "area/release",
            "scripts/setup_windows_mxc.ps1": "area/release",
            "e2e/linux/test_sandbox.sh": None,
            "docs/linux-setup.md": None,
            "README.md": None,
            "Cargo.lock": None,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(pr_labels.file_area(path), expected)

    def test_title_scope_then_type_then_most_changed_lines(self):
        sandbox = ("crates/axis-sandbox/src/lib.rs", 300)
        policy = ("crates/axis-core/src/policy.rs", 100)
        cases = (
            ("fix(gui): example", (sandbox,), "area/gui"),
            ("feat(Proxy)!: example", (sandbox,), "area/network"),
            ("test( daemon ): example", (), "area/cli-daemon"),
            ("ci(gui): example", (sandbox,), "area/gui"),
            ("ci(macos): example", (sandbox,), "area/release"),
            ("ci: example", (), "area/release"),
            ("build: example", (), None),
            ("feat(windows): example", (sandbox, policy), "area/sandbox"),
            ("Bump vite", (("gui/shared/package-lock.json", 40),), "area/gui"),
            (
                "fix(deps): example",
                (
                    ("crates/axis-cli/Cargo.toml", 12),
                    ("crates/axis-proxy/Cargo.toml", 9),
                    ("crates/axis-gpu/Cargo.toml", 4),
                ),
                None,
            ),
            (
                "chore: example",
                (("crates/axis-proxy/src/lib.rs", 3), (".github/workflows/ci.yml", 3)),
                None,
            ),
            ("docs(agents): example", (("AGENTS.md", 500), sandbox), None),
            ("docs: example", (("README.md", 50),), None),
            ("docs: example", (), None),
        )
        for title, files, expected in cases:
            with self.subTest(title=title, files=files):
                self.assertEqual(pr_labels.area_label(title, files), expected)

    def test_labels_are_managed_and_valid(self):
        names = [label.name for label in pr_labels.ALL_LABELS]
        self.assertEqual(len(names), len(set(names)))
        for label in pr_labels.ALL_LABELS:
            with self.subTest(label=label.name):
                self.assertTrue(label.name.startswith(pr_labels.MANAGED_PREFIXES))
                self.assertEqual(label.name, label.name.lower())
                self.assertRegex(label.color, r"^[0-9a-f]{6}$")
                self.assertLessEqual(len(label.description), 100)
        areas = set(pr_labels.AREA_LABELS)
        self.assertLessEqual(set(pr_labels.SCOPE_AREAS.values()), areas)
        self.assertLessEqual(set(pr_labels.TYPE_AREAS.values()), areas)
        self.assertEqual({rule.label for rule in pr_labels.AREA_RULES}, areas)


class StateTests(unittest.TestCase):
    required = frozenset({"CI publication gate", "Security publication gate"})

    def test_required_checks_use_the_newest_run_of_each_check(self):
        cases = (
            (
                [
                    check_run("CI publication gate", 1),
                    check_run("Security publication gate", 2),
                ],
                "pass",
            ),
            (
                [
                    check_run("CI publication gate", 1, conclusion="failure"),
                    check_run("CI publication gate", 3),
                    check_run("Security publication gate", 2, conclusion="skipped"),
                ],
                "pass",
            ),
            (
                [
                    check_run("CI publication gate", 3, conclusion="failure"),
                    check_run("CI publication gate", 1),
                    check_run("Security publication gate", 2),
                ],
                "fail",
            ),
            (
                [
                    check_run("CI publication gate", 1, conclusion="cancelled"),
                    check_run("Security publication gate", 2, status="in_progress"),
                ],
                "fail",
            ),
            ([check_run("CI publication gate", 1)], "pending"),
            (
                [
                    check_run("CI publication gate", 1),
                    check_run("Security publication gate", 2, status="queued"),
                ],
                "pending",
            ),
            (
                [
                    check_run("CI publication gate", 1),
                    check_run("Security publication gate", 2),
                    check_run("Linux MXC proof", 3, conclusion="failure"),
                ],
                "pass",
            ),
        )
        for index, (runs, expected) in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(
                    pr_labels.required_checks_state(runs, self.required), expected
                )

    def test_state_label_precedence(self):
        cases = (
            (pull_request(draft=True, mergeable="CONFLICTING"), "fail", None),
            (pull_request(mergeable="CONFLICTING"), "fail", "pr/needs-rebase"),
            (
                pull_request(review_decision="CHANGES_REQUESTED"),
                "fail",
                "pr/ci-failing",
            ),
            (
                pull_request(review_decision="CHANGES_REQUESTED"),
                "pass",
                "pr/needs-author",
            ),
            (
                pull_request(review_decision="REVIEW_REQUIRED"),
                "pending",
                "pr/needs-review",
            ),
            (pull_request(review_decision=None), "pass", "pr/needs-review"),
            (pull_request(unresolved_threads=True), "pass", "pr/needs-author"),
            (pull_request(), "pass", "pr/merge-ready"),
            (pull_request(), "pending", None),
        )
        for index, (pr, checks, expected) in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(pr_labels.state_label(pr, checks), expected)

    def test_desired_labels_add_the_area_and_keep_state_while_unknown(self):
        ready = pull_request(title="feat(gui): example")
        self.assertEqual(
            pr_labels.desired_labels(ready, "pass"), {"area/gui", "pr/merge-ready"}
        )
        unknown = pull_request(
            mergeable="UNKNOWN",
            labels=frozenset({"pr/needs-rebase", "area/gui"}),
        )
        self.assertEqual(pr_labels.desired_labels(unknown, "fail"), {"pr/needs-rebase"})
        draft = pull_request(
            draft=True, mergeable="UNKNOWN", labels=frozenset({"pr/needs-review"})
        )
        self.assertEqual(pr_labels.desired_labels(draft, "pass"), set())

    def test_label_changes_touch_only_managed_labels(self):
        current = frozenset(
            {
                "dependencies",
                "platform/linux",
                "area/old",
                "pr/needs-review",
                "area/gui",
            }
        )
        desired = {"area/gui", "pr/merge-ready"}
        self.assertEqual(
            pr_labels.label_changes(current, desired),
            (["pr/merge-ready"], ["area/old", "pr/needs-review"]),
        )


class LabelerTests(unittest.TestCase):
    def labeler(self, github, *, dry_run=False) -> pr_labels.Labeler:
        return pr_labels.Labeler(github, "ROCm/axis", dry_run=dry_run)

    def run_quietly(self, function, *arguments):
        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.redirect_stderr(io.StringIO()):
                return function(*arguments)

    def test_sync_adds_state_and_area_labels_and_encodes_removals(self):
        github = FakeGitHub(
            open_nodes=[
                node(
                    5,
                    labels=("pr/ci-failing", "dependencies"),
                    title="fix(macos): example",
                    files={
                        "pageInfo": {"hasNextPage": False},
                        "nodes": [
                            {
                                "path": "crates/axis-sandbox/src/macos/mod.rs",
                                "additions": 8,
                                "deletions": 2,
                            }
                        ],
                    },
                )
            ],
            check_runs=[check_run("CI publication gate", 1)],
        )
        self.assertTrue(self.run_quietly(self.labeler(github).sync_one, 5))
        self.assertEqual(
            github.writes,
            [
                (
                    "POST",
                    "/repos/ROCm/axis/issues/5/labels",
                    {"labels": ["area/sandbox", "pr/needs-review"]},
                ),
                ("DELETE", "/repos/ROCm/axis/issues/5/labels/pr%2Fci-failing", None),
            ],
        )

    def test_large_pull_requests_read_their_files_through_rest(self):
        github = FakeGitHub(
            open_nodes=[
                node(
                    6,
                    files={"pageInfo": {"hasNextPage": True}, "nodes": []},
                )
            ],
            check_runs=[check_run("CI publication gate", 1)],
            files=[{"filename": "gui/icon.png", "additions": 0, "deletions": 0}],
        )
        self.assertTrue(self.run_quietly(self.labeler(github).sync_one, 6))
        self.assertEqual(
            github.writes[0][2], {"labels": ["area/gui", "pr/needs-review"]}
        )

    def test_closed_pull_request_loses_only_state_labels(self):
        github = FakeGitHub(
            closed_nodes=[
                node(9, labels=("pr/merge-ready", "area/gui"), state="MERGED")
            ]
        )
        self.assertTrue(self.run_quietly(self.labeler(github).sync_one, 9))
        self.assertEqual(
            github.writes,
            [("DELETE", "/repos/ROCm/axis/issues/9/labels/pr%2Fmerge-ready", None)],
        )

    def test_sweep_clears_every_closed_pull_request_with_a_state_label(self):
        def closed(number, *labels, pull_request=True):
            issue = {"number": number, "labels": [{"name": n} for n in labels]}
            if pull_request:
                issue["pull_request"] = {}
            return issue

        github = FakeGitHub(
            closed_issues=[
                *(closed(n, "pr/merge-ready", "area/gui") for n in range(100, 140)),
                closed(7, "pr/ci-failing", "pr/needs-rebase"),
                closed(8, "pr/needs-review", pull_request=False),
            ]
        )
        self.assertTrue(self.run_quietly(self.labeler(github).sync_all))
        removed = [path.rsplit("/issues/", 1)[1] for _, path, _ in github.writes]
        self.assertEqual(
            removed,
            [
                "7/labels/pr%2Fci-failing",
                "7/labels/pr%2Fneeds-rebase",
                *(f"{n}/labels/pr%2Fmerge-ready" for n in range(100, 140)),
            ],
        )

    def test_sweep_continues_after_one_pull_request_fails(self):
        github = FakeGitHub(
            open_nodes=[
                node(1, headRefOid="1" * 40),
                node(2, headRefOid="2" * 40),
            ],
            check_runs=[check_run("CI publication gate", 1)],
        )
        github.failing.add("1" * 40)
        self.assertFalse(self.run_quietly(self.labeler(github).sync_all))
        self.assertEqual(
            [path for _, path, _ in github.writes],
            ["/repos/ROCm/axis/issues/2/labels"],
        )

    def test_dry_run_makes_no_changes(self):
        github = FakeGitHub(
            open_nodes=[node(3)], check_runs=[check_run("CI publication gate", 1)]
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.labeler(github, dry_run=True).sync_all()
        self.assertEqual(github.writes, [])
        self.assertIn("#3: +pr/needs-review", output.getvalue())

    def test_rejects_invalid_repository_and_pull_request_numbers(self):
        with self.assertRaises(pr_labels.GitHubError):
            pr_labels.Labeler(FakeGitHub(), "ROCm/axis/extra", dry_run=True)
        self.assertIsNone(pr_labels.pull_request_number(""))
        self.assertEqual(pr_labels.pull_request_number("12"), 12)
        for value in ("0", "-1", "12a"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                pr_labels.pull_request_number(value)

    def test_queries_request_every_field_the_labeler_reads(self):
        for field in (
            "title",
            "state",
            "isDraft",
            "baseRefName",
            "headRefOid",
            "mergeable",
            "reviewDecision",
        ):
            with self.subTest(field=field):
                self.assertRegex(
                    pr_labels.PULL_REQUEST_FRAGMENT, rf"\n  {re.escape(field)}\n"
                )
        self.assertIn(
            "nodes { path additions deletions }", pr_labels.PULL_REQUEST_FRAGMENT
        )


if __name__ == "__main__":
    unittest.main()
