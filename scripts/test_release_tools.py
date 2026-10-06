# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import release_tools
import verify_workflow_structure


FAKE_GH = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time

root = Path(os.environ["FAKE_GH_ROOT"])
root.mkdir(parents=True, exist_ok=True)
arguments = sys.argv[1:]
(root / "log").open("a", encoding="utf-8").write(json.dumps(arguments) + "\n")

def fail_not_found():
    print("HTTP 404: release not found", file=sys.stderr)
    raise SystemExit(1)

def read_state():
    path = root / "release.json"
    if not path.exists():
        fail_not_found()
    state = json.loads(path.read_text(encoding="utf-8"))
    assets = []
    asset_root = root / "assets"
    asset_root.mkdir(exist_ok=True)
    for asset_id, path in enumerate(sorted(asset_root.iterdir()), start=1):
        size = path.stat().st_size
        override = os.environ.get("FAKE_GH_REPORTED_SIZE")
        if override is not None:
            size = int(override)
        assets.append({
            "name": path.name,
            "size": size,
            "id": asset_id,
        })
    state["assets"] = assets
    return state

def option(name, default=None):
    if name not in arguments:
        return default
    index = arguments.index(name)
    return arguments[index + 1]

if arguments[:3] == ["api", "--method", "GET"]:
    endpoint = arguments[3]
    hang_endpoint = os.environ.get("FAKE_GH_HANG_ENDPOINT")
    noisy_endpoint = os.environ.get("FAKE_GH_NOISY_ENDPOINT")
    if hang_endpoint and hang_endpoint in endpoint:
        time.sleep(30)
    if noisy_endpoint and noisy_endpoint in endpoint:
        os.write(1, b"x" * (5 * 1024 * 1024))
        raise SystemExit(0)
    if "/actions/runs/" in endpoint and endpoint.endswith("/jobs"):
        run_id = endpoint.split("/actions/runs/", 1)[1].split("/", 1)[0]
        sys.stdout.write((root / f"jobs-{run_id}.json").read_text())
    elif "/actions/workflows/" in endpoint:
        workflow = endpoint.split("/actions/workflows/", 1)[1].split("/", 1)[0]
        sys.stdout.write((root / f"workflow-{workflow}.json").read_text())
    elif endpoint.count("/") == 2 and endpoint.startswith("repos/"):
        print(json.dumps({"default_branch": "main"}))
    elif "/commits/" in endpoint:
        print(json.dumps({"sha": os.environ["FAKE_GH_DEFAULT_SHA"]}))
    elif "/git/ref/tags/" in endpoint:
        tag_path = root / "tag.json"
        if not tag_path.exists():
            fail_not_found()
        print(tag_path.read_text(encoding="utf-8"))
    elif "/git/tags/" in endpoint:
        print((root / f"annotated-{endpoint.rsplit('/', 1)[1]}.json").read_text())
    elif "/releases/tags/" in endpoint:
        print(json.dumps(read_state()))
    elif "/releases/assets/" in endpoint:
        asset_id = int(endpoint.rsplit("/", 1)[1])
        paths = sorted((root / "assets").iterdir())
        sys.stdout.buffer.write(paths[asset_id - 1].read_bytes())
    else:
        print(f"unexpected api endpoint: {endpoint}", file=sys.stderr)
        raise SystemExit(2)
elif arguments[:2] == ["release", "create"]:
    notes = Path(option("--notes-file")).read_text(encoding="utf-8")
    state = {
        "draft": True,
        "prerelease": "--prerelease" in arguments,
        "target_commitish": option("--target"),
        "name": option("--title"),
        "body": notes,
    }
    (root / "release.json").write_text(json.dumps(state), encoding="utf-8")
    (root / "tag.json").write_text(
        json.dumps({"object": {"type": "commit", "sha": option("--target")}}),
        encoding="utf-8",
    )
elif arguments[:2] == ["release", "edit"]:
    state = read_state()
    state.pop("assets", None)
    if "--draft=false" in arguments:
        state["draft"] = False
        state["immutable"] = os.environ.get("FAKE_GH_MUTABLE_RELEASE") != "1"
        if os.environ.get("FAKE_GH_MUTATE_TAG_ON_PUBLISH"):
            (root / "tag.json").write_text(
                json.dumps({"object": {"type": "commit", "sha": "9" * 40}}),
                encoding="utf-8",
            )
        if os.environ.get("FAKE_GH_MUTATE_ASSET_ON_PUBLISH"):
            paths = sorted((root / "assets").iterdir())
            paths[0].write_bytes(b"substituted")
    if "--draft" in arguments:
        state["draft"] = True
    if "--prerelease" in arguments:
        state["prerelease"] = True
    if "--target" in arguments:
        state["target_commitish"] = option("--target")
    if "--title" in arguments:
        state["name"] = option("--title")
    if "--notes-file" in arguments:
        state["body"] = Path(option("--notes-file")).read_text(encoding="utf-8")
    (root / "release.json").write_text(json.dumps(state), encoding="utf-8")
elif arguments[:2] == ["release", "upload"]:
    destination = root / "assets"
    destination.mkdir(exist_ok=True)
    sources = arguments[3:arguments.index("--repo")]
    for source in sources:
        path = Path(source)
        (destination / path.name).write_bytes(path.read_bytes())
elif arguments[:2] == ["release", "delete-asset"]:
    (root / "assets" / arguments[3]).unlink(missing_ok=True)
else:
    print(f"unexpected gh arguments: {arguments}", file=sys.stderr)
    raise SystemExit(2)
"""


class FakeGhTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)
        self.environment = {
            "FAKE_GH_ROOT": str(self.root / "gh"),
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "AXIS_RELEASE_COMMAND_TIMEOUT": "2",
        }
        self.patch = mock.patch.dict(os.environ, self.environment)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    @property
    def gh_root(self) -> Path:
        path = Path(self.environment["FAKE_GH_ROOT"])
        path.mkdir(parents=True, exist_ok=True)
        return path

    def workflow_response(self, name: str, runs: list[dict]) -> None:
        base_id = 100 if name == "ci.yml" else 200
        normalized = []
        for index, run in enumerate(runs):
            item = dict(run)
            item.setdefault("id", base_id + index)
            normalized.append(item)
            expected = release_tools.REQUIRED_WORKFLOW_JOB_NAMES[name]
            jobs = [
                {"name": job_name, "status": "completed", "conclusion": "success"}
                for job_name in sorted(expected)
            ]
            jobs.extend(
                {"name": job_name, "status": "completed", "conclusion": "skipped"}
                for job_name in sorted(
                    release_tools.SKIPPED_WORKFLOW_JOB_NAMES.get(name, set())
                )
            )
            (self.gh_root / f"jobs-{item['id']}.json").write_text(
                json.dumps({"total_count": len(jobs), "jobs": jobs}),
                encoding="utf-8",
            )
        (self.gh_root / f"workflow-{name}.json").write_text(
            json.dumps({"workflow_runs": normalized}), encoding="utf-8"
        )

    def mutate_job(self, run_id: int, name: str, **changes) -> None:
        path = self.gh_root / f"jobs-{run_id}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        job = next(job for job in document["jobs"] if job["name"] == name)
        job.update(changes)
        path.write_text(json.dumps(document), encoding="utf-8")


class WorkflowGateTests(FakeGhTestCase):
    sha = "1" * 40

    def run_gate(self) -> None:
        release_tools.verify_required_workflows(
            "ROCm/axis", self.sha, ["ci.yml", "security.yml"], 0, 0.01
        )

    def success(self) -> list[dict]:
        return [
            {
                "head_sha": self.sha,
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
            }
        ]

    def test_accepts_success_for_exact_sha_and_workflow_identity(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response("security.yml", self.success())
        self.run_gate()

    def test_rejects_missing_skipped_and_failed_required_jobs(self):
        cases = (
            ("missing", None, "omitted expected jobs"),
            (
                "skipped",
                {"status": "completed", "conclusion": "skipped"},
                "did not succeed",
            ),
            (
                "failed",
                {"status": "completed", "conclusion": "failure"},
                "did not succeed",
            ),
        )
        for label, mutation, message in cases:
            with self.subTest(label=label):
                self.workflow_response("ci.yml", self.success())
                self.workflow_response("security.yml", self.success())
                path = self.gh_root / "jobs-100.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                if mutation is None:
                    document["jobs"] = [
                        job for job in document["jobs"] if job["name"] != "Test (Linux)"
                    ]
                    document["total_count"] -= 1
                    path.write_text(json.dumps(document), encoding="utf-8")
                else:
                    self.mutate_job(100, "Test (Linux)", **mutation)
                with self.assertRaisesRegex(release_tools.ReleaseError, message):
                    self.run_gate()

    def test_rejects_unexpected_jobs_regardless_of_conclusion(self):
        for conclusion in ("success", "skipped", "failure"):
            with self.subTest(conclusion=conclusion):
                self.workflow_response("ci.yml", self.success())
                self.workflow_response("security.yml", self.success())
                path = self.gh_root / "jobs-100.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                document["jobs"].append(
                    {
                        "name": "Unexpected bypass job",
                        "status": "completed",
                        "conclusion": conclusion,
                    }
                )
                document["total_count"] += 1
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(
                    release_tools.ReleaseError, "unexpected jobs"
                ):
                    self.run_gate()

    def test_requires_reviewed_push_only_jobs_to_skip(self):
        for mutation in (
            None,
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "failure"},
            {"status": "in_progress", "conclusion": None},
        ):
            self.workflow_response("ci.yml", self.success())
            self.workflow_response("security.yml", self.success())
            path = self.gh_root / "jobs-200.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            if mutation is None:
                document["jobs"] = [
                    job
                    for job in document["jobs"]
                    if job["name"] != "Dependency review"
                ]
                document["total_count"] -= 1
                path.write_text(json.dumps(document), encoding="utf-8")
                message = "omitted expected jobs"
            else:
                self.mutate_job(200, "Dependency review", **mutation)
                message = "did not skip as reviewed"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                release_tools.ReleaseError, message
            ):
                self.run_gate()

    def test_rejects_incomplete_or_noisy_job_inspection(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response("security.yml", self.success())
        path = self.gh_root / "jobs-100.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["total_count"] += 1
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(release_tools.ReleaseError, "incomplete jobs"):
            self.run_gate()

        self.workflow_response("ci.yml", self.success())
        with mock.patch.dict(
            os.environ, {"FAKE_GH_NOISY_ENDPOINT": "/actions/runs/100/jobs"}
        ):
            with self.assertRaisesRegex(release_tools.ReleaseError, "exceeds"):
                self.run_gate()

    def test_latest_run_must_succeed_even_when_an_older_run_succeeded(self):
        older = self.success()[0] | {"id": 100}
        newer = self.success()[0] | {"id": 101, "conclusion": "failure"}
        self.workflow_response("ci.yml", [older, newer])
        self.workflow_response("security.yml", self.success())
        with self.assertRaisesRegex(release_tools.ReleaseError, "failed.*failure"):
            self.run_gate()

    def test_rechecks_successful_workflow_while_another_workflow_is_pending(self):
        calls = {"ci.yml": 0, "security.yml": 0}

        def response(repository, endpoint, *fields):
            if endpoint == f"repos/{repository}":
                return {"default_branch": "main"}
            if "/actions/workflows/" in endpoint:
                workflow = endpoint.split("/actions/workflows/", 1)[1].split("/", 1)[0]
                calls[workflow] += 1
                if workflow == "ci.yml":
                    runs = [self.success()[0] | {"id": 100}]
                    if calls[workflow] > 1:
                        runs.append(
                            self.success()[0] | {"id": 101, "conclusion": "failure"}
                        )
                    return {"workflow_runs": runs}
                if calls[workflow] == 1:
                    return {
                        "workflow_runs": [
                            self.success()[0]
                            | {"id": 200, "status": "in_progress", "conclusion": None}
                        ]
                    }
                return {"workflow_runs": [self.success()[0] | {"id": 200}]}
            raise AssertionError(endpoint)

        with mock.patch.object(
            release_tools, "gh_api", side_effect=response
        ), mock.patch.object(release_tools.time, "sleep"):
            with self.assertRaisesRegex(release_tools.ReleaseError, "ci.yml failed"):
                release_tools.verify_required_workflows(
                    "ROCm/axis", self.sha, ["ci.yml", "security.yml"], 1, 0.01
                )
        self.assertGreaterEqual(calls["ci.yml"], 2)

    def test_rechecks_all_workflows_after_successful_job_inspection(self):
        calls = {"ci.yml": 0, "security.yml": 0}

        def successful_jobs(workflow):
            names = release_tools.REQUIRED_WORKFLOW_JOB_NAMES[workflow]
            skipped = release_tools.SKIPPED_WORKFLOW_JOB_NAMES.get(workflow, set())
            return {
                "total_count": len(names) + len(skipped),
                "jobs": [
                    {"name": name, "status": "completed", "conclusion": "success"}
                    for name in names
                ]
                + [
                    {"name": name, "status": "completed", "conclusion": "skipped"}
                    for name in skipped
                ],
            }

        def response(repository, endpoint, *fields):
            if endpoint == f"repos/{repository}":
                return {"default_branch": "main"}
            if "/actions/workflows/" in endpoint:
                workflow = endpoint.split("/actions/workflows/", 1)[1].split("/", 1)[0]
                calls[workflow] += 1
                run_id = 100 if workflow == "ci.yml" else 200
                runs = [self.success()[0] | {"id": run_id}]
                if workflow == "ci.yml" and calls[workflow] > 1:
                    runs.append(
                        self.success()[0] | {"id": 101, "conclusion": "failure"}
                    )
                return {"workflow_runs": runs}
            if endpoint.endswith("/actions/runs/100/jobs"):
                return successful_jobs("ci.yml")
            if endpoint.endswith("/actions/runs/200/jobs"):
                return successful_jobs("security.yml")
            raise AssertionError(endpoint)

        with mock.patch.object(
            release_tools, "gh_api", side_effect=response
        ), mock.patch.object(release_tools.time, "sleep"):
            with self.assertRaisesRegex(release_tools.ReleaseError, "ci.yml failed"):
                release_tools.verify_required_workflows(
                    "ROCm/axis", self.sha, ["ci.yml", "security.yml"], 1, 0.01
                )
        self.assertGreaterEqual(calls["ci.yml"], 3)

    def test_rejects_missing_run(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response("security.yml", [])
        with self.assertRaisesRegex(release_tools.ReleaseError, "security.yml=missing"):
            self.run_gate()

    def test_rejects_running_run_at_deadline(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response(
            "security.yml",
            [
                {
                    "head_sha": self.sha,
                    "head_branch": "main",
                    "event": "push",
                    "status": "in_progress",
                    "conclusion": None,
                }
            ],
        )
        with self.assertRaisesRegex(release_tools.ReleaseError, "security.yml=running"):
            self.run_gate()

    def test_rejects_failed_run(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response(
            "security.yml",
            [
                {
                    "head_sha": self.sha,
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ],
        )
        with self.assertRaisesRegex(release_tools.ReleaseError, "failed.*failure"):
            self.run_gate()

    def test_rejects_success_for_wrong_sha(self):
        self.workflow_response("ci.yml", self.success())
        self.workflow_response(
            "security.yml",
            [
                {
                    "head_sha": "2" * 40,
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        )
        with self.assertRaisesRegex(release_tools.ReleaseError, "security.yml=missing"):
            self.run_gate()

    def test_rejects_pull_request_or_nondefault_branch_success(self):
        self.workflow_response("ci.yml", self.success())
        for event, branch in (("pull_request", "main"), ("push", "develop")):
            with self.subTest(event=event, branch=branch):
                self.workflow_response(
                    "security.yml",
                    [
                        {
                            "head_sha": self.sha,
                            "head_branch": branch,
                            "event": event,
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ],
                )
                with self.assertRaisesRegex(
                    release_tools.ReleaseError, "security.yml=missing"
                ):
                    self.run_gate()


class DefaultSourceTests(FakeGhTestCase):
    def test_binds_ref_api_default_commit_and_checkout(self):
        repository = Path(__file__).resolve().parent.parent
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        with mock.patch.dict(os.environ, {"FAKE_GH_DEFAULT_SHA": sha}):
            branch = release_tools.verify_default_source(
                repository, "ROCm/axis", "refs/heads/main", sha
            )
            self.assertEqual(branch, "main")
            with self.assertRaisesRegex(release_tools.ReleaseError, "must be"):
                release_tools.verify_default_source(
                    repository, "ROCm/axis", "refs/heads/topic", sha
                )
            with self.assertRaisesRegex(release_tools.ReleaseError, "current"):
                release_tools.verify_default_source(
                    repository, "ROCm/axis", "refs/heads/main", "5" * 40
                )


class PublicationTests(FakeGhTestCase):
    sha = "3" * 40

    def setUp(self):
        super().setUp()
        os.environ["GITHUB_SHA"] = self.sha
        os.environ["GITHUB_REPOSITORY"] = "ROCm/axis"
        self.assets = self.root / "assets"
        self.assets.mkdir()
        (self.assets / "payload.bin").write_bytes(b"payload")
        self.notes = self.root / "notes.md"
        self.notes.write_text(
            f"Automated nightly build from main at commit {self.sha}.\n",
            encoding="utf-8",
        )

    def publish(self) -> None:
        with redirect_stdout(io.StringIO()):
            release_tools.publish_release(
                Path.cwd(),
                "nightly",
                f"nightly-{self.sha}",
                self.assets,
                f"Nightly {self.sha}",
                self.notes,
            )

    def test_create_idempotence_recovery_and_tamper_detection(self):
        self.publish()
        state_path = self.gh_root / "release.json"
        state = json.loads(state_path.read_text())
        self.assertFalse(state["draft"])
        first_log = [
            json.loads(line) for line in (self.gh_root / "log").read_text().splitlines()
        ]
        self.publish()
        second_log = [
            json.loads(line) for line in (self.gh_root / "log").read_text().splitlines()
        ]
        mutations = (
            ("release", "create"),
            ("release", "edit"),
            ("release", "upload"),
            ("release", "delete-asset"),
        )
        self.assertEqual(
            sum(tuple(entry[:2]) in mutations for entry in first_log),
            sum(tuple(entry[:2]) in mutations for entry in second_log),
        )

        state["draft"] = True
        state_path.write_text(json.dumps(state), encoding="utf-8")
        (self.gh_root / "assets" / "stale").write_bytes(b"stale")
        self.publish()
        self.assertFalse(json.loads(state_path.read_text())["draft"])
        self.assertFalse((self.gh_root / "assets" / "stale").exists())

        (self.gh_root / "assets" / "payload.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(release_tools.ReleaseError, "remote asset differs"):
            self.publish()

    def test_rejects_oversized_remote_before_download(self):
        self.publish()
        with mock.patch.dict(
            os.environ, {"FAKE_GH_REPORTED_SIZE": str(release_tools.MAX_ASSET_SIZE + 1)}
        ):
            with self.assertRaisesRegex(
                release_tools.ReleaseError, "exceeds size limit"
            ):
                self.publish()

    def test_rejects_release_bound_to_another_commit(self):
        self.publish()
        state_path = self.gh_root / "release.json"
        state = json.loads(state_path.read_text())
        state["target_commitish"] = "6" * 40
        state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(release_tools.ReleaseError, "different commit"):
            self.publish()

    def test_rejects_remote_tag_bound_to_another_commit_before_mutation(self):
        (self.gh_root / "tag.json").write_text(
            json.dumps({"object": {"type": "commit", "sha": "8" * 40}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(release_tools.ReleaseError, "remote tag"):
            self.publish()
        self.assertFalse((self.gh_root / "release.json").exists())

    def test_rejects_remote_tag_or_asset_race_during_publication(self):
        for variable, message in (
            ("FAKE_GH_MUTATE_TAG_ON_PUBLISH", "tag changed"),
            ("FAKE_GH_MUTATE_ASSET_ON_PUBLISH", "asset differs"),
        ):
            with self.subTest(variable=variable):
                for path in (self.gh_root / "release.json", self.gh_root / "tag.json"):
                    path.unlink(missing_ok=True)
                assets = self.gh_root / "assets"
                if assets.exists():
                    for path in assets.iterdir():
                        path.unlink()
                with mock.patch.dict(os.environ, {variable: "1"}):
                    with self.assertRaisesRegex(release_tools.ReleaseError, message):
                        self.publish()

    def test_rejects_mutable_published_release(self):
        with mock.patch.dict(os.environ, {"FAKE_GH_MUTABLE_RELEASE": "1"}):
            with self.assertRaisesRegex(release_tools.ReleaseError, "not immutable"):
                self.publish()

    def test_rejects_local_asset_symlinks(self):
        target = self.root / "outside"
        target.write_bytes(b"outside")
        (self.assets / "linked.bin").symlink_to(target)
        with self.assertRaisesRegex(release_tools.ReleaseError, "unsafe"):
            self.publish()

    def test_bounds_hung_and_noisy_gh_operations(self):
        self.publish()
        with mock.patch.dict(
            os.environ,
            {
                "AXIS_RELEASE_COMMAND_TIMEOUT": "0.05",
                "FAKE_GH_HANG_ENDPOINT": "/assets/",
            },
        ):
            with self.assertRaisesRegex(release_tools.ReleaseError, "timed out"):
                self.publish()
        with mock.patch.dict(os.environ, {"FAKE_GH_NOISY_ENDPOINT": "/releases/tags/"}):
            with self.assertRaisesRegex(release_tools.ReleaseError, "exceeds"):
                self.publish()

    def test_stable_publication_uses_tag_bound_metadata(self):
        repository = self.root / "stable-repository"
        repository.mkdir()
        (repository / "Cargo.toml").write_text(
            '[workspace]\nmembers=[]\n[workspace.package]\nversion="1.2.3"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(
            ["git", "config", "commit.gpgsign", "false"], cwd=repository, check=True
        )
        subprocess.run(
            ["git", "config", "tag.gpgsign", "false"], cwd=repository, check=True
        )
        subprocess.run(["git", "add", "Cargo.toml"], cwd=repository, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "initial",
            ],
            cwd=repository,
            check=True,
        )
        subprocess.run(["git", "tag", "v1.2.3"], cwd=repository, check=True)
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        (self.gh_root / "tag.json").write_text(
            json.dumps({"object": {"type": "commit", "sha": sha}}),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"GITHUB_SHA": sha}):
            with redirect_stdout(io.StringIO()):
                release_tools.publish_release(
                    repository, "stable", "v1.2.3", self.assets, "v1.2.3", None
                )
        state = json.loads((self.gh_root / "release.json").read_text())
        self.assertEqual(state["target_commitish"], sha)
        self.assertEqual(state["name"], "v1.2.3")
        self.assertEqual(state["body"], release_tools.stable_notes("v1.2.3", sha))


class IdentityTests(unittest.TestCase):
    def test_stable_identity_binds_version_tag_head_and_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers=[]\n[workspace.package]\nversion="1.2.3"\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "commit.gpgsign", "false"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "config", "tag.gpgsign", "false"], cwd=root, check=True
            )
            subprocess.run(["git", "add", "Cargo.toml"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "initial",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "tag", "v1.2.3"], cwd=root, check=True)
            sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            release_tools.verify_stable_identity(root, "v1.2.3", sha)
            with self.assertRaisesRegex(release_tools.ReleaseError, "must be exactly"):
                release_tools.verify_stable_identity(root, "v1.2.4", sha)


class RemoteTagTests(FakeGhTestCase):
    def test_peels_annotated_tag_and_rejects_cycle(self):
        tag_object = "8" * 40
        commit = "7" * 40
        (self.gh_root / "tag.json").write_text(
            json.dumps({"object": {"type": "tag", "sha": tag_object}}),
            encoding="utf-8",
        )
        annotation = self.gh_root / f"annotated-{tag_object}.json"
        annotation.write_text(
            json.dumps({"object": {"type": "commit", "sha": commit}}),
            encoding="utf-8",
        )
        self.assertEqual(release_tools.remote_tag_commit("ROCm/axis", "v1"), commit)
        annotation.write_text(
            json.dumps({"object": {"type": "tag", "sha": tag_object}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(release_tools.ReleaseError, "cyclic"):
            release_tools.remote_tag_commit("ROCm/axis", "v1")


class MxcClosureTests(unittest.TestCase):
    def test_real_pinned_mxc_path_graph_includes_all_seven_packages(self):
        ref = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"
        names = (
            "lxc",
            "bwrap_common",
            "lxc_common",
            "mxc_build_common",
            "mxc_pty",
            "nanvix_common",
            "wxc_common",
        )
        packages = [
            {
                "id": name,
                "name": name,
                "version": "0.6.1",
                "source": None,
            }
            for name in names
        ]
        edges = {
            "lxc": [
                ("bwrap_common", None),
                ("lxc_common", None),
                ("mxc_build_common", "build"),
                ("nanvix_common", "build"),
                ("wxc_common", None),
            ],
            "bwrap_common": [("lxc_common", None), ("wxc_common", None)],
            "lxc_common": [("mxc_pty", None), ("wxc_common", None)],
            "wxc_common": [("nanvix_common", None)],
        }
        nodes = []
        for name in names:
            nodes.append(
                {
                    "id": name,
                    "deps": [
                        {"pkg": dependency, "dep_kinds": [{"kind": kind}]}
                        for dependency, kind in edges.get(name, [])
                    ],
                }
            )
        metadata = {
            "packages": packages,
            "workspace_members": list(names),
            "resolve": {"nodes": nodes},
            "axisMxcRef": ref,
        }
        closure = release_tools.cargo_production_closure(metadata, "lxc")
        self.assertEqual({package["name"] for package in closure.values()}, set(names))
        self.assertIn("mxc_build_common", {p["name"] for p in closure.values()})

    def test_stages_nested_committed_manifests_and_rejects_dirty_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "mxc"
            root.mkdir()
            (root / "src/nested").mkdir(parents=True)
            (root / "src/Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            (root / "src/Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (root / "src/nested/Cargo.toml").write_text(
                "[package]\nname='nested'\nversion='1.0.0'\n", encoding="utf-8"
            )
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            ref = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            output = Path(temporary) / "output"
            release_tools.stage_mxc_manifests(root, ref, output)
            self.assertTrue((output / "src/nested/Cargo.toml").is_file())
            (root / "src/Cargo.toml").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(release_tools.ReleaseError, "modifications"):
                release_tools.stage_mxc_manifests(root, ref, Path(temporary) / "second")


class SbomTests(unittest.TestCase):
    def raw_document(self, suffix: str, created: str) -> dict:
        root_id = f"SPDXRef-Root-{suffix}"
        package_id = f"SPDXRef-Dependency-{suffix}"
        return {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "raw",
            "documentNamespace": f"https://example.invalid/{suffix}",
            "creationInfo": {"created": created, "creators": ["Tool: syft-1.46.0"]},
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "SPDXID": root_id,
                    "name": "raw",
                    "versionInfo": "raw",
                    "filesAnalyzed": False,
                },
                {
                    "SPDXID": package_id,
                    "name": "serde",
                    "versionInfo": "1.0.228",
                    "sourceInfo": "acquired from Cargo.lock",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:cargo/serde@1.0.228",
                        }
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": root_id,
                },
                {
                    "spdxElementId": package_id,
                    "relationshipType": "DEPENDENCY_OF",
                    "relatedSpdxElement": root_id,
                },
            ],
        }

    def test_normalization_is_deterministic_and_binds_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "axis-linux-x86_64.tar.gz"
            artifact.write_bytes(b"artifact")
            outputs = []
            for suffix, created in (
                ("one", "2026-01-01T00:00:00Z"),
                ("two", "2027-01-01T00:00:00Z"),
            ):
                raw = root / f"{suffix}.json"
                output = root / f"{suffix}.spdx.json"
                raw.write_text(json.dumps(self.raw_document(suffix, created)))
                release_tools.finalize_sbom(
                    raw,
                    output,
                    artifact,
                    "7" * 40,
                    {("cargo", "serde", "1.0.228")},
                    None,
                )
                release_tools.verify_final_sbom(output, artifact, "7" * 40)
                outputs.append(output.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_normalization_fails_when_locked_dependency_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "axis-linux-x86_64.tar.gz"
            artifact.write_bytes(b"artifact")
            raw = root / "raw.json"
            raw.write_text(json.dumps(self.raw_document("one", "2026-01-01T00:00:00Z")))
            with self.assertRaisesRegex(release_tools.ReleaseError, "missing locked"):
                release_tools.finalize_sbom(
                    raw,
                    root / "output.json",
                    artifact,
                    "7" * 40,
                    {("cargo", "reqwest", "0.12.0")},
                    None,
                )

    def test_gui_dependency_set_includes_reviewed_vite_runtime(self):
        root = Path(__file__).resolve().parent.parent
        packages = release_tools.npm_packages(root / "gui/shared/package-lock.json")
        self.assertIn(("npm", "vite", "8.3.1"), packages)

    def test_runtime_metadata_is_synthesized_into_sbom(self):
        root = Path(__file__).resolve().parent.parent
        packages, sources = release_tools.runtime_packages(root, "gui-windows")
        self.assertIn(("generic", "dotnet-desktop-runtime", "8.0"), packages)
        self.assertIn(("generic", "webview2-runtime", "evergreen"), packages)


class WorkflowStaticTests(unittest.TestCase):
    def test_publication_workflows_have_required_security_structure(self):
        root = Path(__file__).resolve().parent.parent
        verify_workflow_structure.verify_repository_workflows(root)

    def test_runtime_job_manifests_match_reviewed_workflow_names(self):
        root = Path(__file__).resolve().parent.parent / ".github/workflows"
        ci = verify_workflow_structure.load_workflow(root / "ci.yml")
        ci_names = {
            job["name"]
            for job_id, job in ci["jobs"].items()
            if job_id != "gui-release-validation"
        }
        gui = verify_workflow_structure.load_workflow(root / "gui-release.yml")
        caller_name = ci["jobs"]["gui-release-validation"]["name"]
        ci_names.update(
            f"{caller_name} / {job['name']}" for job in gui["jobs"].values()
        )
        self.assertEqual(release_tools.REQUIRED_WORKFLOW_JOB_NAMES["ci.yml"], ci_names)

        security = verify_workflow_structure.load_workflow(root / "security.yml")
        security_names = {
            job["name"]
            for job_id, job in security["jobs"].items()
            if job_id not in {"codeql", "dependency-review"}
        }
        codeql = security["jobs"]["codeql"]
        for language in codeql["strategy"]["matrix"]["language"]:
            security_names.add(
                codeql["name"].replace("${{ matrix.language }}", language)
            )
        self.assertEqual(
            release_tools.REQUIRED_WORKFLOW_JOB_NAMES["security.yml"],
            security_names,
        )
        self.assertEqual(
            release_tools.SKIPPED_WORKFLOW_JOB_NAMES["security.yml"],
            {security["jobs"]["dependency-review"]["name"]},
        )


if __name__ == "__main__":
    unittest.main()
