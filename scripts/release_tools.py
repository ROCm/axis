#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed release identity, SBOM, and publication helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import time
import tomllib
from typing import Any
from urllib.parse import quote, unquote

from bounded_subprocess import BoundedProcessError, run_bounded
from generate_third_party_notices import cargo_metadata


MAX_ASSET_COUNT = 64
MAX_ASSET_SIZE = 1024 * 1024 * 1024
MAX_ASSET_TOTAL_SIZE = 8 * 1024 * 1024 * 1024
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
MAX_SBOM_SIZE = 128 * 1024 * 1024
DEFAULT_COMMAND_TIMEOUT = 120.0
DEFAULT_GATE_TIMEOUT = 20 * 60.0
DEFAULT_GATE_POLL_INTERVAL = 15.0
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHIPPED_NPM_DEV_PACKAGES = {"node_modules/vite": "vite"}
MAX_TAG_PEEL_DEPTH = 8
MAX_MXC_MANIFEST_COUNT = 256
MAX_MXC_MANIFEST_SIZE = 2 * 1024 * 1024
MAX_MXC_MANIFEST_TOTAL_SIZE = 32 * 1024 * 1024
REQUIRED_WORKFLOW_JOB_NAMES = {
    "ci.yml": {
        "Format",
        "GUI release validation / Build frontend",
        "GUI release validation / Build macOS desktop",
        "GUI release validation / Build Linux desktop",
        "GUI release validation / Build Windows desktop",
        "Clippy",
        "Detect changes",
        "Test (Linux)",
        "Test (macOS native)",
        "Test Linux netns helper",
        "Test (Windows native)",
        "CI publication gate",
    },
    "security.yml": {
        "CodeQL (rust)",
        "CodeQL (javascript-typescript)",
        "CodeQL (csharp)",
        "CodeQL (swift)",
        "Dependency audit",
        "Windows NuGet audit",
        "Python SAST",
        "Secret scan",
        "GitHub Actions security",
        "Security publication gate",
    },
}
SKIPPED_WORKFLOW_JOB_NAMES = {
    "security.yml": {"Dependency review"},
}


class ReleaseError(RuntimeError):
    """A release input or operation failed validation."""


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    value = parse_json_value(data, label)
    if not isinstance(value, dict):
        raise ReleaseError(f"expected JSON object from {label}")
    return value


def parse_json_value(data: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ReleaseError(f"invalid JSON from {label}") from error
    return value


def command_timeout() -> float:
    raw = os.environ.get("AXIS_RELEASE_COMMAND_TIMEOUT", str(DEFAULT_COMMAND_TIMEOUT))
    try:
        value = float(raw)
    except ValueError as error:
        raise ReleaseError("AXIS_RELEASE_COMMAND_TIMEOUT must be numeric") from error
    if value <= 0 or value > 30 * 60:
        raise ReleaseError("AXIS_RELEASE_COMMAND_TIMEOUT is outside the allowed range")
    return value


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    stdout_limit: int = MAX_COMMAND_OUTPUT,
) -> bytes:
    try:
        return run_bounded(
            command,
            cwd=cwd,
            timeout=command_timeout(),
            stdout_limit=stdout_limit,
            stderr_limit=MAX_COMMAND_OUTPUT,
        ).stdout
    except BoundedProcessError as error:
        raise ReleaseError(str(error)) from error


def validate_sha(sha: str) -> str:
    if not GIT_SHA_RE.fullmatch(sha):
        raise ReleaseError(f"expected a lowercase 40-character Git SHA: {sha!r}")
    return sha


def validate_repository(repository: str) -> str:
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseError(f"invalid GitHub repository: {repository!r}")
    return repository


def workspace_version(repository_root: Path) -> str:
    try:
        document = tomllib.loads(
            (repository_root / "Cargo.toml").read_text(encoding="utf-8")
        )
        version = document["workspace"]["package"]["version"]
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
    ) as error:
        raise ReleaseError("failed to read workspace package version") from error
    semver_number = r"(?:0|[1-9][0-9]*)"
    if not isinstance(version, str) or not re.fullmatch(
        rf"{semver_number}(?:\.{semver_number}){{2}}(?:[-+][0-9A-Za-z.-]+)?",
        version,
    ):
        raise ReleaseError(f"workspace package version is not SemVer: {version!r}")
    return version


def git_output(repository_root: Path, *arguments: str) -> str:
    return run_command(["git", *arguments], cwd=repository_root).decode().strip()


def verify_stable_identity(repository_root: Path, tag: str, sha: str) -> None:
    validate_sha(sha)
    expected_tag = f"v{workspace_version(repository_root)}"
    if tag != expected_tag:
        raise ReleaseError(f"release tag must be exactly {expected_tag}, got {tag}")
    tagged_commit = git_output(
        repository_root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"
    )
    if tagged_commit != sha:
        raise ReleaseError(
            f"tag {tag} resolves to {tagged_commit}, not release commit {sha}"
        )
    head = git_output(repository_root, "rev-parse", "HEAD")
    if head != sha:
        raise ReleaseError(f"checkout HEAD {head} does not match release commit {sha}")


def gh_api(repository: str, endpoint: str, *fields: str) -> dict[str, Any]:
    command = ["gh", "api", "--method", "GET", endpoint]
    for field in fields:
        command.extend(("-f", field))
    return parse_json(run_command(command), f"GitHub API {endpoint}")


def remote_tag_commit(
    repository: str,
    tag: str,
    *,
    allow_missing: bool = False,
    require_annotated: bool = False,
) -> str | None:
    """Resolve a GitHub tag ref to a commit, peeling annotated tags safely."""

    repository = validate_repository(repository)
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", tag):
        raise ReleaseError(f"invalid release tag: {tag!r}")
    endpoint = f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}"
    try:
        document = gh_api(repository, endpoint)
    except ReleaseError as error:
        if allow_missing and (
            "HTTP 404" in str(error) or "not found" in str(error).lower()
        ):
            return None
        raise
    target = document.get("object")
    if require_annotated and (
        not isinstance(target, dict) or target.get("type") != "tag"
    ):
        raise ReleaseError(f"release tag {tag} must be an annotated tag")
    seen: set[str] = set()
    for _ in range(MAX_TAG_PEEL_DEPTH):
        if not isinstance(target, dict):
            raise ReleaseError("GitHub tag ref omitted its target object")
        object_type, object_sha = target.get("type"), target.get("sha")
        if not isinstance(object_type, str) or not isinstance(object_sha, str):
            raise ReleaseError("GitHub tag ref returned a malformed target object")
        validate_sha(object_sha)
        if object_type == "commit":
            return object_sha
        if object_type != "tag" or object_sha in seen:
            raise ReleaseError("GitHub tag ref has an invalid or cyclic target")
        seen.add(object_sha)
        target = gh_api(repository, f"repos/{repository}/git/tags/{object_sha}").get(
            "object"
        )
    raise ReleaseError("GitHub tag ref exceeds the maximum annotation depth")


def verify_default_source(
    repository_root: Path, repository: str, ref: str, sha: str
) -> str:
    repository = validate_repository(repository)
    validate_sha(sha)
    metadata = gh_api(repository, f"repos/{repository}")
    default_branch = metadata.get("default_branch")
    if not isinstance(default_branch, str) or not re.fullmatch(
        r"[A-Za-z0-9._/-]+", default_branch
    ):
        raise ReleaseError("GitHub API returned an invalid default branch")
    if ref != f"refs/heads/{default_branch}":
        raise ReleaseError(
            f"nightly source must be refs/heads/{default_branch}, got {ref}"
        )
    commit = gh_api(
        repository, f"repos/{repository}/commits/{quote(default_branch, safe='')}"
    )
    if commit.get("sha") != sha:
        raise ReleaseError("nightly SHA is not the current default-branch commit")
    head = git_output(repository_root, "rev-parse", "HEAD")
    if head != sha:
        raise ReleaseError(f"checkout HEAD {head} does not match nightly commit {sha}")
    return default_branch


def workflow_state(
    document: dict[str, Any], sha: str, default_branch: str
) -> tuple[str, str, int | None]:
    runs = document.get("workflow_runs")
    if not isinstance(runs, list):
        raise ReleaseError("workflow API response omitted workflow_runs")
    matching = []
    for run in runs:
        if not isinstance(run, dict):
            raise ReleaseError("workflow API returned a malformed run")
        if (
            run.get("head_sha") == sha
            and run.get("event") == "push"
            and run.get("head_branch") == default_branch
        ):
            matching.append(run)
    if not matching:
        return "missing", "", None
    for run in matching:
        run_id = run.get("id")
        if not isinstance(run_id, int) or run_id <= 0:
            raise ReleaseError("workflow API returned a run without a valid id")
    latest = max(matching, key=lambda run: run["id"])
    if latest.get("status") != "completed":
        return "running", "", None
    if latest.get("conclusion") != "success":
        return "failed", str(latest.get("conclusion")), None
    return "success", "", latest["id"]


def verify_workflow_jobs(repository: str, workflow: str, run_id: int) -> None:
    expected = REQUIRED_WORKFLOW_JOB_NAMES.get(workflow)
    if expected is None:
        raise ReleaseError(f"no reviewed job manifest for workflow: {workflow}")
    skipped = SKIPPED_WORKFLOW_JOB_NAMES.get(workflow, set())
    if expected & skipped:
        raise ReleaseError(f"reviewed job manifests overlap for workflow: {workflow}")
    document = gh_api(
        repository,
        f"repos/{repository}/actions/runs/{run_id}/jobs",
        "filter=latest",
        "per_page=100",
    )
    jobs = document.get("jobs")
    total_count = document.get("total_count")
    if (
        not isinstance(jobs, list)
        or not isinstance(total_count, int)
        or total_count != len(jobs)
        or total_count > 100
    ):
        raise ReleaseError(f"required workflow {workflow} returned incomplete jobs")
    by_name: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ReleaseError(f"required workflow {workflow} returned a malformed job")
        name = job["name"]
        if name in by_name:
            raise ReleaseError(f"required workflow {workflow} duplicated job {name}")
        by_name[name] = job
    reviewed = expected | skipped
    missing = sorted(reviewed - set(by_name))
    if missing:
        raise ReleaseError(
            f"required workflow {workflow} omitted expected jobs: {', '.join(missing)}"
        )
    unexpected = sorted(set(by_name) - reviewed)
    if unexpected:
        raise ReleaseError(
            f"required workflow {workflow} returned unexpected jobs: "
            + ", ".join(unexpected)
        )
    unsuccessful = sorted(
        name
        for name in expected
        if by_name[name].get("status") != "completed"
        or by_name[name].get("conclusion") != "success"
    )
    if unsuccessful:
        raise ReleaseError(
            f"required workflow {workflow} jobs did not succeed: "
            + ", ".join(unsuccessful)
        )
    incorrectly_skipped = sorted(
        name
        for name in skipped
        if by_name[name].get("status") != "completed"
        or by_name[name].get("conclusion") != "skipped"
    )
    if incorrectly_skipped:
        raise ReleaseError(
            f"required workflow {workflow} jobs did not skip as reviewed: "
            + ", ".join(incorrectly_skipped)
        )


def verify_required_workflows(
    repository: str,
    sha: str,
    workflows: list[str],
    timeout: float,
    poll_interval: float,
) -> None:
    repository = validate_repository(repository)
    validate_sha(sha)
    if not workflows or len(set(workflows)) != len(workflows):
        raise ReleaseError("required workflow identities must be unique")
    for workflow in workflows:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow):
            raise ReleaseError(f"invalid workflow identity: {workflow!r}")
    if timeout < 0 or timeout > 30 * 60 or poll_interval <= 0:
        raise ReleaseError("workflow gate timing is outside the allowed range")

    metadata = gh_api(repository, f"repos/{repository}")
    default_branch = metadata.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ReleaseError("GitHub API returned an invalid default branch")

    deadline = time.monotonic() + timeout
    while True:
        states: dict[str, str] = {}
        successful_runs: dict[str, int] = {}
        for workflow in sorted(workflows):
            document = gh_api(
                repository,
                f"repos/{repository}/actions/workflows/{workflow}/runs",
                f"head_sha={sha}",
                "per_page=100",
            )
            state, detail, run_id = workflow_state(document, sha, default_branch)
            if state == "success":
                if run_id is None:
                    raise ReleaseError("successful workflow state omitted its run id")
                successful_runs[workflow] = run_id
            elif state == "failed":
                raise ReleaseError(
                    f"required workflow {workflow} failed for {sha}: {detail}"
                )
            else:
                states[workflow] = state
        if len(successful_runs) == len(workflows):
            for workflow in sorted(workflows):
                verify_workflow_jobs(repository, workflow, successful_runs[workflow])

            # Re-read every workflow after job inspection. A rerun can start while
            # another workflow's jobs are being checked, including under the same
            # workflow run id, so publication only trusts an unchanged snapshot.
            stable = True
            for workflow in sorted(workflows):
                document = gh_api(
                    repository,
                    f"repos/{repository}/actions/workflows/{workflow}/runs",
                    f"head_sha={sha}",
                    "per_page=100",
                )
                state, _detail, run_id = workflow_state(document, sha, default_branch)
                if state != "success" or run_id != successful_runs[workflow]:
                    stable = False
            if stable:
                return
            states = {workflow: "changed" for workflow in workflows}
        if time.monotonic() >= deadline:
            detail = ", ".join(f"{name}={states[name]}" for name in sorted(states))
            raise ReleaseError(f"required workflow gate timed out for {sha}: {detail}")
        time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))


def verify_mxc_checkout(mxc_dir: Path, expected_ref: str) -> None:
    validate_sha(expected_ref)
    if git_output(mxc_dir, "rev-parse", "HEAD") != expected_ref:
        raise ReleaseError("MXC checkout does not match the pinned commit")
    if git_output(mxc_dir, "status", "--porcelain", "--untracked-files=no"):
        raise ReleaseError("MXC checkout has tracked modifications")
    for relative in ("src/Cargo.toml", "src/Cargo.lock"):
        path = mxc_dir / relative
        if not path.is_file():
            raise ReleaseError(f"MXC checkout is missing {relative}")
        committed = run_command(
            ["git", "show", f"{expected_ref}:{relative}"],
            cwd=mxc_dir,
            stdout_limit=MAX_SBOM_SIZE,
        )
        if path.read_bytes() != committed:
            raise ReleaseError(f"MXC {relative} does not match the pinned commit")


def stage_mxc_manifests(mxc_dir: Path, expected_ref: str, output_dir: Path) -> None:
    """Copy all committed MXC Cargo manifests without trusting checkout contents."""

    verify_mxc_checkout(mxc_dir, expected_ref)
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ReleaseError("MXC manifest output directory must be empty")
    listing = run_command(
        ["git", "ls-tree", "-r", "-z", "--name-only", expected_ref, "--", "src"],
        cwd=mxc_dir,
    )
    try:
        names = listing.decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise ReleaseError("MXC tree contains a non-UTF-8 path") from error
    manifest_paths: list[PurePosixPath] = []
    for name in names:
        if not name:
            continue
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.parts[0] != "src"
        ):
            raise ReleaseError(f"MXC tree returned an unsafe path: {name}")
        if relative.name in ("Cargo.toml", "Cargo.lock"):
            manifest_paths.append(relative)
    if not manifest_paths or len(manifest_paths) > MAX_MXC_MANIFEST_COUNT:
        raise ReleaseError("MXC manifest count is outside the allowed range")
    total = 0
    for relative in sorted(manifest_paths):
        content = run_command(
            ["git", "show", f"{expected_ref}:{relative.as_posix()}"],
            cwd=mxc_dir,
            stdout_limit=MAX_MXC_MANIFEST_SIZE,
        )
        total += len(content)
        if total > MAX_MXC_MANIFEST_TOTAL_SIZE:
            raise ReleaseError("MXC manifests exceed the aggregate size limit")
        destination = output_dir.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


PackageKey = tuple[str, str, str]
PackageSources = dict[PackageKey, tuple[str, str | None]]


def cargo_production_closure(
    metadata: dict[str, Any], root_package: str | None = None
) -> dict[str, dict[str, Any]]:
    """Return normal/build Cargo dependencies, retaining workspace/path packages."""

    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise ReleaseError("Cargo metadata omitted packages or resolve graph")
    package_by_id: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise ReleaseError("Cargo metadata contains a malformed package")
        if package["id"] in package_by_id:
            raise ReleaseError("Cargo metadata contains a duplicate package id")
        package_by_id[package["id"]] = package
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        raise ReleaseError("Cargo metadata omitted resolve nodes")
    node_by_id: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise ReleaseError("Cargo metadata contains a malformed resolve node")
        if node["id"] in node_by_id:
            raise ReleaseError("Cargo metadata contains a duplicate resolve node")
        node_by_id[node["id"]] = node

    if root_package is None:
        roots = metadata.get("workspace_members")
        if not isinstance(roots, list) or not roots:
            raise ReleaseError("Cargo metadata omitted workspace members")
        root_ids = roots
    else:
        root_ids = [
            package_id
            for package_id, package in package_by_id.items()
            if package.get("name") == root_package and package.get("source") is None
        ]
        if len(root_ids) != 1:
            raise ReleaseError(f"Cargo root package is ambiguous: {root_package}")

    closure: dict[str, dict[str, Any]] = {}
    pending = list(root_ids)
    while pending:
        package_id = pending.pop()
        if package_id in closure:
            continue
        package = package_by_id.get(package_id)
        node = node_by_id.get(package_id)
        if package is None or node is None:
            raise ReleaseError("Cargo resolve graph references an unknown package")
        closure[package_id] = package
        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            raise ReleaseError("Cargo resolve node omitted dependencies")
        for dependency in dependencies:
            if not isinstance(dependency, dict) or not isinstance(
                dependency.get("pkg"), str
            ):
                raise ReleaseError("Cargo resolve node has a malformed dependency")
            dep_kinds = dependency.get("dep_kinds")
            if not isinstance(dep_kinds, list) or not dep_kinds:
                raise ReleaseError("Cargo dependency omitted dependency kinds")
            include = False
            for dep_kind in dep_kinds:
                if not isinstance(dep_kind, dict):
                    raise ReleaseError("Cargo dependency kind is malformed")
                kind = dep_kind.get("kind")
                if kind not in (None, "normal", "build", "dev"):
                    raise ReleaseError(
                        f"Cargo returned an unknown dependency kind: {kind}"
                    )
                include = include or kind in (None, "normal", "build")
            if include:
                pending.append(dependency["pkg"])
    return closure


def cargo_packages(
    manifest: Path,
    target: str,
    root_package: str | None = None,
    *,
    path_source: str | None = None,
) -> tuple[set[PackageKey], PackageSources]:
    extra = ("--no-default-features",) if root_package is not None else ()
    metadata = cargo_metadata(manifest, target, extra)
    closure = cargo_production_closure(metadata, root_package=root_package)
    result: set[PackageKey] = set()
    sources: dict[PackageKey, str] = {}
    synthetic: PackageSources = {}
    for package in closure.values():
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
        ):
            raise ReleaseError("Cargo metadata returned an incomplete dependency")
        key = ("cargo", name, version)
        source_identity = source if isinstance(source, str) else path_source
        if not source_identity:
            # Axis workspace roots describe the artifact itself and are not third-party
            # dependencies. Other path packages require an explicit pinned provenance.
            if root_package is None:
                continue
            raise ReleaseError(f"Cargo path dependency lacks pinned provenance: {name}")
        previous = sources.setdefault(key, source_identity)
        if previous != source_identity:
            raise ReleaseError(f"Cargo package identity is ambiguous: {name}@{version}")
        result.add(key)
        if source is None:
            synthetic[key] = (
                "Pinned Cargo path package from the MXC source checkout",
                path_source,
            )
    return result, synthetic


def npm_packages(lockfile: Path) -> set[PackageKey]:
    document = parse_json(lockfile.read_bytes(), str(lockfile))
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise ReleaseError("npm lockfile omitted packages")
    result: set[PackageKey] = set()
    reviewed_dev_packages_found: set[str] = set()
    for path, package in packages.items():
        if not isinstance(path, str) or not isinstance(package, dict):
            raise ReleaseError("npm lockfile contains malformed package data")
        if not path.startswith("node_modules/"):
            continue
        if package.get("dev") is True:
            if path not in SHIPPED_NPM_DEV_PACKAGES:
                continue
            reviewed_dev_packages_found.add(path)
        name = package.get("name") or path.removeprefix("node_modules/")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ReleaseError(f"npm package is missing identity: {path}")
        reviewed_name = SHIPPED_NPM_DEV_PACKAGES.get(path)
        if reviewed_name is not None and name != reviewed_name:
            raise ReleaseError(f"reviewed npm runtime package changed identity: {path}")
        key = ("npm", name, version)
        if key in result:
            raise ReleaseError(f"duplicate npm package identity: {name}@{version}")
        result.add(key)
    expected_dev_packages = set(SHIPPED_NPM_DEV_PACKAGES)
    if reviewed_dev_packages_found != expected_dev_packages:
        missing = sorted(expected_dev_packages - reviewed_dev_packages_found)
        raise ReleaseError(
            f"reviewed shipped npm runtime packages are missing: {missing}"
        )
    return result


def nuget_packages(lockfile: Path) -> set[PackageKey]:
    document = parse_json(lockfile.read_bytes(), str(lockfile))
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ReleaseError("NuGet lockfile omitted dependencies")
    result: set[PackageKey] = set()
    for target_packages in dependencies.values():
        if not isinstance(target_packages, dict):
            raise ReleaseError("NuGet lockfile contains a malformed target")
        for name, package in target_packages.items():
            if not isinstance(name, str) or not isinstance(package, dict):
                raise ReleaseError("NuGet lockfile contains malformed package data")
            version = package.get("resolved")
            if not isinstance(version, str):
                raise ReleaseError(f"NuGet package is missing a version: {name}")
            result.add(("nuget", name.lower(), version))
    return result


def runtime_packages(
    repository_root: Path, profile: str
) -> tuple[set[PackageKey], PackageSources]:
    metadata_path = repository_root / "packaging/runtime" / f"{profile}.json"
    if not metadata_path.exists():
        return set(), {}
    document = parse_json(metadata_path.read_bytes(), str(metadata_path))
    if document.get("schemaVersion") != 1 or document.get("profile") != profile:
        raise ReleaseError(f"runtime metadata identity is invalid for {profile}")
    requirements = document.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise ReleaseError(f"runtime metadata is empty for {profile}")
    result: set[PackageKey] = set()
    sources: PackageSources = {}
    for requirement in requirements:
        if not isinstance(requirement, dict):
            raise ReleaseError("runtime metadata contains a malformed requirement")
        name = requirement.get("name")
        version = requirement.get("version")
        purl = requirement.get("purl")
        source_info = requirement.get("sourceInfo")
        if not all(
            isinstance(value, str) and value
            for value in (name, version, purl, source_info)
        ):
            raise ReleaseError("runtime metadata contains an incomplete requirement")
        parsed = purl_key(
            {
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": purl,
                    }
                ]
            }
        )
        key = ("generic", name, version)
        if parsed != key or key in result:
            raise ReleaseError(f"runtime metadata has an invalid identity: {purl}")
        result.add(key)
        sources[key] = (source_info, None)
    return result, sources


def expected_packages(
    repository_root: Path,
    profile: str,
    mxc_dir: Path | None,
    mxc_ref: str | None,
) -> tuple[set[PackageKey], PackageSources]:
    targets = {
        "core-linux": "x86_64-unknown-linux-gnu",
        "core-macos": "aarch64-apple-darwin",
        "core-windows": "x86_64-pc-windows-msvc",
        "gui-linux": "x86_64-unknown-linux-gnu",
    }
    result: set[PackageKey] = set()
    synthetic: PackageSources = {}
    if profile.startswith("core-"):
        packages, sources = cargo_packages(
            repository_root / "Cargo.toml", targets[profile]
        )
        result |= packages
        synthetic.update(sources)
    if profile.startswith("gui-"):
        result |= npm_packages(repository_root / "gui/shared/package-lock.json")
    if profile == "gui-linux":
        packages, sources = cargo_packages(
            repository_root / "gui/linux/Cargo.toml", targets[profile]
        )
        result |= packages
        synthetic.update(sources)
    if profile == "gui-windows":
        result |= nuget_packages(
            repository_root / "gui/windows/AXIS/packages.lock.json"
        )
    if profile == "core-linux":
        if mxc_dir is None or mxc_ref is None:
            raise ReleaseError("Linux SBOM generation requires the pinned MXC checkout")
        verify_mxc_checkout(mxc_dir, mxc_ref)
        packages, sources = cargo_packages(
            mxc_dir / "src/Cargo.toml",
            "x86_64-unknown-linux-gnu",
            root_package="lxc",
            path_source=f"git+https://github.com/microsoft/mxc@{mxc_ref}",
        )
        result |= packages
        synthetic.update(sources)
    elif mxc_dir is not None or mxc_ref is not None:
        raise ReleaseError(
            f"non-Linux profile must not include MXC manifests: {profile}"
        )
    runtime, runtime_sources = runtime_packages(repository_root, profile)
    result |= runtime
    synthetic.update(runtime_sources)
    if not result:
        raise ReleaseError(f"empty dependency closure for {profile}")
    return result, synthetic


def purl_key(
    package: dict[str, Any], *, allow_unsupported_ecosystem: bool = False
) -> PackageKey | None:
    references = package.get("externalRefs", [])
    if not isinstance(references, list):
        raise ReleaseError("SPDX package externalRefs is malformed")
    purls = []
    for reference in references:
        if not isinstance(reference, dict):
            raise ReleaseError("SPDX external reference is malformed")
        if reference.get("referenceType") == "purl":
            locator = reference.get("referenceLocator")
            if not isinstance(locator, str):
                raise ReleaseError("SPDX purl is malformed")
            purls.append(locator)
    if not purls:
        return None
    if len(purls) != 1:
        raise ReleaseError("SPDX package has multiple purl identities")
    match = re.fullmatch(
        r"pkg:(cargo|generic|npm|nuget)/([^@?]+)@([^?]+)(?:\?.*)?", purls[0]
    )
    if match is None:
        if allow_unsupported_ecosystem and re.fullmatch(
            r"pkg:[a-z0-9.+-]+/[^@?]+@[^?]+(?:\?.*)?", purls[0]
        ):
            return None
        raise ReleaseError(f"unsupported SPDX package purl: {purls[0]}")
    ecosystem, encoded_name, version = match.groups()
    name = unquote(encoded_name)
    if ecosystem == "nuget":
        name = name.lower()
    return ecosystem, name, unquote(version)


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [canonicalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def finalize_sbom(
    raw_path: Path,
    output_path: Path,
    artifact: Path,
    source_version: str,
    expected: set[PackageKey],
    mxc_ref: str | None,
    synthetic_sources: PackageSources | None = None,
) -> None:
    if artifact.stat().st_size > MAX_ASSET_SIZE:
        raise ReleaseError(f"artifact exceeds size limit: {artifact.name}")
    artifact_hash = sha256_file(artifact)
    if raw_path.stat().st_size > MAX_SBOM_SIZE:
        raise ReleaseError("raw SPDX document exceeds size limit")
    document = parse_json(raw_path.read_bytes(), str(raw_path))
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise ReleaseError("Syft output is not an SPDX 2.3 document")
    packages = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(packages, list) or not isinstance(relationships, list):
        raise ReleaseError("SPDX document omitted packages or relationships")

    root_ids = {
        relation.get("relatedSpdxElement")
        for relation in relationships
        if isinstance(relation, dict)
        and relation.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and relation.get("relationshipType") == "DESCRIBES"
    }
    roots = [package for package in packages if package.get("SPDXID") in root_ids]
    if len(roots) != 1:
        raise ReleaseError("SPDX document must describe exactly one source package")

    selected: dict[PackageKey, dict[str, Any]] = {}
    selected_material: dict[PackageKey, str] = {}
    selected_sources: dict[PackageKey, set[str]] = {}
    old_to_new: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str):
            raise ReleaseError("SPDX package record is malformed")
        key = purl_key(package, allow_unsupported_ecosystem=True)
        if key is None:
            continue
        if key not in expected:
            continue
        material = dict(package)
        material.pop("SPDXID", None)
        source_info = material.pop("sourceInfo", None)
        encoded_material = json.dumps(material, sort_keys=True, separators=(",", ":"))
        previous_material = selected_material.setdefault(key, encoded_material)
        if previous_material != encoded_material:
            raise ReleaseError(f"SBOM contains conflicting duplicate dependency: {key}")
        if source_info is not None:
            if not isinstance(source_info, str):
                raise ReleaseError("SPDX package sourceInfo is malformed")
            selected_sources.setdefault(key, set()).add(source_info)
        current = selected.get(key)
        if current is None or json.dumps(package, sort_keys=True) < json.dumps(
            current, sort_keys=True
        ):
            selected[key] = package

    synthetic_sources = synthetic_sources or {}
    for key in expected - set(selected):
        ecosystem, name, version = key
        source = synthetic_sources.get(key)
        if source is None and (
            ecosystem != "npm" or name not in SHIPPED_NPM_DEV_PACKAGES.values()
        ):
            continue
        source_info, vcs_locator = source or (
            "Reviewed build-tool runtime code included in the GUI bundle",
            None,
        )
        external_references = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": (
                    f"pkg:{ecosystem}/{quote(name, safe='')}@{quote(version, safe='')}"
                ),
            }
        ]
        if vcs_locator is not None:
            external_references.append(
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "vcs",
                    "referenceLocator": vcs_locator,
                }
            )
        selected[key] = {
            "SPDXID": "SPDXRef-Reviewed-Shipped-Build-Runtime",
            "name": name,
            "versionInfo": version,
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "sourceInfo": source_info,
            "externalRefs": external_references,
        }
        selected_sources[key] = {selected[key]["sourceInfo"]}

    missing = sorted(expected - set(selected))
    if missing:
        preview = ", ".join(
            f"{kind}:{name}@{version}" for kind, name, version in missing[:10]
        )
        raise ReleaseError(f"SBOM is missing locked dependencies: {preview}")
    normalized_packages: list[dict[str, Any]] = []
    for key in sorted(selected):
        package = dict(selected[key])
        old_id = package["SPDXID"]
        identity = f"{key[0]}:{key[1]}@{key[2]}"
        new_id = f"SPDXRef-Package-{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
        old_to_new[old_id] = new_id
        package["SPDXID"] = new_id
        sources = selected_sources.get(key)
        if sources:
            package["sourceInfo"] = "; ".join(sorted(sources))
        synthetic_source = synthetic_sources.get(key)
        if synthetic_source is not None:
            source_info, vcs_locator = synthetic_source
            package["sourceInfo"] = source_info
            reference = None
            if vcs_locator is not None:
                reference = {
                    "referenceCategory": "OTHER",
                    "referenceType": "vcs",
                    "referenceLocator": vcs_locator,
                }
            external_references = package.setdefault("externalRefs", [])
            if reference is not None and reference not in external_references:
                external_references.append(reference)
        elif key[0] == "cargo" and key[1] == "lxc" and mxc_ref is not None:
            reference = {
                "referenceCategory": "OTHER",
                "referenceType": "vcs",
                "referenceLocator": f"git+https://github.com/microsoft/mxc@{mxc_ref}",
            }
            external_references = package.setdefault("externalRefs", [])
            if reference not in external_references:
                external_references.append(reference)
            package["sourceInfo"] = f"MXC commit {mxc_ref}"
        normalized_packages.append(package)

    root = dict(roots[0])
    old_root_id = root["SPDXID"]
    root_id = f"SPDXRef-Artifact-{artifact_hash}"
    old_to_new[old_root_id] = root_id
    root.update(
        {
            "SPDXID": root_id,
            "name": artifact.name,
            "versionInfo": source_version,
            "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_hash}],
            "filesAnalyzed": False,
            "primaryPackagePurpose": "FILE",
        }
    )
    normalized_packages.append(root)

    normalized_relationships: dict[tuple[str, str, str], dict[str, str]] = {}
    for relation in relationships:
        if not isinstance(relation, dict):
            raise ReleaseError("SPDX relationship is malformed")
        left = relation.get("spdxElementId")
        right = relation.get("relatedSpdxElement")
        kind = relation.get("relationshipType")
        if not all(isinstance(value, str) for value in (left, right, kind)):
            raise ReleaseError("SPDX relationship is incomplete")
        left = old_to_new.get(left, left if left == "SPDXRef-DOCUMENT" else "")
        right = old_to_new.get(right, right if right == "SPDXRef-DOCUMENT" else "")
        if not left or not right:
            continue
        normalized_relationships[(left, kind, right)] = {
            "spdxElementId": left,
            "relationshipType": kind,
            "relatedSpdxElement": right,
        }
    normalized_relationships[("SPDXRef-DOCUMENT", "DESCRIBES", root_id)] = {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }
    for package in normalized_packages:
        package_id = package["SPDXID"]
        if package_id != root_id:
            normalized_relationships[(root_id, "DEPENDS_ON", package_id)] = {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }

    document["name"] = artifact.name
    document["documentNamespace"] = (
        "https://github.com/ROCm/axis/sbom/"
        f"{quote(artifact.name, safe='')}/{artifact_hash}"
    )
    creation = document.get("creationInfo")
    if not isinstance(creation, dict):
        raise ReleaseError("SPDX document omitted creationInfo")
    creation["created"] = "1980-01-01T00:00:00Z"
    document["packages"] = normalized_packages
    document["relationships"] = list(normalized_relationships.values())
    normalized = canonicalize(document)
    encoded = (json.dumps(normalized, indent=2, ensure_ascii=True) + "\n").encode()
    if len(encoded) > MAX_SBOM_SIZE:
        raise ReleaseError("normalized SPDX document exceeds size limit")
    output_path.write_bytes(encoded)


def verify_final_sbom(document_path: Path, artifact: Path, source_version: str) -> None:
    validate_sha(source_version)
    if artifact.stat().st_size > MAX_ASSET_SIZE:
        raise ReleaseError(f"artifact exceeds size limit: {artifact.name}")
    if document_path.stat().st_size > MAX_SBOM_SIZE:
        raise ReleaseError("release SBOM exceeds size limit")
    artifact_hash = sha256_file(artifact)
    document = parse_json(document_path.read_bytes(), str(document_path))
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise ReleaseError("release SBOM is not an SPDX 2.3 document")
    expected_namespace = (
        "https://github.com/ROCm/axis/sbom/"
        f"{quote(artifact.name, safe='')}/{artifact_hash}"
    )
    if (
        document.get("name") != artifact.name
        or document.get("documentNamespace") != expected_namespace
    ):
        raise ReleaseError("release SBOM identity does not match its artifact")
    packages = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(packages, list) or not isinstance(relationships, list):
        raise ReleaseError("release SBOM omitted packages or relationships")
    root_id = f"SPDXRef-Artifact-{artifact_hash}"
    roots = [package for package in packages if package.get("SPDXID") == root_id]
    if len(roots) != 1:
        raise ReleaseError("release SBOM omitted its artifact package")
    root = roots[0]
    if (
        root.get("name") != artifact.name
        or root.get("versionInfo") != source_version
        or root.get("checksums")
        != [{"algorithm": "SHA256", "checksumValue": artifact_hash}]
    ):
        raise ReleaseError("release SBOM artifact package is inconsistent")
    relation_keys = {
        (
            relation.get("spdxElementId"),
            relation.get("relationshipType"),
            relation.get("relatedSpdxElement"),
        )
        for relation in relationships
        if isinstance(relation, dict)
    }
    if ("SPDXRef-DOCUMENT", "DESCRIBES", root_id) not in relation_keys:
        raise ReleaseError("release SBOM does not describe its artifact package")
    dependency_keys: set[PackageKey] = set()
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("SPDXID"), str):
            raise ReleaseError("release SBOM contains a malformed package")
        if package["SPDXID"] == root_id:
            continue
        key = purl_key(package)
        if key is None or key in dependency_keys:
            raise ReleaseError(
                "release SBOM contains an unidentified or duplicate dependency"
            )
        dependency_keys.add(key)
        if (root_id, "DEPENDS_ON", package["SPDXID"]) not in relation_keys:
            raise ReleaseError(
                f"release SBOM dependency is not related to its artifact: {key}"
            )
    if not dependency_keys:
        raise ReleaseError("release SBOM contains no dependencies")


def run_syft(syft: str, input_dir: Path, output: Path, name: str, version: str) -> None:
    with output.open("wb") as sink:
        try:
            run_bounded(
                [
                    syft,
                    "scan",
                    f"dir:{input_dir}",
                    "--source-name",
                    name,
                    "--source-version",
                    version,
                    "--output",
                    "spdx-json",
                ],
                timeout=command_timeout(),
                stdout_limit=MAX_SBOM_SIZE,
                stderr_limit=MAX_COMMAND_OUTPUT,
                stdout_sink=sink,
                retain_stdout=False,
            )
        except BoundedProcessError as error:
            raise ReleaseError(str(error)) from error


def local_assets(asset_dir: Path) -> list[Path]:
    assets = sorted(path for path in asset_dir.iterdir() if path.is_file())
    if not assets or len(assets) > MAX_ASSET_COUNT:
        raise ReleaseError("release asset count is outside the allowed range")
    total = 0
    names = set()
    for asset in assets:
        if (
            asset.is_symlink()
            or not re.fullmatch(r"[A-Za-z0-9._+-]+", asset.name)
            or asset.name in names
        ):
            raise ReleaseError(f"unsafe or duplicate release asset name: {asset.name}")
        names.add(asset.name)
        size = asset.stat().st_size
        if size > MAX_ASSET_SIZE:
            raise ReleaseError(f"release asset exceeds size limit: {asset.name}")
        total += size
        if total > MAX_ASSET_TOTAL_SIZE:
            raise ReleaseError("release assets exceed aggregate size limit")
    return assets


def gh_release_state(repository: str, tag: str) -> dict[str, Any] | None:
    endpoint = f"repos/{repository}/releases/tags/{quote(tag, safe='')}"
    try:
        return gh_api(repository, endpoint)
    except ReleaseError as error:
        if "HTTP 404" not in str(error) and "release not found" not in str(error).lower():
            raise
    # GitHub's tag endpoint only returns published releases; drafts are only listed.
    return draft_release_state(repository, tag)


def draft_release_state(repository: str, tag: str) -> dict[str, Any] | None:
    endpoint = f"repos/{repository}/releases"
    releases = parse_json_value(
        run_command(["gh", "api", "--method", "GET", endpoint]),
        f"GitHub API {endpoint}",
    )
    if not isinstance(releases, list) or not all(
        isinstance(release, dict) for release in releases
    ):
        raise ReleaseError("GitHub API returned a malformed release list")
    drafts = [
        release
        for release in releases
        if release.get("draft") is True and release.get("tag_name") == tag
    ]
    if len(drafts) > 1:
        raise ReleaseError(f"multiple draft releases exist for tag {tag}")
    return drafts[0] if drafts else None


def validate_remote_manifest(
    state: dict[str, Any], expected_names: set[str]
) -> dict[str, tuple[int, int]]:
    raw_assets = state.get("assets")
    if not isinstance(raw_assets, list) or len(raw_assets) > MAX_ASSET_COUNT:
        raise ReleaseError("remote release asset count is outside the allowed range")
    result: dict[str, tuple[int, int]] = {}
    total = 0
    for asset in raw_assets:
        if not isinstance(asset, dict):
            raise ReleaseError("remote release returned malformed asset metadata")
        name, size, asset_id = asset.get("name"), asset.get("size"), asset.get("id")
        if (
            not isinstance(name, str)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(asset_id, int)
            or asset_id <= 0
        ):
            raise ReleaseError("remote release returned invalid asset metadata")
        if name in result:
            raise ReleaseError(f"remote release contains duplicate asset: {name}")
        if size > MAX_ASSET_SIZE:
            raise ReleaseError(f"remote release asset exceeds size limit: {name}")
        total += size
        if total > MAX_ASSET_TOTAL_SIZE:
            raise ReleaseError("remote release assets exceed aggregate size limit")
        result[name] = (size, asset_id)
    if set(result) != expected_names:
        raise ReleaseError("remote release asset names differ from the expected set")
    return result


def download_and_compare(
    repository: str, state: dict[str, Any], assets: list[Path]
) -> None:
    manifest = validate_remote_manifest(state, {asset.name for asset in assets})
    with tempfile.TemporaryDirectory(prefix="axis-release-download-") as temporary:
        root = Path(temporary)
        for asset in assets:
            expected_size, asset_id = manifest[asset.name]
            destination = root / asset.name
            with destination.open("wb") as sink:
                try:
                    run_bounded(
                        [
                            "gh",
                            "api",
                            "--method",
                            "GET",
                            f"repos/{repository}/releases/assets/{asset_id}",
                            "-H",
                            "Accept: application/octet-stream",
                        ],
                        timeout=command_timeout(),
                        stdout_limit=min(MAX_ASSET_SIZE, expected_size) + 1,
                        stderr_limit=MAX_COMMAND_OUTPUT,
                        stdout_sink=sink,
                        retain_stdout=False,
                    )
                except BoundedProcessError as error:
                    raise ReleaseError(str(error)) from error
            if destination.stat().st_size != expected_size:
                raise ReleaseError(
                    f"remote asset size changed during download: {asset.name}"
                )
            if sha256_file(destination) != sha256_file(asset):
                raise ReleaseError(f"remote asset differs: {asset.name}")


def stable_notes(tag: str, sha: str) -> str:
    return f"AXIS {tag}\n\nRelease commit: `{sha}`.\n"


def publish_release(
    repository_root: Path,
    release_type: str,
    tag: str,
    asset_dir: Path,
    title: str,
    notes_file: Path | None,
) -> None:
    sha = validate_sha(os.environ.get("GITHUB_SHA", ""))
    repository = validate_repository(os.environ.get("GITHUB_REPOSITORY", ""))
    if release_type == "stable":
        verify_stable_identity(repository_root, tag, sha)
        if title != tag or notes_file is not None:
            raise ReleaseError(
                "stable release title and notes are derived from its tag"
            )
        notes = stable_notes(tag, sha)
    elif release_type == "nightly":
        if tag != f"nightly-{sha}" or title != f"Nightly {sha}" or notes_file is None:
            raise ReleaseError("nightly release identity does not match its commit")
        notes = notes_file.read_text(encoding="utf-8")
        if not notes or len(notes.encode()) > 64 * 1024:
            raise ReleaseError("nightly release notes are empty or too large")
    else:
        raise ReleaseError(f"unknown release type: {release_type}")

    assets = local_assets(asset_dir)
    expected_prerelease = release_type == "nightly"
    remote_sha = remote_tag_commit(
        repository,
        tag,
        allow_missing=release_type == "nightly",
        require_annotated=release_type == "stable",
    )
    if remote_sha is None:
        run_command(
            [
                "gh",
                "api",
                "--method",
                "POST",
                f"repos/{repository}/git/refs",
                "-f",
                f"ref=refs/tags/{tag}",
                "-f",
                f"sha={sha}",
            ]
        )
        remote_sha = remote_tag_commit(repository, tag)
    if remote_sha != sha:
        raise ReleaseError(f"remote tag {tag} resolves to {remote_sha}, not {sha}")
    state = gh_release_state(repository, tag)
    if state is not None:
        if remote_sha is None:
            raise ReleaseError("existing release has no corresponding remote tag")
        if not isinstance(state.get("draft"), bool):
            raise ReleaseError("existing release has malformed draft state")
        if state.get("target_commitish") != sha:
            raise ReleaseError("existing release targets a different commit")
        if state.get("prerelease") is not expected_prerelease:
            raise ReleaseError("existing release has the wrong prerelease state")
        if state.get("draft") is False:
            if state.get("immutable") is not True:
                raise ReleaseError("published release is not immutable")
            if state.get("name") != title or state.get("body") != notes:
                raise ReleaseError("published release metadata differs from expected")
            download_and_compare(repository, state, assets)
            print(f"release is already published with exact metadata and assets: {tag}")
            return
        raw_assets = state.get("assets")
        if not isinstance(raw_assets, list) or len(raw_assets) > MAX_ASSET_COUNT:
            raise ReleaseError("draft release asset count is outside the allowed range")
        for asset in raw_assets:
            if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
                raise ReleaseError("draft release returned malformed asset metadata")
            run_command(
                [
                    "gh",
                    "release",
                    "delete-asset",
                    tag,
                    asset["name"],
                    "--yes",
                    "--repo",
                    repository,
                ]
            )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as temporary:
        temporary.write(notes)
        generated_notes = Path(temporary.name)
    try:
        if state is None:
            command = [
                "gh",
                "release",
                "create",
                tag,
                "--draft",
                "--target",
                sha,
                "--title",
                title,
                "--notes-file",
                str(generated_notes),
                "--repo",
                repository,
            ]
            command.append("--verify-tag")
            if release_type == "nightly":
                command.append("--prerelease")
            run_command(command)
        else:
            command = [
                "gh",
                "release",
                "edit",
                tag,
                "--draft",
                "--target",
                sha,
                "--title",
                title,
                "--notes-file",
                str(generated_notes),
                "--repo",
                repository,
            ]
            if release_type == "nightly":
                command.append("--prerelease")
            run_command(command)
        run_command(
            [
                "gh",
                "release",
                "upload",
                tag,
                *map(str, assets),
                "--repo",
                repository,
            ]
        )
        state = gh_release_state(repository, tag)
        if state is None:
            raise ReleaseError("release disappeared after upload")
        if (
            state.get("draft") is not True
            or state.get("target_commitish") != sha
            or state.get("name") != title
            or state.get("body") != notes
        ):
            raise ReleaseError("draft release metadata changed unexpectedly")
        if remote_tag_commit(repository, tag) != sha:
            raise ReleaseError("remote release tag changed after upload")
        download_and_compare(repository, state, assets)
        run_command(
            [
                "gh",
                "release",
                "edit",
                tag,
                "--draft=false",
                "--repo",
                repository,
            ]
        )
        state = gh_release_state(repository, tag)
        if state is None or state.get("draft") is not False:
            raise ReleaseError("release did not remain published")
        if state.get("immutable") is not True:
            raise ReleaseError("published release is not immutable")
        if (
            state.get("target_commitish") != sha
            or state.get("prerelease") is not expected_prerelease
            or state.get("name") != title
            or state.get("body") != notes
        ):
            raise ReleaseError("published release metadata changed unexpectedly")
        if remote_tag_commit(repository, tag) != sha:
            raise ReleaseError("remote release tag changed during publication")
        download_and_compare(repository, state, assets)
    finally:
        generated_notes.unlink(missing_ok=True)
    print(f"published release with verified metadata and assets: {tag}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("verify-identity")
    identity.add_argument("--repository-root", type=Path, required=True)
    identity.add_argument("--tag", required=True)
    identity.add_argument("--sha", required=True)

    source = subparsers.add_parser("verify-default-source")
    source.add_argument("--repository-root", type=Path, required=True)
    source.add_argument("--repository", required=True)
    source.add_argument("--ref", required=True)
    source.add_argument("--sha", required=True)

    workflows = subparsers.add_parser("verify-workflows")
    workflows.add_argument("--repository", required=True)
    workflows.add_argument("--sha", required=True)
    workflows.add_argument("--workflow", action="append", required=True)
    workflows.add_argument("--timeout", type=float, default=DEFAULT_GATE_TIMEOUT)
    workflows.add_argument(
        "--poll-interval", type=float, default=DEFAULT_GATE_POLL_INTERVAL
    )

    stage_mxc = subparsers.add_parser("stage-mxc-manifests")
    stage_mxc.add_argument("--mxc-dir", type=Path, required=True)
    stage_mxc.add_argument("--mxc-ref", required=True)
    stage_mxc.add_argument("--output", type=Path, required=True)

    syft = subparsers.add_parser("run-syft")
    syft.add_argument("--syft", required=True)
    syft.add_argument("--input", type=Path, required=True)
    syft.add_argument("--output", type=Path, required=True)
    syft.add_argument("--name", required=True)
    syft.add_argument("--version", required=True)

    sbom = subparsers.add_parser("finalize-sbom")
    sbom.add_argument("--repository-root", type=Path, required=True)
    sbom.add_argument("--raw", type=Path, required=True)
    sbom.add_argument("--output", type=Path, required=True)
    sbom.add_argument("--artifact", type=Path, required=True)
    sbom.add_argument("--source-version", required=True)
    sbom.add_argument(
        "--profile",
        choices=(
            "core-linux",
            "core-macos",
            "core-windows",
            "gui-linux",
            "gui-macos",
            "gui-windows",
        ),
        required=True,
    )
    sbom.add_argument("--mxc-dir", type=Path)
    sbom.add_argument("--mxc-ref")

    verify_sbom = subparsers.add_parser("verify-sbom")
    verify_sbom.add_argument("--document", type=Path, required=True)
    verify_sbom.add_argument("--artifact", type=Path, required=True)
    verify_sbom.add_argument("--source-version", required=True)

    publish = subparsers.add_parser("publish")
    publish.add_argument("--repository-root", type=Path, required=True)
    publish.add_argument("--release-type", choices=("stable", "nightly"), required=True)
    publish.add_argument("--tag", required=True)
    publish.add_argument("--asset-directory", type=Path, required=True)
    publish.add_argument("--title", required=True)
    publish.add_argument("--notes-file", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "verify-identity":
            verify_stable_identity(args.repository_root.resolve(), args.tag, args.sha)
        elif args.command == "verify-default-source":
            branch = verify_default_source(
                args.repository_root.resolve(), args.repository, args.ref, args.sha
            )
            print(branch)
        elif args.command == "verify-workflows":
            verify_required_workflows(
                args.repository,
                args.sha,
                args.workflow,
                args.timeout,
                args.poll_interval,
            )
        elif args.command == "stage-mxc-manifests":
            stage_mxc_manifests(
                args.mxc_dir.resolve(), args.mxc_ref, args.output.resolve()
            )
        elif args.command == "run-syft":
            run_syft(
                args.syft, args.input.resolve(), args.output, args.name, args.version
            )
        elif args.command == "finalize-sbom":
            expected, synthetic_sources = expected_packages(
                args.repository_root.resolve(),
                args.profile,
                args.mxc_dir.resolve() if args.mxc_dir else None,
                args.mxc_ref,
            )
            finalize_sbom(
                args.raw,
                args.output,
                args.artifact,
                args.source_version,
                expected,
                args.mxc_ref,
                synthetic_sources,
            )
        elif args.command == "verify-sbom":
            verify_final_sbom(args.document, args.artifact, args.source_version)
        elif args.command == "publish":
            publish_release(
                args.repository_root.resolve(),
                args.release_type,
                args.tag,
                args.asset_directory.resolve(),
                args.title,
                args.notes_file,
            )
        else:
            raise AssertionError(f"unhandled command: {args.command}")
    except (OSError, UnicodeError, ReleaseError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
