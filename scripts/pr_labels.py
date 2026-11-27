#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Keep the pr/ and area/ labels on pull requests current.

Every label is derived from what GitHub already records: the title, the changed
files, mergeability, the required checks and the review decision. The script
reads pull requests through the API and never checks out or runs their code.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import http.client
import json
import os
import re
import sys
import time
from typing import Any
from urllib.parse import quote


API_HOST = "api.github.com"
API_TIMEOUT = 30.0
API_ATTEMPTS = 3
MAX_RESPONSE_SIZE = 16 * 1024 * 1024
MAX_PAGES = 30
REPOSITORY_RE = re.compile(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
MANAGED_PREFIXES = ("pr/", "area/")
PASSING_CONCLUSIONS = {"success", "neutral", "skipped"}


class GitHubError(RuntimeError):
    """A GitHub API request failed."""


@dataclass(frozen=True)
class Label:
    name: str
    color: str
    description: str


NEEDS_REBASE = Label("pr/needs-rebase", "b60205", "Conflicts with the base branch")
CI_FAILING = Label("pr/ci-failing", "d93f0b", "A required check failed")
NEEDS_AUTHOR = Label(
    "pr/needs-author",
    "e99695",
    "Changes requested or review threads unresolved; waiting on the author",
)
NEEDS_REVIEW = Label("pr/needs-review", "fbca04", "Waiting on a code owner review")
MERGE_READY = Label(
    "pr/merge-ready",
    "0e8a16",
    "Approved, required checks pass, no conflicts or unresolved threads",
)
# At most one of these, in order of precedence.
STATE_LABELS = (NEEDS_REBASE, CI_FAILING, NEEDS_AUTHOR, NEEDS_REVIEW, MERGE_READY)

POLICY = Label(
    "area/policy",
    "c2e0c6",
    "Policy model, OPA engine, safety checks and bundled policies",
)
SANDBOX = Label(
    "area/sandbox", "c2e0c6", "Process isolation backends and the pseudoterminal"
)
NETWORK = Label(
    "area/network", "c2e0c6", "Proxy, network namespaces and inference routing"
)
GPU = Label("area/gpu", "c2e0c6", "GPU isolation")
CLI_DAEMON = Label("area/cli-daemon", "c2e0c6", "CLI, daemon and gateway")
GUI = Label("area/gui", "c2e0c6", "Desktop GUI")
RELEASE = Label("area/release", "c2e0c6", "CI, release, packaging and installers")
AREA_LABELS = (POLICY, SANDBOX, NETWORK, GPU, CLI_DAEMON, GUI, RELEASE)
ALL_LABELS = (*STATE_LABELS, *AREA_LABELS)

TITLE_RE = re.compile(r"(?P<type>[A-Za-z]+)(?:\((?P<scope>[^()]*)\))?!?:")
# Title scopes that name an area, as in "fix(sandbox): ...".
SCOPE_AREAS = {
    scope: label
    for label, scopes in (
        (POLICY, ("core", "opa", "policy", "safety")),
        (SANDBOX, ("landlock", "mxc", "pty", "sandbox", "seccomp", "vxn")),
        (NETWORK, ("netns", "network", "proxy", "router")),
        (GPU, ("gpu",)),
        (CLI_DAEMON, ("cli", "daemon", "gateway")),
        (GUI, ("gui",)),
        (RELEASE, ("ci", "github", "install", "lint", "packaging", "release")),
    )
    for scope in scopes
}
# Title types that name an area when the scope does not.
TYPE_AREAS = {"ci": RELEASE}


@dataclass(frozen=True)
class AreaRule:
    label: Label
    prefixes: tuple[str, ...] = ()
    tokens: frozenset[str] = frozenset()

    def matches(self, path: str) -> bool:
        return path.startswith(self.prefixes) or not self.tokens.isdisjoint(
            path_tokens(path)
        )


CORE = "crates/axis-core/src/"
# Each changed file counts toward the area of the first rule that matches it,
# so single files come before the crates that contain them.
AREA_RULES = (
    AreaRule(
        NETWORK,
        prefixes=(
            f"{CORE}connect_attribution.rs",
            "crates/axis-sandbox/src/linux/bypass_audit.rs",
            "crates/axis-sandbox/src/linux/connect_attribution.rs",
        ),
    ),
    AreaRule(CLI_DAEMON, prefixes=(f"{CORE}daemon_auth.rs",)),
    AreaRule(
        SANDBOX,
        prefixes=(
            f"{CORE}backend_",
            f"{CORE}capability",
            f"{CORE}container_backend.rs",
            f"{CORE}mxc_config.rs",
            f"{CORE}process_backend.rs",
            f"{CORE}sandbox_env.rs",
            f"{CORE}vm_backend.rs",
        ),
    ),
    AreaRule(GPU, tokens=frozenset({"gpu", "hip"})),
    AreaRule(
        NETWORK,
        prefixes=("crates/axis-proxy/", "crates/axis-router/"),
        tokens=frozenset({"netns", "proxy"}),
    ),
    AreaRule(
        POLICY,
        prefixes=("crates/axis-core/", "crates/axis-safety/", "data/", "policies/"),
    ),
    AreaRule(
        SANDBOX,
        prefixes=("crates/axis-pty/", "crates/axis-sandbox/", "third_party/mxc/"),
    ),
    AreaRule(
        CLI_DAEMON,
        prefixes=("crates/axis-cli/", "crates/axis-daemon/", "crates/axis-gateway/"),
    ),
    AreaRule(GUI, prefixes=("gui/",)),
    AreaRule(
        RELEASE,
        prefixes=(
            ".github/",
            "deny.toml",
            "dist/",
            "install.ps1",
            "install.sh",
            "packaging/",
            "rust-toolchain.toml",
            "scripts/",
        ),
    ),
)

PULL_REQUEST_FRAGMENT = """
fragment PullRequestFields on PullRequest {
  number
  title
  state
  isDraft
  baseRefName
  headRefOid
  mergeable
  reviewDecision
  labels(first: 100) { nodes { name } }
  files(first: 100) {
    pageInfo { hasNextPage }
    nodes { path additions deletions }
  }
  reviewThreads(first: 100) { pageInfo { hasNextPage } nodes { isResolved } }
}
"""
OPEN_PULL_REQUESTS_QUERY = (
    """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 25, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes { ...PullRequestFields }
    }
  }
}
"""
    + PULL_REQUEST_FRAGMENT
)
PULL_REQUEST_QUERY = (
    """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) { ...PullRequestFields }
  }
}
"""
    + PULL_REQUEST_FRAGMENT
)
REVIEW_THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { isResolved }
      }
    }
  }
}
"""


@dataclass(frozen=True)
class PullRequest:
    number: int
    title: str
    draft: bool
    base: str
    head_sha: str
    mergeable: str
    review_decision: str | None
    unresolved_threads: bool
    labels: frozenset[str]
    # (path, changed lines) for each changed file.
    files: tuple[tuple[str, int], ...]


def path_tokens(path: str) -> set[str]:
    return set(re.split(r"[/._-]+", path.lower()))


def file_area(path: str) -> str | None:
    rule = next((rule for rule in AREA_RULES if rule.matches(path)), None)
    return None if rule is None else rule.label.name


def area_label(title: str, files: tuple[tuple[str, int], ...]) -> str | None:
    """Return the one area label of a pull request, or None.

    A title scope that names an area decides, then a title type that does.
    Otherwise the area that has more than half of the changed lines decides.
    """
    if match := TITLE_RE.match(title):
        scope = (match["scope"] or "").strip().lower()
        label = SCOPE_AREAS.get(scope) or TYPE_AREAS.get(match["type"].lower())
        if label is not None:
            return label.name
    lines: Counter[str] = Counter()
    for path, changed in files:
        if area := file_area(path):
            lines[area] += changed
    if lines:
        area, count = lines.most_common(1)[0]
        if 2 * count > sum(changed for _, changed in files):
            return area
    return None


def required_checks_state(
    check_runs: list[dict[str, Any]], required: dict[str, int | None]
) -> str:
    """Return "pass", "fail" or "pending" for the required checks of a commit.

    `required` maps each required check name to the ID of the app that must
    report it, or None when the ruleset accepts any app.
    """
    if not required:
        return "pending"
    latest: dict[str, dict[str, Any]] = {}
    for run in check_runs:
        name = run.get("name")
        if name not in required:
            continue
        app = required[name]
        if app is not None and (run.get("app") or {}).get("id") != app:
            continue
        if name not in latest or run["id"] > latest[name]["id"]:
            latest[name] = run
    if any(
        run.get("status") == "completed"
        and run.get("conclusion") not in PASSING_CONCLUSIONS
        for run in latest.values()
    ):
        return "fail"
    if set(latest) != set(required) or any(
        run.get("status") != "completed" for run in latest.values()
    ):
        return "pending"
    return "pass"


def state_label(pull_request: PullRequest, checks: str) -> str | None:
    if pull_request.draft:
        return None
    if pull_request.mergeable == "CONFLICTING":
        return NEEDS_REBASE.name
    if checks == "fail":
        return CI_FAILING.name
    if pull_request.review_decision == "CHANGES_REQUESTED":
        return NEEDS_AUTHOR.name
    if pull_request.review_decision != "APPROVED":
        return NEEDS_REVIEW.name
    if pull_request.unresolved_threads:
        return NEEDS_AUTHOR.name
    if checks == "pass":
        return MERGE_READY.name
    return None


def desired_labels(pull_request: PullRequest, checks: str) -> set[str]:
    labels: set[str] = set()
    if area := area_label(pull_request.title, pull_request.files):
        labels.add(area)
    state = state_label(pull_request, checks)
    if pull_request.mergeable == "UNKNOWN" and state is not None:
        # GitHub has not computed mergeability yet (usually right after a
        # push): a conflict may or may not remain, and the pull request
        # cannot be called ready until it is known.
        if NEEDS_REBASE.name in pull_request.labels:
            state = NEEDS_REBASE.name
        elif state == MERGE_READY.name:
            state = None
    if state is not None:
        labels.add(state)
    return labels


def label_changes(
    current: frozenset[str], desired: set[str]
) -> tuple[list[str], list[str]]:
    managed = {name for name in current if name.startswith(MANAGED_PREFIXES)}
    return sorted(desired - current), sorted(managed - desired)


class GitHub:
    def __init__(self, token: str) -> None:
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "axis-pr-labels",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        allow_missing: bool = False,
    ) -> Any:
        payload = None if body is None else json.dumps(body).encode()
        headers = dict(self.headers)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        failure = f"{method} {path}: no attempt made"
        for attempt in range(1, API_ATTEMPTS + 1):
            connection = http.client.HTTPSConnection(API_HOST, timeout=API_TIMEOUT)
            try:
                connection.request(method, path, body=payload, headers=headers)
                response = connection.getresponse()
                status = response.status
                data = response.read(MAX_RESPONSE_SIZE + 1)
            except (OSError, http.client.HTTPException) as error:
                status = None
                failure = f"{method} {path}: {error}"
            finally:
                connection.close()
            if status is not None:
                if len(data) > MAX_RESPONSE_SIZE:
                    raise GitHubError(f"{method} {path}: response is too large")
                if status == 404 and allow_missing:
                    return None
                if status < 400:
                    try:
                        return json.loads(data) if data else None
                    except ValueError as error:
                        raise GitHubError(f"{method} {path}: invalid JSON") from error
                detail = data[:300].decode(errors="replace")
                failure = f"{method} {path}: HTTP {status}: {detail}"
                if status < 500 and status != 429:
                    raise GitHubError(failure)
            if attempt < API_ATTEMPTS:
                time.sleep(2**attempt)
        raise GitHubError(failure)

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        result = self.request(
            "POST", "/graphql", {"query": query, "variables": variables}
        )
        if (
            not isinstance(result, dict)
            or result.get("errors")
            or not isinstance(result.get("data"), dict)
        ):
            errors = result.get("errors") if isinstance(result, dict) else result
            raise GitHubError(f"GraphQL query failed: {errors}")
        return result["data"]

    def paginate(self, path: str, key: str | None = None) -> list[Any]:
        items: list[Any] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, MAX_PAGES + 1):
            result = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            batch = result[key] if key is not None else result
            if not isinstance(batch, list):
                raise GitHubError(f"GET {path}: expected a list")
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise GitHubError(f"GET {path}: more than {MAX_PAGES} pages")


class Labeler:
    def __init__(self, github: GitHub, repository: str, *, dry_run: bool) -> None:
        match = REPOSITORY_RE.fullmatch(repository)
        if match is None:
            raise GitHubError(f"invalid repository: {repository!r}")
        self.github = github
        self.owner, self.name = match.groups()
        self.repository = f"/repos/{self.owner}/{self.name}"
        self.dry_run = dry_run
        self.required: dict[str, dict[str, int | None]] = {}

    def variables(self, **extra: Any) -> dict[str, Any]:
        return {"owner": self.owner, "name": self.name, **extra}

    def ensure_labels(self) -> None:
        existing = {
            label["name"].lower()
            for label in self.github.paginate(f"{self.repository}/labels")
        }
        for label in ALL_LABELS:
            if label.name not in existing:
                print(f"create label {label.name}")
                if not self.dry_run:
                    self.github.request(
                        "POST",
                        f"{self.repository}/labels",
                        {
                            "name": label.name,
                            "color": label.color,
                            "description": label.description,
                        },
                    )

    def required_checks(self, branch: str) -> dict[str, int | None]:
        if branch not in self.required:
            rules = self.github.paginate(
                f"{self.repository}/rules/branches/{quote(branch, safe='')}"
            )
            self.required[branch] = {
                check["context"]: check.get("integration_id")
                for rule in rules
                if rule.get("type") == "required_status_checks"
                for check in rule.get("parameters", {}).get(
                    "required_status_checks", []
                )
            }
        return self.required[branch]

    def checks_state(self, pull_request: PullRequest) -> str:
        required = self.required_checks(pull_request.base)
        if not required:
            return "pending"
        commit = f"{self.repository}/commits/{pull_request.head_sha}"
        check_runs = self.github.paginate(
            f"{commit}/check-runs?filter=latest", "check_runs"
        )
        return required_checks_state(check_runs, required)

    def has_unresolved_threads(self, node: dict[str, Any]) -> bool:
        threads = node["reviewThreads"]
        if any(not thread["isResolved"] for thread in threads["nodes"]):
            return True
        cursor = None
        while threads["pageInfo"]["hasNextPage"]:
            data = self.github.graphql(
                REVIEW_THREADS_QUERY,
                self.variables(number=node["number"], cursor=cursor),
            )
            threads = data["repository"]["pullRequest"]["reviewThreads"]
            if any(not thread["isResolved"] for thread in threads["nodes"]):
                return True
            cursor = threads["pageInfo"]["endCursor"]
        return False

    def changed_files(self, node: dict[str, Any]) -> tuple[tuple[str, int], ...]:
        files = node["files"]
        if files["pageInfo"]["hasNextPage"]:
            changes = [
                (file["filename"], file["additions"] + file["deletions"])
                for file in self.github.paginate(
                    f"{self.repository}/pulls/{node['number']}/files"
                )
            ]
        else:
            changes = [
                (file["path"], file["additions"] + file["deletions"])
                for file in files["nodes"]
            ]
        # Binary files and renames report no changed lines; count each as one.
        return tuple((path, max(lines, 1)) for path, lines in changes)

    def pull_request(self, node: dict[str, Any]) -> PullRequest:
        return PullRequest(
            number=node["number"],
            title=node["title"],
            draft=node["isDraft"],
            base=node["baseRefName"],
            head_sha=node["headRefOid"],
            mergeable=node["mergeable"],
            review_decision=node["reviewDecision"],
            unresolved_threads=self.has_unresolved_threads(node),
            labels=frozenset(label["name"] for label in node["labels"]["nodes"]),
            files=self.changed_files(node),
        )

    def apply(self, number: int, add: list[str], remove: list[str]) -> None:
        if not add and not remove:
            return
        print(
            f"#{number}: "
            + " ".join([f"+{n}" for n in add] + [f"-{n}" for n in remove])
        )
        if self.dry_run:
            return
        if add:
            self.github.request(
                "POST", f"{self.repository}/issues/{number}/labels", {"labels": add}
            )
        for name in remove:
            self.github.request(
                "DELETE",
                f"{self.repository}/issues/{number}/labels/{quote(name, safe='')}",
                allow_missing=True,
            )

    def sync(self, node: dict[str, Any]) -> None:
        labels = frozenset(label["name"] for label in node["labels"]["nodes"])
        if node["state"] != "OPEN":
            self.apply(
                node["number"], [], sorted(n for n in labels if n.startswith("pr/"))
            )
            return
        pull_request = self.pull_request(node)
        desired = desired_labels(pull_request, self.checks_state(pull_request))
        self.apply(pull_request.number, *label_changes(pull_request.labels, desired))

    def sync_one(self, number: int) -> bool:
        data = self.github.graphql(PULL_REQUEST_QUERY, self.variables(number=number))
        self.sync(data["repository"]["pullRequest"])
        return True

    def sync_all(self) -> bool:
        ok = True
        cursor = None
        while True:
            data = self.github.graphql(
                OPEN_PULL_REQUESTS_QUERY, self.variables(cursor=cursor)
            )
            connection = data["repository"]["pullRequests"]
            for node in connection["nodes"]:
                try:
                    self.sync(node)
                except GitHubError as error:
                    print(f"#{node['number']}: {error}", file=sys.stderr)
                    ok = False
            if not connection["pageInfo"]["hasNextPage"]:
                break
            cursor = connection["pageInfo"]["endCursor"]
        self.clear_closed()
        return ok

    def clear_closed(self) -> None:
        stale: dict[int, set[str]] = {}
        for label in STATE_LABELS:
            for issue in self.github.paginate(
                f"{self.repository}/issues?state=closed"
                f"&labels={quote(label.name, safe='')}"
            ):
                if "pull_request" not in issue:
                    continue
                names = {n["name"] for n in issue["labels"]}
                stale[issue["number"]] = {n for n in names if n.startswith("pr/")}
        for number, names in sorted(stale.items()):
            self.apply(number, [], sorted(names))


def pull_request_number(value: str) -> int | None:
    if value == "":
        return None
    if not value.isdigit() or int(value) <= 0:
        raise argparse.ArgumentTypeError(f"invalid pull request number: {value!r}")
    return int(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="OWNER/NAME")
    parser.add_argument(
        "--pull-request",
        type=pull_request_number,
        default=None,
        help="sync only this pull request; empty or omitted syncs all of them",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print the changes without making them"
    )
    arguments = parser.parse_args(argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.exit(2, "error: GH_TOKEN or GITHUB_TOKEN must be set\n")
    try:
        labeler = Labeler(
            GitHub(token), arguments.repository, dry_run=arguments.dry_run
        )
        labeler.ensure_labels()
        if arguments.pull_request is None:
            ok = labeler.sync_all()
        else:
            ok = labeler.sync_one(arguments.pull_request)
    except GitHubError as error:
        parser.exit(1, f"error: {error}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
