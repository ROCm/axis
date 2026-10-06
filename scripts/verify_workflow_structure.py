#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Validate security-critical GitHub Actions release workflow structure."""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shlex
from typing import Any

import yaml


ATTEST_ACTION = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PATHS_FILTER_ACTION = "dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d"
NODE_ACTION = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
RUST_ACTION = "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30"
GO_ACTION = "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
PYTHON_ACTION = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
ZIZMOR_ACTION = "zizmorcore/zizmor-action@cc914d7f3750a2d13d75c7f184a1060aa0e9d482"
GUI_WORKFLOW = "./.github/workflows/gui-release.yml"
SBOM_COMMAND = [
    "scripts/generate_release_sboms.sh",
    "artifacts",
    "sbom",
    "$GITHUB_SHA",
    "$MXC_SBOM_DIR",
    "$MXC_REF",
]
WORKFLOW_REVALIDATION_RUN = (
    "python3 scripts/release_tools.py verify-workflows "
    '--repository "$GITHUB_REPOSITORY" --sha "$GITHUB_SHA" '
    "--workflow ci.yml --workflow security.yml"
)
WORKFLOW_REVALIDATION_ARGV = [
    "python3",
    "scripts/release_tools.py",
    "verify-workflows",
    "--repository",
    "$GITHUB_REPOSITORY",
    "--sha",
    "$GITHUB_SHA",
    "--workflow",
    "ci.yml",
    "--workflow",
    "security.yml",
]
RELEASE_SUPERVISOR_SETUP_RUN = """set -euo pipefail
sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
sudo apt-get -o Acquire::Retries=3 -o Dpkg::Use-Pty=0 install -y bubblewrap
if ! bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true; then
  userns_restriction="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)"
  test "$userns_restriction" = "1"
  printf '%s\\n' "$userns_restriction" > "$RUNNER_TEMP/axis-release-apparmor-userns"
  sudo -n sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
fi
bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true
"""
RELEASE_SUPERVISOR_SETUP_STEP = {
    "name": "Install release process supervisor",
    "timeout-minutes": 5,
    "run": RELEASE_SUPERVISOR_SETUP_RUN,
}
RELEASE_SUPERVISOR_RESTORE_RUN = """set -euo pipefail
state="$RUNNER_TEMP/axis-release-apparmor-userns"
if [ -f "$state" ]; then
  sudo -n sysctl -q -w "kernel.apparmor_restrict_unprivileged_userns=$(cat "$state")"
  rm -f "$state"
fi
"""
RELEASE_SUPERVISOR_RESTORE_STEP = {
    "name": "Restore release process supervisor",
    "if": "${{ always() }}",
    "timeout-minutes": 2,
    "run": RELEASE_SUPERVISOR_RESTORE_RUN,
}
COMMON_RELEASE_ENVIRONMENT = {
    "SOURCE_DATE_EPOCH": "315532800",
    "RUST_TOOLCHAIN": "1.95.0",
    "MXC_REPOSITORY": "https://github.com/microsoft/mxc",
    "MXC_REF": "1736b48398c3fe4d1315b2311c0951cc893eb3ae",
}
PACKAGE_ENVIRONMENT = {
    "CARGO_DEB_VERSION": "3.6.4",
    "CARGO_GENERATE_RPM_VERSION": "0.21.0",
}
MXC_BUILD_COMMAND = (
    'cargo build --release --manifest-path "$mxc_dir/src/Cargo.toml" '
    "-p lxc --no-default-features --locked"
)
RELEASE_JOBS = {
    "identity",
    "gate",
    "gui",
    "build",
    "package-linux",
    "sbom",
    "checksums",
    "attest",
    "release",
}
NIGHTLY_JOBS = {
    "source",
    "gate",
    "gui",
    "build",
    "sbom",
    "checksums",
    "attest",
    "publish",
}
GUI_JOBS = {"build-frontend", "build-macos", "build-linux", "build-windows"}
# Canonical job digests cover every field and preserve ordered step lists.
EXACT_RELEASE_JOB_DIGESTS = {
    "identity": "6a0829b6d0fca5d53cbc17051cb8e095cec10af735aa5fe7ecfc5b4087ba063a",
    "gate": "6c2c7b11eefc3f57f2e94c391ad7bbba235c46cc3944ad06fec7a9f245fa41ad",
    "gui": "385abeea4a0aac4cb93b8fc4f50c08bdf89d6949b9a217c2c000efa04bc3eaeb",
    "build": "23ce71f07051b1a631b37d2d088f23ced6c27de0d5e87ce9dae437de30735ab0",
    "package-linux": "6fcb787e28a2734252d3cf519c8b503cec298a98b1e254f742e5612c94ef2dec",
    "sbom": "905e489bfb8fc83707856400547e1b810a5714c51885699a68e1e40be059df50",
    "checksums": "fc4e16e505ca0b1615f92184a47701a1fee165c9c84faa89c18fd4c68c424244",
    "attest": "a876a0a1bbe51786225ca92559e37c20a63877df06cb86742b64849e005b98cb",
    "release": "1e0e0b5282527a96a832f701bee575862dbc118621c8bc991ea03f960dec8c1a",
}
EXACT_NIGHTLY_JOB_DIGESTS = {
    "source": "396c0c9226914fc2d6d77d0abc0962b816b24fdb585f970ecd485b1d536e8443",
    "gate": "ccc3041871c557de8f4d4dda8f22e76b93948bd6f2aec6d7d623a4637292fc12",
    "gui": "d2e806ebd8d87b3d84ea52d7d7b8f171117bc344abfd76e0e77c7f46e1e2e740",
    "build": "5173e93aa245cfcbedae844a9696cf96762e0d7416ab1a4a890705bcd0cb135b",
    "sbom": "a3bf6c64ab13f6e63244bebb0df3b94cdec9fe12218c82435125a79990bef3db",
    "checksums": "a49bf91fc21806960ce8e444c4e5ea615798c8f4f518f94c1e7765113e808a63",
    "attest": "a3817a26b1b2d37b42d5987e5d446822f862a3f1c98988e6811188b0a721c291",
    "publish": "b8c269f7f6a83dca196b3ccb2b1d940dc553f9097549f30097a0ad3f451c7467",
}
EXACT_GUI_JOB_DIGESTS = {
    "build-frontend": "6785a7424702c56fd75609c5404ef6a1b834bd9dca3a3be056c7979c6d6e34d5",
    "build-macos": "8e9568ec42b891bf231d6cc2d3ef647bcaaecede93c2c646fe95c7e411d1ca2b",
    "build-linux": "af28dc471102751a43213efe46996f62c24d6958197d93dda4cb9908f46574e4",
    "build-windows": "edb83817313328fe4188c2a0840a704baf0b7db69f95be830289b147b3de6502",
}
CI_JOBS = {
    "format",
    "gui-release-validation",
    "clippy",
    "changes",
    "test-linux",
    "test-macos",
    "test-linux-netns-helper",
    "test-windows",
    "publication-gate",
}
SECURITY_JOBS = {
    "codeql",
    "codeql-swift",
    "dependency-review",
    "dependency-audit",
    "windows-nuget-audit",
    "python-sast",
    "secret-scan",
    "actions-security",
    "publication-gate",
}
ALWAYS_CONDITION = "${{ always() }}"
PROTECTED_COMMAND_NAMES = {"python", "python3", "bash", "sh", "pwsh"}
PROTECTED_ENVIRONMENT_NAMES = {
    "BASH_ENV",
    "BASH_ALIASES",
    "BASH_CMDS",
    "BASH_LOADABLES_PATH",
    "CDPATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "ENV",
    "GIT_EXEC_PATH",
    "IFS",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PATH",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
    "SHELLOPTS",
}
COMMAND_RESOLUTION_MUTATORS = {
    ".",
    "builtin",
    "command",
    "declare",
    "enable",
    "eval",
    "export",
    "hash",
    "mapfile",
    "read",
    "readarray",
    "readonly",
    "shopt",
    "source",
    "trap",
    "typeset",
    "unset",
    "iex",
    "invoke-expression",
}
REVIEWED_BASH_CONTROL_HEADERS = {
    "if ! bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true; then",
    "if ! timeout --kill-after=1s 5s bwrap --unshare-user --uid 0 --gid 0 "
    "--ro-bind / / -- true; then",
    'if [ -f "$state" ]; then',
    'if [ "$PLATFORM" = "linux-x86_64" ]; then',
    'if [ "$RUNNER_OS" = "Linux" ]; then',
    'if [ -e "$sidecar" ]; then',
    "for binary in axis axisd axis-seccomp-launcher axis-netns-helper; do",
    "while IFS= read -r -d '' artifact; do",
    "while IFS= read -r -d '' asset; do",
}
POWERSHELL_PROVIDER_MUTATORS = {
    "add-content",
    "clear-item",
    "copy-item",
    "move-item",
    "new-item",
    "out-file",
    "remove-item",
    "rename-item",
    "set-content",
    "set-item",
}
REVIEWED_SHELLS = {
    "release": [
        ("build", "Build (Windows)", "pwsh"),
        ("build", "Build MXC Windows executor", "pwsh"),
        ("build", "Install Rust toolchain (Windows)", "pwsh"),
        ("build", "Package (Windows)", "pwsh"),
        ("build", "Verify Windows release archive", "pwsh"),
    ],
    "nightly": [
        ("build", "Build (Windows)", "pwsh"),
        ("build", "Build MXC Windows executor", "pwsh"),
        ("build", "Install Rust toolchain (Windows)", "pwsh"),
        ("build", "Package (Windows)", "pwsh"),
        ("build", "Verify Windows nightly archive", "pwsh"),
    ],
    "gui": [
        ("build-windows", "Package deterministic Windows archive", "pwsh"),
    ],
    "ci": [
        ("test-windows", "Agent policy validation", "pwsh"),
        ("test-windows", "Agent safety tests", "pwsh"),
        ("test-windows", "Assemble and install Windows release archive", "pwsh"),
        ("test-windows", "Build pinned MXC Windows executor", "pwsh"),
        ("test-windows", "PowerShell installer bounded output tests", "pwsh"),
        ("test-windows", "Reject invalid Windows installer checksums", "pwsh"),
        ("test-windows", "Test agent install (PowerShell)", "pwsh"),
        (
            "test-windows",
            "Windows MXC ProcessContainer smoke and security tests",
            "pwsh",
        ),
    ],
    "security": [],
}


class WorkflowError(RuntimeError):
    """A workflow can bypass or omit a required publication control."""


@dataclass(frozen=True)
class ScriptCommand:
    argv: tuple[str, ...]
    controls: tuple[str, ...]


class GitHubActionsLoader(yaml.SafeLoader):
    """Safe YAML 1.2-like loader with duplicate mapping key rejection."""


GitHubActionsLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for resolver_key, resolvers in list(
    GitHubActionsLoader.yaml_implicit_resolvers.items()
):
    GitHubActionsLoader.yaml_implicit_resolvers[resolver_key] = [
        (tag, expression)
        for tag, expression in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
GitHubActionsLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise WorkflowError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


GitHubActionsLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
)


def load_workflow(path: Path) -> dict[str, Any]:
    try:
        document = yaml.load(path.read_text(encoding="utf-8"), GitHubActionsLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise WorkflowError(f"failed to parse workflow {path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        raise WorkflowError(f"workflow has no jobs mapping: {path}")
    return document


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkflowError(f"{label} must be a mapping")
    return value


def require_job(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    job = workflow["jobs"].get(name)
    if not isinstance(job, dict):
        raise WorkflowError(f"required job is missing: {name}")
    reject_protected_environment(job.get("env"), f"job {name}")
    return job


def require_exact_jobs(
    workflow: dict[str, Any], expected: set[str], label: str
) -> None:
    if "defaults" in workflow:
        raise WorkflowError(f"{label} has unexpected workflow execution defaults")
    actual = set(workflow["jobs"])
    if actual != expected:
        raise WorkflowError(
            f"{label} has wrong job set: expected {sorted(expected)}, got {sorted(actual)}"
        )
    jobs_with_defaults = [
        name
        for name, job in workflow["jobs"].items()
        if isinstance(job, dict) and "defaults" in job
    ]
    if jobs_with_defaults:
        raise WorkflowError(
            f"{label} jobs have unexpected execution defaults: "
            + ", ".join(sorted(jobs_with_defaults))
        )


def require_unconditional_job(job: dict[str, Any], label: str) -> None:
    if "if" in job:
        raise WorkflowError(f"{label} must not have a disabling condition")
    if job.get("continue-on-error") not in (None, False):
        raise WorkflowError(f"{label} must not continue on error")


def require_job_condition(job: dict[str, Any], expected: str, label: str) -> None:
    if job.get("if") != expected:
        raise WorkflowError(
            f"{label} has wrong or disabling condition: {job.get('if')!r}"
        )
    if job.get("continue-on-error") not in (None, False):
        raise WorkflowError(f"{label} must not continue on error")


def require_job_name(job: dict[str, Any], expected: str, label: str) -> None:
    if job.get("name") != expected:
        raise WorkflowError(f"{label} has wrong name: {job.get('name')!r}")


def reject_step_bypasses(job: dict[str, Any], label: str) -> None:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise WorkflowError(f"{label} has no steps list")
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise WorkflowError(f"{label} contains malformed step {index}")
        if "if" in step and step.get("if") != ALWAYS_CONDITION:
            raise WorkflowError(f"{label} step {index} has a disabling condition")
        if step.get("continue-on-error") not in (None, False):
            raise WorkflowError(f"{label} step {index} must not continue on error")
        if "run" in step:
            if not isinstance(step["run"], str) or step.get("shell") not in (
                None,
                "bash",
                "pwsh",
            ):
                raise WorkflowError(f"{label} step {index} has unsafe shell topology")
        elif "uses" in step:
            action = step["uses"]
            if not isinstance(action, str) or not (
                action.startswith("./")
                or re.fullmatch(r"[^/@]+/[^/@]+(?:/[^/@]+)*@[0-9a-f]{40}", action)
            ):
                raise WorkflowError(f"{label} step {index} uses an unpinned action")
        else:
            raise WorkflowError(f"{label} contains non-executable step {index}")


def require_no_strategy(job: dict[str, Any], label: str) -> None:
    if "strategy" in job:
        raise WorkflowError(f"{label} has an unexpected matrix or strategy")


def require_job_runtime(
    job: dict[str, Any],
    runner: str,
    timeout: int,
    label: str,
    permissions: dict[str, str] | None = None,
) -> None:
    if job.get("runs-on") != runner or job.get("timeout-minutes") != timeout:
        raise WorkflowError(f"{label} has wrong runner or timeout topology")
    if permissions is None:
        if "permissions" in job:
            raise WorkflowError(f"{label} has unexpected job permissions")
    else:
        require_permissions(job, permissions, label)
    if job.get("uses") is not None:
        raise WorkflowError(f"{label} unexpectedly delegates to another workflow")
    for key in ("concurrency", "container", "defaults", "environment", "services"):
        if key in job:
            raise WorkflowError(f"{label} has unexpected {key} topology")


def require_exact_shell_topology(
    workflow: dict[str, Any], reviewed: list[tuple[str, str, str]], label: str
) -> None:
    actual = []
    for job_name, job in workflow["jobs"].items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict) and "shell" in step:
                shell = step["shell"]
                if not isinstance(shell, str):
                    raise WorkflowError(f"{label} contains a malformed explicit shell")
                actual.append((job_name, str(step.get("name")), shell))
    if sorted(actual) != sorted(reviewed):
        raise WorkflowError(
            f"{label} has unreviewed explicit shell topology: {sorted(actual)}"
        )


def require_exact_gate_step(
    job: dict[str, Any], name: str, environment: dict[str, str], run: str
) -> None:
    step = require_step(job, name)
    expected = {"name": name, "env": environment, "run": run}
    if step != expected or job.get("steps") != [expected]:
        raise WorkflowError(f"publication gate step {name!r} is not exact")


def require_exact_command_step(
    job: dict[str, Any],
    expected: dict[str, Any],
    argv: list[str],
    label: str,
) -> None:
    name = expected.get("name")
    if not isinstance(name, str):
        raise WorkflowError(f"{label} has no reviewed step name")
    step = require_step(job, name, condition=expected.get("if"))
    if step != expected:
        raise WorkflowError(f"{label} {name!r} is not exact")
    require_exact_argv(step, argv, label)


def require_exact_job_steps(
    job: dict[str, Any], expected: list[dict[str, Any]], label: str
) -> None:
    if job.get("steps") != expected:
        raise WorkflowError(f"{label} does not have the exact reviewed step sequence")


def canonical_job_digest(job: dict[str, Any]) -> str:
    encoded = json.dumps(
        job, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def require_exact_job_definitions(
    workflow: dict[str, Any], expected: dict[str, str], label: str
) -> None:
    actual = {
        name: canonical_job_digest(require_mapping(job, f"{label} job {name}"))
        for name, job in workflow["jobs"].items()
    }
    if actual != expected:
        changed = sorted(
            name
            for name in set(actual) | set(expected)
            if actual.get(name) != expected.get(name)
        )
        raise WorkflowError(
            f"{label} jobs do not match exact reviewed definitions: {', '.join(changed)}"
        )


def require_action_step(job: dict[str, Any], name: str, action: str) -> None:
    step = require_step(job, name)
    if step.get("uses") != action:
        raise WorkflowError(f"step {name!r} does not use the pinned reviewed action")


def needs_set(job: dict[str, Any]) -> set[str]:
    needs = job.get("needs")
    if needs is None:
        return set()
    if isinstance(needs, str):
        return {needs}
    if isinstance(needs, list) and all(isinstance(value, str) for value in needs):
        return set(needs)
    raise WorkflowError("job needs must be a string or list of strings")


def require_needs(job: dict[str, Any], expected: set[str], label: str) -> None:
    actual = needs_set(job)
    if actual != expected:
        raise WorkflowError(
            f"{label} has wrong dependencies: expected {sorted(expected)}, got {sorted(actual)}"
        )


def require_permissions(
    owner: dict[str, Any], expected: dict[str, str], label: str
) -> None:
    actual = owner.get("permissions")
    if actual != expected:
        raise WorkflowError(
            f"{label} has wrong permissions: expected {expected}, got {actual}"
        )


def require_release_process_supervisor(job: dict[str, Any], label: str) -> None:
    setup = require_step(job, "Install release process supervisor")
    if setup != RELEASE_SUPERVISOR_SETUP_STEP:
        raise WorkflowError(f"{label} has an invalid process supervisor setup")
    restore = require_step(
        job, "Restore release process supervisor", condition=ALWAYS_CONDITION
    )
    if restore != RELEASE_SUPERVISOR_RESTORE_STEP:
        raise WorkflowError(f"{label} has an invalid process supervisor restoration")


def require_environment(
    workflow: dict[str, Any], expected: dict[str, str], label: str
) -> None:
    environment = require_mapping(workflow.get("env"), f"{label} environment")
    reject_protected_environment(environment, label)
    for name, value in expected.items():
        if str(environment.get(name)) != value:
            raise WorkflowError(
                f"{label} has wrong {name}: expected {value!r}, "
                f"got {environment.get(name)!r}"
            )


def require_step(
    job: dict[str, Any],
    name: str,
    *,
    condition: str | None = None,
) -> dict[str, Any]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise WorkflowError(f"job containing {name!r} has no steps list")
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    if len(matches) != 1:
        raise WorkflowError(f"expected exactly one enabled step named {name!r}")
    step = matches[0]
    actual_condition = step.get("if")
    if actual_condition != condition:
        raise WorkflowError(
            f"step {name!r} has wrong or disabling condition: {actual_condition!r}"
        )
    if step.get("continue-on-error") not in (None, False):
        raise WorkflowError(f"step {name!r} must not continue on error")
    return step


def executable_lines(step: dict[str, Any], label: str) -> list[str]:
    run = step.get("run")
    if not isinstance(run, str) or not run.strip():
        raise WorkflowError(f"{label} has no executable run command")
    shell = step.get("shell")
    if shell not in (None, "bash", "pwsh"):
        raise WorkflowError(f"{label} uses an unsupported shell: {shell!r}")
    if step.get("working-directory") is not None:
        raise WorkflowError(f"{label} changes the required working directory")
    reject_protected_environment(step.get("env"), label)
    logical = run.replace("\\\n", " ").replace("`\n", " ")
    return [
        line.strip()
        for line in logical.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def parse_argv(line: str, label: str) -> tuple[str, ...]:
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return tuple(lexer)
    except ValueError as error:
        raise WorkflowError(
            f"{label} contains invalid shell syntax: {line!r}"
        ) from error


def reject_bypass_command(argv: tuple[str, ...], label: str) -> None:
    if not argv:
        return
    command_index = 0
    while command_index < len(argv) and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]+\])?=.*", argv[command_index]
    ):
        command_index += 1
    if command_index == len(argv):
        command = ""
    else:
        command = argv[command_index]
    if command.startswith("$") or "$(" in command:
        raise WorkflowError(f"{label} dynamically resolves a shell command")
    if command in COMMAND_RESOLUTION_MUTATORS:
        raise WorkflowError(
            f"{label} mutates shell execution or command resolution: {command}"
        )
    if command in ("return", "exec", "logout"):
        raise WorkflowError(f"{label} contains forbidden control command: {command}")
    if command == "exit" and argv != ("exit", "1"):
        raise WorkflowError(
            f"{label} contains successful early exit or unsupported exit status"
        )
    if command == "set" and any(value.startswith("+") for value in argv[1:]):
        raise WorkflowError(f"{label} disables fail-closed shell options")
    if command == "printf" and "-v" in argv[1:]:
        raise WorkflowError(f"{label} mutates shell state with printf -v")
    if command in ("alias", "unalias", "set-alias", "new-alias"):
        raise WorkflowError(f"{label} changes command resolution")
    if command == "kill" and any(value in ("$$", "$PID") for value in argv[1:]):
        raise WorkflowError(f"{label} can terminate its own control shell")
    if (
        command in PROTECTED_COMMAND_NAMES
        and len(argv) > command_index + 1
        and argv[command_index + 1] == "()"
    ):
        raise WorkflowError(f"{label} shadows a protected command")
    for assignment in argv:
        name = assignment.split("=", 1)[0]
        base_name = name.split("[", 1)[0].upper()
        if "=" in assignment and (
            base_name in PROTECTED_ENVIRONMENT_NAMES
            or base_name in ("BASH_ALIASES", "BASH_CMDS")
            or base_name.startswith("BASH_FUNC_")
        ):
            raise WorkflowError(f"{label} changes protected shell environment: {name}")


def reject_bypass_commands(argv: tuple[str, ...], label: str) -> None:
    segment = []
    for token in argv:
        if token in (";", "&&", "||", "|", "&"):
            reject_bypass_command(tuple(segment), label)
            segment = []
        else:
            segment.append(token)
    reject_bypass_command(tuple(segment), label)


def reject_protected_environment(value: Any, label: str) -> None:
    if value is None:
        return
    environment = require_mapping(value, f"{label} environment")
    protected = [
        str(name)
        for name in environment
        if str(name).upper() in PROTECTED_ENVIRONMENT_NAMES
        or str(name).upper().startswith("BASH_FUNC_")
    ]
    if protected:
        raise WorkflowError(
            f"{label} changes protected environment: {sorted(protected)}"
        )


def bash_script_commands(step: dict[str, Any], label: str) -> list[ScriptCommand]:
    commands = []
    controls: list[str] = []
    for line in executable_lines(step, label):
        if re.match(r"^\s*function(?:\s|$)", line):
            raise WorkflowError(f"{label} contains a shell function definition")
        if re.search(
            r"(?:^|[;&|]\s*)(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*"
            r"\s*(?:\(\))?\s*\{",
            line,
        ):
            raise WorkflowError(f"{label} contains a shell function definition")
        if line == "else":
            if not controls or not controls[-1].startswith("if "):
                raise WorkflowError(f"{label} contains unmatched else")
            controls[-1] = f"else ({controls[-1]})"
            continue
        if line == "fi":
            if not controls or not (
                controls[-1].startswith("if ") or controls[-1].startswith("else (if ")
            ):
                raise WorkflowError(f"{label} contains unmatched fi")
            controls.pop()
            continue
        if line == "done" or line.startswith("done "):
            if not controls or not controls[-1].startswith(("for ", "while ")):
                raise WorkflowError(f"{label} contains unmatched done")
            controls.pop()
            continue
        if (line.startswith("if ") and line.endswith("; then")) or (
            line.startswith(("for ", "while ")) and line.endswith("; do")
        ):
            if line not in REVIEWED_BASH_CONTROL_HEADERS:
                raise WorkflowError(
                    f"{label} contains unreviewed shell control flow: {line}"
                )
            controls.append(line)
            continue
        if line.startswith(("elif ", "case ", "until ", "select ")):
            raise WorkflowError(
                f"{label} contains unsupported shell control flow: {line}"
            )
        argv = parse_argv(line, label)
        reject_bypass_commands(argv, label)
        commands.append(ScriptCommand(argv, tuple(controls)))
    if controls:
        raise WorkflowError(f"{label} contains unterminated shell control flow")
    return commands


def powershell_script_commands(step: dict[str, Any], label: str) -> list[ScriptCommand]:
    commands = []
    depth = 0
    for line in executable_lines(step, label):
        function = re.search(
            r"\b(?:filter|function)\s+(?:(?:global|local|private|script):)?"
            r"([A-Za-z_][A-Za-z0-9_-]*)",
            line,
            re.I,
        )
        if function and function.group(1).lower() in PROTECTED_COMMAND_NAMES:
            raise WorkflowError(f"{label} shadows a protected command")
        if re.search(r"(?:\$\{?)?\b(?:alias|function):", line, re.I):
            raise WorkflowError(f"{label} mutates PowerShell command providers")
        if re.match(r"^\s*&(?:\s|$)", line):
            raise WorkflowError(f"{label} dynamically invokes a PowerShell command")
        argv = parse_argv(line, label)
        lowered = tuple(value.lower() for value in argv)
        reject_bypass_commands(lowered, label)
        raw_command = line.split(maxsplit=1)[0].lower()
        command = raw_command.rsplit("\\", 1)[-1]
        if command in COMMAND_RESOLUTION_MUTATORS or command in (
            "alias",
            "new-alias",
            "set-alias",
            "unalias",
        ):
            raise WorkflowError(f"{label} mutates PowerShell command resolution")
        if command in POWERSHELL_PROVIDER_MUTATORS:
            raise WorkflowError(f"{label} mutates PowerShell command providers")
        controls = tuple("powershell-block" for _ in range(depth))
        commands.append(ScriptCommand(argv, controls))
        depth += line.count("{") - line.count("}")
        if depth < 0:
            raise WorkflowError(f"{label} contains unmatched PowerShell block")
    if depth:
        raise WorkflowError(f"{label} contains unterminated PowerShell block")
    return commands


def script_commands(step: dict[str, Any], label: str) -> list[ScriptCommand]:
    if step.get("shell") == "pwsh":
        return powershell_script_commands(step, label)
    return bash_script_commands(step, label)


def require_command_line(
    step: dict[str, Any],
    command: str,
    label: str,
    *,
    controls: tuple[str, ...] = (),
) -> None:
    require_argv_line(step, list(parse_argv(command, label)), label, controls=controls)


def require_command_sequence(
    step: dict[str, Any],
    expected: list[tuple[str, tuple[str, ...]]],
    label: str,
) -> None:
    commands = script_commands(step, label)
    next_index = 0
    for command, controls in expected:
        required = ScriptCommand(tuple(parse_argv(command, label)), controls)
        try:
            next_index = commands.index(required, next_index) + 1
        except ValueError as error:
            raise WorkflowError(f"{label} does not preserve required command order") from error


def require_exclusive_sysctl_write(
    step: dict[str, Any],
    key: str,
    command: str,
    label: str,
    *,
    controls: tuple[str, ...] = (),
) -> None:
    expected = ScriptCommand(tuple(parse_argv(command, label)), controls)
    writes = [
        candidate
        for candidate in script_commands(step, label)
        if any(argument.rsplit("/", 1)[-1] == "sysctl" for argument in candidate.argv)
        and any(argument in {"-w", "--write"} for argument in candidate.argv)
        and any(argument == key or argument.startswith(f"{key}=") for argument in candidate.argv)
    ]
    if writes != [expected]:
        raise WorkflowError(f"{label} requires exactly one reviewed sysctl write")


def require_exact_argv(step: dict[str, Any], expected: list[str], label: str) -> None:
    commands = script_commands(step, label)
    if commands != [ScriptCommand(tuple(expected), ())]:
        raise WorkflowError(f"{label} has unexpected command structure: {commands}")


def require_argv_line(
    step: dict[str, Any],
    expected: list[str],
    label: str,
    *,
    controls: tuple[str, ...] = (),
) -> None:
    required = ScriptCommand(tuple(expected), controls)
    if required not in script_commands(step, label):
        raise WorkflowError(
            f"{label} does not unconditionally execute required command argv: {expected}"
        )


def verify_common_release_build(workflow: dict[str, Any], *, nightly: bool) -> None:
    require_environment(workflow, COMMON_RELEASE_ENVIRONMENT, "publication workflow")
    source_job = "source" if nightly else "identity"

    gui = require_job(workflow, "gui")
    require_unconditional_job(gui, "GUI job")
    require_needs(gui, {source_job, "gate"}, "GUI job")
    require_permissions(gui, {"contents": "read"}, "GUI job")
    if gui.get("uses") != GUI_WORKFLOW or "if" in gui:
        raise WorkflowError("GUI job must unconditionally call the reviewed workflow")

    build = require_job(workflow, "build")
    require_unconditional_job(build, "build job")
    require_needs(build, {source_job, "gate"}, "build job")
    mxc_step = require_step(
        build,
        "Build MXC Linux executor",
        condition="matrix.platform == 'linux-x86_64'",
    )
    require_command_line(mxc_step, MXC_BUILD_COMMAND, "MXC build step")
    require_command_line(
        mxc_step, 'git -C "$mxc_dir" checkout "$MXC_REF"', "MXC build step"
    )
    require_command_line(
        mxc_step,
        'cp "$mxc_dir/src/target/release/lxc-exec" "target/$TARGET/release/lxc-exec"',
        "MXC build step",
    )
    windows_mxc_step = require_step(
        build,
        "Build MXC Windows executor",
        condition="runner.os == 'Windows'",
    )
    expected_windows_mxc_step = {
        "name": "Build MXC Windows executor",
        "if": "runner.os == 'Windows'",
        "shell": "pwsh",
        "run": """$mxcDir = Join-Path $env:RUNNER_TEMP "mxc"
git clone --filter=blob:none $env:MXC_REPOSITORY $mxcDir
git -C $mxcDir checkout $env:MXC_REF
Get-ChildItem (Join-Path $env:GITHUB_WORKSPACE "third_party\\mxc\\patches\\*.patch") |
  Sort-Object Name | ForEach-Object { git -C $mxcDir apply --whitespace=error $_.FullName }
Push-Location (Join-Path $mxcDir "src")
cargo build --release -p wxc --no-default-features --locked --target ${{ matrix.target }}
Pop-Location
Copy-Item (Join-Path $mxcDir "src\\target\\${{ matrix.target }}\\release\\wxc-exec.exe") target\\${{ matrix.target }}\\release\\wxc-exec.exe
""",
    }
    if windows_mxc_step != expected_windows_mxc_step:
        raise WorkflowError("MXC Windows build step is not exact")
    package_step = require_step(
        build, "Package (Unix)", condition="runner.os != 'Windows'"
    )
    require_command_line(
        package_step,
        'cp "$target_dir/lxc-exec" "$package_dir/"',
        "Unix package step",
        controls=('if [ "$PLATFORM" = "linux-x86_64" ]; then',),
    )
    require_command_line(
        package_step,
        'cp "$target_dir/axis-seccomp-launcher" "$package_dir/"',
        "Unix package step",
        controls=('if [ "$PLATFORM" = "linux-x86_64" ]; then',),
    )
    unix_name = (
        "Verify Unix nightly archive" if nightly else "Verify Unix release archive"
    )
    windows_name = (
        "Verify Windows nightly archive"
        if nightly
        else "Verify Windows release archive"
    )
    unix_step = require_step(build, unix_name, condition="runner.os != 'Windows'")
    require_command_line(
        unix_step,
        'python3 scripts/verify_release_archive.py "$archive" "$archive_root" "${required[@]}"',
        f"{unix_name} step",
    )
    require_exact_command_step(
        build,
        {
            "name": windows_name,
            "if": "runner.os == 'Windows'",
            "shell": "pwsh",
            "env": {"PLATFORM": "${{ matrix.platform }}"},
            "run": (
                "python scripts/verify_release_archive.py "
                '"dist/axis-$env:PLATFORM.zip" "axis-$env:PLATFORM" '
                "--require axis.exe --require axisd.exe "
                "--require wxc-exec.exe "
                "--require axis-wfp-broker.exe "
                "--require axis-ssh-proxy.exe "
                "--require install_windows_wfp_broker.ps1 "
                "--require REPRODUCIBILITY.json"
            ),
        },
        [
            "python",
            "scripts/verify_release_archive.py",
            "dist/axis-$env:PLATFORM.zip",
            "axis-$env:PLATFORM",
            "--require",
            "axis.exe",
            "--require",
            "axisd.exe",
            "--require",
            "wxc-exec.exe",
            "--require",
            "axis-wfp-broker.exe",
            "--require",
            "axis-ssh-proxy.exe",
            "--require",
            "install_windows_wfp_broker.ps1",
            "--require",
            "REPRODUCIBILITY.json",
        ],
        f"{windows_name} step",
    )
    require_command_line(
        package_step,
        'cp "packaging/reproducibility/core-${PLATFORM%%-*}.json" '
        '"$package_dir/REPRODUCIBILITY.json"',
        "Unix package step",
    )
    require_command_line(
        package_step,
        'cp packaging/runtime/core-linux.json "$package_dir/RUNTIME_DEPENDENCIES.json"',
        "Unix package step",
        controls=('if [ "$PLATFORM" = "linux-x86_64" ]; then',),
    )
    linux_rebuild = require_step(
        build,
        "Compare independent clean Linux core build",
        condition="matrix.platform == 'linux-x86_64'",
    )
    require_command_line(
        linux_rebuild, 'cargo clean --target "$TARGET"', "Linux rebuild step"
    )
    require_command_line(
        linux_rebuild,
        'cargo build --locked --release --target "$TARGET"',
        "Linux rebuild step",
    )
    require_command_line(
        linux_rebuild,
        'cmp "$RUNNER_TEMP/axis-first-build/$binary" "target/$TARGET/release/$binary"',
        "Linux rebuild step",
        controls=(
            "for binary in axis axisd axis-seccomp-launcher axis-netns-helper; do",
        ),
    )


def verify_release_workflow(workflow: dict[str, Any]) -> None:
    require_exact_jobs(workflow, RELEASE_JOBS, "release workflow")
    require_exact_shell_topology(
        workflow, REVIEWED_SHELLS["release"], "release workflow"
    )
    require_permissions(workflow, {"contents": "read"}, "release workflow")
    require_environment(workflow, PACKAGE_ENVIRONMENT, "release workflow")
    if (
        require_mapping(workflow.get("concurrency"), "release concurrency").get(
            "cancel-in-progress"
        )
        is not False
    ):
        raise WorkflowError(
            "release concurrency must not cancel in-progress publication"
        )
    verify_common_release_build(workflow, nightly=False)

    for job_name in (
        "identity",
        "gate",
        "package-linux",
        "sbom",
        "checksums",
        "attest",
        "release",
    ):
        require_unconditional_job(require_job(workflow, job_name), f"{job_name} job")

    identity = require_job(workflow, "identity")
    require_job_runtime(identity, "ubuntu-24.04", 10, "release identity job")
    require_release_process_supervisor(identity, "release identity job")
    identity_run = (
        "python3 scripts/release_tools.py verify-identity --repository-root . "
        '--tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA"'
    )
    identity_step = {
        "name": "Bind tag, version, and commit",
        "run": identity_run,
    }
    require_exact_command_step(
        identity,
        identity_step,
        [
            "python3",
            "scripts/release_tools.py",
            "verify-identity",
            "--repository-root",
            ".",
            "--tag",
            "$GITHUB_REF_NAME",
            "--sha",
            "$GITHUB_SHA",
        ],
        "release identity step",
    )
    require_exact_job_steps(
        identity,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {
                    "ref": "${{ github.ref }}",
                    "fetch-depth": 0,
                    "persist-credentials": False,
                },
            },
            RELEASE_SUPERVISOR_SETUP_STEP,
            identity_step,
            RELEASE_SUPERVISOR_RESTORE_STEP,
        ],
        "release identity job",
    )
    gate = require_job(workflow, "gate")
    require_needs(gate, {"identity"}, "release gate job")
    require_job_runtime(
        gate,
        "ubuntu-24.04",
        25,
        "release gate job",
        {"actions": "read", "contents": "read"},
    )
    require_release_process_supervisor(gate, "release gate job")
    gate_run = (
        "python3 scripts/release_tools.py verify-workflows "
        '--repository "$GITHUB_REPOSITORY" --sha "$GITHUB_SHA" '
        "--workflow ci.yml --workflow security.yml"
    )
    gate_step = {
        "name": "Require successful CI and security runs for the release commit",
        "env": {"GH_TOKEN": "${{ github.token }}"},
        "run": gate_run,
    }
    require_exact_command_step(
        gate,
        gate_step,
        [
            "python3",
            "scripts/release_tools.py",
            "verify-workflows",
            "--repository",
            "$GITHUB_REPOSITORY",
            "--sha",
            "$GITHUB_SHA",
            "--workflow",
            "ci.yml",
            "--workflow",
            "security.yml",
        ],
        "release gate step",
    )
    require_exact_job_steps(
        gate,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {
                    "ref": "${{ github.sha }}",
                    "persist-credentials": False,
                },
            },
            RELEASE_SUPERVISOR_SETUP_STEP,
            gate_step,
            RELEASE_SUPERVISOR_RESTORE_STEP,
        ],
        "release gate job",
    )

    package = require_job(workflow, "package-linux")
    require_needs(package, {"build"}, "Linux package job")
    package_mxc_step = require_step(package, "Build MXC Linux executor")
    require_command_line(package_mxc_step, MXC_BUILD_COMMAND, "package MXC build step")
    require_command_line(
        package_mxc_step,
        'cp "$mxc_dir/src/target/release/lxc-exec" target/release/lxc-exec',
        "package MXC build step",
    )
    require_command_line(
        require_step(package, "Build .deb"),
        'cargo install cargo-deb --version "$CARGO_DEB_VERSION" --locked',
        "Debian package build step",
    )
    rpm_build_step = require_step(package, "Build .rpm")
    require_command_line(
        rpm_build_step,
        'cargo install cargo-generate-rpm --version "$CARGO_GENERATE_RPM_VERSION" --locked',
        "RPM package build step",
    )
    require_command_line(
        rpm_build_step,
        "cargo generate-rpm -p crates/axis-daemon",
        "RPM package build step",
    )
    require_command_line(
        require_step(package, "Verify .deb contents"),
        'scripts/verify_linux_package_manifest.sh deb "$deb"',
        "Debian package verification step",
    )
    require_command_line(
        require_step(package, "Verify .rpm contents"),
        'scripts/verify_linux_package_manifest.sh rpm "$rpm_path"',
        "RPM package verification step",
    )

    sbom = require_job(workflow, "sbom")
    require_needs(sbom, {"build", "package-linux", "gui"}, "SBOM job")
    require_exact_argv(
        require_step(sbom, "Generate and verify dependency-backed SPDX SBOMs"),
        SBOM_COMMAND,
        "SBOM step",
    )
    checksums = require_job(workflow, "checksums")
    require_needs(checksums, {"build", "package-linux", "gui", "sbom"}, "checksum job")
    checksum_step = require_step(
        checksums, "Create one SHA-256 sidecar per release artifact"
    )
    require_command_line(
        checksum_step,
        'sha256sum "$artifact" | awk -v name="$name" \'{print $1 "  " name}\' > "$sidecar"',
        "release checksum step",
        controls=("while IFS= read -r -d '' artifact; do",),
    )

    attest = require_job(workflow, "attest")
    require_needs(
        attest,
        {"gate", "build", "package-linux", "gui", "sbom", "checksums"},
        "attestation job",
    )
    require_permissions(
        attest,
        {"contents": "read", "id-token": "write", "attestations": "write"},
        "attestation job",
    )
    subject_step = require_step(attest, "Assemble and verify attestation subjects")
    require_command_line(
        subject_step,
        'scripts/verify_release_assets.sh stable attest-assets "$GITHUB_SHA"',
        "attestation subject step",
    )
    action_step = require_step(attest, "Generate build provenance attestations")
    if action_step.get("uses") != ATTEST_ACTION:
        raise WorkflowError(
            "attestation job does not use the pinned attestation action"
        )

    publish = require_job(workflow, "release")
    require_needs(
        publish,
        {"gate", "build", "package-linux", "gui", "sbom", "checksums", "attest"},
        "release publication job",
    )
    require_release_process_supervisor(publish, "release publication job")
    require_permissions(
        publish,
        {"actions": "read", "contents": "write"},
        "release publication job",
    )
    require_exact_command_step(
        publish,
        {
            "name": "Revalidate required workflows immediately before publication",
            "env": {"GH_TOKEN": "${{ github.token }}"},
            "run": WORKFLOW_REVALIDATION_RUN,
        },
        WORKFLOW_REVALIDATION_ARGV,
        "release pre-publication workflow gate",
    )
    publish_step = require_step(publish, "Create release from complete artifact set")
    require_argv_line(
        publish_step,
        [
            "scripts/publish_github_release.sh",
            "stable",
            "$RELEASE_TAG",
            "publish-assets",
            "$RELEASE_TAG",
        ],
        "release publication step",
    )
    require_exact_job_definitions(
        workflow, EXACT_RELEASE_JOB_DIGESTS, "release workflow"
    )


def verify_nightly_workflow(workflow: dict[str, Any]) -> None:
    require_exact_jobs(workflow, NIGHTLY_JOBS, "nightly workflow")
    require_exact_shell_topology(
        workflow, REVIEWED_SHELLS["nightly"], "nightly workflow"
    )
    require_permissions(workflow, {"contents": "read"}, "nightly workflow")
    if (
        require_mapping(workflow.get("concurrency"), "nightly concurrency").get(
            "cancel-in-progress"
        )
        is not False
    ):
        raise WorkflowError(
            "nightly concurrency must not cancel in-progress publication"
        )
    verify_common_release_build(workflow, nightly=True)
    for job_name in ("source", "gate", "sbom", "checksums", "attest", "publish"):
        require_unconditional_job(require_job(workflow, job_name), f"{job_name} job")
    source = require_job(workflow, "source")
    require_job_runtime(source, "ubuntu-24.04", 10, "nightly source job")
    require_release_process_supervisor(source, "nightly source job")
    source_run = (
        "python3 scripts/release_tools.py verify-default-source "
        '--repository-root . --repository "$GITHUB_REPOSITORY" '
        '--ref "$GITHUB_REF" --sha "$GITHUB_SHA"'
    )
    source_step = {
        "name": "Bind the run to the current default-branch commit",
        "env": {"GH_TOKEN": "${{ github.token }}"},
        "run": source_run,
    }
    require_exact_command_step(
        source,
        source_step,
        [
            "python3",
            "scripts/release_tools.py",
            "verify-default-source",
            "--repository-root",
            ".",
            "--repository",
            "$GITHUB_REPOSITORY",
            "--ref",
            "$GITHUB_REF",
            "--sha",
            "$GITHUB_SHA",
        ],
        "nightly source identity step",
    )
    require_exact_job_steps(
        source,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {
                    "ref": "${{ github.sha }}",
                    "fetch-depth": 0,
                    "persist-credentials": False,
                },
            },
            RELEASE_SUPERVISOR_SETUP_STEP,
            source_step,
            RELEASE_SUPERVISOR_RESTORE_STEP,
        ],
        "nightly source job",
    )
    gate = require_job(workflow, "gate")
    require_needs(gate, {"source"}, "nightly gate job")
    require_job_runtime(
        gate,
        "ubuntu-24.04",
        25,
        "nightly gate job",
        {"actions": "read", "contents": "read"},
    )
    require_release_process_supervisor(gate, "nightly gate job")
    gate_run = (
        "python3 scripts/release_tools.py verify-workflows "
        '--repository "$GITHUB_REPOSITORY" --sha "$GITHUB_SHA" '
        "--workflow ci.yml --workflow security.yml"
    )
    gate_step = {
        "name": "Require successful CI and security runs for the nightly commit",
        "env": {"GH_TOKEN": "${{ github.token }}"},
        "run": gate_run,
    }
    require_exact_command_step(
        gate,
        gate_step,
        [
            "python3",
            "scripts/release_tools.py",
            "verify-workflows",
            "--repository",
            "$GITHUB_REPOSITORY",
            "--sha",
            "$GITHUB_SHA",
            "--workflow",
            "ci.yml",
            "--workflow",
            "security.yml",
        ],
        "nightly gate step",
    )
    require_exact_job_steps(
        gate,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {
                    "ref": "${{ github.sha }}",
                    "persist-credentials": False,
                },
            },
            RELEASE_SUPERVISOR_SETUP_STEP,
            gate_step,
            RELEASE_SUPERVISOR_RESTORE_STEP,
        ],
        "nightly gate job",
    )

    sbom = require_job(workflow, "sbom")
    require_needs(sbom, {"build", "gui"}, "nightly SBOM job")
    require_exact_argv(
        require_step(sbom, "Generate and verify dependency-backed SPDX SBOMs"),
        SBOM_COMMAND,
        "nightly SBOM step",
    )
    checksums = require_job(workflow, "checksums")
    require_needs(checksums, {"build", "gui", "sbom"}, "nightly checksum job")
    require_command_line(
        require_step(checksums, "Create one SHA-256 sidecar per nightly artifact"),
        'sha256sum "$artifact" | awk -v name="$name" \'{print $1 "  " name}\' > "$sidecar"',
        "nightly checksum step",
        controls=("while IFS= read -r -d '' artifact; do",),
    )

    attest = require_job(workflow, "attest")
    require_needs(
        attest,
        {"source", "gate", "build", "gui", "sbom", "checksums"},
        "nightly attest job",
    )
    require_permissions(
        attest,
        {"contents": "read", "id-token": "write", "attestations": "write"},
        "nightly attest job",
    )
    require_command_line(
        require_step(attest, "Assemble and verify attestation subjects"),
        'scripts/verify_release_assets.sh nightly attest-assets "$GITHUB_SHA"',
        "nightly attestation subject step",
    )
    action_step = require_step(attest, "Generate build provenance attestations")
    if action_step.get("uses") != ATTEST_ACTION:
        raise WorkflowError("nightly job does not use the pinned attestation action")

    publish = require_job(workflow, "publish")
    require_needs(
        publish,
        {"source", "gate", "build", "gui", "sbom", "checksums", "attest"},
        "nightly publication job",
    )
    require_release_process_supervisor(publish, "nightly publication job")
    require_permissions(
        publish,
        {"actions": "read", "contents": "write"},
        "nightly publication job",
    )
    require_exact_command_step(
        publish,
        {
            "name": "Revalidate required workflows immediately before publication",
            "env": {"GH_TOKEN": "${{ github.token }}"},
            "run": WORKFLOW_REVALIDATION_RUN,
        },
        WORKFLOW_REVALIDATION_ARGV,
        "nightly pre-publication workflow gate",
    )
    publish_step = require_step(publish, "Publish immutable nightly release")
    require_argv_line(
        publish_step,
        [
            "scripts/publish_github_release.sh",
            "nightly",
            "$tag",
            "publish-assets",
            "Nightly $GITHUB_SHA",
            "$notes",
        ],
        "nightly publication step",
    )
    require_exact_job_definitions(
        workflow, EXACT_NIGHTLY_JOB_DIGESTS, "nightly workflow"
    )


def verify_gui_workflow(workflow: dict[str, Any]) -> None:
    require_exact_jobs(workflow, GUI_JOBS, "GUI workflow")
    require_exact_shell_topology(workflow, REVIEWED_SHELLS["gui"], "GUI workflow")
    require_permissions(workflow, {"contents": "read"}, "GUI workflow")
    triggers = require_mapping(workflow.get("on"), "GUI workflow triggers")
    if "workflow_call" not in triggers:
        raise WorkflowError("GUI workflow is not reusable through workflow_call")
    for job_name in ("build-frontend", "build-macos", "build-linux", "build-windows"):
        require_unconditional_job(
            require_job(workflow, job_name), f"GUI {job_name} job"
        )
    for job_name in ("build-macos", "build-linux", "build-windows"):
        require_needs(require_job(workflow, job_name), {"build-frontend"}, job_name)
    archive_commands = {
        "build-macos": [
            "python3",
            "scripts/verify_release_archive.py",
            "release/axis-desktop-macos-aarch64.tar.gz",
            "axis-desktop-macos-aarch64",
            "--require",
            "AXIS",
            "--require",
            "RUNTIME_DEPENDENCIES.json",
            "--require",
            "REPRODUCIBILITY.json",
        ],
        "build-linux": [
            "python3",
            "scripts/verify_release_archive.py",
            "release/axis-desktop-linux-x86_64.tar.gz",
            "axis-desktop-linux-x86_64",
            "--require",
            "axis-desktop",
            "--require",
            "web/index.html",
            "--require",
            "RUNTIME_DEPENDENCIES.json",
            "--require",
            "REPRODUCIBILITY.json",
        ],
        "build-windows": [
            "python",
            "scripts/verify_release_archive.py",
            "$archive",
            "axis-desktop-windows-x86_64",
            "--require",
            "AXIS.exe",
            "--require",
            "web/index.html",
            "--require",
            "RUNTIME_DEPENDENCIES.json",
            "--require",
            "REPRODUCIBILITY.json",
        ],
    }
    for job_name, step_name in (
        ("build-macos", "Package deterministic macOS archive"),
        ("build-linux", "Package deterministic Linux archive"),
        ("build-windows", "Package deterministic Windows archive"),
    ):
        step = require_step(require_job(workflow, job_name), step_name)
        if job_name != "build-windows":
            require_argv_line(step, archive_commands[job_name], step_name)
    linux_rebuild = require_step(
        require_job(workflow, "build-linux"),
        "Compare independent clean Linux GUI build",
    )
    require_command_line(
        linux_rebuild,
        "cargo clean --manifest-path gui/linux/Cargo.toml",
        "Linux GUI rebuild step",
    )
    require_command_line(
        linux_rebuild,
        "cargo build --locked --release --manifest-path gui/linux/Cargo.toml",
        "Linux GUI rebuild step",
    )
    require_command_line(
        linux_rebuild,
        'cmp "$RUNNER_TEMP/axis-desktop.first" gui/linux/target/release/axis-desktop',
        "Linux GUI rebuild step",
    )
    require_exact_job_definitions(workflow, EXACT_GUI_JOB_DIGESTS, "GUI workflow")


def verify_ci_workflow(workflow: dict[str, Any]) -> None:
    require_exact_jobs(workflow, CI_JOBS, "CI workflow")
    require_exact_shell_topology(workflow, REVIEWED_SHELLS["ci"], "CI workflow")
    require_permissions(workflow, {"contents": "read"}, "CI workflow")
    require_environment(
        workflow,
        COMMON_RELEASE_ENVIRONMENT | PACKAGE_ENVIRONMENT,
        "CI workflow",
    )
    expected_names = {
        "format": "Format",
        "gui-release-validation": "GUI release validation",
        "clippy": "Clippy",
        "changes": "Detect changes",
        "test-linux": "Test (Linux)",
        "test-macos": "Test (macOS native)",
        "test-linux-netns-helper": "Test Linux netns helper",
        "test-windows": "Test (Windows native)",
        "publication-gate": "CI publication gate",
    }
    expected_runtime = {
        "format": ("ubuntu-24.04", 10, None),
        "clippy": ("ubuntu-24.04", 20, None),
        "changes": (
            "ubuntu-24.04",
            5,
            {"contents": "read", "pull-requests": "read"},
        ),
        "test-linux": ("ubuntu-24.04", 60, None),
        "test-macos": ("macos-14", 45, None),
        "test-linux-netns-helper": ("ubuntu-24.04", 30, None),
        "test-windows": ("windows-2022", 45, None),
        "publication-gate": ("ubuntu-24.04", 5, None),
    }
    for job_name, expected_name in expected_names.items():
        job = require_job(workflow, job_name)
        require_job_name(job, expected_name, f"CI {job_name} job")
        if job_name == "publication-gate":
            require_job_condition(job, ALWAYS_CONDITION, "CI publication gate job")
        else:
            require_unconditional_job(job, f"CI {job_name} job")
        require_no_strategy(job, f"CI {job_name} job")
        if job_name != "gui-release-validation":
            runner, timeout, permissions = expected_runtime[job_name]
            require_job_runtime(
                job, runner, timeout, f"CI {job_name} job", permissions
            )
            reject_step_bypasses(job, f"CI {job_name} job")

    gui = require_job(workflow, "gui-release-validation")
    require_needs(gui, {"changes"}, "CI GUI validation job")
    require_permissions(gui, {"contents": "read"}, "CI GUI validation job")
    if gui != {
        "name": "GUI release validation",
        "needs": "changes",
        "uses": GUI_WORKFLOW,
        "permissions": {"contents": "read"},
    }:
        raise WorkflowError("CI GUI validation does not call the reviewed workflow")
    for job_name in (
        "format",
        "clippy",
        "changes",
    ):
        require_needs(require_job(workflow, job_name), set(), f"CI {job_name} job")
    changes = require_job(workflow, "changes")
    expected_changes_checkout = {
        "uses": CHECKOUT_ACTION,
        "with": {"fetch-depth": 0, "persist-credentials": False},
    }
    changes_steps = changes.get("steps")
    if not isinstance(changes_steps, list) or changes_steps[:1] != [
        expected_changes_checkout
    ]:
        raise WorkflowError(
            "CI change detection checkout must fetch complete history without "
            "persisting credentials"
        )
    if len(changes_steps) < 2:
        raise WorkflowError("CI change detection must use local git history")
    filter_step = changes_steps[1]
    filter_inputs = filter_step.get("with")
    if (
        filter_step.get("uses") != PATHS_FILTER_ACTION
        or filter_step.get("id") != "filter"
        or not isinstance(filter_inputs, dict)
        or filter_inputs.get("token") != ""
    ):
        raise WorkflowError(
            "CI change detection must use local git history without an API token"
        )
    for job_name in (
        "test-linux",
        "test-macos",
        "test-linux-netns-helper",
        "test-windows",
    ):
        require_needs(
            require_job(workflow, job_name), {"changes"}, f"CI {job_name} job"
        )
    publication = require_job(workflow, "publication-gate")
    require_needs(
        publication, set(CI_JOBS) - {"publication-gate"}, "CI publication gate"
    )
    require_exact_gate_step(
        publication,
        "Require every publication CI job to succeed",
        {
            "FORMAT_RESULT": "${{ needs.format.result }}",
            "GUI_RESULT": "${{ needs.gui-release-validation.result }}",
            "CLIPPY_RESULT": "${{ needs.clippy.result }}",
            "CHANGES_RESULT": "${{ needs.changes.result }}",
            "LINUX_RESULT": "${{ needs.test-linux.result }}",
            "MACOS_RESULT": "${{ needs.test-macos.result }}",
            "NETNS_RESULT": "${{ needs.test-linux-netns-helper.result }}",
            "WINDOWS_RESULT": "${{ needs.test-windows.result }}",
        },
        """set -euo pipefail
for result in "$FORMAT_RESULT" "$GUI_RESULT" "$CLIPPY_RESULT" \\
  "$CHANGES_RESULT" "$LINUX_RESULT" "$MACOS_RESULT" \\
  "$NETNS_RESULT" "$WINDOWS_RESULT"; do
  test "$result" = success
done
""",
    )
    linux = require_job(workflow, "test-linux")
    sandbox_dependencies = require_step(linux, "Install Linux sandbox dependencies")
    require_command_line(
        sandbox_dependencies,
        "bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true",
        "CI Bubblewrap availability proof",
    )
    require_command_line(
        sandbox_dependencies,
        'printf \'%s\\n\' "$userns_restriction" > "$RUNNER_TEMP/axis-apparmor-userns"',
        "CI user namespace state capture",
        controls=(
            "if ! bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true; then",
        ),
    )
    mxc_step = require_step(linux, "Build MXC Linux executor")
    require_command_line(mxc_step, MXC_BUILD_COMMAND, "CI MXC build step")
    require_command_line(
        mxc_step,
        'cp "$mxc_dir/src/target/release/lxc-exec" target/release/lxc-exec',
        "CI MXC build step",
    )
    windows = require_job(workflow, "test-windows")
    windows_mxc_step = require_step(windows, "Build pinned MXC Windows executor")
    if windows_mxc_step != {
        "name": "Build pinned MXC Windows executor",
        "shell": "pwsh",
        "run": """$mxcDir = Join-Path $env:RUNNER_TEMP "mxc"
git clone --filter=blob:none $env:MXC_REPOSITORY $mxcDir
git -C $mxcDir checkout $env:MXC_REF
Get-ChildItem (Join-Path $env:GITHUB_WORKSPACE "third_party\\mxc\\patches\\*.patch") |
  Sort-Object Name | ForEach-Object { git -C $mxcDir apply --whitespace=error $_.FullName }
Push-Location (Join-Path $mxcDir "src")
cargo build --release -p wxc --no-default-features --locked
Pop-Location
Copy-Item (Join-Path $mxcDir "src\\target\\release\\wxc-exec.exe") target\\release\\wxc-exec.exe
""",
    }:
        raise WorkflowError("CI MXC Windows build step is not exact")
    require_exact_command_step(
        windows,
        {
            "name": "Windows MXC ProcessContainer smoke and security tests",
            "shell": "pwsh",
            "env": {
                "AXIS_RUN_MXC_BASECONTAINER_E2E": "1",
                "AXIS_SKIP_UNAVAILABLE_MXC_BASECONTAINER_E2E": "1",
                "AXIS_TEST_MXC_EXECUTOR": "${{ github.workspace }}\\target\\release\\wxc-exec.exe",
            },
            "run": (
                "pwsh -NoProfile -File e2e/windows/test_mxc_processcontainer.ps1 "
                "-AxisBin ./target/release/axis.exe"
            ),
        },
        [
            "pwsh",
            "-NoProfile",
            "-File",
            "e2e/windows/test_mxc_processcontainer.ps1",
            "-AxisBin",
            "./target/release/axis.exe",
        ],
        "CI Windows MXC smoke step",
    )
    package_step = require_step(linux, "Build and inspect Linux native packages")
    require_command_line(
        package_step,
        'cargo install cargo-deb --version "$CARGO_DEB_VERSION" --locked',
        "CI Debian package build",
    )
    require_command_line(
        package_step,
        'cargo install cargo-generate-rpm --version "$CARGO_GENERATE_RPM_VERSION" --locked',
        "CI RPM package build",
    )
    require_command_line(
        package_step,
        "cargo generate-rpm -p crates/axis-daemon",
        "CI RPM package build",
    )
    require_command_line(
        package_step,
        'scripts/verify_linux_package_manifest.sh deb "$deb"',
        "CI Debian package verification",
    )
    userns_restore = require_step(
        linux,
        "Restore Linux user namespace restriction",
        condition=ALWAYS_CONDITION,
    )
    require_command_line(
        userns_restore,
        'state="$RUNNER_TEMP/axis-apparmor-userns"',
        "CI user namespace restoration state",
    )
    require_command_line(
        userns_restore,
        'sudo -n sysctl -q -w "kernel.apparmor_restrict_unprivileged_userns=$(cat "$state")"',
        "CI user namespace restoration",
        controls=('if [ -f "$state" ]; then',),
    )
    netns = require_job(workflow, "test-linux-netns-helper")
    netns_dependencies = require_step(netns, "Install kernel namespace tooling")
    netns_proof = (
        "timeout --kill-after=1s 5s bwrap --unshare-user --uid 0 --gid 0 "
        "--ro-bind / / -- true"
    )
    require_command_line(
        netns_dependencies,
        netns_proof,
        "CI netns Bubblewrap availability proof",
    )
    netns_userns_control = (
        "if ! timeout --kill-after=1s 5s "
        "bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true; then"
    )
    netns_state_read = (
        'userns_restriction="$(timeout --kill-after=1s 5s '
        'sysctl -n kernel.apparmor_restrict_unprivileged_userns)"'
    )
    require_command_line(
        netns_dependencies,
        netns_state_read,
        "CI netns user namespace state read",
        controls=(netns_userns_control,),
    )
    netns_state_validation = 'test "$userns_restriction" = "1"'
    require_command_line(
        netns_dependencies,
        netns_state_validation,
        "CI netns user namespace expected state",
        controls=(netns_userns_control,),
    )
    netns_state_capture = (
        'printf \'%s\\n\' "$userns_restriction" '
        '> "$RUNNER_TEMP/axis-netns-helper-apparmor-userns"'
    )
    require_command_line(
        netns_dependencies,
        netns_state_capture,
        "CI netns user namespace state capture",
        controls=(netns_userns_control,),
    )
    netns_provision = (
        "timeout --kill-after=1s 7s sudo -n timeout --kill-after=1s 5s "
        "sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0"
    )
    require_command_line(
        netns_dependencies,
        netns_provision,
        "CI netns user namespace provisioning",
        controls=(netns_userns_control,),
    )
    require_exclusive_sysctl_write(
        netns_dependencies,
        "kernel.apparmor_restrict_unprivileged_userns",
        netns_provision,
        "CI netns user namespace provisioning",
        controls=(netns_userns_control,),
    )
    require_command_sequence(
        netns_dependencies,
        [
            (netns_state_read, (netns_userns_control,)),
            (netns_state_validation, (netns_userns_control,)),
            (netns_state_capture, (netns_userns_control,)),
            (netns_provision, (netns_userns_control,)),
            (netns_proof, ()),
        ],
        "CI netns user namespace provisioning sequence",
    )
    netns_userns_restore = require_step(
        netns,
        "Restore helper user namespace restriction",
        condition=ALWAYS_CONDITION,
    )
    if netns_userns_restore.get("timeout-minutes") != 2:
        raise WorkflowError("CI netns user namespace restoration requires a 2 minute timeout")
    require_command_line(
        netns_userns_restore,
        'state="$RUNNER_TEMP/axis-netns-helper-apparmor-userns"',
        "CI netns user namespace restoration state",
    )
    netns_restore = (
        'timeout --kill-after=1s 7s sudo -n timeout --kill-after=1s 5s '
        'sysctl -q -w "kernel.apparmor_restrict_unprivileged_userns=$(cat "$state")"'
    )
    require_command_line(
        netns_userns_restore,
        netns_restore,
        "CI netns user namespace restoration",
        controls=('if [ -f "$state" ]; then',),
    )
    require_exclusive_sysctl_write(
        netns_userns_restore,
        "kernel.apparmor_restrict_unprivileged_userns",
        netns_restore,
        "CI netns user namespace restoration",
        controls=('if [ -f "$state" ]; then',),
    )
    require_command_line(
        netns_userns_restore,
        'rm -f "$state"',
        "CI netns user namespace restoration marker cleanup",
        controls=('if [ -f "$state" ]; then',),
    )
    require_command_line(
        package_step,
        'scripts/verify_linux_package_manifest.sh rpm "$rpm_path"',
        "CI RPM package verification",
    )
    checksum_test = require_step(
        require_job(workflow, "test-windows"),
        "Reject invalid Windows installer checksums",
    )
    if checksum_test != {
        "name": "Reject invalid Windows installer checksums",
        "shell": "pwsh",
        "run": ".\\scripts\\test_installers.ps1",
    }:
        raise WorkflowError("Windows checksum rejection test is not exact")
    require_exact_command_step(
        require_job(workflow, "test-windows"),
        {
            "name": "PowerShell installer bounded output tests",
            "shell": "pwsh",
            "run": "python -m unittest scripts.test_installers.PowerShellInstallerTests",
        },
        [
            "python",
            "-m",
            "unittest",
            "scripts.test_installers.PowerShellInstallerTests",
        ],
        "PowerShell installer bounded output tests",
    )


def verify_security_workflow(workflow: dict[str, Any]) -> None:
    require_exact_jobs(workflow, SECURITY_JOBS, "security workflow")
    require_exact_shell_topology(
        workflow, REVIEWED_SHELLS["security"], "security workflow"
    )
    require_permissions(workflow, {"contents": "read"}, "security workflow")
    expected_names = {
        "codeql": "CodeQL (${{ matrix.language }})",
        "codeql-swift": "CodeQL (swift)",
        "dependency-review": "Dependency review",
        "dependency-audit": "Dependency audit",
        "windows-nuget-audit": "Windows NuGet audit",
        "python-sast": "Python SAST",
        "secret-scan": "Secret scan",
        "actions-security": "GitHub Actions security",
        "publication-gate": "Security publication gate",
    }
    expected_runtime = {
        "codeql": (
            "ubuntu-24.04",
            30,
            {"actions": "read", "contents": "read", "security-events": "write"},
        ),
        "codeql-swift": (
            "macos-14",
            30,
            {"actions": "read", "contents": "read", "security-events": "write"},
        ),
        "dependency-review": ("ubuntu-24.04", 10, None),
        "dependency-audit": ("ubuntu-24.04", 20, None),
        "windows-nuget-audit": ("windows-latest", 15, None),
        "python-sast": ("ubuntu-24.04", 10, None),
        "secret-scan": ("ubuntu-24.04", 15, None),
        "actions-security": ("ubuntu-24.04", 10, None),
        "publication-gate": ("ubuntu-24.04", 5, None),
    }
    for job_name, expected_name in expected_names.items():
        job = require_job(workflow, job_name)
        require_job_name(job, expected_name, f"security {job_name} job")
        if job_name == "dependency-review":
            require_job_condition(
                job, "github.event_name == 'pull_request'", "dependency review job"
            )
        elif job_name == "publication-gate":
            require_job_condition(job, ALWAYS_CONDITION, "security publication gate")
        else:
            require_unconditional_job(job, f"security {job_name} job")
        runner, timeout, permissions = expected_runtime[job_name]
        require_job_runtime(
            job, runner, timeout, f"security {job_name} job", permissions
        )
        reject_step_bypasses(job, f"security {job_name} job")

    codeql = require_job(workflow, "codeql")
    expected_strategy = {
        "fail-fast": False,
        "matrix": {"language": ["rust", "javascript-typescript", "csharp"]},
    }
    if codeql.get("strategy") != expected_strategy:
        raise WorkflowError("security CodeQL job has wrong matrix topology")
    for job_name in SECURITY_JOBS - {"codeql"}:
        require_no_strategy(require_job(workflow, job_name), f"security {job_name} job")

    for job_name in SECURITY_JOBS - {"publication-gate"}:
        require_needs(
            require_job(workflow, job_name), set(), f"security {job_name} job"
        )
    publication = require_job(workflow, "publication-gate")
    require_needs(
        publication,
        SECURITY_JOBS - {"publication-gate", "dependency-review"},
        "security publication gate",
    )
    require_exact_gate_step(
        publication,
        "Require every publication security job to succeed",
        {
            "CODEQL_RESULT": "${{ needs.codeql.result }}",
            "SWIFT_RESULT": "${{ needs.codeql-swift.result }}",
            "AUDIT_RESULT": "${{ needs.dependency-audit.result }}",
            "NUGET_RESULT": "${{ needs.windows-nuget-audit.result }}",
            "SAST_RESULT": "${{ needs.python-sast.result }}",
            "SECRETS_RESULT": "${{ needs.secret-scan.result }}",
            "ACTIONS_RESULT": "${{ needs.actions-security.result }}",
        },
        """set -euo pipefail
for result in "$CODEQL_RESULT" "$SWIFT_RESULT" "$AUDIT_RESULT" \\
  "$NUGET_RESULT" "$SAST_RESULT" "$SECRETS_RESULT" \\
  "$ACTIONS_RESULT"; do
  test "$result" = success
done
""",
    )

    require_action_step(
        require_job(workflow, "dependency-review"),
        "Reject vulnerable dependency changes",
        "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294",
    )
    python_sast = require_job(workflow, "python-sast")
    bandit_install_step = {
        "name": "Install Bandit",
        "run": (
            "python -m pip install --disable-pip-version-check --require-hashes "
            "-r .github/security-requirements.txt"
        ),
    }
    require_exact_command_step(
        python_sast,
        bandit_install_step,
        [
            "python",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--require-hashes",
            "-r",
            ".github/security-requirements.txt",
        ],
        "Bandit installation step",
    )
    bandit_scan_step = {
        "name": "Scan Python sources",
        "run": (
            "bandit --severity-level high --confidence-level high --quiet "
            "e2e/linux/test_hip_sandbox.py scripts/bounded_subprocess.py "
            "scripts/bounded_tar.py scripts/generate_third_party_notices.py "
            "scripts/release_tools.py scripts/verify_release_archive.py"
        ),
    }
    require_exact_command_step(
        python_sast,
        bandit_scan_step,
        [
            "bandit",
            "--severity-level",
            "high",
            "--confidence-level",
            "high",
            "--quiet",
            "e2e/linux/test_hip_sandbox.py",
            "scripts/bounded_subprocess.py",
            "scripts/bounded_tar.py",
            "scripts/generate_third_party_notices.py",
            "scripts/release_tools.py",
            "scripts/verify_release_archive.py",
        ],
        "Bandit scan step",
    )
    require_exact_job_steps(
        python_sast,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {"persist-credentials": False},
            },
            {
                "uses": PYTHON_ACTION,
                "with": {
                    "python-version": "3.12",
                    "cache": "pip",
                    "cache-dependency-path": ".github/security-requirements.txt",
                },
            },
            bandit_install_step,
            bandit_scan_step,
        ],
        "Bandit scan job",
    )
    secret_scan = require_job(workflow, "secret-scan")
    gitleaks_step = {
        "name": "Scan branch history with Gitleaks",
        "run": (
            "go run github.com/zricethezav/gitleaks/v8@v8.30.1 git "
            "--log-opts=HEAD --redact --no-banner --exit-code 1 ."
        ),
    }
    require_exact_command_step(
        secret_scan,
        gitleaks_step,
        [
            "go",
            "run",
            "github.com/zricethezav/gitleaks/v8@v8.30.1",
            "git",
            "--log-opts=HEAD",
            "--redact",
            "--no-banner",
            "--exit-code",
            "1",
            ".",
        ],
        "Gitleaks scan step",
    )
    require_exact_job_steps(
        secret_scan,
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {"fetch-depth": 0, "persist-credentials": False},
            },
            {"uses": GO_ACTION, "with": {"go-version": "1.25.12"}},
            gitleaks_step,
        ],
        "Gitleaks scan job",
    )
    require_exact_job_steps(
        require_job(workflow, "actions-security"),
        [
            {
                "uses": CHECKOUT_ACTION,
                "with": {"persist-credentials": False},
            },
            {
                "name": "Audit workflows with Zizmor",
                "uses": ZIZMOR_ACTION,
                "with": {
                    "advanced-security": False,
                    "min-severity": "medium",
                    "online-audits": False,
                    "persona": "regular",
                    "version": "1.26.1",
                },
            },
        ],
        "Zizmor audit job",
    )
    for job_name in ("codeql", "codeql-swift"):
        require_action_step(
            require_job(workflow, job_name),
            "Initialize CodeQL",
            "github/codeql-action/init@1ad29ea4a422cce9a242a9fae469541dcd08addc",
        )
        require_action_step(
            require_job(workflow, job_name),
            "Analyze",
            "github/codeql-action/analyze@1ad29ea4a422cce9a242a9fae469541dcd08addc",
        )


def verify_repository_workflows(repository_root: Path) -> None:
    workflows = repository_root / ".github/workflows"
    verify_release_workflow(load_workflow(workflows / "release.yml"))
    verify_nightly_workflow(load_workflow(workflows / "nightly.yml"))
    verify_gui_workflow(load_workflow(workflows / "gui-release.yml"))
    verify_ci_workflow(load_workflow(workflows / "ci.yml"))
    verify_security_workflow(load_workflow(workflows / "security.yml"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository_root", type=Path)
    arguments = parser.parse_args()
    try:
        verify_repository_workflows(arguments.repository_root.resolve())
    except WorkflowError as error:
        parser.exit(1, f"error: {error}\n")
    print("Release workflow structure: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
