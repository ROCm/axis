#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated Linux MXC LXC runtime smoke tests.
#
# These tests do not install MXC, configure LXC, or mutate host runtime state.
# They run only when a caller opts into LXC and provides the matching MXC
# executor through PATH or AXIS_TEST_MXC_EXECUTOR.
set -euo pipefail

PASS=0
FAIL=0
SKIP=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

summary() {
    echo ""
    echo "  Result: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
    [ "$FAIL" -eq 0 ]
}

need_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 is required to generate MXC LXC smoke configs"
        return 1
    fi
}

resolve_executor() {
    if [ -n "${AXIS_TEST_MXC_EXECUTOR:-}" ]; then
        if [ ! -x "$AXIS_TEST_MXC_EXECUTOR" ]; then
            fail "AXIS_TEST_MXC_EXECUTOR is not executable: $AXIS_TEST_MXC_EXECUTOR"
            return 1
        fi
        EXECUTOR="$AXIS_TEST_MXC_EXECUTOR"
        return 0
    fi

    if EXECUTOR="$(command -v lxc-exec 2>/dev/null)"; then
        return 0
    fi

    fail "set AXIS_TEST_MXC_EXECUTOR or provide lxc-exec on PATH"
    return 1
}

write_config() {
    local config=$1
    local timeout_ms=$2
    local network_policy=$3
    local rw_path=${4:-}

    python3 - "$config" "$timeout_ms" "$network_policy" "$DISTRIBUTION" "$RELEASE" "$rw_path" <<'PY'
import json
import sys

config_path, timeout_ms, network_policy, distribution, release, rw_path = sys.argv[1:]
command = sys.stdin.read()
network_postures = {
    "block": {
        "egress": {"default": "deny"},
        "ingress": {"default": "deny", "hostLoopback": "deny"},
    },
}
config = {
    "version": "1.0.0",
    "containerId": "axis-mxc-lxc-smoke",
    "containment": "lxc",
    "process": {
        "commandLine": command,
        "timeout": int(timeout_ms),
    },
    "filesystem": {
        "readwritePaths": [],
        "readonlyPaths": [],
        "deniedPaths": [],
    },
    "network": network_postures[network_policy],
    "lifecycle": {
        "destroyOnExit": True,
        "preservePolicy": False,
    },
    "lxc": {
        "distribution": distribution,
        "release": release,
    },
}
if rw_path:
    config["filesystem"]["readwritePaths"].append(rw_path)

with open(config_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
}

run_config() {
    local config=$1
    local output=$2
    local seconds=$3

    set +e
    timeout "$seconds" "$EXECUTOR" --experimental --config "$config" >"$output" 2>&1
    local status=$?
    set -e
    return "$status"
}

expect_success_marker() {
    local label=$1
    local config=$2
    local output=$3
    local marker=$4

    if run_config "$config" "$output" 180; then
        if grep -q "$marker" "$output"; then
            pass "$label"
        else
            fail "$label did not print marker $marker"
            sed -n '1,120p' "$output"
        fi
    else
        fail "$label failed to execute"
        sed -n '1,120p' "$output"
    fi
}

expect_failure_marker() {
    local label=$1
    local config=$2
    local output=$3
    local marker=$4

    if run_config "$config" "$output" 180; then
        fail "$label unexpectedly exited successfully"
        sed -n '1,120p' "$output"
    elif grep -q "$marker" "$output"; then
        pass "$label"
    else
        fail "$label failed without marker $marker"
        sed -n '1,120p' "$output"
    fi
}

expect_timeout() {
    local label=$1
    local config=$2
    local output=$3

    if run_config "$config" "$output" 180; then
        fail "$label unexpectedly exited successfully"
        sed -n '1,120p' "$output"
    elif grep -q "AXIS_MXC_LXC_TIMEOUT_BAD" "$output"; then
        fail "$label printed the post-timeout marker"
        sed -n '1,120p' "$output"
    elif grep -Eiq "timed out|timeout" "$output"; then
        pass "$label"
    else
        fail "$label failed without timeout evidence"
        sed -n '1,120p' "$output"
    fi
}

if [ "${AXIS_RUN_MXC_LXC_E2E:-}" != "1" ]; then
    skip "set AXIS_RUN_MXC_LXC_E2E=1"
    summary
    exit $?
fi

DISTRIBUTION=${AXIS_MXC_LXC_DISTRIBUTION:-alpine}
RELEASE=${AXIS_MXC_LXC_RELEASE:-3.23}

TMPDIR="$(mktemp -d /tmp/axis-mxc-lxc.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

need_python || {
    summary
    exit 1
}
resolve_executor || {
    summary
    exit 1
}

echo "=== AXIS MXC LXC Smoke ==="
echo "executor: $EXECUTOR"
echo "distribution: $DISTRIBUTION"
echo "release: $RELEASE"
echo "tmpdir: $TMPDIR"
echo ""

config="$TMPDIR/lxc-stdout.json"
output="$TMPDIR/lxc-stdout.out"
write_config "$config" 30000 block <<'SH'
sh -c 'echo AXIS_MXC_LXC_STDOUT'
SH
expect_success_marker "lxc command stdout" "$config" "$output" "AXIS_MXC_LXC_STDOUT"

config="$TMPDIR/lxc-stderr.json"
output="$TMPDIR/lxc-stderr.out"
write_config "$config" 30000 block <<'SH'
sh -c 'echo AXIS_MXC_LXC_STDERR >&2; exit 7'
SH
expect_failure_marker "lxc stderr and exit code" "$config" "$output" "AXIS_MXC_LXC_STDERR"

share="$(mktemp -d "$TMPDIR/lxc-rw.XXXXXX")"
marker="$share/axis-mxc-lxc-marker.txt"
config="$TMPDIR/lxc-filesystem.json"
output="$TMPDIR/lxc-filesystem.out"
write_config "$config" 30000 block "$share" <<SH
sh -c 'echo lxc-write > "$marker"; echo AXIS_MXC_LXC_FILESYSTEM'
SH
expect_success_marker "lxc readwrite filesystem" "$config" "$output" "AXIS_MXC_LXC_FILESYSTEM"
if [ -f "$marker" ] && grep -q "lxc-write" "$marker"; then
    pass "lxc wrote through readwrite host path"
else
    fail "lxc did not write through readwrite host path"
fi

config="$TMPDIR/lxc-timeout.json"
output="$TMPDIR/lxc-timeout.out"
write_config "$config" 1000 block <<'SH'
sh -c 'sleep 120; echo AXIS_MXC_LXC_TIMEOUT_BAD'
SH
expect_timeout "lxc timeout" "$config" "$output"

summary
