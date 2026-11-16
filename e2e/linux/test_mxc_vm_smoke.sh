#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated MXC VM-style runtime smoke tests.
#
# These tests intentionally do not install MXC, change host VM/container
# settings, or require privileged setup. They run only when a caller opts into
# a concrete VM backend and provides the matching MXC executor through PATH or
# AXIS_TEST_MXC_EXECUTOR.
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
        fail "python3 is required to generate MXC VM smoke configs"
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

require_kvm() {
    if [ ! -e /dev/kvm ]; then
        fail "/dev/kvm is required for Linux MXC VM smoke tests"
        return 1
    fi
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        fail "/dev/kvm must be readable and writable by the current user"
        return 1
    fi
}

write_config() {
    local config=$1
    local containment=$2
    local timeout_ms=$3
    local network_policy=$4
    local rw_path=${5:-}

    python3 - "$config" "$containment" "$timeout_ms" "$network_policy" "$rw_path" <<'PY'
import json
import sys

config_path, containment, timeout_ms, network_policy, rw_path = sys.argv[1:]
code = sys.stdin.read()
# MicroVM and Hyperlight are only in the MXC 1.1.0-alpha development contract.
config = {
    "version": "1.1.0-alpha",
    "containerId": f"axis-mxc-smoke-{containment}",
    "containment": containment,
    "process": {
        "commandLine": code,
        "timeout": int(timeout_ms),
    },
    "filesystem": {
        "readwritePaths": [],
        "readonlyPaths": [],
        "deniedPaths": [],
    },
    "lifecycle": {
        "destroyOnExit": True,
        "preservePolicy": False,
    },
}
if network_policy != "block":
    raise SystemExit(f"unsupported smoke network policy: {network_policy}")
if containment != "hyperlight":
    # Hyperlight accepts only MXC's default-deny posture, expressed by
    # omitting the network section.
    config["network"] = {
        "egress": {"default": "deny"},
        "ingress": {"default": "deny", "hostLoopback": "deny"},
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

    if run_config "$config" "$output" 120; then
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

    if run_config "$config" "$output" 120; then
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

    if run_config "$config" "$output" 140; then
        fail "$label unexpectedly exited successfully"
        sed -n '1,120p' "$output"
    elif grep -q "AXIS_MXC_TIMEOUT_BAD" "$output"; then
        fail "$label printed the post-timeout marker"
        sed -n '1,120p' "$output"
    elif grep -Eiq "timed out|timeout" "$output"; then
        pass "$label"
    else
        fail "$label failed without timeout evidence"
        sed -n '1,120p' "$output"
    fi
}

run_microvm() {
    echo "--- MXC MicroVM smoke ---"
    require_kvm || return 0

    local config output share marker
    config="$TMPDIR/microvm-stdout.json"
    output="$TMPDIR/microvm-stdout.out"
    write_config "$config" microvm 30000 block <<'PY'
print("AXIS_MXC_MICROVM_STDOUT")
PY
    expect_success_marker "microvm command stdout" "$config" "$output" "AXIS_MXC_MICROVM_STDOUT"

    config="$TMPDIR/microvm-stderr.json"
    output="$TMPDIR/microvm-stderr.out"
    write_config "$config" microvm 30000 block <<'PY'
import sys
print("AXIS_MXC_MICROVM_STDERR", file=sys.stderr)
raise SystemExit(7)
PY
    expect_failure_marker "microvm stderr and exit code" "$config" "$output" "AXIS_MXC_MICROVM_STDERR"

    share="$(mktemp -d "$TMPDIR/microvm-rw.XXXXXX")"
    marker="$share/axis-mxc-microvm-marker.txt"
    config="$TMPDIR/microvm-filesystem.json"
    output="$TMPDIR/microvm-filesystem.out"
    write_config "$config" microvm 30000 block "$share" <<PY
with open("$marker", "w", encoding="utf-8") as handle:
    handle.write("microvm copyback\\n")
print("AXIS_MXC_MICROVM_FILESYSTEM")
PY
    expect_success_marker "microvm readwrite copyback" "$config" "$output" "AXIS_MXC_MICROVM_FILESYSTEM"
    if [ -f "$marker" ] && grep -q "microvm copyback" "$marker"; then
        pass "microvm copied staged write back to host path"
    else
        fail "microvm did not copy staged write back to host path"
    fi

    config="$TMPDIR/microvm-timeout.json"
    output="$TMPDIR/microvm-timeout.out"
    write_config "$config" microvm 1000 block <<'PY'
import time
time.sleep(120)
print("AXIS_MXC_TIMEOUT_BAD")
PY
    expect_timeout "microvm timeout" "$config" "$output"
}

run_hyperlight() {
    echo "--- MXC Hyperlight smoke ---"
    require_kvm || return 0

    local config output share marker
    config="$TMPDIR/hyperlight-stdout.json"
    output="$TMPDIR/hyperlight-stdout.out"
    write_config "$config" hyperlight 30000 block <<'PY'
print("AXIS_MXC_HYPERLIGHT_STDOUT")
PY
    expect_success_marker "hyperlight command stdout" "$config" "$output" "AXIS_MXC_HYPERLIGHT_STDOUT"

    config="$TMPDIR/hyperlight-stderr.json"
    output="$TMPDIR/hyperlight-stderr.out"
    write_config "$config" hyperlight 30000 block <<'PY'
import sys
print("AXIS_MXC_HYPERLIGHT_STDERR", file=sys.stderr)
raise SystemExit(7)
PY
    expect_failure_marker "hyperlight stderr and exit code" "$config" "$output" "AXIS_MXC_HYPERLIGHT_STDERR"

    share="$(mktemp -d "$TMPDIR/hyperlight-rw.XXXXXX")"
    marker="$share/axis-mxc-hyperlight-marker.txt"
    config="$TMPDIR/hyperlight-filesystem.json"
    output="$TMPDIR/hyperlight-filesystem.out"
    write_config "$config" hyperlight 30000 block "$share" <<PY
with open("/host/$(basename "$share")/axis-mxc-hyperlight-marker.txt", "w", encoding="utf-8") as handle:
    handle.write("hyperlight preopen\\n")
print("AXIS_MXC_HYPERLIGHT_FILESYSTEM")
PY
    expect_success_marker "hyperlight readwrite preopen" "$config" "$output" "AXIS_MXC_HYPERLIGHT_FILESYSTEM"
    if [ -f "$marker" ] && grep -q "hyperlight preopen" "$marker"; then
        pass "hyperlight wrote through preopened host path"
    else
        fail "hyperlight did not write through preopened host path"
    fi

    config="$TMPDIR/hyperlight-timeout.json"
    output="$TMPDIR/hyperlight-timeout.out"
    write_config "$config" hyperlight 1000 block <<'PY'
import time
time.sleep(120)
print("AXIS_MXC_TIMEOUT_BAD")
PY
    expect_timeout "hyperlight timeout" "$config" "$output"
}

if [ "${AXIS_RUN_MXC_MICROVM_E2E:-}" != "1" ] && [ "${AXIS_RUN_MXC_HYPERLIGHT_E2E:-}" != "1" ]; then
    skip "set AXIS_RUN_MXC_MICROVM_E2E=1 or AXIS_RUN_MXC_HYPERLIGHT_E2E=1"
    summary
    exit $?
fi

TMPDIR="$(mktemp -d /tmp/axis-mxc-vm.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

need_python || {
    summary
    exit 1
}
resolve_executor || {
    summary
    exit 1
}

echo "=== AXIS MXC VM Smoke ==="
echo "executor: $EXECUTOR"
echo "tmpdir: $TMPDIR"
echo ""

if [ "${AXIS_RUN_MXC_MICROVM_E2E:-}" = "1" ]; then
    run_microvm
fi

if [ "${AXIS_RUN_MXC_HYPERLIGHT_E2E:-}" = "1" ]; then
    run_hyperlight
fi

summary
