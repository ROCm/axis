#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Unprivileged Linux e2e proof for axisd + axis CLI lifecycle behavior.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
AXIS="${AXIS_BIN:-${1:-${REPO_ROOT}/target/release/axis}}"
if [ ! -x "$AXIS" ] && [ -x "${REPO_ROOT}/target/debug/axis" ]; then
    AXIS="${REPO_ROOT}/target/debug/axis"
fi
if [ -x "$AXIS" ]; then
    AXIS="$(cd "$(dirname "$AXIS")" && pwd)/$(basename "$AXIS")"
fi
AXSD="${AXIS%axis}axisd"

PASS=0
FAIL=0
SKIP=0
TMP_ROOT="$(mktemp -d /tmp/axis-daemon-e2e-XXXXXX)"
SOCKET="${TMP_ROOT}/axis.sock"
AXSD_PID=""
READY_WORKSPACE=""
READY_PID=""

cleanup() {
    if [ -n "$AXSD_PID" ]; then
        kill "$AXSD_PID" 2>/dev/null || true
        wait "$AXSD_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

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

capability_skip_output() {
    grep -Fq "resources: process count rlimit fallback requires a dedicated run_as_user" <<<"$1" ||
        grep -Fq "resources: CPU rate limits require writable cgroups v2" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is unavailable" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is read-only" <<<"$1" ||
        grep -Fq "seccomp: seccomp is unavailable" <<<"$1" ||
        grep -Fq "filesystem: Landlock unavailable" <<<"$1" ||
        grep -Fq "bwrap: setting up uid map: Permission denied" <<<"$1" ||
        grep -Fq "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" <<<"$1"
}

require_binaries() {
    if [ ! -x "$AXIS" ]; then
        echo "ERROR: axis binary not found: $AXIS"
        echo "Build it with: cargo build --locked --release -p axis-cli -p axis-daemon"
        exit 1
    fi
    if [ ! -x "$AXSD" ]; then
        echo "ERROR: axisd binary not found: $AXSD"
        echo "Build it with: cargo build --locked --release -p axis-cli -p axis-daemon"
        exit 1
    fi
}

new_case_dir() {
    mktemp -d "${TMP_ROOT}/case-XXXXXX"
}

append_read_only_path() {
    local path="$1"
    [ -e "$path" ] || return 0
    printf '    - %s\n' "$path" >>"$POLICY_FILE"
}

write_policy() {
    local mode="$1"
    local timeout="${2:-}"
    local dir
    dir="$(new_case_dir)"
    POLICY_FILE="${dir}/policy.yaml"
    cat >"$POLICY_FILE" <<EOF
version: 1
name: daemon-e2e-${mode}

runtime:
  containment: process
  provider: axis_native

filesystem:
  compatibility: hard_requirement
  read_only:
EOF
    append_read_only_path /bin
    append_read_only_path /sbin
    append_read_only_path /usr
    append_read_only_path /lib
    append_read_only_path /lib64
    append_read_only_path /etc
    append_read_only_path /nix/store
    cat >>"$POLICY_FILE" <<EOF
  read_write:
    - "{workspace}"
    - /dev/null

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
EOF
    if [ -n "$timeout" ]; then
        printf '  timeout_sec: %s\n' "$timeout" >>"$POLICY_FILE"
    fi
    cat >>"$POLICY_FILE" <<EOF

network:
  mode: ${mode}
EOF
    printf '%s\n' "$POLICY_FILE"
}

axis_cli() {
    "$AXIS" --socket "$SOCKET" "$@"
}

wait_for_socket() {
    for _ in $(seq 1 50); do
        [ -S "$SOCKET" ] && return 0
        sleep 0.1
    done
    return 1
}

create_sandbox() {
    local policy="$1"
    local command="$2"
    local output
    output="$(axis_cli create --policy "$policy" -- /bin/sh -c "$command" 2>&1)"
    local status=$?
    CREATE_OUTPUT="$output"
    if [ "$status" -ne 0 ]; then
        if capability_skip_output "$output"; then
            return 77
        fi
        return 1
    fi
    SANDBOX_ID="$(grep -oE '[0-9a-f]{8}-[0-9a-f-]{27}' <<<"$output" | head -n1)"
    [ -n "$SANDBOX_ID" ]
}

wait_for_absent() {
    local id="$1"
    for _ in $(seq 1 60); do
        if ! axis_cli list 2>/dev/null | grep -q "$id"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

sandbox_workspace() {
    local id="$1"
    axis_cli list | awk -v id="$id" '$1 == id {print $4; exit}'
}

pid_alive() {
    local pid="$1"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

wait_for_sandbox_child() {
    local id="$1"
    local attempts="${2:-50}"
    local workspace=""
    local pid=""
    READY_WORKSPACE=""
    READY_PID=""
    for _ in $(seq 1 "$attempts"); do
        workspace="$(sandbox_workspace "$id" 2>/dev/null || true)"
        if [ -n "$workspace" ] && [ -d "$workspace" ]; then
            READY_WORKSPACE="$workspace"
            if [ -s "${workspace}/sleep.pid" ]; then
                pid="$(cat "${workspace}/sleep.pid")"
                if pid_alive "$pid"; then
                    READY_PID="$pid"
                    return 0
                fi
            fi
        fi
        sleep 0.1
    done
    if [ -n "$READY_WORKSPACE" ]; then
        echo "--- sandbox stdout ---" >&2
        cat "${READY_WORKSPACE}/stdout.log" >&2 2>/dev/null || true
        echo "--- sandbox stderr ---" >&2
        cat "${READY_WORKSPACE}/stderr.log" >&2 2>/dev/null || true
    fi
    return 1
}

cleanup_pid_if_alive() {
    local pid="$1"
    if pid_alive "$pid"; then
        kill "$pid" 2>/dev/null || true
    fi
}

wait_for_pid_exit() {
    local pid="$1"
    local attempts="${2:-50}"
    [ -n "$pid" ] || return 0
    for _ in $(seq 1 "$attempts"); do
        if ! pid_alive "$pid"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

summary() {
    echo ""
    echo "  ---------------------------------------------------------"
    echo "  Result: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
    if [ "$FAIL" -ne 0 ]; then
        echo ""
        echo "--- axisd log ---"
        cat "${TMP_ROOT}/axisd.log" 2>/dev/null || true
    fi
    [ "$FAIL" -eq 0 ]
}

echo "=== AXIS Daemon Linux E2E ==="
echo "axis: $AXIS"
echo "axisd: $AXSD"
echo "socket: $SOCKET"
echo "kernel: $(uname -r)"
echo ""

require_binaries

echo "--- Starting axisd ---"
XDG_DATA_HOME="${TMP_ROOT}/xdg" AXIS_SOCKET="$SOCKET" "$AXSD" >"${TMP_ROOT}/axisd.log" 2>&1 &
AXSD_PID=$!
if wait_for_socket && kill -0 "$AXSD_PID" 2>/dev/null; then
    pass "axisd started and created IPC socket"
else
    cat "${TMP_ROOT}/axisd.log" || true
    fail "axisd started and created IPC socket"
    summary || exit 1
    exit 0
fi

echo "--- List starts empty ---"
if axis_cli list | grep -qi "No running sandboxes"; then
    pass "axis list shows no running sandboxes"
else
    fail "axis list starts empty"
fi

echo "--- Create, list, exec, destroy ---"
lifecycle_policy="$(write_policy allow)"
set +e
create_sandbox "$lifecycle_policy" "(sleep 30) & echo \$! > sleep.pid; wait"
create_status=$?
set -e
if [ "$create_status" -eq 77 ]; then
    skip "daemon create/list/exec/destroy unavailable on this runner: ${CREATE_OUTPUT//$'\n'/ }"
elif [ "$create_status" -ne 0 ]; then
    echo "$CREATE_OUTPUT"
    fail "sandbox created"
else
    pass "sandbox created: $SANDBOX_ID"

    if wait_for_sandbox_child "$SANDBOX_ID"; then
        child_ready=1
    else
        child_ready=0
    fi
    sandbox_dir="$READY_WORKSPACE"
    sleep_pid="$READY_PID"
    if [ -n "$sandbox_dir" ] && [ -d "$sandbox_dir" ]; then
        pass "sandbox visible in list"
    else
        fail "sandbox visible in list"
    fi
    if [ "$child_ready" -eq 1 ]; then
        pass "sandbox child process is running"
    else
        fail "sandbox child process is running"
    fi

    if axis_cli exec --sandbox "$SANDBOX_ID" -- /bin/sh -c "printf exec-ok > exec-ok.txt"; then
        pass "axis exec runs inside existing sandbox"
    else
        fail "axis exec runs inside existing sandbox"
    fi
    if [ -n "$sandbox_dir" ] && [ -f "${sandbox_dir}/exec-ok.txt" ] && grep -q "exec-ok" "${sandbox_dir}/exec-ok.txt"; then
        pass "axis exec writes in daemon-managed workspace"
    else
        fail "axis exec writes in daemon-managed workspace"
    fi

    outside_exec="${TMP_ROOT}/exec-outside-denied"
    set +e
    axis_cli exec --sandbox "$SANDBOX_ID" -- /bin/sh -c "printf bad > '${outside_exec}'" >/dev/null 2>&1
    outside_status=$?
    set -e
    if [ "$outside_status" -ne 0 ] && [ ! -e "$outside_exec" ]; then
        pass "axis exec cannot write outside sandbox policy"
    else
        fail "axis exec cannot write outside sandbox policy"
        rm -f "$outside_exec"
    fi

    if axis_cli destroy "$SANDBOX_ID" >/dev/null; then
        pass "sandbox destroyed"
    else
        fail "sandbox destroyed"
    fi

    if wait_for_absent "$SANDBOX_ID"; then
        pass "destroy removes sandbox from list"
    else
        fail "destroy removes sandbox from list"
    fi

    if [ -n "$sleep_pid" ] && ! pid_alive "$sleep_pid"; then
        pass "destroy terminates sandbox process tree"
    else
        fail "destroy terminates sandbox process tree"
        cleanup_pid_if_alive "$sleep_pid"
    fi
fi

echo "--- Managed timeout cleanup ---"
timeout_policy="$(write_policy allow 1)"
set +e
create_sandbox "$timeout_policy" "(sleep 10) & echo \$! > sleep.pid; wait"
timeout_create_status=$?
set -e
if [ "$timeout_create_status" -eq 77 ]; then
    skip "daemon timeout unavailable on this runner: ${CREATE_OUTPUT//$'\n'/ }"
elif [ "$timeout_create_status" -ne 0 ]; then
    echo "$CREATE_OUTPUT"
    fail "timeout sandbox created"
else
    timeout_id="$SANDBOX_ID"
    pass "timeout sandbox created: $timeout_id"
    if wait_for_sandbox_child "$timeout_id"; then
        pass "timeout sandbox child process is running"
    else
        fail "timeout sandbox child process is running"
    fi
    timeout_pid="$READY_PID"
    if wait_for_absent "$timeout_id"; then
        pass "timeout destroys sandbox and cleanup removes it from list"
    else
        fail "timeout destroys sandbox and cleanup removes it from list"
        axis_cli destroy "$timeout_id" >/dev/null 2>&1 || true
    fi
    if [ -n "$timeout_pid" ] && ! pid_alive "$timeout_pid"; then
        pass "timeout terminates sandbox process tree"
    else
        fail "timeout terminates sandbox process tree"
        cleanup_pid_if_alive "$timeout_pid"
    fi
fi

echo "--- Block-mode exec network denial ---"
if command -v python3 >/dev/null 2>&1; then
    block_policy="$(write_policy block)"
    set +e
    create_sandbox "$block_policy" "(sleep 30) & echo \$! > sleep.pid; wait"
    block_create_status=$?
    set -e
    if [ "$block_create_status" -eq 77 ]; then
        skip "daemon block-mode exec unavailable on this runner: ${CREATE_OUTPUT//$'\n'/ }"
    elif [ "$block_create_status" -ne 0 ]; then
        echo "$CREATE_OUTPUT"
        fail "block-mode sandbox created"
    else
        block_id="$SANDBOX_ID"
        if wait_for_sandbox_child "$block_id"; then
            pass "block-mode sandbox child process is running"
        else
            fail "block-mode sandbox child process is running"
        fi
        block_pid="$READY_PID"
        set +e
        axis_cli exec --sandbox "$block_id" -- python3 -c 'import socket, sys
checks = [
    ("ipv4-tcp", socket.AF_INET, socket.SOCK_STREAM, 0),
    ("ipv4-udp-dns", socket.AF_INET, socket.SOCK_DGRAM, 0),
    ("ipv6-tcp", socket.AF_INET6, socket.SOCK_STREAM, 0),
]
if hasattr(socket, "AF_PACKET"):
    checks.append(("packet", socket.AF_PACKET, socket.SOCK_RAW, 0))
for label, family, socktype, proto in checks:
    try:
        sock = socket.socket(family, socktype, proto)
    except OSError:
        continue
    sock.close()
    print(f"{label} socket unexpectedly succeeded")
    sys.exit(42)
sys.exit(0)' >/dev/null 2>&1
        block_exec_status=$?
        set -e
        if [ "$block_exec_status" -eq 0 ]; then
            pass "daemon exec preserves broad block-mode network denial"
        else
            fail "daemon exec preserves broad block-mode network denial"
        fi
        axis_cli destroy "$block_id" >/dev/null 2>&1 || true
        cleanup_pid_if_alive "$block_pid"
    fi
else
    skip "daemon block-mode exec requires python3 on PATH"
fi

echo "--- Daemon crash cleanup ---"
crash_policy="$(write_policy allow)"
set +e
create_sandbox "$crash_policy" "(sleep 60) & echo \$! > sleep.pid; wait"
crash_create_status=$?
set -e
if [ "$crash_create_status" -eq 77 ]; then
    skip "daemon crash cleanup unavailable on this runner: ${CREATE_OUTPUT//$'\n'/ }"
elif [ "$crash_create_status" -ne 0 ]; then
    echo "$CREATE_OUTPUT"
    fail "crash-cleanup sandbox created"
else
    crash_id="$SANDBOX_ID"
    if wait_for_sandbox_child "$crash_id"; then
        pass "crash-cleanup sandbox child process is running"
    else
        fail "crash-cleanup sandbox child process is running"
    fi
    crash_pid="$READY_PID"

    if [ -n "$AXSD_PID" ]; then
        kill -KILL "$AXSD_PID" 2>/dev/null || true
        wait "$AXSD_PID" 2>/dev/null || true
        AXSD_PID=""
    fi

    if wait_for_pid_exit "$crash_pid" 60; then
        pass "daemon hard crash terminates sandbox process tree"
    else
        fail "daemon hard crash terminates sandbox process tree"
        cleanup_pid_if_alive "$crash_pid"
    fi
fi

summary || exit 1
