#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Unprivileged Linux e2e proof for standalone `axis run`.
#
# This script must not require sudo, a developer-installed setuid helper, or
# host firewall mutation. Kernel/resource capabilities that are absent on the
# current runner are reported as explicit skips.
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

PASS=0
FAIL=0
SKIP=0
TMP_ROOT="$(mktemp -d /tmp/axis-e2e-root-XXXXXX)"

cleanup() {
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

require_axis() {
    if [ ! -x "$AXIS" ]; then
        echo "ERROR: axis binary not found: $AXIS"
        echo "Build it with: cargo build --locked --release -p axis-cli"
        exit 1
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        skip "$2 requires '$1' on PATH"
        return 1
    fi
}

new_tmpdir() {
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
    local blocked_syscall="${3:-}"
    local runtime_provider="${4:-auto}"
    local filesystem_compatibility="${5:-best_effort}"
    local dir
    dir="$(new_tmpdir)"
    POLICY_FILE="${dir}/policy.yaml"
    cat >"$POLICY_FILE" <<EOF
version: 1
name: linux-e2e-${mode}

runtime:
  containment: process
  provider: ${runtime_provider}

filesystem:
  compatibility: ${filesystem_compatibility}
  read_only:
EOF
    append_read_only_path /bin
    append_read_only_path /sbin
    append_read_only_path /usr
    append_read_only_path /lib
    append_read_only_path /lib64
    append_read_only_path /etc
    append_read_only_path /nix/store
    if command -v python3 >/dev/null 2>&1; then
        local python_path
        python_path="$(command -v python3)"
        append_read_only_path "$(dirname "$python_path")"
    fi
    cat >>"$POLICY_FILE" <<EOF
  read_write:
    - "{workspace}"

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
EOF
    if [ -n "$blocked_syscall" ]; then
        cat >>"$POLICY_FILE" <<EOF
  blocked_syscalls:
    - ${blocked_syscall}
EOF
    fi
    if [ -n "$timeout" ]; then
        printf '  timeout_sec: %s\n' "$timeout" >>"$POLICY_FILE"
    fi
    cat >>"$POLICY_FILE" <<EOF

network:
  mode: ${mode}
EOF
    printf '%s\n' "$POLICY_FILE"
}

run_axis() {
    local output_file="$1"
    local workdir="$2"
    shift 2
    local socket="/tmp/axis-e2e-standalone-$$-$RANDOM.sock"
    (
        cd "$workdir"
        timeout 15 "$AXIS" --socket "$socket" run "$@"
    ) >"$output_file" 2>&1
}

# Runs `axis run` in a fresh case directory and records the outcome in
# AXIS_CASE_RESULT (pass, fail, or skip) and the directory in AXIS_CASE_DIR.
# A zero exit status alone is not proof: the payload must also print
# `marker` as a whole line, which it does only after observing the enforced
# behavior. That keeps a run that never executed the payload from passing.
expect_axis_marker_or_skip() {
    local label="$1"
    local marker="$2"
    shift 2
    local output_file
    local case_dir
    local status=0
    case_dir="$(new_tmpdir)"
    output_file="${case_dir}/output.txt"
    AXIS_CASE_DIR="$case_dir"
    run_axis "$output_file" "$case_dir" "$@" || status=$?
    local output
    # When stdin is a terminal, axis relays the payload through a PTY, which
    # turns line endings into CRLF.
    output="$(tr -d '\r' <"$output_file")"
    if [ "$status" -eq 0 ]; then
        if [ -z "$marker" ] || grep -Fxq -- "$marker" <<<"$output"; then
            AXIS_CASE_RESULT=pass
            pass "$label"
            return 0
        fi
        echo "$output"
        AXIS_CASE_RESULT=fail
        fail "$label (payload marker '$marker' missing)"
        return 0
    fi
    if capability_skip_output "$output"; then
        AXIS_CASE_RESULT=skip
        skip "$label unavailable on this runner: ${output//$'\n'/ }"
        return 0
    fi
    echo "$output"
    AXIS_CASE_RESULT=fail
    fail "$label"
    return 0
}

# Exit-status-only variant, unused here but kept so checks written against
# the previous helper keep working. New checks should use
# expect_axis_marker_or_skip so that the payload's own verdict is asserted.
expect_axis_success_or_skip() {
    local label="$1"
    shift
    expect_axis_marker_or_skip "$label" "" "$@"
}

# Requires `axis policy validate` to accept the policy and report it by name.
expect_policy_validates() {
    local label="$1"
    local policy="$2"
    local name
    local output
    name="$(sed -n 's/^name: *//p' "$policy" | head -n 1)"
    if output="$("$AXIS" policy validate "$policy" 2>&1)" &&
        grep -Fxq "Policy '${name}' is valid." <<<"$output"; then
        pass "$label"
    else
        echo "$output"
        fail "$label"
    fi
}

echo "=== AXIS Linux Standalone E2E ==="
echo "axis: $AXIS"
echo "kernel: $(uname -r)"
echo ""

require_axis

echo "--- Policy validation ---"
expect_policy_validates "minimal policy validates" "${REPO_ROOT}/policies/minimal.yaml"
expect_policy_validates "coding-agent policy validates" "${REPO_ROOT}/policies/coding-agent.yaml"
invalid_policy="$(new_tmpdir)/unsupported-version.yaml"
sed 's/^version: 1$/version: 99/' "${REPO_ROOT}/policies/minimal.yaml" >"$invalid_policy"
if ! grep -Fxq "version: 99" "$invalid_policy"; then
    fail "unsupported policy version fixture could not be generated"
elif invalid_output="$("$AXIS" policy validate "$invalid_policy" 2>&1)"; then
    echo "$invalid_output"
    fail "unsupported policy version is rejected (validate exited 0)"
elif grep -Fxq "Policy validation failed: unsupported policy version: 99" <<<"$invalid_output"; then
    pass "unsupported policy version is rejected"
else
    echo "$invalid_output"
    fail "unsupported policy version is rejected"
fi

echo "--- Filesystem isolation through axis run ---"
fs_policy="$(write_policy block "" "" axis_native hard_requirement)"
denied="/tmp/axis-e2e-denied-$$"
rm -f "$denied"
expect_axis_marker_or_skip \
    "workspace write succeeds and outside write is denied" outside-write-denied \
    --policy "$fs_policy" -- /bin/sh -c \
    "printf ok > inside.txt; if printf bad > '$denied'; then echo outside-write-succeeded; exit 42; else echo outside-write-denied; fi; test -f inside.txt"
if [ -e "$denied" ] || [ -L "$denied" ]; then
    fail "outside path was not created on the host"
elif [ "$AXIS_CASE_RESULT" = pass ]; then
    pass "outside path was not created on the host"
fi
if [ "$AXIS_CASE_RESULT" = pass ]; then
    if [ "$(cat "${AXIS_CASE_DIR}/inside.txt" 2>/dev/null)" = ok ]; then
        pass "workspace write is visible on the host"
    else
        fail "workspace write is visible on the host"
    fi
fi
rm -f "$denied"

echo "--- Environment boundary through axis run ---"
env_policy="$(write_policy allow)"
secret_fixture="sandbox-fixture"
export OPENAI_API_KEY="axis-e2e-openai-${secret_fixture}"
export ANTHROPIC_API_KEY="axis-e2e-anthropic-${secret_fixture}"
export HTTPS_PROXY="http://proxy.example.invalid:8080"
expect_axis_marker_or_skip \
    "provider secrets and inherited proxy env are omitted" env-filtered \
    --policy "$env_policy" -- /bin/sh -c \
    'if env | grep -E "^(OPENAI_API_KEY|ANTHROPIC_API_KEY|HTTPS_PROXY)="; then exit 42; fi; echo env-filtered'
unset OPENAI_API_KEY ANTHROPIC_API_KEY HTTPS_PROXY secret_fixture

echo "--- Block-mode network through axis run ---"
if require_cmd python3 "block-mode network test"; then
    net_policy="$(write_policy block)"
    expect_axis_marker_or_skip \
        "IPv4, IPv6, DNS, and packet sockets are denied in block mode" all-sockets-blocked \
        --policy "$net_policy" -- python3 -c \
        'import socket, sys

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
    except OSError as exc:
        print(f"{label} blocked: {exc}")
        continue
    sock.close()
    print(f"{label} socket unexpectedly succeeded")
    sys.exit(42)
print("all-sockets-blocked")
sys.exit(0)'
fi

echo "--- Policy-aware seccomp through axis run ---"
if require_cmd python3 "seccomp ptrace test"; then
    seccomp_policy="$(write_policy allow "" ptrace)"
    expect_axis_marker_or_skip \
        "configured ptrace syscall is denied" "ptrace blocked" \
        --policy "$seccomp_policy" -- python3 -c \
        'import ctypes, errno, sys
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ret = libc.ptrace(0, 0, 0, 0)
err = ctypes.get_errno()
if err == errno.EPERM:
    print("ptrace blocked")
    sys.exit(0)
print(f"ptrace not blocked: ret={ret} errno={err}")
sys.exit(42)'
fi

echo "--- Timeout enforcement through axis run ---"
timeout_policy="$(write_policy allow 1)"
timeout_output="$(new_tmpdir)/timeout.txt"
start_sec="$(date +%s)"
set +e
run_axis "$timeout_output" "$(dirname "$timeout_output")" --policy "$timeout_policy" -- /bin/sh -c "echo timeout-payload-started; sleep 10"
timeout_status=$?
set -e
elapsed=$(( $(date +%s) - start_sec ))
timeout_text="$(tr -d '\r' <"$timeout_output")"
if capability_skip_output "$timeout_text"; then
    skip "timeout enforcement unavailable on this runner: ${timeout_text//$'\n'/ }"
elif [ "$timeout_status" -ne 0 ] &&
    [ "$timeout_status" -ne 124 ] &&
    [ "$elapsed" -lt 8 ] &&
    grep -Fxq "timeout-payload-started" <<<"$timeout_text" &&
    ! grep -Fq "failed to run command" <<<"$timeout_text"; then
    pass "timeout stops long-running sandbox"
else
    echo "$timeout_text"
    fail "timeout stops long-running sandbox (status=$timeout_status elapsed=${elapsed}s)"
fi

echo ""
echo "  ---------------------------------------------------------"
echo "  Result: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
if [ "$FAIL" -eq 0 ]; then
    echo "  Linux standalone e2e completed."
else
    exit 1
fi
