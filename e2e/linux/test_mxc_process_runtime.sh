#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated Linux MXC process-runtime proofs.
#
# This wrapper exposes the existing Rust real-runtime MXC process tests as a
# repeatable e2e command. It builds the unprivileged AXIS seccomp launcher from
# the current checkout but never installs local artifacts or changes host
# sandbox settings.
set -euo pipefail

fail() {
    echo "  FAIL: $1"
    exit 1
}

skip() {
    echo "  SKIP: $1"
    exit 0
}

need_tool() {
    local tool=$1
    local reason=$2

    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool is required to $reason"
    fi
}

resolve_executor() {
    if [ -n "${AXIS_TEST_MXC_EXECUTOR:-}" ]; then
        if [ ! -x "$AXIS_TEST_MXC_EXECUTOR" ]; then
            fail "AXIS_TEST_MXC_EXECUTOR is not executable: $AXIS_TEST_MXC_EXECUTOR"
        fi
        EXECUTOR="$AXIS_TEST_MXC_EXECUTOR"
        return
    fi

    if EXECUTOR="$(command -v lxc-exec 2>/dev/null)"; then
        return
    fi

    fail "set AXIS_TEST_MXC_EXECUTOR or provide lxc-exec on PATH"
}

require_userns() {
    local userns=/proc/sys/kernel/unprivileged_userns_clone

    if [ ! -r "$userns" ]; then
        fail "$userns must be readable for MXC process-runtime proofs"
    fi
    if [ "$(cat "$userns")" != "1" ]; then
        fail "unprivileged user namespaces must be enabled for MXC process-runtime proofs"
    fi
}

if [ "${AXIS_RUN_MXC_PROCESS_E2E:-}" != "1" ]; then
    skip "set AXIS_RUN_MXC_PROCESS_E2E=1"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_BIN=${CARGO:-cargo}

need_tool "$CARGO_BIN" "build and run AXIS MXC process-runtime tests"
need_tool bwrap "run MXC Bubblewrap process-runtime tests"
need_tool python3 "run MXC process-runtime probes"
# MXC 1.x runs allow-mode sandboxes in a private slirp4netns network namespace.
# Keep this list and search path in step with MXC_PRIVATE_NETWORK_TOOLS and
# MXC_EXECUTOR_PATH in crates/axis-sandbox/src/linux/mxc.rs, which AXIS probes.
for tool in slirp4netns unshare nsenter iptables ip6tables iptables-restore ip6tables-restore; do
    if ! PATH="/usr/sbin:/usr/bin:/sbin:/bin" command -v "$tool" >/dev/null 2>&1; then
        fail "$tool is required to run MXC allow-mode process-runtime probes"
    fi
done
if [ ! -c /dev/net/tun ]; then
    fail "/dev/net/tun is required to run MXC allow-mode process-runtime probes"
fi
resolve_executor
require_userns

cd "$REPO_ROOT"

echo "=== AXIS MXC Process Runtime ==="
echo "executor: $EXECUTOR"
echo "cargo: $CARGO_BIN"

"$CARGO_BIN" build --locked -p axis-sandbox --bin axis-seccomp-launcher

if [ -n "${AXIS_TEST_AXIS_SECCOMP_LAUNCHER:-}" ]; then
    if [ ! -x "$AXIS_TEST_AXIS_SECCOMP_LAUNCHER" ]; then
        fail "AXIS_TEST_AXIS_SECCOMP_LAUNCHER is not executable: $AXIS_TEST_AXIS_SECCOMP_LAUNCHER"
    fi
    LAUNCHER="$AXIS_TEST_AXIS_SECCOMP_LAUNCHER"
else
    LAUNCHER="$REPO_ROOT/target/debug/axis-seccomp-launcher"
fi
if [ ! -x "$LAUNCHER" ]; then
    fail "axis-seccomp-launcher was not built at $LAUNCHER"
fi

export AXIS_TEST_MXC_EXECUTOR="$EXECUTOR"
export AXIS_TEST_AXIS_SECCOMP_LAUNCHER="$LAUNCHER"

# The real-MXC tests are #[ignore]d so a plain `cargo test` never reports them
# as passed. Run exactly the named one and require that it ran and passed: a
# filter that matches nothing must not pass either.
run_gated_test() {
    local name=$1 output
    if ! output=$("$CARGO_BIN" test --locked -p axis-sandbox --lib "linux::mxc::tests::$name" \
        -- --ignored --exact --nocapture 2>&1); then
        printf '%s\n' "$output"
        fail "$name failed"
    fi
    printf '%s\n' "$output"
    if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored' <<<"$output"; then
        fail "$name did not run exactly once"
    fi
}

run_test() {
    run_gated_test "$1"
}

run_process_test() {
    AXIS_REAL_MXC_PROCESS_TESTS=1 run_gated_test "$1"
}

# The strict proxy proof needs network-namespace privileges the process proofs
# must not run with, so a privileged caller can run it alone.
if [ "${AXIS_MXC_PROXY_PROOF_ONLY:-}" = "1" ]; then
    if [ "${AXIS_REAL_MXC_PROXY_TESTS:-}" != "1" ]; then
        fail "AXIS_MXC_PROXY_PROOF_ONLY=1 requires AXIS_REAL_MXC_PROXY_TESTS=1"
    fi
else
    run_process_test gated_real_mxc_allow_and_block_runtime_parity
    run_process_test gated_real_mxc_payload_cannot_read_axis_config_fd
    run_process_test gated_real_mxc_timeout_cleans_tmpdir
fi

if [ "${AXIS_REAL_MXC_PROXY_TESTS:-}" = "1" ]; then
    run_test gated_real_mxc_native_proxy_reaches_only_axis_proxy_address
else
    echo "  SKIP: set AXIS_REAL_MXC_PROXY_TESTS=1 for real MXC strict proxy reachability proof"
fi

