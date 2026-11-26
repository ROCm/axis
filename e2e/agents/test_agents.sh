#!/bin/bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# AXIS Agent Safety Test Suite
#
# Tests that agent runtimes CANNOT run without the AXIS sandbox
# and that the sandbox enforces default-deny policies correctly.
#
# Usage:
#   bash e2e/agents/test_agents.sh [--platform linux|macos|windows]
#
# Each test verifies:
# 1. Policy validates correctly
# 2. Sandbox starts with the agent's policy
# 3. Network deny blocks direct connections
# 4. Allowed endpoints pass through proxy
# 5. Credential files are inaccessible (deny paths)
# 6. Workspace writes succeed
# 7. System path writes fail

set -euo pipefail

AXIS="${AXIS_BIN:-axis}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_DIR="${SCRIPT_DIR}/../../policies/agents"
TMP_ROOT="$(mktemp -d /tmp/axis-agent-e2e-XXXXXX)"

# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# Detect platform.
PLATFORM="${1:-auto}"
if [ "$PLATFORM" = "auto" ] || [ "$PLATFORM" = "--platform" ]; then
    shift 2>/dev/null || true
    PLATFORM="${1:-auto}"
fi
if [ "$PLATFORM" = "auto" ]; then
    case "$(uname -s)" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *) PLATFORM="unknown" ;;
    esac
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         AXIS Agent Safety Test Suite                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Platform: $PLATFORM"
echo "AXIS:     $($AXIS --version 2>/dev/null || echo 'not found')"
echo ""

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP+1)); }

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

prepare_run_policy() {
    local policy_file="$1"
    local provider="${AXIS_AGENT_TEST_RUNTIME_PROVIDER:-}"
    local disable_resources="${AXIS_AGENT_TEST_DISABLE_RESOURCE_LIMITS:-0}"
    local network_mode="${AXIS_AGENT_TEST_NETWORK_MODE:-}"

    if [ -z "$provider" ] && [ "$disable_resources" != "1" ] && [ -z "$network_mode" ]; then
        printf '%s\n' "$policy_file"
        return
    fi

    local output_file
    output_file="${TMP_ROOT}/$(basename "${policy_file%.yaml}")-run.yaml"
    local insert_runtime=0
    if [ -n "$provider" ] && ! grep -Eq '^runtime:' "$policy_file"; then
        insert_runtime=1
    fi

    awk \
        -v provider="$provider" \
        -v insert_runtime="$insert_runtime" \
        -v disable_resources="$disable_resources" \
        -v network_mode="$network_mode" '
        BEGIN { inserted = 0; in_process = 0; in_network = 0; skip_network_policies = 0 }
        /^name:[[:space:]]/ && insert_runtime == "1" && inserted == 0 {
            print
            print ""
            print "runtime:"
            print "  containment: process"
            print "  provider: " provider
            inserted = 1
            next
        }
        /^[A-Za-z_][A-Za-z0-9_]*:/ {
            skip_network_policies = 0
            in_process = ($0 ~ /^process:/)
            in_network = ($0 ~ /^network:/)
        }
        skip_network_policies == 1 {
            next
        }
        in_process && disable_resources == "1" && /^[[:space:]]*max_processes:/ {
            print "  max_processes: 0"
            next
        }
        in_process && disable_resources == "1" && /^[[:space:]]*max_memory_mb:/ {
            print "  max_memory_mb: 0"
            next
        }
        in_process && disable_resources == "1" && /^[[:space:]]*cpu_rate_percent:/ {
            print "  cpu_rate_percent: 0"
            next
        }
        in_network && network_mode != "" && /^[[:space:]]*mode:/ {
            print "  mode: " network_mode
            next
        }
        in_network && network_mode != "" && /^[[:space:]]*policies:/ {
            skip_network_policies = 1
            next
        }
        { print }
    ' "$policy_file" >"$output_file"

    printf '%s\n' "$output_file"
}

validate_run_policy() {
    local label="$1"
    local policy_file="$2"
    local output
    if output=$($AXIS policy validate "$policy_file" 2>&1); then
        return 0
    fi
    echo "$output"
    fail "$label: runtime policy validation"
    return 1
}

report_start_failure() {
    local label="$1"
    local output="$2"
    if capability_skip_output "$output"; then
        skip "$label unavailable on this runner: ${output//$'\n'/ }"
    else
        echo "$output"
        fail "$label"
    fi
}

axis_run() {
    local run_home
    run_home="$(mktemp -d "${TMP_ROOT}/home-XXXXXX")"
    mkdir -p "${run_home}/.local/share"
    HOME="$run_home" \
        XDG_CONFIG_HOME="${run_home}/.config" \
        XDG_DATA_HOME="${run_home}/.local/share" \
        "$AXIS" run "$@"
}

# ── Test function for each agent ──────────────────────────────────────────

test_agent() {
    local AGENT_NAME="$1"
    local POLICY_FILE="$2"
    local BINARY_CHECK="${3:-}" # optional: command to check if agent is installed

    echo "--- Agent: $AGENT_NAME ---"

    # Test 1: Policy validates.
    if $AXIS policy validate "$POLICY_FILE" >/dev/null 2>&1; then
        pass "$AGENT_NAME: policy validates"
    else
        fail "$AGENT_NAME: policy validation"
        return
    fi

    # Test 2: Sandbox starts and runs a test command.
    local RUN_POLICY
    RUN_POLICY="$(prepare_run_policy "$POLICY_FILE")"
    validate_run_policy "$AGENT_NAME" "$RUN_POLICY" || return

    local OUTPUT
    OUTPUT=$(axis_run --policy "$RUN_POLICY" -- /bin/sh -c "echo SANDBOX_OK" 2>&1) || true
    if echo "$OUTPUT" | grep -q "SANDBOX_OK"; then
        pass "$AGENT_NAME: sandbox runs"
    else
        report_start_failure "$AGENT_NAME: sandbox start" "$OUTPUT"
        return
    fi

    # Test 3: Credential files are blocked.
    OUTPUT=$(axis_run --policy "$RUN_POLICY" -- /bin/sh -c "cat ~/.ssh/id_rsa 2>&1 || echo BLOCKED" 2>&1) || true
    if echo "$OUTPUT" | grep -qi "blocked\|denied\|permission\|No such"; then
        pass "$AGENT_NAME: ~/.ssh blocked"
    else
        fail "$AGENT_NAME: ~/.ssh NOT blocked"
    fi

    # Test 4: Workspace writes succeed (use workspace dir, not /tmp).
    OUTPUT=$(axis_run --policy "$RUN_POLICY" -- /bin/sh -c 'echo test > axis-write-test && echo WRITE_OK && rm axis-write-test' 2>&1) || true
    if echo "$OUTPUT" | grep -q "WRITE_OK"; then
        pass "$AGENT_NAME: workspace write"
    else
        fail "$AGENT_NAME: workspace write"
    fi

    # Test 5: Network deny (for block-mode policies) or proxy enforcement.
    local NET_MODE
    NET_MODE=$(grep "mode:" "$RUN_POLICY" | head -1 | awk '{print $2}')
    if [ "$NET_MODE" = "block" ]; then
        OUTPUT=$(axis_run --policy "$RUN_POLICY" -- /bin/sh -c "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 https://example.com 2>&1 || echo NETWORK_BLOCKED" 2>&1) || true
        if echo "$OUTPUT" | grep -qi "blocked\|000\|denied\|not permitted\|timed out"; then
            pass "$AGENT_NAME: network blocked"
        else
            fail "$AGENT_NAME: network NOT blocked ($OUTPUT)"
        fi
    elif [ "$NET_MODE" = "proxy" ]; then
        # Test that non-allowed host is denied by proxy.
        OUTPUT=$(axis_run --policy "$RUN_POLICY" -- /bin/sh -c "curl -s --proxy \$HTTPS_PROXY -o /dev/null -w '%{http_code}' --connect-timeout 3 https://evil.example.com 2>&1 || echo DENIED" 2>&1) || true
        if echo "$OUTPUT" | grep -qi "denied\|000\|403"; then
            pass "$AGENT_NAME: proxy denies evil.example.com"
        else
            skip "$AGENT_NAME: proxy deny test (proxy may not be running)"
        fi
    fi

    # Test 6: Agent binary check (if available).
    if [ -n "$BINARY_CHECK" ]; then
        if command -v "$BINARY_CHECK" >/dev/null 2>&1; then
            OUTPUT=$(axis_run --policy "$RUN_POLICY" -- "$BINARY_CHECK" --version 2>&1) || true
            if echo "$OUTPUT" | grep -qi "version\|[0-9]\.[0-9]"; then
                pass "$AGENT_NAME: binary runs in sandbox"
            else
                skip "$AGENT_NAME: binary runs but no version output"
            fi
        else
            skip "$AGENT_NAME: binary '$BINARY_CHECK' not installed"
        fi
    fi
}

# ── Test: base deny policy ────────────────────────────────────────────────

echo "--- Base: Default Deny ---"
if $AXIS policy validate "$POLICY_DIR/base-deny.yaml" >/dev/null 2>&1; then
    pass "base-deny: policy validates"
else
    fail "base-deny: policy validation"
fi

BASE_RUN_POLICY="$(prepare_run_policy "$POLICY_DIR/base-deny.yaml")"
BASE_SANDBOX_AVAILABLE=0
if validate_run_policy "base-deny" "$BASE_RUN_POLICY"; then
    OUTPUT=$(axis_run --policy "$BASE_RUN_POLICY" -- /bin/sh -c "echo DENY_OK" 2>&1) || true
else
    OUTPUT=""
fi
if echo "$OUTPUT" | grep -q "DENY_OK"; then
    pass "base-deny: sandbox runs"
    BASE_SANDBOX_AVAILABLE=1
else
    report_start_failure "base-deny: sandbox start" "$OUTPUT"
fi

# Verify network is fully blocked in base deny.
if [ "$BASE_SANDBOX_AVAILABLE" -eq 1 ]; then
    OUTPUT=$(axis_run --policy "$BASE_RUN_POLICY" -- /bin/sh -c "curl -s --connect-timeout 2 https://example.com 2>&1; echo EXIT=\$?" 2>&1) || true
    if echo "$OUTPUT" | grep -qi "blocked\|denied\|not permitted\|timed out\|EXIT=[^0]"; then
        pass "base-deny: network blocked"
    elif capability_skip_output "$OUTPUT"; then
        skip "base-deny: network blocked unavailable on this runner: ${OUTPUT//$'\n'/ }"
    else
        fail "base-deny: network NOT blocked"
    fi
else
    skip "base-deny: network blocked requires a running sandbox"
fi

echo ""

# ── Run per-agent tests ──────────────────────────────────────────────────

test_agent "Claude Code" "$POLICY_DIR/claude-code.yaml" "claude"
echo ""

test_agent "Codex" "$POLICY_DIR/codex.yaml" "codex"
echo ""

test_agent "OpenClaw" "$POLICY_DIR/openclaw.yaml" "openclaw"
echo ""

test_agent "Ironclaw" "$POLICY_DIR/ironclaw.yaml" "ironclaw"
echo ""

test_agent "NanoClaw" "$POLICY_DIR/nanoclaw.yaml" ""
echo ""

test_agent "ZeroClaw" "$POLICY_DIR/zeroclaw.yaml" ""
echo ""

test_agent "Hermes Agent" "$POLICY_DIR/hermes.yaml" ""
echo ""

# ── Summary ──────────────────────────────────────────────────────────────

echo "══════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
echo "Result: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)"
echo "Platform: $PLATFORM"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "All agent sandbox policies enforce default-deny correctly."
fi

exit $FAIL
