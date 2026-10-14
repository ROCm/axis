#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Privileged Linux e2e proof for axis-netns-helper launch mode.
#
# This is intentionally an ephemeral-runner harness, not a local developer
# install path. It mutates /usr/libexec/axis only after an explicit opt-in so
# ordinary repo tests never depend on a host setuid helper.
# shellcheck disable=SC2317,SC2329 # Callback functions are invoked indirectly by name.
set -euo pipefail

run_preflight_namespace_state_machine() {
    local namespace="$1"
    local exists_fn="$2"
    local add_fn="$3"
    local configure_fn="$4"
    local delete_fn="$5"
    local status=0

    if "$exists_fn" "$namespace"; then
        echo "ERROR: refusing to use preexisting preflight namespace: $namespace" >&2
        return 126
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            return "$status"
        fi
    fi
    status=0
    "$add_fn" "$namespace" || return $?
    "$configure_fn" "$namespace" || status=$?
    if ! "$delete_fn" "$namespace"; then
        echo "ERROR: failed to remove owned preflight namespace: $namespace" >&2
        return 125
    fi
    return "$status"
}

kmsg_gate_status() {
    local required="$1"
    local readable="$2"
    if [ "$readable" = "1" ]; then
        return 0
    fi
    if [ "$required" = "1" ]; then
        return 1
    fi
    return 77
}

install_kmsg_capability_binary() {
    local source_binary="$1"
    local installed_binary="$2"
    local collision_check_fn="$3"
    local install_fn="$4"
    local grant_fn="$5"
    local inspect_fn="$6"
    local installed_capabilities=""
    local expected_capabilities="${installed_binary} cap_dac_read_search,cap_syslog=ep"

    "$collision_check_fn" "$installed_binary" || return $?
    KMSG_AXISD_INSTALL="$installed_binary"
    "$install_fn" "$source_binary" "$installed_binary"
    KMSG_CAPABILITY_INSTALLED=1
    "$grant_fn" "$installed_binary"
    installed_capabilities="$("$inspect_fn" "$installed_binary")"
    if [ "$installed_capabilities" != "$expected_capabilities" ]; then
        echo "ERROR: temporary axisd kmsg capabilities do not match: $installed_capabilities" >&2
        return 1
    fi
}

cleanup_kmsg_capability_binary() {
    local revoke_fn="$1"
    local remove_fn="$2"
    local status=0

    if [ "$KMSG_CAPABILITY_INSTALLED" -eq 1 ]; then
        if ! "$revoke_fn" "$KMSG_AXISD_INSTALL"; then
            echo "ERROR: failed to remove temporary axisd kmsg capabilities" >&2
            status=1
        fi
    fi
    if [ -n "$KMSG_AXISD_INSTALL" ]; then
        if ! "$remove_fn" "$KMSG_AXISD_INSTALL"; then
            echo "ERROR: failed to remove temporary axisd kmsg support executables" >&2
            status=1
        fi
    fi
    return "$status"
}

reject_kmsg_bundle_collisions() {
    local axisd_path="$1"
    local launcher_path="$2"
    local collision_check_fn="$3"

    "$collision_check_fn" "$axisd_path" "kmsg-enabled axisd" || return $?
    "$collision_check_fn" "$launcher_path" "axis seccomp launcher" || return $?
}

provision_nf_log_all_netns() {
    local read_fn="$1"
    local write_fn="$2"
    local current=""

    current="$("$read_fn")" || return $?
    if [ "$current" != "0" ] && [ "$current" != "1" ]; then
        echo "ERROR: invalid net.netfilter.nf_log_all_netns value: $current" >&2
        return 1
    fi
    if [ "$current" = "1" ]; then
        return 0
    fi

    NF_LOG_ALL_NETNS_ORIGINAL="$current"
    NF_LOG_ALL_NETNS_CHANGED=1
    "$write_fn" 1 || return $?
    current="$("$read_fn")" || return $?
    if [ "$current" != "1" ]; then
        echo "ERROR: net.netfilter.nf_log_all_netns was not enabled" >&2
        return 1
    fi
}

restore_nf_log_all_netns() {
    local write_fn="$1"
    if [ "$NF_LOG_ALL_NETNS_CHANGED" -eq 0 ]; then
        return 0
    fi
    "$write_fn" "$NF_LOG_ALL_NETNS_ORIGINAL"
}

audit_log_contains_matching_bypass() {
    local log_path="$1"
    local sandbox_id="$2"
    local destination_port="$3"
    python3 - "$log_path" "$sandbox_id" "$destination_port" <<'PY'
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
sandbox_id = sys.argv[2]
destination_port = int(sys.argv[3])
try:
    lines = log_path.read_text().splitlines()
except (FileNotFoundError, OSError):
    raise SystemExit(1)

for line in lines:
    try:
        envelope = json.loads(line)
        if envelope.get("target") != "axis::audit":
            continue
        event = json.loads(envelope.get("fields", {}).get("message", ""))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        continue
    details = event.get("details")
    if (
        event.get("category") == "security_finding"
        and event.get("sandbox_id") == sandbox_id
        and isinstance(event.get("message"), str)
        and event["message"].startswith("network bypass attempt to ")
        and isinstance(details, dict)
        and details.get("destination_port") == destination_port
    ):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

lifecycle_resources_absent() {
    local state_path="$1"
    local namespace="$2"
    local veth_name="$3"
    local state_exists_fn="${4:-helper_state_exists}"
    local namespace_exists_fn="${5:-namespace_exists}"
    local veth_exists_fn="${6:-host_veth_exists}"
    local status=0

    "$state_exists_fn" "$state_path" || status=$?
    if [ "$status" -eq 0 ]; then
        return 1
    elif [ "$status" -ne 1 ]; then
        return 2
    fi
    status=0
    "$namespace_exists_fn" "$namespace" || status=$?
    if [ "$status" -eq 0 ]; then
        return 1
    elif [ "$status" -ne 1 ]; then
        return 2
    fi
    status=0
    "$veth_exists_fn" "$veth_name" || status=$?
    if [ "$status" -eq 0 ]; then
        return 1
    elif [ "$status" -ne 1 ]; then
        return 2
    fi
    return 0
}

wait_for_lifecycle_resources_absent() {
    local state_path="$1"
    local namespace="$2"
    local veth_name="$3"
    local attempts="${4:-20}"
    local status=0

    for _ in $(seq 1 "$attempts"); do
        status=0
        lifecycle_resources_absent "$state_path" "$namespace" "$veth_name" || status=$?
        if [ "$status" -eq 0 ]; then
            return 0
        elif [ "$status" -ne 1 ]; then
            return "$status"
        fi
        sleep 0.1
    done
    return 1
}

read_helper_destroy_token() {
    # shellcheck disable=SC2016 # The awk field expression is literal.
    bounded_sudo 2 awk 'NR == 2 { print $1 }' "$1"
}

destroy_helper_with_token() {
    bounded 5 "$HELPER_INSTALL" destroy-token "$1" "$2"
}

cleanup_lifecycle_resources() {
    local sandbox_id="$1"
    local namespace="$2"
    local veth_name="$3"
    local wait_fn="${4:-wait_for_lifecycle_resources_absent}"
    local state_exists_fn="${5:-helper_state_exists}"
    local read_token_fn="${6:-read_helper_destroy_token}"
    local destroy_fn="${7:-destroy_helper_with_token}"
    local state_path="/run/axis/netns/${sandbox_id}"
    local destroy_token=""
    local status=0

    "$wait_fn" "$state_path" "$namespace" "$veth_name" || status=$?
    if [ "$status" -eq 0 ]; then
        return 0
    elif [ "$status" -ne 1 ]; then
        return 2
    fi

    status=0
    "$state_exists_fn" "$state_path" || status=$?
    if [ "$status" -eq 1 ]; then
        status=0
        "$wait_fn" "$state_path" "$namespace" "$veth_name" || status=$?
        if [ "$status" -eq 0 ]; then
            return 0
        elif [ "$status" -eq 1 ]; then
            return 3
        fi
        return 2
    elif [ "$status" -ne 0 ]; then
        return 2
    fi

    status=0
    destroy_token="$("$read_token_fn" "$state_path")" || status=$?
    if [ "$status" -ne 0 ] || [[ ! "$destroy_token" =~ ^[[:xdigit:]]{64}$ ]]; then
        status=0
        "$wait_fn" "$state_path" "$namespace" "$veth_name" || status=$?
        if [ "$status" -eq 0 ]; then
            return 0
        elif [ "$status" -eq 1 ]; then
            return 4
        fi
        return 2
    fi

    "$destroy_fn" "$sandbox_id" "$destroy_token" >/dev/null 2>&1 || true
    status=0
    "$wait_fn" "$state_path" "$namespace" "$veth_name" || status=$?
    if [ "$status" -eq 0 ]; then
        return 0
    elif [ "$status" -eq 1 ]; then
        return 5
    fi
    return 2
}

run_rootless_harness_self_tests() {
    local add_count=0
    local delete_count=0
    fake_exists() { return 0; }
    fake_add() { add_count=$((add_count + 1)); }
    fake_configure() { return 0; }
    fake_delete() { delete_count=$((delete_count + 1)); }

    local status=0
    run_preflight_namespace_state_machine collision fake_exists fake_add fake_configure fake_delete \
        >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 126 ] || [ "$add_count" -ne 0 ] || [ "$delete_count" -ne 0 ]; then
        echo "ERROR: preflight collision self-test deleted or replaced a preexisting namespace"
        return 1
    fi

    fake_absent() { return 1; }
    fake_add_failure() { return 42; }
    status=0
    run_preflight_namespace_state_machine add-failure fake_absent fake_add_failure \
        fake_configure fake_delete >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 42 ] || [ "$delete_count" -ne 0 ]; then
        echo "ERROR: failed preflight add triggered deletion without ownership"
        return 1
    fi

    local success_add_count=0
    local success_delete_count=0
    fake_success_add() { success_add_count=$((success_add_count + 1)); }
    fake_success_delete() { success_delete_count=$((success_delete_count + 1)); }
    status=0
    run_preflight_namespace_state_machine success fake_absent fake_success_add \
        fake_configure fake_success_delete >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 0 ] || [ "$success_add_count" -ne 1 ] ||
        [ "$success_delete_count" -ne 1 ]; then
        echo "ERROR: successful preflight retained the expected-absence status"
        return 1
    fi

    fake_owned_add() { add_count=$((add_count + 1)); }
    fake_configure_failure() { return 41; }
    status=0
    run_preflight_namespace_state_machine owned fake_absent fake_owned_add \
        fake_configure_failure fake_delete >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 41 ] || [ "$add_count" -ne 1 ] || [ "$delete_count" -ne 1 ]; then
        echo "ERROR: owned preflight namespace was not cleaned after configuration failure"
        return 1
    fi

    fake_delete_failure() {
        delete_count=$((delete_count + 1))
        return 1
    }
    status=0
    run_preflight_namespace_state_machine cleanup-failure fake_absent fake_owned_add \
        fake_configure fake_delete_failure >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 125 ] || [ "$add_count" -ne 2 ] || [ "$delete_count" -ne 2 ]; then
        echo "ERROR: preflight namespace cleanup failure was not surfaced"
        return 1
    fi

    if kmsg_gate_status 1 0; then
        echo "ERROR: strict kmsg gate accepted an unavailable audit source"
        return 1
    fi
    status=0
    kmsg_gate_status 0 0 || status=$?
    if [ "$status" -ne 77 ]; then
        echo "ERROR: optional kmsg gate did not return the skip status"
        return 1
    fi
    kmsg_gate_status 1 1

    local capability_ops=""
    local capability_root=""
    local capability_source="source-axisd"
    local capability_install="installed-axisd"
    KMSG_AXISD_INSTALL=""
    KMSG_CAPABILITY_INSTALLED=0
    fake_cap_collision() { return 1; }
    fake_cap_absent() { return 0; }
    fake_cap_install() { capability_ops+="install:$1:$2 "; }
    fake_cap_grant() {
        if [ "$KMSG_AXISD_INSTALL" != "$1" ] || [ "$KMSG_CAPABILITY_INSTALLED" -ne 1 ]; then
            return 91
        fi
        capability_ops+="grant:$1 "
    }
    fake_cap_inspect() { printf '%s cap_dac_read_search,cap_syslog=ep\n' "$1"; }
    fake_cap_inspect_wrong() { printf '%s cap_syslog=ep\n' "$1"; }
    fake_cap_revoke() { capability_ops+="revoke:$1 "; }
    fake_cap_revoke_failure() {
        capability_ops+="revoke:$1 "
        return 1
    }
    fake_cap_remove() { capability_ops+="remove:$1 "; }
    local bundle_checks=0
    fake_bundle_collision() {
        bundle_checks=$((bundle_checks + 1))
        [ "$1" != "$capability_install" ]
    }

    status=0
    reject_kmsg_bundle_collisions \
        "$capability_install" launcher-install fake_bundle_collision || status=$?
    if [ "$status" -ne 1 ] || [ "$bundle_checks" -ne 1 ]; then
        echo "ERROR: kmsg bundle collision self-test discarded the first path failure"
        return 1
    fi

    status=0
    install_kmsg_capability_binary "$capability_source" "$capability_install" \
        fake_cap_collision fake_cap_install fake_cap_grant fake_cap_inspect \
        >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 1 ] || [ -n "$capability_ops" ] || [ -n "$KMSG_AXISD_INSTALL" ]; then
        echo "ERROR: kmsg capability collision self-test modified existing state"
        return 1
    fi

    install_kmsg_capability_binary "$capability_source" "$capability_install" \
        fake_cap_absent fake_cap_install fake_cap_grant fake_cap_inspect
    if [ "$capability_ops" != \
        "install:${capability_source}:${capability_install} grant:${capability_install} " ]; then
        echo "ERROR: kmsg capability install self-test violated operation ordering"
        return 1
    fi
    cleanup_kmsg_capability_binary fake_cap_revoke fake_cap_remove
    if [ "$capability_ops" != \
        "install:${capability_source}:${capability_install} grant:${capability_install} revoke:${capability_install} remove:${capability_install} " ]; then
        echo "ERROR: kmsg capability cleanup self-test did not revoke before removal"
        return 1
    fi

    capability_ops=""
    KMSG_AXISD_INSTALL=""
    KMSG_CAPABILITY_INSTALLED=0
    status=0
    install_kmsg_capability_binary "$capability_source" "$capability_install" \
        fake_cap_absent fake_cap_install fake_cap_grant fake_cap_inspect_wrong \
        >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 1 ] || [ "$KMSG_CAPABILITY_INSTALLED" -ne 1 ]; then
        echo "ERROR: kmsg capability verification self-test accepted an incomplete grant"
        return 1
    fi
    status=0
    cleanup_kmsg_capability_binary fake_cap_revoke_failure fake_cap_remove \
        >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 1 ] || [[ "$capability_ops" != *"remove:${capability_install} " ]]; then
        echo "ERROR: kmsg capability cleanup self-test hid revocation failure or skipped removal"
        return 1
    fi

    local mock_nf_log_value=1
    local mock_nf_log_writes=""
    NF_LOG_ALL_NETNS_ORIGINAL=""
    NF_LOG_ALL_NETNS_CHANGED=0
    fake_nf_log_read() { printf '%s\n' "$mock_nf_log_value"; }
    fake_nf_log_write() {
        if [ "$NF_LOG_ALL_NETNS_CHANGED" -ne 1 ] || [ "$NF_LOG_ALL_NETNS_ORIGINAL" != "0" ]; then
            return 92
        fi
        mock_nf_log_value="$1"
        mock_nf_log_writes+="$1 "
    }
    provision_nf_log_all_netns fake_nf_log_read fake_nf_log_write
    if [ -n "$mock_nf_log_writes" ] || [ "$NF_LOG_ALL_NETNS_CHANGED" -ne 0 ]; then
        echo "ERROR: pre-enabled netfilter logging self-test changed kernel state"
        return 1
    fi

    mock_nf_log_value=0
    provision_nf_log_all_netns fake_nf_log_read fake_nf_log_write
    if [ "$mock_nf_log_value" != "1" ] || [ "$mock_nf_log_writes" != "1 " ]; then
        echo "ERROR: netfilter logging provisioning self-test did not enable namespaced logs"
        return 1
    fi
    restore_nf_log_all_netns fake_nf_log_write
    if [ "$mock_nf_log_value" != "0" ] || [ "$mock_nf_log_writes" != "1 0 " ]; then
        echo "ERROR: netfilter logging provisioning self-test did not restore kernel state"
        return 1
    fi

    capability_root="$(mktemp -d)"
    python3 - "$capability_root/audit.log" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
events = [
    {
        "target": "axis::audit",
        "fields": {"message": json.dumps({
            "category": "security_finding",
            "sandbox_id": "wrong-sandbox",
            "message": "network bypass attempt to 10.0.0.1:443 rejected by firewall",
            "details": {"destination_port": 443},
        })},
    },
    {
        "target": "axis::audit",
        "fields": {"message": json.dumps({
            "category": "sandbox_lifecycle",
            "sandbox_id": "expected-sandbox",
            "message": "sandbox created",
            "details": {},
        })},
    },
    {"target": "axisd", "fields": {"message": "probe destination port 443"}},
]
path.write_text("".join(json.dumps(event) + "\n" for event in events))
PY
    if audit_log_contains_matching_bypass \
        "$capability_root/audit.log" expected-sandbox 443; then
        echo "ERROR: structured bypass audit matcher combined unrelated log lines"
        rm -rf "$capability_root"
        return 1
    fi
    python3 - "$capability_root/audit.log" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
event = {
    "target": "axis::audit",
    "fields": {"message": json.dumps({
        "category": "security_finding",
        "sandbox_id": "expected-sandbox",
        "message": "network bypass attempt to 10.0.0.1:443 rejected by firewall",
        "details": {"destination_port": 443},
    })},
}
with path.open("a") as output:
    output.write(json.dumps(event) + "\n")
PY
    if ! audit_log_contains_matching_bypass \
        "$capability_root/audit.log" expected-sandbox 443; then
        echo "ERROR: structured bypass audit matcher rejected an exact record"
        rm -rf "$capability_root"
        return 1
    fi
    rm -rf "$capability_root"

    fake_present() { return 0; }
    fake_unknown() { return 2; }
    lifecycle_resources_absent state namespace veth fake_absent fake_absent fake_absent
    status=0
    lifecycle_resources_absent state namespace veth fake_present fake_absent fake_absent || status=$?
    if [ "$status" -ne 1 ]; then
        echo "ERROR: lifecycle cleanup self-test accepted surviving state"
        return 1
    fi
    status=0
    lifecycle_resources_absent state namespace veth fake_absent fake_present fake_absent || status=$?
    if [ "$status" -ne 1 ]; then
        echo "ERROR: lifecycle cleanup self-test accepted a surviving namespace"
        return 1
    fi
    status=0
    lifecycle_resources_absent state namespace veth fake_absent fake_absent fake_present || status=$?
    if [ "$status" -ne 1 ]; then
        echo "ERROR: lifecycle cleanup self-test accepted a surviving veth"
        return 1
    fi
    status=0
    lifecycle_resources_absent state namespace veth fake_unknown fake_absent fake_absent || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup self-test hid a probe failure"
        return 1
    fi

    local -a wait_statuses=()
    local wait_index=0
    local destroy_count=0
    fake_wait() {
        local result="${wait_statuses[$wait_index]}"
        wait_index=$((wait_index + 1))
        return "$result"
    }
    fake_token() { printf '%064d\n' 0; }
    fake_malformed_token() { printf 'invalid\n'; }
    fake_token_failure() { return 42; }
    fake_destroy() { destroy_count=$((destroy_count + 1)); }
    fake_destroy_failure() {
        destroy_count=$((destroy_count + 1))
        return 43
    }

    wait_statuses=(0)
    wait_index=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_unknown fake_token fake_destroy
    if [ "$wait_index" -ne 1 ] || [ "$destroy_count" -ne 0 ]; then
        echo "ERROR: completed lifecycle cleanup performed unnecessary authentication"
        return 1
    fi
    wait_statuses=(2)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_absent fake_token fake_destroy || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup hid an initial resource probe failure"
        return 1
    fi
    wait_statuses=(1 0)
    wait_index=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_absent fake_token fake_destroy
    wait_statuses=(1 1)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_absent fake_token fake_destroy || status=$?
    if [ "$status" -ne 3 ]; then
        echo "ERROR: lifecycle cleanup accepted surviving resources without helper state"
        return 1
    fi
    wait_statuses=(1 2)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_absent fake_token fake_destroy || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup hid a missing-state confirmation failure"
        return 1
    fi
    wait_statuses=(1)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_unknown fake_token fake_destroy || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup hid a helper state probe failure"
        return 1
    fi
    for token_fn in fake_malformed_token fake_token_failure; do
        wait_statuses=(1 0)
        wait_index=0
        status=0
        cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present "$token_fn" fake_destroy || status=$?
        if [ "$status" -ne 0 ] || [ "$destroy_count" -ne 0 ]; then
            echo "ERROR: lifecycle cleanup rejected concurrent completion after token read failure"
            return 1
        fi
    done
    wait_statuses=(1 1)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present fake_malformed_token fake_destroy || status=$?
    if [ "$status" -ne 4 ]; then
        echo "ERROR: lifecycle cleanup accepted a malformed token while resources survived"
        return 1
    fi
    wait_statuses=(1 2)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present fake_malformed_token fake_destroy || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup hid a post-token resource probe failure"
        return 1
    fi
    for destroy_fn in fake_destroy fake_destroy_failure; do
        wait_statuses=(1 0)
        wait_index=0
        destroy_count=0
        cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present fake_token "$destroy_fn"
        if [ "$destroy_count" -ne 1 ]; then
            echo "ERROR: lifecycle cleanup did not attempt authenticated destruction exactly once"
            return 1
        fi
    done
    wait_statuses=(1 1)
    wait_index=0
    destroy_count=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present fake_token fake_destroy || status=$?
    if [ "$status" -ne 5 ] || [ "$destroy_count" -ne 1 ]; then
        echo "ERROR: lifecycle cleanup accepted resources surviving authenticated destruction"
        return 1
    fi
    wait_statuses=(1 2)
    wait_index=0
    status=0
    cleanup_lifecycle_resources sandbox namespace veth fake_wait fake_present fake_token fake_destroy || status=$?
    if [ "$status" -ne 2 ]; then
        echo "ERROR: lifecycle cleanup hid its final resource probe failure"
        return 1
    fi
    echo "PASS: rootless preflight, kmsg capability, and audit matcher self-tests"
}

if [ "${1:-}" = "--self-test" ]; then
    run_rootless_harness_self_tests
    exit 0
fi

if [ "${AXIS_REQUIRE_NETNS_HELPER_E2E:-}" = "1" ] && [ "${AXIS_RUN_PRIVILEGED_E2E:-}" != "1" ]; then
    echo "ERROR: AXIS_REQUIRE_NETNS_HELPER_E2E=1 requires AXIS_RUN_PRIVILEGED_E2E=1"
    exit 1
fi
if [ "${AXIS_RUN_PRIVILEGED_E2E:-}" != "1" ]; then
    echo "SKIP: set AXIS_RUN_PRIVILEGED_E2E=1 in an ephemeral CI/container runner"
    exit 77
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: helper launch proof must run cargo test as a non-root user"
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: sudo is required to install the helper inside the ephemeral test runner"
    exit 1
fi

for tool in cargo install stat timeout tail readlink python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not found on PATH: $tool"
        exit 1
    fi
done

for tool in ip iptables sysctl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required netns proof tool not found on PATH: $tool"
        exit 1
    fi
done

bounded() {
    local seconds="$1"
    shift
    local status=0
    timeout --kill-after=1s "${seconds}s" "$@" || status=$?
    if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
        echo "ERROR: command exceeded ${seconds}s deadline: $*" >&2
        return 125
    fi
    return "$status"
}

bounded_sudo() {
    local seconds="$1"
    shift
    bounded "$((seconds + 2))" sudo -n timeout --kill-after=1s "${seconds}s" "$@"
}

if ! bounded_sudo 2 true >/dev/null 2>&1; then
    echo "ERROR: bounded passwordless sudo is required in the ephemeral test runner"
    exit 1
fi

if [ "${AXIS_REQUIRE_NETNS_HELPER_E2E:-}" = "1" ] && [ -z "${AXIS_EXPECT_MXC_EXECUTOR:-}" ]; then
    echo "ERROR: strict helper proof requires AXIS_EXPECT_MXC_EXECUTOR"
    exit 1
fi
expected_executor="${AXIS_EXPECT_MXC_EXECUTOR:-/usr/local/bin/lxc-exec}"
case "$expected_executor" in
    /usr/local/bin/lxc-exec | /usr/bin/lxc-exec) ;;
    *)
        echo "ERROR: helper proof executor must use an allowed system lxc-exec path"
        exit 1
        ;;
esac
executor_build="${AXIS_MXC_EXECUTOR_BUILD:-}"
if [ -z "$executor_build" ] || [ ! -x "$executor_build" ]; then
    echo "ERROR: AXIS_MXC_EXECUTOR_BUILD must name the locally built executable"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/axis-netns-helper-e2e-XXXXXX)"
HOST_PEER_MARKER="${REPO_ROOT}/.axis-host-peer-checked-$$"
SERVER_PID=""
DIRECT_SERVER_PID=""
AXSD_PID=""
PROXY_PROOF_PID=""
PREFLIGHT_NS=""
PREFLIGHT_NS_CREATED=0
HELPER_INSTALL="/usr/libexec/axis/axis-netns-helper"
KMSG_AXISD_PATH="/usr/libexec/axis/axisd-kmsg-e2e"
KMSG_LAUNCHER_PATH="/usr/libexec/axis/axis-seccomp-launcher"
INSTALLED_HELPER=0
INSTALLED_MXC_EXECUTOR=0
CREATED_HELPER_DIR=0
KMSG_AXISD_INSTALL=""
KMSG_CAPABILITY_INSTALLED=0
KMSG_LAUNCHER_INSTALL=""
KMSG_LAUNCHER_SOURCE=""
NF_LOG_ALL_NETNS_CHANGED=0
NF_LOG_ALL_NETNS_ORIGINAL=""
# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap.
cleanup() {
    local original_status=$?
    local cleanup_failed=0
    set +e
    if declare -F stop_background_servers >/dev/null; then
        stop_background_servers
    fi
    if [ -n "$AXSD_PID" ]; then
        terminate_background_process "$AXSD_PID" "axisd cleanup"
    fi
    if [ -n "$PROXY_PROOF_PID" ]; then
        terminate_background_process "$PROXY_PROOF_PID" "proxy proof cleanup"
    fi
    if declare -F write_nf_log_all_netns >/dev/null; then
        if ! restore_nf_log_all_netns write_nf_log_all_netns; then
            echo "ERROR: failed to restore net.netfilter.nf_log_all_netns" >&2
            cleanup_failed=1
        fi
    fi
    if declare -F revoke_kmsg_capabilities >/dev/null; then
        if ! cleanup_kmsg_capability_binary \
            revoke_kmsg_capabilities remove_kmsg_axisd; then
            cleanup_failed=1
        fi
    fi
    if [ "$INSTALLED_HELPER" -eq 1 ]; then
        if ! bounded_sudo 5 rm -f "$HELPER_INSTALL"; then
            echo "ERROR: failed to remove installed helper: $HELPER_INSTALL" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$CREATED_HELPER_DIR" -eq 1 ]; then
        if ! bounded_sudo 5 rmdir /usr/libexec/axis; then
            echo "ERROR: failed to remove owned helper install directory: /usr/libexec/axis" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$INSTALLED_MXC_EXECUTOR" -eq 1 ]; then
        if ! bounded_sudo 5 rm -f "$expected_executor"; then
            echo "ERROR: failed to remove installed MXC executor: $expected_executor" >&2
            cleanup_failed=1
        fi
    fi
    if [ "$PREFLIGHT_NS_CREATED" -eq 1 ] && [ -n "$PREFLIGHT_NS" ]; then
        if ! bounded_sudo 5 ip netns del "$PREFLIGHT_NS"; then
            echo "ERROR: failed to remove owned preflight namespace: $PREFLIGHT_NS" >&2
            cleanup_failed=1
        fi
    fi
    rm -f /tmp/axis-helper-lifecycle-*"$$".sock
    if ! rm -f "$HOST_PEER_MARKER"; then
        echo "ERROR: failed to remove host peer completion marker: $HOST_PEER_MARKER" >&2
        cleanup_failed=1
    fi
    if ! rm -rf "$TMP_ROOT"; then
        echo "ERROR: failed to remove helper test directory: $TMP_ROOT" >&2
        cleanup_failed=1
    fi
    trap - EXIT
    if [ "$original_status" -ne 0 ]; then
        exit "$original_status"
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
}
trap cleanup EXIT

provision_kmsg_audit_source() {
    local axisd_binary="$1"
    local launcher_binary="$2"

    [ "${AXIS_PROVISION_KMSG_AUDIT_E2E:-}" = "1" ] || return 0
    if [ ! -c /dev/kmsg ]; then
        echo "ERROR: strict kmsg provisioning requires /dev/kmsg"
        return 1
    fi
    if ! command -v getcap >/dev/null || ! command -v setcap >/dev/null; then
        echo "ERROR: strict kmsg provisioning requires getcap and setcap"
        return 1
    fi
    KMSG_LAUNCHER_SOURCE="$launcher_binary"
    install_kmsg_capability_binary "$axisd_binary" "$KMSG_AXISD_PATH" \
        reject_kmsg_axisd_collision install_kmsg_axisd grant_kmsg_capabilities \
        inspect_kmsg_capabilities
}

reject_kmsg_axisd_collision() {
    reject_kmsg_bundle_collisions \
        "$1" "$KMSG_LAUNCHER_PATH" reject_preexisting_privileged_path
}

install_kmsg_axisd() {
    bounded_sudo 5 install -o root -g root -m 0755 "$1" "$2"
    KMSG_LAUNCHER_INSTALL="$KMSG_LAUNCHER_PATH"
    bounded_sudo 5 install -o root -g root -m 0755 \
        "$KMSG_LAUNCHER_SOURCE" "$KMSG_LAUNCHER_INSTALL"
}

grant_kmsg_capabilities() {
    bounded_sudo 5 setcap cap_dac_read_search,cap_syslog=ep "$1"
}

inspect_kmsg_capabilities() {
    bounded 2 getcap "$1"
}

revoke_kmsg_capabilities() {
    bounded_sudo 5 setcap -r "$1"
}

remove_kmsg_axisd() {
    local status=0
    bounded_sudo 5 rm -f "$1" || status=$?
    if [ -n "$KMSG_LAUNCHER_INSTALL" ]; then
        bounded_sudo 5 rm -f "$KMSG_LAUNCHER_INSTALL" || status=$?
    fi
    return "$status"
}

read_nf_log_all_netns() {
    bounded 2 sysctl -n net.netfilter.nf_log_all_netns
}

write_nf_log_all_netns() {
    bounded_sudo 5 sysctl -q -w "net.netfilter.nf_log_all_netns=$1"
}

kmsg_source_available() {
    if [ "$KMSG_CAPABILITY_INSTALLED" -eq 1 ]; then
        return 0
    fi
    bounded 2 "$PYTHON_BIN" - <<'PY'
import os

fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
os.close(fd)
PY
}

reject_preexisting_privileged_path() {
    local path="$1"
    local label="$2"
    local status=0
    if bounded_sudo 2 test -e "$path"; then
        echo "ERROR: refusing to overwrite preexisting $label: $path"
        return 1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "ERROR: timed out or failed while checking $label path: $path"
            return "$status"
        fi
    fi
    if bounded_sudo 2 test -L "$path"; then
        echo "ERROR: refusing to overwrite preexisting $label symlink: $path"
        return 1
    else
        status=$?
        if [ "$status" -ne 1 ]; then
            echo "ERROR: timed out or failed while checking $label symlink: $path"
            return "$status"
        fi
    fi
}

validate_privileged_directory() {
    local path="$1"
    local label="$2"
    local metadata=""
    local owner=""
    local kind=""
    local mode=""
    local status=0

    bounded_sudo 2 test -L "$path" || status=$?
    if [ "$status" -eq 0 ]; then
        echo "ERROR: $label must not be a symlink: $path"
        return 1
    elif [ "$status" -ne 1 ]; then
        echo "ERROR: failed or timed out checking $label symlink: $path"
        return "$status"
    fi
    metadata="$(bounded_sudo 2 stat -c '%u|%F|%a' "$path")" || return $?
    IFS='|' read -r owner kind mode <<<"$metadata"
    if [ "$owner" != "0" ] || [ "$kind" != "directory" ] ||
        [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || ((8#$mode & 022)); then
        echo "ERROR: $label must be a root-owned non-writable real directory: $path ($metadata)"
        return 1
    fi
}

validate_privileged_directory "$(dirname "$expected_executor")" "MXC executor parent"
reject_preexisting_privileged_path "$expected_executor" "MXC executor"
INSTALLED_MXC_EXECUTOR=1
bounded_sudo 5 install -o root -g root -m 0755 "$executor_build" "$expected_executor"
resolved_executor="$(bounded 2 readlink -f "$(command -v lxc-exec)")"
if [ "$resolved_executor" != "$expected_executor" ]; then
    echo "ERROR: lxc-exec resolves to $resolved_executor, expected $expected_executor"
    exit 1
fi
executor_metadata="$(bounded 2 stat -c '%u:%g %a' "$expected_executor")"
if [ "$executor_metadata" != "0:0 755" ]; then
    echo "ERROR: trusted lxc-exec mode mismatch: $executor_metadata"
    exit 1
fi

terminate_background_process() {
    local pid="$1"
    local label="$2"
    bounded 2 kill -KILL "$pid" 2>/dev/null || true
    if bounded 2 tail --pid="$pid" -f /dev/null >/dev/null 2>&1; then
        wait "$pid" 2>/dev/null || true
    else
        echo "WARNING: $label process $pid did not exit within cleanup deadline" >&2
    fi
}

process_start_time() {
    local pid="$1"
    bounded 2 python3 - "$pid" <<'PY'
import pathlib
import sys

path = pathlib.Path("/proc") / sys.argv[1] / "stat"
try:
    contents = path.read_text()
except FileNotFoundError:
    raise SystemExit(1)
except OSError as error:
    print(f"ERROR: read {path}: {error}", file=sys.stderr)
    raise SystemExit(2)
fields = contents.rsplit(")", 1)
if len(fields) != 2:
    print(f"ERROR: malformed process stat for {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(2)
remainder = fields[1].split()
if len(remainder) <= 19:
    print(f"ERROR: incomplete process stat for {sys.argv[1]}", file=sys.stderr)
    raise SystemExit(2)
print(remainder[19])
PY
}

process_identity_matches() {
    local pid="$1"
    local expected_start_time="$2"
    local actual_start_time=""
    local status=0
    actual_start_time="$(process_start_time "$pid")" || status=$?
    if [ "$status" -eq 1 ]; then
        return 1
    fi
    if [ "$status" -ne 0 ]; then
        return 2
    fi
    [ "$actual_start_time" = "$expected_start_time" ]
}

namespace_exists() {
    local namespace="$1"
    local listing=""
    local names=""
    local status=0
    listing="$(bounded_sudo 5 ip netns list 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "ERROR: failed to list network namespaces (status $status): $listing" >&2
        return 2
    fi
    # shellcheck disable=SC2016 # The awk field expression is literal.
    names="$(bounded 2 awk '{print $1}' <<<"$listing")" || {
        status=$?
        echo "ERROR: failed to parse network namespaces (status $status)" >&2
        return 2
    }
    grep -Fxq "$namespace" <<<"$names"
}

host_veth_exists() {
    local veth_name="$1"
    local listing=""
    local names=""
    local status=0
    listing="$(bounded 5 ip -o link show 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "ERROR: failed to list host network links (status $status): $listing" >&2
        return 2
    fi
    # shellcheck disable=SC2016 # The awk field expression is literal.
    names="$(bounded 2 awk -F ': ' '{ sub(/@.*/, "", $2); print $2 }' <<<"$listing")" || {
        status=$?
        echo "ERROR: failed to parse host network links (status $status)" >&2
        return 2
    }
    grep -Fxq "$veth_name" <<<"$names"
}

helper_state_exists() {
    local state_path="$1"
    local state_name="${state_path##*/}"
    local listing=""
    local status=0
    listing="$(bounded_sudo 2 find /run/axis/netns -mindepth 1 -maxdepth 1 \
        -name "$state_name" -print 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "ERROR: failed to list helper state (status $status): $listing" >&2
        return 2
    fi
    grep -Fxq "$state_path" <<<"$listing"
}

stop_background_servers() {
    if [ -n "$SERVER_PID" ]; then
        terminate_background_process "$SERVER_PID" "TCP server cleanup"
        SERVER_PID=""
    fi
    if [ -n "$DIRECT_SERVER_PID" ]; then
        terminate_background_process "$DIRECT_SERVER_PID" "direct server cleanup"
        DIRECT_SERVER_PID=""
    fi
}

wait_for_port_file() {
    local port_file="$1"
    for _ in $(seq 1 50); do
        [ -s "$port_file" ] && return 0
        sleep 0.1
    done
    return 1
}

wait_for_socket_path() {
    local socket_path="$1"
    for _ in $(seq 1 50); do
        [ -S "$socket_path" ] && return 0
        sleep 0.1
    done
    return 1
}

capability_skip_output() {
    grep -Fq "resources: process count rlimit fallback requires a dedicated run_as_user" <<<"$1" ||
        grep -Fq "resources: CPU rate limits require writable cgroups v2" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is unavailable" <<<"$1" ||
        grep -Fq "resources: cgroups v2 is read-only" <<<"$1" ||
        grep -Fq "seccomp: seccomp is unavailable" <<<"$1" ||
        grep -Fq "filesystem: Landlock unavailable" <<<"$1"
}

helper_launch_capability_skip_output() {
    grep -Fq "netns helper setup failed:" <<<"$1" &&
        grep -Fq "/iptables -A OUTPUT" <<<"$1"
}

skip_or_require() {
    local require_var="$1"
    local message="$2"
    echo "SKIP: $message"
    if [ "${!require_var:-}" = "1" ]; then
        echo "ERROR: $require_var=1 makes this skip a failure"
        exit 1
    fi
    exit 0
}

start_tcp_server() {
    local port_file="$1"
    local bind_addr="$2"
    local pid_var="$3"
    python3 - "$port_file" "$bind_addr" <<'PY' &
import pathlib
import socket
import sys

port_file = pathlib.Path(sys.argv[1])
bind_addr = sys.argv[2]
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((bind_addr, 0))
server.listen(1)
server.settimeout(30)
port_file.write_text(str(server.getsockname()[1]))
try:
    conn, _ = server.accept()
    conn.settimeout(30)
    try:
        data = conn.recv(1)
        if data:
            conn.sendall(b"AXIS-ECHO")
    except socket.timeout:
        pass
    conn.close()
except socket.timeout:
    pass
finally:
    server.close()
PY
    printf -v "$pid_var" '%s' "$!"
}

write_proxy_policy() {
    local policy_file="$1"
    local policy_name="$2"
    local allowed_port="$3"
    local runtime_provider="${4:-auto}"
    local include_proc="${5:-0}"
    cat >"$policy_file" <<EOF
version: 1
name: ${policy_name}

runtime:
  containment: process
  provider: ${runtime_provider}

filesystem:
  read_only:
EOF
    for path in /bin /sbin /usr /lib /lib64 /etc /nix/store; do
        if [ -e "$path" ]; then
            printf '    - %s\n' "$path" >>"$policy_file"
        fi
    done
    if [ "$include_proc" = "1" ]; then
        printf '    - /proc\n' >>"$policy_file"
    fi
    cat >>"$policy_file" <<EOF
  read_write:
    - "{workspace}"

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0

network:
  mode: proxy
  policies:
    - name: local-target
      endpoints:
        - host: "127.0.0.1"
          port: ${allowed_port}
EOF
}

snapshot_helper_states() {
    local output_file="$1"
    bounded_sudo 5 find /run/axis/netns -mindepth 1 -maxdepth 1 \
        ! -name .lock \
        -printf '%f\n' 2>/dev/null | bounded 2 sort >"$output_file"
}

wait_for_new_helper_state() {
    local before_file="$1"
    local current_file="$2"
    local owner_pid="$3"
    local owner_start_time="$4"
    local sandbox_id=""
    for _ in $(seq 1 100); do
        snapshot_helper_states "$current_file"
        sandbox_id="$(comm -13 "$before_file" "$current_file" | \
            grep -Em1 '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || true)"
        if [ -n "$sandbox_id" ]; then
            printf '%s\n' "$sandbox_id"
            return 0
        fi
        local probe_status=0
        process_identity_matches "$owner_pid" "$owner_start_time" || probe_status=$?
        if [ "$probe_status" -eq 2 ]; then
            return 2
        fi
        if [ "$probe_status" -ne 0 ]; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

wait_for_process_exit_bounded() {
    local pid="$1"
    local label="$2"
    if ! bounded 10 tail --pid="$pid" -f /dev/null; then
        echo "ERROR: $label process $pid did not exit within 10 seconds"
        return 1
    fi
    local status=0
    wait "$pid" || status=$?
    printf 'INFO: %s process exited with status %s\n' "$label" "$status"
}

assert_helper_lifecycle_cleanup() {
    local sandbox_id="$1"
    local veth_name="$2"
    local payload_pids_file="$3"
    local state_path="/run/axis/netns/${sandbox_id}"
    local namespace="axis-${sandbox_id}"

    for _ in $(seq 1 100); do
        local state_exists=0
        local namespace_present=0
        local veth_exists=0
        local probe_status=0
        bounded_sudo 2 test -e "$state_path" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            state_exists=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        probe_status=0
        namespace_exists "$namespace" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            namespace_present=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        probe_status=0
        host_veth_exists "$veth_name" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            veth_exists=1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
        if [ "$state_exists" -eq 0 ] && [ "$namespace_present" -eq 0 ] && [ "$veth_exists" -eq 0 ]; then
            break
        fi
        sleep 0.1
    done

    local probe_status=0
    bounded_sudo 2 test -e "$state_path" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: helper state survived lifecycle cleanup: $state_path"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    namespace_exists "$namespace" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: network namespace survived lifecycle cleanup: $namespace"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    host_veth_exists "$veth_name" || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: host veth survived lifecycle cleanup: $veth_name"
        return 1
    elif [ "$probe_status" -ne 1 ]; then
        return 1
    fi
    probe_status=0
    bounded_sudo 5 ip netns exec "$namespace" iptables -S OUTPUT >/dev/null 2>&1 || probe_status=$?
    if [ "$probe_status" -eq 0 ]; then
        echo "ERROR: namespace firewall remained reachable after lifecycle cleanup: $namespace"
        return 1
    elif [ "$probe_status" -eq 125 ]; then
        return 1
    fi

    while read -r pid start_time; do
        [ -n "$pid" ] || continue
        probe_status=0
        process_identity_matches "$pid" "$start_time" || probe_status=$?
        if [ "$probe_status" -eq 0 ]; then
            echo "ERROR: payload namespace member survived lifecycle cleanup: $pid $start_time"
            return 1
        elif [ "$probe_status" -ne 1 ]; then
            return 1
        fi
    done <"$payload_pids_file"

    local stale_temp=""
    stale_temp="$(bounded_sudo 5 find /run/axis/netns -mindepth 1 -maxdepth 1 \
        -name ".tmp-u$(id -u)-*" -print -quit)"
    if [ -n "$stale_temp" ]; then
        echo "ERROR: attributable helper state temp survived lifecycle cleanup: $stale_temp"
        return 1
    fi
}

# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the per-case EXIT trap.
cleanup_helper_lifecycle_case() {
    local original_status=$?
    local owner_pid="$1"
    local helper_pid="$2"
    local sandbox_id="$3"
    local namespace="$4"
    local veth_name="$5"
    local socket_path="$6"
    local _before_states="$7"
    local _current_states="$8"
    local owner_start_time="$9"
    local helper_start_time="${10}"
    local cleanup_failed=0
    local probe_status=0
    set +e

    if [ -n "$owner_pid" ] && [ -n "$owner_start_time" ] &&
        process_identity_matches "$owner_pid" "$owner_start_time"; then
        if ! bounded 2 kill -KILL "$owner_pid"; then
            echo "ERROR: failed to terminate lifecycle owner $owner_pid" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$helper_pid" ] && [ -n "$helper_start_time" ] &&
        process_identity_matches "$helper_pid" "$helper_start_time"; then
        if ! bounded 2 kill -KILL "$helper_pid"; then
            echo "ERROR: failed to terminate lifecycle helper $helper_pid" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$owner_pid" ]; then
        if bounded 2 tail --pid="$owner_pid" -f /dev/null >/dev/null 2>&1; then
            wait "$owner_pid" 2>/dev/null || true
        else
            echo "ERROR: lifecycle owner $owner_pid did not exit within cleanup deadline" >&2
            cleanup_failed=1
        fi
    fi
    if [ -n "$sandbox_id" ]; then
        cleanup_lifecycle_resources "$sandbox_id" "$namespace" "$veth_name" || probe_status=$?
        if [ "$probe_status" -ne 0 ]; then
            case "$probe_status" in
                2) echo "ERROR: failed to inspect lifecycle resources for $sandbox_id" >&2 ;;
                3) echo "ERROR: lifecycle resources survived without authenticated helper state: $sandbox_id" >&2 ;;
                4) echo "ERROR: refusing lifecycle cleanup with missing or malformed state token: $sandbox_id" >&2 ;;
                5) echo "ERROR: authenticated lifecycle cleanup left resources for $sandbox_id" >&2 ;;
                *) echo "ERROR: unexpected lifecycle cleanup status $probe_status for $sandbox_id" >&2 ;;
            esac
            cleanup_failed=1
        fi
    elif [ "$original_status" -ne 0 ]; then
        echo "ERROR: lifecycle case failed before resource ownership could be identified; refusing name-only cleanup" >&2
    fi
    if ! rm -f "$socket_path"; then
        echo "ERROR: failed to remove lifecycle socket: $socket_path" >&2
        cleanup_failed=1
    fi
    trap - EXIT
    if [ "$original_status" -ne 0 ]; then
        exit "$original_status"
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
}

run_helper_lifecycle_case() (
    local provider="$1"
    local failure_mode="$2"
    local case_name="${provider}-${failure_mode}"
    local case_root="${TMP_ROOT}/lifecycle-${case_name}"
    local workspace="${case_root}/workspace"
    local policy="${case_root}/policy.yaml"
    local output="${case_root}/axis.out"
    local before_states="${case_root}/states.before"
    local current_states="${case_root}/states.current"
    local raw_payload_pids="${case_root}/payload-host-pids.raw"
    local payload_pids="${case_root}/payload-host-pids"
    local socket_path="/tmp/axis-helper-lifecycle-${case_name}-$$.sock"
    local owner_pid=""
    local owner_start_time=""
    local helper_pid=""
    local helper_start_time=""
    local sandbox_id=""
    local namespace=""
    local veth_name=""
    trap 'cleanup_helper_lifecycle_case "$owner_pid" "$helper_pid" "$sandbox_id" "$namespace" "$veth_name" "$socket_path" "$before_states" "$current_states" "$owner_start_time" "$helper_start_time"' EXIT
    mkdir -p "$workspace"
    if [ "$provider" = "axis_native" ]; then
        write_proxy_policy "$policy" "helper-lifecycle-${case_name}" 9 "$provider" 1
    else
        write_proxy_policy "$policy" "helper-lifecycle-${case_name}" 9 "$provider"
    fi
    snapshot_helper_states "$before_states"

    (
        cd "$workspace"
        exec env AXIS_SOCKET="$socket_path" "$AXIS_RELEASE" --socket "$socket_path" \
            run --policy "$policy" -- "$PYTHON_BIN" -c "$LIFECYCLE_PROBE"
    ) >"$output" 2>&1 &
    owner_pid=$!
    owner_start_time="$(process_start_time "$owner_pid")"

    if ! sandbox_id="$(wait_for_new_helper_state "$before_states" "$current_states" "$owner_pid" "$owner_start_time")"; then
        echo "ERROR: $case_name did not create helper state"
        cat "$output"
        return 1
    fi
    local state_path="/run/axis/netns/${sandbox_id}"
    namespace="axis-${sandbox_id}"
    veth_name="axh$(tr -d '-' <<<"$sandbox_id" | cut -c1-12)"

    for _ in $(seq 1 100); do
        [ -s "$workspace/lifecycle-ready" ] && break
        local probe_status=0
        process_identity_matches "$owner_pid" "$owner_start_time" || probe_status=$?
        if [ "$probe_status" -eq 2 ]; then
            return 1
        fi
        if [ "$probe_status" -ne 0 ]; then
            break
        fi
        sleep 0.1
    done
    if [ ! -s "$workspace/lifecycle-ready" ]; then
        echo "ERROR: $case_name payload did not reach its ready marker"
        if [ -s "$workspace/lifecycle-error" ]; then
            cat "$workspace/lifecycle-error"
        fi
        if [ -s "$workspace/leaked-helper-fds" ]; then
            echo "Leaked helper descriptors:"
            cat "$workspace/leaked-helper-fds"
        fi
        if [ -s "$workspace/visible-helper-config-fds" ]; then
            echo "Visible helper config descriptors:"
            cat "$workspace/visible-helper-config-fds"
        fi
        cat "$output"
        return 1
    fi
    if [ -s "$workspace/leaked-helper-fds" ]; then
        echo "ERROR: $case_name payload inherited helper-only descriptors"
        cat "$workspace/leaked-helper-fds"
        return 1
    fi
    if [ -s "$workspace/visible-helper-config-fds" ]; then
        echo "ERROR: $case_name payload can resolve a helper config descriptor"
        cat "$workspace/visible-helper-config-fds"
        return 1
    fi
    local probe_status=0
    namespace_exists "$namespace" || probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
        echo "ERROR: $case_name namespace was not present before termination: $namespace"
        return 1
    fi
    probe_status=0
    host_veth_exists "$veth_name" || probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
        echo "ERROR: $case_name host veth was not present before termination: $veth_name"
        return 1
    fi
    local firewall_rules=""
    firewall_rules="$(bounded_sudo 5 ip netns exec "$namespace" iptables -S OUTPUT)" || return 1
    if ! grep -Fq -- '-j REJECT' <<<"$firewall_rules"; then
        echo "ERROR: $case_name firewall deny rule was not present before termination"
        return 1
    fi
    bounded_sudo 5 ip netns pids "$namespace" >"$raw_payload_pids"
    : >"$payload_pids"
    while read -r pid; do
        [ -n "$pid" ] || continue
        local start_time=""
        local identity_status=0
        start_time="$(process_start_time "$pid")" || identity_status=$?
        if [ "$identity_status" -eq 1 ]; then
            continue
        fi
        if [ "$identity_status" -ne 0 ]; then
            return 1
        fi
        printf '%s %s\n' "$pid" "$start_time" >>"$payload_pids"
    done <"$raw_payload_pids"
    if [ "$(wc -l <"$payload_pids")" -lt 6 ]; then
        echo "ERROR: $case_name did not create the expected payload descendant tree"
        cat "$payload_pids"
        cat "$output"
        return 1
    fi
    local churn_before=""
    local churn_after=""
    churn_before="$(cat "$workspace/lifecycle-churner")"
    for _ in $(seq 1 50); do
        sleep 0.02
        churn_after="$(cat "$workspace/lifecycle-churner")"
        if [[ "$churn_before" =~ ^[0-9]+$ ]] && [[ "$churn_after" =~ ^[0-9]+$ ]] &&
            [ "$churn_after" -gt "$churn_before" ]; then
            break
        fi
    done
    if [[ ! "$churn_before" =~ ^[0-9]+$ ]] || [[ ! "$churn_after" =~ ^[0-9]+$ ]] ||
        [ "$churn_after" -le "$churn_before" ]; then
        echo "ERROR: $case_name did not sustain successful descendant churn"
        cat "$output"
        return 1
    fi
    if [ "$provider" = "mxc" ]; then
        local expected_executor_seen=0
        while read -r pid _start_time; do
            [ -n "$pid" ] || continue
            local executable=""
            local readlink_status=0
            executable="$(bounded_sudo 2 readlink -f "/proc/${pid}/exe" 2>/dev/null)" || readlink_status=$?
            if [ "$readlink_status" -eq 125 ]; then
                return 1
            fi
            if [ "$readlink_status" -ne 0 ]; then
                continue
            fi
            if [ "$executable" = "$expected_executor" ]; then
                expected_executor_seen=1
                break
            fi
        done <"$payload_pids"
        if [ "$expected_executor_seen" -ne 1 ]; then
            echo "ERROR: $case_name did not execute trusted MXC binary $expected_executor"
            while read -r pid _start_time; do
                bounded_sudo 2 readlink -f "/proc/${pid}/exe" 2>/dev/null || true
            done <"$payload_pids"
            return 1
        fi
    fi

    local boundary_pid
    # shellcheck disable=SC2016 # The awk field expression is literal.
    boundary_pid="$(bounded_sudo 2 awk 'NR == 4 && $1 == "payload" { print $2 }' "$state_path")"
    if [ -z "$boundary_pid" ]; then
        echo "ERROR: $case_name helper state did not record its PID namespace init"
        return 1
    fi
    helper_pid="$(bounded 2 ps -o ppid= -p "$boundary_pid" | bounded 2 tr -d '[:space:]')"
    if [ -z "$helper_pid" ]; then
        echo "ERROR: $case_name could not identify the setuid helper process"
        return 1
    fi
    helper_start_time="$(process_start_time "$helper_pid")"

    case "$failure_mode" in
        owner-death)
            process_identity_matches "$owner_pid" "$owner_start_time"
            bounded 2 kill -KILL "$owner_pid"
            ;;
        helper-sigkill)
            process_identity_matches "$helper_pid" "$helper_start_time"
            bounded 2 kill -KILL "$helper_pid"
            ;;
        *) echo "ERROR: unknown lifecycle failure mode: $failure_mode"; return 1 ;;
    esac
    wait_for_process_exit_bounded "$owner_pid" "$case_name owner"
    owner_pid=""
    assert_helper_lifecycle_cleanup "$sandbox_id" "$veth_name" "$payload_pids"
    helper_pid=""
    echo "PASS: $case_name removed payloads, helper state, namespace, firewall, and veth"
)

cd "$REPO_ROOT"

cargo build --locked -p axis-sandbox --bin axis-netns-helper

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="${REPO_ROOT}/${TARGET_DIR}" ;;
esac

HELPER_BUILD="${TARGET_DIR}/debug/axis-netns-helper"

if [ ! -x "$HELPER_BUILD" ]; then
    echo "ERROR: helper build output missing: $HELPER_BUILD"
    exit 1
fi

if ! reject_preexisting_privileged_path "$HELPER_INSTALL" "helper on an e2e runner"; then
    echo "Run this proof only in a disposable CI/container/VM without a preinstalled helper."
    exit 1
fi

validate_privileged_directory /usr/libexec "helper install parent"
helper_dir_status=0
bounded_sudo 2 test -e /usr/libexec/axis || helper_dir_status=$?
if [ "$helper_dir_status" -eq 0 ]; then
    validate_privileged_directory /usr/libexec/axis "helper install directory"
elif [ "$helper_dir_status" -eq 1 ]; then
    helper_dir_symlink_status=0
    bounded_sudo 2 test -L /usr/libexec/axis || helper_dir_symlink_status=$?
    if [ "$helper_dir_symlink_status" -eq 0 ]; then
        echo "ERROR: refusing dangling helper install directory symlink: /usr/libexec/axis"
        exit 1
    elif [ "$helper_dir_symlink_status" -ne 1 ]; then
        echo "ERROR: failed to inspect helper install directory symlink: /usr/libexec/axis"
        exit "$helper_dir_symlink_status"
    fi
    bounded_sudo 5 install -d -o root -g root -m 0755 /usr/libexec/axis
    CREATED_HELPER_DIR=1
else
    echo "ERROR: failed to inspect helper install directory: /usr/libexec/axis"
    exit "$helper_dir_status"
fi
INSTALLED_HELPER=1
bounded_sudo 5 install -o root -g root -m 4755 "$HELPER_BUILD" "$HELPER_INSTALL"

owner="$(bounded 2 stat -c '%u:%g %a' "$HELPER_INSTALL")"
if [ "$owner" != "0:0 4755" ]; then
    echo "ERROR: helper install mode mismatch: $owner"
    exit 1
fi

set +e
helper_check_output="$(bounded 10 "$HELPER_INSTALL" check 2>&1)"
helper_check_status=$?
set -e
if [ "$helper_check_status" -ne 0 ]; then
    echo "ERROR: installed helper failed availability check"
    echo "$helper_check_output"
    exit "$helper_check_status"
fi

preflight_suffix="$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-16)"
PREFLIGHT_NS="axis-helper-preflight-${preflight_suffix}-$$"
preflight_namespace_exists() {
    namespace_exists "$1"
}
preflight_namespace_add() {
    bounded_sudo 5 ip netns add "$1" || return $?
    PREFLIGHT_NS_CREATED=1
}
preflight_namespace_configure() {
    bounded_sudo 5 ip netns exec "$1" iptables -A OUTPUT -o lo -j ACCEPT
}
preflight_namespace_delete() {
    bounded_sudo 5 ip netns del "$1" || return $?
    PREFLIGHT_NS_CREATED=0
}
set +e
preflight_output_file="${TMP_ROOT}/preflight.out"
run_preflight_namespace_state_machine \
    "$PREFLIGHT_NS" \
    preflight_namespace_exists \
    preflight_namespace_add \
    preflight_namespace_configure \
    preflight_namespace_delete >"$preflight_output_file" 2>&1
preflight_status=$?
preflight_output="$(cat "$preflight_output_file")"
set -e
if [ "$preflight_status" -ne 0 ]; then
    if [ "$preflight_status" -eq 126 ]; then
        echo "$preflight_output"
        exit 1
    fi
    if [ "$preflight_status" -eq 125 ]; then
        echo "ERROR: netns helper preflight timed out or failed to clean up its namespace"
        echo "$preflight_output"
        exit 1
    fi
    skip_or_require \
        AXIS_REQUIRE_NETNS_HELPER_E2E \
        "netns helper launch proof requires privileged iptables in network namespaces (status $preflight_status): ${preflight_output//$'\n'/ }"
fi

HELPER_TEST_OUTPUT="${TMP_ROOT}/helper-test.out"
set +e
bounded 300 env AXIS_TEST_NETNS_HELPER_LAUNCH=1 cargo test --locked -p axis-sandbox \
    gated_netns_helper_launch_starts_proxy_mode_sandbox_as_unprivileged_daemon \
    -- --nocapture >"$HELPER_TEST_OUTPUT" 2>&1
helper_test_status=$?
set -e
if [ "$helper_test_status" -ne 0 ]; then
    helper_test_output="$(cat "$HELPER_TEST_OUTPUT")"
    if capability_skip_output "$helper_test_output" ||
        helper_launch_capability_skip_output "$helper_test_output"; then
        tail -n 120 "$HELPER_TEST_OUTPUT"
        skip_or_require \
            AXIS_REQUIRE_NETNS_HELPER_E2E \
            "netns helper launch proof is unavailable on this runner"
    fi
    cat "$HELPER_TEST_OUTPUT"
    exit "$helper_test_status"
fi
cat "$HELPER_TEST_OUTPUT"

echo ""
echo "=== Built axis proxy-mode proof ==="

cargo build --locked --release -p axis-cli -p axis-sandbox --bins
AXIS_RELEASE="${TARGET_DIR}/release/axis"
if [ ! -x "$AXIS_RELEASE" ]; then
    echo "ERROR: release axis binary missing: $AXIS_RELEASE"
    exit 1
fi
if [ ! -x "${TARGET_DIR}/release/axis-seccomp-launcher" ]; then
    echo "ERROR: release axis-seccomp-launcher binary missing: ${TARGET_DIR}/release/axis-seccomp-launcher"
    exit 1
fi

PYTHON_BIN="$(command -v python3)"

read -r -d '' LIFECYCLE_PROBE <<'PY' || true
import os
import pathlib
import time

workspace = pathlib.Path.cwd()
leaked = []
for name in os.listdir("/proc/self/fd"):
    try:
        fd = int(name)
        if fd <= 2:
            continue
        target = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        continue
    leaked.append(f"{fd} {target}")

if leaked:
    (workspace / "leaked-helper-fds").write_text("\n".join(leaked) + "\n")
    raise SystemExit(91)

visible_config_fds = []
for fd_dir in pathlib.Path("/proc").glob("[0-9]*/fd"):
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        continue
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if "axis-mxc-config" in target:
            visible_config_fds.append(f"{entry} {target}")

if visible_config_fds:
    (workspace / "visible-helper-config-fds").write_text(
        "\n".join(visible_config_fds) + "\n"
    )
    raise SystemExit(92)
(workspace / "payload-fds").write_text("stdio-only\n")

def mark(name, value="ready"):
    destination = workspace / f"lifecycle-{name}"
    temporary = workspace / f".lifecycle-{name}-{os.getpid()}"
    temporary.write_text(f"{value}\n")
    os.replace(temporary, destination)

def hold(name):
    descendant = os.fork()
    if descendant == 0:
        mark(f"{name}-descendant")
        while True:
            time.sleep(1)
    mark(f"{name}-holder")
    while True:
        time.sleep(1)

def churn():
    cycles = 0
    while True:
        worker = os.fork()
        if worker == 0:
            orphan = os.fork()
            if orphan == 0:
                time.sleep(0.05)
                os._exit(0)
            os._exit(0)
        _, status = os.waitpid(worker, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise SystemExit(93)
        cycles += 1
        mark("churner", cycles)
        time.sleep(0.005)

for name in ("first", "second"):
    child = os.fork()
    if child == 0:
        hold(name)

churner = os.fork()
if churner == 0:
    churn()

expected = (
    "lifecycle-first-holder",
    "lifecycle-first-descendant",
    "lifecycle-second-holder",
    "lifecycle-second-descendant",
    "lifecycle-churner",
)
deadline = time.monotonic() + 5
while not all((workspace / name).is_file() for name in expected):
    if time.monotonic() >= deadline:
        missing = [name for name in expected if not (workspace / name).is_file()]
        (workspace / "lifecycle-error").write_text("missing: " + ", ".join(missing) + "\n")
        raise SystemExit(92)
    time.sleep(0.01)

(workspace / "lifecycle-ready").write_text("ready\n")
while True:
    time.sleep(1)
PY

echo ""
echo "=== Helper PID namespace lifecycle proof ==="
for failure_mode in owner-death helper-sigkill; do
    run_helper_lifecycle_case axis_native "$failure_mode"
done

echo ""
echo "=== MXC helper launch refusal proof ==="
# The helper runs the payload in a new PID namespace without a matching procfs,
# and MXC v1.0.0 locates its slirp4netns network namespace through
# /proc/<pid>. AXIS refuses the MXC helper path before launch.
MXC_REFUSAL_ROOT="${TMP_ROOT}/mxc-helper-refusal"
mkdir -p "${MXC_REFUSAL_ROOT}/workspace"
MXC_REFUSAL_POLICY="${MXC_REFUSAL_ROOT}/policy.yaml"
write_proxy_policy "$MXC_REFUSAL_POLICY" "helper-mxc-refusal" 9 mxc
snapshot_helper_states "${MXC_REFUSAL_ROOT}/states.before"
set +e
(
    cd "${MXC_REFUSAL_ROOT}/workspace"
    bounded 30 "$AXIS_RELEASE" --socket "/tmp/axis-helper-mxc-refusal-$$.sock" \
        run --policy "$MXC_REFUSAL_POLICY" -- "$PYTHON_BIN" -c 'open("ran", "w").write("ran")'
) >"${MXC_REFUSAL_ROOT}/axis.out" 2>&1
mxc_refusal_status=$?
set -e
snapshot_helper_states "${MXC_REFUSAL_ROOT}/states.after"
if [ "$mxc_refusal_status" -eq 0 ] ||
    ! grep -Fq "strict proxy through axis-netns-helper is unsupported" "${MXC_REFUSAL_ROOT}/axis.out"; then
    echo "ERROR: MXC helper launch was not refused before launch (status $mxc_refusal_status)"
    cat "${MXC_REFUSAL_ROOT}/axis.out"
    exit 1
fi
if [ -e "${MXC_REFUSAL_ROOT}/workspace/ran" ]; then
    echo "ERROR: refused MXC helper launch still ran its payload"
    exit 1
fi
if ! cmp -s "${MXC_REFUSAL_ROOT}/states.before" "${MXC_REFUSAL_ROOT}/states.after"; then
    echo "ERROR: refused MXC helper launch left helper state behind"
    exit 1
fi
echo "PASS: MXC helper launch is refused before any helper state or payload exists"

SERVER_PORT_FILE="${TMP_ROOT}/server.port"
start_tcp_server "$SERVER_PORT_FILE" "127.0.0.1" SERVER_PID

if ! wait_for_port_file "$SERVER_PORT_FILE"; then
    echo "ERROR: local proxy target server did not publish a port"
    exit 1
fi
SERVER_PORT="$(cat "$SERVER_PORT_FILE")"

DIRECT_PORT_FILE="${TMP_ROOT}/direct.port"
start_tcp_server "$DIRECT_PORT_FILE" "0.0.0.0" DIRECT_SERVER_PID

if ! wait_for_port_file "$DIRECT_PORT_FILE"; then
    echo "ERROR: direct-bypass target server did not publish a port"
    exit 1
fi
DIRECT_PORT="$(cat "$DIRECT_PORT_FILE")"

PROXY_POLICY="${TMP_ROOT}/proxy-policy.yaml"
# MXC v1.0.0 cannot run behind the helper (see the MXC refusal proof), so
# the built-binary helper proofs use the native provider explicitly.
write_proxy_policy "$PROXY_POLICY" "helper-proxy-e2e" "$SERVER_PORT" axis_native
if ! rm -f "$HOST_PEER_MARKER"; then
    echo "ERROR: failed to initialize host peer completion marker: $HOST_PEER_MARKER"
    exit 1
fi

read -r -d '' PROXY_PROBE <<PY || true
import os
import pathlib
import socket
import sys
import time
from urllib.parse import urlparse

proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
if not proxy_url:
    print("missing proxy environment")
    sys.exit(1)
proxy = urlparse(proxy_url)
proxy_host = proxy.hostname
proxy_port = proxy.port
if not proxy_host or not proxy_port:
    print(f"invalid proxy environment: {proxy_url!r}")
    sys.exit(1)

def connect_request(host, port):
    s = socket.create_connection((proxy_host, proxy_port), timeout=3)
    request = f"CONNECT {host}:{port} HTTP/1.1\\r\\nHost: {host}:{port}\\r\\n\\r\\n"
    s.sendall(request.encode())
    response = s.recv(256)
    return s, response

allowed_socket, allowed = connect_request("127.0.0.1", ${SERVER_PORT})
if b"200" not in allowed.splitlines()[0]:
    print(f"allowed CONNECT did not return 200: {allowed!r}")
    sys.exit(2)
allowed_socket.sendall(b"!")
tunneled = allowed_socket.recv(9)
allowed_socket.close()
if tunneled != b"AXIS-ECHO":
    print(f"allowed CONNECT did not tunnel bytes to target: {tunneled!r}")
    sys.exit(5)

denied_socket, denied = connect_request("denied.example.invalid", 443)
denied_socket.close()
if b"403" not in denied.splitlines()[0]:
    print(f"denied CONNECT did not return 403: {denied!r}")
    sys.exit(3)

try:
    direct = socket.create_connection((proxy_host, ${DIRECT_PORT}), timeout=1)
except OSError:
    pass
else:
    direct.close()
    print("direct non-proxy connection unexpectedly succeeded")
    sys.exit(4)

print("proxy allowed/denied/direct-bypass checks passed", flush=True)
host_peer_marker = pathlib.Path("${HOST_PEER_MARKER}")
deadline = time.monotonic() + 25
while not host_peer_marker.exists() and time.monotonic() < deadline:
    time.sleep(0.1)
if not host_peer_marker.exists():
    print("host-side strict proxy peer check did not complete")
    sys.exit(6)
PY

PROXY_OUTPUT="${TMP_ROOT}/proxy-proof.out"
AXIS_SOCKET="/tmp/axis-proxy-e2e-$$.sock" \
    timeout 45 "$AXIS_RELEASE" --socket "/tmp/axis-proxy-e2e-$$.sock" \
    run --policy "$PROXY_POLICY" -- "$PYTHON_BIN" -c "$PROXY_PROBE" \
    >"$PROXY_OUTPUT" 2>&1 &
PROXY_PROOF_PID=$!

proxy_address=""
proxy_address_deadline=$((SECONDS + 20))
while ((SECONDS < proxy_address_deadline)); do
    proxy_address="$(sed -n 's/^AXIS: proxy on \([^[:space:]]*\).*$/\1/p' "$PROXY_OUTPUT" | head -n1)"
    [ -n "$proxy_address" ] && break
    sleep 0.1
done

if [ -z "$proxy_address" ]; then
    echo "ERROR: built axis proof did not advertise its strict proxy address"
    cat "$PROXY_OUTPUT"
    exit 1
fi
bounded 20 "$PYTHON_BIN" - "$proxy_address" "$SERVER_PORT" "$HOST_PEER_MARKER" <<'PY'
import pathlib
import socket
import sys
import time

host, port = sys.argv[1].rsplit(":", 1)
target_port = int(sys.argv[2])
completion_marker = pathlib.Path(sys.argv[3])
deadline = time.monotonic() + 10
last_error = None
while True:
    try:
        connection = socket.create_connection((host, int(port)), timeout=1)
        break
    except OSError as error:
        last_error = error
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"strict proxy at {host}:{port} did not accept a host connection"
            ) from last_error
        time.sleep(0.1)
with connection:
    connection.settimeout(3)
    request = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    connection.sendall(request.encode())
    response = b""
    while len(response) < 8192:
        chunk = connection.recv(min(1024, 8192 - len(response)))
        if not chunk:
            break
        response += chunk
        if b"\r\n\r\n" in response and b"unauthenticated sandbox peer" in response:
            break
if b"\r\n\r\n" not in response:
    print(f"host-side strict proxy returned incomplete headers: {response!r}")
    sys.exit(3)
status_fields = response.split(b"\r\n", 1)[0].split()
if len(status_fields) < 2 or status_fields[1] != b"403":
    print(f"host-side strict proxy connection was not rejected: {response!r}")
    sys.exit(1)
if b"unauthenticated sandbox peer" not in response:
    print(f"host-side request was not rejected by peer authentication: {response!r}")
    sys.exit(2)
completion_marker.touch()
print("host-side strict proxy peer rejected")
PY

set +e
wait "$PROXY_PROOF_PID"
proxy_status=$?
set -e
PROXY_PROOF_PID=""
proxy_output="$(cat "$PROXY_OUTPUT")"
if [ "$proxy_status" -ne 0 ]; then
    if [ "$proxy_status" -eq 124 ] || [ "$proxy_status" -eq 125 ] || [ "$proxy_status" -eq 137 ]; then
        echo "ERROR: built axis proxy proof exceeded its command deadline"
        echo "$proxy_output"
        exit 1
    fi
    if capability_skip_output "$proxy_output"; then
        skip_or_require \
            AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E \
            "built axis proxy proof unavailable on this runner: ${proxy_output//$'\n'/ }"
    fi
    echo "$proxy_output"
    exit "$proxy_status"
fi
if ! grep -Fq "proxy allowed/denied/direct-bypass checks passed" <<<"$proxy_output"; then
    echo "ERROR: built axis proof did not complete its proxy checks"
    echo "$proxy_output"
    exit 1
fi
echo "$proxy_output"

stop_background_servers

echo ""
echo "=== Kmsg bypass audit proof ==="

cargo build --locked --release -p axis-daemon
AXISD_RELEASE="${TARGET_DIR}/release/axisd"
if [ ! -x "$AXISD_RELEASE" ]; then
    echo "ERROR: release axisd binary missing: $AXISD_RELEASE"
    exit 1
fi
AXISD_AUDIT_BINARY="$AXISD_RELEASE"
provision_kmsg_audit_source \
    "$AXISD_RELEASE" "${TARGET_DIR}/release/axis-seccomp-launcher"
if [ "${AXIS_PROVISION_KMSG_AUDIT_E2E:-}" = "1" ]; then
    provision_nf_log_all_netns read_nf_log_all_netns write_nf_log_all_netns
fi
if [ -n "$KMSG_AXISD_INSTALL" ]; then
    AXISD_AUDIT_BINARY="$KMSG_AXISD_INSTALL"
fi
kmsg_status=0
kmsg_available=0
if kmsg_source_available; then
    kmsg_available=1
fi
kmsg_gate_status "${AXIS_REQUIRE_KMSG_AUDIT_E2E:-0}" "$kmsg_available" || kmsg_status=$?
if [ "$kmsg_status" -eq 1 ]; then
    echo "ERROR: AXIS_REQUIRE_KMSG_AUDIT_E2E=1 requires a usable /dev/kmsg audit source"
    exit 1
elif [ "$kmsg_status" -eq 77 ]; then
    skip_or_require AXIS_REQUIRE_KMSG_AUDIT_E2E "bypass audit proof requires a usable /dev/kmsg source"
fi

AUDIT_SOCKET="${TMP_ROOT}/axisd-audit.sock"
AUDIT_LOG_DIR="${TMP_ROOT}/logs"
mkdir -p "$AUDIT_LOG_DIR"
SERVER_PORT_FILE="${TMP_ROOT}/audit-server.port"
DIRECT_PORT_FILE="${TMP_ROOT}/audit-direct.port"
start_tcp_server "$SERVER_PORT_FILE" "127.0.0.1" SERVER_PID
start_tcp_server "$DIRECT_PORT_FILE" "0.0.0.0" DIRECT_SERVER_PID
if ! wait_for_port_file "$SERVER_PORT_FILE"; then
    echo "ERROR: audit proxy target server did not publish a port"
    exit 1
fi
if ! wait_for_port_file "$DIRECT_PORT_FILE"; then
    echo "ERROR: audit direct-bypass target server did not publish a port"
    exit 1
fi
AUDIT_SERVER_PORT="$(cat "$SERVER_PORT_FILE")"
AUDIT_DIRECT_PORT="$(cat "$DIRECT_PORT_FILE")"
AUDIT_POLICY="${TMP_ROOT}/audit-proxy-policy.yaml"
write_proxy_policy "$AUDIT_POLICY" "helper-proxy-audit-e2e" "$AUDIT_SERVER_PORT" axis_native

AXIS_LOG_LEVEL="axis=info,axis::audit=info" \
AXIS_LOG_DIR="$AUDIT_LOG_DIR" \
XDG_DATA_HOME="${TMP_ROOT}/xdg-audit" \
AXIS_SOCKET="$AUDIT_SOCKET" \
    "$AXISD_AUDIT_BINARY" >"${TMP_ROOT}/axisd-audit.stderr" 2>&1 &
AXSD_PID=$!

if ! wait_for_socket_path "$AUDIT_SOCKET"; then
    echo "ERROR: audit axisd did not create IPC socket"
    cat "${TMP_ROOT}/axisd-audit.stderr" || true
    exit 1
fi

read -r -d '' AUDIT_PROBE <<PY || true
import os
import socket
import sys
import time
from urllib.parse import urlparse

proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
if not proxy_url:
    print("missing proxy environment")
    sys.exit(1)
proxy = urlparse(proxy_url)
if not proxy.hostname:
    print(f"invalid proxy environment: {proxy_url!r}")
    sys.exit(1)
try:
    direct = socket.create_connection((proxy.hostname, ${AUDIT_DIRECT_PORT}), timeout=1)
except OSError:
    print("direct bypass rejected")
    time.sleep(3)
    sys.exit(0)
else:
    direct.close()
    print("direct bypass unexpectedly succeeded")
    sys.exit(4)
PY

set +e
create_output="$(bounded 20 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" create --policy "$AUDIT_POLICY" -- "$PYTHON_BIN" -c "$AUDIT_PROBE" 2>&1)"
create_status=$?
set -e
if [ "$create_status" -ne 0 ]; then
    if capability_skip_output "$create_output"; then
        skip_or_require \
            AXIS_REQUIRE_KMSG_AUDIT_E2E \
            "bypass audit proof unavailable on this runner: ${create_output//$'\n'/ }"
    fi
    echo "$create_output"
    echo "ERROR: audit sandbox was not created"
    exit "$create_status"
fi
if ! grep -Eq 'Sandbox created: [0-9a-f-]+' <<<"$create_output"; then
    echo "$create_output"
    echo "ERROR: audit sandbox was not created"
    exit 1
fi
audit_sandbox_id="$(grep -oE '[0-9a-f]{8}-[0-9a-f-]{27}' <<<"$create_output" | head -n1)"

for _ in $(seq 1 40); do
    if audit_log_contains_matching_bypass \
        "${AUDIT_LOG_DIR}/axisd.log" "$audit_sandbox_id" "$AUDIT_DIRECT_PORT"; then
        echo "PASS: bypass audit event recorded"
        if ! bounded 10 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id"; then
            echo "ERROR: failed to destroy audited sandbox: $audit_sandbox_id"
            exit 1
        fi
        exit 0
    fi
    sleep 0.25
done

cat "${AUDIT_LOG_DIR}/axisd.log" 2>/dev/null || true
echo "ERROR: bypass audit event was not recorded"
if ! bounded 10 "$AXIS_RELEASE" --socket "$AUDIT_SOCKET" destroy "$audit_sandbox_id"; then
    echo "ERROR: failed to destroy unaudited sandbox: $audit_sandbox_id"
fi
exit 1
