#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Capability-gated Linux e2e proof for the bubblewrap fallback path.
#
# This is not part of the default quickstart proof. It runs only when the
# caller opts in and the runner has a trusted bubblewrap executable available.
set -euo pipefail

if [ "${AXIS_RUN_BWRAP_E2E:-}" != "1" ]; then
    echo "SKIP: set AXIS_RUN_BWRAP_E2E=1 on a runner with bubblewrap installed"
    exit 77
fi

if ! command -v bwrap >/dev/null 2>&1; then
    echo "SKIP: bwrap not found on PATH"
    exit 77
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo is required to run the bubblewrap fallback proof"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: built axis bubblewrap fallback proof requires python3 on PATH"
    exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/axis-bwrap-e2e-XXXXXX)"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
cd "$REPO_ROOT"

cargo build --locked --release -p axis-cli

if python3 - <<'PY'
import ctypes
import sys

SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
sys.exit(0 if ret >= 0 else 1)
PY
then
    echo "SKIP: built axis bwrap fallback requires a runner without Landlock; running crate-level fallback proof"
else
    POLICY_FILE="${TMP_ROOT}/policy.yaml"
    cat >"$POLICY_FILE" <<EOF
version: 1
name: bwrap-fallback-e2e

filesystem:
  read_only:
EOF
    for path in /bin /sbin /usr /lib /lib64 /etc /nix/store; do
        if [ -e "$path" ]; then
            printf '    - %s\n' "$path" >>"$POLICY_FILE"
        fi
    done
    cat >>"$POLICY_FILE" <<EOF
  read_write:
    - "{workspace}"

process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0

network:
  mode: block
EOF
    (
        cd "$TMP_ROOT"
        timeout 30 "${REPO_ROOT}/target/release/axis" \
            --socket "/tmp/axis-bwrap-e2e-$$.sock" \
            run --policy "$POLICY_FILE" -- python3 -c 'import pathlib, socket, sys
pathlib.Path("inside.txt").write_text("ok")
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError:
    sys.exit(0)
print("network socket unexpectedly succeeded", file=sys.stderr)
sys.exit(42)'
    )

    # In allow mode the fallback binds the host resolver's file and socket
    # read-only, and nothing else from its directory; in block mode it binds
    # nothing. The policies name axis_native: auto would choose MXC.
    resolver_socket=/run/systemd/resolve/io.systemd.Resolve
    if [ -S "$resolver_socket" ]; then
        resolver_probe='import errno, os, socket, sys
expect, path, conf = sys.argv[1:4]
def connect(target):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(target)
        return 0
    except OSError as exc:
        return exc.errno
    finally:
        s.close()
result = connect(path)
if expect == "reachable":
    if result != 0:
        print(f"resolver connect: {errno.errorcode.get(result, result)}", file=sys.stderr)
        sys.exit(42)
    try:
        open(conf).read()
    except OSError as exc:
        print(f"resolver configuration {conf}: {exc}", file=sys.stderr)
        sys.exit(42)
    # Only the socket and the file the configuration resolves to are bound
    # from the resolver directory; every other entry must be absent.
    directory = os.path.dirname(path)
    target = os.path.realpath(conf)
    bound = {os.path.basename(path)}
    if os.path.dirname(target) == directory:
        if not os.path.isfile(target):
            print(f"resolver configuration {target} is missing", file=sys.stderr)
            sys.exit(42)
        bound.add(os.path.basename(target))
    exposed = sorted(set(os.listdir(directory)) - bound)
    if exposed:
        print(f"resolver directory exposes {exposed}", file=sys.stderr)
        sys.exit(42)
    print("bwrap-resolver-reachable")
elif result not in (errno.ENOENT, errno.EACCES):
    print(f"resolver connect in block mode: {errno.errorcode.get(result, result)}", file=sys.stderr)
    sys.exit(42)
else:
    print("bwrap-resolver-denied")'
        for mode in allow block; do
            resolver_policy="${TMP_ROOT}/resolver-${mode}.yaml"
            {
                printf 'runtime:\n  provider: axis_native\n'
                sed "s/^  mode: block$/  mode: ${mode}/" "$POLICY_FILE"
            } >"$resolver_policy"
            expect=reachable
            [ "$mode" = block ] && expect=denied
            output="$(
                cd "$TMP_ROOT"
                timeout 30 "${REPO_ROOT}/target/release/axis" \
                    --socket "/tmp/axis-bwrap-e2e-$$.sock" \
                    run --policy "$resolver_policy" -- python3 -c "$resolver_probe" "$expect" "$resolver_socket" /etc/resolv.conf
            )"
            if ! grep -Fxq "bwrap-resolver-${expect}" <<<"${output//$'\r'/}"; then
                echo "$output"
                echo "ERROR: bubblewrap fallback host resolver check failed in ${mode} mode"
                exit 1
            fi
        done
    else
        echo "SKIP: host resolver checks need systemd-resolved ($resolver_socket is not a socket)"
    fi
fi

AXIS_BWRAP_TESTS=1 \
    cargo test --locked -p axis-sandbox \
    gated_bubblewrap_fallback_mounts_workspace_and_blocks_network \
    -- --nocapture
