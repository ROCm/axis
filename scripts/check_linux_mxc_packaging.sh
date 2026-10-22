#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Validate the Linux MXC packaging and installer contract without sudo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/mxc-packaging-XXXXXX)"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

assert_file() {
    local path="$1"
    [ -f "$path" ] || fail "expected file: $path"
}

assert_executable() {
    local path="$1"
    [ -x "$path" ] || fail "expected executable: $path"
}

assert_contains() {
    local path="$1"
    local pattern="$2"
    grep -Fq -- "$pattern" "$path" || fail "expected '$pattern' in $path"
}

assert_not_contains() {
    local path="$1"
    local pattern="$2"
    if grep -Fq -- "$pattern" "$path"; then
        fail "unexpected '$pattern' in $path"
    fi
}

assert_repository_references() {
    python3 - "$REPO_ROOT" <<'PY' || fail "invalid AXIS repository reference"
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

root = Path(sys.argv[1])
assignments = [
    (root / "install.sh", re.compile(r'^REPO="([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"$')),
    (root / "install.ps1", re.compile(r'^\$Repo = "([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"$')),
]
for path, pattern in assignments:
    values = [
        match.group(1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if (match := pattern.fullmatch(line))
    ]
    if values != ["ROCm/axis"]:
        raise SystemExit(f"unexpected repository assignment in {path}: {values}")

paths = [
    root / "install.sh",
    root / "install.ps1",
    root / "README.md",
    root / "docs/setup-and-install.md",
    root / "docs/linux-setup.md",
]
url_pattern = re.compile(r"https://(?:raw\.githubusercontent\.com|github\.com)/[^\s'\"()]+")
for path in paths:
    urls = url_pattern.findall(path.read_text(encoding="utf-8"))
    if not urls:
        raise SystemExit(f"no GitHub repository URL found in {path}")
    for url in urls:
        parsed = urlparse(url.rstrip(".\\"))
        if parsed.netloc == "github.com" and (
            "$Repo" in parsed.path or "${REPO}" in parsed.path
        ):
            continue
        repository = parsed.path.strip("/").split("/")[:2]
        if parsed.netloc == "github.com" and repository[1:2] != ["axis"]:
            continue
        if repository != ["ROCm", "axis"]:
            raise SystemExit(f"unexpected AXIS repository URL in {path}: {url}")
PY
}

write_fake_binary() {
    local path="$1"
    cat >"$path" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod 0755 "$path"
}

make_archive() {
    local archive="$1"
    local root
    shift
    root="$TMP_ROOT/archive-$(basename "$archive" .tar.gz)"
    mkdir -p "$root"
    for bin in "$@"; do
        write_fake_binary "$root/$bin"
    done
    tar czf "$archive" -C "$root" .
}

make_checksum() {
    local archive="$1"
    (
        cd "$(dirname "$archive")"
        sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256"
    )
}

run_installer() {
    local archive="$1"
    local home="$2"
    shift 2
    HOME="$home" AXIS_INSTALL_ARCHIVE="$archive" sh "$REPO_ROOT/install.sh" "$@"
}

make_fake_sudo() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    cat >"$bin_dir/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$1" != "install" ]; then
    echo "unexpected fake sudo command: $*" >&2
    exit 1
fi
shift

args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|-g)
            shift 2
            ;;
        /usr/*)
            args+=("$AXIS_TEST_FAKE_ROOT$1")
            shift
            ;;
        *)
            args+=("$1")
            shift
            ;;
    esac
done
exec install "${args[@]}"
EOF
    chmod 0755 "$bin_dir/sudo"
}

FULL_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64.tar.gz"
MISSING_MXC_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64-missing-mxc.tar.gz"
MISSING_SECCOMP_ARCHIVE="$TMP_ROOT/pkg-linux-x86_64-missing-seccomp.tar.gz"
INSTALL_HOME="$TMP_ROOT/home"
INSTALL_PREFIX="$INSTALL_HOME/.local/bin"
INSTALL_DEPS_DOC="$REPO_ROOT/docs/install-and-runtime-dependencies.md"
SETUP_DOC="$REPO_ROOT/docs/setup-and-install.md"
CI_WORKFLOW="$REPO_ROOT/.github/workflows/ci.yml"

mkdir -p "$INSTALL_HOME"
make_archive "$FULL_ARCHIVE" axis axisd axis-seccomp-launcher lxc-exec axis-netns-helper
make_archive "$MISSING_MXC_ARCHIVE" axis axisd axis-seccomp-launcher
make_archive "$MISSING_SECCOMP_ARCHIVE" axis axisd lxc-exec
make_checksum "$FULL_ARCHIVE"
make_checksum "$MISSING_MXC_ARCHIVE"
make_checksum "$MISSING_SECCOMP_ARCHIVE"

sh -n "$REPO_ROOT/install.sh"
assert_repository_references
# shellcheck disable=SC2016 # Match the literal PowerShell variable expression.
assert_contains "$REPO_ROOT/install.ps1" 'Get-FileHash -LiteralPath $archivePath -Algorithm SHA256'
assert_contains "$REPO_ROOT/install.sh" 'HELPER_MXC_EXECUTOR_PATH="/usr/local/bin/lxc-exec"'
# shellcheck disable=SC2016 # Match the literal installer command contract.
assert_contains "$REPO_ROOT/install.sh" 'need_privilege install -o root -g root -m 0755 "$MXC_EXECUTOR_SRC" "$HELPER_MXC_EXECUTOR_PATH"'
run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --prefix "$INSTALL_PREFIX" >/"$TMP_ROOT/install.log"
for bin in axis axisd axis-seccomp-launcher lxc-exec; do
    assert_file "$INSTALL_PREFIX/$bin"
    assert_executable "$INSTALL_PREFIX/$bin"
done
if [ -e "$INSTALL_PREFIX/axis-netns-helper" ]; then
    fail "default installer must not install the privileged netns helper"
fi

NO_CHECKSUM_ARCHIVE="$TMP_ROOT/no-checksum-linux-x86_64.tar.gz"
cp "$FULL_ARCHIVE" "$NO_CHECKSUM_ARCHIVE"
if run_installer "$NO_CHECKSUM_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/no-checksum/bin" \
    >"$TMP_ROOT/no-checksum.log" 2>&1; then
    fail "installer succeeded without a checksum sidecar"
fi
assert_contains "$TMP_ROOT/no-checksum.log" "checksum file not found"

WRONG_NAME_ARCHIVE="$TMP_ROOT/wrong-name-linux-x86_64.tar.gz"
cp "$FULL_ARCHIVE" "$WRONG_NAME_ARCHIVE"
cp "${FULL_ARCHIVE}.sha256" "${WRONG_NAME_ARCHIVE}.sha256"
if run_installer "$WRONG_NAME_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/wrong-name/bin" \
    >"$TMP_ROOT/wrong-name.log" 2>&1; then
    fail "installer accepted a checksum for a different archive name"
fi
assert_contains "$TMP_ROOT/wrong-name.log" "invalid checksum file"

TAMPERED_ARCHIVE="$TMP_ROOT/tampered-linux-x86_64.tar.gz"
cp "$FULL_ARCHIVE" "$TAMPERED_ARCHIVE"
make_checksum "$TAMPERED_ARCHIVE"
printf 'tampered' >>"$TAMPERED_ARCHIVE"
if run_installer "$TAMPERED_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/tampered/bin" \
    >"$TMP_ROOT/tampered.log" 2>&1; then
    fail "installer accepted an archive whose digest does not match"
fi
assert_contains "$TMP_ROOT/tampered.log" "checksum verification failed"
if [ -e "$TMP_ROOT/tampered/bin/axis" ]; then
    fail "installer extracted a checksum-mismatched archive"
fi

if run_installer "$MISSING_MXC_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/missing/bin" \
    >"$TMP_ROOT/missing.log" 2>&1; then
    fail "installer succeeded without lxc-exec"
fi
assert_contains "$TMP_ROOT/missing.log" "archive does not contain lxc-exec"

if run_installer "$MISSING_SECCOMP_ARCHIVE" "$INSTALL_HOME" --prefix "$TMP_ROOT/missing-seccomp/bin" \
    >"$TMP_ROOT/missing-seccomp.log" 2>&1; then
    fail "installer succeeded without axis-seccomp-launcher"
fi
assert_contains "$TMP_ROOT/missing-seccomp.log" "archive does not contain axis-seccomp-launcher"

if run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --with-cap-net-admin --prefix "$INSTALL_HOME/cap-bin" \
    >"$TMP_ROOT/cap-home.log" 2>&1; then
    fail "--with-cap-net-admin accepted an explicit user prefix"
fi
assert_contains "$TMP_ROOT/cap-home.log" "--with-cap-net-admin requires a root-owned install prefix"

if run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --with-netns-helper --with-cap-net-admin \
    >"$TMP_ROOT/conflict.log" 2>&1; then
    fail "installer accepted conflicting privileged network options"
fi
assert_contains "$TMP_ROOT/conflict.log" "choose either --with-netns-helper or --with-cap-net-admin"

FAKE_SUDO_BIN="$TMP_ROOT/fake-sudo/bin"
FAKE_SYSTEM_ROOT="$TMP_ROOT/fake-system-root"
make_fake_sudo "$FAKE_SUDO_BIN"
PATH="$FAKE_SUDO_BIN:$PATH" AXIS_TEST_FAKE_ROOT="$FAKE_SYSTEM_ROOT" \
    run_installer "$FULL_ARCHIVE" "$INSTALL_HOME" --with-netns-helper \
    --prefix "$TMP_ROOT/helper-user/bin" >"$TMP_ROOT/helper-install.log"
assert_executable "$FAKE_SYSTEM_ROOT/usr/libexec/axis/axis-netns-helper"
assert_executable "$FAKE_SYSTEM_ROOT/usr/local/bin/lxc-exec"
helper_mode="$(stat -c '%a' "$FAKE_SYSTEM_ROOT/usr/libexec/axis/axis-netns-helper")"
[ "$helper_mode" = "4755" ] || fail "netns helper mode is $helper_mode, expected 4755"
executor_mode="$(stat -c '%a' "$FAKE_SYSTEM_ROOT/usr/local/bin/lxc-exec")"
[ "$executor_mode" = "755" ] || fail "trusted lxc-exec mode is $executor_mode, expected 755"

assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" '["target/release/lxc-exec", "usr/bin/", "755"]'
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" 'dest = "/usr/bin/lxc-exec"'
for policy in minimal coding-agent gpu-agent; do
    assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" "dest = \"/etc/axis/policies/$policy.yaml\""
done
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" 'usr/share/doc/axis/LICENSE'
# MXC Bubblewrap allow and proxy modes need slirp4netns and the iptables tools.
# They are recommended rather than required; the pre-launch check rejects those
# policies when the tools are missing.
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" 'depends = "$auto, bubblewrap"'
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" 'recommends = "iptables, slirp4netns"'
assert_contains "$REPO_ROOT/crates/axis-daemon/Cargo.toml" '[package.metadata.generate-rpm.recommends]'
assert_contains "$REPO_ROOT/packaging/runtime/core-linux.json" '"purl": "pkg:generic/iptables@0"'
assert_contains "$REPO_ROOT/packaging/runtime/core-linux.json" '"purl": "pkg:generic/slirp4netns@0"'
if grep -Fq 'axis-netns-helper", "usr/libexec/axis/", "4755"' "$REPO_ROOT/crates/axis-daemon/Cargo.toml"; then
    fail "base deb package must not install axis-netns-helper setuid content"
fi
if grep -Fq 'axis-netns-helper", mode = "4755"' "$REPO_ROOT/crates/axis-daemon/Cargo.toml"; then
    fail "base rpm package must not install axis-netns-helper setuid content"
fi

PYTHONPATH="$REPO_ROOT/scripts" python3 -m unittest \
    scripts.test_verify_release_archive.ReleaseArchiveTests.test_rejects_forged_zip_size_and_prefix_crc_after_full_decompression \
    scripts.test_verify_release_archive.ReleaseArchiveTests.test_rejects_windows_components_changed_by_unicode_normalization \
    scripts.test_verify_workflow_structure.WorkflowStructureTests.test_rejects_unrecognized_jobs_in_every_reviewed_workflow \
    scripts.test_verify_workflow_structure.WorkflowStructureTests.test_rejects_echoed_unreachable_and_conditionally_wrapped_controls \
    >/dev/null || fail "publication security regression tests failed"
python3 "$REPO_ROOT/scripts/verify_workflow_structure.py" "$REPO_ROOT" >/dev/null || \
    fail "release workflow structure validation failed"

assert_contains "$REPO_ROOT/install.sh" 'linux-x86_64|macos-aarch64'
assert_contains "$REPO_ROOT/install.ps1" 'return "windows-x86_64"'
assert_not_contains "$REPO_ROOT/install.ps1" 'return "windows-aarch64"'
assert_contains "$CI_WORKFLOW" "timeout-minutes: 30"
assert_contains "$CI_WORKFLOW" "Acquire::Retries=3"
assert_contains "$REPO_ROOT/e2e/linux/test_netns_helper_launch.sh" "cargo build --locked --release -p axis-cli -p axis-sandbox --bins"

PACKAGE_ROOT="$TMP_ROOT/package-root"
for entry in \
    "0644 etc/axis/policies/coding-agent.yaml" \
    "0644 etc/axis/policies/gpu-agent.yaml" \
    "0644 etc/axis/policies/minimal.yaml" \
    "0644 lib/systemd/system/axis.service" \
    "0755 usr/bin/axis" \
    "0755 usr/bin/axisd" \
    "0755 usr/bin/lxc-exec" \
    "0755 usr/libexec/axis/axis-seccomp-launcher" \
    "0644 usr/share/doc/axis/LICENSE"; do
    mode="${entry%% *}"
    relative="${entry#* }"
    mkdir -p "$PACKAGE_ROOT/$(dirname "$relative")"
    : >"$PACKAGE_ROOT/$relative"
    chmod "$mode" "$PACKAGE_ROOT/$relative"
done
find "$PACKAGE_ROOT" -type d -exec chmod 0755 {} +
cp "$REPO_ROOT/LICENSE" "$PACKAGE_ROOT/usr/share/doc/axis/LICENSE"

if command -v dpkg-deb >/dev/null; then
    DEB_FIXTURE_ROOT="$TMP_ROOT/deb-fixture"
    cp -a "$PACKAGE_ROOT/." "$DEB_FIXTURE_ROOT/"
    mkdir -p "$DEB_FIXTURE_ROOT/DEBIAN"
    cat >"$DEB_FIXTURE_ROOT/DEBIAN/control" <<'EOF'
Package: axis-verifier-fixture
Version: 1.0
Architecture: all
Maintainer: AXIS maintainers
Description: AXIS package verifier fixture
EOF
    : >"$DEB_FIXTURE_ROOT/usr/share/doc/axis/copyright"
    chmod 0644 "$DEB_FIXTURE_ROOT/usr/share/doc/axis/copyright"
    dpkg-deb --build --root-owner-group "$DEB_FIXTURE_ROOT" \
        "$TMP_ROOT/axis-verifier-fixture.deb" >/dev/null
    "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" deb \
        "$TMP_ROOT/axis-verifier-fixture.deb" >/dev/null

    chmod 4755 "$DEB_FIXTURE_ROOT/usr/bin/axis"
    dpkg-deb --build --root-owner-group "$DEB_FIXTURE_ROOT" \
        "$TMP_ROOT/axis-verifier-setuid.deb" >/dev/null
    if "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" deb \
        "$TMP_ROOT/axis-verifier-setuid.deb" \
        >"$TMP_ROOT/package-deb-setuid.log" 2>&1; then
        fail "package verifier accepted a .deb with a setuid executable"
    fi
    assert_contains "$TMP_ROOT/package-deb-setuid.log" \
        "forbidden special mode bits"
    chmod 0755 "$DEB_FIXTURE_ROOT/usr/bin/axis"

    printf '%s\n' tampered >>"$DEB_FIXTURE_ROOT/usr/share/doc/axis/LICENSE"
    dpkg-deb --build --root-owner-group "$DEB_FIXTURE_ROOT" \
        "$TMP_ROOT/axis-verifier-tampered.deb" >/dev/null
    if "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" deb \
        "$TMP_ROOT/axis-verifier-tampered.deb" \
        >"$TMP_ROOT/package-deb-license.log" 2>&1; then
        fail "package verifier accepted a .deb with a tampered LICENSE"
    fi
    assert_contains "$TMP_ROOT/package-deb-license.log" \
        "LICENSE differs from the repository source"
fi
"$REPO_ROOT/scripts/verify_linux_package_manifest.sh" root "$PACKAGE_ROOT" >/dev/null
: >"$PACKAGE_ROOT/usr/bin/unexpected"
if "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" root "$PACKAGE_ROOT" \
    >"$TMP_ROOT/package-extra.log" 2>&1; then
    fail "package manifest verifier accepted an undeclared file"
fi
rm "$PACKAGE_ROOT/usr/bin/unexpected"
chmod 0644 "$PACKAGE_ROOT/usr/bin/axis"
if "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" root "$PACKAGE_ROOT" \
    >"$TMP_ROOT/package-mode.log" 2>&1; then
    fail "package manifest verifier accepted an incorrect executable mode"
fi
chmod 0755 "$PACKAGE_ROOT/usr/bin/axis"
printf '%s\n' tampered >>"$PACKAGE_ROOT/usr/share/doc/axis/LICENSE"
if "$REPO_ROOT/scripts/verify_linux_package_manifest.sh" root "$PACKAGE_ROOT" \
    >"$TMP_ROOT/package-license.log" 2>&1; then
    fail "package manifest verifier accepted a tampered LICENSE"
fi
assert_contains "$TMP_ROOT/package-license.log" \
    "LICENSE differs from the repository source"
cp "$REPO_ROOT/LICENSE" "$PACKAGE_ROOT/usr/share/doc/axis/LICENSE"

assert_contains "$REPO_ROOT/crates/axis-sandbox/src/linux/mxc.rs" 'const MXC_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];'
assert_contains "$REPO_ROOT/crates/axis-sandbox/src/linux/mxc.rs" 'dir.join(AXIS_SECCOMP_LAUNCHER_NAME)'

assert_contains "$REPO_ROOT/rust-toolchain.toml" 'channel = "1.95.0"'
assert_contains "$REPO_ROOT/README.md" "docs/setup-and-install.md"
assert_contains "$REPO_ROOT/README.md" "docs/install-and-runtime-dependencies.md"
assert_contains "$REPO_ROOT/docs/linux-setup.md" "install-and-runtime-dependencies.md"
assert_contains "$REPO_ROOT/docs/linux-setup.md" "setup-and-install.md"
assert_contains "$INSTALL_DEPS_DOC" "Default Install Contract"
assert_contains "$INSTALL_DEPS_DOC" "Runtime Dependency Matrix"
assert_contains "$INSTALL_DEPS_DOC" "Test Dependency Classes"
assert_contains "$INSTALL_DEPS_DOC" "Safe Executor Discovery"
assert_contains "$INSTALL_DEPS_DOC" "Bubblewrap"
assert_contains "$INSTALL_DEPS_DOC" "LXC"
assert_contains "$INSTALL_DEPS_DOC" "WSL2"
assert_contains "$INSTALL_DEPS_DOC" "Windows Sandbox"
assert_contains "$INSTALL_DEPS_DOC" "WHP"
assert_contains "$INSTALL_DEPS_DOC" "KVM"
assert_contains "$INSTALL_DEPS_DOC" "Hyperlight"
assert_contains "$INSTALL_DEPS_DOC" "Xcode Command Line Tools"
assert_contains "$INSTALL_DEPS_DOC" "must not require root-installing a locally built AXIS artifact"
assert_contains "$SETUP_DOC" "cargo build --locked --release -p axis-cli -p axis-daemon -p axis-sandbox --bins"
assert_contains "$SETUP_DOC" "MXC_REF=7bf210247986cb73b1b314df60c2f1109c479c0b"
assert_contains "$SETUP_DOC" "bubblewrap"
assert_contains "$SETUP_DOC" "cgroups v2"
assert_contains "$SETUP_DOC" "/dev/kvm"
assert_contains "$SETUP_DOC" "AXIS_RUN_MXC_MICROVM_E2E=1"
assert_contains "$SETUP_DOC" "AXIS_RUN_MXC_HYPERLIGHT_E2E=1"
assert_contains "$SETUP_DOC" "AXIS_RUN_PRIVILEGED_E2E=1"

echo "Linux MXC packaging checks passed"
