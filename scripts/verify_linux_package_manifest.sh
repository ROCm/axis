#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARCHIVE_HELPER="$SCRIPT_DIR/verify_release_archive.py"

usage() {
    echo "usage: $0 <deb|rpm|root> <package-or-root>" >&2
    exit 2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
package_type="$1"
package_path="$2"
[ -e "$package_path" ] || fail "package input does not exist: $package_path"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/axis-package-manifest-XXXXXX")"
cleanup() {
    rm -rf "$tmp_root"
}
trap cleanup EXIT

case "$package_type" in
    deb)
        payload_root="$tmp_root/payload"
        python3 "$ARCHIVE_HELPER" --extract-command-tar "$payload_root" \
            dpkg-deb --fsys-tarfile "$package_path"
        ;;
    rpm)
        payload_root="$tmp_root/payload"
        package_path="$(realpath "$package_path")"
        python3 "$ARCHIVE_HELPER" --extract-command-tar "$payload_root" \
            rpm2archive -n "$package_path"
        ;;
    root)
        payload_root="$(realpath "$package_path")"
        ;;
    *)
        usage
        ;;
esac

expected="$tmp_root/expected"
cat >"$expected" <<'EOF'
d 0755 /etc
d 0755 /etc/axis
d 0755 /etc/axis/policies
d 0755 /lib
d 0755 /lib/systemd
d 0755 /lib/systemd/system
d 0755 /usr
d 0755 /usr/bin
d 0755 /usr/libexec
d 0755 /usr/libexec/axis
d 0755 /usr/share
d 0755 /usr/share/doc
d 0755 /usr/share/doc/axis
f 0644 /etc/axis/policies/coding-agent.yaml
f 0644 /etc/axis/policies/gpu-agent.yaml
f 0644 /etc/axis/policies/minimal.yaml
f 0644 /lib/systemd/system/axis.service
f 0755 /usr/bin/axis
f 0755 /usr/bin/axisd
f 0755 /usr/bin/lxc-exec
f 0755 /usr/libexec/axis/axis-seccomp-launcher
f 0644 /usr/share/doc/axis/LICENSE
EOF

# cargo-deb emits the Debian copyright file from package metadata. RPM does not.
if [ "$package_type" = "deb" ]; then
    printf '%s\n' 'f 0644 /usr/share/doc/axis/copyright' >>"$expected"
fi
sort -o "$expected" "$expected"

actual="$tmp_root/actual"
while IFS= read -r -d '' path; do
    relative="/${path#"$payload_root"/}"
    mode="$(stat -c '%04a' "$path")"
    if [ -d "$path" ]; then
        type=d
    elif [ -f "$path" ]; then
        type=f
    else
        fail "package payload contains an unsupported file type: $relative"
    fi
    printf '%s %s %s\n' "$type" "$mode" "$relative"
done < <(find "$payload_root" -mindepth 1 -print0) | sort >"$actual"

if ! diff -u "$expected" "$actual"; then
    fail "$package_type payload does not match the expected path-and-mode manifest"
fi

# shellcheck disable=SC2043 # One file today; the loop takes more legal files.
for legal_file in LICENSE; do
    packaged="$payload_root/usr/share/doc/axis/$legal_file"
    if ! cmp -s "$REPO_ROOT/$legal_file" "$packaged"; then
        fail "$package_type payload $legal_file differs from the repository source"
    fi
done

echo "$package_type package payload manifest: OK"
