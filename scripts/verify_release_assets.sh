#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    echo "usage: $0 <stable|nightly> <flat-asset-directory> <source-commit>" >&2
    exit 2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$#" -eq 3 ] || usage
release_type="$1"
asset_dir="$(realpath "$2")"
source_version="$3"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
max_asset_size=$((1024 * 1024 * 1024))
max_total_size=$((8 * 1024 * 1024 * 1024))

if [[ ! "$source_version" =~ ^[0-9a-f]{40}$ ]]; then
    fail "source commit must be a Git SHA"
fi

workspace_version="$(python3 -c \
    'import pathlib,sys,tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["workspace"]["package"]["version"])' \
    "$repo_root/Cargo.toml" 2>/dev/null)" || fail "failed to read workspace package version"

expected_payloads=(
    axis-desktop-linux-x86_64.tar.gz
    axis-desktop-macos-aarch64.tar.gz
    axis-desktop-windows-x86_64.zip
    axis-linux-x86_64.tar.gz
    axis-macos-aarch64.tar.gz
    axis-windows-x86_64.zip
)

case "$release_type" in
    stable)
        mapfile -t debs < <(find "$asset_dir" -maxdepth 1 -type f -name '*.deb' -printf '%f\n')
        mapfile -t rpms < <(find "$asset_dir" -maxdepth 1 -type f -name '*.rpm' -printf '%f\n')
        [ "${#debs[@]}" -eq 1 ] || fail "stable release must contain exactly one Debian package"
        [ "${#rpms[@]}" -eq 1 ] || fail "stable release must contain exactly one RPM package"
        expected_deb="axis_${workspace_version}-1_amd64.deb"
        expected_rpm="axis-daemon-${workspace_version}-1.x86_64.rpm"
        [ "${debs[0]}" = "$expected_deb" ] || fail "unexpected Debian package name: ${debs[0]}"
        [ "${rpms[0]}" = "$expected_rpm" ] || fail "unexpected RPM package name: ${rpms[0]}"
        expected_payloads+=("${debs[0]}" "${rpms[0]}")

        command -v dpkg-deb >/dev/null || fail "dpkg-deb is required for stable release verification"
        command -v rpm >/dev/null || fail "rpm is required for stable release verification"
        deb_identity="$(timeout 30 dpkg-deb -f "$asset_dir/${debs[0]}" Package Version Architecture)" ||
            fail "failed to inspect Debian package metadata"
        expected_deb_identity="$(printf 'Package: axis\nVersion: %s-1\nArchitecture: amd64' "$workspace_version")"
        [ "$deb_identity" = "$expected_deb_identity" ] ||
            fail "Debian package identity does not match the release version"
        deb_dependencies="$(timeout 30 dpkg-deb -f "$asset_dir/${debs[0]}" Depends)" ||
            fail "failed to inspect Debian package dependencies"
        printf '%s\n' "$deb_dependencies" | grep -Eq '(^|,)[[:space:]]*bubblewrap([[:space:](]|$)' ||
            fail "Debian package does not require bubblewrap"
        deb_recommends="$(timeout 30 dpkg-deb -f "$asset_dir/${debs[0]}" Recommends)" ||
            fail "failed to inspect Debian package recommendations"
        [ "$deb_recommends" = "iptables, slirp4netns" ] ||
            fail "Debian package must recommend exactly iptables and slirp4netns"
        rpm_identity="$(timeout 30 rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}' "$asset_dir/${rpms[0]}")" ||
            fail "failed to inspect RPM package metadata"
        [ "$rpm_identity" = "axis-daemon ${workspace_version}-1 x86_64" ] ||
            fail "RPM package identity does not match the release version"
        rpm_dependencies="$(timeout 30 rpm -qp --requires "$asset_dir/${rpms[0]}")" ||
            fail "failed to inspect RPM package dependencies"
        printf '%s\n' "$rpm_dependencies" | grep -Eq '^bubblewrap([[:space:]]|$)' ||
            fail "RPM package does not require bubblewrap"
        rpm_recommends="$(timeout 30 rpm -qp --recommends "$asset_dir/${rpms[0]}")" ||
            fail "failed to inspect RPM package recommendations"
        [ "$(printf '%s\n' "$rpm_recommends" | LC_ALL=C sort)" = "$(printf 'iptables\nslirp4netns')" ] ||
            fail "RPM package must recommend exactly iptables and slirp4netns"
        ;;
    nightly) ;;
    *) usage ;;
esac

expected="$asset_dir/.expected-assets"
actual="$asset_dir/.actual-assets"
trap 'rm -f "$expected" "$actual"' EXIT
for payload in "${expected_payloads[@]}"; do
    printf '%s\n' "$payload"
    printf '%s\n' "$payload.spdx.json"
    printf '%s\n' "$payload.sha256"
    printf '%s\n' "$payload.spdx.json.sha256"
done | LC_ALL=C sort >"$expected"

find "$asset_dir" -maxdepth 1 -type f \
    ! -name '.expected-assets' ! -name '.actual-assets' -printf '%f\n' |
    LC_ALL=C sort >"$actual"
if ! diff -u "$expected" "$actual"; then
    fail "$release_type release does not contain the exact expected asset set"
fi

total_size=0
while IFS= read -r -d '' asset; do
    size="$(stat -c '%s' "$asset")"
    [ "$size" -le "$max_asset_size" ] || fail "release asset exceeds size limit: $(basename "$asset")"
    total_size=$((total_size + size))
    [ "$total_size" -le "$max_total_size" ] || fail "release assets exceed aggregate size limit"
done < <(find "$asset_dir" -maxdepth 1 -type f \
    ! -name '.expected-assets' ! -name '.actual-assets' -print0)

for payload in "${expected_payloads[@]}"; do
    for protected in "$payload" "$payload.spdx.json"; do
        sidecar="$asset_dir/$protected.sha256"
        expected_line="$(sha256sum "$asset_dir/$protected" | awk -v name="$protected" '{print $1 "  " name}')"
        [ "$(cat "$sidecar")" = "$expected_line" ] || fail "invalid checksum sidecar: $protected.sha256"
    done
    python3 "$repo_root/scripts/release_tools.py" verify-sbom \
        --document "$asset_dir/$payload.spdx.json" \
        --artifact "$asset_dir/$payload" \
        --source-version "$source_version"
done

echo "$release_type release asset manifest: OK"
