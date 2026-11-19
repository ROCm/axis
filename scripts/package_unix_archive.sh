#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Package built AXIS binaries into the deterministic dist/axis-<platform>.tar.gz
# archive that release, nightly and CI build and that install.sh installs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    echo "usage: $0 <linux-x86_64|macos-aarch64> <cargo-release-dir> [extra-file...]" >&2
    exit 2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$#" -ge 2 ] || usage
platform="$1"
case "$platform" in
    linux-x86_64 | macos-aarch64) ;;
    *) usage ;;
esac
target_dir="$(cd "$2" && pwd)" || fail "cargo release directory does not exist: $2"
shift 2

cd "$REPO_ROOT"
archive_root="axis-$platform"
package_dir="dist/$archive_root"
rm -rf "$package_dir" "$package_dir.tar.gz"
mkdir -p "$package_dir"
cp "$target_dir/axis" "$package_dir/"
cp "$target_dir/axisd" "$package_dir/"
if [ "$platform" = "linux-x86_64" ]; then
    cp "$target_dir/lxc-exec" "$package_dir/"
    cp "$target_dir/axis-seccomp-launcher" "$package_dir/"
    cp "$target_dir/axis-netns-helper" "$package_dir/"
fi
cp policies/*.yaml "$package_dir/"
cp "$@" LICENSE "$package_dir/"
cp "packaging/reproducibility/core-${platform%%-*}.json" "$package_dir/REPRODUCIBILITY.json"
if [ "$platform" = "linux-x86_64" ]; then
    cp packaging/runtime/core-linux.json "$package_dir/RUNTIME_DEPENDENCIES.json"
fi

cd dist
find "$archive_root" -exec touch -t 198001010000 {} +

write_archive() {
    if [ "$(uname -s)" = "Linux" ]; then
        tar --sort=name --mtime='UTC 1980-01-01' --owner=0 --group=0 --numeric-owner \
            -cf - "$archive_root" | gzip -n > "$archive_root.tar.gz"
    else
        COPYFILE_DISABLE=1 find "$archive_root" -print | LC_ALL=C sort | \
            tar -T - --no-recursion --uid 0 --gid 0 --uname root --gname root \
            -cf - | gzip -n > "$archive_root.tar.gz"
    fi
}

# Writing the archive twice proves the packaging is deterministic.
write_archive
cp "$archive_root.tar.gz" "$archive_root.first.tar.gz"
write_archive
cmp "$archive_root.first.tar.gz" "$archive_root.tar.gz"
rm "$archive_root.first.tar.gz"
