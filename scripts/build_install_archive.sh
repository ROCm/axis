#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Build this checkout, and on Linux the pinned MXC executor, into an archive
# and checksum that install.sh installs through AXIS_INSTALL_ARCHIVE.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Keep the default in sync with MXC_REF in the release, nightly and CI workflows.
MXC_REPOSITORY="${MXC_REPOSITORY:-https://github.com/microsoft/mxc}"
MXC_REF="${MXC_REF:-7bf210247986cb73b1b314df60c2f1109c479c0b}"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform="linux-x86_64" ;;
    Darwin-arm64) platform="macos-aarch64" ;;
    *) fail "no AXIS install archive for $(uname -s) $(uname -m)" ;;
esac

cd "$REPO_ROOT"
cargo build --locked --release
target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release"

if [ "$platform" = "linux-x86_64" ]; then
    mxc_dir="$(mktemp -d)"
    trap 'rm -rf "$mxc_dir"' EXIT
    git clone --filter=blob:none "$MXC_REPOSITORY" "$mxc_dir/mxc"
    git -C "$mxc_dir/mxc" checkout --quiet "$MXC_REF"
    CARGO_TARGET_DIR="$mxc_dir/target" cargo build --release \
        --manifest-path "$mxc_dir/mxc/src/Cargo.toml" -p lxc --no-default-features --locked
    cp "$mxc_dir/target/release/lxc-exec" "$target_dir/lxc-exec"
fi

"$SCRIPT_DIR/package_unix_archive.sh" "$platform" "$target_dir" README.md

archive="axis-$platform.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum "dist/$archive" | awk '{print $1}')"
else
    sum="$(shasum -a 256 "dist/$archive" | awk '{print $1}')"
fi
printf '%s  %s\n' "$sum" "$archive" > "dist/$archive.sha256"

echo "Built $REPO_ROOT/dist/$archive. Install it with:"
echo "  AXIS_INSTALL_ARCHIVE=\"$REPO_ROOT/dist/$archive\" sh install.sh"
