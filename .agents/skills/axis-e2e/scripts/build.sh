#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Build AXIS revisions side by side for end-to-end runs, each with the
# lxc-exec its ci.yml pins, into bin directories AXIS accepts.
#
#   build.sh WORK NAME=REF[@BASE] [NAME=REF[@BASE] ...]
#   build.sh --clean WORK
#
# Run it inside an AXIS checkout. REF is anything `git rev-parse` accepts;
# fetch a pull request first (git fetch origin pull/N/head:pr-N).
# NAME=REF@BASE builds REF merged onto BASE, for testing a PR on current main.
# Binaries land in WORK/bin/NAME with a BUILD_INFO file.
# MXC_SRC=<clone of microsoft/mxc> avoids a fresh clone; NO_MXC=1 skips lxc-exec.

set -euo pipefail

die() { echo "build: $*" >&2; exit 1; }
repo=$(git rev-parse --show-toplevel 2>/dev/null) || die "run inside an AXIS git checkout"

if [ "${1:-}" = "--clean" ]; then
    work=${2:?usage: build.sh --clean WORK}
    for src in "$work"/src/*/; do
        [ -d "$src" ] && git -C "$repo" worktree remove --force "$src" 2>/dev/null || true
    done
    git -C "$repo" worktree prune
    rm -rf "$work"
    echo "removed $work"
    exit 0
fi

[ $# -ge 2 ] || { sed -n '5,16p' "$0" >&2; exit 2; }
work=$(realpath -m "$1"); shift
for spec in "$@"; do
    case "$spec" in ?*=?*) ;; *) die "expected NAME=REF[@BASE], got '$spec'" ;; esac
done
umask 022
mkdir -p "$work"/{src,target,bin,mxc}
chmod 700 "$work"

ci_value() { sed -n "s/^  $1: \(.*\)\$/\1/p" "$2/.github/workflows/ci.yml" | head -1; }

build_lxc_exec() { # MXC_REF MXC_REPOSITORY -> path
    local ref=$1 url=$2 dir=$work/mxc/$1
    if [ ! -x "$dir/lxc-exec" ]; then
        local src=$dir/src
        if [ -n "${MXC_SRC:-}" ]; then
            git -C "$MXC_SRC" worktree add --detach "$src" "$ref" >&2
        else
            git clone -q --filter=blob:none "$url" "$src" >&2
            git -C "$src" checkout -q "$ref"
        fi
        cargo build --release --locked --manifest-path "$src/src/Cargo.toml" -p lxc --no-default-features >&2
        install -m 755 "$src/src/target/release/lxc-exec" "$dir/lxc-exec"
    fi
    echo "$dir/lxc-exec"
}

# Mirrors validate_safe_executable_path in crates/axis-sandbox/src/linux/mxc.rs;
# keep the two in step.
check_safe_path() { # path: every component owned by root or us, no symlink, not group/world-writable
    local path=$1 current="" part
    IFS=/ read -ra parts <<< "${path#/}"
    for part in "${parts[@]}"; do
        current="$current/$part"
        [ -L "$current" ] && die "$current is a symlink; AXIS will not use helpers under it"
        read -r uid mode <<< "$(stat -c '%u %a' "$current")"
        if [ "$uid" != 0 ] && [ "$uid" != "$(id -u)" ]; then
            die "$current is owned by uid $uid; AXIS needs root or the effective user"
        fi
        if (( 8#$mode & 8#022 )); then
            die "$current is group- or world-writable (mode $mode); AXIS will not use helpers under it"
        fi
    done
}

declare -a names=()
for spec in "$@"; do
    name=${spec%%=*}; refs=${spec#*=}
    [ "$name" != "$spec" ] && [ -n "$name" ] || die "expected NAME=REF[@BASE], got '$spec'"
    ref=${refs%%@*}; base=""; [ "$refs" != "$ref" ] && base=${refs#*@}
    src=$work/src/$name; bin=$work/bin/$name
    [ -e "$src" ] && die "$src exists; use another NAME or build.sh --clean"

    head=$(git -C "$repo" rev-parse --verify "$ref^{commit}") || die "unknown ref '$ref'"
    if [ -n "$base" ]; then
        basec=$(git -C "$repo" rev-parse --verify "$base^{commit}") || die "unknown ref '$base'"
        git -C "$repo" worktree add -q --detach "$src" "$basec"
        git -C "$src" -c user.name=axis-e2e -c user.email=axis-e2e@invalid merge -q --no-edit --no-ff "$head" \
            || { git -C "$src" merge --abort; die "$ref does not merge cleanly onto $base"; }
    else
        git -C "$repo" worktree add -q --detach "$src" "$head"
    fi
    commit=$(git -C "$src" rev-parse HEAD)

    echo "== $name: building $commit" >&2
    (cd "$src" && CARGO_TARGET_DIR=$work/target/$name cargo build --release --locked -p axis-cli -p axis-sandbox --bins >&2)

    install -d -m 755 "$bin"
    for f in axis axis-seccomp-launcher axis-netns-helper; do
        if [ -x "$work/target/$name/release/$f" ]; then
            install -m 755 "$work/target/$name/release/$f" "$bin/$f"
        fi
    done
    [ -x "$bin/axis-seccomp-launcher" ] || die "$name: axis-seccomp-launcher was not built"

    mxc_ref=$(ci_value MXC_REF "$src")
    if [ -z "${NO_MXC:-}" ]; then
        [ -n "$mxc_ref" ] || die "$name: no MXC_REF in .github/workflows/ci.yml"
        install -m 755 "$(build_lxc_exec "$mxc_ref" "$(ci_value MXC_REPOSITORY "$src")")" "$bin/lxc-exec"
    fi

    {
        echo "name=$name"
        echo "ref=$ref"
        echo "base=${base:-none}"
        echo "head_commit=$head"
        echo "built_commit=$commit"
        echo "mxc_ref=${mxc_ref:-none}"
        echo "rustc=$(cd "$src" && rustc --version)"
        (cd "$bin" && sha256sum ./*)
    } > "$bin/BUILD_INFO"
    names+=("$name")
done

check_safe_path "$work/bin"
for name in "${names[@]}"; do check_safe_path "$work/bin/$name"; done

declare -A by_hash=()
for name in "${names[@]}"; do
    commit=$(sed -n 's/^built_commit=//p' "$work/bin/$name/BUILD_INFO")
    hash=$(sha256sum "$work/bin/$name/axis" | cut -d' ' -f1)
    if [ -n "${by_hash[$hash]:-}" ] && [ "${by_hash[$hash]%%:*}" != "$commit" ]; then
        die "$name and ${by_hash[$hash]#*:} have the same axis binary from different commits; a build was reused"
    fi
    by_hash[$hash]="$commit:$name"
    printf '%-16s %s  axis %s\n' "$name" "${commit:0:12}" "${hash:0:12}"
done
