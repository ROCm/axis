#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Record what this host offers AXIS end-to-end runs, and fail when a
# requirement given with --require is missing.
#
#   preflight.sh [--require mxc,strace,tty] [--out FILE]

set -uo pipefail

require=""
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --require) require="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        -h|--help) sed -n '5,9p' "$0"; exit 0 ;;
        *) echo "preflight: unknown argument: $1" >&2; exit 2 ;;
    esac
done

report=""
missing=()
record() { report+="$1=$2"$'\n'; }
need() { case ",$require," in *",$1,"*) missing+=("$1: $2") ;; esac; }
tool() { PATH="$PATH:/usr/sbin:/usr/bin:/sbin:/bin" command -v "$1" 2>/dev/null || true; }

record date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record kernel "$(uname -r)"
record distro "$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null)"
record arch "$(uname -m)"
record uid "$(id -u)"
record lsm "$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
record apparmor_restrict_unprivileged_userns "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
record ptrace_scope "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"
record rustc "$(rustc --version 2>/dev/null || echo missing)"

for t in git cargo bwrap slirp4netns unshare nsenter iptables ip6tables iptables-restore ip6tables-restore script strace; do
    record "tool_$t" "$(tool "$t")"
done

if [ -n "$(tool bwrap)" ] && bwrap --unshare-user --uid 0 --gid 0 --ro-bind / / -- true 2>/dev/null; then
    record bwrap_userns ok
else
    record bwrap_userns failed
    need mxc "bwrap cannot create a user namespace (see apparmor_restrict_unprivileged_userns)"
fi
for t in bwrap slirp4netns unshare nsenter iptables; do
    [ -n "$(tool "$t")" ] || need mxc "$t is not installed"
done
[ -c /dev/net/tun ] || need mxc "/dev/net/tun is missing"

if [ -n "$(tool strace)" ]; then
    if strace --status=failed -qq -o /dev/null true 2>/dev/null; then record strace_status_filter ok; else record strace_status_filter unsupported; fi
    case "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" in
        0|1) ;;
        *) need strace "kernel.yama.ptrace_scope does not allow tracing" ;;
    esac
else
    need strace "strace is not installed"
fi
[ -n "$(tool script)" ] || need tty "script (util-linux) is not installed"

if [ "$(id -u)" = 0 ]; then
    record note "running as root; MXC runs should use a non-root user"
fi

printf '%s' "$report"
[ -n "$out" ] && printf '%s' "$report" > "$out"

if [ ${#missing[@]} -gt 0 ]; then
    printf 'preflight: missing %s\n' "${missing[@]}" >&2
    exit 1
fi
