#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Run a terminal program under `axis run` in a PTY, type Ctrl-C as a user
# would, and record whether it came up, whether it exited, and what it left.
#
#   run-tui.sh --axis BIN|none --policy FILE --out DIR --expect TEXT
#              [--home-template DIR] [--ctrl-c-after S] [--second-ctrl-c S]
#              [--max S] [--strace] -- PROGRAM [ARGS...]
#
# --axis none runs PROGRAM without AXIS, to see what it shows when it works.
# --expect is text PROGRAM prints once it is up. Ctrl-C (0x03) is typed after
# --ctrl-c-after seconds (default 20, 0 for never) and again --second-ctrl-c
# seconds later (default 2). The run is stopped after --max seconds (default 60).
# DIR must not exist; it gets home/, ws/, tty.log and result.txt.

set -euo pipefail

die() { echo "run-tui: $*" >&2; exit 2; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }

axis="" policy="" out="" expect="" template="" use_strace=""
ctrl_after=20 second_after=2 max=60
while [ $# -gt 0 ]; do
    case "$1" in
        --axis) axis="$2"; shift 2 ;;
        --policy) policy="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --expect) expect="$2"; shift 2 ;;
        --home-template) template="$2"; shift 2 ;;
        --ctrl-c-after) ctrl_after="$2"; shift 2 ;;
        --second-ctrl-c) second_after="$2"; shift 2 ;;
        --max) max="$2"; shift 2 ;;
        --strace) use_strace=1; shift ;;
        -h|--help) sed -n '5,16p' "$0"; exit 0 ;;
        --) shift; break ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ $# -gt 0 ] || die "missing PROGRAM after --"
[ -n "$axis" ] && [ -n "$out" ] && [ -n "$expect" ] || die "--axis, --out and --expect are required"
[ "$axis" = none ] || { [ -n "$policy" ] || die "--policy is required with an AXIS binary"; axis=$(realpath "$axis"); policy=$(realpath "$policy"); }
[ ! -e "$out" ] || die "$out exists"

out=$(realpath -m "$out")
home=$out/home ws=$out/ws
# The PTY bridge socket is <workspace>/.axis-pty/<uuid>/stdio.sock and must stay under 108 bytes.
[ $(( ${#ws} + 58 )) -lt 108 ] || die "workspace path $ws is too long for the PTY socket; use a shorter --out"
mkdir -p "$home" "$ws"
[ -z "$template" ] || cp -a "$template/." "$home/"

run=()
[ -z "$use_strace" ] || run+=(strace -f -qq --status=failed -o "$out/strace.log")
if [ "$axis" != none ]; then
    # A path that does not exist keeps `axis run` standalone instead of reaching another user's axisd.
    run+=("$axis" --socket "$out/no-axisd.sock" run --policy "$policy" --)
fi
run+=("$@")
inner="cd $(printf %q "$ws") && exec env -i PATH=/usr/bin:/bin HOME=$(printf %q "$home") TERM=xterm-256color LANG=C.UTF-8 $(printf '%q ' "${run[@]}")"

# Leftovers are processes that name this run's directory or PROGRAM and did not exist before it.
regex() { printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g'; }
match="$(regex "$out")|$(regex "$1")"
candidates() { pgrep -u "$(id -u)" -af -- "$match" | grep -v -e run-tui -e pgrep | cut -d' ' -f1 || true; }
mapfile -t before < <(candidates)

mkfifo "$out/stdin"
start=$(now)
timeout -k 5 "$max" script -qfec "$inner" /dev/null < "$out/stdin" > "$out/tty.log" 2>&1 &
pid=$!
exec 3> "$out/stdin"

up_at="" ctrl_at="" second_at=""
while kill -0 "$pid" 2>/dev/null; do
    t=$(now)
    if [ -z "$up_at" ] && sed 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' "$out/tty.log" | grep -qF -- "$expect"; then
        up_at=$t
    fi
    if [ "$ctrl_after" != 0 ] && [ -z "$ctrl_at" ] && [ "$(since "$start" "$t" | cut -d. -f1)" -ge "$ctrl_after" ]; then
        printf '\003' >&3; ctrl_at=$t
    elif [ -n "$ctrl_at" ] && [ -z "$second_at" ] && [ "$(since "$ctrl_at" "$t" | cut -d. -f1)" -ge "$second_after" ]; then
        printf '\003' >&3 2>/dev/null || true; second_at=$t
    fi
    sleep 0.2
done
end=$(now)
rc=0; wait "$pid" || rc=$?
exec 3>&-
if [ -z "$up_at" ] && sed 's/\x1b\[[0-9;?]*[ -\/]*[@-~]//g' "$out/tty.log" | grep -qF -- "$expect"; then up_at=$end; fi

sleep 2
leftover=()
while read -r p; do
    [ "$p" = $$ ] && continue
    case " ${before[*]} " in *" $p "*) continue ;; esac
    leftover+=("$p")
done < <(candidates)
leftover_count=${#leftover[@]}
if [ "$leftover_count" -gt 0 ]; then
    ps -o pid=,args= -p "$(IFS=,; echo "${leftover[*]}")" > "$out/leftovers.txt" || true
    kill -TERM "${leftover[@]}" 2>/dev/null || true; sleep 2; kill -KILL "${leftover[@]}" 2>/dev/null || true
fi
pty_left=no; [ -e "$ws/.axis-pty" ] && [ -n "$(ls -A "$ws/.axis-pty" 2>/dev/null)" ] && pty_left=yes

# timeout(1) exits 124 when it had to stop the run, 137 when it had to kill it.
stopped=no; case "$rc" in 124|137) stopped=yes ;; esac
{
    echo "program=$*"
    echo "axis=$axis"
    echo "policy=${policy:-none}"
    echo "up=$([ -n "$up_at" ] && echo yes || echo no)"
    echo "up_after_s=$([ -n "$up_at" ] && since "$start" "$up_at" || echo -)"
    echo "ctrl_c_after_s=$([ -n "$ctrl_at" ] && since "$start" "$ctrl_at" || echo -)"
    echo "second_ctrl_c=$([ -n "$second_at" ] && echo yes || echo no)"
    echo "stopped_by_timeout=$stopped"
    echo "exit_code=$rc"
    echo "exit_after_ctrl_c_s=$([ -n "$ctrl_at" ] && [ "$stopped" = no ] && since "$ctrl_at" "$end" || echo -)"
    echo "leftover_processes=$leftover_count"
    echo "leftover_pty_socket=$pty_left"
} > "$out/result.txt"

if [ -n "$use_strace" ] && [ -f "$out/strace.log" ]; then
    # Bubblewrap and MXC setup fail these on purpose; they are not the payload's.
    grep -E '= -1 EPERM' "$out/strace.log" | grep -vE 'PR_CAPBSET_DROP|SO_(SND|RCV)BUFFORCE' \
        | sed -E 's/^[0-9]+ +(<\.\.\. )?([a-z0-9_]+).*/\2/' | sort | uniq -c | sort -rn > "$out/denied.txt" || true
fi

sed 's/^/  /' "$out/result.txt"
