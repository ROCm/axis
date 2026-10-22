#!/usr/bin/env bash
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Gated macOS MXC Seatbelt runtime benchmarks.
#
# This harness does not install MXC, mutate host sandbox settings, or require
# privileged setup. It runs only when the caller opts into the macOS Seatbelt
# benchmark gate and provides the matching MXC executor through PATH or
# AXIS_TEST_MXC_EXECUTOR.
set -euo pipefail

fail() {
    echo "  FAIL: $1"
    exit 1
}

skip() {
    echo "  SKIP: $1"
    exit 0
}

positive_int() {
    local name=$1
    local value=$2

    case "$value" in
        ''|*[!0-9]*)
            fail "$name must be a positive integer"
            ;;
        0)
            fail "$name must be greater than zero"
            ;;
    esac
}

need_tool() {
    local tool=$1
    local reason=$2

    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool is required to $reason"
    fi
}

resolve_executor() {
    if [ -n "${AXIS_TEST_MXC_EXECUTOR:-}" ]; then
        if [ ! -x "$AXIS_TEST_MXC_EXECUTOR" ]; then
            fail "AXIS_TEST_MXC_EXECUTOR is not executable: $AXIS_TEST_MXC_EXECUTOR"
        fi
        EXECUTOR="$AXIS_TEST_MXC_EXECUTOR"
        return
    fi

    if EXECUTOR="$(command -v mxc-exec 2>/dev/null)"; then
        return
    fi
    if EXECUTOR="$(command -v lxc-exec 2>/dev/null)"; then
        return
    fi

    fail "set AXIS_TEST_MXC_EXECUTOR or provide mxc-exec or lxc-exec on PATH"
}

if [ "${AXIS_BENCH_MXC_MACOS_SEATBELT:-}" != "1" ]; then
    skip "set AXIS_BENCH_MXC_MACOS_SEATBELT=1"
fi

if [ "$(uname -s)" != "Darwin" ]; then
    fail "AXIS_BENCH_MXC_MACOS_SEATBELT=1 requires a macOS host"
fi

RUNS=${AXIS_MXC_MACOS_BENCH_RUNS:-5}
DENSITY=${AXIS_MXC_MACOS_BENCH_DENSITY:-4}
TIMEOUT_SECONDS=${AXIS_MXC_MACOS_BENCH_TIMEOUT_SECONDS:-120}
OUTPUT=${AXIS_MXC_MACOS_BENCH_OUTPUT:-}

positive_int AXIS_MXC_MACOS_BENCH_RUNS "$RUNS"
positive_int AXIS_MXC_MACOS_BENCH_DENSITY "$DENSITY"
positive_int AXIS_MXC_MACOS_BENCH_TIMEOUT_SECONDS "$TIMEOUT_SECONDS"

need_tool python3 "generate configs and summarize benchmark results"
need_tool /usr/bin/time "capture child max RSS for MXC Seatbelt benchmarks"
resolve_executor

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/axis-mxc-macos-bench.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

echo "=== AXIS MXC macOS Runtime Benchmark ==="
echo "executor: $EXECUTOR"
echo "tmpdir: $TMPDIR"
echo "runs: $RUNS"
echo "density: $DENSITY"
echo "timeout_seconds: $TIMEOUT_SECONDS"
if [ -n "$OUTPUT" ]; then
    echo "output: $OUTPUT"
fi
echo ""

python3 - "$EXECUTOR" "$TMPDIR" "$RUNS" "$DENSITY" "$TIMEOUT_SECONDS" "$OUTPUT" <<'PY'
import concurrent.futures
import json
import pathlib
import re
import statistics
import subprocess
import sys
import time

executor, tmpdir, runs, density, timeout_seconds, output_path = sys.argv[1:]
runs = int(runs)
density = int(density)
timeout_seconds = int(timeout_seconds)
tmpdir = pathlib.Path(tmpdir)
rss_pattern = re.compile(r"^\s*(\d+)\s+maximum resident set size", re.MULTILINE)


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def summarize(values):
    return {
        "min": min(values),
        "median": statistics.median(values),
        "p95": percentile(values, 95),
        "max": max(values),
    }


def write_config(path, marker, sleep_seconds=0):
    command = f"/bin/sh -c 'echo {marker}"
    if sleep_seconds:
        command += f"; sleep {sleep_seconds}"
    command += "'"
    config = {
        "version": "1.0.0",
        "containerId": f"axis-mxc-bench-seatbelt-{marker.lower().replace('_', '-')}",
        "containment": "seatbelt",
        "process": {
            "commandLine": command,
            "timeout": timeout_seconds * 1000,
        },
        "filesystem": {
            "readwritePaths": [],
            "readonlyPaths": [],
            "deniedPaths": [],
        },
        "network": {
            "egress": {"default": "deny"},
            "ingress": {"default": "deny", "hostLoopback": "deny"},
        },
        "lifecycle": {
            "destroyOnExit": True,
            "preservePolicy": False,
        },
        "seatbelt": {
            "guiAccess": False,
            "nestedPty": False,
            "keychainAccess": False,
        },
    }
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def run_config(config_path, marker):
    command = [
        "/usr/bin/time",
        "-l",
        executor,
        "--experimental",
        "--config",
        str(config_path),
    ]
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds + 10,
            check=False,
        )
    except subprocess.TimeoutExpired as err:
        raise RuntimeError(f"{marker} exceeded outer benchmark timeout") from err
    elapsed_ms = (time.perf_counter() - start) * 1000

    if proc.returncode != 0:
        raise RuntimeError(
            f"{marker} failed with exit {proc.returncode}; "
            f"stdout={proc.stdout[:400]!r}; stderr={proc.stderr[:400]!r}"
        )
    if marker not in proc.stdout:
        raise RuntimeError(f"{marker} missing from stdout; stdout={proc.stdout[:400]!r}")

    match = rss_pattern.search(proc.stderr)
    if not match:
        raise RuntimeError(f"{marker} did not report macOS time -l max RSS data")
    max_rss_kb = int(match.group(1)) // 1024

    return {
        "wall_ms": round(elapsed_ms, 3),
        "max_rss_kb": max_rss_kb,
    }


def benchmark_backend():
    cold_marker = "AXIS_MXC_BENCH_SEATBELT_COLD"
    cold_config = tmpdir / "seatbelt-cold.json"
    write_config(cold_config, cold_marker)
    cold = run_config(cold_config, cold_marker)

    warm_results = []
    for index in range(runs):
        marker = f"AXIS_MXC_BENCH_SEATBELT_WARM_{index}"
        config = tmpdir / f"seatbelt-warm-{index}.json"
        write_config(config, marker)
        warm_results.append(run_config(config, marker))

    density_configs = []
    for index in range(density):
        marker = f"AXIS_MXC_BENCH_SEATBELT_DENSITY_{index}"
        config = tmpdir / f"seatbelt-density-{index}.json"
        write_config(config, marker, sleep_seconds=0.25)
        density_configs.append((config, marker))

    density_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=density) as pool:
        density_results = list(
            pool.map(lambda item: run_config(item[0], item[1]), density_configs)
        )
    density_total_ms = (time.perf_counter() - density_start) * 1000

    warm_wall = [result["wall_ms"] for result in warm_results]
    warm_rss = [result["max_rss_kb"] for result in warm_results]
    density_wall = [result["wall_ms"] for result in density_results]
    density_rss = [result["max_rss_kb"] for result in density_results]

    return {
        "backend": "mxc-macos-seatbelt",
        "containment": "seatbelt",
        "runs": runs,
        "density": density,
        "cold_lifecycle_ms": cold["wall_ms"],
        "warm_lifecycle_ms": summarize(warm_wall),
        "density_total_ms": round(density_total_ms, 3),
        "density_member_ms": summarize(density_wall),
        "max_rss_kb": {
            "cold": cold["max_rss_kb"],
            "warm_max": max(warm_rss),
            "density_max": max(density_rss),
        },
        "metric_gaps": [
            {
                "metric": "teardown",
                "reason": "MXC executor output does not expose teardown separately; lifecycle values include startup, command execution, and cleanup.",
            },
            {
                "metric": "file_descriptors",
                "reason": "Descriptor counts are not yet collected by this shell harness.",
            },
            {
                "metric": "process_count",
                "reason": "Process-tree high-water marks are not yet collected by this shell harness.",
            },
        ],
    }


try:
    result = benchmark_backend()
except Exception as err:
    print(f"  FAIL: macOS Seatbelt benchmark failed: {err}", file=sys.stderr)
    sys.exit(1)

print(json.dumps(result, sort_keys=True))
if output_path:
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([result], indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
