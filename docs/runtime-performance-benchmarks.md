# Runtime Performance Benchmarks

AXIS process sandboxes need low startup overhead and fast proxy policy checks.
The runtime benchmark suite separates policy evaluation, proxy request timing,
backend launch work, and interactive terminal cost so numbers can be compared
only when they measure the same surface.

Run the profile benchmark with:

```bash
cargo run --locked -p axis-bench --bin runtime-metrics
```

The command emits JSON with `profile_definitions` and one row per executed
profile. Rows with `status: "ok"` include startup, cold proxy deny, and
synthetic OPA metrics. Rows with `status: "error"` include profile metadata
and a reason, but no timing or throughput fields.

The default run selects all profiles and all runtime providers. Narrow the run
with comma-separated environment variables:

```bash
AXIS_RUNTIME_METRICS_PROFILES=main_compat,mxc_process \
AXIS_RUNTIME_METRICS_PROVIDERS=axis_native,mxc \
AXIS_RUNTIME_METRICS_STARTUP_SAMPLES=20 \
AXIS_RUNTIME_METRICS_PROXY_BASELINE_CONNS=100 \
AXIS_RUNTIME_METRICS_PROXY_REQUESTS=1000 \
AXIS_RUNTIME_METRICS_OPA_EVALS=50000 \
  cargo run --locked -p axis-bench --bin runtime-metrics
```

## Profiles

| Profile | Purpose |
| --- | --- |
| `main_compat` | Match the historical minimal process policy as closely as the current code allows. |
| `axis_native` | Measure direct native process isolation with Landlock/seccomp where available. |
| `mxc_process` | Measure MXC Bubblewrap process containment with AXIS-owned policy layers. |
| `binary_attribution` | Measure native strict proxy policy that requires connect-time identity. |
| `interactive` | Measure PTY bridge overhead separately from non-interactive launch. |

`main_compat` is the apples-to-apples row for comparing current startup, cold
host/port deny, and synthetic OPA numbers against the historical
`success-metrics` policy surface. The other profiles intentionally measure
stronger or different surfaces:

- `axis_native` disables process resource limits to isolate native
  Landlock/seccomp launch overhead from cgroup setup.
- `mxc_process` uses the MXC Bubblewrap process executor and AXIS-owned policy
  layers with resource limits disabled.
- `binary_attribution` measures a strict proxy policy that requires
  connect-time binary attribution and must fail closed when that setup is
  unavailable. It runs on the AXIS native provider because the MXC Bubblewrap
  backend relays sandbox connections through `slirp4netns` and rejects
  binary-restricted endpoint policies.
- `interactive` isolates PTY bridge cost from non-interactive process launch.
  When collected from `runtime-metrics`, this profile requires an `axis` CLI
  binary beside the benchmark binary so the hidden PTY bridge subcommand is
  served by AXIS rather than by the benchmark itself.

## Startup Phases

Startup metrics report phase timings where the runtime can measure them:

| Phase | Scope |
| --- | --- |
| `front_door` | policy validation, runtime provider selection, managed workspace preparation |
| `backend_prepare` | native isolation plan or MXC strategy resolution, capability planning, config translation |
| `preflight` | explicit dry-run or validation subprocesses |
| `support_files` | private config files, seccomp filter files, helper-visible file setup |
| `resources` | cgroup or rlimit preparation |
| `network` | netns/helper setup or proxy strategy setup |
| `pty` | interactive terminal bridge setup |
| `spawn` | child process or backend executor spawn |
| `child_setup` | setup-pipe failures and handoff completion observable after spawn |
| `post_spawn` | seccomp listener receive, connect-attribution supervisor start, bookkeeping |

Non-interactive runs do not set up the PTY bridge. Explicit MXC validation or
dry-run modes are reported as preflight cost instead of being folded into the
normal launch path.

## Proxy Timing

Cold proxy deny measurements start one AXIS proxy for each profile and then
send repeated denied `CONNECT` requests through that already-running proxy.
They do not include sandbox startup or proxy teardown. Host/port-only profiles
measure the direct proxy request loop without binary identity resolution. The
`binary_attribution` profile adds test connect-attribution records so the
strict binary policy can exercise the attribution path explicitly.

Dependency gates are profile-specific. AXIS native profiles require native
process isolation support. MXC profiles require a safe MXC process executor;
MXC profiles that allow network access also need the MXC private-network tools
(`slirp4netns`, `unshare`, `nsenter`, the `iptables`/`ip6tables` tools with
their `-restore` variants, and `/dev/net/tun`).
Strict attribution also requires the launcher/proxy attribution path. Missing
or unsupported dependencies produce `status: "error"` rows rather than
placeholder performance numbers.
