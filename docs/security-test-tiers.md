# Security Test Tiers

## Purpose

AXIS security testing is delivered by the repository. Normal tests must not
depend on root-installing a locally built helper, setting file capabilities on
local build output, changing host firewall state, or relying on artifacts from a
previous development session.

The tiers below define how backend tests are named, gated, skipped, and run.
They apply to AXIS-native and MXC-backed work on Windows, Linux, and macOS.

## Tier Model

| Tier | Name | Privilege model | Purpose | Default |
| --- | --- | --- | --- | --- |
| 0 | Unit and translation | No special host dependencies | Policy validation, capability planning, config generation, unsupported combinations, secret stripping, and cleanup branches. | Runs by default. |
| 1 | Fake executor e2e | No special host dependencies | End-to-end lifecycle through fake executors, fake helpers, generated configs, timeout paths, logging, and cleanup behavior. | Runs by default. |
| 2 | Unprivileged real runtime | Optional installed tools | Smoke tests for installed non-privileged runtimes such as Bubblewrap, packaged MXC executors, or macOS Seatbelt. | Opt-in or capability-detected. |
| 3 | Capability-gated runtime | Host feature required | Tests for host features such as Windows Sandbox, WSL2, WHP, KVM, LXC, Hyperlight snapshots, cgroups, seccomp notify, user namespaces, and platform build features. | Opt-in with explicit gates. |
| 4 | Privileged disposable CI | Repeatable CI/container/VM setup | Helper proofs, firewall proofs, VM feature setup, privileged capability proofs, and strict network bypass proofs. | Disposable runner only. |

Tier 0 and Tier 1 are the default security proof. They must run without hidden
host setup. Tier 2 and Tier 3 may skip only when the missing dependency is
reported clearly. Tier 4 belongs in repeatable disposable CI or VM scripts that
build from the current checkout, perform privileged setup inside that runner,
prove behavior as a non-root user where appropriate, and tear down all state.

## Default Harness

Run the default no-dependency security harness with:

```bash
bash scripts/test_security_tier0.sh
```

The harness currently runs:

- `cargo test --locked -p axis-core capability`
- `cargo test --locked -p axis-core process_backend`
- `cargo test --locked -p axis-core container_backend`
- `cargo test --locked -p axis-core vm_backend`
- `cargo test --locked -p axis-core mxc_config`
- `cargo test --locked -p axis-sandbox mxc -- --skip gated_`

Backend default evidence can be inspected without host dependencies with:

```bash
cargo run --locked -p axis-bench --bin backend-defaults
cargo run --locked -p axis-bench --bin backend-evidence
cargo run --locked -p axis-bench --bin opa-scenarios
cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

This covers the shared capability planner, process backend planning, container
backend planning, VM backend planning, MXC wire config generation, and the MXC
fake executor/dry-run paths by default. The OPA proxy benchmark measures
policy-specific denied proxy requests against already-running AXIS proxy
instances. On Linux it also measures MXC Bubblewrap proxy modes only when a
safe MXC executor is supplied through `AXIS_TEST_MXC_EXECUTOR` or `lxc-exec` is
on `PATH`; otherwise it reports the missing gate once and emits no MXC runtime
rows. The MXC isolation matrix reports only current-platform MXC backends. It
can run without an executor, in which case the MXC section reports the missing
gate and emits no MXC rows; when an executor is supplied, unavailable backend
dependencies and unsupported backend/mode combinations are reported as data, not
as benchmark timings. The MXC command intentionally skips tests named with the
`gated_` prefix so real-runtime and privileged proofs do not become hidden
host-specific requirements.

CI must run this harness as part of ordinary code testing. Full `cargo test`
may also run, but this harness is the explicit signal that no-dependency
security and fake executor coverage are part of the default gate.

## Skip And Failure Rules

Tests must distinguish unavailable dependencies from failed security behavior.

Use these result categories:

- `PASS`: the behavior was enforced and verified.
- `FAIL`: the dependency was expected to exist, or the behavior was attempted,
  and AXIS did not enforce the contract.
- `SKIP`: the test was optional or explicitly gated, the dependency was absent,
  and the skip message names the missing gate or host feature.

Skip messages must include the gate or dependency. Examples:

- `SKIP: AXIS_RUN_BWRAP_E2E=1 not set`
- `SKIP: bwrap not found on PATH`
- `SKIP: AXIS_REAL_MXC_PROXY_TESTS=1 requires a safe lxc-exec or AXIS_TEST_MXC_EXECUTOR`
- `SKIP: Windows Sandbox feature unavailable`
- `SKIP: /dev/kvm is not readable by the current user`

A test must fail, not skip, when its gate says the dependency is required. For
example, `AXIS_REQUIRE_KMSG_AUDIT_E2E=1` turns unreadable `/dev/kmsg` from a
visible skip into a failure.

## Current Gates

| Gate | Tier | Meaning |
| --- | --- | --- |
| `AXIS_RUN_BWRAP_E2E=1` | 2 | Run Bubblewrap fallback e2e proof when a trusted `bwrap` exists. |
| `AXIS_TEST_MXC_EXECUTOR=<path>` | 2 | Inject a safe MXC executor path for real-runtime tests. |
| `AXIS_TEST_AXIS_SECCOMP_LAUNCHER=<path>` | 2 | Inject a safe AXIS seccomp launcher path for real-runtime tests. |
| `AXIS_REAL_MXC_PROCESS_TESTS=1` | 3 | Run real MXC Bubblewrap process tests when a safe executor, seccomp launcher, and host prerequisites are present. |
| `AXIS_REAL_CGROUP_TESTS=1` | 3 | Run real cgroup tests on hosts with delegated cgroup support. |
| `AXIS_REAL_NETNS_TESTS=1` | 3 | Run real network namespace tests on hosts with required namespace support. |
| `AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1` | 3 | Run seccomp-notify connect-attribution proofs. |
| `AXIS_TEST_RUN_AS_USER=<user>` | 3 | Run identity/resource fallback tests for an existing non-root user. |
| `AXIS_RUN_MXC_PROCESS_E2E=1` | 3 | Run Linux MXC process-runtime proofs when a safe executor and backend prerequisites are present. The Bubblewrap proofs also require `bwrap`, unprivileged user namespaces, `python3`, and, for allow-mode proofs, the MXC private-network tools (`slirp4netns`, `unshare`, `nsenter`, `iptables`/`ip6tables` and their `-restore` variants) with `/dev/net/tun`. |
| `AXIS_RUN_MXC_BASECONTAINER_E2E=1` | 3 | Require and exercise MXC BaseContainer on a feature-enabled Windows host with DACL fallback disabled. The proof covers least-privilege launch, managed-profile and environment filtering, filesystem read-only/read-write/default-deny behavior, child-tree process/aggregate-memory/single-CPU-equivalent rate limits, network allow/block behavior, timeout descendant cleanup, and host-ACL non-mutation. |
| `AXIS_SKIP_UNAVAILABLE_MXC_BASECONTAINER_E2E=1` | CI only | Permit the Windows BaseContainer suite to report an explicit skip only when MXC returns the exact unavailable-BaseContainer and disabled-DACL-fallback result. Missing-executor fail-closed behavior is still proved first; all other launch or policy failures remain fatal. Do not set this on a runtime-qualified BaseContainer host. |
| `AXIS_RUN_WINDOWS_WFP_E2E=1` | 4 | Run the elevated Windows BaseContainer strict-proxy suite with the installed `AxisWfpBroker`. Proves allowed proxy transport, endpoint denial, raw TCP/DNS/QUIC/IPv6 bypass resistance, WFP audit correlation, concurrent lease isolation, and persistent-block crash recovery. |
| `AXIS_REAL_MXC_PROXY_TESTS=1` | 3 | Add real MXC strict proxy reachability proofs to the MXC process e2e wrapper when executor, launcher, and network prerequisites are present. |
| `AXIS_RUN_MXC_LXC_E2E=1` | 3 | Run Linux MXC LXC smoke tests when a safe `lxc-exec` or `AXIS_TEST_MXC_EXECUTOR` and configured LXC runtime/image inputs are present. |
| `AXIS_RUN_MXC_WSLC_E2E=1` | 3 | Run Windows MXC WSLC smoke tests when a safe MXC executor, WSL2, and configured distribution inputs are present. |
| `AXIS_RUN_MXC_MICROVM_E2E=1` | 3 | Run Linux MXC MicroVM smoke tests when a safe `lxc-exec` or `AXIS_TEST_MXC_EXECUTOR`, KVM access, and runtime artifacts are present. |
| `AXIS_RUN_MXC_HYPERLIGHT_E2E=1` | 3 | Run Linux MXC Hyperlight smoke tests when a safe `lxc-exec` or `AXIS_TEST_MXC_EXECUTOR`, KVM access, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_BUBBLEWRAP=1` | 3 | Run Linux MXC Bubblewrap lifecycle, memory, and density benchmarks when executor, `bwrap`, unprivileged user namespaces, `/usr/bin/time`, and `python3` are present. |
| `AXIS_BENCH_MXC_LXC=1` | 3 | Run Linux MXC LXC lifecycle, memory, and density benchmarks when executor, LXC runtime/image inputs, `/usr/bin/time`, and `python3` are present. |
| `AXIS_BENCH_MXC_MICROVM=1` | 3 | Run Linux MXC MicroVM cold/warm, memory, and density benchmarks when executor, KVM, `/usr/bin/time`, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_HYPERLIGHT=1` | 3 | Run Linux MXC Hyperlight cold/warm, memory, and density benchmarks when executor, KVM, `/usr/bin/time`, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_MACOS_SEATBELT=1` | 3 | Run macOS MXC Seatbelt lifecycle, memory, and density benchmarks when a safe MXC executor, `/usr/bin/time`, and `python3` are present. |
| `AXIS_BENCH_MXC_WINDOWS_PROCESSCONTAINER=1` | 3 | Run Windows MXC ProcessContainer lifecycle, memory, and density benchmarks when a safe MXC executor and ProcessContainer prerequisites are present. |
| `AXIS_BENCH_MXC_WINDOWS_WSLC=1` | 3 | Run Windows MXC WSLC lifecycle, memory, and density benchmarks when a safe MXC executor, WSL2, and repeatable image inputs such as `AXIS_MXC_WSLC_IMAGE_TAR_PATH` are present. |
| `AXIS_BENCH_MXC_WINDOWS_SANDBOX=1` | 3 | Run Windows MXC Windows Sandbox cold/warm, memory, and density benchmarks when a safe MXC executor, Windows Sandbox, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_WINDOWS_ISOLATION_SESSION=1` | 3 | Run Windows MXC Isolation Session cold/warm, memory, and density benchmarks when a safe MXC executor, Isolation Session support, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_WINDOWS_MICROVM=1` | 3 | Run Windows MXC MicroVM cold/warm, memory, and density benchmarks when a safe MXC executor, WHP, and runtime artifacts are present. |
| `AXIS_BENCH_MXC_WINDOWS_HYPERLIGHT=1` | 3 | Run Windows MXC Hyperlight cold/warm, memory, and density benchmarks when a safe MXC executor and runtime artifacts are present. |
| `AXIS_RUN_PRIVILEGED_E2E=1` | 4 | Run the disposable privileged helper e2e script. |
| `AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E=1` | 4 | Treat missing built proxy prerequisites as failures. |
| `AXIS_REQUIRE_KMSG_AUDIT_E2E=1` | 4 | Treat missing kernel-log audit evidence as failure. |

Platform-specific test plans may add gates, but they must document the tier,
host dependency, skip message, and failure behavior.

## Invalid Normal Test Dependencies

These are not valid requirements for Tier 0, Tier 1, or ordinary local tests:

- root-installing an AXIS-built helper on a developer host;
- setting setuid or file capabilities on a locally built artifact;
- changing host firewall, OS feature, cgroup, VM, or container state without an
  explicit Tier 3 or Tier 4 gate;
- relying on a helper, executor, cgroup, namespace, image, snapshot, or firewall
  rule installed by a previous manual test;
- weakening a policy so the test passes on the current host;
- using real cloud provider credentials.

Privileged setup is valid only when it is scripted, repeatable, tied to a Tier
4 gate, runs in a disposable environment, and cleans up after itself.

## Review Requirements

Every backend test change must review:

- whether the test proves policy behavior rather than a private implementation
  detail;
- whether missing dependencies produce exact skip or failure messages;
- whether a gate hides a real security failure;
- whether any local artifact install, host mutation, or credential dependency
  has leaked into ordinary tests;
- whether fake executor tests cover success, failure, malformed output,
  timeout, cleanup, and secret-handling branches.
