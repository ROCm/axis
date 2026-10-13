# Install And Runtime Dependencies

This document defines the dependency and packaging boundary for AXIS runtime
installs, optional backend support, and security testing. It applies to
AXIS-native and MXC-backed paths on Windows, Linux, and macOS.
Concrete build commands, package boundaries, cgroup setup, KVM setup, and
feature-level verification commands are in [Setup And Install](setup-and-install.md).

## Default Install Contract

The default install path installs AXIS binaries and non-privileged platform
executors. It must preserve the quickstart contract for supported default modes:
running a basic sandbox does not require administrator privileges, root
privileges, containers, VMs, local checkout paths, or host firewall changes.

Release archives and packages resolve MXC executors from stable release inputs.
They must not depend on a developer checkout, a machine-local build directory, or
state left by a prior test. Source-tree tests may inject an executor path, but
that is a test dependency and not an install instruction.

Privileged helpers, file capabilities, firewall setup, and OS feature enablement
are optional setup choices. They must be behind explicit install flags,
administrator-controlled package steps, or disposable CI/e2e scripts.

## Runtime Dependency Matrix

| Runtime path | Runtime dependencies | Privilege boundary |
| --- | --- | --- |
| AXIS-native process sandbox | Landlock and seccomp on Linux and Seatbelt on macOS. The Windows native path is disabled until Job Object, AppContainer or equivalent token isolation, filesystem controls, proxy enforcement, and environment isolation can be applied before user code executes. | Supported native paths reject before spawn when a requested policy cannot be enforced. Windows uses the MXC process backend instead of the incomplete native host-spawn path. |
| MXC process sandbox | Packaged MXC executor for the selected platform backend: `lxc-exec` on Linux and `wxc-exec.exe` on Windows. Bubblewrap, unprivileged user namespaces, and AXIS seccomp launcher support are additional Linux dependencies; Linux allow and proxy network modes also need `slirp4netns`, `unshare` and `nsenter` (util-linux), `iptables`, `ip6tables`, `iptables-restore`, `ip6tables-restore`, and `/dev/net/tun` for MXC's private sandbox network namespace. Windows ProcessContainer also requires a supported Windows build/API state. | Default user install for packaged non-privileged executors. Optional host features are discovered safely and missing enforcement fails closed. |
| MXC container sandbox | LXC for Linux container launches or WSL2 for Windows container launches, plus configured rootfs/image inputs. | Host runtime setup is explicit and backend-specific. Unsupported or unavailable runtime state must reject before spawn rather than falling back silently. |
| MXC VM-style sandbox | KVM on Linux, WHP on Windows, Windows Sandbox, Hyperlight runtime artifacts, microVM images, snapshots, or guest-agent assets depending on the selected backend. | VM and host-feature enablement is explicit setup. VM-style backends remain gated until AXIS can prove command, filesystem, network, lifecycle, and cleanup semantics for the requested policy. |
| AXIS proxy networking | The AXIS proxy plus platform network controls. Linux strict native proxy mode needs `ip`, `iptables`, and either native `CAP_NET_ADMIN` or the optional `axis-netns-helper`; binary-restricted Linux proxy policies additionally need connect-time attribution from the native seccomp-notify path, so `runtime.provider: auto` runs them on the native backend and an explicit `mxc` provider rejects them. Windows BaseContainer strict proxy mode needs the installed `AxisWfpBroker` service and patched MXC executor. | The default quickstart does not require proxy-mode privileges. Linux helper/capability setup and Windows WFP service installation are explicit administrator choices. Missing broker state rejects proxy policies before spawn. |
| Source builds | Rust toolchain and platform build tools. Xcode Command Line Tools may be needed to build or test macOS binaries from source. | Build tools are developer dependencies, not runtime prerequisites for installing release artifacts. |

## Optional Backend Dependencies

Optional backend dependencies are resolved only for policies and backend choices
that need them. They include Bubblewrap, LXC, WSL2, Windows Sandbox, WHP, KVM,
Hyperlight snapshots or runtime artifacts, configured container images/rootfs
inputs, and Xcode Command Line Tools for source builds where needed.

Missing optional dependencies are not setup hints to weaken policy. Planner and
adapter code must report the missing dependency and reject the launch before
spawning user code when the selected backend cannot enforce the requested AXIS
policy exactly.

## Test Dependency Classes

Repository-delivered tests are split by dependency class:

| Class | Dependency model | Normal developer expectation |
| --- | --- | --- |
| Tier 0 and Tier 1 | Unit, translation, planner, and fake-executor tests with no special host dependencies. | Runs by default. |
| Tier 2 | Optional installed non-privileged runtimes such as Bubblewrap, packaged MXC executors, or macOS Seatbelt tools. | Opt-in or capability-detected with explicit skips. |
| Tier 3 | Host features such as WSL2, Windows Sandbox, WHP, KVM, LXC, Hyperlight snapshots, cgroups, seccomp notify, and user namespaces. | Explicit gate required; missing prerequisites skip or fail according to the gate. |
| Tier 4 | Privileged helper, firewall, VM setup, and strict bypass proofs in disposable CI/container/VM runners. | Not part of ordinary local testing. |

Normal tests must not require root-installing a locally built AXIS artifact,
setting setuid or file capabilities on checkout output, changing host firewall
rules, enabling OS features, or relying on artifacts from a previous manual run.
Privileged e2e proof is valid only when scripted, repeatable, gated, run in a
disposable environment, and cleaned up by the script.

## Safe Executor Discovery

Production executor discovery must use stable install locations, packaged
artifacts, or user-controlled explicit configuration. It must reject unexpected
executor paths when the host can prove unsafe ownership, world-writable parent
directories, missing execute permission, non-files, or other path properties
that make replacement attacks plausible.

Test injection is allowed only as a test hook and must pass the same path-safety
validation as production discovery unless the test is explicitly exercising an
unsafe-path rejection branch. Public docs and package metadata must not contain
developer-machine paths.

## Package Ownership And Privilege Boundaries

Base packages install ordinary AXIS binaries and non-privileged executor/helper
files. Linux base packages include the MXC `lxc-exec` executor and the AXIS
`axis-seccomp-launcher`; they do not install the privileged `axis-netns-helper`
as setuid content by default.
Windows archives include the pinned `wxc-exec.exe` beside AXIS. They require
BaseContainer but do not enable Windows feature keys or consent to MXC's
host-DACL fallback.

Privileged setup is intentionally separate from the base package contract:

- setuid helper install is an explicit privileged option;
- file capabilities such as `CAP_NET_ADMIN` require an explicit root-owned
  prefix and broaden the privilege held by the main runtime;
- firewall, VM, container, WSL2, Windows Sandbox, WHP, KVM, and Hyperlight host
  setup must be documented as backend-specific host setup;
- source-tree testing must not treat a manually installed helper or capability
  bit as repository-delivered test coverage.
