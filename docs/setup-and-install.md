# Setup And Install

This page is the operational setup guide for fresh machines. It separates the
base AXIS install from optional host features so the quickstart remains
unprivileged while stronger isolation modes have clear prerequisites.

## Recommended Install

Install release artifacts first:

Prebuilt archives are published for Linux x86-64, macOS Apple silicon, and
Windows x86-64. Other operating-system and architecture combinations require a
source build until a matching release job is added.

```bash
# Linux / macOS
curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh | sh
```

Windows installation requires PowerShell 7 or later, invoked as `pwsh`. Install
it from <https://aka.ms/powershell-release> before running the installer.

```powershell
# PowerShell 7 on Windows
irm 'https://raw.githubusercontent.com/ROCm/axis/main/install.ps1' | iex
```

On Linux, release archives and packages include `axis`, `axisd`,
`axis-seccomp-launcher`, and the MXC `lxc-exec` executor. The default install
does not install setuid content, grant file capabilities, configure cgroups,
enable VM features, or modify firewall rules.
Windows archives include the pinned MXC `wxc-exec.exe` used by the default
ProcessContainer path.

Verify the basic process sandbox:

```bash
axis --version
axis run -- python3 -c 'print("hello from axis")'
```

The default Linux quickstart uses MXC Bubblewrap process containment,
AXIS-owned seccomp filtering, `network.mode: block`, and no requested cgroup
resource limits.

## Build From Source

Source builds require Rust 1.95 or newer because the AXIS Cargo workspace uses
Rust 2024. The repository contains `rust-toolchain.toml`, so `rustup` users can
run the plain `cargo` commands below.

```bash
rustup toolchain install 1.95.0 --profile minimal
cargo build --locked --release -p axis-cli -p axis-daemon -p axis-sandbox --bins
./target/release/axis --version
```

That builds AXIS binaries and `axis-seccomp-launcher`. To run the default Linux
MXC process backend from a source checkout, also build the pinned MXC executor
used by AXIS release jobs:

```bash
MXC_REPOSITORY=https://github.com/microsoft/mxc
MXC_REF=1736b48398c3fe4d1315b2311c0951cc893eb3ae
mxc_dir="$(mktemp -d)"
git clone --filter=blob:none "$MXC_REPOSITORY" "$mxc_dir"
git -C "$mxc_dir" checkout "$MXC_REF"
cargo build --release --manifest-path "$mxc_dir/src/Cargo.toml" \
  -p lxc --no-default-features --locked
cp "$mxc_dir/src/target/release/lxc-exec" target/release/lxc-exec
```

Keeping `lxc-exec` in `target/release` is enough for a checkout smoke test
because the AXIS resolver checks the current executable directory. A user-prefix
install can copy all non-privileged binaries without sudo:

```bash
install -d "$HOME/.local/bin"
install -m 0755 \
  target/release/axis \
  target/release/axisd \
  target/release/axis-seccomp-launcher \
  target/release/lxc-exec \
  "$HOME/.local/bin/"
```

Do not root-install checkout-built privileged helpers as part of normal
testing. Privileged helper proofs belong in the gated e2e scripts described
below.

For a Windows source checkout, build the same pinned executor used by release
jobs and place it beside `axis.exe`:

```powershell
.\scripts\setup_windows_mxc.ps1
```

The script keeps its MXC checkout under `%LOCALAPPDATA%\axis-dev\mxc`, pins
the tested revision, applies AXIS's compatibility patch idempotently, builds
both release binaries, and configures the current PowerShell process to use
BaseContainer. Pass `-SkipAxisBuild` when only `wxc-exec.exe` needs rebuilding.

Strict Windows proxy policies additionally require the narrowly privileged
AXIS WFP broker. From an elevated PowerShell session, build/install it once:

```powershell
.\scripts\install_windows_wfp_broker.ps1
Get-Service AxisWfpBroker
```

The service accepts only a fixed lease operation for a suspended
`wxc-exec.exe` child. It reads the real AppContainer SID from that child,
allows TCP only to the exact per-sandbox AXIS proxy endpoint, and blocks other
IPv4/IPv6 connects. Dynamic proxy permits disappear on broker failure;
persistent fail-closed blocks are journaled under
`%ProgramData%\axis\wfp-leases` and reaped on restart after PID creation-time
validation. The install script restricts that journal to SYSTEM and
Administrators. Use `-Uninstall` only after all sandboxes have exited.

Windows `auto` and `mxc` policies use ProcessContainer. `axis_native` is
disabled because the legacy path does not enforce the AXIS policy boundary.
The supported policy slice includes filesystem read-only/read-write allowlists,
non-overlapping deny rules that are redundant under BaseContainer default-deny,
a managed Windows profile, child-tree process/aggregate-memory/CPU limits,
default allow/block networking, and broker-backed BaseContainer strict proxy
routing. Nested deny rules and other unmapped Windows
process-policy surfaces fail before launch. AXIS leaves MXC's upstream
BaseContainer-first tier selection intact and always emits
`fallback.allowDaclMutation=false`. An unavailable BaseContainer therefore fails
closed instead of selecting an older AppContainer/DACL tier or temporarily
changing host ACLs.

MXC least-privilege mode remains enabled for BaseContainer. AXIS does not select
an older tier solely to gain a feature, including ConPTY, that the current
BaseContainer API cannot provide.

## Linux Host Packages

The package names below are the common Debian/Ubuntu names. Other
distributions expose the same host features under their native package names.

```bash
# Source builds and local smoke tests
sudo apt-get update
sudo apt-get install -y build-essential curl git python3 bubblewrap

# Optional LXC container backend
sudo apt-get install -y lxc

# Optional KVM access helper and benchmarking utility
sudo apt-get install -y acl time

# Optional strict native proxy path
sudo apt-get install -y iproute2 iptables
```

`bubblewrap` is required for the Linux MXC Bubblewrap process backend. Packaged
AXIS release artifacts supply the AXIS and MXC executables, but the host still
needs the runtime tools that each selected backend uses.

## Feature Dependency Matrix

| Goal | Required host/runtime dependencies | Privilege model | Verification command |
| --- | --- | --- | --- |
| Basic Linux MXC process sandbox | `axis`, `axis-seccomp-launcher`, safe `lxc-exec`, `bwrap`, unprivileged user namespaces, seccomp-BPF | No admin to launch after packages are installed | `axis run -- python3 -c 'print("hello from axis")'` |
| Linux AXIS-native process sandbox | Linux Landlock ABI v3 or newer, seccomp-BPF; safe system `bwrap` only if using the block-mode fallback | No admin to launch on supported kernels | Set `runtime.provider: axis_native`, then run `axis run --policy <policy> -- <command>` |
| Resource limits | Writable delegated cgroups v2 subtree with `cpu`, `memory`, and `pids` controllers | No admin to launch once the shell has cgroup delegation | `AXIS_REAL_CGROUP_TESTS=1 cargo test --locked -p axis-sandbox gated_real_cgroup` |
| Strict Linux proxy policies without binary allowlists | `ip`, `iptables`, network namespaces, and either `axis-netns-helper` or `CAP_NET_ADMIN` on root-owned AXIS binaries | Explicit privileged setup required | `AXIS_RUN_PRIVILEGED_E2E=1 bash e2e/linux/test_netns_helper_launch.sh` in a disposable runner |
| Binary-restricted Linux proxy policies | Strict native proxy dependencies plus seccomp-notify connect attribution from the native `CAP_NET_ADMIN` launch path. Helper-only hosts currently reject binary allowlists. | Explicit privileged setup required | Gated native proxy proof in a disposable runner |
| MXC LXC container backend | Safe `lxc-exec`, prepared LXC runtime usable by the current user, configured distribution/release or image inputs, `python3` for the smoke harness | Backend-specific host setup; no AXIS helper install required | `AXIS_RUN_MXC_LXC_E2E=1 bash e2e/linux/test_mxc_lxc_smoke.sh` |
| MXC microVM backend | Safe `lxc-exec`, readable/writable `/dev/kvm`, MXC microVM runtime artifacts, guest/runtime image inputs | KVM access must be granted by the host; backend is experimental | `AXIS_RUN_MXC_MICROVM_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh` |
| MXC Hyperlight backend | Safe `lxc-exec`, readable/writable `/dev/kvm`, MXC Hyperlight runtime artifacts or snapshots | KVM access must be granted by the host; backend is experimental | `AXIS_RUN_MXC_HYPERLIGHT_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh` |
| VM-isolation vxn backend (Xen DomU) | A Xen environment: a native Xen dom0 (bare metal), or the relocatable vxn SDK built from the meta-virtualization Yocto layer, which boots a dom0 under QEMU and so needs readable/writable `/dev/kvm`. Hosts: Linux, or Windows (WSL2 today; direct Hyper-V planned) | No admin on a native dom0; the SDK path needs host KVM access. Backend is opt-in (`runtime.provider: vxn`) | `axis run --policy vxn -- <tool>` |
| Windows process sandbox | Packaged `wxc-exec.exe`, supported MXC BaseContainer, and Windows Job Objects for AXIS lifecycle cleanup | Normal user launch on a BaseContainer-enabled host | `axis run -- python -c "print('hello from axis')"` |
| Windows VM-style backends | Windows Sandbox, WSL2, Windows Hypervisor Platform, Isolation Session, microVM, or Hyperlight features depending on backend | Explicit Windows feature enablement | Backend-specific gated smoke or benchmark command |
| macOS Seatbelt process sandbox | macOS Seatbelt profile execution support; Xcode Command Line Tools for source builds and platform test builds | Normal user launch | `axis run -- python3 -c 'print("hello from axis")'` |

Missing dependencies are enforcement failures for policies that need them. AXIS
must reject before spawning user code rather than silently weakening the
sandbox.

The Windows install currently provides artifacts only; it does not provide a
usable native process sandbox. Job Object, AppContainer, restricted-token/Low
Integrity, ACL, proxy, and environment controls are targets rather than current
runtime guarantees. Do not use `axis run` on Windows as a containment boundary
until that launcher is enabled with enforcement and negative-test evidence.

## Cgroups V2 Setup

The default minimal policy does not require cgroups. Policies that request
`max_processes`, `max_memory_mb`, or `cpu_rate_percent` need writable cgroups
v2, or a documented fallback for the requested limit.

Check that the host is using cgroups v2:

```bash
stat -fc %T /sys/fs/cgroup
```

The expected value is `cgroup2fs`.

For a one-off delegated shell on systemd hosts:

```bash
systemd-run --user --scope --collect -p Delegate=yes --same-dir "$SHELL" -l
```

Inside that shell, verify cgroup delegation:

```bash
cg="/sys/fs/cgroup$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
test -w "$cg/cgroup.subtree_control" && test -w "$cg/cgroup.procs"
```

Then run the cgroup proof:

```bash
AXIS_REAL_CGROUP_TESTS=1 cargo test --locked -p axis-sandbox gated_real_cgroup
```

## KVM Setup For VM-Style Backends

The MXC microVM and Hyperlight rows are VM-style isolation paths. They are
Firecracker-like in the sense that they require hardware virtualization exposed
through KVM on Linux, but AXIS reaches them through MXC backend configs rather
than invoking Firecracker directly.

Check host support:

```bash
lsmod | grep kvm
test -r /dev/kvm && test -w /dev/kvm
```

If the host uses a `kvm` group, add the user to it and start a new login
session:

```bash
sudo usermod -aG kvm "$USER"
newgrp kvm
```

Some hosts use ACLs instead:

```bash
sudo setfacl -m "u:${USER}:rw" /dev/kvm
```

KVM access alone is not enough for AXIS VM-style smoke tests. The selected MXC
backend also needs its runtime artifacts, image, snapshot, or guest-agent
inputs. If a specific runtime artifact needs additional tools such as QEMU, that
requirement belongs to that artifact's setup instructions. When those inputs are
absent, the gated smoke tests report the missing dependency instead of
installing anything.

## Validation Commands

Build and static validation:

```bash
bash scripts/test_security_tier0.sh
cargo build --locked --release -p axis-cli -p axis-daemon -p axis-sandbox --bins
```

Default Linux runtime validation also needs the basic process-sandbox runtime
dependencies from the feature matrix:

```bash
AXIS_BIN=./target/release/axis bash e2e/linux/test_sandbox.sh
AXIS_BIN=./target/release/axis bash e2e/linux/test_e2e_daemon.sh
```

Optional backend checks:

```bash
AXIS_RUN_MXC_PROCESS_E2E=1 bash e2e/linux/test_mxc_process_runtime.sh
AXIS_RUN_MXC_LXC_E2E=1 bash e2e/linux/test_mxc_lxc_smoke.sh
AXIS_RUN_MXC_MICROVM_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh
AXIS_RUN_MXC_HYPERLIGHT_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh
cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

On a host with the BaseContainer feature enabled, run the AXIS-through-MXC
ProcessContainer proof with a trusted pinned executor:

```powershell
$env:AXIS_RUN_MXC_BASECONTAINER_E2E = "1"
$env:AXIS_TEST_MXC_EXECUTOR = (Resolve-Path ".\target\release\wxc-exec.exe")
.\e2e\windows\test_mxc_processcontainer.ps1 `
    -AxisBin .\target\release\axis.exe
```

The suite tests command execution, environment filtering, managed-profile
projection, explicit/default-deny filesystem behavior, network allow/block
behavior, process count, aggregate memory, single-CPU-equivalent rate limits,
timeout descendant cleanup, and absence of host directory ACL mutation.
Feature-key, fallback, policy, launch, isolation, resource, and cleanup errors
are test failures once the gate is set.

Run the privileged strict-proxy adversarial suite from an elevated PowerShell
session after installing the broker:

```powershell
$env:AXIS_RUN_WINDOWS_WFP_E2E = "1"
$env:AXIS_TEST_MXC_EXECUTOR = (Resolve-Path ".\target\release\wxc-exec.exe")
.\e2e\windows\test_mxc_strict_proxy.ps1 `
    -AxisBin .\target\release\axis.exe
```

It proves allowed HTTPS through the proxy; endpoint denial; raw TCP, DNS,
QUIC/UDP, and IPv6 bypass resistance; correlated WFP events; concurrent lease
isolation; and fail-closed broker restart recovery.

With the same broker and BaseContainer prerequisites, run the managed-inference
boundary proof:

```powershell
$env:AXIS_RUN_WINDOWS_INFERENCE_E2E = "1"
$env:AXIS_TEST_MXC_EXECUTOR = (Resolve-Path ".\target\release\wxc-exec.exe")
.\e2e\windows\test_mxc_inference.ps1 `
    -AxisBin .\target\release\axis.exe
```

This uses a host mock provider to prove streaming, host-only credential
injection, guest secret absence, and token-budget rejection before provider
bytes are forwarded. Windows inference policies require strict proxy mode and
therefore the BaseContainer/WFP tier. `action_on_exhaust: reject` is currently
the only exact budget action; queue and fallback require the future trusted
request scheduler and fail during proxy initialization.

For standalone `axis run`, set `AXIS_INFERENCE_ENDPOINT=127.0.0.1:<port>` to
map the sandbox-visible `inference.local` route to a managed host provider.
AXIS consumes this value in the host proxy and does not project it into the
sandbox environment.

Scoped SSH uses that same BaseContainer/WFP boundary and requires the packaged
`axis-ssh-proxy.exe` beside `axis.exe`. To run its gated proof:

```powershell
$env:AXIS_RUN_WINDOWS_SSH_E2E = "1"
$env:AXIS_TEST_MXC_EXECUTOR = (Resolve-Path ".\target\release\wxc-exec.exe")
.\e2e\windows\test_mxc_scoped_ssh.ps1 `
    -AxisBin .\target\release\axis.exe
```

For enforceable raw-key projection, all selected keys must declare the same
literal host set, generated config and known-hosts must be enabled, and that
host set must exactly match the strict network policy's port-22 endpoints.
This prevents a custom SSH client from using one projected key against another
key's destination. More granular key-to-host sets require a future signing
broker rather than readable private-key copies.

Benchmark checks:

```bash
AXIS_BENCH_MXC_BUBBLEWRAP=1 bash e2e/linux/bench_mxc_runtime.sh
AXIS_BENCH_MXC_LXC=1 bash e2e/linux/bench_mxc_runtime.sh
AXIS_BENCH_MXC_MICROVM=1 bash e2e/linux/bench_mxc_vm.sh
AXIS_BENCH_MXC_HYPERLIGHT=1 bash e2e/linux/bench_mxc_vm.sh
```

These commands never install local artifacts. When a gate is set, missing
declared dependencies are failures; without the gate, optional proofs skip with
the missing prerequisite named.
