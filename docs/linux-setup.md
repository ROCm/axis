# Linux Setup And Operations

This page describes the Linux behavior shipped by the current source tree.
It is a platform mapping for the shared
[AXIS Isolation Contract](axis-isolation-contract.md). Linux sandboxing is
direct process execution, not Docker or a VM.
The cross-platform install, optional dependency, and package boundary is
documented in
[Install And Runtime Dependencies](install-and-runtime-dependencies.md).
For concrete fresh-machine commands, including source builds, cgroup
delegation, KVM checks, and optional MXC backend smoke tests, see
[Setup And Install](setup-and-install.md).

## Quickstart

Build from a checkout:

```bash
cargo build --locked --release -p axis-cli -p axis-daemon -p axis-sandbox --bins
```

Linux release archives and packages include the MXC `lxc-exec` executor and
the AXIS `axis-seccomp-launcher` helper. The Linux MXC Bubblewrap process
backend also needs a host `bwrap` runtime and unprivileged user namespaces.
Source-tree builds produce the AXIS helper; real MXC runtime validation from a
checkout also needs `lxc-exec` built from the pinned MXC revision and available
from a safe, non-writable executable path. Set `runtime.provider: axis_native`
in a policy to use the retained native Landlock/seccomp path instead of the
default MXC process provider.

Run the default block-mode sandbox:

```bash
./target/release/axis run -- python3 -c 'print("hello from axis")'
```

The built-in `minimal` policy is the no-admin process path. On Linux with the
default `runtime.provider: auto`, AXIS runs it through the MXC Bubblewrap
process executor and still applies AXIS-owned syscall, environment, lifecycle,
and policy checks around that backend. It requests:

- filesystem confinement through the selected process backend,
- AXIS seccomp syscall filtering,
- `network.mode: block`,
- no process, memory, or CPU resource limits.

It does not require a setuid helper, local sudo setup, a writable cgroup
delegation, Docker, or a VM. If a required kernel feature such as Landlock or
seccomp is unavailable for the selected provider, or the MXC process executor
is unavailable for the default provider, AXIS fails before running the command.

## Policy Modes

| Policy choice | Linux behavior | Extra requirements |
| --- | --- | --- |
| `network.mode: block` | Denies outbound IP sockets and does not inject proxy environment variables. UNIX domain sockets are not an IP exception: pathname `connect()` to host sockets is Landlock filesystem policy. | Default provider: safe MXC Bubblewrap executor and AXIS seccomp launcher. Native provider: Landlock and seccomp, or a supported block-mode fallback such as bubblewrap when Landlock is unavailable. Native Landlock denies host pathname UNIX connect on ABI 9+ (`RESOLVE_UNIX`); older ABIs cannot. |
| `network.mode: allow` | Uses host networking while still applying filesystem, seccomp, identity, timeout, and requested resource policy. | No endpoint policies may be configured. Requested resource limits still need enforcement support. |
| `network.mode: proxy` | Starts an AXIS CONNECT proxy behind a netns boundary that rejects direct egress. | `ip`, `iptables`, and either native `CAP_NET_ADMIN` or the optional AXIS netns helper. Kernel-log audit evidence additionally needs readable `/dev/kmsg`. |
| Resource limits | `max_processes`, `max_memory_mb`, and `cpu_rate_percent` are enforced through cgroups v2 when available. | Writable cgroups v2. Memory-only rlimit fallback is documented; process-count rlimit fallback requires a dedicated `run_as_user`; CPU quota has no rlimit fallback. |
| `run_as_user` | Drops to a configured non-root user and prepares writable workspace state for that user. | The target user must already exist, must not be root, and must be usable by the current caller. |
| Bubblewrap fallback | Can provide block-mode fallback when Landlock is unavailable. | A safe root-owned system `bwrap` executable. It is not a proxy-mode fallback unless proxy reachability is also implemented. |

`0` for `max_processes`, `max_memory_mb`, or `cpu_rate_percent` means that
specific limit is not requested. Defaults in richer policies may request
resource limits; those policies fail closed on hosts that cannot enforce them.

## Proxy Credential Handling

Linux sandboxes do not receive common provider API keys or inherited proxy
credentials in their process environment by default. In proxy mode, AXIS can
inject a credential for an explicit local `http://` inference route after the
request reaches the host-side proxy. The sandbox sends an ordinary request
without the raw key.

Credential injection is intentionally fail-closed:

- missing `api_key_env` values are not forwarded upstream,
- unsupported `axis:resolve:*` placeholders reject the route,
- injected values are not logged or added to sandbox argv/env/audit fields,
- credential routes outside proxy mode are rejected,
- remote plaintext and HTTPS credential injection are rejected before launch.

Ordinary HTTPS endpoint traffic remains an opaque CONNECT tunnel. AXIS does not
currently distribute a per-sandbox CA trust bundle, so it does not advertise
method/path filtering or host-boundary credential injection inside HTTPS.

## Proxy Binary Identity

Proxy endpoint policies with `binaries` require Linux native proxy launch with
seccomp-notify connect attribution. The attribution supervisor records the
executable that created the socket before the process can exec or hand the fd to
another binary. If that mechanism is unavailable, AXIS fails closed instead of
falling back to accept-time `/proc` identity for binary allowlists. The
`axis-netns-helper` launch path does not yet publish connect-time records, so
binary-restricted proxy policies are rejected on helper-only hosts.

## Optional Netns Helper

The Linux runtime uses two ordinary unprivileged helper binaries in the default
install path:

```text
lxc-exec
axis-seccomp-launcher
```

Release archives install both beside `axis` and `axisd` for user-prefix
installs. Linux `.deb` and `.rpm` packages install `lxc-exec` into `/usr/bin`
and `axis-seccomp-launcher` into `/usr/libexec/axis`. These helpers are not
setuid and do not make the quickstart privileged.

Proxy mode needs network namespace and firewall setup. Standard user processes
usually lack `CAP_NET_ADMIN`, so production packages may also install a narrow
setuid-root helper at:

```text
/usr/libexec/axis/axis-netns-helper
```

The netns helper is not part of the quickstart requirement. Ordinary local tests
and block-mode use do not depend on it, and base Linux `.deb` and `.rpm`
packages do not install setuid content by default. The curl installer keeps the
default no-admin path, but can install the helper explicitly. This option also
installs the bundled `lxc-exec` at `/usr/local/bin/lxc-exec` with root ownership,
which is required so the setuid helper cannot execute a user-replaceable MXC
binary:

```bash
curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh \
  | sh -s -- --with-netns-helper
```

Advanced users can instead grant `CAP_NET_ADMIN` to root-owned `axis` and
`axisd` binaries:

```bash
curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh \
  | sh -s -- --with-cap-net-admin --prefix /usr/local/bin
```

The helper path is preferred because it confines privilege to the narrow network
setup binary. Granting capabilities to `axis` and `axisd` broadens the privilege
held by the main runtime and should be used only on hosts where that tradeoff is
acceptable.

For source-tree validation, do not install a manual host helper and then treat
that as test coverage. The repo-owned privileged proof is:

```bash
AXIS_RUN_PRIVILEGED_E2E=1 bash e2e/linux/test_netns_helper_launch.sh
```

Run it only in a disposable CI/container/VM runner with passwordless sudo. The
script builds the helper from the current checkout, refuses to overwrite a
preexisting helper, installs it only inside that disposable runner, executes
the proof as a non-root user, and removes the helper during cleanup.

Use these flags when the runner is expected to provide the stronger proof:

```bash
AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E=1
AXIS_REQUIRE_KMSG_AUDIT_E2E=1
```

They turn missing proxy or `/dev/kmsg` prerequisites into failures instead of
visible skips.

## Local Test Commands

Default local Linux proof:

```bash
bash scripts/test_security_tier0.sh
cargo build --locked --release -p axis-cli -p axis-daemon -p axis-sandbox --bins
AXIS_BIN=./target/release/axis bash e2e/linux/test_sandbox.sh
AXIS_BIN=./target/release/axis bash e2e/linux/test_e2e_daemon.sh
```

The security harness is Tier 0/1 and must not require optional runtime tools,
root-installed local artifacts, or host mutation.

Capability-gated proofs:

```bash
AXIS_RUN_BWRAP_E2E=1 bash e2e/linux/test_bwrap_fallback.sh
AXIS_REAL_CGROUP_TESTS=1 cargo test --locked -p axis-sandbox gated_real_cgroup
AXIS_REAL_NETNS_TESTS=1 cargo test --locked -p axis-sandbox gated_real_ip_netns
AXIS_RUN_MXC_PROCESS_E2E=1 bash e2e/linux/test_mxc_process_runtime.sh
AXIS_RUN_MXC_LXC_E2E=1 bash e2e/linux/test_mxc_lxc_smoke.sh
AXIS_RUN_MXC_MICROVM_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh
AXIS_RUN_MXC_HYPERLIGHT_E2E=1 bash e2e/linux/test_mxc_vm_smoke.sh
AXIS_BENCH_MXC_BUBBLEWRAP=1 bash e2e/linux/bench_mxc_runtime.sh
AXIS_BENCH_MXC_LXC=1 bash e2e/linux/bench_mxc_runtime.sh
AXIS_BENCH_MXC_MICROVM=1 bash e2e/linux/bench_mxc_vm.sh
AXIS_BENCH_MXC_HYPERLIGHT=1 bash e2e/linux/bench_mxc_vm.sh
AXIS_RUN_PRIVILEGED_E2E=1 bash e2e/linux/test_netns_helper_launch.sh
```

The capability matrix in [e2e/linux/CAPABILITY_MATRIX.md](../e2e/linux/CAPABILITY_MATRIX.md)
defines which tests are unprivileged, which are gated, and what each skip means.

## Fail-Closed Rules

AXIS should fail before spawning user code when a requested policy cannot be
enforced. Expected examples:

- proxy mode without native netns privileges or the optional helper,
- CPU quotas without writable cgroups v2,
- process-count rlimit fallback without a dedicated `run_as_user`,
- missing seccomp support,
- missing Landlock with no supported fallback,
- endpoint policies under `network.mode: block` or `network.mode: allow`.

These are policy enforcement failures, not setup hints to weaken the sandbox.
