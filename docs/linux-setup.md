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
default MXC process provider. Besides the policy's paths, the native path grants
the workspace (read-write, or read-only with `workspace_read_only`) and
`/dev/null` (read-write unless a `deny` path covers it; still writable if listed as read-only, because writes are discarded).

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
| `network.mode: block` | Denies outbound IP sockets and does not inject proxy environment variables. UNIX domain sockets are not an IP exception: pathname `connect()` to host sockets is Landlock filesystem policy. | Default provider: safe MXC Bubblewrap executor and AXIS seccomp launcher. Native provider: Landlock and seccomp, or a supported block-mode fallback such as bubblewrap when Landlock is unavailable. Native Landlock denies host pathname UNIX connect on ABI 9+ (`RESOLVE_UNIX`). On older ABIs AXIS supervises `connect()` in both compatibility modes so it reaches only sockets beneath read-write grants, denies abstract connects and `AF_UNIX` datagram sockets, and fails the launch if supervision cannot start. |
| `network.mode: allow` | Permits outbound networking while still applying filesystem, seccomp, identity, timeout, and requested resource policy. The default MXC provider runs the workload in a private network namespace connected through `slirp4netns`, so inbound connections and the host loopback interface stay unreachable. | No endpoint policies may be configured. Requested resource limits still need enforcement support. MXC provider: `slirp4netns`, `unshare` and `nsenter` (util-linux), `iptables`, `ip6tables`, `iptables-restore`, `ip6tables-restore`, and `/dev/net/tun`; without them, AXIS refuses the policy before launch and names what is missing. |
| `network.mode: proxy` | Starts an AXIS CONNECT proxy behind a netns boundary that rejects direct egress. With `runtime.provider: auto` the native backend runs the workload. With an explicit `runtime.provider: mxc`, the workload reaches that boundary through MXC's `slirp4netns` private namespace. | `ip`, `iptables`, and either native `CAP_NET_ADMIN` or the optional AXIS netns helper. Kernel-log audit evidence additionally needs readable `/dev/kmsg`. An explicit `mxc` provider additionally needs native `CAP_NET_ADMIN` (it is rejected behind the helper), `slirp4netns`, `unshare` and `nsenter` (util-linux), `iptables`, `ip6tables`, `iptables-restore`, `ip6tables-restore`, and `/dev/net/tun`. |
| Resource limits | `max_processes`, `max_memory_mb`, and `cpu_rate_percent` are enforced through cgroups v2 when available. | Writable cgroups v2. Memory-only rlimit fallback is documented; process-count rlimit fallback requires a dedicated `run_as_user`; CPU quota has no rlimit fallback. |
| `run_as_user` | Drops to a configured non-root user and prepares writable workspace state for that user. | The target user must already exist, must not be root, and must be usable by the current caller. |
| Bubblewrap fallback | Can provide block-mode fallback when Landlock is unavailable. | A safe root-owned system `bwrap` executable. It is not a proxy-mode fallback unless proxy reachability is also implemented. |

`0` for `max_processes`, `max_memory_mb`, or `cpu_rate_percent` means that
specific limit is not requested. Defaults in richer policies may request
resource limits; those policies fail closed on hosts that cannot enforce them.

## Seccomp Syscall Filter

Every Linux process backend builds its filter from the same AXIS seccomp
allowlist: native Landlock, native Bubblewrap, the netns helper used for proxy
mode, and MXC. MXC also allows `setsid`, `setpgid` and `tgkill`, and policies
with AMD GPU passthrough also allow `sched_setaffinity`. Other syscalls fail
with `EPERM`, with these exceptions: `clone3` fails with `ENOSYS` so thread
runtimes fall back to `clone`, unless the policy blocks it; the extended
attribute calls in the table below fail with `EOPNOTSUPP`; under connect
supervision, `AF_UNIX` datagram sockets fail with `EACCES`; and a syscall made
through another architecture's syscall table kills the process.

Mode and owner changes are allowed both by path (`chmod`, `chown`, `fchmodat`,
`fchownat`) and on an open file descriptor (`fchmod`, `fchown`). `getgroups` is
allowed; it reads only the command's own groups. `fchdir`, `symlinkat` and
`close_range` are allowed; they reach the same checks as the allowed `chdir`,
`symlink` and `close`. `linkat` is allowed too. Unlike `link`, it can link an
open file descriptor (`AT_EMPTY_PATH`) or follow a symlink, but Landlock still
refuses a link whose source is outside the `read_write` paths, and Bubblewrap
and MXC mount each granted path separately, so a link cannot cross from one
into another.

A policy that blocks `chdir`, `chmod`, `chown`, `link`, `symlink` or `close` in
`process.blocked_syscalls` also blocks `fchdir`, `fchmod`, `fchown`, `linkat`,
`symlinkat` or `close_range` respectively. Each blocked name blocks only itself
and the variant listed here; for example, blocking `chmod` does not block
`fchmodat`, and blocking `chown` does not block `fchownat`. A policy that names
an extended attribute call there is rejected, because those calls are always
refused.

These calls stay denied:

| Syscalls | Why they stay denied | What you may see |
| --- | --- | --- |
| `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `getxattrat`, `listxattrat`, `setxattr`, `lsetxattr`, `fsetxattr`, `setxattrat`, `removexattr`, `lremovexattr`, `fremovexattr`, `removexattrat` | Landlock does not check extended attribute calls, so they could read attributes of paths the policy denies, or change attributes of files it denies or grants read-only. | They fail with `EOPNOTSUPP` ("Operation not supported"), as on a filesystem without extended attributes. Tools such as `ls -l`, `sed -i` and `cp -p` then treat files as having no ACLs and continue without an error. |
| `setsid`, `setpgid` | The native provider ends the sandbox by killing its process group, and a process that leaves the group would survive. MXC allows them because its PID namespace contains the whole process tree. | On the native provider, `git` can print `fatal: setsid failed` after a successful commit when it starts background maintenance. `git config maintenance.auto false` avoids it. |

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
seccomp-notify connect attribution. The MXC Bubblewrap backend relays sandbox
connections through `slirp4netns`, so attribution there would name
`slirp4netns` instead of the workload. With `runtime.provider: auto`, such
policies therefore use the native backend; with an explicit
`runtime.provider: mxc`, AXIS rejects them before launch. The attribution supervisor records the
executable that created the socket before the process can exec or hand the fd to
another binary. If that mechanism is unavailable, AXIS fails closed instead of
falling back to accept-time `/proc` identity for binary allowlists. The
`axis-netns-helper` launch path does not yet publish connect-time records, so
binary-restricted proxy policies are rejected on helper-only hosts.

## Backend Selection For Proxy And Allow Mode

With `runtime.provider: auto`, strict proxy mode always runs on the native
backend. MXC v1.0.0 strict proxy is available only with an explicit
`runtime.provider: mxc`, until a capable-host CI run proves it; the
`linux-mxc-proof` workflow runs that proof. MXC also cannot run behind
`axis-netns-helper` at all: the helper starts the workload in its own PID
namespace while `/proc` still shows host PIDs, and MXC v1.0.0 finds its
`slirp4netns` network namespace through `/proc/<pid>`. An explicit
`runtime.provider: mxc` is therefore rejected before launch on helper-only
hosts, and needs native `CAP_NET_ADMIN` elsewhere.

Allow mode always runs on MXC under `auto`, and needs MXC's private-network
dependencies (`slirp4netns`, `unshare`, `nsenter`, the `iptables` tools and
`/dev/net/tun`). Without them, for example in a container with no
`/dev/net/tun`, AXIS refuses the policy before launch; the error names the
missing tool or device and how to provide it. AXIS does not move such a policy
to the native backend on its own, because native allow mode shares the host
network, including host loopback services and inbound connections. Set
`runtime.provider: axis_native` to accept that, or provide the missing
dependency. MXC allow mode denies inbound connections and host loopback, so a
workload that needs a host-local service must not rely on allow mode reaching
it.

Whenever `auto` selects the native backend and that backend cannot enforce the
policy on the host either, AXIS refuses it before launch and says that `auto`
selected the native backend and why.

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
default no-admin path, but can install the helper explicitly. The helper
launches only the native backend: `runtime.provider: auto` runs strict proxy
policies on the native backend and an explicit `provider: mxc` is rejected
before launch behind the helper, so the helper never runs `lxc-exec`:

```bash
curl -sSf https://raw.githubusercontent.com/ROCm/axis/main/install.sh \
  | sh -s -- --with-netns-helper
```

Reinstall the helper whenever you upgrade AXIS. `axis` does not launch through
a helper from a release that predates Unix connect supervision; it logs a
warning and treats the helper as unavailable.

Earlier versions of this option also installed a root-owned
`/usr/local/bin/lxc-exec`. AXIS no longer installs it, but an AXIS binary with
no `lxc-exec` beside it still finds it there, so remove that older copy unless
you installed it there yourself:

```bash
sudo rm /usr/local/bin/lxc-exec
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
