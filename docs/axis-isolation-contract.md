# AXIS Isolation Contract

## Status And Scope

This is the shared AXIS isolation contract. It defines the policy semantics
that every backend adapter must preserve, whether the backend is AXIS-native,
MXC-backed, process-based, container-based, or VM-based.

Platform-specific documents and backend plans may describe how an operating
system or runtime enforces this contract. They must not redefine the contract
itself. If a backend cannot enforce a required behavior exactly enough for the
selected mode, AXIS must reject the policy before user code starts.

## Contract Model

AXIS policy is the source of truth. Backend adapters translate policy only
after validation and capability planning prove that the selected backend can
deliver the requested behavior.

Every policy/backend pair must produce one of these outcomes:

| Outcome | Meaning |
| --- | --- |
| `Exact` | The backend plus any AXIS-owned layers enforce the requested policy. |
| `ExactWithHostDependency` | The policy is enforceable only when a declared host dependency is present. Missing dependencies fail before spawn. |
| `WeakerOnly` | The backend provides a weaker behavior that is not equivalent to the requested policy and must be selected explicitly. |
| `Unsupported` | The policy/backend pair cannot satisfy the contract and must be rejected before spawn. |

Backends may also mark a policy surface as AXIS-owned when the backend starts
the workload but AXIS remains responsible for enforcement. Examples include the
strict network proxy, supported local credential injection, inference routing,
audit aggregation, and some lifecycle cleanup.

## Shared Invariants

These invariants apply to all platforms and backend families:

- Unsupported policy combinations fail before user code starts.
- Missing host dependencies fail before user code starts unless the selected
  policy explicitly allows the weaker or absent behavior.
- A backend setup failure must not fall back to unsandboxed host execution.
- A weaker backend behavior must never be reported as exact enforcement.
- Backend probes must not mutate host policy, install local artifacts, change
  OS features, or rely on previous developer-machine setup.
- Runtime errors must preserve the original failure while still attempting
  complete cleanup.
- Sandbox-visible configuration, argv, environment, files, inherited file
  descriptors, logs, and audit records must not contain raw provider secrets.
- Security decisions that require binary identity, sandbox identity, or route
  identity fail closed when that identity is unavailable or ambiguous.

## Filesystem Semantics

AXIS filesystem policy defines what the sandboxed workload may read or write.

Required behavior:

- Read-only paths may be read but not modified by the sandbox.
- Read-write paths may be read and modified by the sandbox.
- Denied paths must be inaccessible or masked so the sandbox cannot inspect
  their contents, metadata, or symlink targets beyond what the platform
  unavoidably exposes.
- Pathname UNIX `connect()` and addressed `sendmsg()` to a socket created
  outside the sandbox is filesystem access, not `network.mode`. Native Landlock
  handles `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (ABI 9+) and does not grant it on
  allow paths, so host sockets (`/var/run/docker.sock`, sockets under `/tmp`)
  are default-denied. Connections to UNIX servers created inside the same
  Landlock domain remain allowed. Abstract UNIX `connect()` is scoped to the
  sandbox with `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6+).
  On Landlock ABI < 9 the native backend supervises `connect()` with seccomp
  user notification under both compatibility modes, and fails the launch if
  the supervisor cannot start. A pathname connect reaches a socket only when
  the socket resolves, in the sandbox's own root and working directory,
  beneath a read-write grant or the writable workspace, and the sandbox
  identity has permission to it; the supervisor then connects through the
  resolved inode, as the sandbox identity. Abstract connects are denied, and
  the sandbox cannot create `AF_UNIX` `SOCK_DGRAM` sockets. This is weaker
  than ABI 9: a socket inside a read-write grant is reachable even when
  another process created it there.
- MXC Bubblewrap mounts the host root read-only, and a socket on a read-only
  mount still accepts connections. AXIS masks all of `/run`, and LXD and Incus
  socket directories, unless a path beneath `/run` must stay visible: a grant,
  or in `network.mode: allow` the resolver configuration `/etc/resolv.conf`
  points to. AXIS then masks every directory under `/run` that is not on the
  way to that path. MXC masks only directories, so sockets directly in a
  directory on the way stay visible, and AXIS logs them. Keep read grants to
  the paths a workload needs.
- In MXC Bubblewrap `network.mode: allow`, the workload runs in MXC's private
  `slirp4netns` network namespace, so the host's abstract UNIX sockets are not
  reachable from it. As defence in depth, `axis-seccomp-launcher` also scopes
  abstract UNIX `connect()` to the sandbox with Landlock (ABI 6+), so inside
  that namespace too the workload reaches only abstract sockets the sandbox
  itself created. Install the launcher from the same release as `axis`; an
  older launcher fails the launch. Where the kernel cannot apply that scope
  (below Landlock ABI 6, or without Landlock), `hard_requirement` fails the
  launch and `best_effort` logs a warning. The messages name
  `provider: axis_native`, which can run `network.mode: allow` under
  `hard_requirement` where its own Landlock requirements are met but shares
  the host network, including host loopback, and `network.mode: block` or
  `proxy`.
- Denied paths take precedence over read-only and read-write grants.
- Workspace and temporary directories must be scoped to the sandbox or policy
  and must not widen access to the caller's home directory.
- Symlink, hardlink, path traversal, and canonicalization behavior must not
  allow a granted path to escape into a denied path.

If a backend cannot represent a deny rule exactly, AXIS must either add an
AXIS-owned layer that masks the path exactly, select another backend, or reject
the policy. A backend that merely ignores deny rules is `Unsupported` for that
policy.

## Network Semantics

AXIS network policy has distinct modes. They are not interchangeable.

### Allow Mode

`network.mode: allow` permits outbound networking for the workload. It makes
no promise about inbound connections or about services on the host's loopback
interface, and backends differ there:

- MXC Linux Bubblewrap runs the workload in a private network namespace
  connected through `slirp4netns`, and MXC Seatbelt writes a profile that
  denies them. On both, the workload cannot reach host loopback services and
  nothing can connect in.
- The native Linux and macOS backends share the host network, so both work.

Which of these runs a policy depends on the platform and on
`runtime.provider` (see Backend Selection Rules below; on Linux, `auto` keeps
allow mode on MXC), so a workload that needs a host-local service must not
rely on allow mode reaching it. Endpoint allow
or deny policy is not enforced in this mode unless another explicit AXIS-owned
network enforcement layer is selected. A policy that combines allow mode with
endpoint restrictions must be rejected unless such a layer is present and
planned as `Exact`.

### Block Mode

`network.mode: block` denies outbound IP networking from the workload. It must
not inject proxy environment variables or leave a documented direct-egress path
open. If a backend can only partially block networking, that backend is
`Unsupported` for block mode unless the policy explicitly selects a weaker
behavior.

### Strict Proxy Mode

`network.mode: proxy` means strict AXIS proxy isolation:

- direct outbound network access is denied;
- the sandbox can reach only the AXIS proxy or router endpoint needed for the
  policy;
- endpoint policy is evaluated by AXIS outside the sandbox;
- supported local provider credentials are injected only at the host-side policy boundary;
- direct bypass attempts are denied and auditable where the platform can
  provide evidence;
- binary-restricted endpoint policy requires reliable connect-time attribution
  or another equally strong identity mechanism.

If binary attribution, sandbox identity, or proxy reachability cannot be proven,
strict proxy mode is `Unsupported` for that backend and host state.

### Cooperative Proxy Mode

Cooperative proxying is not strict proxy isolation. A backend that only sets
`HTTP_PROXY`, `HTTPS_PROXY`, or related environment variables while sharing host
networking provides a weaker behavior because clients can ignore those
variables or open raw sockets directly.

Cooperative proxying may be exposed only as an explicitly weaker mode with a
`WeakerOnly` outcome. It must not silently satisfy `network.mode: proxy`.

## Process And Identity Semantics

AXIS process policy covers the command, arguments, working directory,
environment, user identity, process tree, terminal mode, timeout, and exit
status.

Required behavior:

- The executed command, argv, cwd, and environment must match the planned
  sandbox launch.
- Environment filtering must remove inherited provider secrets and inherited
  proxy credentials unless AXIS intentionally adds sanitized values.
- `run_as_user` must not run as root and must fail if the requested identity
  cannot be prepared safely.
- `identity: isolated` is portable intent for a backend-owned isolated token or
  account. It must not be implemented by guessing a host username. Windows MXC
  maps it to the actual least-privilege ProcessContainer token; legacy
  `run_as_user` remains unsupported there.
- `child_processes: deny` means the workload may have no descendants. Backends
  enforce it as an atomic one-process tree limit; it is not translated into a
  guessed list of `fork`, `clone`, or process-creation API names.
- `blocked_syscalls` remains an explicitly Linux-specific seccomp surface.
  Portable restrictions must use semantic fields rather than syscall names.
- Process-tree limits, process groups, sessions, and job handles must not allow
  child processes to escape timeout or destroy behavior.
- PTY support must be planned explicitly. A backend without PTY support is
  `Unsupported` for policies that require it.
- Exit status, stdout, stderr, and timeout status must report the sandboxed
  workload, not an unrelated wrapper failure unless wrapper setup failed before
  spawn.
- When AXIS itself fails, for example on an invalid policy or a sandbox that
  cannot start, `axis run` and `axis exec` exit with status 125 and print the
  reason on stderr, so a caller can tell an AXIS failure from the workload's
  own status.

### macOS system services

`macos.restrict_system_services` defaults to false. The native macOS Seatbelt
profile then allows `mach*` and `sysctl-read`.

When the flag is true, that profile replaces both with a fixed allowlist of
Mach lookups for user lookup and preferences, and sysctl reads for CPU and OS
identity. `macos.mach_lookup` and `macos.sysctl_read` add exact names, for
example a Keychain service. The clipboard service is not on the fixed list.
Names that cannot be embedded in the profile are rejected when the policy is
parsed.

Only `axis-native-macos-seatbelt` enforces the flag. Every other backend
reports `Unsupported` when it is set, and the launch fails before user code
runs.

## Backend Selection Rules

These rules decide which backend runs a policy, or reject it before launch:

- Linux `runtime.provider: auto` selects the native backend instead of MXC
  Bubblewrap for a policy with binary-restricted endpoint rules and for every
  strict-proxy policy. If the native backend cannot enforce the policy either,
  the launch fails before user code runs, and the error says that `auto`
  selected the native backend and why.
- `auto` never moves an allow-mode policy to the native backend because the
  host lacks MXC's private-network dependencies (`slirp4netns`, `unshare`,
  `nsenter`, the `iptables` tools and `/dev/net/tun`): native allow mode would
  give the workload the host's loopback services and inbound connections. MXC
  refuses such a launch before user code runs and names the missing tool or
  device and how to provide it.
- Linux `runtime.provider: mxc` never moves. MXC Bubblewrap rejects before
  launch: binary-restricted endpoint rules, because `slirp4netns` relays the
  workload's connections and connect-time attribution cannot name the
  program; allow and strict proxy without its private-network dependencies;
  and strict proxy behind `axis-netns-helper`, which MXC cannot run behind.
- MXC Linux Hyperlight supports only block mode. Allow and strict proxy are
  rejected before launch.
- MXC Windows Isolation Session supports no network mode. Its configuration is
  never generated, because MXC has no network enforcement primitive for it.
- The MXC 1.x configuration formats (Linux and macOS) carry no AXIS proxy
  endpoint. A policy that asks MXC to configure one is rejected rather than
  launched without it.

Per-binary network policy remains unsupported on Windows ProcessContainer. A
SID-scoped WFP lease proves the sandbox identity but not the executable behind
each proxied CONNECT; user-mode PID/tuple reconstruction is vulnerable to PID
reuse and short-lived-connection races. AXIS will not weaken that requirement
without ALE process metadata or an equivalent race-safe boundary.

## Credential Semantics

Raw credentials are host-side policy material. The sandbox may receive
placeholders, dummy values required by client libraries, or AXIS-generated
proxy settings, but not raw provider keys.

Required behavior:

- Raw provider credentials must not appear in sandbox environment variables,
  MXC JSON, backend config files, argv, logs, audit records, or sandbox-visible
  files.
- Provider credentials are resolved and injected only by AXIS-owned host-side
  proxy or router code for supported policy-allowed requests.
- Host-boundary injection is currently limited to explicit local `http://`
  routes. Remote plaintext and HTTPS credential routes are unsupported and
  fail before launch.
- Missing required credentials fail closed for the route that needs them.
- Unsupported credential placeholders fail closed.
- Error messages must name the missing or unsupported credential reference
  without printing the credential value.

## Inference Semantics

Inference policy describes how sandboxed workloads reach local or external
model providers.

Required behavior:

- `inference.local` remains the explicit managed local inference endpoint.
- External provider hosts are governed by ordinary network and provider policy;
  they must not be implicitly rewritten into local inference routes.
- Local inference routing, provider failover, streaming, model discovery,
  embeddings, and chat or responses APIs must preserve sandbox identity and
  route policy.
- If TLS interception, local CA trust, streaming, or protocol inspection is
  required for a route and the backend cannot support it, the route is
  `Unsupported` unless an AXIS-owned layer supplies exact behavior.
- HIP Remote and GPU-related inference support must keep hardware access
  outside the sandbox unless the selected policy explicitly allows otherwise.
- HIP Remote GPU controls that the worker does not enforce yet (VRAM limits,
  compute timeouts, HIP API allow/deny lists, and Unix-socket transport) are
  `Unsupported` on every backend and are rejected before launch when the
  policy enables the GPU.

## Resource Semantics

Resource policy includes process count, memory, CPU, timeout, and backend
native limits.

Required behavior:

- Requested limits must be enforced by the backend or an AXIS-owned layer.
- A missing resource primitive is `Unsupported` unless the policy explicitly
  allows a documented weaker fallback.
- CPU limits must not degrade into no CPU enforcement.
- Process-count fallbacks that depend on user identity must require an identity
  that cannot affect unrelated host processes.
- Cleanup must remove resource groups, job handles, cgroups, temporary state,
  and backend lifecycle objects after normal exit, timeout, failed spawn, and
  partial setup failure.

## Lifecycle And Cleanup Semantics

AXIS lifecycle policy covers create, start, exec, destroy, timeout, daemon
shutdown, and repeated cleanup.

Required behavior:

- User code starts only after all required isolation layers are planned and
  applied.
- Partial setup failure must clean all state created before the failure.
- Destroy must be idempotent.
- Timeout must stop the full sandbox workload and any backend-owned child
  processes, containers, or VM sessions.
- Cleanup failures must be reported without hiding the original sandbox
  failure.
- Stateful backends must make persisted state explicit in policy or launch
  options. Hidden state reuse is not allowed.
- axisd accepts IPC and gateway requests only with the per-user token in
  `axisd.token`, so a sandboxed process cannot ask it for a less restricted
  sandbox. axisd replaces the token on every start and deletes it on clean
  shutdown. The token directory is `~/.axis/run` on Unix and
  `%LOCALAPPDATA%\axis` on Windows, taken from the user account (not `HOME`
  or `LOCALAPPDATA`) and resolved through symlinks, so every process agrees
  on it. Sandboxes must not see it:
  - Every launch is refused when it cannot be determined.
  - Linux and Windows refuse launches whose final workspace or grants, after
    AXIS adds its own, cover it, and treat a grant they cannot resolve as
    covering.
  - macOS denies it in the Seatbelt profile.
  - Only Linux (native and MXC) has a runtime test that a sandboxed process
    cannot read the token; Windows and macOS are covered by unit tests of the
    grant check and the generated profile.

## Audit And Evidence Semantics

Audit records are part of the security contract because they explain policy
decisions and denied behavior.

Required behavior:

- Denials must identify the policy surface, backend, sandbox identity, and
  reason without exposing raw secrets.
- Missing optional evidence may be reported as a skip only for tests or
  diagnostics. Runtime policy enforcement must still fail closed when evidence
  is required.
- Direct network bypass attempts in strict proxy mode must be denied. They
  should be auditable where the platform provides reliable evidence.
- Backend capability probes, dependency skips, and unsupported combinations
  must produce actionable messages.

## Platform Appendices And Backend Maps

Platform appendices and backend capability maps must use this contract
vocabulary. They should describe:

- which policy surfaces are `Exact`, `ExactWithHostDependency`, `WeakerOnly`,
  or `Unsupported`;
- which host dependencies or OS features are required;
- which enforcement layers are backend-owned and which are AXIS-owned;
- which tests prove the behavior;
- which behavior is intentionally unavailable.

Appendices may mention platform primitives such as Landlock, seccomp,
Seatbelt, AppContainer, Job Object, LXC, Bubblewrap, WHP, KVM, or Hyper-V.
Shared AXIS code and public policy semantics should not depend on those
primitive names.
