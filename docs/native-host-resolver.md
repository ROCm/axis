# Native Host Resolver

This document records how the native Linux backend lets a sandbox resolve host
names on hosts that use systemd-resolved, the options considered, and the
questions left for maintainers. What each backend enforces is specified in the
[isolation contract](axis-isolation-contract.md#filesystem-semantics).

## Problem

Issue #123: on a stock Ubuntu host, no program in a native Linux sandbox could
resolve a host name, even with `network.mode: allow`. `/etc/nsswitch.conf` has
`hosts: files mdns4_minimal resolve [!UNAVAIL=return] dns myhostname`, so
systemd's `nss-resolve` module connects to the Unix socket
`/run/systemd/resolve/io.systemd.Resolve` first, and `/etc/resolv.conf` is a
symlink to `/run/systemd/resolve/stub-resolv.conf`.

Measured before the change (Ubuntu 24.04, systemd 255, glibc 2.39, Landlock
ABI 7, `runtime.provider: axis_native`, `network.mode: allow`):

| Grant for `/run/systemd/resolve` | Connect to `io.systemd.Resolve` | Read `/etc/resolv.conf` | UDP query to `127.0.0.53` | `getaddrinfo("pypi.org")` |
|---|---|---|---|---|
| none | `EACCES` | `EACCES` | works | fails, `EBUSY` |
| `read_only` | `EACCES` | works | works | fails, `EBUSY` |
| `read_write` | works | works | works | works |

The native backend lets a sandbox connect to a host socket only beneath a
read-write grant (the `connect()` supervisor below Landlock ABI 9) or not at all
(`RESOLVE_UNIX` on ABI 9+), so the only workaround was a writable system
directory. The socket is load-bearing: with the change below but the socket
alone denied, `getaddrinfo` still fails with `EBUSY` on this host, because a
refused connect does not make `nss-resolve` return `UNAVAIL`, so the lookup
does not fall through to `dns`.

## Options

1. **Implicit grant in `network.mode: allow`.** Allow mode already lets the
   workload query the host's stub resolver on loopback and any DNS server, so
   name resolution is treated as part of that mode. No policy change is needed;
   existing allow-mode policies change behaviour.
2. **Explicit opt-in policy field**, for example a list of connectable Unix
   socket paths or a `network.host_resolver: true` switch. Planner-visible and
   explicit, but every backend must enforce or reject it, and every allow-mode
   policy on a systemd-resolved host must carry it to resolve names.
3. **Socket grant conditional on the `/etc/resolv.conf` grant.** Grant the
   socket only when the policy already lets the workload read
   `/etc/resolv.conf`, treating that grant as the opt-in. Ties a socket to an
   unrelated file grant; a policy without `/etc` would get no resolution.
4. **Document only.** Tell users to grant `/run/systemd/resolve` read-write.
   Gives the workload write access to a system directory.

Within option 1, one mechanism was rejected: a Landlock `RESOLVE_UNIX` rule on
the whole directory `/run/systemd/resolve` on ABI 9+. It would survive resolver
restarts, but it admits every socket in the directory, including any added
later, leaving only file modes to keep them out. The rule sits on the socket
file instead.

## Decision (proposed)

The change implements option 1, recommended here, with this scope:

- Only `network.mode: allow` on the native backend (Landlock or its Bubblewrap
  fallback). `proxy` adds nothing, because the resolver would be a DNS channel
  around the proxy; `block` has no network.
- The socket `/run/systemd/resolve/io.systemd.Resolve` becomes connectable. No
  other socket does.
- The file `/etc/resolv.conf` resolves to becomes readable when a grant already
  covers `/etc/resolv.conf`. With Landlock, when that file is in
  `/run/systemd/resolve`, every file in that directory becomes readable (see
  Lifetimes).
- A `deny:` entry covering either path keeps it denied. A grant that cannot be
  applied leaves its path denied and is logged; it never stops the launch.

This is a recommendation, not a settled decision. Option 2 is the main
alternative; the open questions below are for maintainers.

## Evidence

- **Precedent for option 1.** MXC Bubblewrap already keeps the directory
  `/etc/resolv.conf` points to visible in `network.mode: allow`
  (`resolver_config_dir()` in `crates/axis-sandbox/src/linux/mxc.rs`). It
  exposes that whole directory, sockets included; native exposes less.
- **Precedent for option 2.** `process.windows_win32k` and
  `filesystem.windows_enumerate_ancestors` are off-by-default fields that widen
  access, reported at launch and by `axis policy validate`. They argue that
  widening access belongs in an explicit, visible field rather than an
  implication of another setting.
- **The repository's rule for policy semantics argues for option 2 too.**
  `AGENTS.md`, "Changing policy semantics", requires that a policy field mean
  the same thing on every backend and that the planner see it: "add its
  requirement in `requirements_for_policy` in
  `crates/axis-core/src/capability.rs` and record the support of every backend
  that has an entry in `crates/axis-core/src/capability_map.rs`". Option 1 adds
  no field, so nothing reaches the planner, yet it changes what
  `network.mode: allow` grants on the native backend. An explicit field would
  go through that process.
- **What existing users see.** With option 1, every existing allow-mode policy
  on the native backend gains the grant on upgrade, with no policy edit. The
  change is visible only in logs (info level at launch) and in the note
  `axis policy validate` prints for `provider: axis_native`; no audit event
  records it.
- **The socket adds no network reach.** A workload in native allow mode can
  already send DNS queries to `127.0.0.53` or any server. The socket is still a
  different interface: it can ask for cache-only answers and its replies name
  the interface a lookup used.
- **The directory's other entries.** On the test host, `/run/systemd/resolve`
  holds `io.systemd.Resolve` (0666), `io.systemd.Resolve.Monitor` (0600, owner
  systemd-resolve), `netif/` (0700), and `resolv.conf` and `stub-resolv.conf`
  (0644). The native launch drops every capability and sets `no_new_privs`, so
  a sandbox started as root has no DAC override; `Monitor` and `netif/` stay out
  of reach by mode, and the only other readable file is `resolv.conf`.
- **Replace-by-rename.** systemd-resolved writes its configuration to a
  temporary file and renames it into place (from systemd's documentation and
  source; not triggered here, which would need privileges). On the test host
  `resolv.conf` has a later inode and mtime than the entries created at boot,
  consistent with that. `systemd-resolved.service` sets
  `RuntimeDirectoryPreserve=yes`, so the directory itself persists across
  restarts. A Landlock test renames a file over the granted one: a rule on the
  file loses access, a rule on the directory keeps it.

## Lifetimes

Landlock rules and bind mounts attach to inodes, so each mechanism lasts a
different time:

| Mechanism | Configuration | Socket |
|---|---|---|
| Landlock, ABI 9+ | `READ_FILE` on the directory: the sandbox's lifetime. Elsewhere, on the file: until it is replaced. | `RESOLVE_UNIX` on the socket file: until systemd-resolved restarts. |
| Landlock, ABI < 9 | As above. | `connect()` supervisor admits it by directory and name: the sandbox's lifetime, including restarts. |
| Bubblewrap fallback | Bind of the file: shows the contents at launch. | Bind of the socket: until systemd-resolved restarts. |

The Bubblewrap fallback has no Landlock rule and no `connect()` supervisor, and
a socket on a read-only mount accepts connections, so it never binds the
directory, which would expose every socket in it.

## Open Questions For Maintainers

- **Implicit or explicit.** Keep option 1, or require an opt-in field
  (option 2) that the planner can see? Option 1 changes existing allow-mode
  deployments without a policy edit; option 2 makes every such policy carry an
  entry.
- **Directory-wide `READ_FILE` or file-only.** Landlock has no rule keyed by
  name, so surviving a replaced file needs the directory rule, which also
  exposes the directory's other files subject to their modes. A file-only rule
  stops working at the first DNS configuration change in a long-running
  sandbox.
- **By-name admission below ABI 9.** It survives resolver restarts, but trusts
  any socket put under that name. Optional hardening: refuse by-name admission
  when the directory is writable by anyone other than its owner and root.
- **One source of truth.** The resolver is derived from `policy.network.mode`;
  `plan.network` is equivalent today (`allow` always plans `AllowHost`), but
  deriving it from the plan would give Landlock, the supervisor and Bubblewrap
  one input. The socket and configuration paths could also be shared with MXC's
  `resolver_config_dir()`.

## Not Verified

- Landlock ABI 9+: the `RESOLVE_UNIX` rule on a socket file. Its test skips
  below ABI 9 with a message; no ABI 9 kernel was available.
- The Bubblewrap fallback at runtime: unprivileged user namespaces were blocked
  on the test host, so only plan-level tests ran.
- `network.mode: proxy` at runtime: it needs `CAP_NET_ADMIN` or the netns
  helper. Unit tests cover that it adds nothing.
- Triggering a real systemd-resolved configuration change.
