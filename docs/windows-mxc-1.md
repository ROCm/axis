# Windows MXC 1.x Backend

AXIS runs Windows process policies through MXC BaseContainer
(`mxc-windows-processcontainer`). This document records the move of that
backend from a patched pre-1.x MXC executor to unpatched MXC 1.x, the isolation
trade-offs it accepts, and the evidence. Backend defaults are recorded in
[Backend Default Decisions](backend-default-decisions.md).

## Problem

Through AXIS v0.4.0, Windows `wxc-exec.exe` was built from MXC commit
`1736b48398c3fe4d1315b2311c0951cc893eb3ae` with three AXIS patches:

- process-count, memory and CPU fields in the ProcessContainer schema;
- assignment of the BaseContainer child to an inner resource Job;
- a pre-resume hook into a privileged AXIS WFP broker service
  (`axis-wfp-broker.exe`, installed by `scripts/install_windows_wfp_broker.ps1`)
  that installed per-SID proxy permit and default-deny filters.

The patches did not apply to the MXC 1.x `src/mxc-sdk` layout, so Windows was
stuck on a pre-release contract (`0.6.0-alpha`) while Linux moved to MXC
v1.0.0. Strict proxy mode also needed an elevated service install, and the
broker was AXIS-owned privileged code with its own lease journal and recovery
path.

MXC 1.x changes the picture:

- `runtimeConfig.networkProxy` installs per-container WFP filters that allow
  egress only to one loopback proxy endpoint;
- `ui` controls Win32k, which USER32-linked tools (PowerShell, Git for Windows)
  need to start;
- `processContainer.filesystem.enumeratePaths` lets the child list grant
  ancestors without reading them, which path canonicalization needs;
- there is no resource-limit schema and no least-privilege (LPAC) token option
  (<https://github.com/microsoft/mxc/issues/1496>).

## Options

1. **Keep the patched pre-1.x executor.** No isolation change, but the patches
   would have to be rewritten for every MXC update, strict proxy keeps the
   privileged broker, and Windows stays on a contract MXC no longer accepts.
2. **Port the patches to MXC 1.x.** Keeps LPAC only if MXC accepts an LPAC
   patch upstream; until then it is a long-lived fork of the security-relevant
   part of MXC.
3. **Use unpatched MXC 1.x and move resource limits into AXIS.** Drops the fork
   and the broker; accepts the MXC 1.x limits listed under Accepted trade-offs
   and reports them.

## Decision

Option 3. Windows `wxc-exec.exe` is built from MXC v1.0.1
(`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`) without patches. v1.0.1 rather
than v1.0.0 because it fixes BaseContainer loopback access to host services on
PSEC 1.0 hosts, which the proxy mapping depends on.

- **Resource limits.** AXIS creates `wxc-exec.exe` with `CREATE_SUSPENDED`,
  assigns it to a kill-on-close Job Object that carries the process-count,
  memory and CPU limits, and resumes it only after the assignment succeeds. The
  job is sized `max_processes + 1` for the executor itself. The MXC config
  builder now rejects resource limits unless the caller states that AXIS
  enforces them, so a future launcher that forgets the Job fails closed.
- **Strict proxy.** AXIS emits `runtimeConfig.networkProxy` with the
  per-sandbox proxy URL. The WFP broker, its install script, its release assets
  and the `windows.axis_wfp_broker` host dependency are removed.
- **Win32k and ancestor enumeration** are opt-in policy fields,
  `process.windows_win32k` and `filesystem.windows_enumerate_ancestors`, both
  off by default. They only grant access on Windows and are ignored elsewhere.
  `windows_enumerate_ancestors` exposes names, sizes and times (not contents)
  below every ancestor of a grant, such as `C:\`; an ancestor inside another
  grant is left out so it cannot downgrade that grant.
- **Executor config file.** The temporary config is written to a host temp
  directory outside every read-write grant, so a sandbox cannot rewrite the
  next launch's policy even when the caller points `TEMP` at a lease directory.
- **Environment.** AXIS always passes an explicit environment, adding
  `SYSTEMROOT` and `LOCALAPPDATA` when the caller does not set them (MXC 1.x
  refuses to launch without them), so the child does not inherit the user's
  persisted variables through its environment block.

### Accepted trade-offs

| Area | MXC 1.x behavior | AXIS handling |
| --- | --- | --- |
| Token | No LPAC. The child keeps the caller's user SID inside the container and the token keeps ALL APPLICATION PACKAGES. | `process.identity: isolated` is `Unsupported` and rejects before launch. Filesystem grants stay exact: user files outside the grants are denied, but system locations (for example `C:\Windows`) and the user's registry hive (including `HKCU\Environment`) stay readable. |
| Strict proxy ingress | `runtimeConfig.networkProxy` requires `network.ingress.default: allow`, which adds `privateNetworkClientServer`. | Egress is limited to the proxy. Whether a private-network peer can connect to a listener in the sandbox depends on the host firewall; AXIS does not enforce it. `network.strict_proxy` stays exact because the isolation contract scopes strict proxy to outbound traffic and leaves inbound reach to each backend. Marking it weaker would disable Windows proxy mode, since no policy can accept a weaker strict proxy today. |
| Bypass evidence | MXC's WFP filters block direct egress but do not report individual blocked connections. | Bypass attempts are denied but no longer produce AXIS audit records; the removed broker logged correlated WFP block events. The contract asks for bypass audit only where the platform provides reliable evidence. Collecting Windows Filtering Platform audit events would require an administrator audit policy, which AXIS does not change. |
| Other Windows MXC contracts | MXC 1.x rejects `0.6.0-alpha`. | Only ProcessContainer has a Windows launch path. The WSLc, Isolation Session and VM-style config builders, and their benchmark harness rows, still emit `0.6.0-alpha` and need the 1.0.0 contract before they can launch. |

## Evidence

Windows 11 build 26100.9711, MXC v1.0.1 (the signed x64 `wxc-exec.exe` from
the MXC release, built from the pinned commit, SHA-256
`090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a`), and AXIS
built from the commit that added this document.

- **Gated e2e.** `test_mxc_processcontainer.ps1`, `test_mxc_strict_proxy.ps1`
  and `test_mxc_inference.ps1` pass. The strict proxy run left out the QUIC
  baseline and probe because the test network blocks outbound UDP 443 for the
  host as well.
- **Isolation probes.**
  - Block and proxy modes both block direct egress, and loopback port 445 is
    blocked.
  - Through the proxy, the allowed host returns 200 and a denied host 403.
  - Host loopback cannot connect to a listener in the sandbox in either mode.
  - A connection from a different host interface (WSL NAT, `172.17.64.0/20`)
    reached a host-side listener but not a sandbox listener in proxy or block
    mode. That interface is not a private-profile LAN, so private-network
    ingress remains untested.
  - Writes to user files outside the workspace, `C:\Users`, `ProgramData` and
    `C:\Users\Public` are denied; `C:\Windows` and `HKCU\Environment` are
    readable.
  - `max_processes` and `max_memory_mb` are enforced through the Job Object.
    A process that exceeds the memory limit terminates with an access
    violation rather than a clean allocation error.
- **Launch latency.** `axis run -- cmd.exe /c exit 0`, 20 runs after 2 warm-up
  runs, against the AXIS v0.4.0 Windows package (patched pre-1.x executor):

  | Build | Mode | Median | p90 | Failures |
  | --- | --- | --- | --- | --- |
  | v0.4.0 | block | 2372 ms | 2395 ms | 0 |
  | v0.4.0 | allow | 2383 ms | 2444 ms | 0 |
  | MXC 1.x | block | 748 ms | 800 ms | 0 |
  | MXC 1.x | allow | 702 ms | 782 ms | 0 |
  | MXC 1.x | proxy | 1067 ms | 1138 ms | 0 |

  v0.4.0 proxy mode needs the installed broker and was not measured.

## Follow-ups

- Adopt an LPAC option when MXC provides one (microsoft/mxc#1496) and restore
  `process.identity: isolated`.
- Prove or deny private-network ingress on a private-profile LAN. MXC 1.0.1
  requires `ingress.default: allow` with the proxy mapping even when
  `allowedProxyPeer` narrows host loopback, so denying ingress needs an MXC
  change.
- Move the WSLc, Isolation Session and VM-style Windows config builders to the
  1.0.0 contract before they gain a launch path.
