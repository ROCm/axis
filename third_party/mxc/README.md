# Pinned MXC

AXIS builds the MXC executors from pinned upstream commits without local
patches:

- Linux `lxc-exec` is built from MXC v1.0.0
  (`7bf210247986cb73b1b314df60c2f1109c479c0b`, `MXC_REF` in the workflows).
- Windows `wxc-exec.exe` is built from MXC v1.0.1
  (`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`, `MXC_WINDOWS_REF` in the
  workflows and `scripts/setup_windows_mxc.ps1`).

AXIS uses MXC BaseContainer only. The generated configuration leaves
`fallback.allowDaclMutation=false`, so an unavailable BaseContainer fails closed
instead of selecting an AppContainer/DACL tier.

MXC 1.x BaseContainer has three limits that AXIS accepts and reports rather
than patches; [Windows MXC 1.x Backend](../../docs/windows-mxc-1.md) has the
evidence:

- There is no least-privilege (LPAC) token option
  (<https://github.com/microsoft/mxc/issues/1496>). The child keeps the
  caller's user SID inside the container, so system locations and the user's
  registry hive stay readable. `process.identity: isolated` is rejected.
- `runtimeConfig.networkProxy` requires `network.ingress.default: allow`, which
  adds the `privateNetworkClientServer` capability. Egress is limited to the
  AXIS proxy, but inbound connections from private-network peers depend on the
  host firewall.
- The proxy mapping's WFP filters do not report individual blocked
  connections, so direct bypass attempts are denied without an AXIS audit
  record.

Process-count, memory and CPU limits are applied by AXIS: the executor starts
suspended inside an AXIS Job Object and is resumed only after the assignment
succeeds, so the whole executor tree is accounted for from its first
instruction.

The `Experimental_CreateProcessInSandbox` API rejects
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` with `ERROR_INVALID_HANDLE` on Windows
build 26300. AXIS does not downgrade to AppContainer/DACL solely to provide
ConPTY. Enable the BaseContainer interactive path only after a runtime
capability probe proves the OS accepts pseudoconsole startup handles.
