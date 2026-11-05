# Native Backend Retention

AXIS records whether each native process backend provides a current capability,
dependency, or performance advantage that MXC-backed paths have not yet matched.
The decisions below are represented in
`axis_core::process_backend` and use the same backend capability vocabulary as
MXC process backends. Current default-backend status and benchmark evidence
requirements are documented in
[Backend Default Decisions](backend-default-decisions.md).

## Current Decisions

| Platform | Native backend | Decision | Why it remains |
| --- | --- | --- | --- |
| Linux | `axis-native-linux` | Retain | Direct Landlock plus seccomp keep strict native filesystem and network controls, lightweight process startup comparisons, strict proxy integration, and seccomp-notify binary attribution available while the MXC default path is expanded. `runtime.provider: auto` already selects it for every strict-proxy policy and for binary-restricted endpoint rules (see [Backend Default Decisions](backend-default-decisions.md)). |
| macOS | `axis-native-macos-seatbelt` | Retain | Direct Seatbelt profile generation preserves the no-extra-runtime process sandbox and platform-native filesystem/network-deny controls while the MXC Seatbelt path is compared for equivalent profile, lifecycle, and packaging behavior. |
| Windows | `axis-native-windows` | Disabled | Job Object, restricted-token/AppContainer, ACL, proxy, environment, lifecycle, and cleanup controls are implementation assets, but the native launcher rejects before process creation until they are applied and proven as one boundary. |

## Replacement Rule

No native process backend should be removed or made non-selectable merely because
an MXC backend exists for the same platform. Replacement requires:

- matching AXIS policy semantics for filesystem, process, network, credentials,
  inference, resources, lifecycle, cleanup, and audit surfaces;
- equivalent native backend tests and negative security coverage;
- benchmark evidence for startup, teardown, memory, descriptor/process overhead,
  and density on the relevant platform;
- public documentation of any weaker behavior that remains and explicit user
  selection when weaker behavior is accepted.

Until that evidence exists, implemented native backends remain selectable
through the shared planner vocabulary. Disabled adapters and unsupported or
weaker policy/backend combinations must reject before spawning user code.
