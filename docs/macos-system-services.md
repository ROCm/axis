# macOS system service allowlist

## Problem

The native macOS Seatbelt profile allows every Mach lookup and every
`sysctl-read`. A sandboxed agent can therefore talk to system services such as
the clipboard, and it can read the whole sysctl tree. Codex, under the same
Apache-2.0 licence, already uses a short allowlist. A single short list is a
poor default for AXIS: Claude Code keeps its login in the Keychain, and other
agents need different services.

## Options

1. Replace `(allow mach*)` and `(allow sysctl-read)` for every macOS policy.
   This closes the hole immediately and breaks agents whose services are not
   on the list.
2. Add an opt-in policy field. The native Seatbelt profile enforces a fixed
   allowlist plus names the policy adds. Backends that cannot enforce the
   field reject the policy.

## Decision

Option 2. The default stays as it is, so existing policies do not lose
Keychain or other services in this change.

The settings live under `process`, which is where AXIS groups what a workload
may do as a process. No other backend has its own policy section, so a
`macos` section would make every future backend that gains support add a
section of its own and force policy files to change.

```yaml
process:
  restrict_system_services: true
  macos_mach_lookup: [com.apple.SecurityServer]
  macos_sysctl_read: [kern.boottime]
```

- `process.restrict_system_services` (default false) asks for the allowlist.
- `process.macos_mach_lookup` and `process.macos_sysctl_read` add exact names.
  They are raw macOS names, prefixed `macos_` because they mean nothing on
  another platform. They require `restrict_system_services: true`.

The lists take raw macOS names rather than purposes such as `keychain` or
`clipboard`. A purpose name needs AXIS to know, and test, everything the
purpose needs on each platform (see the clipboard below). If another backend
gains support, a purpose list can be added next to these fields without
changing them.

### Who enforces it

`axis-native-macos-seatbelt` is the only backend that enforces the flag. Every
other backend refuses the policy before user code runs, in two places:

- The capability planner reports `Unsupported` for
  `process.restrict_system_services` on every backend except the native macOS
  Seatbelt backend.
- `Sandbox::create_inner_with_backend` refuses the policy on any backend that
  is not the native macOS one. Native Linux and vxn never consult the planner
  before launching, so this check is what refuses them.

### What the fixed lists contain

The fixed sysctl list follows Codex's `seatbelt_base_policy.sbpl` except
`kern.proc.pid`, `kern.proc.pgrp`, and `net.routetable`. It adds the prefixes
`sysctl.oidfmt.` and `sysctl.name.`: the `sysctl` tool looks up the format and
name of an OID before it reads one, so without them `sysctl hw.ncpu` fails
even though `hw.ncpu` is allowed. They return the type and name of an OID,
not its value.

The Mach list is the user lookup service and the two preference daemons
(`com.apple.cfprefsd.agent`, `com.apple.cfprefsd.daemon`). Codex's list also
has `com.apple.PowerManagement.control`, which lets a process hold a
power-management assertion and keep the machine awake. Nothing an agent needs
uses it, so it is not here. `user-preference-read` is not allowed either:
the default profile does not allow it, and the restriction must not grant what
the default withheld.

### What the flag does not do

- It does not hide other processes. Leaving `kern.proc.pid` and
  `kern.proc.pgrp` off the sysctl list closes the sysctl route only. The
  profile still allows `process*`, so a workload can list and inspect other
  processes through libproc. This is the same with the flag off.
- It does not stop a policy from adding a name back. `macos_sysctl_read` and
  `macos_mach_lookup` are exact names and can name anything.

### Allowing a service is not always enough

A Mach name in `macos_mach_lookup` lets the workload look that one service up.
The service can need more. `pbpaste` is the known case: with the clipboard
service `com.apple.pasteboard.1` alone it still returns 0 bytes. It also needs
`com.apple.CoreServices.coreservicesd` and `com.apple.lsd.mapdb`:

```yaml
process:
  restrict_system_services: true
  macos_mach_lookup:
    - com.apple.pasteboard.1
    - com.apple.CoreServices.coreservicesd
    - com.apple.lsd.mapdb
```

Allowing `coreservicesd` and `lsd.mapdb` also gives the workload those
services. Keychain and full agent sessions have not been checked. A policy
that needs a service may need to add more than the service's own name.

## Evidence

On macOS 26.6.2 (arm64), with `sandbox-exec` and a profile of the shape the
generator emits (network allowed):

| Command | Default profile | Restricted profile |
|---|---|---|
| `/bin/echo`, `python3 -c 'os.cpu_count()'`, `id`, `whoami`, `git --version` | works | works |
| `getaddrinfo('example.com')`, `curl https://example.com` | works | works |
| `sysctl hw.ncpu`, `sysctl -n hw.memsize` | works | works |
| `sysctl kern.boottime` (not on the list) | prints the value | prints nothing |
| `pbpaste` | 11 bytes | 0 bytes |
| `pbpaste` with `com.apple.pasteboard.1` only | | 0 bytes |
| `pbpaste` with the three names above | | 11 bytes |
| libproc `proc_listpids` (other processes) | 615 pids | 615 pids |

`sysctl hw.ncpu` failed with `Operation not permitted` until the
`sysctl.oidfmt.` and `sysctl.name.` prefixes were added.
