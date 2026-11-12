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
Keychain or other services in this change. A policy that sets
`macos.restrict_system_services: true` gets the allowlist, and may add Mach
service names and exact sysctl names. `axis-native-macos-seatbelt` is the only
backend that enforces the flag. Every other backend reports `Unsupported`,
and the launch fails before user code runs.

The fixed sysctl list follows Codex's `seatbelt_base_policy.sbpl` except
`kern.proc.pid`, `kern.proc.pgrp`, and `net.routetable`, which expose other
processes and the routing table. The Mach list is user lookup, power
management, and preferences. The clipboard service is not included.

## Evidence

On macOS 26, `sandbox-exec` with that Mach list returned an empty clipboard
(`pbpaste` was 8 bytes outside the sandbox and 0 inside) while `/bin/echo` and
`python3 -c 'print(...)'` still ran. `os.cpu_count()` succeeded when the
profile allowed only `hw.ncpu`, which is the same `sysctl-name` filter the
generator emits.
