// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Seatbelt profile generation from AXIS policy.
//!
//! Generates an Apple Sandbox Profile Language (.sb) file that enforces
//! the AXIS policy using macOS kernel-level sandboxing.

use axis_core::policy::Policy;
use std::path::Path;

/// Generate a Seatbelt profile string from an AXIS policy.
pub fn generate_profile(policy: &Policy, workspace: &Path) -> String {
    let mut sb = String::new();

    sb.push_str("(version 1)\n");
    sb.push_str(&format!(";; AXIS sandbox profile — {}\n\n", policy.name));

    // Default deny everything, then selectively allow.
    sb.push_str("(deny default)\n\n");

    // ── Essential: process execution + Mach IPC ──
    // macOS processes need Mach IPC for basic operation (dyld, libsystem).
    sb.push_str(";; Essential for process execution\n");
    sb.push_str("(allow process*)\n");
    sb.push_str("(allow signal)\n");
    append_system_access(&mut sb, policy);
    sb.push_str("(allow ipc-posix-shm*)\n");
    sb.push_str("(allow file-ioctl)\n"); // TTY ioctls (setraw, tcsetattr) for TUI apps
    sb.push_str("(allow pseudo-tty)\n"); // Allocate/use pseudo-terminals for TUI apps
    sb.push('\n');

    // ── Filesystem: read-only ──
    // Allow reading the entire filesystem — macOS processes need access to
    // dyld shared cache, frameworks, and other system locations that can't
    // be enumerated individually. Write restrictions (below) provide the
    // actual security boundary.
    sb.push_str(";; Filesystem: read entire system (writes restricted below)\n");
    sb.push_str("(allow file-read* (subpath \"/\"))\n");
    sb.push('\n');

    // ── Filesystem: read-write (workspace + policy paths) ──
    sb.push_str(";; Filesystem: read-write\n");
    let ws = workspace.to_string_lossy();
    sb.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{ws}\"))\n"
    ));

    for path in &policy.filesystem.read_write {
        let expanded = expand_path(path, workspace);
        if expanded != ws.as_ref() {
            sb.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{expanded}\"))\n"
            ));
        }
    }

    // Temp directories (macOS uses /private/var/folders for TMPDIR).
    sb.push_str("(allow file-read* file-write* (subpath \"/tmp\"))\n");
    sb.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");
    sb.push_str("(allow file-read* file-write* (subpath \"/private/var/folders\"))\n");

    // TTY/PTY for stdout/stderr.
    sb.push_str("(allow file-read* file-write* (regex #\"^/dev/ttys\"))\n");
    sb.push_str("(allow file-read* file-write* (regex #\"^/dev/fd/\"))\n");
    sb.push_str("(allow file-write* (literal \"/dev/null\"))\n");
    sb.push('\n');

    // ── Filesystem: deny paths (override allows) ──
    if !policy.filesystem.deny.is_empty() {
        sb.push_str(";; Filesystem: explicit deny\n");
        for path in &policy.filesystem.deny {
            let expanded = expand_path(path, workspace);
            sb.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{expanded}\"))\n"
            ));
        }
        sb.push('\n');
    }

    // The whole filesystem is readable above; the axisd token must not be.
    // Sandbox::create refuses launches with no token dir or an unsafe path.
    if let Some(token_dir) =
        axis_core::daemon_auth::token_dir().filter(|dir| is_profile_safe_path(dir))
    {
        sb.push_str(";; axisd client token\n");
        sb.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{}\"))\n\n",
            token_dir.display()
        ));
    }

    // ── Network ──
    sb.push_str(";; Network\n");
    match policy.network.mode {
        axis_core::policy::NetworkMode::Block => {
            sb.push_str("(deny network*)\n");
        }
        axis_core::policy::NetworkMode::Allow => {
            sb.push_str("(allow network*)\n");
        }
        axis_core::policy::NetworkMode::Proxy => {
            // Allow outbound to localhost only (AXIS proxy runs on loopback).
            // The (deny default) at the top blocks all non-localhost connections.
            // All external traffic goes through HTTP_PROXY → AXIS proxy → OPA eval.
            sb.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
            sb.push_str("(allow network* (local ip \"localhost:*\"))\n");
        }
    }
    sb.push('\n');

    // ── Security: deny dangerous operations ──
    sb.push_str(";; Security\n");
    sb.push_str("(deny file-write* (subpath \"/System\"))\n");
    sb.push_str("(deny file-write* (subpath \"/usr\"))\n");
    sb.push_str("(deny file-write* (subpath \"/Library\"))\n");

    sb
}

/// Whether `path` can be embedded in a quoted Seatbelt string as-is.
pub fn is_profile_safe_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|s| !s.chars().any(|c| c == '"' || c == '\\' || c.is_control()))
}

/// Sysctl names a restricted profile may read.
///
/// The list follows Codex's Apache-2.0 `seatbelt_base_policy.sbpl`, without
/// `kern.proc.pid`, `kern.proc.pgrp`, and `net.routetable`. Those expose other
/// processes and the routing table.
const SYSCTL_READ_NAMES: &[&str] = &[
    "hw.activecpu",
    "hw.busfrequency_compat",
    "hw.byteorder",
    "hw.cacheconfig",
    "hw.cachelinesize_compat",
    "hw.cpufamily",
    "hw.cpufrequency",
    "hw.cpufrequency_compat",
    "hw.cputype",
    "hw.l1dcachesize_compat",
    "hw.l1icachesize_compat",
    "hw.l2cachesize_compat",
    "hw.l3cachesize_compat",
    "hw.logicalcpu",
    "hw.logicalcpu_max",
    "hw.machine",
    "hw.memsize",
    "hw.model",
    "hw.ncpu",
    "hw.nperflevels",
    "hw.packages",
    "hw.pagesize",
    "hw.pagesize_compat",
    "hw.physicalcpu",
    "hw.physicalcpu_max",
    "hw.tbfrequency_compat",
    "hw.vectorunit",
    "kern.argmax",
    "kern.hostname",
    "kern.maxfilesperproc",
    "kern.maxproc",
    "kern.osproductversion",
    "kern.osrelease",
    "kern.ostype",
    "kern.osvariant_status",
    "kern.osversion",
    "kern.secure_kernel",
    "kern.sysv.semmns",
    "kern.usrstack64",
    "kern.version",
    "machdep.cpu.brand_string",
    "sysctl.proc_cputype",
    "vm.loadavg",
];

const SYSCTL_READ_PREFIXES: &[&str] = &["hw.optional.arm.", "hw.optional.armv8_", "hw.perflevel"];

/// User lookup, power management, and preferences. The clipboard service is
/// intentionally absent; a policy adds it with `macos.mach_lookup` if needed.
const MACH_LOOKUP_NAMES: &[&str] = &[
    "com.apple.PowerManagement.control",
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
    "com.apple.system.opendirectoryd.libinfo",
];

fn append_system_access(sb: &mut String, policy: &Policy) {
    if !policy.macos.restrict_system_services {
        sb.push_str("(allow sysctl-read)\n");
        sb.push_str("(allow mach*)\n"); // Mach IPC required for dyld, libsystem
        return;
    }

    sb.push_str(";; Restricted sysctl and Mach allowlist\n");
    sb.push_str("(allow sysctl-read\n");
    for name in SYSCTL_READ_NAMES {
        sb.push_str(&format!("    (sysctl-name \"{name}\")\n"));
    }
    for prefix in SYSCTL_READ_PREFIXES {
        sb.push_str(&format!("    (sysctl-name-prefix \"{prefix}\")\n"));
    }
    for name in &policy.macos.sysctl_read {
        if !SYSCTL_READ_NAMES.contains(&name.as_str()) {
            sb.push_str(&format!("    (sysctl-name \"{name}\")\n"));
        }
    }
    sb.push_str(")\n");

    sb.push_str("(allow mach-lookup\n");
    for name in MACH_LOOKUP_NAMES {
        sb.push_str(&format!("    (global-name \"{name}\")\n"));
    }
    sb.push_str("    (local-name \"com.apple.cfprefsd.agent\")\n");
    for name in &policy.macos.mach_lookup {
        if !MACH_LOOKUP_NAMES.contains(&name.as_str()) {
            sb.push_str(&format!("    (global-name \"{name}\")\n"));
        }
    }
    sb.push_str(")\n");
    sb.push_str("(allow user-preference-read)\n");
}

fn expand_path(path: &str, workspace: &Path) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".into());
    path.replace("{workspace}", &workspace.to_string_lossy())
        .replace("{tmpdir}", "/tmp")
        .replace("~", &home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::Policy;

    #[test]
    fn generates_valid_profile() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"));
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("/tmp/workspace"));
        assert!(profile.contains("(allow process*)"));
        assert!(profile.contains("(allow mach*)"));
    }

    #[test]
    fn restricted_system_services_replace_blanket_mach_and_sysctl() {
        let yaml = r#"
version: 1
name: test
macos:
  restrict_system_services: true
  mach_lookup:
    - com.apple.SecurityServer
  sysctl_read:
    - user.cs_path
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"));
        assert!(!profile.contains("(allow mach*)"));
        assert!(!profile.contains("(allow sysctl-read)\n"));
        assert!(profile.contains("(sysctl-name \"hw.ncpu\")"));
        assert!(profile.contains("(sysctl-name \"kern.osproductversion\")"));
        assert!(profile.contains("(sysctl-name-prefix \"hw.optional.arm.\")"));
        assert!(profile.contains("(sysctl-name \"user.cs_path\")"));
        assert!(profile.contains("(global-name \"com.apple.system.opendirectoryd.libinfo\")"));
        assert!(profile.contains("(global-name \"com.apple.cfprefsd.agent\")"));
        assert!(profile.contains("(local-name \"com.apple.cfprefsd.agent\")"));
        assert!(profile.contains("(allow user-preference-read)"));
        assert!(profile.contains("(global-name \"com.apple.SecurityServer\")"));
        assert!(!profile.contains("com.apple.pasteboard"));
        assert!(!profile.contains("kern.proc.pid"));
        assert!(!profile.contains("net.routetable"));
    }

    #[test]
    fn proxy_mode_allows_loopback() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: proxy\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"));
        assert!(profile.contains("localhost"));
    }

    #[test]
    fn block_mode_denies_network() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: block\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn daemon_token_dir_is_denied_even_inside_grants() {
        let token_dir = axis_core::daemon_auth::token_dir().unwrap();
        let yaml = format!(
            "version: 1\nname: test\nfilesystem:\n  read_write: [\"{}\"]\n",
            token_dir.parent().unwrap().display()
        );
        let policy = Policy::from_yaml(&yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"));
        let deny = format!(
            "(deny file-read* file-write* (subpath \"{}\"))",
            token_dir.display()
        );
        let allow = format!(
            "(allow file-read* file-write* (subpath \"{}\"))",
            token_dir.parent().unwrap().display()
        );
        assert!(
            profile.find(&deny).unwrap() > profile.find(&allow).unwrap(),
            "the token deny must come after every allow"
        );
    }

    #[test]
    fn unquotable_paths_are_not_profile_safe() {
        assert!(is_profile_safe_path(Path::new("/Users/me/.axis/run")));
        for unsafe_path in ["/Users/a\"b/.axis/run", "/Users/a\\b", "/Users/a\nb", "rel"] {
            assert!(
                !is_profile_safe_path(Path::new(unsafe_path)),
                "{unsafe_path:?}"
            );
        }
    }
}
