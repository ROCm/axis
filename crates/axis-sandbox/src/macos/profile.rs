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
    // Signals and process-info stay inside this sandbox. An unrestricted
    // allow would let the workload signal or inspect the caller's other
    // processes. process-exec and process-fork stay open so children run.
    sb.push_str(";; Essential for process execution\n");
    sb.push_str("(allow process-exec)\n");
    sb.push_str("(allow process-fork)\n");
    sb.push_str("(allow process-info* (target same-sandbox))\n");
    sb.push_str("(allow signal (target same-sandbox))\n");
    sb.push_str("(allow sysctl-read)\n");
    sb.push_str("(allow mach*)\n"); // Mach IPC required for dyld, libsystem
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
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow signal (target same-sandbox))"));
        assert!(profile.contains("(allow mach*)"));
    }

    #[test]
    fn signals_and_process_info_stay_in_the_sandbox() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"));
        assert!(profile.contains("(allow process-exec)\n"));
        assert!(profile.contains("(allow process-fork)\n"));
        assert!(profile.contains("(allow process-info* (target same-sandbox))\n"));
        assert!(profile.contains("(allow signal (target same-sandbox))\n"));
        assert!(!profile.contains("(allow process*)"));
        assert!(!profile.contains("(allow signal)\n"));
        assert!(!profile.contains("(allow process-info*)\n"));
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
