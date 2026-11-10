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
    sb.push_str("(allow sysctl-read)\n");
    sb.push_str("(allow mach*)\n"); // Mach IPC required for dyld, libsystem
    sb.push_str("(allow ipc-posix-shm*)\n");
    sb.push_str("(allow file-ioctl)\n"); // TTY ioctls (setraw, tcsetattr) for TUI apps
    sb.push_str("(allow pseudo-tty)\n"); // Allocate/use pseudo-terminals for TUI apps
    sb.push('\n');

    // ── Filesystem: read-only ──
    // Path lookup needs metadata for ancestors of permitted files.
    sb.push_str("(allow file-read-metadata)\n");
    sb.push_str(";; Filesystem: policy read-only paths\n");
    for path in &policy.filesystem.read_only {
        let expanded = expand_path(path, workspace);
        sb.push_str(&format!("(allow file-read* (subpath \"{expanded}\"))\n"));
    }
    // dyld caches and standard device files are needed independently of agent state.
    for path in [
        "/private/var/db/dyld",
        "/private/preboot/Cryptexes/OS/System",
    ] {
        sb.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }
    for path in ["/dev/null", "/dev/random", "/dev/urandom"] {
        sb.push_str(&format!("(allow file-read* (literal \"{path}\"))\n"));
    }
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

    // Keep the axisd token denied even when a policy grants its parent.
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
        assert!(profile.contains("(allow process*)"));
        assert!(profile.contains("(allow mach*)"));
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

    #[test]
    fn filesystem_reads_are_limited_to_policy_and_runtime_paths() {
        let policy = Policy::from_yaml(
            "version: 1\nname: test\nfilesystem:\n  read_only: [/System, /usr]\n  read_write: [/agent/xdg-config]\n",
        )
        .unwrap();
        let profile = generate_profile(&policy, Path::new("/workspace"));
        assert!(profile.contains("(allow file-read* (subpath \"/System\"))"));
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
        assert!(profile.contains("(allow file-read* file-write* (subpath \"/agent/xdg-config\"))"));
        assert!(!profile.contains("(allow file-read* (subpath \"/\"))"));
        assert!(!profile.contains("(subpath \"/agent\")"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_config_access_does_not_expose_host_or_legacy_credentials() {
        // Keep credential fixtures outside the platform's shared temporary paths.
        let home = tempfile::tempdir_in("/Users/Shared").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        crate::test_support::with_home(home.path(), || {
            let config = home.path().join(".axis/agents/test/xdg-config");
            std::fs::create_dir_all(&config).unwrap();
            let secrets = [
                home.path().join(".config/gh/hosts.yml"),
                home.path().join(".axis/agents/test/config/credential"),
                home.path().join(".axis/agents/other/xdg-config/credential"),
            ];
            for secret in &secrets {
                std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
                std::fs::write(secret, "fake-token").unwrap();
            }
            let mut policy = Policy::from_yaml("version: 1\nname: test\nfilesystem:\n  read_only: [/System, /usr, /bin, /Library]\n  deny: ['~/.config']\n").unwrap();
            policy
                .filesystem
                .read_write
                .push(config.to_string_lossy().into_owned());
            let profile = generate_profile(&policy, workspace.path());
            let output = std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "/bin/sh", "-c"])
                .arg("set -eu; printf 'isolated\n' > \"$XDG_CONFIG_HOME/settings\"; read -r value < \"$XDG_CONFIG_HOME/settings\"; [ \"$value\" = isolated ]; for secret do if ( : < \"$secret\" ) 2>/dev/null; then exit 40; fi; done")
                .arg("config-probe")
                .args(&secrets)
                .env_clear()
                .env("HOME", home.path())
                .env("XDG_CONFIG_HOME", &config)
                .current_dir(workspace.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "config isolation probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
    }
}
