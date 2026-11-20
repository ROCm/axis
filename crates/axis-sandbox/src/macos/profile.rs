// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Seatbelt profile generation from AXIS policy.
//!
//! Generates an Apple Sandbox Profile Language (.sb) file that enforces
//! the AXIS policy using macOS kernel-level sandboxing.

use axis_core::policy::Policy;
use std::path::Path;

/// Generate a Seatbelt profile string from an AXIS policy.
///
/// `proxy_port` is the AXIS proxy the workload must be able to reach. Zero
/// means no proxy is listening, so proxy mode opens no proxy port.
pub fn generate_profile(policy: &Policy, workspace: &Path, proxy_port: u16) -> String {
    let mut sb = String::new();

    sb.push_str("(version 1)\n");
    sb.push_str(&format!(";; AXIS sandbox profile — {}\n\n", policy.name));

    // Default deny everything, then selectively allow.
    sb.push_str("(deny default)\n\n");

    // ── Essential: process execution + Mach IPC ──
    // macOS processes need Mach IPC for basic operation (dyld, libsystem).
    // Signals stay inside this sandbox. An unrestricted signal allow would
    // let the workload signal the caller's other processes. process-exec
    // and process-fork stay open so children run.
    sb.push_str(";; Essential for process execution\n");
    sb.push_str("(allow process-exec)\n");
    sb.push_str("(allow process-fork)\n");
    sb.push_str("(allow process-info* (target same-sandbox))\n");
    sb.push_str("(allow signal (target same-sandbox))\n");
    append_system_access(&mut sb, policy);
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
            // Seatbelt shares host loopback, so only the AXIS proxy port is
            // opened. Loopback endpoints in network.policies are reachable
            // only through the proxy, as on backends with a private loopback.
            // Binding stays denied: a listener here would be visible to host
            // clients.
            if proxy_port > 0 {
                sb.push_str(";; Loopback: AXIS proxy port only\n");
                sb.push_str(&format!(
                    "(allow network-outbound (remote ip \"localhost:{proxy_port}\"))\n"
                ));
            }
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
/// `kern.proc.pid`, `kern.proc.pgrp`, and `net.routetable`. Leaving those out
/// only closes the sysctl route to process and routing data. It does not hide
/// other processes: the profile's `(allow process*)` still lets a workload
/// list and inspect them through libproc.
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

/// `sysctl.oidfmt.` and `sysctl.name.` are the metadata lookups the `sysctl`
/// tool makes for every name it reads; without them `sysctl hw.ncpu` fails
/// even though `hw.ncpu` is allowed. They return the type and name of an OID,
/// never its value, so reading a value still needs an exact name above.
const SYSCTL_READ_PREFIXES: &[&str] = &[
    "hw.optional.arm.",
    "hw.optional.armv8_",
    "hw.perflevel",
    "sysctl.oidfmt.",
    "sysctl.name.",
];

/// User lookup and the preference daemons. The clipboard service is
/// intentionally absent; a policy adds it with `process.macos_mach_lookup` if
/// needed (see `docs/macos-system-services.md` for what `pbpaste` needs).
const MACH_LOOKUP_NAMES: &[&str] = &[
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
    "com.apple.system.opendirectoryd.libinfo",
];

fn append_system_access(sb: &mut String, policy: &Policy) {
    if !policy.process.restrict_system_services {
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
    for name in &policy.process.macos_sysctl_read {
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
    for name in &policy.process.macos_mach_lookup {
        if !MACH_LOOKUP_NAMES.contains(&name.as_str()) {
            sb.push_str(&format!("    (global-name \"{name}\")\n"));
        }
    }
    sb.push_str(")\n");
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn generates_valid_profile() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"), 0);
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("/tmp/workspace"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow signal (target same-sandbox))"));
        assert!(profile.contains("(allow mach*)"));
    }

    #[test]
    fn signal_and_process_info_allows_target_same_sandbox() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"), 0);
        assert!(profile.contains("(allow process-exec)\n"));
        assert!(profile.contains("(allow process-fork)\n"));
        assert!(!profile.contains("(allow process*)"));

        // Every allow of signal or process-info must name the same sandbox.
        let mut saw_signal = false;
        let mut saw_process_info = false;
        for line in profile.lines() {
            let mentions_signal = line.contains("signal");
            let mentions_process_info = line.contains("process-info");
            if !line.contains("(allow") || !(mentions_signal || mentions_process_info) {
                continue;
            }
            assert!(
                line.contains("(target same-sandbox)"),
                "allow must target same-sandbox: {line}"
            );
            saw_signal |= mentions_signal;
            saw_process_info |= mentions_process_info;
        }
        assert!(saw_signal, "missing signal allow:\n{profile}");
        assert!(saw_process_info, "missing process-info allow:\n{profile}");
    }

    /// Seatbelt behavior, not the profile text. This module is macOS-only, so
    /// `cargo test` on the macOS CI runner executes it.
    #[test]
    fn sandbox_exec_confines_signals_and_runs_shell_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("profile.sb");
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        std::fs::write(&profile_path, generate_profile(&policy, dir.path(), 0)).unwrap();

        let outside = KillOnDrop(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep outside the sandbox"),
        );
        let outside_pid = outside.pid().to_string();
        assert!(
            std::process::Command::new("kill")
                .args(["-0", &outside_pid])
                .status()
                .unwrap()
                .success(),
            "sleep outside the sandbox did not start"
        );

        let kill_outside = run_sandboxed(&profile_path, &["kill", "-0", &outside_pid]);
        let kill_outside_stderr = String::from_utf8_lossy(&kill_outside.stderr);
        assert!(
            !kill_outside.status.success(),
            "kill -0 of pid {outside_pid} from inside the sandbox must fail\nstderr: {kill_outside_stderr}"
        );
        assert!(
            kill_outside_stderr.contains("Operation not permitted"),
            "expected Seatbelt to refuse the signal, stderr: {kill_outside_stderr}"
        );
        assert!(
            std::process::Command::new("kill")
                .args(["-0", &outside_pid])
                .status()
                .unwrap()
                .success(),
            "the outside sleep must still be running after the refused signal"
        );

        let kill_child = run_sandboxed(&profile_path, &["sh", "-c", "sleep 5 & kill $!"]);
        assert!(
            kill_child.status.success(),
            "signaling a same-sandbox child must succeed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&kill_child.stdout),
            String::from_utf8_lossy(&kill_child.stderr)
        );

        // Exec the script so the kernel follows `#!/bin/sh`.
        let script = dir.path().join("hello.sh");
        std::fs::write(&script, "#!/bin/sh\necho shebang-ok\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script_arg = script.to_str().expect("script path is utf-8");
        let ran_script = run_sandboxed(&profile_path, &[script_arg]);
        assert!(
            ran_script.status.success(),
            "#!/bin/sh script must run inside the sandbox\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&ran_script.stdout),
            String::from_utf8_lossy(&ran_script.stderr)
        );
        assert!(
            String::from_utf8_lossy(&ran_script.stdout).contains("shebang-ok"),
            "script stdout: {}",
            String::from_utf8_lossy(&ran_script.stdout)
        );
    }

    struct KillOnDrop(std::process::Child);

    impl KillOnDrop {
        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn run_sandboxed(profile: &Path, args: &[&str]) -> std::process::Output {
        std::process::Command::new("sandbox-exec")
            .arg("-f")
            .arg(profile)
            .arg("--")
            .args(args)
            .output()
            .expect("spawn sandbox-exec")
    }

    #[test]
    fn restricted_system_services_replace_blanket_mach_and_sysctl() {
        let yaml = r#"
version: 1
name: test
process:
  restrict_system_services: true
  macos_mach_lookup:
    - com.apple.SecurityServer
  macos_sysctl_read:
    - user.cs_path
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"), 0);
        assert!(!profile.contains("(allow mach*)"));
        assert!(!profile.contains("(allow sysctl-read)\n"));
        assert!(profile.contains("(sysctl-name \"hw.ncpu\")"));
        assert!(profile.contains("(sysctl-name \"kern.osproductversion\")"));
        assert!(profile.contains("(sysctl-name-prefix \"hw.optional.arm.\")"));
        assert!(profile.contains("(sysctl-name \"user.cs_path\")"));
        assert!(profile.contains("(global-name \"com.apple.system.opendirectoryd.libinfo\")"));
        assert!(profile.contains("(global-name \"com.apple.cfprefsd.agent\")"));
        assert!(profile.contains("(local-name \"com.apple.cfprefsd.agent\")"));
        assert!(profile.contains("(global-name \"com.apple.SecurityServer\")"));
        assert!(!profile.contains("com.apple.pasteboard"));
        assert!(!profile.contains("kern.proc.pid"));
        assert!(!profile.contains("net.routetable"));
    }

    #[test]
    fn restricted_system_services_grant_nothing_the_default_profile_denied() {
        let yaml = "version: 1\nname: test\nprocess:\n  restrict_system_services: true\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"), 0);
        // The default profile never allowed these; the restriction must not
        // add them.
        assert!(!profile.contains("user-preference-read"));
        assert!(!profile.contains("PowerManagement"));
    }

    #[test]
    fn restricted_system_services_allow_sysctl_tool_metadata_lookups() {
        let yaml = "version: 1\nname: test\nprocess:\n  restrict_system_services: true\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/workspace"), 0);
        assert!(profile.contains("(sysctl-name-prefix \"sysctl.oidfmt.\")"));
        assert!(profile.contains("(sysctl-name-prefix \"sysctl.name.\")"));
        // Metadata lookups must not widen into value reads or enumeration.
        assert!(!profile.contains("(sysctl-name-prefix \"sysctl.next"));
        assert!(!profile.contains("(sysctl-name-prefix \"kern."));
        assert!(!profile.contains("(sysctl-name-prefix \"hw.\")"));
    }

    #[test]
    fn proxy_mode_opens_only_the_proxy_port() {
        let yaml = r#"
version: 1
name: test
network:
  mode: proxy
  policies:
    - name: bridge
      endpoints:
        - host: 127.0.0.1
          port: 8765
        - host: "::1"
          port: 8765
        - host: localhost
          port: 9
    - name: anthropic
      endpoints:
        - host: api.anthropic.com
          port: 443
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"), 3128);
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:3128\"))\n"));
        assert_eq!(profile.matches("(allow network").count(), 1);
        assert!(!profile.contains("localhost:*"));
        assert!(!profile.contains("localhost:8765"));
        assert!(!profile.contains("localhost:9"));
        assert!(!profile.contains("localhost:443"));
        assert!(!profile.contains("api.anthropic.com"));
        assert!(!profile.contains("network-bind"));
        assert!(!profile.contains("network-inbound"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn gated_seatbelt_proxy_mode_reaches_only_the_proxy_port() {
        const REQUIRE_ENV: &str = "AXIS_REQUIRE_SEATBELT_TESTS";
        let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
        let applies = sandbox_exec.exists()
            && std::process::Command::new(sandbox_exec)
                .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
                .status()
                .is_ok_and(|status| status.success());
        if !applies {
            assert!(
                std::env::var_os(REQUIRE_ENV).is_none(),
                "sandbox-exec cannot apply a profile but {REQUIRE_ENV} is set"
            );
            eprintln!("SKIP: sandbox-exec cannot apply a profile (missing or nested sandbox)");
            return;
        }

        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let helper = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let helper_port = helper.local_addr().unwrap().port();
        let yaml = format!(
            "version: 1\nname: test\nnetwork:\n  mode: proxy\n  policies:\n    - name: helper\n      endpoints:\n        - host: 127.0.0.1\n          port: {helper_port}\n"
        );
        let policy = Policy::from_yaml(&yaml).unwrap();
        let workspace = std::env::temp_dir().join(format!("axis-seatbelt-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let profile_path = workspace.join(".axis-sandbox.sb");
        std::fs::write(
            &profile_path,
            generate_profile(&policy, &workspace, proxy_port),
        )
        .unwrap();

        let run = |args: &[&str]| {
            std::process::Command::new(sandbox_exec)
                .arg("-f")
                .arg(&profile_path)
                .args(args)
                .output()
                .unwrap()
        };
        let connect = |port: u16| {
            let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
            run(&["/bin/bash", "-c", &script])
        };

        let reached = connect(proxy_port);
        let direct = connect(helper_port);
        let bind = run(&[
            "/usr/bin/perl",
            "-MIO::Socket::INET",
            "-e",
            "IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1) or die \"bind: $!\\n\"",
        ]);
        let _ = std::fs::remove_dir_all(&workspace);

        assert!(
            reached.status.success(),
            "proxy port unreachable: {}",
            String::from_utf8_lossy(&reached.stderr)
        );
        let direct_err = String::from_utf8_lossy(&direct.stderr);
        assert!(
            !direct.status.success() && direct_err.contains("Operation not permitted"),
            "loopback endpoint was reachable without the proxy: {direct_err}"
        );
        let bind_err = String::from_utf8_lossy(&bind.stderr);
        assert!(
            !bind.status.success() && bind_err.contains("Operation not permitted"),
            "loopback bind was allowed: {bind_err}"
        );
    }

    #[test]
    fn proxy_mode_without_a_port_opens_no_loopback() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: proxy\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"), 0);
        assert!(!profile.contains("localhost"));
        assert!(!profile.contains("(allow network"));
    }

    #[test]
    fn block_mode_denies_network() {
        let yaml = "version: 1\nname: test\nnetwork:\n  mode: block\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        let profile = generate_profile(&policy, Path::new("/tmp/ws"), 0);
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
        let profile = generate_profile(&policy, Path::new("/tmp/ws"), 0);
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
