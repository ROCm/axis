// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exit status of `axis run` and `axis exec`: when AXIS itself fails they exit
//! with 125, otherwise with the sandboxed command's own status.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const AXIS_FAILURE_EXIT_CODE: i32 = 125;

fn axis(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_axis"))
        .arg("--socket")
        .arg(workspace.join("no-axisd.sock"))
        .args(args)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .output()
        .expect("failed to launch axis")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn run_exits_125_when_the_policy_is_invalid() {
    let workspace = tempfile::tempdir().unwrap();
    let policy = workspace.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\nname: invalid\nfilesystem:\n  not_a_field: true\n",
    )
    .unwrap();

    let output = axis(
        workspace.path(),
        &["run", "--policy", policy.to_str().unwrap(), "--", "true"],
    );

    assert_eq!(
        output.status.code(),
        Some(AXIS_FAILURE_EXIT_CODE),
        "stderr:\n{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("not_a_field"),
        "stderr must name the rejected field:\n{}",
        stderr(&output)
    );
}

#[test]
fn exec_exits_125_when_the_daemon_is_unreachable() {
    let workspace = tempfile::tempdir().unwrap();

    let output = axis(
        workspace.path(),
        &["exec", "--sandbox", "missing", "--", "true"],
    );

    assert_eq!(
        output.status.code(),
        Some(AXIS_FAILURE_EXIT_CODE),
        "stderr:\n{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("cannot connect to axisd"),
        "stderr:\n{}",
        stderr(&output)
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::PathBuf;

    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

    fn landlock_abi_supports_axis() -> bool {
        // SAFETY: a NULL attribute with size 0 and the VERSION flag only queries the ABI.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 3 {
            eprintln!(
                "Landlock ABI {abi} cannot enforce the AXIS filesystem contract (test skipped)"
            );
            return false;
        }
        true
    }

    fn native_policy(workspace: &Path, read_write: &[&str]) -> PathBuf {
        let read_only = ["/usr", "/lib", "/lib64", "/bin", "/etc"]
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let read_write = read_write
            .iter()
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let policy = workspace.join("policy.yaml");
        std::fs::write(
            &policy,
            format!(
                "version: 1\n\
                 name: exit-status\n\
                 runtime:\n  provider: axis_native\n\
                 filesystem:\n  read_only: [{read_only}]\n  read_write: [{read_write}]\n\
                 process:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n\
                 network:\n  mode: block\n"
            ),
        )
        .unwrap();
        policy
    }

    #[test]
    fn run_exits_125_when_the_sandbox_cannot_start() {
        if !landlock_abi_supports_axis() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let policy = native_policy(workspace.path(), &["{deploy}"]);

        let output = axis(
            workspace.path(),
            &[
                "run",
                "--policy",
                policy.to_str().unwrap(),
                "--",
                "/bin/true",
            ],
        );

        assert_eq!(
            output.status.code(),
            Some(AXIS_FAILURE_EXIT_CODE),
            "stderr:\n{}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("{deploy}"),
            "stderr must name the path that failed to expand:\n{}",
            stderr(&output)
        );
    }

    #[test]
    fn run_passes_the_command_exit_status_through() {
        if !landlock_abi_supports_axis() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let policy = native_policy(workspace.path(), &[]);

        for code in [0, 1, 7] {
            let output = axis(
                workspace.path(),
                &[
                    "run",
                    "--policy",
                    policy.to_str().unwrap(),
                    "--",
                    "/bin/sh",
                    "-c",
                    &format!("exit {code}"),
                ],
            );

            assert_eq!(
                output.status.code(),
                Some(code),
                "stderr:\n{}",
                stderr(&output)
            );
        }
    }
}
