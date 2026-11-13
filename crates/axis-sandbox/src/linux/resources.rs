// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux process resource controls.

use axis_core::policy::ProcessPolicy;
use axis_core::types::SandboxId;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CPU_PERIOD_US: u64 = 100_000;
const CGROUP_DRAIN_TIMEOUT_MS: u64 = 500;
const CGROUP_DRAIN_INTERVAL_MS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupHandle {
    path: PathBuf,
}

impl CgroupHandle {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn add_process(&self, pid: u32) -> Result<(), String> {
        write_file(self.path.join("cgroup.procs"), pid.to_string())
    }

    pub(crate) fn open_procs_fd(&self) -> Result<i32, String> {
        open_writeonly_cloexec(&self.path.join("cgroup.procs"))
    }

    pub(crate) fn cleanup(self) -> Result<(), String> {
        kill_cgroup_processes(&self.path)?;
        drain_cgroup_processes(&self.path)?;
        remove_cgroup_dir(&self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupLimits {
    memory_max: Option<u64>,
    pids_max: Option<u32>,
    cpu_max: Option<CpuMax>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuMax {
    quota_us: u64,
    period_us: u64,
}

pub(crate) fn create_cgroup(
    sandbox_id: SandboxId,
    policy: &ProcessPolicy,
) -> Result<CgroupHandle, String> {
    let root = find_writable_cgroup_v2_delegation()?;
    create_cgroup_at(&root, sandbox_id, policy)
}

pub(crate) fn probe_cgroup_v2_delegation(root: &Path) -> Result<(), String> {
    enable_child_controllers(root)?;
    let probe_path = root.join(format!("axis-probe-{}", SandboxId::new()));
    std::fs::create_dir(&probe_path)
        .map_err(|e| format!("create cgroup probe {}: {e}", probe_path.display()))?;

    let probe_result =
        required_cgroup_files_present(&probe_path).and_then(|_| probe_cgroup_writes(&probe_path));
    let cleanup_result = remove_cgroup_dir(&probe_path);
    probe_result?;
    cleanup_result
}

pub(crate) fn find_writable_cgroup_v2_delegation() -> Result<PathBuf, String> {
    let current = current_cgroup_v2_path()?;
    let mut errors = Vec::new();
    for candidate in candidate_cgroup_roots(&current) {
        if !candidate.join("cgroup.controllers").exists() {
            continue;
        }
        match probe_cgroup_v2_delegation(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) => errors.push(format!("{}: {err}", candidate.display())),
        }
    }

    Err(format!(
        "no writable cgroup v2 delegation found from current cgroup '{}': {}",
        current.display(),
        errors.join("; ")
    ))
}

fn current_cgroup_v2_path() -> Result<PathBuf, String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
    cgroup_v2_path_from_proc_self_cgroup(&cgroup)
}

fn cgroup_v2_path_from_proc_self_cgroup(cgroup: &str) -> Result<PathBuf, String> {
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        if hierarchy == "0" && controllers.is_empty() {
            return cgroup_path_from_kernel_path(path);
        }
    }

    Err("no cgroup v2 entry found in /proc/self/cgroup".into())
}

fn cgroup_path_from_kernel_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(format!(
            "cgroup v2 path '{}' is not absolute",
            path.display()
        ));
    }

    let mut full = PathBuf::from(CGROUP_ROOT);
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => full.push(part),
            _ => {
                return Err(format!(
                    "cgroup v2 path '{}' contains unsupported component",
                    path.display()
                ));
            }
        }
    }
    Ok(full)
}

fn candidate_cgroup_roots(current: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut next = Some(current);
    while let Some(path) = next {
        candidates.push(path.to_path_buf());
        if path == Path::new(CGROUP_ROOT) {
            break;
        }
        next = path.parent();
    }
    candidates
}

fn enable_child_controllers(root: &Path) -> Result<(), String> {
    let controllers_path = root.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path)
        .map_err(|e| format!("read {}: {e}", controllers_path.display()))?;
    let requested = ["cpu", "memory", "pids"]
        .into_iter()
        .filter(|controller| {
            controllers
                .split_whitespace()
                .any(|value| value == *controller)
        })
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Err(format!(
            "cgroup {} does not expose cpu, memory, or pids controllers",
            root.display()
        ));
    }

    write_file(root.join("cgroup.subtree_control"), requested.join(" "))
}

pub(crate) fn create_cgroup_at(
    root: &Path,
    sandbox_id: SandboxId,
    policy: &ProcessPolicy,
) -> Result<CgroupHandle, String> {
    let path = root.join(format!("axis-{sandbox_id}"));
    std::fs::create_dir(&path).map_err(|e| format!("create cgroup {}: {e}", path.display()))?;

    let limits = match cgroup_limits(policy) {
        Ok(limits) => limits,
        Err(e) => {
            let _ = remove_cgroup_dir(&path);
            return Err(e);
        }
    };
    if let Err(e) = write_cgroup_limits(&path, &limits) {
        let _ = remove_cgroup_dir(&path);
        return Err(e);
    }

    Ok(CgroupHandle { path })
}

fn required_cgroup_files_present(path: &Path) -> Result<(), String> {
    for file in ["cgroup.procs", "memory.max", "pids.max", "cpu.max"] {
        let file_path = path.join(file);
        if !file_path.exists() {
            return Err(format!(
                "cgroup controller file {} is unavailable",
                file_path.display()
            ));
        }
    }
    Ok(())
}

fn probe_cgroup_writes(path: &Path) -> Result<(), String> {
    write_file(path.join("memory.max"), "max".to_string())?;
    write_file(path.join("pids.max"), "max".to_string())?;
    write_file(
        path.join("cpu.max"),
        format!("{CPU_PERIOD_US} {CPU_PERIOD_US}"),
    )?;
    let procs_fd = open_writeonly_cloexec(&path.join("cgroup.procs"))?;
    unsafe {
        libc::close(procs_fd);
    }
    Ok(())
}

fn cgroup_limits(policy: &ProcessPolicy) -> Result<CgroupLimits, String> {
    Ok(CgroupLimits {
        memory_max: if policy.max_memory_mb > 0 {
            Some(memory_limit_bytes(policy.max_memory_mb)?)
        } else {
            None
        },
        pids_max: (policy.effective_max_processes() > 0).then(|| policy.effective_max_processes()),
        cpu_max: (policy.cpu_rate_percent > 0).then(|| CpuMax {
            quota_us: CPU_PERIOD_US * u64::from(policy.cpu_rate_percent) / 100,
            period_us: CPU_PERIOD_US,
        }),
    })
}

fn memory_limit_bytes(max_memory_mb: u64) -> Result<u64, String> {
    max_memory_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| format!("memory limit {max_memory_mb} MiB overflows byte conversion"))
}

fn write_cgroup_limits(path: &Path, limits: &CgroupLimits) -> Result<(), String> {
    if let Some(memory_max) = limits.memory_max {
        write_file(path.join("memory.max"), memory_max.to_string())?;
    }
    if let Some(pids_max) = limits.pids_max {
        write_file(path.join("pids.max"), pids_max.to_string())?;
    }
    if let Some(cpu_max) = limits.cpu_max {
        write_file(
            path.join("cpu.max"),
            format!("{} {}", cpu_max.quota_us, cpu_max.period_us),
        )?;
    }
    Ok(())
}

fn write_file(path: impl AsRef<Path>, value: String) -> Result<(), String> {
    let path = path.as_ref();
    std::fs::write(path, value).map_err(|e| format!("write {}: {e}", path.display()))
}

fn remove_cgroup_dir(path: &Path) -> Result<(), String> {
    #[cfg(test)]
    if !path.starts_with(CGROUP_ROOT) {
        // Unit tests model cgroup controller files as regular files under a
        // temp root; real cgroup v2 controller files are removed by rmdir.
        for file in [
            "cgroup.procs",
            "cgroup.kill",
            "memory.max",
            "pids.max",
            "cpu.max",
        ] {
            let file_path = path.join(file);
            match std::fs::remove_file(&file_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("remove {}: {e}", file_path.display())),
            }
        }
    }

    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove cgroup {}: {e}", path.display())),
    }
}

fn kill_cgroup_processes(path: &Path) -> Result<(), String> {
    let kill_path = path.join("cgroup.kill");
    if !kill_path.exists() {
        return Ok(());
    }
    write_file(kill_path, "1".to_string())
}

fn drain_cgroup_processes(path: &Path) -> Result<(), String> {
    let procs_path = path.join("cgroup.procs");
    if !procs_path.exists() {
        return Ok(());
    }

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(CGROUP_DRAIN_TIMEOUT_MS);
    loop {
        let procs = std::fs::read_to_string(&procs_path)
            .map_err(|e| format!("read {}: {e}", procs_path.display()))?;
        if procs.trim().is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "cgroup {} still has member processes: {}",
                path.display(),
                procs.trim()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(CGROUP_DRAIN_INTERVAL_MS));
    }
}

fn open_writeonly_cloexec(path: &Path) -> Result<i32, String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("open {}: path contains NUL", path.display()))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(format!(
            "open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProcessPolicy {
        ProcessPolicy {
            max_processes: 7,
            max_memory_mb: 64,
            cpu_rate_percent: 25,
            run_as_user: None,
            blocked_syscalls: Vec::new(),
            identity: Default::default(),
            child_processes: Default::default(),
            timeout_sec: None,
            windows_win32k: false,
        }
    }

    #[test]
    fn cgroup_limits_convert_policy_to_cgroup_files() {
        let limits = cgroup_limits(&policy()).unwrap();

        assert_eq!(limits.memory_max, Some(64 * 1024 * 1024));
        assert_eq!(limits.pids_max, Some(7));
        assert_eq!(
            limits.cpu_max,
            Some(CpuMax {
                quota_us: 25_000,
                period_us: CPU_PERIOD_US,
            })
        );
    }

    #[test]
    fn cgroup_limits_skip_unrequested_cpu_limit() {
        let mut policy = policy();
        policy.cpu_rate_percent = 0;

        let limits = cgroup_limits(&policy).unwrap();

        assert_eq!(limits.memory_max, Some(64 * 1024 * 1024));
        assert_eq!(limits.pids_max, Some(7));
        assert_eq!(limits.cpu_max, None);
    }

    #[test]
    fn cgroup_limits_enforce_full_cpu_as_quota() {
        let mut policy = policy();
        policy.cpu_rate_percent = 100;

        let limits = cgroup_limits(&policy).unwrap();

        assert_eq!(
            limits.cpu_max,
            Some(CpuMax {
                quota_us: CPU_PERIOD_US,
                period_us: CPU_PERIOD_US,
            })
        );
    }

    #[test]
    fn cgroup_limits_reject_memory_byte_overflow() {
        let mut policy = policy();
        policy.max_memory_mb = u64::MAX;

        let err = cgroup_limits(&policy).unwrap_err();

        assert!(err.contains("overflows"));
    }

    #[test]
    fn probe_cgroup_v2_delegation_cleans_failed_probe() {
        let root = tempfile::tempdir().unwrap();

        let err = probe_cgroup_v2_delegation(root.path()).unwrap_err();

        assert!(err.contains("cgroup.controllers"));
        assert!(
            std::fs::read_dir(root.path()).unwrap().next().is_none(),
            "failed probe directory was not removed"
        );
    }

    #[test]
    fn probe_cgroup_writes_verifies_controller_writes_and_procs_open() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("axis-test");
        std::fs::create_dir(&path).unwrap();
        for file in ["memory.max", "pids.max", "cpu.max", "cgroup.procs"] {
            std::fs::write(path.join(file), "").unwrap();
        }

        probe_cgroup_writes(&path).unwrap();

        assert_eq!(
            std::fs::read_to_string(path.join("memory.max")).unwrap(),
            "max"
        );
        assert_eq!(
            std::fs::read_to_string(path.join("pids.max")).unwrap(),
            "max"
        );
        assert_eq!(
            std::fs::read_to_string(path.join("cpu.max")).unwrap(),
            "100000 100000"
        );
    }

    #[test]
    fn cgroup_v2_path_parses_proc_self_cgroup_entry() {
        let path =
            cgroup_v2_path_from_proc_self_cgroup("0::/user.slice/user-1000.slice/session.scope\n")
                .unwrap();

        assert_eq!(
            path,
            Path::new(CGROUP_ROOT).join("user.slice/user-1000.slice/session.scope")
        );
    }

    #[test]
    fn cgroup_v2_path_rejects_non_absolute_proc_entry() {
        let err = cgroup_v2_path_from_proc_self_cgroup("0::relative\n").unwrap_err();

        assert!(err.contains("not absolute"));
    }

    #[test]
    fn candidate_cgroup_roots_walk_from_current_to_cgroup_root() {
        let current = Path::new(CGROUP_ROOT).join("user.slice/user-1000.slice/session.scope");
        let candidates = candidate_cgroup_roots(&current);

        assert_eq!(candidates[0], current);
        assert_eq!(candidates.last().unwrap(), Path::new(CGROUP_ROOT));
    }

    #[test]
    fn create_cgroup_at_writes_limits_and_adds_process() {
        let root = tempfile::tempdir().unwrap();
        let sandbox_id = "00000000-0000-4000-8000-00000000c901".parse().unwrap();

        let handle = create_cgroup_at(root.path(), sandbox_id, &policy()).unwrap();
        handle.add_process(1234).unwrap();
        let procs_fd = handle.open_procs_fd().unwrap();
        unsafe {
            libc::close(procs_fd);
        }

        assert_eq!(
            std::fs::read_to_string(handle.path().join("memory.max")).unwrap(),
            (64 * 1024 * 1024).to_string()
        );
        assert_eq!(
            std::fs::read_to_string(handle.path().join("pids.max")).unwrap(),
            "7"
        );
        assert_eq!(
            std::fs::read_to_string(handle.path().join("cpu.max")).unwrap(),
            "25000 100000"
        );
        assert_eq!(
            std::fs::read_to_string(handle.path().join("cgroup.procs")).unwrap(),
            "1234"
        );

        let path = handle.path().to_path_buf();
        for file in ["memory.max", "pids.max", "cpu.max", "cgroup.procs"] {
            std::fs::remove_file(path.join(file)).unwrap();
        }
        handle.cleanup().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn write_cgroup_limits_reports_write_failure() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("axis-test");
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("memory.max")).unwrap();

        let err = write_cgroup_limits(&path, &cgroup_limits(&policy()).unwrap()).unwrap_err();

        assert!(err.contains("write"));
    }

    #[test]
    fn create_cgroup_at_cleans_up_after_limit_conversion_failure() {
        let root = tempfile::tempdir().unwrap();
        let sandbox_id = "00000000-0000-4000-8000-00000000c902".parse().unwrap();
        let mut policy = policy();
        policy.max_memory_mb = u64::MAX;

        let err = create_cgroup_at(root.path(), sandbox_id, &policy).unwrap_err();

        assert!(err.contains("overflows"));
        assert!(!root.path().join(format!("axis-{sandbox_id}")).exists());
    }

    #[test]
    fn drain_cgroup_processes_accepts_empty_or_missing_procs_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("axis-test");
        std::fs::create_dir(&path).unwrap();

        drain_cgroup_processes(&path).unwrap();
        std::fs::write(path.join("cgroup.procs"), "").unwrap();
        drain_cgroup_processes(&path).unwrap();
    }

    #[test]
    fn drain_cgroup_processes_reports_stubborn_members() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("axis-test");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.procs"), "1234\n").unwrap();

        let err = drain_cgroup_processes(&path).unwrap_err();

        assert!(err.contains("still has member processes"));
    }

    #[test]
    fn kill_cgroup_processes_is_noop_without_cgroup_kill_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("axis-test");
        std::fs::create_dir(&path).unwrap();

        kill_cgroup_processes(&path).unwrap();
    }

    #[test]
    fn gated_real_cgroup_v2_create_assign_and_cleanup() {
        if std::env::var("AXIS_REAL_CGROUP_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_CGROUP_TESTS=1 not set (test skipped)");
            return;
        }

        let sandbox_id = SandboxId::new();
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("AXIS_REAL_CGROUP_TESTS=1 requires sleep on PATH");

        let handle = match create_cgroup(sandbox_id, &policy()) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("real cgroup create failed: {e}");
            }
        };

        let add_result = handle.add_process(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let path = handle.path().to_path_buf();
        let cleanup_result = handle.cleanup();

        assert!(add_result.is_ok(), "real cgroup add failed: {add_result:?}");
        assert!(
            cleanup_result.is_ok(),
            "real cgroup cleanup failed: {cleanup_result:?}"
        );
        assert!(!path.exists(), "real cgroup remained after cleanup");
    }
}
