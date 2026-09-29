// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock, seccomp-BPF, and network namespaces.

mod bwrap;
pub mod bypass_audit;
mod connect_attribution;
mod identity;
pub mod landlock;
pub mod mxc;
pub mod netns;
pub mod resources;
pub mod seccomp;
pub mod strategy;
pub(crate) mod vxn;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use axis_core::connect_attribution::policy_requires_connect_attribution;
use axis_core::types::SandboxId;
use std::io;
use std::process::Child;

const CLOSED_FD: i32 = -1;
#[cfg(test)]
const PARENT_DEATH_GUARD_OWNER_DIED: u8 = 0;
const PARENT_DEATH_GUARD_DISARM: u8 = 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const LINUX_CAPABILITY_U32S_3: usize = 2;
const CAP_LAST_CAP: i32 = 40;
const POST_TIMEOUT_REAP_GRACE_SEC: u64 = 5;
const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PreparedRlimits {
    address_space_bytes: Option<libc::rlim_t>,
    max_processes: Option<libc::rlim_t>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildSetupErrorKind {
    SetProcessGroup = 1,
    EnterCgroup = 2,
    EnterNetworkNamespace = 3,
    NoNewPrivs = 4,
    Landlock = 5,
    SetGroups = 6,
    SetGid = 7,
    SetUid = 8,
    ApplyResourceLimits = 9,
    DropCapabilities = 10,
    CloseFileDescriptors = 11,
    Seccomp = 12,
    ParentDeathSignal = 13,
}

impl ChildSetupErrorKind {
    fn label(self) -> &'static str {
        match self {
            Self::SetProcessGroup => "set process group",
            Self::EnterCgroup => "enter cgroup",
            Self::EnterNetworkNamespace => "enter network namespace",
            Self::NoNewPrivs => "set no_new_privs",
            Self::Landlock => "apply Landlock",
            Self::SetGroups => "clear supplementary groups",
            Self::SetGid => "drop group id",
            Self::SetUid => "drop user id",
            Self::ApplyResourceLimits => "apply resource limits",
            Self::DropCapabilities => "drop capabilities",
            Self::CloseFileDescriptors => "close inherited file descriptors",
            Self::Seccomp => "apply seccomp",
            Self::ParentDeathSignal => "install parent-death guard",
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::SetProcessGroup),
            2 => Some(Self::EnterCgroup),
            3 => Some(Self::EnterNetworkNamespace),
            4 => Some(Self::NoNewPrivs),
            5 => Some(Self::Landlock),
            6 => Some(Self::SetGroups),
            7 => Some(Self::SetGid),
            8 => Some(Self::SetUid),
            9 => Some(Self::ApplyResourceLimits),
            10 => Some(Self::DropCapabilities),
            11 => Some(Self::CloseFileDescriptors),
            12 => Some(Self::Seccomp),
            13 => Some(Self::ParentDeathSignal),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ChildSetupErrorPipe {
    read_fd: i32,
    write_fd: i32,
}

impl ChildSetupErrorPipe {
    fn new() -> Result<Self, io::Error> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
            })
        }
    }

    fn close_write(&mut self) {
        if self.write_fd != CLOSED_FD {
            unsafe {
                libc::close(self.write_fd);
            }
            self.write_fd = CLOSED_FD;
        }
    }

    fn read_error_kind(&mut self) -> Option<ChildSetupErrorKind> {
        self.close_write();
        if self.read_fd == CLOSED_FD {
            return None;
        }

        let mut byte = 0u8;
        let ret = unsafe { libc::read(self.read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) };
        if ret == 1 {
            ChildSetupErrorKind::from_byte(byte)
        } else {
            None
        }
    }
}

impl Drop for ChildSetupErrorPipe {
    fn drop(&mut self) {
        if self.read_fd != CLOSED_FD {
            unsafe {
                libc::close(self.read_fd);
            }
            self.read_fd = CLOSED_FD;
        }
        self.close_write();
    }
}

#[derive(Debug)]
struct ParentDeathGuardPipe {
    read_fd: i32,
    write_fd: i32,
}

impl ParentDeathGuardPipe {
    fn new() -> Result<Self, io::Error> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
            })
        }
    }

    fn child_fds(&self) -> (i32, i32) {
        (self.read_fd, self.write_fd)
    }

    fn close_read(&mut self) {
        if self.read_fd != CLOSED_FD {
            unsafe {
                libc::close(self.read_fd);
            }
            self.read_fd = CLOSED_FD;
        }
    }

    fn close_write(&mut self) {
        if self.write_fd != CLOSED_FD {
            unsafe {
                libc::close(self.write_fd);
            }
            self.write_fd = CLOSED_FD;
        }
    }
}

impl Drop for ParentDeathGuardPipe {
    fn drop(&mut self) {
        self.close_read();
        self.close_write();
    }
}

#[derive(Debug)]
struct ParentDeathGuard {
    write_fd: i32,
    monitor_pid: libc::pid_t,
}

impl ParentDeathGuard {
    fn spawn_for_process_group(
        process_group: libc::pid_t,
        mut pipe: ParentDeathGuardPipe,
    ) -> Result<Self, io::Error> {
        let monitor_pid = unsafe { libc::fork() };
        if monitor_pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if monitor_pid == 0 {
            unsafe {
                libc::close(pipe.write_fd);
                libc::setpgid(0, 0);
                run_parent_death_monitor(pipe.read_fd, process_group);
            }
        }

        pipe.close_read();
        let write_fd = pipe.write_fd;
        pipe.write_fd = CLOSED_FD;
        Ok(Self {
            write_fd,
            monitor_pid,
        })
    }

    fn finish(&mut self) {
        self.disarm();
        self.wait_for_monitor();
    }

    fn disarm(&mut self) {
        if self.write_fd != CLOSED_FD {
            let disarm = [PARENT_DEATH_GUARD_DISARM];
            unsafe {
                let _ = libc::write(self.write_fd, disarm.as_ptr().cast(), disarm.len());
            }
            unsafe {
                libc::close(self.write_fd);
            }
            self.write_fd = CLOSED_FD;
        }
    }

    #[cfg(test)]
    fn trigger_owner_death_for_test(&mut self) {
        if self.write_fd != CLOSED_FD {
            unsafe {
                let owner_died = [PARENT_DEATH_GUARD_OWNER_DIED];
                let _ = libc::write(self.write_fd, owner_died.as_ptr().cast(), owner_died.len());
                libc::close(self.write_fd);
            }
            self.write_fd = CLOSED_FD;
        }
        self.wait_for_monitor();
    }

    fn wait_for_monitor(&mut self) {
        // The owner-death path may spend up to about 500 ms repeatedly killing
        // the sandbox process group before the monitor exits.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut status = 0;
            let ret = unsafe { libc::waitpid(self.monitor_pid, &mut status, libc::WNOHANG) };
            if ret == self.monitor_pid || ret < 0 {
                return;
            }
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(self.monitor_pid, libc::SIGKILL);
                    libc::waitpid(self.monitor_pid, &mut status, 0);
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Drop for ParentDeathGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

#[derive(Debug)]
struct NetnsHelperOwnerPidFd {
    fd: i32,
}

impl NetnsHelperOwnerPidFd {
    fn new() -> Result<Self, io::Error> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32 };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { fd })
        }
    }

    fn fd(&self) -> i32 {
        self.fd
    }

    fn configure_command(&self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;

        let fd = self.fd;
        unsafe {
            command.pre_exec(move || clear_fd_cloexec(fd).map_err(io::Error::from_raw_os_error));
        }
    }

    fn spawned(&mut self) {
        if self.fd != CLOSED_FD {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = CLOSED_FD;
        }
    }
}

impl Drop for NetnsHelperOwnerPidFd {
    fn drop(&mut self) {
        if self.fd != CLOSED_FD {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = CLOSED_FD;
        }
    }
}

/// Linux sandbox using native isolation primitives.
pub(crate) struct LinuxSandbox {
    config: SandboxConfig,
    plan: strategy::LinuxIsolationPlan,
    child: Option<Child>,
    parent_death_guard: Option<ParentDeathGuard>,
    exit_code: Option<i32>,
    netns_name: Option<String>,
    netns_helper_destroy_token: Option<String>,
    cgroup: Option<resources::CgroupHandle>,
    connect_supervisor: Option<connect_attribution::ConnectAttributionSupervisor>,
    tmpdir_active: bool,
}

impl LinuxSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        let mut config = config.clone();
        axis_core::sandbox_env::retain_linux_sandbox_env(&mut config.env);

        let trace = config.startup_trace.clone();
        crate::sandbox::record_startup_result(&trace, "support_files.workspace_dir", || {
            std::fs::create_dir_all(&config.workspace_dir)
        })?;
        let plan = crate::sandbox::record_startup_result(&trace, "backend.preflight", || {
            strategy::build_isolation_plan(&config)
                .map_err(|e| SandboxError::IsolationFailed(e.to_string()))
        })?;

        Ok(Self {
            config,
            plan,
            child: None,
            parent_death_guard: None,
            exit_code: None,
            netns_name: None,
            netns_helper_destroy_token: None,
            cgroup: None,
            connect_supervisor: None,
            tmpdir_active: false,
        })
    }

    fn cleanup_netns(&mut self) -> Option<String> {
        if self.netns_helper_destroy_token.is_some() {
            self.cleanup_netns_with_helper_token(|sandbox_id, token| {
                netns::destroy_netns_with_helper_token(sandbox_id, token)
            })
        } else {
            self.cleanup_netns_with(netns::destroy_netns)
        }
    }

    fn cleanup_netns_with_helper_token<F>(&mut self, destroy: F) -> Option<String>
    where
        F: FnOnce(SandboxId, &str) -> Result<netns::HelperCleanupOutcome, String>,
    {
        let token = self.netns_helper_destroy_token.clone()?;
        let sandbox_id = self.config.id;

        match destroy(sandbox_id, &token) {
            Ok(netns::HelperCleanupOutcome::Destroyed) => {}
            Ok(netns::HelperCleanupOutcome::AlreadyCompleted) => {
                tracing::debug!("sandbox {sandbox_id}: netns helper cleanup was already completed");
            }
            Err(e) => {
                tracing::warn!("sandbox {sandbox_id}: netns helper cleanup failed: {e}");
                return Some(format!(
                    "netns helper cleanup for sandbox {sandbox_id}: {e}"
                ));
            }
        }

        self.netns_helper_destroy_token = None;
        self.netns_name = None;
        None
    }

    fn cleanup_netns_with<F>(&mut self, destroy: F) -> Option<String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        if let Some(ns_name) = self.netns_name.clone() {
            if let Err(e) = destroy(&ns_name) {
                tracing::warn!("failed to destroy netns '{ns_name}': {e}");
                return Some(format!("netns '{ns_name}': {e}"));
            }
            self.netns_name = None;
        }
        None
    }

    fn cleanup_cgroup(&mut self) -> Option<String> {
        let cgroup = self.cgroup.clone()?;
        let path = cgroup.path().to_path_buf();
        if let Err(e) = cgroup.cleanup() {
            tracing::warn!("failed to remove cgroup '{}': {e}", path.display());
            return Some(format!("cgroup '{}': {e}", path.display()));
        }
        self.cgroup = None;
        None
    }

    fn finish_parent_death_guard(&mut self) {
        if let Some(mut guard) = self.parent_death_guard.take() {
            guard.finish();
        }
    }

    fn stop_connect_supervisor(&mut self) {
        if let Some(mut supervisor) = self.connect_supervisor.take() {
            supervisor.stop();
        }
    }

    fn connect_attribution_required(&self) -> bool {
        policy_requires_connect_attribution(&self.config.policy)
    }

    fn connect_attribution_required_for_native_proxy(&self) -> Result<bool, SandboxError> {
        if !self.connect_attribution_required() {
            return Ok(false);
        }
        match self.plan.network {
            strategy::NetworkStrategy::Proxy {
                setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                ..
            } => {
                if self
                    .config
                    .policy
                    .process
                    .blocked_syscalls
                    .iter()
                    .any(|name| name == "connect")
                {
                    return Err(SandboxError::IsolationFailed(
                        "binary-restricted proxy policy cannot use connect-time attribution when process.blocked_syscalls includes connect"
                            .into(),
                    ));
                }
                if self.config.connect_attribution.is_none() {
                    return Err(SandboxError::IsolationFailed(
                        "binary-restricted proxy policy requires connect-time attribution store"
                            .into(),
                    ));
                }
                Ok(true)
            }
            strategy::NetworkStrategy::Proxy {
                setup: strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
                ..
            } => Err(SandboxError::IsolationFailed(
                "binary-restricted proxy policy requires connect-time attribution, which is not implemented for axis-netns-helper launch"
                    .into(),
            )),
            _ => Ok(false),
        }
    }

    fn cleanup_after_process_exit(&mut self) -> Option<String> {
        self.cleanup_after_process_exit_with_handlers(
            netns::destroy_netns,
            netns::destroy_netns_with_helper_token,
        )
    }

    #[cfg(test)]
    fn cleanup_after_process_exit_with<F>(&mut self, destroy: F) -> Option<String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        self.cleanup_after_process_exit_with_handlers(
            destroy,
            netns::destroy_netns_with_helper_token,
        )
    }

    fn cleanup_after_process_exit_with_handlers<N, H>(
        &mut self,
        destroy_native: N,
        destroy_helper: H,
    ) -> Option<String>
    where
        N: FnOnce(&str) -> Result<(), String>,
        H: FnOnce(SandboxId, &str) -> Result<netns::HelperCleanupOutcome, String>,
    {
        let mut cleanup_errors = Vec::new();
        self.stop_connect_supervisor();
        self.finish_parent_death_guard();
        let netns_cleanup = if self.netns_helper_destroy_token.is_some() {
            self.cleanup_netns_with_helper_token(destroy_helper)
        } else {
            self.cleanup_netns_with(destroy_native)
        };
        if let Some(e) = netns_cleanup {
            cleanup_errors.push(format!("netns cleanup failed: {e}"));
        }
        if let Some(e) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {e}"));
        }
        self.cleanup_tmpdir_after_stop();
        if cleanup_errors.is_empty() {
            None
        } else {
            Some(cleanup_errors.join("; "))
        }
    }

    fn cleanup_parent_resources_after_setup_failure(
        &mut self,
        netns_fd: Option<i32>,
    ) -> Option<String> {
        self.cleanup_parent_resources_after_setup_failure_with_handlers(
            netns_fd,
            netns::destroy_netns,
            netns::destroy_netns_with_helper_token,
        )
    }

    #[cfg(test)]
    fn cleanup_parent_resources_after_setup_failure_with<F>(
        &mut self,
        netns_fd: Option<i32>,
        destroy: F,
    ) -> Option<String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        self.cleanup_parent_resources_after_setup_failure_with_handlers(
            netns_fd,
            destroy,
            netns::destroy_netns_with_helper_token,
        )
    }

    fn cleanup_parent_resources_after_setup_failure_with_handlers<N, H>(
        &mut self,
        netns_fd: Option<i32>,
        destroy_native: N,
        destroy_helper: H,
    ) -> Option<String>
    where
        N: FnOnce(&str) -> Result<(), String>,
        H: FnOnce(SandboxId, &str) -> Result<netns::HelperCleanupOutcome, String>,
    {
        close_fd(netns_fd);
        self.stop_connect_supervisor();
        let mut cleanup_errors = Vec::new();
        let netns_cleanup = if self.netns_helper_destroy_token.is_some() {
            self.cleanup_netns_with_helper_token(destroy_helper)
        } else {
            self.cleanup_netns_with(destroy_native)
        };
        if let Some(e) = netns_cleanup {
            cleanup_errors.push(format!("netns cleanup failed: {e}"));
        }
        if let Some(e) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {e}"));
        }
        if let Some(e) = self.cleanup_tmpdir_for_setup_failure() {
            cleanup_errors.push(format!("tmpdir cleanup failed: {e}"));
        }
        if cleanup_errors.is_empty() {
            None
        } else {
            Some(cleanup_errors.join("; "))
        }
    }

    fn start_with_bwrap(&mut self) -> Result<u32, SandboxError> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        if self.config.policy.process.run_as_user.is_some() {
            return Err(SandboxError::IsolationFailed(
                "bubblewrap fallback with run_as_user is not implemented yet".into(),
            ));
        }
        if matches!(self.plan.network, strategy::NetworkStrategy::Proxy { .. }) {
            return Err(SandboxError::IsolationFailed(
                "bubblewrap fallback cannot preserve proxy network semantics".into(),
            ));
        }

        let sandbox_id = self.config.id;
        let tmpdir_required = landlock::policy_uses_tmpdir(&self.config.policy.filesystem);
        if tmpdir_required {
            match landlock::create_tmpdir(&self.config.workspace_dir) {
                Ok(()) => self.tmpdir_active = true,
                Err(e) => return Err(SandboxError::IsolationFailed(e)),
            }
        }

        let seccomp_options = seccomp_options_for_network(&self.plan.network, false);
        let prepared_seccomp = match seccomp::prepare_seccomp_with_options(
            &self.config.policy.process,
            seccomp_options,
        ) {
            Ok(filter) => filter,
            Err(e) => {
                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(e),
                    cleanup_error,
                ));
            }
        };
        let seccomp_fd = match bwrap::create_seccomp_fd(&prepared_seccomp) {
            Ok(fd) => fd,
            Err(e) => {
                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(e),
                    cleanup_error,
                ));
            }
        };

        let prepared_rlimits =
            match prepare_rlimits_for_plan(&self.config.policy.process, &self.plan.resources) {
                Ok(limits) => limits,
                Err(e) => {
                    close_fd(Some(seccomp_fd));
                    let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("resource limits: {e}")),
                        cleanup_error,
                    ));
                }
            };

        if matches!(
            self.plan.resources,
            strategy::ResourceStrategy::CgroupsV2 { .. }
        ) {
            match resources::create_cgroup(sandbox_id, &self.config.policy.process) {
                Ok(cgroup) => self.cgroup = Some(cgroup),
                Err(e) => {
                    close_fd(Some(seccomp_fd));
                    let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("cgroup: creation failed: {e}")),
                        cleanup_error,
                    ));
                }
            }
        }

        let cgroup_procs_fd = match &self.cgroup {
            Some(cgroup) => match cgroup.open_procs_fd() {
                Ok(fd) => Some(fd),
                Err(e) => {
                    close_fd(Some(seccomp_fd));
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("cgroup: cannot open procs: {e}")),
                        cleanup_error,
                    ));
                }
            },
            None => None,
        };

        let network = match self.plan.network {
            strategy::NetworkStrategy::BlockedBySeccomp
            | strategy::NetworkStrategy::BlockedByBubblewrap => bwrap::BubblewrapNetwork::Block,
            strategy::NetworkStrategy::AllowHost => bwrap::BubblewrapNetwork::AllowHost,
            strategy::NetworkStrategy::Proxy { .. } => unreachable!("proxy rejected above"),
        };
        let plan = match bwrap::build_plan(bwrap::BubblewrapPlanInput {
            filesystem: &self.config.policy.filesystem,
            workspace: &self.config.workspace_dir,
            working_dir: self.config.working_dir.as_deref(),
            network,
            env: &self.config.env,
            command: &self.config.command,
            command_args: &self.config.args,
            seccomp_fd,
        }) {
            Ok(plan) => plan,
            Err(e) => {
                close_fd(Some(seccomp_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(format!("bubblewrap plan: {e}")),
                    cleanup_error,
                ));
            }
        };

        let mut cmd = Command::new(&plan.program);
        cmd.args(&plan.args);
        cmd.env_clear();
        let bwrap_bind_fds = plan.inherited_fds();
        if self.config.capture_output {
            cmd.stdin(std::process::Stdio::null());
            let stdout_file =
                match std::fs::File::create(self.config.workspace_dir.join("stdout.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        close_fd(Some(seccomp_fd));
                        close_fd(cgroup_procs_fd);
                        let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stdout log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            let stderr_file =
                match std::fs::File::create(self.config.workspace_dir.join("stderr.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        close_fd(Some(seccomp_fd));
                        close_fd(cgroup_procs_fd);
                        let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stderr log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            cmd.stdout(std::process::Stdio::from(stdout_file));
            cmd.stderr(std::process::Stdio::from(stderr_file));
        }

        let parent_death_guard_pipe = match ParentDeathGuardPipe::new() {
            Ok(pipe) => pipe,
            Err(e) => {
                close_fd(Some(seccomp_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("parent-death guard pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let parent_death_child_fds = parent_death_guard_pipe.child_fds();
        let owner_pid = unsafe { libc::getpid() };

        let mut child_error_pipe = match ChildSetupErrorPipe::new() {
            Ok(pipe) => pipe,
            Err(e) => {
                close_fd(Some(seccomp_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("child setup error pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let child_error_write_fd = child_error_pipe.write_fd;
        unsafe {
            cmd.pre_exec(move || {
                if let Err(errno) = install_parent_death_signal(owner_pid) {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::ParentDeathSignal,
                        errno,
                    ));
                }
                close_parent_death_guard_child_fds(parent_death_child_fds);
                if libc::setpgid(0, 0) < 0 {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::SetProcessGroup,
                        current_errno(),
                    ));
                }
                if let Some(fd) = cgroup_procs_fd {
                    if let Err(errno) = enter_cgroup_from_child_fd(fd) {
                        libc::close(fd);
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::EnterCgroup,
                            errno,
                        ));
                    }
                    libc::close(fd);
                }
                if let Some(limits) = prepared_rlimits
                    && let Err(errno) = apply_prepared_rlimits(limits)
                {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::ApplyResourceLimits,
                        errno,
                    ));
                }
                if let Err(errno) = mark_unexpected_child_fds_close_on_exec() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::CloseFileDescriptors,
                        errno,
                    ));
                }
                for fd in &bwrap_bind_fds {
                    if let Err(errno) = clear_fd_cloexec(*fd) {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::CloseFileDescriptors,
                            errno,
                        ));
                    }
                }
                if let Err(errno) = clear_fd_cloexec(seccomp_fd) {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::CloseFileDescriptors,
                        errno,
                    ));
                }
                Ok(())
            });
        }

        let mut child = match cmd.spawn() {
            Ok(child) => {
                close_fd(Some(seccomp_fd));
                close_fd(cgroup_procs_fd);
                drop(child_error_pipe);
                child
            }
            Err(e) => {
                close_fd(Some(seccomp_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    spawn_error(e, &mut child_error_pipe),
                    cleanup_error,
                ));
            }
        };

        let pid = child.id();
        let parent_death_guard =
            match ParentDeathGuard::spawn_for_process_group(pid as i32, parent_death_guard_pipe) {
                Ok(guard) => guard,
                Err(e) => {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                    return Err(append_cleanup_failure(
                        SandboxError::SpawnFailed(format!("parent-death guard monitor: {e}")),
                        cleanup_error,
                    ));
                }
            };
        self.parent_death_guard = Some(parent_death_guard);
        self.child = Some(child);
        tracing::info!("sandbox {sandbox_id} started via bubblewrap fallback, pid={pid}");
        Ok(pid)
    }

    fn start_with_netns_helper(&mut self, proxy_port: u16) -> Result<u32, SandboxError> {
        use std::process::Command;

        if self.connect_attribution_required() {
            return Err(SandboxError::IsolationFailed(
                "binary-restricted proxy policy requires connect-time attribution, which is not implemented for axis-netns-helper launch"
                    .into(),
            ));
        }

        if self.config.policy.process.run_as_user.is_some() {
            return Err(SandboxError::IsolationFailed(
                "netns helper launch with run_as_user is not implemented yet".into(),
            ));
        }

        let sandbox_id = self.config.id;
        let tmpdir_required = landlock::policy_uses_tmpdir(&self.config.policy.filesystem);
        if tmpdir_required {
            return Err(SandboxError::IsolationFailed(
                "netns helper launch with {tmpdir} filesystem policy is not implemented yet".into(),
            ));
        }
        let prepared_rlimits =
            match prepare_rlimits_for_plan(&self.config.policy.process, &self.plan.resources) {
                Ok(limits) => limits,
                Err(e) => {
                    return Err(SandboxError::IsolationFailed(format!(
                        "resource limits: {e}"
                    )));
                }
            };

        if matches!(
            self.plan.resources,
            strategy::ResourceStrategy::CgroupsV2 { .. }
        ) {
            match resources::create_cgroup(sandbox_id, &self.config.policy.process) {
                Ok(cgroup) => self.cgroup = Some(cgroup),
                Err(e) => {
                    return Err(SandboxError::IsolationFailed(format!(
                        "cgroup: creation failed: {e}"
                    )));
                }
            }
        }

        let cgroup_procs_fd = match &self.cgroup {
            Some(cgroup) => match cgroup.open_procs_fd() {
                Ok(fd) => Some(fd),
                Err(e) => {
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("cgroup: cannot open procs: {e}")),
                        cleanup_error,
                    ));
                }
            },
            None => None,
        };

        let destroy_token = netns::new_destroy_token();
        let helper_env = self.helper_target_env();
        let spec = netns::HelperLaunchSpec {
            launch_kind: netns::HelperLaunchKind::DirectProcess,
            mxc_config_fd: None,
            workspace_dir: self.config.workspace_dir.clone(),
            filesystem: self.config.policy.filesystem.clone(),
            process: self.config.policy.process.clone(),
            rlimits: helper_rlimits_from_prepared(prepared_rlimits),
            command: self.config.command.clone(),
            args: self.config.args.clone(),
            env: helper_env,
            destroy_token: destroy_token.clone(),
        };

        let spec_fd = match netns::create_launch_spec_fd(&spec) {
            Ok(fd) => fd,
            Err(e) => {
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(format!("netns helper launch spec: {e}")),
                    cleanup_error,
                ));
            }
        };

        let (sync_read_fd, sync_write_fd) = match helper_sync_pipe() {
            Ok(fds) => fds,
            Err(e) => {
                close_fd(Some(spec_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("netns helper sync pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let mut owner_guard = match NetnsHelperOwnerPidFd::new() {
            Ok(guard) => guard,
            Err(e) => {
                close_fd(Some(spec_fd));
                close_fd(Some(sync_read_fd));
                close_fd(Some(sync_write_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("netns helper owner pidfd: {e}")),
                    cleanup_error,
                ));
            }
        };

        let allocation = netns::proxy_netns_allocation(sandbox_id, proxy_port);
        let mut cmd = Command::new(netns::helper_path());
        let helper_args = [
            "launch".to_string(),
            sandbox_id.to_string(),
            proxy_port.to_string(),
            spec_fd.to_string(),
            sync_write_fd.to_string(),
            cgroup_procs_fd
                .map(|fd| fd.to_string())
                .unwrap_or_else(|| "-1".into()),
            owner_guard.fd().to_string(),
        ];
        cmd.args(helper_args);

        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.config.workspace_dir);
        }

        if self.config.capture_output {
            cmd.stdin(std::process::Stdio::null());
            let stdout_file =
                match std::fs::File::create(self.config.workspace_dir.join("stdout.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        close_fd(Some(spec_fd));
                        close_fd(Some(sync_read_fd));
                        close_fd(Some(sync_write_fd));
                        close_fd(cgroup_procs_fd);
                        let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stdout log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            let stderr_file =
                match std::fs::File::create(self.config.workspace_dir.join("stderr.log")) {
                    Ok(file) => file,
                    Err(e) => {
                        close_fd(Some(spec_fd));
                        close_fd(Some(sync_read_fd));
                        close_fd(Some(sync_write_fd));
                        close_fd(cgroup_procs_fd);
                        let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stderr log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            cmd.stdout(std::process::Stdio::from(stdout_file));
            cmd.stderr(std::process::Stdio::from(stderr_file));
        }

        cmd.env_clear();
        configure_helper_launch_fds_for_spawn(
            &mut cmd,
            HelperLaunchFds {
                spec_fd,
                sync_write_fd,
                cgroup_procs_fd,
                mxc_config_fd: None,
            },
        );
        owner_guard.configure_command(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                close_fd(Some(spec_fd));
                close_fd(Some(sync_read_fd));
                close_fd(Some(sync_write_fd));
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("netns helper: {e}")),
                    cleanup_error,
                ));
            }
        };
        owner_guard.spawned();

        close_fd(Some(spec_fd));
        close_fd(Some(sync_write_fd));
        close_fd(cgroup_procs_fd);

        self.netns_name = Some(allocation.namespace);
        self.netns_helper_destroy_token = Some(destroy_token);

        if let Err(e) = netns::read_helper_sync(sync_read_fd) {
            let termination_error = terminate_netns_helper_startup(&mut child)
                .err()
                .map(|error| format!("helper termination failed: {error}"));
            let cleanup_error = combine_cleanup_errors(
                termination_error,
                self.cleanup_parent_resources_after_setup_failure(None),
            );
            return Err(append_cleanup_failure(
                SandboxError::IsolationFailed(format!("netns helper setup failed: {e}")),
                cleanup_error,
            ));
        }

        self.tmpdir_active = tmpdir_required;

        let pid = child.id();
        self.child = Some(child);
        tracing::info!("sandbox {sandbox_id} started via netns helper, pid={pid}");
        Ok(pid)
    }

    fn helper_target_env(&self) -> Vec<(String, String)> {
        let mut env = self.config.env.clone();
        if let strategy::ProxyStrategy::Required {
            sandbox_addr, port, ..
        } = &self.plan.proxy
        {
            retain_non_proxy_env(&mut env);
            env.extend(proxy_env_vars(sandbox_addr, *port));
        }
        env
    }

    fn cleanup_tmpdir_after_stop(&mut self) {
        if let Err(e) = self.cleanup_tmpdir() {
            tracing::warn!("sandbox {}: tmpdir cleanup failed: {e}", self.config.id);
        }
    }

    fn cleanup_tmpdir_for_setup_failure(&mut self) -> Option<String> {
        self.cleanup_tmpdir().err()
    }

    fn cleanup_tmpdir(&mut self) -> Result<(), String> {
        if !self.tmpdir_active {
            return Ok(());
        }
        landlock::cleanup_tmpdir(&self.config.workspace_dir)?;
        self.tmpdir_active = false;
        Ok(())
    }

    fn resolve_identity(&self) -> Result<Option<ResolvedIdentity>, SandboxError> {
        match &self.plan.identity {
            strategy::IdentityStrategy::CurrentUser => Ok(None),
            strategy::IdentityStrategy::RunAsUser { username } => {
                identity::resolve_run_as_user(username, &identity::SystemUserLookup)
                    .map(Some)
                    .map_err(SandboxError::IsolationFailed)
            }
        }
    }
}

type ResolvedIdentity = identity::ResolvedIdentity;

fn close_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe {
            libc::close(fd);
        }
    }
}

pub(super) fn terminate_netns_helper_startup(child: &mut Child) -> Result<(), String> {
    let pid = child.id() as libc::pid_t;
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => return Err(format!("inspect helper process {pid}: {error}")),
    }
    if let Err(error) = child.kill()
        && error.raw_os_error() != Some(libc::ESRCH)
    {
        return Err(format!("terminate helper process {pid}: {error}"));
    }
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) => {
                return Err(format!(
                    "helper process {pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after SIGKILL"
                ));
            }
            Err(error) => return Err(format!("reap helper process {pid}: {error}")),
        }
    }
}

fn combine_cleanup_errors(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
    }
}

fn clear_fd_cloexec(fd: i32) -> Result<(), i32> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(current_errno());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn child_setup_error(write_fd: i32, kind: ChildSetupErrorKind, errno: i32) -> io::Error {
    let byte = kind as u8;
    unsafe {
        libc::write(write_fd, &byte as *const u8 as *const libc::c_void, 1);
    }
    io::Error::from_raw_os_error(errno)
}

fn spawn_error(e: io::Error, child_error_pipe: &mut ChildSetupErrorPipe) -> SandboxError {
    if let Some(kind) = child_error_pipe.read_error_kind() {
        SandboxError::IsolationFailed(format!("{} failed: {e}", kind.label()))
    } else {
        SandboxError::SpawnFailed(e.to_string())
    }
}

fn append_cleanup_failure(error: SandboxError, cleanup_error: Option<String>) -> SandboxError {
    let Some(cleanup_error) = cleanup_error else {
        return error;
    };
    match error {
        SandboxError::IsolationFailed(message) => {
            SandboxError::IsolationFailed(format!("{message}; cleanup failed: {cleanup_error}"))
        }
        SandboxError::SpawnFailed(message) => {
            SandboxError::SpawnFailed(format!("{message}; cleanup failed: {cleanup_error}"))
        }
        other => other,
    }
}

fn helper_sync_pipe() -> Result<(i32, i32), io::Error> {
    let mut fds = [0; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

#[derive(Debug, Clone, Copy)]
struct HelperLaunchFds {
    spec_fd: i32,
    sync_write_fd: i32,
    cgroup_procs_fd: Option<i32>,
    mxc_config_fd: Option<i32>,
}

fn configure_helper_launch_fds_for_spawn(cmd: &mut std::process::Command, fds: HelperLaunchFds) {
    use std::os::unix::process::CommandExt;

    unsafe {
        cmd.pre_exec(move || {
            for fd in [
                Some(fds.spec_fd),
                Some(fds.sync_write_fd),
                fds.cgroup_procs_fd,
                fds.mxc_config_fd,
            ]
            .into_iter()
            .flatten()
            {
                if let Err(errno) = clear_fd_cloexec(fd) {
                    return Err(io::Error::from_raw_os_error(errno));
                }
            }
            Ok(())
        });
    }
}

fn helper_rlimits_from_prepared(limits: Option<PreparedRlimits>) -> netns::HelperRlimits {
    match limits {
        Some(limits) => netns::HelperRlimits {
            address_space_bytes: limits.address_space_bytes,
            max_processes: limits.max_processes,
        },
        None => netns::HelperRlimits::default(),
    }
}

fn prepare_rlimits_for_plan(
    policy: &axis_core::policy::ProcessPolicy,
    resources: &strategy::ResourceStrategy,
) -> Result<Option<PreparedRlimits>, String> {
    let strategy::ResourceStrategy::RlimitFallback {
        memory_limit,
        process_limit,
        ..
    } = resources
    else {
        return Ok(None);
    };

    let address_space_bytes = if *memory_limit {
        Some(rlim_from_u64(memory_limit_bytes(policy.max_memory_mb)?)?)
    } else {
        None
    };
    let max_processes = match process_limit {
        strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser => {
            Some(rlim_from_u64(u64::from(policy.effective_max_processes()))?)
        }
        strategy::ProcessLimitFallback::NotRequested => None,
    };

    if address_space_bytes.is_none() && max_processes.is_none() {
        Ok(None)
    } else {
        Ok(Some(PreparedRlimits {
            address_space_bytes,
            max_processes,
        }))
    }
}

fn memory_limit_bytes(max_memory_mb: u64) -> Result<u64, String> {
    max_memory_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| format!("memory limit {max_memory_mb} MiB overflows byte conversion"))
}

fn rlim_from_u64(value: u64) -> Result<libc::rlim_t, String> {
    if u128::from(value) > libc::rlim_t::MAX as u128 {
        Err(format!("resource limit {value} exceeds rlim_t range"))
    } else {
        Ok(value as libc::rlim_t)
    }
}

fn apply_prepared_rlimits(limits: PreparedRlimits) -> Result<(), i32> {
    if let Some(value) = limits.address_space_bytes {
        set_resource_limit(libc::RLIMIT_AS, value)?;
    }
    if let Some(value) = limits.max_processes {
        set_resource_limit(libc::RLIMIT_NPROC, value)?;
    }
    Ok(())
}

fn set_resource_limit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> Result<(), i32> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    let ret = unsafe { libc::setrlimit(resource, &limit as *const libc::rlimit) };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn seccomp_options_for_network(
    network: &strategy::NetworkStrategy,
    notify_connect: bool,
) -> seccomp::SeccompOptions {
    let options = match network {
        strategy::NetworkStrategy::BlockedBySeccomp
        | strategy::NetworkStrategy::BlockedByBubblewrap => {
            seccomp::SeccompOptions::deny_network_socket_domains()
        }
        strategy::NetworkStrategy::AllowHost | strategy::NetworkStrategy::Proxy { .. } => {
            seccomp::SeccompOptions::default()
        }
    };
    if notify_connect {
        options.notify_connect()
    } else {
        options
    }
}

fn child_fd_close_on_exec_range() -> (u32, u32, libc::c_uint) {
    (3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC)
}

fn close_child_fd_range(first: u32, last: u32, flags: libc::c_uint) -> Result<(), i32> {
    if first > last {
        return Ok(());
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_uint,
            last as libc::c_uint,
            flags,
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn mark_unexpected_child_fds_close_on_exec() -> Result<(), i32> {
    let (first, last, flags) = child_fd_close_on_exec_range();
    close_child_fd_range(first, last, flags)
}

fn enter_cgroup_from_child_fd(fd: i32) -> Result<(), i32> {
    let pid = unsafe { libc::getpid() };
    let mut buffer = [0u8; 32];
    let len = decimal_pid(pid, &mut buffer);
    write_all_fd(fd, &buffer[..len])
}

fn decimal_pid(pid: libc::pid_t, buffer: &mut [u8; 32]) -> usize {
    let mut value = pid as u32;
    let mut digits = [0u8; 10];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
        if value == 0 {
            break;
        }
    }
    for index in 0..len {
        buffer[index] = digits[len - index - 1];
    }
    len
}

fn write_all_fd(fd: i32, mut bytes: &[u8]) -> Result<(), i32> {
    while !bytes.is_empty() {
        let ret = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
        if ret < 0 {
            return Err(current_errno());
        }
        if ret == 0 {
            return Err(libc::EIO);
        }
        bytes = &bytes[ret as usize..];
    }
    Ok(())
}

fn empty_capability_data() -> [CapData; LINUX_CAPABILITY_U32S_3] {
    [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; LINUX_CAPABILITY_U32S_3]
}

fn clear_ambient_capabilities() -> Result<(), i32> {
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn drop_capability_bounding_set() -> Result<(), i32> {
    for cap in 0..=CAP_LAST_CAP {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret < 0 {
            match current_errno() {
                // Some kernels expose fewer capabilities than CAP_LAST_CAP.
                libc::EINVAL => continue,
                // Non-privileged callers cannot edit the bounding set. Clearing
                // the process sets below is still mandatory and fail-closed.
                libc::EPERM => continue,
                errno => return Err(errno),
            }
        }
    }
    Ok(())
}

fn clear_process_capability_sets() -> Result<(), i32> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = empty_capability_data();
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

fn drop_process_capabilities() -> Result<(), i32> {
    clear_ambient_capabilities()?;
    drop_capability_bounding_set()?;
    clear_process_capability_sets()
}

fn apply_proxy_env_from_strategy(cmd: &mut std::process::Command, proxy: &strategy::ProxyStrategy) {
    if let strategy::ProxyStrategy::Required {
        sandbox_addr, port, ..
    } = proxy
    {
        remove_proxy_env_from_command(cmd);
        for (key, value) in proxy_env_vars(sandbox_addr, *port) {
            cmd.env(key, value);
        }
    }
}

fn remove_proxy_env_from_command(cmd: &mut std::process::Command) {
    let keys: Vec<_> = cmd
        .get_envs()
        .filter_map(|(key, _)| {
            let key_str = key.to_string_lossy();
            axis_core::sandbox_env::is_proxy_env_key(&key_str).then(|| key.to_os_string())
        })
        .collect();
    for key in keys {
        cmd.env_remove(key);
    }
}

fn proxy_env_vars(sandbox_addr: &std::net::Ipv4Addr, port: u16) -> Vec<(String, String)> {
    let proxy_url = format!("http://{sandbox_addr}:{port}");
    vec![
        ("HTTP_PROXY".into(), proxy_url.clone()),
        ("HTTPS_PROXY".into(), proxy_url.clone()),
        ("http_proxy".into(), proxy_url.clone()),
        ("https_proxy".into(), proxy_url),
        ("NO_PROXY".into(), NO_PROXY_VALUE.into()),
        ("no_proxy".into(), NO_PROXY_VALUE.into()),
    ]
}

fn retain_non_proxy_env(env: &mut Vec<(String, String)>) {
    env.retain(|(key, _)| !is_proxy_env_key(key));
}

fn is_proxy_env_key(key: &str) -> bool {
    axis_core::sandbox_env::is_proxy_env_key(key)
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn run_parent_death_monitor(read_fd: i32, process_group: libc::pid_t) -> ! {
    let mut byte = 0u8;
    let mut disarmed = false;
    loop {
        let ret = unsafe { libc::read(read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) };
        if ret > 0 {
            disarmed = byte == PARENT_DEATH_GUARD_DISARM;
            break;
        }
        if ret == 0 {
            break;
        }
        if ret < 0 && current_errno() != libc::EINTR {
            break;
        }
    }

    unsafe {
        libc::close(read_fd);
    }
    if !disarmed && process_group > 1 {
        parent_death_kill_process_group(process_group);
    }
    unsafe {
        libc::_exit(0);
    }
}

fn parent_death_kill_process_group(process_group: libc::pid_t) {
    for _ in 0..25 {
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }

        let probe = unsafe { libc::kill(-process_group, 0) };
        if probe < 0 && current_errno() == libc::ESRCH {
            return;
        }

        unsafe {
            libc::usleep(20_000);
        }
    }
}

fn install_parent_death_signal(owner_pid: libc::pid_t) -> Result<(), i32> {
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if ret < 0 {
        return Err(current_errno());
    }

    if unsafe { libc::getppid() } != owner_pid {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        return Err(libc::ESRCH);
    }

    Ok(())
}

fn close_parent_death_guard_child_fds((read_fd, write_fd): (i32, i32)) {
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

impl SandboxImpl for LinuxSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let trace = self.config.startup_trace.clone();
        let sandbox_id = self.config.id;
        tracing::debug!(
            "sandbox {sandbox_id}: linux isolation plan: {:?}",
            self.plan
        );
        if matches!(
            self.plan.filesystem,
            strategy::FilesystemStrategy::Bubblewrap
        ) {
            return self.start_with_bwrap();
        }
        if let strategy::NetworkStrategy::Proxy {
            setup: strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            proxy_port,
            ..
        } = self.plan.network
        {
            return self.start_with_netns_helper(proxy_port);
        }
        let resolved_identity =
            crate::sandbox::record_startup_result(&trace, "backend.preflight.identity", || {
                self.resolve_identity()
            })?;
        let tmpdir_required = landlock::policy_uses_tmpdir(&self.config.policy.filesystem);
        if let Some(identity) = &resolved_identity {
            crate::sandbox::record_startup_result(
                &trace,
                "support_files.run_as_user_workspace",
                || {
                    identity::prepare_workspace_for_identity(&self.config.workspace_dir, identity)
                        .map_err(|e| SandboxError::IsolationFailed(format!("run_as_user: {e}")))
                },
            )?;
        }
        let prepared_landlock =
            crate::sandbox::record_startup_result(&trace, "filesystem_setup.landlock", || {
                if let (Some(identity), true) = (&resolved_identity, tmpdir_required) {
                    if let Err(e) =
                        identity::create_tmpdir_for_identity(&self.config.workspace_dir, identity)
                    {
                        return Err(SandboxError::IsolationFailed(format!("run_as_user: {e}")));
                    }
                    self.tmpdir_active = true;
                    landlock::prepare_landlock_with_tmpdir_setup(
                        &self.config.policy.filesystem,
                        &self.config.workspace_dir,
                        landlock::TmpdirSetup::AlreadyPrepared,
                    )
                    .map_err(|e| {
                        let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                        append_cleanup_failure(SandboxError::IsolationFailed(e), cleanup_error)
                    })
                } else {
                    let ruleset = landlock::prepare_landlock(
                        &self.config.policy.filesystem,
                        &self.config.workspace_dir,
                    )
                    .map_err(SandboxError::IsolationFailed)?;
                    self.tmpdir_active = tmpdir_required;
                    Ok(ruleset)
                }
            })?;
        let notify_connect = self.connect_attribution_required_for_native_proxy()?;
        let seccomp_options = seccomp_options_for_network(&self.plan.network, notify_connect);
        let prepared_seccomp = match crate::sandbox::record_startup_result(
            &trace,
            "child_setup.seccomp_filter",
            || seccomp::prepare_seccomp_with_options(&self.config.policy.process, seccomp_options),
        ) {
            Ok(filter) => filter,
            Err(e) => {
                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(e),
                    cleanup_error,
                ));
            }
        };
        let mut seccomp_listener_pair = if notify_connect {
            match connect_attribution::SeccompListenerPair::new() {
                Ok(pair) => Some(pair),
                Err(e) => {
                    let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!(
                            "connect attribution listener channel: {e}"
                        )),
                        cleanup_error,
                    ));
                }
            }
        } else {
            None
        };
        let seccomp_listener_child_fd = seccomp_listener_pair
            .as_ref()
            .and_then(|pair| pair.child_fd());
        let connect_supervisor_config = if notify_connect {
            Some(connect_attribution::ConnectSupervisorConfig {
                sandbox_id,
                proxy_addr: self.config.proxy_addr.ok_or_else(|| {
                    SandboxError::IsolationFailed(
                        "connect attribution requires proxy bind address".into(),
                    )
                })?,
                store: self.config.connect_attribution.clone().ok_or_else(|| {
                    SandboxError::IsolationFailed(
                        "connect attribution requires shared attribution store".into(),
                    )
                })?,
            })
        } else {
            None
        };
        let prepared_rlimits = match crate::sandbox::record_startup_result(
            &trace,
            "resource_setup.rlimit_prepare",
            || prepare_rlimits_for_plan(&self.config.policy.process, &self.plan.resources),
        ) {
            Ok(limits) => limits,
            Err(e) => {
                let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                return Err(append_cleanup_failure(
                    SandboxError::IsolationFailed(format!("resource limits: {e}")),
                    cleanup_error,
                ));
            }
        };

        if matches!(
            self.plan.resources,
            strategy::ResourceStrategy::CgroupsV2 { .. }
        ) {
            match crate::sandbox::record_startup_result(&trace, "resource_setup.cgroup", || {
                resources::create_cgroup(sandbox_id, &self.config.policy.process)
            }) {
                Ok(cgroup) => self.cgroup = Some(cgroup),
                Err(e) => {
                    let cleanup_error = self.cleanup_tmpdir_for_setup_failure();
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("cgroup: creation failed: {e}")),
                        cleanup_error,
                    ));
                }
            }
        }

        // ── Step 1: Create network namespace (parent side) ──
        // This creates the netns, veth pair, and iptables rules.
        // The child will enter this namespace via setns() in pre_exec.
        let native_netns_proxy_port = match &self.plan.network {
            strategy::NetworkStrategy::Proxy {
                setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                proxy_port,
                ..
            } => Some(*proxy_port),
            _ => None,
        };
        let netns_fd: Option<i32> = if let Some(proxy_port) = native_netns_proxy_port {
            crate::sandbox::record_startup_result(&trace, "network_setup.netns", || {
                match netns::create_netns(sandbox_id, proxy_port) {
                    Ok(name) => {
                        self.netns_name = Some(name.clone());
                        // Open the netns fd for the child to setns() into.
                        match netns::enter_netns(&name) {
                            Ok(fd) => Ok(Some(fd)),
                            Err(e) => {
                                let cleanup_error =
                                    self.cleanup_parent_resources_after_setup_failure(None);
                                Err(append_cleanup_failure(
                                    SandboxError::IsolationFailed(format!(
                                        "netns: cannot open fd for '{name}': {e}"
                                    )),
                                    cleanup_error,
                                ))
                            }
                        }
                    }
                    Err(e) => {
                        let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                        Err(append_cleanup_failure(
                            SandboxError::IsolationFailed(format!("netns: creation failed: {e}")),
                            cleanup_error,
                        ))
                    }
                }
            })?
        } else {
            None
        };

        // ── Step 2: Build child process with pre_exec isolation ──
        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args);

        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.config.workspace_dir);
        }

        // Capture output to workspace files (daemon mode) or inherit stdio (standalone).
        if self.config.capture_output {
            cmd.stdin(std::process::Stdio::null());
            let stdout_file =
                match crate::sandbox::record_startup_result(&trace, "support_files.stdio", || {
                    std::fs::File::create(self.config.workspace_dir.join("stdout.log"))
                }) {
                    Ok(file) => file,
                    Err(e) => {
                        let cleanup_error =
                            self.cleanup_parent_resources_after_setup_failure(netns_fd);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stdout log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            let stderr_file =
                match crate::sandbox::record_startup_result(&trace, "support_files.stdio", || {
                    std::fs::File::create(self.config.workspace_dir.join("stderr.log"))
                }) {
                    Ok(file) => file,
                    Err(e) => {
                        let cleanup_error =
                            self.cleanup_parent_resources_after_setup_failure(netns_fd);
                        return Err(append_cleanup_failure(
                            SandboxError::SpawnFailed(format!("stderr log: {e}")),
                            cleanup_error,
                        ));
                    }
                };
            cmd.stdout(std::process::Stdio::from(stdout_file));
            cmd.stderr(std::process::Stdio::from(stderr_file));
        }
        // else: inherit parent's stdio (standalone/run mode)

        // Set environment.
        cmd.env_clear();
        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        apply_proxy_env_from_strategy(&mut cmd, &self.plan.proxy);

        let cgroup_procs_fd = match &self.cgroup {
            Some(cgroup) => match cgroup.open_procs_fd() {
                Ok(fd) => Some(fd),
                Err(e) => {
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!("cgroup: cannot open procs: {e}")),
                        cleanup_error,
                    ));
                }
            },
            None => None,
        };

        let parent_death_guard_pipe = match ParentDeathGuardPipe::new() {
            Ok(pipe) => pipe,
            Err(e) => {
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("parent-death guard pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let parent_death_child_fds = parent_death_guard_pipe.child_fds();
        let owner_pid = unsafe { libc::getpid() };

        // Safety: pre_exec runs after fork, before exec in the child process.
        let mut child_error_pipe = match ChildSetupErrorPipe::new() {
            Ok(pipe) => pipe,
            Err(e) => {
                close_fd(cgroup_procs_fd);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("child setup error pipe: {e}")),
                    cleanup_error,
                ));
            }
        };
        let child_error_write_fd = child_error_pipe.write_fd;
        unsafe {
            cmd.pre_exec(move || {
                // 1. Kill the sandbox child if its AXIS owner dies before normal cleanup.
                if let Err(errno) = install_parent_death_signal(owner_pid) {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::ParentDeathSignal,
                        errno,
                    ));
                }
                close_parent_death_guard_child_fds(parent_death_child_fds);

                // 2. Own process group.
                if libc::setpgid(0, 0) < 0 {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::SetProcessGroup,
                        current_errno(),
                    ));
                }

                // 3. Enter the prepared cgroup before the child can exec or fork workload code.
                if let Some(fd) = cgroup_procs_fd {
                    if let Err(errno) = enter_cgroup_from_child_fd(fd) {
                        libc::close(fd);
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::EnterCgroup,
                            errno,
                        ));
                    }
                    libc::close(fd);
                }

                // 4. Enter network namespace (if created by parent).
                if let Some(fd) = netns_fd {
                    let ret = libc::setns(fd, libc::CLONE_NEWNET);
                    libc::close(fd);
                    if ret < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::EnterNetworkNamespace,
                            current_errno(),
                        ));
                    }
                }

                // 5. Prevent SUID escalation.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::NoNewPrivs,
                        current_errno(),
                    ));
                }

                // 6. Apply Landlock filesystem policy.
                if let Err(e) = prepared_landlock.restrict_current_process() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::Landlock,
                        e,
                    ));
                }

                // 7. Drop to the configured sandbox user after Landlock setup.
                if let Some(identity) = &resolved_identity {
                    if libc::setgroups(0, std::ptr::null()) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetGroups,
                            current_errno(),
                        ));
                    }
                    if libc::setgid(identity.gid) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetGid,
                            current_errno(),
                        ));
                    }
                    if libc::setuid(identity.uid) < 0 {
                        return Err(child_setup_error(
                            child_error_write_fd,
                            ChildSetupErrorKind::SetUid,
                            current_errno(),
                        ));
                    }
                }

                // 8. Apply rlimit fallback after any UID switch.
                if let Some(limits) = prepared_rlimits
                    && let Err(errno) = apply_prepared_rlimits(limits)
                {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::ApplyResourceLimits,
                        errno,
                    ));
                }

                // 9. Drop Linux capabilities before exec so a privileged parent
                // cannot leave CAP_NET_ADMIN inside the sandbox netns.
                if let Err(errno) = drop_process_capabilities() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::DropCapabilities,
                        errno,
                    ));
                }

                // 10. Prevent inherited descriptors from surviving a successful exec.
                if let Err(errno) = mark_unexpected_child_fds_close_on_exec() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::CloseFileDescriptors,
                        errno,
                    ));
                }

                // 11. seccomp-BPF syscall filter (must be last - it restricts further syscalls).
                if let Some(listener_socket_fd) = seccomp_listener_child_fd {
                    match prepared_seccomp.apply_current_process_with_listener() {
                        Ok(listener_fd) => {
                            if let Err(errno) = connect_attribution::send_listener_fd(
                                listener_socket_fd,
                                listener_fd,
                            ) {
                                libc::close(listener_fd);
                                libc::close(listener_socket_fd);
                                return Err(child_setup_error(
                                    child_error_write_fd,
                                    ChildSetupErrorKind::Seccomp,
                                    errno,
                                ));
                            }
                            libc::close(listener_fd);
                            libc::close(listener_socket_fd);
                        }
                        Err(errno) => {
                            libc::close(listener_socket_fd);
                            return Err(child_setup_error(
                                child_error_write_fd,
                                ChildSetupErrorKind::Seccomp,
                                errno,
                            ));
                        }
                    }
                } else if let Err(e) = prepared_seccomp.apply_current_process() {
                    return Err(child_setup_error(
                        child_error_write_fd,
                        ChildSetupErrorKind::Seccomp,
                        e,
                    ));
                }

                Ok(())
            });
        }

        let mut child =
            match crate::sandbox::record_startup_result(&trace, "spawn.child", || cmd.spawn()) {
                Ok(child) => {
                    close_fd(netns_fd);
                    close_fd(cgroup_procs_fd);
                    if let Some(pair) = seccomp_listener_pair.as_mut() {
                        pair.close_child_in_parent();
                    }
                    drop(child_error_pipe);
                    child
                }
                Err(e) => {
                    close_fd(cgroup_procs_fd);
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(netns_fd);
                    return Err(append_cleanup_failure(
                        spawn_error(e, &mut child_error_pipe),
                        cleanup_error,
                    ));
                }
            };

        let pid = child.id();
        if let Some(mut pair) = seccomp_listener_pair.take() {
            let listener_fd = match crate::sandbox::record_startup_result(
                &trace,
                "child_setup_handoff.connect_attribution",
                || pair.recv_listener_fd(),
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!(
                            "connect attribution listener receive failed: {e}"
                        )),
                        cleanup_error,
                    ));
                }
            };
            let config = connect_supervisor_config
                .clone()
                .expect("connect supervisor config exists when listener pair exists");
            match crate::sandbox::record_startup_result(
                &trace,
                "post_spawn_handoff.connect_supervisor",
                || connect_attribution::ConnectAttributionSupervisor::start(listener_fd, config),
            ) {
                Ok(supervisor) => self.connect_supervisor = Some(supervisor),
                Err(e) => {
                    close_fd(Some(listener_fd));
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                    return Err(append_cleanup_failure(
                        SandboxError::IsolationFailed(format!(
                            "connect attribution supervisor failed: {e}"
                        )),
                        cleanup_error,
                    ));
                }
            }
        }
        let parent_death_guard = match crate::sandbox::record_startup_result(
            &trace,
            "post_spawn_handoff.parent_guard",
            || ParentDeathGuard::spawn_for_process_group(pid as i32, parent_death_guard_pipe),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                kill_process_group(pid as i32);
                let _ = wait_for_killed_child(&mut child, pid as i32);
                let cleanup_error = self.cleanup_parent_resources_after_setup_failure(None);
                return Err(append_cleanup_failure(
                    SandboxError::SpawnFailed(format!("parent-death guard monitor: {e}")),
                    cleanup_error,
                ));
            }
        };
        self.parent_death_guard = Some(parent_death_guard);
        self.child = Some(child);

        tracing::info!("sandbox {sandbox_id} started, pid={pid}");
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async {
            if let Some(code) = self.exit_code {
                if (self.netns_name.is_some() || self.cgroup.is_some())
                    && let Some(e) = self.cleanup_after_process_exit()
                {
                    return Err(SandboxError::IsolationFailed(format!(
                        "process cleanup failed: {e}"
                    )));
                }
                return Ok(code);
            }

            let child = self
                .child
                .take()
                .ok_or_else(|| SandboxError::SpawnFailed("no child process".into()))?;
            let pid = child.id() as i32;

            let status = match wait_child_with_timeout(child, self.config.timeout_sec).await {
                Ok(status) => status,
                Err(e) => {
                    self.exit_code = Some(-1);
                    kill_process_group(pid);
                    if let Some(cleanup_error) = self.cleanup_after_process_exit() {
                        return Err(SandboxError::IsolationFailed(format!(
                            "process cleanup failed after wait error {e}: {cleanup_error}"
                        )));
                    }
                    return Err(SandboxError::Io(e));
                }
            };
            let code = status.code().unwrap_or(-1);
            self.exit_code = Some(code);
            kill_process_group(pid);
            if let Some(e) = self.cleanup_after_process_exit() {
                return Err(SandboxError::IsolationFailed(format!(
                    "process cleanup failed: {e}"
                )));
            }
            Ok(code)
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if let Some(code) = self.exit_code {
            if (self.netns_name.is_some() || self.cgroup.is_some())
                && let Some(e) = self.cleanup_after_process_exit()
            {
                return Err(SandboxError::IsolationFailed(format!(
                    "process cleanup failed: {e}"
                )));
            }
            return Ok(Some(code));
        }

        let Some(child) = self.child.as_mut() else {
            return Err(SandboxError::SpawnFailed("no child process".into()));
        };
        let pid = child.id() as i32;
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };

        self.child.take();
        let code = status.code().unwrap_or(-1);
        self.exit_code = Some(code);
        kill_process_group(pid);
        if let Some(e) = self.cleanup_after_process_exit() {
            return Err(SandboxError::IsolationFailed(format!(
                "process cleanup failed: {e}"
            )));
        }
        Ok(Some(code))
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            // Kill both the process and its group to catch any children.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            self.exit_code = Some(wait_for_killed_child(&mut child, pid));
            kill_process_group(pid);
        }
        self.finish_parent_death_guard();
        self.stop_connect_supervisor();

        let mut cleanup_errors = Vec::new();
        if let Some(e) = self.cleanup_netns() {
            cleanup_errors.push(format!("netns cleanup failed: {e}"));
        }
        if let Some(e) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {e}"));
        }
        self.cleanup_tmpdir_after_stop();

        if !cleanup_errors.is_empty() {
            return Err(SandboxError::IsolationFailed(cleanup_errors.join("; ")));
        }

        tracing::info!("sandbox {} destroyed", self.config.id);
        Ok(())
    }
}

async fn wait_child_with_timeout(
    mut child: Child,
    timeout_sec: Option<u64>,
) -> Result<std::process::ExitStatus, io::Error> {
    let pid = child.id() as i32;
    let mut wait_task = tokio::task::spawn_blocking(move || child.wait());

    let Some(timeout_sec) = timeout_sec else {
        return join_child_wait(wait_task.await);
    };

    let timeout = tokio::time::sleep(std::time::Duration::from_secs(timeout_sec));
    tokio::pin!(timeout);
    tokio::select! {
        result = &mut wait_task => join_child_wait(result),
        _ = &mut timeout => {
            tracing::warn!("sandbox child pid={pid} exceeded timeout of {timeout_sec}s");
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            let reap_grace = std::time::Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
            match tokio::time::timeout(reap_grace, &mut wait_task).await {
                Ok(result) => join_child_wait(result),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after SIGKILL"
                    ),
                )),
            }
        }
    }
}

fn join_child_wait(
    result: Result<Result<std::process::ExitStatus, io::Error>, tokio::task::JoinError>,
) -> Result<std::process::ExitStatus, io::Error> {
    result.map_err(|e| io::Error::other(format!("wait task: {e}")))?
}

fn wait_for_killed_child(child: &mut Child, pid: i32) -> i32 {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(-1),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) => {
                tracing::warn!(
                    "sandbox child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after destroy SIGKILL"
                );
                return -1;
            }
            Err(e) => {
                tracing::warn!("sandbox child pid={pid}: wait after destroy failed: {e}");
                return -1;
            }
        }
    }
}

fn kill_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        while libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        BinaryMatch, Compatibility, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkMode, NetworkPolicy, Policy, ProcessPolicy, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::str::FromStr;

    #[test]
    fn spawn_error_maps_child_setup_pipe_failures() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let byte = ChildSetupErrorKind::Landlock as u8;
        unsafe {
            libc::write(pipe.write_fd, &byte as *const u8 as *const libc::c_void, 1);
        }
        let err = io::Error::from_raw_os_error(libc::EPERM);

        match spawn_error(err, &mut pipe) {
            SandboxError::IsolationFailed(message) => {
                assert!(message.contains("apply Landlock failed"));
            }
            other => panic!("expected IsolationFailed, got {other:?}"),
        }
    }

    #[test]
    fn spawn_error_keeps_plain_spawn_failures() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let err = io::Error::new(io::ErrorKind::NotFound, "command not found");

        match spawn_error(err, &mut pipe) {
            SandboxError::SpawnFailed(message) => {
                assert_eq!(message, "command not found");
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    #[test]
    fn real_pre_exec_failure_maps_to_isolation_failed() {
        let mut pipe = ChildSetupErrorPipe::new().unwrap();
        let write_fd = pipe.write_fd;
        let mut cmd = Command::new("true");
        unsafe {
            cmd.pre_exec(move || {
                Err(child_setup_error(
                    write_fd,
                    ChildSetupErrorKind::Seccomp,
                    libc::EPERM,
                ))
            });
        }

        let err = cmd.spawn().unwrap_err();

        match spawn_error(err, &mut pipe) {
            SandboxError::IsolationFailed(message) => {
                assert!(message.contains("apply seccomp failed"));
            }
            other => panic!("expected IsolationFailed, got {other:?}"),
        }
    }

    #[test]
    fn fd_close_on_exec_range_covers_full_descriptor_space() {
        assert_eq!(
            child_fd_close_on_exec_range(),
            (3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC)
        );
    }

    #[test]
    fn empty_capability_data_has_no_capabilities() {
        for data in empty_capability_data() {
            assert_eq!(data.effective, 0);
            assert_eq!(data.permitted, 0);
            assert_eq!(data.inheritable, 0);
        }
    }

    #[test]
    fn prepare_rlimits_converts_rlimit_fallback_policy() {
        let policy = ProcessPolicy {
            max_memory_mb: 64,
            max_processes: 9,
            ..Default::default()
        };
        let resources = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        let limits = prepare_rlimits_for_plan(&policy, &resources)
            .unwrap()
            .unwrap();

        assert_eq!(limits.address_space_bytes, Some(64 * 1024 * 1024));
        assert_eq!(limits.max_processes, Some(9));
    }

    #[test]
    fn prepare_rlimits_skips_unrequested_and_cgroup_limits() {
        let policy = ProcessPolicy::default();

        assert!(
            prepare_rlimits_for_plan(
                &policy,
                &strategy::ResourceStrategy::CgroupsV2 {
                    support: strategy::CgroupV2Support::Writable,
                },
            )
            .unwrap()
            .is_none()
        );
        assert!(
            prepare_rlimits_for_plan(
                &policy,
                &strategy::ResourceStrategy::RlimitFallback {
                    memory_limit: false,
                    process_limit: strategy::ProcessLimitFallback::NotRequested,
                    cpu_limit: strategy::CpuLimitFallback::NotRequested,
                },
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn prepare_rlimits_rejects_memory_byte_overflow() {
        let policy = ProcessPolicy {
            max_memory_mb: u64::MAX,
            ..Default::default()
        };
        let resources = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        let err = prepare_rlimits_for_plan(&policy, &resources).unwrap_err();

        assert!(err.contains("overflows"));
    }

    #[test]
    fn decimal_pid_formats_positive_pid_without_allocation() {
        let mut buffer = [0u8; 32];

        let len = decimal_pid(12345, &mut buffer);

        assert_eq!(&buffer[..len], b"12345");
    }

    #[test]
    fn capability_drop_clears_effective_caps_for_exec_target() {
        if !Path::new("/bin/sh").exists() || !Path::new("/proc/self/status").exists() {
            eprintln!("/bin/sh or /proc unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let marker_path = workspace.path().join("cap-status");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(
                "grep -E '^(CapInh|CapPrm|CapEff|CapAmb):' /proc/self/status > \"$AXIS_CAP_MARKER\"",
            )
            .env("AXIS_CAP_MARKER", &marker_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| drop_process_capabilities().map_err(io::Error::from_raw_os_error));
        }

        let status = cmd.status().unwrap();
        let cap_status = std::fs::read_to_string(marker_path).unwrap_or_default();

        assert!(status.success(), "capability status command failed");
        for label in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let expected = format!("{label}:\t0000000000000000");
            assert!(
                cap_status.contains(&expected),
                "unexpected capability status: {cap_status}"
            );
        }
    }

    #[test]
    fn close_on_exec_guard_prevents_exec_target_from_inheriting_descriptors() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let marker_path = workspace.path().join("fd-leak-marker");
        let mut marker = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&marker_path)
            .unwrap();
        let marker_fd = marker.as_raw_fd();
        clear_cloexec(marker_fd);

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("printf leaked >&{marker_fd}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(move || {
                mark_unexpected_child_fds_close_on_exec().map_err(std::io::Error::from_raw_os_error)
            });
        }

        let status = cmd.status().unwrap();
        marker.flush().unwrap();

        assert!(!status.success());
        assert_eq!(std::fs::read_to_string(marker_path).unwrap(), "");
    }

    #[test]
    fn close_on_exec_guard_preserves_std_exec_error_reporting() {
        let mut cmd = Command::new("/axis/definitely/not/a/real/program");
        unsafe {
            cmd.pre_exec(|| {
                mark_unexpected_child_fds_close_on_exec().map_err(std::io::Error::from_raw_os_error)
            });
        }

        let err = cmd.spawn().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_reaps_child_and_clears_handle() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("true").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let code_again = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(code_again, 0);
        assert!(sandbox.child.is_none());
        assert!(!tmpdir.exists());
        sandbox.destroy().unwrap();
    }

    #[test]
    fn try_wait_returns_none_for_running_child() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("sleep").arg("1").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        assert_eq!(SandboxImpl::try_wait(&mut sandbox).unwrap(), None);
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn try_wait_reaps_exited_child_and_caches_exit_code() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("true").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        let code = loop {
            if let Some(code) = SandboxImpl::try_wait(&mut sandbox).unwrap() {
                break code;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        let code_again = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(code_again, 0);
        assert!(sandbox.child.is_none());
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_kills_background_process_group_after_foreground_exit() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("background-survived");
        let id = SandboxId::new();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("(sleep 1; printf survived > \"$MARKER\") &")
            .env("MARKER", &marker);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        assert_eq!(code, 0);
        assert!(!marker.exists(), "background process survived sandbox wait");
        sandbox.destroy().unwrap();
    }

    #[test]
    fn parent_death_guard_kills_process_group_descendants_on_owner_close() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let pid_path = workspace.path().join("background.pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 30 & echo $! > \"$PID_PATH\"; wait")
            .env("PID_PATH", &pid_path);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let process_group = child.id() as libc::pid_t;

        let background_pid = wait_for_recorded_test_pid(&pid_path, &mut child, process_group);
        assert!(process_exists(background_pid));

        let pipe = ParentDeathGuardPipe::new().unwrap();
        let mut guard = ParentDeathGuard::spawn_for_process_group(process_group, pipe).unwrap();
        guard.trigger_owner_death_for_test();
        let _ = wait_for_killed_child(&mut child, process_group);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while process_exists(background_pid) {
            if std::time::Instant::now() >= deadline {
                kill_process_group(process_group);
                panic!("background process {background_pid} survived parent-death guard");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn parent_death_guard_finish_disarms_monitor_without_killing_process_group() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let pid_path = workspace.path().join("background.pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 30 & echo $! > \"$PID_PATH\"; wait")
            .env("PID_PATH", &pid_path);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let process_group = child.id() as libc::pid_t;

        let background_pid = wait_for_recorded_test_pid(&pid_path, &mut child, process_group);

        let pipe = ParentDeathGuardPipe::new().unwrap();
        let mut guard = ParentDeathGuard::spawn_for_process_group(process_group, pipe).unwrap();
        guard.finish();

        assert!(
            process_exists(background_pid),
            "normal guard finish should disarm the owner-death monitor"
        );
        kill_process_group(process_group);
        let _ = wait_for_killed_child(&mut child, process_group);
    }

    fn wait_for_recorded_test_pid(
        pid_path: &Path,
        child: &mut Child,
        process_group: libc::pid_t,
    ) -> libc::pid_t {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(contents) = std::fs::read_to_string(pid_path)
                && let Ok(pid) = contents.trim().parse::<libc::pid_t>()
                && pid > 0
            {
                return pid;
            }
            if std::time::Instant::now() >= deadline {
                kill_process_group(process_group);
                let _ = wait_for_killed_child(child, process_group);
                panic!("background pid was not recorded");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wait_enforces_timeout_and_cleans_process_group() {
        if !Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 10");
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));
        sandbox.config.timeout_sec = Some(1);

        let start = std::time::Instant::now();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, -1);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "timeout wait took too long"
        );
        sandbox.destroy().unwrap();
    }

    #[test]
    fn destroy_is_idempotent_after_killing_child() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let child = Command::new("sleep").arg("10").spawn().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), Some(child));

        sandbox.destroy().unwrap();
        assert!(sandbox.child.is_none());
        sandbox.destroy().unwrap();
    }

    #[test]
    fn cleanup_netns_preserves_name_until_destroy_succeeds() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());

        let cleanup_error = sandbox.cleanup_netns_with(|name| {
            assert_eq!(name, "axis-test-cleanup");
            Err("expected fake cleanup failure".into())
        });

        let cleanup_error = cleanup_error.expect("netns cleanup failure should be returned");
        assert!(cleanup_error.contains("expected fake cleanup failure"));
        assert_eq!(sandbox.netns_name.as_deref(), Some("axis-test-cleanup"));
        assert!(
            sandbox
                .cleanup_netns_with(|name| {
                    assert_eq!(name, "axis-test-cleanup");
                    Ok(())
                })
                .is_none()
        );
        assert!(sandbox.netns_name.is_none());
        assert!(
            sandbox
                .cleanup_netns_with(|_| panic!("cleanup must be idempotent"))
                .is_none()
        );
    }

    #[test]
    fn setup_failure_cleanup_closes_fd_and_takes_netns_name() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0);

        let cleanup_error =
            sandbox.cleanup_parent_resources_after_setup_failure_with(Some(fds[0]), |name| {
                assert_eq!(name, "axis-test-cleanup");
                Ok(())
            });

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(!tmpdir.exists());
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn setup_failure_cleanup_closes_netns_fd() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let mut fds = [0; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);

        let cleanup_error = sandbox
            .cleanup_parent_resources_after_setup_failure_with(Some(fds[0]), |_| {
                panic!("no netns cleanup should run without a netns name")
            });

        assert!(cleanup_error.is_none());
        let byte = [0u8; 1];
        let send_result = unsafe {
            libc::send(
                fds[1],
                byte.as_ptr() as *const libc::c_void,
                byte.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(send_result, -1);
        assert_eq!(current_errno(), libc::EPIPE);
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn setup_failure_cleanup_surfaces_netns_cleanup_error() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());

        let cleanup_error =
            sandbox.cleanup_parent_resources_after_setup_failure_with(None, |name| {
                assert_eq!(name, "axis-test-cleanup");
                Err("expected fake netns cleanup failure".into())
            });

        let cleanup_error = cleanup_error.expect("netns cleanup failure should be returned");
        assert!(cleanup_error.contains("netns cleanup failed"));
        assert!(cleanup_error.contains("expected fake netns cleanup failure"));
        assert_eq!(sandbox.netns_name.as_deref(), Some("axis-test-cleanup"));
    }

    #[test]
    fn process_exit_cleanup_removes_netns_and_tmpdir() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;

        let cleanup_error = sandbox.cleanup_after_process_exit_with(|name| {
            assert_eq!(name, "axis-test-cleanup");
            Ok(())
        });

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(!tmpdir.exists());
    }

    #[test]
    fn process_exit_cleanup_preserves_netns_name_when_cleanup_fails() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;

        let cleanup_error = sandbox.cleanup_after_process_exit_with(|name| {
            assert_eq!(name, "axis-test-cleanup");
            Err("expected fake netns cleanup failure".into())
        });

        let cleanup_error = cleanup_error.expect("netns cleanup failure should be returned");
        assert!(cleanup_error.contains("expected fake netns cleanup failure"));
        assert_eq!(sandbox.netns_name.as_deref(), Some("axis-test-cleanup"));
        assert!(!tmpdir.exists());
    }

    #[test]
    fn helper_token_cleanup_clears_state_when_destroy_succeeds() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token().into());

        let cleanup_error = sandbox.cleanup_netns_with_helper_token(|sandbox_id, token| {
            assert_eq!(sandbox_id, id);
            assert_eq!(token, helper_test_token());
            Ok(netns::HelperCleanupOutcome::Destroyed)
        });

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
    }

    #[test]
    fn helper_token_cleanup_accepts_authenticated_completed_outcome() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token().into());

        let cleanup_error = sandbox.cleanup_netns_with_helper_token(|_, _| {
            Ok(netns::HelperCleanupOutcome::AlreadyCompleted)
        });

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
    }

    #[test]
    fn helper_token_cleanup_preserves_state_on_real_destroy_failure() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token().into());

        let cleanup_error =
            sandbox.cleanup_netns_with_helper_token(|_, _| Err("iptables cleanup failed".into()));

        let cleanup_error = cleanup_error.expect("destroy failure should be returned");
        assert!(cleanup_error.contains("iptables cleanup failed"));
        assert_eq!(sandbox.netns_name.as_deref(), Some("axis-test-cleanup"));
        assert_eq!(
            sandbox.netns_helper_destroy_token.as_deref(),
            Some(helper_test_token())
        );
    }

    #[test]
    fn setup_failure_cleanup_uses_helper_token_cleanup_when_present() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token().into());
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();
        sandbox.tmpdir_active = true;

        let cleanup_error = sandbox.cleanup_parent_resources_after_setup_failure_with_handlers(
            None,
            |_| panic!("helper-launched sandbox must not use native netns cleanup"),
            |sandbox_id, token| {
                assert_eq!(sandbox_id, id);
                assert_eq!(token, helper_test_token());
                Ok(netns::HelperCleanupOutcome::Destroyed)
            },
        );

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
        assert!(!tmpdir.exists());
    }

    #[test]
    fn process_exit_cleanup_uses_helper_token_cleanup_when_present() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.netns_name = Some("axis-test-cleanup".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token().into());

        let cleanup_error = sandbox.cleanup_after_process_exit_with_handlers(
            |_| panic!("helper-launched sandbox must not use native netns cleanup"),
            |sandbox_id, token| {
                assert_eq!(sandbox_id, id);
                assert_eq!(token, helper_test_token());
                Ok(netns::HelperCleanupOutcome::Destroyed)
            },
        );

        assert!(cleanup_error.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
    }

    #[test]
    fn setup_failure_cleanup_surfaces_tmpdir_cleanup_error() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::write(&tmpdir, b"not a directory").unwrap();
        sandbox.tmpdir_active = true;

        let cleanup_error = sandbox.cleanup_parent_resources_after_setup_failure_with(None, |_| {
            panic!("no netns cleanup should run without a netns name")
        });

        let cleanup_error = cleanup_error.expect("tmpdir cleanup failure should be returned");
        assert!(cleanup_error.contains("cannot remove tmpdir"));
        std::fs::remove_file(&tmpdir).unwrap();
    }

    #[test]
    fn inactive_tmpdir_cleanup_does_not_remove_preexisting_path() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());
        std::fs::create_dir_all(&tmpdir).unwrap();

        sandbox.cleanup_tmpdir_after_stop();

        assert!(tmpdir.exists());
    }

    #[test]
    fn helper_launch_fds_are_made_inheritable_only_in_spawned_child() {
        if !Path::new("/proc/self/fd").exists() {
            eprintln!("/proc/self/fd unavailable (test skipped)");
            return;
        }
        let Some(shell) = find_on_path("sh").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("sh unavailable (test skipped)");
            return;
        };

        let (read_fd, write_fd) = helper_sync_pipe().unwrap();
        assert!(fd_cloexec(write_fd));

        let mut cmd = Command::new(shell);
        cmd.arg("-c")
            .arg(format!("test -e /proc/self/fd/{write_fd}"));
        configure_helper_launch_fds_for_spawn(
            &mut cmd,
            HelperLaunchFds {
                spec_fd: write_fd,
                sync_write_fd: write_fd,
                cgroup_procs_fd: None,
                mxc_config_fd: None,
            },
        );

        let status = cmd.status().unwrap();
        assert!(status.success(), "spawned child could not see helper fd");
        assert!(
            fd_cloexec(write_fd),
            "parent-side helper fd must remain close-on-exec"
        );

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    #[test]
    fn stalled_netns_helper_startup_is_terminated_and_reaped() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let started = std::time::Instant::now();

        terminate_netns_helper_startup(&mut child).unwrap();

        assert!(child.try_wait().unwrap().is_some());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn seccomp_options_follow_network_strategy() {
        assert!(
            seccomp_options_for_network(&strategy::NetworkStrategy::BlockedBySeccomp, false)
                .denies_non_unix_socket_domains()
        );
        assert!(
            !seccomp_options_for_network(&strategy::NetworkStrategy::AllowHost, false)
                .denies_non_unix_socket_domains()
        );
        assert!(
            !seccomp_options_for_network(
                &strategy::NetworkStrategy::Proxy {
                    setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                    firewall: Some(strategy::FirewallTool::Iptables),
                    host_addr: Ipv4Addr::new(10, 200, 0, 1),
                    sandbox_addr: Ipv4Addr::new(10, 200, 0, 2),
                    proxy_port: 3128,
                },
                false
            )
            .denies_non_unix_socket_domains()
        );
    }

    #[test]
    fn binary_restricted_proxy_requires_attribution_store_for_native_proxy() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000201").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy = binary_restricted_proxy_policy();
        sandbox.config.proxy_addr = Some(proxy_bind_addr(id, 3128));
        sandbox.plan.network = native_proxy_network(id, 3128);

        let err = sandbox
            .connect_attribution_required_for_native_proxy()
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::IsolationFailed(message) if message.contains("requires connect-time attribution store"))
        );
    }

    #[test]
    fn binary_restricted_proxy_allows_native_proxy_with_attribution_store() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000202").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy = binary_restricted_proxy_policy();
        sandbox.config.proxy_addr = Some(proxy_bind_addr(id, 3128));
        sandbox.config.connect_attribution =
            Some(axis_core::connect_attribution::ConnectAttributionStore::default());
        sandbox.plan.network = native_proxy_network(id, 3128);

        assert!(
            sandbox
                .connect_attribution_required_for_native_proxy()
                .unwrap()
        );
    }

    #[test]
    fn binary_restricted_native_proxy_rejects_policy_blocked_connect() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000204").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy = binary_restricted_proxy_policy();
        sandbox.config.policy.process.blocked_syscalls = vec!["connect".into()];
        sandbox.config.proxy_addr = Some(proxy_bind_addr(id, 3128));
        sandbox.config.connect_attribution =
            Some(axis_core::connect_attribution::ConnectAttributionStore::default());
        sandbox.plan.network = native_proxy_network(id, 3128);

        let err = sandbox
            .connect_attribution_required_for_native_proxy()
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::IsolationFailed(message) if message.contains("blocked_syscalls includes connect"))
        );
    }

    #[test]
    fn binary_restricted_proxy_rejects_helper_launch_without_record_channel() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000203").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy = binary_restricted_proxy_policy();
        sandbox.config.proxy_addr = Some(proxy_bind_addr(id, 3128));
        let allocation = netns::proxy_netns_allocation(id, 3128);
        sandbox.plan.network = strategy::NetworkStrategy::Proxy {
            setup: strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            firewall: Some(strategy::FirewallTool::Iptables),
            host_addr: allocation.host_addr,
            sandbox_addr: allocation.sandbox_addr,
            proxy_port: 3128,
        };

        let err = sandbox
            .connect_attribution_required_for_native_proxy()
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::IsolationFailed(message) if message.contains("axis-netns-helper launch"))
        );
    }

    #[test]
    fn start_rejects_binary_restricted_helper_launch_without_record_channel() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000205").unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy = binary_restricted_proxy_policy();
        sandbox.config.proxy_addr = Some(proxy_bind_addr(id, 3128));
        let allocation = netns::proxy_netns_allocation(id, 3128);
        sandbox.plan.network = strategy::NetworkStrategy::Proxy {
            setup: strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            firewall: Some(strategy::FirewallTool::Iptables),
            host_addr: allocation.host_addr,
            sandbox_addr: allocation.sandbox_addr,
            proxy_port: 3128,
        };

        match SandboxImpl::start(&mut sandbox) {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("axis-netns-helper launch"));
            }
            other => panic!("expected helper launch attribution rejection, got {other:?}"),
        }
    }

    #[test]
    fn helper_target_env_injects_proxy_env_from_strategy() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000111").unwrap();
        let proxy_port = 31_280;
        let allocation = netns::proxy_netns_allocation(id, proxy_port);
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.env = vec![
            ("PATH".into(), "/bin".into()),
            ("HTTP_PROXY".into(), "http://stale-proxy:1".into()),
            ("All_Proxy".into(), "http://stale-all-proxy:1".into()),
            ("ftp_proxy".into(), "http://stale-ftp-proxy:1".into()),
            ("NO_PROXY".into(), "stale-no-proxy".into()),
        ];
        sandbox.plan.proxy = strategy::ProxyStrategy::Required {
            bind_addr: allocation.host_addr,
            sandbox_addr: allocation.host_addr,
            port: proxy_port,
        };

        let env = sandbox.helper_target_env();
        let env_value = |key: &str| {
            env.iter()
                .find(|(env_key, _)| env_key == key)
                .map(|(_, value)| value.as_str())
        };
        let expected_proxy = format!("http://{}:{proxy_port}", allocation.host_addr);

        assert_eq!(env_value("PATH"), Some("/bin"));
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(env_value(key), Some(expected_proxy.as_str()), "{key}");
            assert_eq!(
                env.iter().filter(|(env_key, _)| env_key == key).count(),
                1,
                "{key} should not retain stale inherited values"
            );
        }
        for key in ["NO_PROXY", "no_proxy"] {
            assert_eq!(env_value(key), Some(NO_PROXY_VALUE), "{key}");
            assert_eq!(
                env.iter().filter(|(env_key, _)| env_key == key).count(),
                1,
                "{key} should not retain stale inherited values"
            );
        }
        assert!(
            env.iter().all(|(env_key, _)| env_key != "All_Proxy"),
            "mixed-case inherited ALL_PROXY should be stripped"
        );
        assert!(
            env.iter().all(|(env_key, _)| env_key != "ftp_proxy"),
            "inherited FTP_PROXY should be stripped"
        );
    }

    #[test]
    fn native_proxy_env_from_strategy_overrides_inherited_proxy_env() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000112").unwrap();
        let proxy_port = 31_281;
        let allocation = netns::proxy_netns_allocation(id, proxy_port);
        let proxy = strategy::ProxyStrategy::Required {
            bind_addr: allocation.host_addr,
            sandbox_addr: allocation.host_addr,
            port: proxy_port,
        };
        let mut cmd = Command::new("true");
        cmd.env("PATH", "/bin")
            .env("HTTP_PROXY", "http://stale-proxy:1")
            .env("All_Proxy", "http://stale-all-proxy:1")
            .env("ftp_proxy", "http://stale-ftp-proxy:1")
            .env("NO_PROXY", "stale-no-proxy");

        apply_proxy_env_from_strategy(&mut cmd, &proxy);

        let envs: Vec<_> = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let env_value = |key: &str| {
            envs.iter()
                .find(|(env_key, _)| env_key == key)
                .and_then(|(_, value)| value.as_deref())
        };
        let expected_proxy = format!("http://{}:{proxy_port}", allocation.host_addr);

        assert_eq!(env_value("PATH"), Some("/bin"));
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(env_value(key), Some(expected_proxy.as_str()), "{key}");
        }
        for key in ["NO_PROXY", "no_proxy"] {
            assert_eq!(env_value(key), Some(NO_PROXY_VALUE), "{key}");
        }
        assert_eq!(
            env_value("All_Proxy"),
            None,
            "mixed-case inherited ALL_PROXY should be stripped"
        );
        assert_eq!(
            env_value("ftp_proxy"),
            None,
            "inherited FTP_PROXY should be stripped"
        );
    }

    #[test]
    fn linux_sandbox_new_strips_secret_and_proxy_env() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = test_policy();
        policy.process.max_processes = 0;
        policy.process.max_memory_mb = 0;
        policy.process.cpu_rate_percent = 0;
        let config = SandboxConfig {
            id: SandboxId::from_str("00000000-0000-4000-8000-000000000113").unwrap(),
            policy,
            command: "true".into(),
            args: Vec::new(),
            working_dir: None,
            workspace_dir: workspace.path().to_path_buf(),
            env: vec![
                ("PATH".into(), "/bin".into()),
                ("ANTHROPIC_API_KEY".into(), "secret".into()),
                ("OPENAI_API_KEY".into(), "secret".into()),
                ("AZURE_STORAGE_CONNECTION_STRING".into(), "secret".into()),
                ("CLAUDE_CODE_OAUTH_TOKEN".into(), "secret".into()),
                ("All_Proxy".into(), "http://proxy-with-creds".into()),
                ("FTP_PROXY".into(), "http://ftp-proxy-with-creds".into()),
                ("CUSTOM_CONFIG".into(), "value".into()),
            ],
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: false,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: None,
            backend_preflight: Default::default(),
            startup_trace: None,
        };

        let sandbox = LinuxSandbox::new(&config).unwrap();

        assert_eq!(
            sandbox.config.env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("CUSTOM_CONFIG".into(), "value".into())
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_mode_sandbox_denies_ip_sockets_preserves_unix_and_omits_proxy_env() {
        if !contract_landlock_available() {
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&python).arg("-c").arg("pass").status() else {
            eprintln!("python3 baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("python3 baseline failed (test skipped)");
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let (inherited_socket, _peer_socket) = localhost_tcp_pair().unwrap();
        let inherited_fd = inherited_socket.as_raw_fd();
        clear_cloexec(inherited_fd);
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.command = python.to_string_lossy().into_owned();
        sandbox.config.args = vec!["-c".into(), block_mode_python_probe().into()];
        sandbox.config.capture_output = true;
        sandbox.config.env = vec![("LEAKED_FD".into(), inherited_fd.to_string())];
        sandbox.config.policy.network.mode = NetworkMode::Block;
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_only: runtime_read_only_paths_for(&python),
            ..Default::default()
        };
        sandbox.plan.network = strategy::NetworkStrategy::BlockedBySeccomp;
        sandbox.plan.proxy = strategy::ProxyStrategy::None;

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        let stderr =
            std::fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();
        assert_eq!(code, 0, "block-mode probe failed with stderr:\n{stderr}");
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_netns_helper_launch_starts_proxy_mode_sandbox_as_unprivileged_daemon() {
        if std::env::var("AXIS_TEST_NETNS_HELPER_LAUNCH").as_deref() != Ok("1") {
            eprintln!("AXIS_TEST_NETNS_HELPER_LAUNCH=1 not set (test skipped)");
            return;
        }
        if !contract_landlock_available() {
            panic!("AXIS_TEST_NETNS_HELPER_LAUNCH=1 requires Landlock ABI >= 3");
        }
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("netns helper launch proof requires non-root euid (test skipped)");
            return;
        }
        if !netns::helper_available() {
            panic!(
                "AXIS_TEST_NETNS_HELPER_LAUNCH=1 but {} is not an available setuid-root helper",
                netns::helper_path().display()
            );
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = free_tcp_port_with_adjacent_port();
        let denied_port = proxy_port + 1;
        let allocation = netns::proxy_netns_allocation(id, proxy_port);
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.command = python.to_string_lossy().into_owned();
        sandbox.config.args = vec!["-c".into(), helper_launch_probe_python().into()];
        sandbox.config.capture_output = true;
        sandbox.config.timeout_sec = Some(5);
        sandbox.config.proxy_port = proxy_port;
        sandbox.config.env = vec![
            (
                "AXIS_EXPECT_PROXY_HOST".into(),
                allocation.host_addr.to_string(),
            ),
            ("AXIS_EXPECT_PROXY_PORT".into(), proxy_port.to_string()),
            ("AXIS_DENIED_HOST_PORT".into(), denied_port.to_string()),
        ];
        sandbox.config.policy.network.mode = NetworkMode::Proxy;
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_only: runtime_read_only_paths_for(&python),
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };
        sandbox.config.policy.process.cpu_rate_percent = 0;
        sandbox.plan.network = strategy::NetworkStrategy::Proxy {
            setup: strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            firewall: Some(strategy::FirewallTool::Iptables),
            host_addr: allocation.host_addr,
            sandbox_addr: allocation.sandbox_addr,
            proxy_port,
        };
        sandbox.plan.proxy = strategy::ProxyStrategy::Required {
            bind_addr: allocation.host_addr,
            sandbox_addr: allocation.host_addr,
            port: proxy_port,
        };
        sandbox.plan.resources = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: false,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        SandboxImpl::start(&mut sandbox).unwrap();
        let helper_token = sandbox
            .netns_helper_destroy_token
            .clone()
            .expect("helper launch should record a destroy token");
        let listener = TcpListener::bind((allocation.host_addr, proxy_port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let denied_listener = TcpListener::bind((allocation.host_addr, denied_port)).unwrap();
        denied_listener.set_nonblocking(true).unwrap();
        assert!(
            listener_observed_probe(&listener),
            "host-veth proxy listener did not observe helper-launched sandbox"
        );
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr =
            std::fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "helper launch probe failed:\n{stderr}");
        assert!(
            !listener_observed_probe_with_timeout(
                &denied_listener,
                std::time::Duration::from_millis(500)
            ),
            "host-veth denied listener observed direct non-proxy egress"
        );
        assert!(workspace.path().join("helper-launch-ok").exists());
        assert_background_probe_was_terminated(workspace.path());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
        let stale_destroy = netns::destroy_netns_with_helper_token(id, &helper_token);
        assert!(stale_destroy.is_err(), "helper state survived wait");
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_bubblewrap_fallback_mounts_workspace_and_blocks_network() {
        if std::env::var("AXIS_BWRAP_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_BWRAP_TESTS=1 not set (test skipped)");
            return;
        }
        if !bwrap::available() {
            eprintln!("safe bubblewrap executable unavailable (test skipped)");
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };

        let workspace = tempfile::tempdir().unwrap();
        let inherited_file_workspace = tempfile::tempdir().unwrap();
        let inherited_file_path = inherited_file_workspace.path().join("leaked-fd");
        let inherited_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&inherited_file_path)
            .unwrap();
        let inherited_file_fd = inherited_file.as_raw_fd();
        clear_cloexec(inherited_file_fd);
        let (inherited_socket, _peer_socket) = localhost_tcp_pair().unwrap();
        let inherited_socket_fd = inherited_socket.as_raw_fd();
        clear_cloexec(inherited_socket_fd);

        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.command = python.to_string_lossy().into_owned();
        sandbox.config.args = vec!["-c".into(), bubblewrap_probe_python().into()];
        sandbox.config.capture_output = true;
        sandbox.config.env = vec![
            ("LEAKED_FD".into(), inherited_file_fd.to_string()),
            ("LEAKED_TCP_FD".into(), inherited_socket_fd.to_string()),
        ];
        sandbox.config.timeout_sec = Some(5);
        sandbox.config.policy.network.mode = NetworkMode::Block;
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_only: runtime_read_only_paths_for(&python),
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };
        sandbox.config.policy.process.cpu_rate_percent = 0;
        sandbox.plan.filesystem = strategy::FilesystemStrategy::Bubblewrap;
        sandbox.plan.network = strategy::NetworkStrategy::BlockedByBubblewrap;
        sandbox.plan.proxy = strategy::ProxyStrategy::None;
        sandbox.plan.resources = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: false,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr =
            std::fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "bubblewrap fallback probe failed:\n{stderr}");
        assert!(workspace.path().join("bwrap-ok").exists());
        assert_eq!(std::fs::read_to_string(inherited_file_path).unwrap(), "");
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_run_as_user_drops_uid_gid_and_supplementary_groups() {
        if !contract_landlock_available() {
            return;
        }
        if identity::current_euid() != 0 {
            eprintln!("run_as_user runtime test requires euid 0 (test skipped)");
            return;
        }
        let Ok(username) = std::env::var("AXIS_TEST_RUN_AS_USER") else {
            eprintln!("AXIS_TEST_RUN_AS_USER not set (test skipped)");
            return;
        };
        let target = match identity::resolve_run_as_user(&username, &identity::SystemUserLookup) {
            Ok(identity) => identity,
            Err(e) => {
                eprintln!("cannot use AXIS_TEST_RUN_AS_USER='{username}': {e} (test skipped)");
                return;
            }
        };

        let Some(shell) = find_on_path("sh").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("sh unavailable (test skipped)");
            return;
        };

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.command = shell.to_string_lossy().into_owned();
        sandbox.config.args = vec![
            "-c".into(),
            concat!(
                "id -u > uid && id -g > gid && id -G > groups && ",
                "touch run_as_user_probe || exit 1; ",
                "if ( echo leak > /tmp/axis-run-as-user-denied-$$ ) 2>/dev/null; ",
                "then exit 42; fi"
            )
            .into(),
        ];
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_only: runtime_read_only_paths_for(&shell),
            read_write: vec!["{workspace}".into(), "{tmpdir}".into()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };
        sandbox.config.policy.process.run_as_user = Some(username);
        sandbox.config.policy.process.cpu_rate_percent = 0;
        sandbox.plan.identity = strategy::IdentityStrategy::RunAsUser {
            username: target.username.clone(),
        };
        sandbox.plan.resources = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: false,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        SandboxImpl::start(&mut sandbox).unwrap();
        let workspace_meta = std::fs::metadata(workspace.path()).unwrap();
        assert_eq!(workspace_meta.uid(), target.uid);
        assert_eq!(workspace_meta.gid(), target.gid);

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("uid"))
                .unwrap()
                .trim(),
            target.uid.to_string()
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("gid"))
                .unwrap()
                .trim(),
            target.gid.to_string()
        );
        let groups = std::fs::read_to_string(workspace.path().join("groups")).unwrap();
        let target_gid = target.gid.to_string();
        assert_eq!(
            groups.split_whitespace().collect::<Vec<_>>(),
            vec![target_gid.as_str()]
        );
        assert!(workspace.path().join("run_as_user_probe").exists());
        sandbox.destroy().unwrap();
    }

    #[test]
    fn start_cleans_tmpdir_when_seccomp_policy_preparation_fails() {
        if !contract_landlock_available() {
            return;
        }

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.config.policy.filesystem = FilesystemPolicy {
            read_write: vec!["{tmpdir}".into()],
            ..Default::default()
        };
        sandbox.config.policy.process = ProcessPolicy {
            blocked_syscalls: vec!["not_a_real_syscall".into()],
            ..Default::default()
        };
        let tmpdir = landlock::sandbox_tmpdir(workspace.path());

        match SandboxImpl::start(&mut sandbox) {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("unknown syscall"));
            }
            other => panic!("expected seccomp preparation failure, got {other:?}"),
        }

        assert!(!tmpdir.exists());
        assert!(!sandbox.tmpdir_active);
    }

    fn clear_cloexec(fd: i32) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(ret, 0, "fcntl(F_SETFD) failed");
    }

    fn fd_cloexec(fd: i32) -> bool {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        flags & libc::FD_CLOEXEC != 0
    }

    fn localhost_tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    fn free_tcp_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn free_tcp_port_with_adjacent_port() -> u16 {
        loop {
            let port = free_tcp_port();
            if port < u16::MAX {
                return port;
            }
        }
    }

    fn listener_observed_probe(listener: &TcpListener) -> bool {
        listener_observed_probe_with_timeout(listener, std::time::Duration::from_secs(3))
    }

    fn listener_observed_probe_with_timeout(
        listener: &TcpListener,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((_stream, _addr)) => return true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("proxy listener accept failed: {e}"),
            }
        }
    }

    fn assert_background_probe_was_terminated(workspace: &Path) {
        verify_background_probe_terminated(workspace, std::time::Duration::from_secs(3))
            .unwrap_or_else(|error| panic!("{error}"));
    }

    fn verify_background_probe_terminated(
        workspace: &Path,
        observation_delay: std::time::Duration,
    ) -> Result<(), &'static str> {
        if !workspace.join("helper-background-started").exists() {
            return Err("helper background probe did not start");
        }
        std::thread::sleep(observation_delay);
        if workspace.join("helper-background-survived").exists() {
            Err("helper background probe survived payload cleanup")
        } else {
            Ok(())
        }
    }

    fn process_exists(pid: libc::pid_t) -> bool {
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some((_, rest)) = stat.rsplit_once(") ")
            && let Some(state) = rest.split_whitespace().next()
        {
            return state != "Z";
        }

        let ret = unsafe { libc::kill(pid, 0) };
        ret == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[test]
    fn resolve_identity_rejects_root_aliases() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.plan.identity = strategy::IdentityStrategy::RunAsUser {
            username: "root".into(),
        };

        match sandbox.resolve_identity() {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("UID or GID 0"));
            }
            other => panic!("expected UID/GID 0 rejection, got {other:?}"),
        }
    }

    #[test]
    fn resolve_identity_rejects_missing_user() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let mut sandbox = test_sandbox(id, workspace.path(), None);
        sandbox.plan.identity = strategy::IdentityStrategy::RunAsUser {
            username: format!("axis-missing-user-{id}"),
        };

        match sandbox.resolve_identity() {
            Err(SandboxError::IsolationFailed(message)) => {
                assert!(message.contains("does not exist"));
            }
            other => panic!("expected missing user rejection, got {other:?}"),
        }
    }

    fn test_sandbox(id: SandboxId, workspace: &Path, child: Option<Child>) -> LinuxSandbox {
        LinuxSandbox {
            config: SandboxConfig {
                id,
                policy: test_policy(),
                command: "true".into(),
                args: Vec::new(),
                working_dir: None,
                workspace_dir: workspace.to_path_buf(),
                env: Vec::new(),
                proxy_port: 0,
                proxy_addr: None,
                connect_attribution: None,
                capture_output: false,
                interactive_terminal: false,
                pty_bridge_helper: None,
                timeout_sec: None,
                backend_preflight: Default::default(),
                startup_trace: None,
            },
            plan: test_plan(id, workspace),
            child,
            parent_death_guard: None,
            exit_code: None,
            netns_name: None,
            netns_helper_destroy_token: None,
            cgroup: None,
            connect_supervisor: None,
            tmpdir_active: false,
        }
    }

    fn test_policy() -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Allow,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn binary_restricted_proxy_policy() -> Policy {
        let mut policy = test_policy();
        policy.network = NetworkPolicy {
            mode: NetworkMode::Proxy,
            policies: vec![EndpointPolicy {
                name: "api".into(),
                endpoints: vec![Endpoint {
                    host: "api.example.com".into(),
                    port: 443,
                    access: axis_core::policy::Access::ReadWrite,
                    protocol: None,
                    rules: Vec::new(),
                }],
                binaries: vec![BinaryMatch {
                    path: "/usr/bin/curl".into(),
                }],
            }],
        };
        policy
    }

    fn proxy_bind_addr(id: SandboxId, proxy_port: u16) -> std::net::SocketAddr {
        netns::proxy_netns_allocation(id, proxy_port).proxy_addr
    }

    fn native_proxy_network(id: SandboxId, proxy_port: u16) -> strategy::NetworkStrategy {
        let allocation = netns::proxy_netns_allocation(id, proxy_port);
        strategy::NetworkStrategy::Proxy {
            setup: strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
            firewall: Some(strategy::FirewallTool::Iptables),
            host_addr: allocation.host_addr,
            sandbox_addr: allocation.sandbox_addr,
            proxy_port,
        }
    }

    fn test_plan(id: SandboxId, workspace: &Path) -> strategy::LinuxIsolationPlan {
        strategy::LinuxIsolationPlan {
            sandbox_id: id,
            workspace_dir: workspace.to_path_buf(),
            filesystem: strategy::FilesystemStrategy::Landlock { abi: 7 },
            seccomp: strategy::SeccompStrategy::Native,
            network: strategy::NetworkStrategy::AllowHost,
            resources: strategy::ResourceStrategy::RlimitFallback {
                memory_limit: false,
                process_limit: strategy::ProcessLimitFallback::NotRequested,
                cpu_limit: strategy::CpuLimitFallback::NotRequested,
            },
            identity: strategy::IdentityStrategy::CurrentUser,
            proxy: strategy::ProxyStrategy::None,
            fallbacks: Vec::new(),
        }
    }

    fn contract_landlock_available() -> bool {
        match landlock::detect_abi_version() {
            Ok(v) if v >= 3 => true,
            Ok(v) => {
                eprintln!(
                    "Landlock ABI {v} cannot enforce the AXIS filesystem contract (test skipped)"
                );
                false
            }
            Err(e) => {
                eprintln!("Landlock not available: {e} (test skipped)");
                false
            }
        }
    }

    fn find_on_path(binary: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }

    fn runtime_read_only_paths_for(binary: &Path) -> Vec<String> {
        existing_runtime_read_only_paths(
            ["/bin", "/usr", "/lib", "/lib64", "/nix/store", "/etc"]
                .into_iter()
                .map(Path::new)
                .chain(binary.parent()),
        )
    }

    fn existing_runtime_read_only_paths<'a>(
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> Vec<String> {
        paths
            .into_iter()
            .filter(|path| path.exists())
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn runtime_read_only_fixture_uses_only_present_paths() {
        let runtime = tempfile::tempdir().unwrap();
        let missing = runtime.path().join("missing");
        let paths = existing_runtime_read_only_paths([runtime.path(), missing.as_path()]);
        assert_eq!(paths, [runtime.path().to_string_lossy().into_owned()]);
    }

    #[test]
    fn background_probe_termination_verifier_covers_all_marker_states() {
        let workspace = tempfile::tempdir().unwrap();
        let no_delay = std::time::Duration::ZERO;
        assert_eq!(
            verify_background_probe_terminated(workspace.path(), no_delay),
            Err("helper background probe did not start")
        );

        std::fs::write(
            workspace.path().join("helper-background-started"),
            "started",
        )
        .unwrap();
        assert_eq!(
            verify_background_probe_terminated(workspace.path(), no_delay),
            Ok(())
        );

        std::fs::write(
            workspace.path().join("helper-background-survived"),
            "survived",
        )
        .unwrap();
        assert_eq!(
            verify_background_probe_terminated(workspace.path(), no_delay),
            Err("helper background probe survived payload cleanup")
        );
    }

    fn helper_launch_probe_python() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys
import time

host = os.environ["AXIS_EXPECT_PROXY_HOST"]
port = int(os.environ["AXIS_EXPECT_PROXY_PORT"])
denied_port = int(os.environ["AXIS_DENIED_HOST_PORT"])
expected_proxy = f"http://{host}:{port}"
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    assert os.environ.get(key) == expected_proxy, (key, os.environ.get(key), expected_proxy)
for key in ("NO_PROXY", "no_proxy"):
    assert os.environ.get(key) == "localhost,127.0.0.1,::1", (key, os.environ.get(key))

started = pathlib.Path("helper-background-started")
survived = pathlib.Path("helper-background-survived")
foreground_done = pathlib.Path("helper-foreground-done")
pid = os.fork()
if pid == 0:
    started.write_text("started")
    while not foreground_done.exists():
        time.sleep(0.01)
    time.sleep(2)
    survived.write_text("survived")
    os._exit(0)

for _ in range(100):
    if started.exists():
        break
    time.sleep(0.01)
else:
    print("background process did not start", file=sys.stderr)
    sys.exit(39)
sock = socket.create_connection((host, port), 3)
sock.sendall(b"axis-helper-probe")
sock.close()
try:
    denied = socket.create_connection((host, denied_port), 1)
except OSError:
    pass
else:
    denied.close()
    print("direct non-proxy host-veth port was reachable", file=sys.stderr)
    sys.exit(40)
try:
    ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ipv6.settimeout(1)
    ipv6.connect(("::1", denied_port))
except OSError:
    pass
else:
    ipv6.close()
    print("IPv6 connection unexpectedly succeeded", file=sys.stderr)
    sys.exit(41)
pathlib.Path("helper-launch-ok").write_text("ok")
foreground_done.write_text("done")
"#
    }

    fn helper_test_token() -> &'static str {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    fn block_mode_python_probe() -> &'static str {
        r#"
import errno
import os
import socket
import sys

for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(10)

leaked_fd = os.environ.get("LEAKED_FD")
if leaked_fd is not None:
    try:
        os.write(int(leaked_fd), b"fd-leak")
    except OSError as exc:
        if exc.errno != errno.EBADF:
            print(f"unexpected inherited fd errno: {exc.errno}", file=sys.stderr)
            sys.exit(11)
    else:
        print("inherited fd unexpectedly remained open", file=sys.stderr)
        sys.exit(12)

for family in (socket.AF_INET, socket.AF_INET6):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            print(f"unexpected socket errno for {family}: {exc.errno}", file=sys.stderr)
            sys.exit(20)
    else:
        sock.close()
        print(f"socket unexpectedly succeeded for {family}", file=sys.stderr)
        sys.exit(21)

try:
    left, right = socket.socketpair()
except OSError as exc:
    print(f"AF_UNIX socketpair failed: {exc.errno}", file=sys.stderr)
    sys.exit(30)
else:
    left.close()
    right.close()

sys.exit(0)
"#
    }

    fn bubblewrap_probe_python() -> &'static str {
        r#"
import errno
import os
import pathlib
import socket
import sys

pathlib.Path("bwrap-ok").write_text("ok")

for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(10)

for key in ("LEAKED_FD", "LEAKED_TCP_FD"):
    leaked_fd = os.environ.get(key)
    if leaked_fd is None:
        print(f"missing {key}", file=sys.stderr)
        sys.exit(11)
    try:
        os.write(int(leaked_fd), b"fd-leak")
    except OSError as exc:
        if exc.errno != errno.EBADF:
            print(f"unexpected inherited {key} errno: {exc.errno}", file=sys.stderr)
            sys.exit(12)
    else:
        print(f"{key} unexpectedly remained open", file=sys.stderr)
        sys.exit(13)

for family in (socket.AF_INET, socket.AF_INET6):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            print(f"unexpected socket errno for {family}: {exc.errno}", file=sys.stderr)
            sys.exit(20)
    else:
        sock.close()
        print(f"socket unexpectedly succeeded for {family}", file=sys.stderr)
        sys.exit(21)

left, right = socket.socketpair()
left.close()
right.close()
"#
    }
}
