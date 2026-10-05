// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux MXC configuration translation.
//!
//! This module is the first MXC migration layer: it converts AXIS sandbox
//! policy into an AXIS-owned MXC JSON shape without changing runtime backend
//! selection. Unsupported AXIS guarantees fail before launch instead of being
//! mapped to weaker MXC behavior.

use crate::sandbox::{BackendPreflight, SandboxConfig, SandboxError, SandboxImpl};
use axis_core::capability::{DependencyState, PlannerOptions, RuntimeProbeSnapshot};
use axis_core::capability_map::{BackendCapabilityMapId, host_dependency};
use axis_core::connect_attribution::{
    ConnectAttributionStore, policy_requires_connect_attribution,
};
use axis_core::container_backend::{
    ContainerBackendFilesystemSpec, ContainerBindMount, ContainerLaunchOptions,
    ContainerMountAccess, ContainerRootfsSource, build_container_backend_execution_spec,
};
use axis_core::mxc_config as shared_mxc;
use axis_core::policy::{Compatibility, FilesystemPolicy, NetworkMode, Policy};
use axis_core::process_backend::{
    ProcessBackendFilesystemSpec, ProcessLaunchOptions, build_process_backend_execution_spec,
    plan_process_backend_policy,
};
use axis_core::types::SandboxId;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const MXC_LINUX_PLATFORM: &str = "linux";
const MXC_BUBBLEWRAP_CONTAINMENT: &str = "bubblewrap";
const MXC_LXC_CONTAINMENT: &str = "lxc";
const MXC_EXECUTOR_NAME: &str = "lxc-exec";
const MXC_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];
const AXIS_SECCOMP_LAUNCHER_NAME: &str = "axis-seccomp-launcher";
const AXIS_SECCOMP_LAUNCHER_DIRS: &[&str] = &[
    "/usr/libexec/axis",
    "/usr/local/libexec/axis",
    "/usr/lib/axis",
    "/usr/local/lib/axis",
];
const MXC_DRY_RUN_SUCCESS: &str = "Dry run completed. Result: validation passed";
const MAX_DRY_RUN_OUTPUT_BYTES: u64 = 64 * 1024;
const POST_TIMEOUT_REAP_GRACE_SEC: u64 = 5;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcTranslationError {
    #[error("MXC translation does not support AXIS proxy mode yet: {0}")]
    ProxyModeUnsupported(String),

    #[error("network endpoint policies are invalid in {mode} mode")]
    EndpointPoliciesInNonProxyMode { mode: &'static str },

    #[error("filesystem policy cannot be represented by MXC: {0}")]
    Filesystem(String),

    #[error("container launch cannot be represented by MXC LXC: {0}")]
    Container(String),

    #[error("process launch cannot be represented by MXC Bubblewrap: {0}")]
    Process(String),

    #[error(
        "MXC Bubblewrap filesystem isolation cannot preserve AXIS default-deny semantics: current MXC Bubblewrap mounts the host root read-only"
    )]
    FilesystemDefaultDenyUnsupported,

    #[error("process command must not be empty")]
    EmptyCommand,

    #[error("invalid environment variable: {0}")]
    InvalidEnv(String),

    #[error("path cannot be represented as UTF-8: {0}")]
    NonUtf8Path(String),

    #[error("timeout {seconds}s cannot be represented as MXC milliseconds")]
    TimeoutOverflow { seconds: u64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcExecutorError {
    #[error("no safe MXC executor found in eligible install locations")]
    Unavailable,

    #[error("unsafe MXC executor candidate '{}': {reason}", path.display())]
    UnsafeCandidate { path: PathBuf, reason: String },

    #[error("MXC config contains environment entry filtered by AXIS sandbox policy: {key}")]
    FilteredEnv { key: String },

    #[error("MXC config contains malformed environment entry")]
    MalformedEnv,

    #[error("failed to serialize MXC dry-run config: {0}")]
    Serialize(String),

    #[error("failed to prepare MXC dry-run config: {0}")]
    ConfigIo(String),

    #[error("failed to spawn MXC executor: {0}")]
    Spawn(String),

    #[error("MXC dry-run timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u128 },

    #[error("MXC dry-run failed with exit code {code:?}")]
    DryRunFailed { code: Option<i32> },

    #[error("MXC dry-run exited successfully without reporting validation success")]
    MalformedDryRunOutput,
}

#[derive(Debug, Error, PartialEq, Eq)]
enum MxcSeccompLauncherError {
    #[error(
        "no safe axis-seccomp-launcher found in stable install locations or beside the current executable"
    )]
    Unavailable,

    #[error("unsafe axis-seccomp-launcher candidate '{}': {reason}", path.display())]
    UnsafeCandidate { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcExecutionSpec {
    pub version: String,
    pub platform: String,
    pub containment: String,
    pub process: MxcProcess,
    pub filesystem: MxcFilesystem,
    pub network: MxcNetwork,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<MxcLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxc: Option<MxcLxcConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcExecutor {
    path: PathBuf,
    #[cfg(test)]
    injected_script: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MxcSeccompLauncher {
    path: PathBuf,
}

#[cfg(test)]
fn injected_executor_script_path(path: &Path) -> PathBuf {
    path.with_extension("axis-test-script")
}

impl MxcExecutor {
    pub fn resolve() -> Result<Self, MxcExecutorError> {
        Self::resolve_from_candidates(production_executor_candidates())
    }

    fn resolve_for_helper_launch() -> Result<Self, MxcExecutorError> {
        for candidate in helper_executor_candidates() {
            if let Ok(executor) = Self::from_helper_path(candidate) {
                return Ok(executor);
            }
        }
        Err(MxcExecutorError::Unavailable)
    }

    fn from_helper_path<P>(path: P) -> Result<Self, MxcExecutorError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_executor_path(&path, ExecutorPathMode::PrivilegedHelper)?;
        Ok(Self {
            path,
            #[cfg(test)]
            injected_script: None,
        })
    }

    pub fn resolve_from_candidates<I, P>(candidates: I) -> Result<Self, MxcExecutorError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(executor) = Self::from_path(candidate) {
                return Ok(executor);
            }
        }

        Err(MxcExecutorError::Unavailable)
    }

    pub fn from_path<P>(path: P) -> Result<Self, MxcExecutorError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_executor_path(&path, ExecutorPathMode::Production)?;
        Ok(Self {
            path,
            #[cfg(test)]
            injected_script: None,
        })
    }

    #[cfg(test)]
    fn from_injected_path<P>(path: P) -> Result<Self, MxcExecutorError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_executor_path(&path, ExecutorPathMode::TestInjected)?;
        let script = injected_executor_script_path(&path);
        let injected_script = script.is_file().then_some(script);
        Ok(Self {
            path,
            injected_script,
        })
    }

    #[cfg(test)]
    fn resolve_from_injected_candidates<I, P>(candidates: I) -> Result<Self, MxcExecutorError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(executor) = Self::from_injected_path(candidate) {
                return Ok(executor);
            }
        }

        Err(MxcExecutorError::Unavailable)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn command(&self) -> Command {
        #[cfg(test)]
        {
            let mut command = if self.injected_script.is_some() && self.path.is_file() {
                Command::new("/bin/sh")
            } else {
                Command::new(&self.path)
            };
            if let Some(script) = &self.injected_script {
                command.arg(script);
            }
            command
        }
        #[cfg(not(test))]
        {
            Command::new(&self.path)
        }
    }

    pub fn dry_run(
        &self,
        spec: &MxcExecutionSpec,
        timeout: Duration,
    ) -> Result<MxcDryRunResult, MxcExecutorError> {
        self.dry_run_with_allowed_env(spec, timeout, &[])
    }

    fn dry_run_with_allowed_env(
        &self,
        spec: &MxcExecutionSpec,
        timeout: Duration,
        allowed_proxy_env: &[(String, String)],
    ) -> Result<MxcDryRunResult, MxcExecutorError> {
        let config = self.write_private_config_with_allowed_env(spec, allowed_proxy_env)?;

        let mut stdout_file =
            tempfile::tempfile().map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let mut stderr_file =
            tempfile::tempfile().map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let stdout = stdout_file
            .try_clone()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        let stderr = stderr_file
            .try_clone()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;

        let mut command = self.command();
        command
            .arg("--experimental")
            .arg("--dry-run")
            .arg("--config")
            .arg(config.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: this pre_exec hook only calls async-signal-safe setpgid(2)
        // and returns the OS error directly when it fails.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }

        let child = command
            .spawn()
            .map_err(|err| MxcExecutorError::Spawn(err.to_string()))?;
        let status = wait_child_with_timeout(child, timeout)?;
        let stdout = read_limited_output(&mut stdout_file)?;
        let stderr = read_limited_output(&mut stderr_file)?;

        if !status.success() {
            return Err(MxcExecutorError::DryRunFailed {
                code: status.code(),
            });
        }
        if !stdout.contains(MXC_DRY_RUN_SUCCESS) {
            return Err(MxcExecutorError::MalformedDryRunOutput);
        }

        Ok(MxcDryRunResult { stdout, stderr })
    }

    fn write_private_config_with_allowed_env(
        &self,
        spec: &MxcExecutionSpec,
        allowed_proxy_env: &[(String, String)],
    ) -> Result<tempfile::NamedTempFile, MxcExecutorError> {
        validate_spec_env_for_launch(spec, allowed_proxy_env)?;

        let json =
            serde_json::to_vec(spec).map_err(|err| MxcExecutorError::Serialize(err.to_string()))?;
        let mut config = tempfile::Builder::new()
            .prefix("axis-mxc-")
            .suffix(".json")
            .tempfile()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .write_all(&json)
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        config
            .flush()
            .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
        Ok(config)
    }
}

impl MxcSeccompLauncher {
    fn resolve() -> Result<Self, MxcSeccompLauncherError> {
        Self::resolve_from_candidates(production_seccomp_launcher_candidates())
    }

    fn resolve_from_candidates<I, P>(candidates: I) -> Result<Self, MxcSeccompLauncherError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(launcher) = Self::from_path(candidate) {
                return Ok(launcher);
            }
        }

        Err(MxcSeccompLauncherError::Unavailable)
    }

    fn from_path<P>(path: P) -> Result<Self, MxcSeccompLauncherError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_safe_executable_path(&path, ExecutorPathMode::Production).map_err(|reason| {
            MxcSeccompLauncherError::UnsafeCandidate {
                path: path.clone(),
                reason,
            }
        })?;
        Ok(Self { path })
    }

    #[cfg(test)]
    fn from_injected_path<P>(path: P) -> Result<Self, MxcSeccompLauncherError>
    where
        P: Into<PathBuf>,
    {
        let path = path.into();
        validate_safe_executable_path(&path, ExecutorPathMode::TestInjected).map_err(|reason| {
            MxcSeccompLauncherError::UnsafeCandidate {
                path: path.clone(),
                reason,
            }
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcDryRunResult {
    pub stdout: String,
    pub stderr: String,
}

pub(crate) struct MxcLinuxSandbox {
    id: SandboxId,
    spec: MxcExecutionSpec,
    executor: MxcExecutor,
    resolved_identity: Option<super::identity::ResolvedIdentity>,
    process_policy: axis_core::policy::ProcessPolicy,
    filesystem_policy: axis_core::policy::FilesystemPolicy,
    network_strategy: super::strategy::NetworkStrategy,
    proxy_strategy: super::strategy::ProxyStrategy,
    resource_strategy: super::strategy::ResourceStrategy,
    notify_connect: bool,
    proxy_addr: Option<SocketAddr>,
    connect_attribution: Option<ConnectAttributionStore>,
    connect_supervisor: Option<super::connect_attribution::ConnectAttributionSupervisor>,
    child: Option<Child>,
    parent_death_guard: Option<super::ParentDeathGuard>,
    exit_code: Option<i32>,
    config_file: Option<tempfile::NamedTempFile>,
    seccomp_filter_file: Option<tempfile::NamedTempFile>,
    pty_bridge: Option<MxcPtyBridge>,
    netns_name: Option<String>,
    netns_helper_destroy_token: Option<String>,
    cgroup: Option<super::resources::CgroupHandle>,
    #[cfg(test)]
    cgroup_override: Option<super::resources::CgroupHandle>,
    #[cfg(test)]
    netns_override: Option<MxcNetnsOverride>,
    #[cfg(test)]
    netns_cleanup_result: Option<Result<(), String>>,
    workspace_dir: PathBuf,
    capture_output: bool,
    timeout_sec: Option<u64>,
    tmpdir_active: bool,
    startup_trace: Option<crate::sandbox::StartupTrace>,
}

struct MxcPtyBridge {
    runtime_parent: PathBuf,
    runtime_dir: PathBuf,
    socket_path: PathBuf,
    relay: Option<PtyRelay>,
}

struct PtyRelay {
    stop: Arc<AtomicBool>,
    socket_path: PathBuf,
    handle: thread::JoinHandle<()>,
}

#[cfg(test)]
#[derive(Debug)]
struct MxcNetnsOverride {
    name: String,
    fd: i32,
    cleanup: Result<(), String>,
}

impl MxcPtyBridge {
    fn new(id: SandboxId, workspace: &Path) -> Result<Self, SandboxError> {
        let runtime_parent = workspace.join(".axis-pty");
        let runtime_dir = runtime_parent.join(id.to_string());
        let socket_path = runtime_dir.join("stdio.sock");
        validate_unix_socket_path(&socket_path)?;
        Ok(Self {
            runtime_parent,
            runtime_dir,
            socket_path,
            relay: None,
        })
    }

    fn start(&mut self) -> Result<(), SandboxError> {
        if self.relay.is_some() {
            return Ok(());
        }

        fs::create_dir_all(&self.runtime_parent).map_err(|err| {
            SandboxError::IsolationFailed(format!(
                "MXC PTY bridge runtime parent '{}': {err}",
                self.runtime_parent.display()
            ))
        })?;
        fs::set_permissions(&self.runtime_parent, fs::Permissions::from_mode(0o700)).map_err(
            |err| {
                SandboxError::IsolationFailed(format!(
                    "MXC PTY bridge runtime parent '{}': {err}",
                    self.runtime_parent.display()
                ))
            },
        )?;
        fs::create_dir_all(&self.runtime_dir).map_err(|err| {
            SandboxError::IsolationFailed(format!(
                "MXC PTY bridge runtime dir '{}': {err}",
                self.runtime_dir.display()
            ))
        })?;
        fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700)).map_err(
            |err| {
                SandboxError::IsolationFailed(format!(
                    "MXC PTY bridge runtime dir '{}': {err}",
                    self.runtime_dir.display()
                ))
            },
        )?;
        if self.socket_path.exists() {
            fs::remove_file(&self.socket_path).map_err(|err| {
                SandboxError::IsolationFailed(format!(
                    "MXC PTY bridge stale socket '{}': {err}",
                    self.socket_path.display()
                ))
            })?;
        }
        let listener = UnixListener::bind(&self.socket_path).map_err(|err| {
            SandboxError::IsolationFailed(format!(
                "MXC PTY bridge socket '{}': {err}",
                self.socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            SandboxError::IsolationFailed(format!("MXC PTY bridge socket: {err}"))
        })?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || relay_mxc_pty(listener, thread_stop));
        self.relay = Some(PtyRelay {
            stop,
            socket_path: self.socket_path.clone(),
            handle,
        });
        Ok(())
    }

    fn cleanup(&mut self) -> Option<String> {
        if let Some(relay) = self.relay.take() {
            relay.stop();
        }
        let mut errors = Vec::new();
        match fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                errors.push(format!(
                    "remove socket '{}': {err}",
                    self.socket_path.display()
                ));
            }
        }
        match fs::remove_dir(&self.runtime_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                errors.push(format!(
                    "remove runtime dir '{}': {err}",
                    self.runtime_dir.display()
                ));
            }
        }
        match fs::remove_dir(&self.runtime_parent) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(err) => {
                errors.push(format!(
                    "remove runtime parent '{}': {err}",
                    self.runtime_parent.display()
                ));
            }
        }
        (!errors.is_empty()).then(|| errors.join("; "))
    }
}

impl PtyRelay {
    fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket_path);
        let _ = self.handle.join();
    }
}

struct RawTerminalGuard {
    fd: i32,
    original: libc::termios,
    active: bool,
}

impl RawTerminalGuard {
    fn enter(fd: i32) -> Option<Self> {
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } < 0 {
            return None;
        }
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } < 0 {
            return None;
        }
        Some(Self {
            fd,
            original,
            active: true,
        })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

fn validate_unix_socket_path(path: &Path) -> Result<(), SandboxError> {
    if path.as_os_str().as_bytes().len() >= 108 {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC PTY bridge socket path is too long for sockaddr_un: '{}'",
            path.display()
        )));
    }
    Ok(())
}

fn relay_mxc_pty(listener: UnixListener, stop: Arc<AtomicBool>) {
    let stream = loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((stream, _addr)) => break stream,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return,
        }
    };

    let _raw = RawTerminalGuard::enter(libc::STDIN_FILENO);
    let stream_fd = stream.as_raw_fd();
    let mut buf = [0u8; 8192];
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut fds = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 {
            continue;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            match read_fd(libc::STDIN_FILENO, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_all_fd(stream_fd, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            match read_fd(stream_fd, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_all_fd(libc::STDOUT_FILENO, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break;
        }
    }
}

fn read_fd(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if ret >= 0 {
            return Ok(ret as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn write_all_fd(fd: i32, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if ret >= 0 {
            if ret == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "PTY bridge write returned zero bytes",
                ));
            }
            buf = &buf[ret as usize..];
            continue;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

impl MxcLinuxSandbox {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        let trace = config.startup_trace.clone();
        crate::sandbox::record_startup_result(&trace, "support_files.workspace_dir", || {
            std::fs::create_dir_all(&config.workspace_dir)
        })?;
        Self::new_with_resolvers(
            config,
            |helper_launch| {
                let executor = if helper_launch {
                    MxcExecutor::resolve_for_helper_launch()
                } else {
                    MxcExecutor::resolve()
                };
                executor.map_err(|err| {
                    SandboxError::IsolationFailed(format!("MXC Linux executor unavailable: {err}"))
                })
            },
            || {
                MxcSeccompLauncher::resolve().map_err(|err| {
                    SandboxError::IsolationFailed(format!(
                        "MXC Linux seccomp launcher unavailable: {err}"
                    ))
                })
            },
            || resolve_mxc_network_strategy(config),
            || resolve_mxc_resource_strategy(&config.policy.process),
        )
    }

    #[cfg(test)]
    fn new_with_executor(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            |_| Ok(executor),
            || Ok(seccomp_launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        )
    }

    #[cfg(test)]
    fn new_with_executor_and_resource_strategy(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
        resource_strategy: super::strategy::ResourceStrategy,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            |_| Ok(executor),
            || Ok(seccomp_launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(resource_strategy),
        )
    }

    #[cfg(test)]
    fn new_with_executor_and_strategies(
        config: &SandboxConfig,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
        network_strategy: super::strategy::NetworkStrategy,
        proxy_strategy: super::strategy::ProxyStrategy,
        resource_strategy: super::strategy::ResourceStrategy,
    ) -> Result<Self, SandboxError> {
        Self::new_with_resolvers(
            config,
            |_| Ok(executor),
            || Ok(seccomp_launcher),
            || Ok((network_strategy, proxy_strategy)),
            || Ok(resource_strategy),
        )
    }

    #[cfg(test)]
    fn new_lxc_container_with_executor(
        config: &SandboxConfig,
        launch: ContainerLaunchOptions,
        runtime: RuntimeProbeSnapshot,
        executor: MxcExecutor,
        seccomp_launcher: MxcSeccompLauncher,
    ) -> Result<Self, SandboxError> {
        Self::new_with_spec_builder(
            config,
            |_| Ok(executor),
            || Ok(seccomp_launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
            move |config, _network_translation| {
                MxcExecutionSpec::from_lxc_container_config(config, &launch, &runtime)
            },
        )
    }

    fn new_with_resolvers<F, G, H, I>(
        config: &SandboxConfig,
        resolve_executor: F,
        resolve_seccomp_launcher: G,
        resolve_network: H,
        resolve_resources: I,
    ) -> Result<Self, SandboxError>
    where
        F: FnOnce(bool) -> Result<MxcExecutor, SandboxError>,
        G: FnOnce() -> Result<MxcSeccompLauncher, SandboxError>,
        H: FnOnce() -> Result<
            (
                super::strategy::NetworkStrategy,
                super::strategy::ProxyStrategy,
            ),
            SandboxError,
        >,
        I: FnOnce() -> Result<super::strategy::ResourceStrategy, SandboxError>,
    {
        Self::new_with_spec_builder(
            config,
            resolve_executor,
            resolve_seccomp_launcher,
            resolve_network,
            resolve_resources,
            |config, network_translation| {
                MxcExecutionSpec::from_sandbox_config_with_network_mode(config, network_translation)
            },
        )
    }

    fn new_with_spec_builder<F, G, H, I, J>(
        config: &SandboxConfig,
        resolve_executor: F,
        resolve_seccomp_launcher: G,
        resolve_network: H,
        resolve_resources: I,
        build_spec: J,
    ) -> Result<Self, SandboxError>
    where
        F: FnOnce(bool) -> Result<MxcExecutor, SandboxError>,
        G: FnOnce() -> Result<MxcSeccompLauncher, SandboxError>,
        H: FnOnce() -> Result<
            (
                super::strategy::NetworkStrategy,
                super::strategy::ProxyStrategy,
            ),
            SandboxError,
        >,
        I: FnOnce() -> Result<super::strategy::ResourceStrategy, SandboxError>,
        J: FnOnce(
            &SandboxConfig,
            MxcNetworkTranslationMode,
        ) -> Result<MxcExecutionSpec, MxcTranslationError>,
    {
        let trace = config.startup_trace.clone();
        let resolved_identity =
            crate::sandbox::record_startup_result(&trace, "backend.preflight.identity", || {
                resolve_mxc_identity(&config.policy.process)
            })?;
        let (network_strategy, proxy_strategy) = crate::sandbox::record_startup_result(
            &trace,
            "backend.preflight.network",
            resolve_network,
        )?;
        let resource_strategy = crate::sandbox::record_startup_result(
            &trace,
            "backend.preflight.resources",
            resolve_resources,
        )?;
        let notify_connect = crate::sandbox::record_startup_result(
            &trace,
            "backend.preflight.connect_attribution",
            || mxc_connect_attribution_required(config, &network_strategy),
        )?;
        crate::sandbox::record_startup_result(&trace, "backend.preflight.capability", || {
            validate_mxc_linux_capability_plan(
                config,
                &network_strategy,
                &resource_strategy,
                notify_connect,
            )
        })?;
        let mut tmpdir_active = false;
        let tmpdir_required = super::landlock::policy_uses_tmpdir(&config.policy.filesystem);
        if let Some(identity) = &resolved_identity {
            crate::sandbox::record_startup_result(
                &trace,
                "support_files.run_as_user_workspace",
                || {
                    super::identity::prepare_workspace_for_identity(&config.workspace_dir, identity)
                        .map_err(|err| {
                            SandboxError::IsolationFailed(format!("MXC run_as_user: {err}"))
                        })
                },
            )?;
            if tmpdir_required {
                crate::sandbox::record_startup_result(&trace, "support_files.tmpdir", || {
                    super::identity::create_tmpdir_for_identity(&config.workspace_dir, identity)
                        .map_err(|err| {
                            SandboxError::IsolationFailed(format!("MXC run_as_user: {err}"))
                        })
                })?;
                tmpdir_active = true;
            }
        } else if tmpdir_required {
            crate::sandbox::record_startup_result(&trace, "support_files.tmpdir", || {
                super::landlock::create_tmpdir(&config.workspace_dir)
                    .map_err(|err| SandboxError::IsolationFailed(format!("MXC tmpdir: {err}")))
            })?;
            tmpdir_active = true;
        }

        let network_translation = mxc_network_translation_mode(&network_strategy);
        let spec =
            crate::sandbox::record_startup_result(&trace, "backend.preflight.mxc_spec", || {
                build_spec(config, network_translation)
            })
            .map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(
                    SandboxError::IsolationFailed(format!("MXC Linux backend unsupported: {err}")),
                    cleanup_error,
                )
            })?;
        let mut spec = spec;
        apply_proxy_env_to_spec(&mut spec, &proxy_strategy);
        let mut launch_command = config.command.clone();
        let mut launch_args = config.args.clone();
        let pty_bridge = if config.interactive_terminal {
            match crate::sandbox::record_startup_result(&trace, "pty_setup.prepare", || {
                prepare_mxc_pty_bridge_launch(config, &mut spec)
            }) {
                Ok((bridge, command, args)) => {
                    launch_command = command;
                    launch_args = args;
                    Some(bridge)
                }
                Err(err) => {
                    let cleanup_error =
                        cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                    return Err(append_cleanup_failure(err, cleanup_error));
                }
            }
        } else {
            None
        };
        let seccomp_filter_file =
            crate::sandbox::record_startup_result(&trace, "child_setup.seccomp_launcher", || {
                prepare_mxc_seccomp_launch(
                    &config.policy,
                    &mut spec,
                    resolve_seccomp_launcher,
                    &launch_command,
                    &launch_args,
                )
            })
            .map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(err, cleanup_error)
            })?;
        if let Some(identity) = &resolved_identity {
            prepare_seccomp_filter_for_identity(&seccomp_filter_file, identity).map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(err, cleanup_error)
            })?;
        }
        let executor =
            crate::sandbox::record_startup_result(&trace, "backend.preflight.executor", || {
                resolve_executor(network_requires_helper_executor(&network_strategy))
            })
            .map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(err, cleanup_error)
            })?;
        let allowed_proxy_env = allowed_proxy_env(&proxy_strategy);
        if config.backend_preflight == BackendPreflight::DryRun {
            crate::sandbox::record_startup_result(&trace, "backend.preflight.mxc_dry_run", || {
                executor.dry_run_with_allowed_env(&spec, Duration::from_secs(5), &allowed_proxy_env)
            })
            .map_err(|err| {
                let cleanup_error =
                    cleanup_tmpdir_on_setup_failure(&config.workspace_dir, tmpdir_active);
                append_cleanup_failure(
                    SandboxError::IsolationFailed(format!(
                        "MXC Linux dry-run validation failed: {err}"
                    )),
                    cleanup_error,
                )
            })?;
        }

        Ok(Self {
            id: config.id,
            spec,
            executor,
            resolved_identity,
            process_policy: config.policy.process.clone(),
            filesystem_policy: config.policy.filesystem.clone(),
            network_strategy,
            proxy_strategy,
            resource_strategy,
            notify_connect,
            proxy_addr: config.proxy_addr,
            connect_attribution: config.connect_attribution.clone(),
            connect_supervisor: None,
            child: None,
            parent_death_guard: None,
            exit_code: None,
            config_file: None,
            seccomp_filter_file: Some(seccomp_filter_file),
            pty_bridge,
            netns_name: None,
            netns_helper_destroy_token: None,
            cgroup: None,
            #[cfg(test)]
            cgroup_override: None,
            #[cfg(test)]
            netns_override: None,
            #[cfg(test)]
            netns_cleanup_result: None,
            workspace_dir: config.workspace_dir.clone(),
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec,
            tmpdir_active,
            startup_trace: config.startup_trace.clone(),
        })
    }

    fn cleanup_after_stop(&mut self) -> Result<(), SandboxError> {
        self.stop_connect_supervisor();
        self.finish_parent_death_guard();
        self.config_file.take();
        self.seccomp_filter_file.take();
        let mut cleanup_errors = Vec::new();
        if let Some(error) = self.cleanup_netns() {
            cleanup_errors.push(format!("netns cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_pty_bridge() {
            cleanup_errors.push(format!("PTY bridge cleanup failed: {error}"));
        }
        if let Err(error) = self.cleanup_tmpdir() {
            cleanup_errors.push(format!("tmpdir cleanup failed: {error}"));
        }
        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::IsolationFailed(cleanup_errors.join("; ")))
        }
    }

    fn stop_connect_supervisor(&mut self) {
        if let Some(mut supervisor) = self.connect_supervisor.take() {
            supervisor.stop();
        }
    }

    fn finish_parent_death_guard(&mut self) {
        if let Some(mut guard) = self.parent_death_guard.take() {
            guard.finish();
        }
    }

    fn cleanup_tmpdir(&mut self) -> Result<(), SandboxError> {
        if !self.tmpdir_active {
            return Ok(());
        }
        super::landlock::cleanup_tmpdir(&self.workspace_dir)
            .map_err(|err| SandboxError::IsolationFailed(format!("MXC tmpdir cleanup: {err}")))?;
        self.tmpdir_active = false;
        Ok(())
    }

    fn cleanup_netns(&mut self) -> Option<String> {
        let ns_name = self.netns_name.clone()?;
        if self.netns_helper_destroy_token.is_some() {
            return self.cleanup_netns_with_helper_token(
                &ns_name,
                super::netns::destroy_netns_with_helper_token,
            );
        }

        #[cfg(test)]
        if let Some(result) = self.netns_cleanup_result.clone() {
            match result {
                Ok(()) => {
                    self.netns_cleanup_result = None;
                    self.netns_name = None;
                    return None;
                }
                Err(error) => {
                    tracing::warn!("failed to destroy MXC netns '{ns_name}': {error}");
                    return Some(format!("netns '{ns_name}': {error}"));
                }
            }
        }

        if let Err(error) = super::netns::destroy_netns(&ns_name) {
            tracing::warn!("failed to destroy MXC netns '{ns_name}': {error}");
            return Some(format!("netns '{ns_name}': {error}"));
        }
        self.netns_name = None;
        None
    }

    fn cleanup_netns_with_helper_token<F>(&mut self, ns_name: &str, destroy: F) -> Option<String>
    where
        F: FnOnce(SandboxId, &str) -> Result<super::netns::HelperCleanupOutcome, String>,
    {
        let token = self.netns_helper_destroy_token.clone()?;
        match destroy(self.id, &token) {
            Ok(
                super::netns::HelperCleanupOutcome::Destroyed
                | super::netns::HelperCleanupOutcome::AlreadyCompleted,
            ) => {
                self.netns_name = None;
                self.netns_helper_destroy_token = None;
                None
            }
            Err(error) => {
                tracing::warn!("failed to destroy MXC helper netns '{ns_name}': {error}");
                Some(format!("netns '{ns_name}': {error}"))
            }
        }
    }

    fn cleanup_cgroup(&mut self) -> Option<String> {
        let cgroup = self.cgroup.clone()?;
        let path = cgroup.path().to_path_buf();
        if let Err(err) = cgroup.cleanup() {
            tracing::warn!("failed to remove MXC cgroup '{}': {err}", path.display());
            return Some(format!("cgroup '{}': {err}", path.display()));
        }
        self.cgroup = None;
        None
    }

    fn cleanup_pty_bridge(&mut self) -> Option<String> {
        self.pty_bridge.as_mut().and_then(MxcPtyBridge::cleanup)
    }

    fn cleanup_for_start_failure(&mut self, error: SandboxError) -> SandboxError {
        self.cleanup_for_start_failure_with_netns_fd(None, error)
    }

    fn cleanup_for_start_failure_with_netns_fd(
        &mut self,
        netns_fd: Option<i32>,
        error: SandboxError,
    ) -> SandboxError {
        self.stop_connect_supervisor();
        self.finish_parent_death_guard();
        super::close_fd(netns_fd);
        self.config_file.take();
        self.seccomp_filter_file.take();
        let mut cleanup_errors = Vec::new();
        if let Some(error) = self.cleanup_netns() {
            cleanup_errors.push(format!("netns cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_cgroup() {
            cleanup_errors.push(format!("cgroup cleanup failed: {error}"));
        }
        if let Some(error) = self.cleanup_pty_bridge() {
            cleanup_errors.push(format!("PTY bridge cleanup failed: {error}"));
        }
        if let Err(error) = self.cleanup_tmpdir() {
            cleanup_errors.push(format!("tmpdir cleanup failed: {error}"));
        }
        append_cleanup_failure(
            error,
            (!cleanup_errors.is_empty()).then(|| cleanup_errors.join("; ")),
        )
    }

    fn create_cgroup_for_start(&mut self) -> Result<super::resources::CgroupHandle, String> {
        #[cfg(test)]
        if let Some(cgroup) = self.cgroup_override.take() {
            return Ok(cgroup);
        }

        super::resources::create_cgroup(self.id, &self.process_policy)
    }

    fn create_netns_for_start(&mut self, proxy_port: u16) -> Result<i32, String> {
        #[cfg(test)]
        if let Some(netns) = self.netns_override.take() {
            self.netns_name = Some(netns.name);
            self.netns_cleanup_result = Some(netns.cleanup);
            return Ok(netns.fd);
        }

        let name = super::netns::create_netns(self.id, proxy_port)?;
        self.netns_name = Some(name.clone());
        super::netns::enter_netns(&name)
            .map_err(|error| format!("cannot open fd for '{name}': {error}"))
    }
}

fn resolve_mxc_resource_strategy(
    policy: &axis_core::policy::ProcessPolicy,
) -> Result<super::strategy::ResourceStrategy, SandboxError> {
    let (resources, fallbacks) = super::strategy::build_resource_strategy(policy)
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC Linux resources: {err}")))?;
    for fallback in fallbacks {
        tracing::debug!(
            "MXC Linux resource fallback for {}: {}",
            fallback.area,
            fallback.reason
        );
    }
    validate_mxc_resource_strategy(policy, &resources)?;
    Ok(resources)
}

fn resolve_mxc_network_strategy(
    config: &SandboxConfig,
) -> Result<
    (
        super::strategy::NetworkStrategy,
        super::strategy::ProxyStrategy,
    ),
    SandboxError,
> {
    resolve_mxc_network_strategy_with_strict_proxy(
        config,
        |policy, sandbox_id, proxy_port, proxy_addr| {
            super::strategy::build_strict_proxy_strategy(policy, sandbox_id, proxy_port, proxy_addr)
                .map_err(|err| SandboxError::IsolationFailed(format!("MXC Linux network: {err}")))
        },
    )
}

fn resolve_mxc_network_strategy_with_strict_proxy<F>(
    config: &SandboxConfig,
    resolve_strict_proxy: F,
) -> Result<
    (
        super::strategy::NetworkStrategy,
        super::strategy::ProxyStrategy,
    ),
    SandboxError,
>
where
    F: FnOnce(
        &Policy,
        SandboxId,
        u16,
        Option<SocketAddr>,
    ) -> Result<
        (
            super::strategy::NetworkStrategy,
            super::strategy::ProxyStrategy,
        ),
        SandboxError,
    >,
{
    let (network, proxy) = match config.policy.network.mode {
        NetworkMode::Allow => {
            reject_endpoint_policies(&config.policy, "allow").map_err(|err| {
                SandboxError::IsolationFailed(format!("MXC Linux network: {err}"))
            })?;
            (
                super::strategy::NetworkStrategy::AllowHost,
                super::strategy::ProxyStrategy::None,
            )
        }
        NetworkMode::Block => {
            reject_endpoint_policies(&config.policy, "block").map_err(|err| {
                SandboxError::IsolationFailed(format!("MXC Linux network: {err}"))
            })?;
            (
                super::strategy::NetworkStrategy::BlockedBySeccomp,
                super::strategy::ProxyStrategy::None,
            )
        }
        NetworkMode::Proxy => resolve_strict_proxy(
            &config.policy,
            config.id,
            config.proxy_port,
            config.proxy_addr,
        )?,
    };

    validate_mxc_network_strategy(config, &network)?;
    Ok((network, proxy))
}

fn validate_mxc_network_strategy(
    config: &SandboxConfig,
    network: &super::strategy::NetworkStrategy,
) -> Result<(), SandboxError> {
    let super::strategy::NetworkStrategy::Proxy { setup, .. } = network else {
        return Ok(());
    };

    let _ = mxc_connect_attribution_required(config, network)?;

    match setup {
        super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin => Ok(()),
        super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch => Ok(()),
    }
}

fn network_requires_helper_executor(network: &super::strategy::NetworkStrategy) -> bool {
    matches!(
        network,
        super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            ..
        }
    )
}

fn validate_mxc_linux_capability_plan(
    config: &SandboxConfig,
    network: &super::strategy::NetworkStrategy,
    resources: &super::strategy::ResourceStrategy,
    notify_connect: bool,
) -> Result<(), SandboxError> {
    let runtime = mxc_linux_runtime_snapshot(network, resources, notify_connect);
    let plan = plan_process_backend_policy(
        &config.policy,
        BackendCapabilityMapId::MxcLinuxBubblewrap,
        &runtime,
        &PlannerOptions::new(),
    )
    .ok_or_else(|| {
        SandboxError::IsolationFailed(
            "MXC Linux bubblewrap is not registered as a process backend".into(),
        )
    })?;

    if plan.spawn_allowed() {
        return Ok(());
    }

    Err(SandboxError::IsolationFailed(format!(
        "MXC Linux capability planner rejected policy before executor invocation: {}",
        plan.pre_spawn_error()
            .unwrap_or_else(|| "unknown capability planning failure".into())
    )))
}

fn mxc_linux_runtime_snapshot(
    network: &super::strategy::NetworkStrategy,
    resources: &super::strategy::ResourceStrategy,
    notify_connect: bool,
) -> RuntimeProbeSnapshot {
    // This snapshot records dependencies already selected by AXIS strategy
    // planning before MXC config generation. Executable availability and path
    // safety are still enforced by the resolver and dry-run boundary below.
    let mut snapshot = RuntimeProbeSnapshot::new()
        .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
        .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
        .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
        .with_dependency(
            host_dependency::AXIS_SECCOMP_LAUNCHER,
            DependencyState::Present,
        );

    if notify_connect {
        snapshot = snapshot.with_dependency(
            host_dependency::LINUX_SECCOMP_NOTIFY,
            DependencyState::Present,
        );
    }

    if matches!(network, super::strategy::NetworkStrategy::Proxy { .. }) {
        snapshot = snapshot.with_dependency(
            host_dependency::LINUX_STRICT_PROXY,
            DependencyState::Present,
        );
    }

    if matches!(
        network,
        super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
            ..
        }
    ) {
        snapshot = snapshot.with_dependency(host_dependency::LINUX_NETNS, DependencyState::Present);
    }

    if matches!(
        network,
        super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            ..
        }
    ) {
        snapshot = snapshot
            .with_dependency(host_dependency::LINUX_NETNS, DependencyState::Present)
            .with_dependency(host_dependency::AXIS_NETNS_HELPER, DependencyState::Present);
    }

    if matches!(
        resources,
        super::strategy::ResourceStrategy::CgroupsV2 { .. }
    ) {
        snapshot =
            snapshot.with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);
    }

    snapshot
}

fn mxc_connect_attribution_required(
    config: &SandboxConfig,
    network: &super::strategy::NetworkStrategy,
) -> Result<bool, SandboxError> {
    if !policy_requires_connect_attribution(&config.policy) {
        return Ok(false);
    }

    match network {
        super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
            ..
        } => {
            if config
                .policy
                .process
                .blocked_syscalls
                .iter()
                .any(|name| name == "connect")
            {
                return Err(SandboxError::IsolationFailed(
                    "MXC Linux proxy mode: binary-restricted endpoint policies cannot use connect-time attribution when process.blocked_syscalls includes connect"
                        .into(),
                ));
            }
            if config.connect_attribution.is_none() {
                return Err(SandboxError::IsolationFailed(
                    "MXC Linux proxy mode: binary-restricted endpoint policies require connect-time attribution store"
                        .into(),
                ));
            }
            if config.proxy_addr.is_none() {
                return Err(SandboxError::IsolationFailed(
                    "MXC Linux proxy mode: binary-restricted endpoint policies require proxy bind address"
                        .into(),
                ));
            }
            Ok(true)
        }
        super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            ..
        } => Err(SandboxError::IsolationFailed(
            "MXC Linux proxy mode: binary-restricted endpoint policies require connect-time attribution, which is not implemented for axis-netns-helper launch"
                .into(),
        )),
        _ => Err(SandboxError::IsolationFailed(
            "MXC Linux proxy mode: binary-restricted endpoint policies require strict AXIS proxy networking"
                .into(),
        )),
    }
}

fn resolve_mxc_identity(
    policy: &axis_core::policy::ProcessPolicy,
) -> Result<Option<super::identity::ResolvedIdentity>, SandboxError> {
    let Some(username) = &policy.run_as_user else {
        return Ok(None);
    };

    super::identity::resolve_run_as_user(username, &super::identity::SystemUserLookup)
        .map(Some)
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC run_as_user: {err}")))
}

fn validate_mxc_resource_strategy(
    policy: &axis_core::policy::ProcessPolicy,
    resources: &super::strategy::ResourceStrategy,
) -> Result<(), SandboxError> {
    if let super::strategy::ResourceStrategy::RlimitFallback {
        process_limit: super::strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
        ..
    } = resources
        && policy.run_as_user.is_none()
    {
        return Err(SandboxError::IsolationFailed(
            "MXC Linux resources: process-count rlimit fallback requires a configured dedicated run_as_user"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn no_resource_limits_strategy() -> super::strategy::ResourceStrategy {
    super::strategy::ResourceStrategy::RlimitFallback {
        memory_limit: false,
        process_limit: super::strategy::ProcessLimitFallback::NotRequested,
        cpu_limit: super::strategy::CpuLimitFallback::NotRequested,
    }
}

#[cfg(test)]
fn no_proxy_network_strategy() -> (
    super::strategy::NetworkStrategy,
    super::strategy::ProxyStrategy,
) {
    (
        super::strategy::NetworkStrategy::AllowHost,
        super::strategy::ProxyStrategy::None,
    )
}

impl SandboxImpl for MxcLinuxSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        if self.child.is_some() {
            return Err(SandboxError::SpawnFailed(
                "MXC Linux backend is already running".into(),
            ));
        }

        let trace = self.startup_trace.clone();
        let allowed_proxy_env = allowed_proxy_env(&self.proxy_strategy);
        let config =
            match crate::sandbox::record_startup_result(&trace, "support_files.mxc_config", || {
                self.executor
                    .write_private_config_with_allowed_env(&self.spec, &allowed_proxy_env)
            }) {
                Ok(config) => config,
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC config: {err}"
                        ))),
                    );
                }
            };
        let prepared_rlimits = match crate::sandbox::record_startup_result(
            &trace,
            "resource_setup.rlimit_prepare",
            || super::prepare_rlimits_for_plan(&self.process_policy, &self.resource_strategy),
        ) {
            Ok(limits) => limits,
            Err(err) => {
                return Err(
                    self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                        "MXC resource limits: {err}"
                    ))),
                );
            }
        };

        if matches!(
            self.resource_strategy,
            super::strategy::ResourceStrategy::CgroupsV2 { .. }
        ) {
            match crate::sandbox::record_startup_result(&trace, "resource_setup.cgroup", || {
                self.create_cgroup_for_start()
            }) {
                Ok(cgroup) => self.cgroup = Some(cgroup),
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC cgroup: creation failed: {err}"
                        ))),
                    );
                }
            }
        }

        let cgroup_procs_fd = match &self.cgroup {
            Some(cgroup) => match cgroup.open_procs_fd() {
                Ok(fd) => Some(fd),
                Err(err) => {
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC cgroup: cannot open procs: {err}"
                        ))),
                    );
                }
            },
            None => None,
        };

        if let super::strategy::NetworkStrategy::Proxy {
            setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
            proxy_port,
            ..
        } = &self.network_strategy
        {
            return self.start_with_netns_helper(
                *proxy_port,
                config,
                prepared_rlimits,
                cgroup_procs_fd,
            );
        }

        let native_netns_proxy_port = match &self.network_strategy {
            super::strategy::NetworkStrategy::Proxy {
                setup: super::strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                proxy_port,
                ..
            } => Some(*proxy_port),
            super::strategy::NetworkStrategy::Proxy {
                setup: super::strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
                ..
            } => unreachable!("MXC helper launch is handled before native netns setup"),
            _ => None,
        };
        let netns_fd = if let Some(proxy_port) = native_netns_proxy_port {
            match crate::sandbox::record_startup_result(&trace, "network_setup.netns", || {
                self.create_netns_for_start(proxy_port)
            }) {
                Ok(fd) => Some(fd),
                Err(err) => {
                    super::close_fd(cgroup_procs_fd);
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC netns: creation failed: {err}"
                        ))),
                    );
                }
            }
        } else {
            None
        };

        let prepared_connect_notify_filter = self
            .notify_connect
            .then(super::seccomp::prepare_connect_notify_only);
        let mut seccomp_listener_pair = if self.notify_connect {
            match super::connect_attribution::SeccompListenerPair::new() {
                Ok(pair) => Some(pair),
                Err(err) => {
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure_with_netns_fd(
                        netns_fd,
                        SandboxError::IsolationFailed(format!(
                            "MXC connect attribution listener channel: {err}"
                        )),
                    ));
                }
            }
        } else {
            None
        };
        let seccomp_listener_child_fd = seccomp_listener_pair
            .as_ref()
            .and_then(|pair| pair.child_fd());
        let connect_supervisor_config = if self.notify_connect {
            let Some(proxy_addr) = self.proxy_addr else {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure_with_netns_fd(
                    netns_fd,
                    SandboxError::IsolationFailed(
                        "MXC connect attribution requires proxy bind address".into(),
                    ),
                ));
            };
            let Some(store) = self.connect_attribution.clone() else {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure_with_netns_fd(
                    netns_fd,
                    SandboxError::IsolationFailed(
                        "MXC connect attribution requires shared attribution store".into(),
                    ),
                ));
            };
            Some(super::connect_attribution::ConnectSupervisorConfig {
                sandbox_id: self.id,
                proxy_addr,
                store,
            })
        } else {
            None
        };

        let mut command = self.executor.command();
        command
            .arg("--experimental")
            .arg("--config")
            .arg(config.path())
            .current_dir(&self.workspace_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");

        if self.capture_output {
            command.stdin(Stdio::null());
            let stdout =
                match crate::sandbox::record_startup_result(&trace, "support_files.stdio", || {
                    File::create(self.workspace_dir.join("stdout.log"))
                }) {
                    Ok(stdout) => stdout,
                    Err(err) => {
                        super::close_fd(cgroup_procs_fd);
                        return Err(self.cleanup_for_start_failure_with_netns_fd(
                            netns_fd,
                            SandboxError::SpawnFailed(format!("stdout log: {err}")),
                        ));
                    }
                };
            let stderr =
                match crate::sandbox::record_startup_result(&trace, "support_files.stdio", || {
                    File::create(self.workspace_dir.join("stderr.log"))
                }) {
                    Ok(stderr) => stderr,
                    Err(err) => {
                        super::close_fd(cgroup_procs_fd);
                        return Err(self.cleanup_for_start_failure_with_netns_fd(
                            netns_fd,
                            SandboxError::SpawnFailed(format!("stderr log: {err}")),
                        ));
                    }
                };
            command.stdout(Stdio::from(stdout));
            command.stderr(Stdio::from(stderr));
        }

        if let Some(bridge) = self.pty_bridge.as_mut()
            && let Err(err) =
                crate::sandbox::record_startup_result(&trace, "pty_setup.bridge", || bridge.start())
        {
            super::close_fd(cgroup_procs_fd);
            return Err(self.cleanup_for_start_failure_with_netns_fd(netns_fd, err));
        }

        let parent_death_guard_pipe = match super::ParentDeathGuardPipe::new() {
            Ok(pipe) => pipe,
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure_with_netns_fd(
                    netns_fd,
                    SandboxError::SpawnFailed(format!("parent-death guard pipe: {err}")),
                ));
            }
        };
        let parent_death_child_fds = parent_death_guard_pipe.child_fds();
        let owner_pid = unsafe { libc::getpid() };

        let mut child_error_pipe = match super::ChildSetupErrorPipe::new() {
            Ok(pipe) => pipe,
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure_with_netns_fd(
                    netns_fd,
                    SandboxError::SpawnFailed(format!("child setup error pipe: {err}")),
                ));
            }
        };
        let child_error_write_fd = child_error_pipe.write_fd;
        let resolved_identity = self.resolved_identity.clone();
        unsafe {
            command.pre_exec(move || {
                if let Err(errno) = super::install_parent_death_signal(owner_pid) {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::ParentDeathSignal,
                        errno,
                    ));
                }
                super::close_parent_death_guard_child_fds(parent_death_child_fds);

                if libc::setpgid(0, 0) < 0 {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::SetProcessGroup,
                        super::current_errno(),
                    ));
                }

                if let Some(fd) = cgroup_procs_fd {
                    if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
                        libc::close(fd);
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::EnterCgroup,
                            errno,
                        ));
                    }
                    libc::close(fd);
                }

                if let Some(fd) = netns_fd {
                    let ret = libc::setns(fd, libc::CLONE_NEWNET);
                    libc::close(fd);
                    if ret < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::EnterNetworkNamespace,
                            super::current_errno(),
                        ));
                    }
                }

                if let Err(errno) = set_no_new_privs_for_mxc_run_as_user(resolved_identity.as_ref())
                {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::NoNewPrivs,
                        errno,
                    ));
                }

                if let Some(identity) = &resolved_identity {
                    if libc::setgroups(0, std::ptr::null()) < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::SetGroups,
                            super::current_errno(),
                        ));
                    }
                    if libc::setgid(identity.gid) < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::SetGid,
                            super::current_errno(),
                        ));
                    }
                    if libc::setuid(identity.uid) < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::SetUid,
                            super::current_errno(),
                        ));
                    }
                }

                if let Some(limits) = prepared_rlimits
                    && let Err(errno) = super::apply_prepared_rlimits(limits)
                {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::ApplyResourceLimits,
                        errno,
                    ));
                }

                if let Err(errno) = super::drop_process_capabilities() {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::DropCapabilities,
                        errno,
                    ));
                }

                if let Some(filter) = &prepared_connect_notify_filter {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                        return Err(super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::NoNewPrivs,
                            super::current_errno(),
                        ));
                    }

                    let listener_socket_fd = seccomp_listener_child_fd.ok_or_else(|| {
                        super::child_setup_error(
                            child_error_write_fd,
                            super::ChildSetupErrorKind::Seccomp,
                            libc::EBADF,
                        )
                    })?;
                    match filter.apply_current_process_with_listener() {
                        Ok(listener_fd) => {
                            if let Err(errno) = super::connect_attribution::send_listener_fd(
                                listener_socket_fd,
                                listener_fd,
                            ) {
                                libc::close(listener_fd);
                                libc::close(listener_socket_fd);
                                return Err(super::child_setup_error(
                                    child_error_write_fd,
                                    super::ChildSetupErrorKind::Seccomp,
                                    errno,
                                ));
                            }
                            libc::close(listener_fd);
                            libc::close(listener_socket_fd);
                        }
                        Err(errno) => {
                            libc::close(listener_socket_fd);
                            return Err(super::child_setup_error(
                                child_error_write_fd,
                                super::ChildSetupErrorKind::Seccomp,
                                errno,
                            ));
                        }
                    }
                }

                if let Err(errno) = super::mark_unexpected_child_fds_close_on_exec() {
                    return Err(super::child_setup_error(
                        child_error_write_fd,
                        super::ChildSetupErrorKind::CloseFileDescriptors,
                        errno,
                    ));
                }

                Ok(())
            });
        }

        let mut child = match crate::sandbox::record_startup_result(&trace, "spawn.child", || {
            command.spawn()
        }) {
            Ok(child) => {
                super::close_fd(netns_fd);
                super::close_fd(cgroup_procs_fd);
                if let Some(pair) = seccomp_listener_pair.as_mut() {
                    pair.close_child_in_parent();
                }
                drop(child_error_pipe);
                child
            }
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                let err = match super::spawn_error(err, &mut child_error_pipe) {
                    SandboxError::IsolationFailed(message) => {
                        SandboxError::IsolationFailed(format!("MXC executor setup: {message}"))
                    }
                    SandboxError::SpawnFailed(message) => {
                        SandboxError::SpawnFailed(format!("MXC executor: {message}"))
                    }
                    other => other,
                };
                return Err(self.cleanup_for_start_failure_with_netns_fd(netns_fd, err));
            }
        };
        let pid = child.id();
        let parent_death_guard =
            match crate::sandbox::record_startup_result(
                &trace,
                "post_spawn_handoff.parent_death_guard",
                || {
                    super::ParentDeathGuard::spawn_for_process_group(
                        pid as i32,
                        parent_death_guard_pipe,
                    )
                },
            ) {
                Ok(guard) => guard,
                Err(err) => {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("parent-death guard monitor: {err}"),
                    )));
                }
            };
        if let Some(mut pair) = seccomp_listener_pair.take() {
            let listener_fd = match crate::sandbox::record_startup_result(
                &trace,
                "child_setup_handoff.connect_attribution",
                || pair.recv_listener_fd(),
            ) {
                Ok(fd) => fd,
                Err(err) => {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC connect attribution listener receive failed: {err}"
                        ))),
                    );
                }
            };
            let config = connect_supervisor_config
                .clone()
                .expect("connect supervisor config exists when listener pair exists");
            match crate::sandbox::record_startup_result(
                &trace,
                "post_spawn_handoff.connect_supervisor",
                || {
                    super::connect_attribution::ConnectAttributionSupervisor::start(
                        listener_fd,
                        config,
                    )
                },
            ) {
                Ok(supervisor) => self.connect_supervisor = Some(supervisor),
                Err(err) => {
                    super::close_fd(Some(listener_fd));
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    kill_process_group(pid as i32);
                    let _ = wait_for_killed_child(&mut child, pid as i32);
                    return Err(
                        self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                            "MXC connect attribution supervisor failed: {err}"
                        ))),
                    );
                }
            }
        }
        self.config_file = Some(config);
        self.parent_death_guard = Some(parent_death_guard);
        self.child = Some(child);
        tracing::info!(
            "sandbox {} started via MXC Linux backend, pid={pid}",
            self.id
        );
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async {
            if let Some(code) = self.exit_code {
                self.cleanup_after_stop()?;
                return Ok(code);
            }

            let child = self
                .child
                .take()
                .ok_or_else(|| SandboxError::SpawnFailed("no MXC child process".into()))?;
            let pid = child.id() as i32;
            let status = match wait_runtime_child_with_timeout(child, self.timeout_sec).await {
                Ok(status) => status,
                Err(err) => {
                    self.exit_code = Some(-1);
                    if err.kind() == io::ErrorKind::TimedOut {
                        signal_process_group(pid);
                    } else {
                        kill_process_group(pid);
                    }
                    if let Err(cleanup_error) = self.cleanup_after_stop() {
                        return Err(SandboxError::IsolationFailed(format!(
                            "process cleanup failed after wait error {err}: {cleanup_error}"
                        )));
                    }
                    return Err(SandboxError::Io(err));
                }
            };
            let code = status.code().unwrap_or(-1);
            self.exit_code = Some(code);
            kill_process_group(pid);
            self.cleanup_after_stop()?;
            Ok(code)
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if let Some(code) = self.exit_code {
            self.cleanup_after_stop()?;
            return Ok(Some(code));
        }

        let Some(child) = self.child.as_mut() else {
            return Err(SandboxError::SpawnFailed("no MXC child process".into()));
        };
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };

        let pid = child.id() as i32;
        self.child.take();
        let code = status.code().unwrap_or(-1);
        self.exit_code = Some(code);
        kill_process_group(pid);
        self.cleanup_after_stop()?;
        Ok(Some(code))
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::kill(-pid, libc::SIGKILL);
            }
            self.exit_code = Some(wait_for_killed_child(&mut child, pid));
            kill_process_group(pid);
        }
        self.cleanup_after_stop()?;
        tracing::info!("sandbox {} destroyed via MXC Linux backend", self.id);
        Ok(())
    }
}

impl MxcLinuxSandbox {
    fn start_with_netns_helper(
        &mut self,
        proxy_port: u16,
        config: tempfile::NamedTempFile,
        prepared_rlimits: Option<super::PreparedRlimits>,
        cgroup_procs_fd: Option<i32>,
    ) -> Result<u32, SandboxError> {
        if self.notify_connect {
            super::close_fd(cgroup_procs_fd);
            return Err(
                self.cleanup_for_start_failure(SandboxError::IsolationFailed(
                    "MXC helper launch cannot provide connect-time attribution yet".into(),
                )),
            );
        }
        if self.process_policy.run_as_user.is_some() {
            super::close_fd(cgroup_procs_fd);
            return Err(
                self.cleanup_for_start_failure(SandboxError::IsolationFailed(
                    "MXC helper launch with run_as_user is not implemented yet".into(),
                )),
            );
        }
        if super::landlock::policy_uses_tmpdir(&self.filesystem_policy) {
            super::close_fd(cgroup_procs_fd);
            return Err(
                self.cleanup_for_start_failure(SandboxError::IsolationFailed(
                    "MXC helper launch with {tmpdir} filesystem policy is not implemented yet"
                        .into(),
                )),
            );
        }

        let config_fd = match sealed_mxc_config_fd(&config) {
            Ok(fd) => fd,
            Err(err) => {
                super::close_fd(cgroup_procs_fd);
                return Err(self.cleanup_for_start_failure(err));
            }
        };

        let destroy_token = super::netns::new_destroy_token();
        let helper_spec =
            match self.mxc_helper_launch_spec(config_fd, prepared_rlimits, destroy_token.clone()) {
                Ok(spec) => spec,
                Err(err) => {
                    super::close_fd(Some(config_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(err);
                }
            };
        let spec_fd = match super::netns::create_launch_spec_fd(&helper_spec) {
            Ok(fd) => fd,
            Err(err) => {
                super::close_fd(Some(config_fd));
                super::close_fd(cgroup_procs_fd);
                return Err(
                    self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                        "MXC helper launch spec: {err}"
                    ))),
                );
            }
        };
        let (sync_read_fd, sync_write_fd) =
            match super::helper_sync_pipe() {
                Ok(fds) => fds,
                Err(err) => {
                    super::close_fd(Some(spec_fd));
                    super::close_fd(Some(config_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("MXC helper sync pipe: {err}"),
                    )));
                }
            };
        let mut owner_guard =
            match super::NetnsHelperOwnerPidFd::new() {
                Ok(guard) => guard,
                Err(err) => {
                    super::close_fd(Some(spec_fd));
                    super::close_fd(Some(config_fd));
                    super::close_fd(Some(sync_read_fd));
                    super::close_fd(Some(sync_write_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("MXC helper owner pidfd: {err}"),
                    )));
                }
            };

        let allocation = super::netns::proxy_netns_allocation(self.id, proxy_port);
        let mut command = Command::new(super::netns::helper_path());
        let helper_args = [
            "launch".to_string(),
            self.id.to_string(),
            proxy_port.to_string(),
            spec_fd.to_string(),
            sync_write_fd.to_string(),
            cgroup_procs_fd
                .map(|fd| fd.to_string())
                .unwrap_or_else(|| "-1".into()),
            owner_guard.fd().to_string(),
        ];
        command.args(helper_args);
        command.current_dir(&self.workspace_dir);
        command.env_clear();

        if self.capture_output {
            command.stdin(Stdio::null());
            let stdout = match File::create(self.workspace_dir.join("stdout.log")) {
                Ok(stdout) => stdout,
                Err(err) => {
                    super::close_fd(Some(spec_fd));
                    super::close_fd(Some(config_fd));
                    super::close_fd(Some(sync_read_fd));
                    super::close_fd(Some(sync_write_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("stdout log: {err}"),
                    )));
                }
            };
            let stderr = match File::create(self.workspace_dir.join("stderr.log")) {
                Ok(stderr) => stderr,
                Err(err) => {
                    super::close_fd(Some(spec_fd));
                    super::close_fd(Some(config_fd));
                    super::close_fd(Some(sync_read_fd));
                    super::close_fd(Some(sync_write_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("stderr log: {err}"),
                    )));
                }
            };
            command.stdout(Stdio::from(stdout));
            command.stderr(Stdio::from(stderr));
        }

        if let Some(bridge) = self.pty_bridge.as_mut()
            && let Err(err) = bridge.start()
        {
            super::close_fd(Some(spec_fd));
            super::close_fd(Some(config_fd));
            super::close_fd(Some(sync_read_fd));
            super::close_fd(Some(sync_write_fd));
            super::close_fd(cgroup_procs_fd);
            return Err(self.cleanup_for_start_failure(err));
        }

        super::configure_helper_launch_fds_for_spawn(
            &mut command,
            super::HelperLaunchFds {
                spec_fd,
                sync_write_fd,
                cgroup_procs_fd,
                mxc_config_fd: Some(config_fd),
            },
        );
        owner_guard.configure_command(&mut command);

        let mut child =
            match command.spawn() {
                Ok(child) => child,
                Err(err) => {
                    super::close_fd(Some(spec_fd));
                    super::close_fd(Some(config_fd));
                    super::close_fd(Some(sync_read_fd));
                    super::close_fd(Some(sync_write_fd));
                    super::close_fd(cgroup_procs_fd);
                    return Err(self.cleanup_for_start_failure(SandboxError::SpawnFailed(
                        format!("MXC netns helper: {err}"),
                    )));
                }
            };

        owner_guard.spawned();

        super::close_fd(Some(spec_fd));
        super::close_fd(Some(config_fd));
        super::close_fd(Some(sync_write_fd));
        super::close_fd(cgroup_procs_fd);

        self.netns_name = Some(allocation.namespace);
        self.netns_helper_destroy_token = Some(destroy_token);

        if let Err(err) = super::netns::read_helper_sync(sync_read_fd) {
            let termination_error = super::terminate_netns_helper_startup(&mut child)
                .err()
                .map(|error| format!("helper termination failed: {error}"));
            let error = self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                "MXC netns helper setup failed: {err}"
            )));
            return Err(match termination_error {
                Some(cleanup) => append_cleanup_failure(error, Some(cleanup)),
                None => error,
            });
        }

        let pid = child.id();
        self.config_file = Some(config);
        self.child = Some(child);
        tracing::info!(
            "sandbox {} started via MXC Linux helper backend, pid={pid}",
            self.id
        );
        Ok(pid)
    }

    fn mxc_helper_launch_spec(
        &mut self,
        config_fd: i32,
        prepared_rlimits: Option<super::PreparedRlimits>,
        destroy_token: String,
    ) -> Result<super::netns::HelperLaunchSpec, SandboxError> {
        if config_fd < 3 {
            return Err(
                self.cleanup_for_start_failure(SandboxError::IsolationFailed(
                    "MXC helper config fd must be an inherited fd >= 3".into(),
                )),
            );
        }
        let executor_path = path_to_string(self.executor.path()).map_err(|err| {
            self.cleanup_for_start_failure(SandboxError::IsolationFailed(format!(
                "MXC helper executor path: {err}"
            )))
        })?;
        Ok(super::netns::HelperLaunchSpec {
            launch_kind: super::netns::HelperLaunchKind::MxcExecutor,
            mxc_config_fd: Some(config_fd),
            workspace_dir: self.workspace_dir.clone(),
            filesystem: self.filesystem_policy.clone(),
            process: self.process_policy.clone(),
            rlimits: super::helper_rlimits_from_prepared(prepared_rlimits),
            command: executor_path,
            args: vec![
                "--experimental".into(),
                "--config".into(),
                format!("/proc/self/fd/{config_fd}"),
            ],
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LC_ALL".into(), "C".into()),
            ],
            destroy_token,
        })
    }
}

fn sealed_mxc_config_fd(config: &tempfile::NamedTempFile) -> Result<i32, SandboxError> {
    let mut config_file = config.as_file().try_clone().map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC helper config clone failed: {err}"))
    })?;
    config_file.seek(SeekFrom::Start(0)).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC helper config rewind failed: {err}"))
    })?;
    let mut bytes = Vec::new();
    config_file.read_to_end(&mut bytes).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC helper config read failed: {err}"))
    })?;
    super::netns::create_mxc_config_fd(&bytes)
        .and_then(ensure_mxc_config_fd_above_stdio)
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC config seal: {err}")))
}

fn ensure_mxc_config_fd_above_stdio(fd: i32) -> Result<i32, String> {
    if fd >= 3 {
        return Ok(fd);
    }

    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    unsafe {
        libc::close(fd);
    }
    if duplicated < 0 {
        Err(format!(
            "MXC config fd duplicate failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(duplicated)
    }
}

fn set_no_new_privs_for_mxc_run_as_user(
    identity: Option<&super::identity::ResolvedIdentity>,
) -> Result<(), i32> {
    if identity.is_none() {
        return Ok(());
    }

    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        Err(super::current_errno())
    } else {
        Ok(())
    }
}

impl MxcExecutionSpec {
    pub fn from_sandbox_config(config: &SandboxConfig) -> Result<Self, MxcTranslationError> {
        Self::from_sandbox_config_with_network_mode(config, MxcNetworkTranslationMode::Standalone)
    }

    pub fn from_lxc_container_config(
        config: &SandboxConfig,
        launch: &ContainerLaunchOptions,
        runtime: &RuntimeProbeSnapshot,
    ) -> Result<Self, MxcTranslationError> {
        translate_lxc_container_config(config, launch, runtime)
    }

    fn from_sandbox_config_with_network_mode(
        config: &SandboxConfig,
        network_mode: MxcNetworkTranslationMode,
    ) -> Result<Self, MxcTranslationError> {
        let translated = translate_sandbox_config_with_metadata(config, network_mode)?;
        validate_current_bubblewrap_filesystem_substrate(
            translated.root_read_substrate_acknowledged,
        )?;
        Ok(translated.spec)
    }
}

#[cfg(test)]
fn translate_sandbox_config(
    config: &SandboxConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    Ok(translate_sandbox_config_with_metadata(config, MxcNetworkTranslationMode::Standalone)?.spec)
}

#[cfg(test)]
pub(crate) fn translate_sandbox_config_for_test(
    config: &SandboxConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    translate_sandbox_config(config)
}

struct MxcTranslatedConfig {
    spec: MxcExecutionSpec,
    root_read_substrate_acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MxcNetworkTranslationMode {
    Standalone,
    StrictProxyEnforcedByAxis,
}

struct MxcTranslatedFilesystem {
    filesystem: MxcFilesystem,
    root_read_substrate_acknowledged: bool,
}

fn translate_sandbox_config_with_metadata(
    config: &SandboxConfig,
    network_mode: MxcNetworkTranslationMode,
) -> Result<MxcTranslatedConfig, MxcTranslationError> {
    let process = translate_process(config)?;
    let network = translate_network(&config.policy, network_mode)?;
    let filesystem = translate_filesystem(&config.policy.filesystem, &config.workspace_dir)?;
    let mut spec = build_process_backend_execution_spec(
        &config.policy,
        BackendCapabilityMapId::MxcLinuxBubblewrap,
        process_launch_options_from_translated(config, &process)?,
        &mxc_process_config_runtime_snapshot(network_mode),
        &PlannerOptions::new(),
    )
    .map_err(process_spec_error)?;
    spec.filesystem = process_filesystem_spec_from_mxc(&filesystem.filesystem);
    spec.timeout_ms = process.timeout.map(u64::from);

    let wire = shared_mxc::build_mxc_process_config(
        process.command_line.clone(),
        &spec,
        shared_mxc::MxcProcessConfigOptions {
            strict_proxy_enforced_by_axis: network_mode
                == MxcNetworkTranslationMode::StrictProxyEnforcedByAxis,
            cooperative_proxy_configured_by_mxc: false,
            resource_limits_enforced_by_axis: true,
            ..Default::default()
        },
    )
    .map_err(|err| MxcTranslationError::Process(err.to_string()))?;
    let mut translated_spec = mxc_execution_spec_from_process_wire(wire)?;
    translated_spec.process.env = process.env;
    translated_spec.network = network;

    Ok(MxcTranslatedConfig {
        spec: translated_spec,
        root_read_substrate_acknowledged: filesystem.root_read_substrate_acknowledged,
    })
}

fn translate_lxc_container_config(
    config: &SandboxConfig,
    launch: &ContainerLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    let mut spec = build_container_backend_execution_spec(
        &config.policy,
        BackendCapabilityMapId::MxcLinuxLxc,
        launch.clone(),
        runtime,
        &PlannerOptions::new(),
    )
    .map_err(lxc_spec_error)?;

    validate_lxc_launch_options(launch)?;

    if matches!(config.policy.network.mode, NetworkMode::Proxy) {
        return Err(MxcTranslationError::ProxyModeUnsupported(
            "MXC LXC config generation cannot preserve AXIS strict proxy isolation until AXIS owns the LXC network namespace proxy path".into(),
        ));
    }

    let mut process = translate_process(config)?;
    if let Some(working_dir) = &launch.working_dir {
        process.cwd = working_dir.clone();
    }

    validate_lxc_filesystem_policy(&config.policy.filesystem)?;
    let filesystem = translate_filesystem(&config.policy.filesystem, &config.workspace_dir)?;
    validate_lxc_bind_mounts(launch, &filesystem.filesystem)?;
    spec.filesystem = container_filesystem_spec_from_mxc(&filesystem.filesystem);

    let wire = shared_mxc::build_mxc_container_config(
        mxc_process_config_from_translated(&process),
        &spec,
        shared_mxc::MxcContainerConfigOptions {
            resource_limits_enforced_by_axis: true,
            ..Default::default()
        },
    )
    .map_err(|err| MxcTranslationError::Container(err.to_string()))?;
    mxc_execution_spec_from_container_wire(wire)
}

fn lxc_spec_error(
    error: axis_core::container_backend::ContainerBackendSpecError,
) -> MxcTranslationError {
    MxcTranslationError::Container(format!(
        "container backend plan rejected launch before spawn: {error}"
    ))
}

fn process_spec_error(
    error: axis_core::process_backend::ProcessBackendSpecError,
) -> MxcTranslationError {
    MxcTranslationError::Process(format!(
        "process backend plan rejected launch before spawn: {error}"
    ))
}

fn container_filesystem_spec_from_mxc(
    filesystem: &MxcFilesystem,
) -> ContainerBackendFilesystemSpec {
    ContainerBackendFilesystemSpec {
        read_only: filesystem.readonly_paths.clone(),
        read_write: filesystem.readwrite_paths.clone(),
        deny: filesystem.denied_paths.clone(),
    }
}

fn process_filesystem_spec_from_mxc(filesystem: &MxcFilesystem) -> ProcessBackendFilesystemSpec {
    ProcessBackendFilesystemSpec {
        read_only: filesystem.readonly_paths.clone(),
        read_write: filesystem.readwrite_paths.clone(),
        deny: filesystem.denied_paths.clone(),
    }
}

fn mxc_process_config_from_translated(process: &MxcProcess) -> shared_mxc::MxcProcessConfig {
    shared_mxc::MxcProcessConfig {
        command_line: process.command_line.clone(),
        cwd: Some(process.cwd.clone()),
        env: process.env.clone(),
        timeout: process.timeout,
    }
}

fn process_launch_options_from_translated(
    config: &SandboxConfig,
    process: &MxcProcess,
) -> Result<ProcessLaunchOptions, MxcTranslationError> {
    Ok(ProcessLaunchOptions {
        command: config.command.clone(),
        args: config.args.clone(),
        working_dir: Some(process.cwd.clone()),
        environment: process_environment_from_mxc(&process.env)?,
        capture_output: config.capture_output,
        timeout_sec: config.timeout_sec,
    })
}

fn process_environment_from_mxc(
    env: &[String],
) -> Result<BTreeMap<String, String>, MxcTranslationError> {
    let mut environment = BTreeMap::new();
    for entry in env {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(MxcTranslationError::InvalidEnv(entry.clone()));
        };
        if key.trim().is_empty() {
            return Err(MxcTranslationError::InvalidEnv(key.into()));
        }
        environment.insert(key.into(), value.into());
    }
    Ok(environment)
}

fn mxc_process_config_runtime_snapshot(
    network_mode: MxcNetworkTranslationMode,
) -> RuntimeProbeSnapshot {
    // Spawn-time capability planning uses the strategy-selected runtime
    // snapshot. Config translation keeps this side-effect-free snapshot so
    // serializer tests do not probe or mutate the host.
    let mut runtime = RuntimeProbeSnapshot::new()
        .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
        .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
        .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
        .with_dependency(
            host_dependency::AXIS_SECCOMP_LAUNCHER,
            DependencyState::Present,
        )
        .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present);

    if network_mode == MxcNetworkTranslationMode::StrictProxyEnforcedByAxis {
        runtime = runtime
            .with_dependency(
                host_dependency::LINUX_STRICT_PROXY,
                DependencyState::Present,
            )
            .with_dependency(host_dependency::LINUX_NETNS, DependencyState::Present)
            .with_dependency(
                host_dependency::LINUX_SECCOMP_NOTIFY,
                DependencyState::Present,
            )
            .with_dependency(host_dependency::AXIS_NETNS_HELPER, DependencyState::Present);
    }

    runtime
}

fn mxc_execution_spec_from_process_wire(
    wire: shared_mxc::MxcProcessWireConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    if wire.platform != shared_mxc::MxcPlatform::Linux
        || wire.containment != shared_mxc::MxcContainment::Bubblewrap
    {
        return Err(MxcTranslationError::Process(
            "Linux MXC adapter can only execute MXC Bubblewrap process wire configs".into(),
        ));
    }
    if wire.process_container.is_some() || wire.fallback.is_some() || wire.experimental.is_some() {
        return Err(MxcTranslationError::Process(
            "MXC Bubblewrap process wire config contains foreign backend sections".into(),
        ));
    }

    Ok(MxcExecutionSpec {
        version: wire.version,
        platform: MXC_LINUX_PLATFORM.into(),
        containment: MXC_BUBBLEWRAP_CONTAINMENT.into(),
        process: MxcProcess {
            command_line: wire.process.command_line,
            cwd: wire.process.cwd.unwrap_or_default(),
            env: wire.process.env,
            timeout: wire.process.timeout,
        },
        filesystem: MxcFilesystem {
            readwrite_paths: wire.filesystem.readwrite_paths,
            readonly_paths: wire.filesystem.readonly_paths,
            denied_paths: wire.filesystem.denied_paths,
        },
        network: MxcNetwork {
            default_policy: match wire.network.default_policy {
                shared_mxc::MxcNetworkDefaultPolicy::Allow => MxcNetworkDefaultPolicy::Allow,
                shared_mxc::MxcNetworkDefaultPolicy::Block => MxcNetworkDefaultPolicy::Block,
            },
            proxy: None,
        },
        lifecycle: Some(MxcLifecycle {
            destroy_on_exit: wire.lifecycle.destroy_on_exit,
            preserve_policy: wire.lifecycle.preserve_policy,
        }),
        lxc: None,
    })
}

fn mxc_execution_spec_from_container_wire(
    wire: shared_mxc::MxcContainerWireConfig,
) -> Result<MxcExecutionSpec, MxcTranslationError> {
    if wire.platform != shared_mxc::MxcPlatform::Linux
        || wire.containment != shared_mxc::MxcContainment::Lxc
    {
        return Err(MxcTranslationError::Container(
            "Linux MXC adapter can only execute MXC LXC wire configs".into(),
        ));
    }
    let lxc = wire.lxc.ok_or_else(|| {
        MxcTranslationError::Container("MXC LXC wire config missing lxc section".into())
    })?;

    Ok(MxcExecutionSpec {
        version: wire.version,
        platform: MXC_LINUX_PLATFORM.into(),
        containment: MXC_LXC_CONTAINMENT.into(),
        process: MxcProcess {
            command_line: wire.process.command_line,
            cwd: wire.process.cwd.unwrap_or_default(),
            env: wire.process.env,
            timeout: wire.process.timeout,
        },
        filesystem: MxcFilesystem {
            readwrite_paths: wire.filesystem.readwrite_paths,
            readonly_paths: wire.filesystem.readonly_paths,
            denied_paths: wire.filesystem.denied_paths,
        },
        network: MxcNetwork {
            default_policy: match wire.network.default_policy {
                shared_mxc::MxcNetworkDefaultPolicy::Allow => MxcNetworkDefaultPolicy::Allow,
                shared_mxc::MxcNetworkDefaultPolicy::Block => MxcNetworkDefaultPolicy::Block,
            },
            proxy: None,
        },
        lifecycle: Some(MxcLifecycle {
            destroy_on_exit: wire.lifecycle.destroy_on_exit,
            preserve_policy: wire.lifecycle.preserve_policy,
        }),
        lxc: Some(MxcLxcConfig {
            distribution: lxc.distribution,
            release: lxc.release,
        }),
    })
}

fn validate_lxc_launch_options(launch: &ContainerLaunchOptions) -> Result<(), MxcTranslationError> {
    lxc_distribution_release(launch)?;

    if launch.storage_path.is_some() {
        return Err(MxcTranslationError::Container(
            "custom LXC storage paths are not mapped by AXIS".into(),
        ));
    }

    if !launch.destroy_on_exit {
        return Err(MxcTranslationError::Container(
            "persistent LXC state is not mapped to AXIS lifecycle cleanup".into(),
        ));
    }

    for mount in &launch.bind_mounts {
        validate_lxc_bind_mount_shape(mount)?;
    }

    Ok(())
}

fn validate_lxc_filesystem_policy(policy: &FilesystemPolicy) -> Result<(), MxcTranslationError> {
    if policy
        .read_only
        .iter()
        .chain(policy.read_write.iter())
        .any(|path| Path::new(path.trim()) == Path::new("/"))
    {
        return Err(MxcTranslationError::Container(
            "MXC LXC uses a container rootfs; AXIS host root grants cannot be represented as LXC filesystem binds".into(),
        ));
    }

    Ok(())
}

fn validate_lxc_bind_mount_shape(mount: &ContainerBindMount) -> Result<(), MxcTranslationError> {
    if mount.host_path.trim().is_empty() || mount.container_path.trim().is_empty() {
        return Err(MxcTranslationError::Container(
            "LXC bind mounts require host and container paths".into(),
        ));
    }

    if Path::new(&mount.host_path) != Path::new(&mount.container_path) {
        return Err(MxcTranslationError::Container(format!(
            "MXC LXC config represents filesystem mounts by host path only; bind mount '{}' -> '{}' would require a container path alias",
            mount.host_path, mount.container_path
        )));
    }

    Ok(())
}

fn validate_lxc_bind_mounts(
    launch: &ContainerLaunchOptions,
    filesystem: &MxcFilesystem,
) -> Result<(), MxcTranslationError> {
    for mount in &launch.bind_mounts {
        let covered = match mount.access {
            ContainerMountAccess::ReadOnly => filesystem
                .readonly_paths
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
            ContainerMountAccess::ReadWrite => filesystem
                .readwrite_paths
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
        };

        if !covered {
            return Err(MxcTranslationError::Container(format!(
                "LXC bind mount '{}' with {:?} access is not granted by the AXIS filesystem policy",
                mount.host_path, mount.access
            )));
        }
    }

    Ok(())
}

fn lxc_distribution_release(
    launch: &ContainerLaunchOptions,
) -> Result<(&str, &str), MxcTranslationError> {
    let ContainerRootfsSource::LxcDistributionRelease {
        distribution,
        release,
    } = &launch.rootfs
    else {
        return Err(MxcTranslationError::Container(
            "MXC LXC requires distribution/release rootfs selection".into(),
        ));
    };

    if distribution.trim().is_empty() || release.trim().is_empty() {
        return Err(MxcTranslationError::Container(
            "LXC distribution and release must not be empty".into(),
        ));
    }

    Ok((distribution, release))
}

fn validate_current_bubblewrap_filesystem_substrate(
    root_read_substrate_acknowledged: bool,
) -> Result<(), MxcTranslationError> {
    if root_read_substrate_acknowledged {
        Ok(())
    } else {
        Err(MxcTranslationError::FilesystemDefaultDenyUnsupported)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcProcess {
    #[serde(rename = "commandLine")]
    pub command_line: String,
    pub cwd: String,
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcFilesystem {
    #[serde(rename = "readwritePaths")]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths")]
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcNetwork {
    #[serde(rename = "defaultPolicy")]
    pub default_policy: MxcNetworkDefaultPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<MxcNetworkProxy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcNetworkProxy {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcLifecycle {
    #[serde(rename = "destroyOnExit")]
    pub destroy_on_exit: bool,
    #[serde(rename = "preservePolicy")]
    pub preserve_policy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MxcLxcConfig {
    pub distribution: String,
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcNetworkDefaultPolicy {
    Allow,
    Block,
}

fn translate_process(config: &SandboxConfig) -> Result<MxcProcess, MxcTranslationError> {
    if config.command.is_empty() {
        return Err(MxcTranslationError::EmptyCommand);
    }

    let cwd = config
        .working_dir
        .as_deref()
        .unwrap_or(&config.workspace_dir)
        .to_path_buf();

    Ok(MxcProcess {
        command_line: shell_command_line(&config.command, &config.args),
        cwd: path_to_string(&cwd)?,
        env: translate_env(&config.env)?,
        timeout: translate_timeout(config.timeout_sec.or(config.policy.process.timeout_sec))?,
    })
}

fn translate_filesystem(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<MxcTranslatedFilesystem, MxcTranslationError> {
    let expanded = super::landlock::expand_filesystem_policy(policy, workspace)
        .map_err(MxcTranslationError::Filesystem)?;
    let workspace = std::fs::canonicalize(workspace).map_err(|e| {
        MxcTranslationError::Filesystem(format!(
            "workspace '{}' cannot be canonicalized: {e}",
            workspace.display()
        ))
    })?;
    validate_mxc_filesystem_overlays(&expanded, &workspace)
        .map_err(MxcTranslationError::Filesystem)?;
    let root_read_substrate_acknowledged =
        expanded_paths_grant_root_read(&expanded.read_only, &expanded.read_write)
            || matches!(policy.compatibility, Compatibility::BestEffort);
    let mut readwrite_paths = represented_paths(policy, &expanded.read_write)?;
    push_unique(&mut readwrite_paths, path_to_string(&workspace)?);
    let mut readonly_paths = represented_paths(policy, &expanded.read_only)?;
    readonly_paths.retain(|path| Path::new(path) != Path::new("/"));
    let denied_paths = represented_paths(policy, &expanded.deny)?;
    if matches!(policy.compatibility, Compatibility::HardRequirement) && !denied_paths.is_empty() {
        return Err(MxcTranslationError::Filesystem(
            "MXC Bubblewrap deniedPaths mask host contents with writable tmpfs and cannot enforce AXIS hard deny semantics".into(),
        ));
    }

    Ok(MxcTranslatedFilesystem {
        filesystem: MxcFilesystem {
            readwrite_paths,
            readonly_paths,
            denied_paths,
        },
        root_read_substrate_acknowledged,
    })
}

fn represented_paths(
    policy: &FilesystemPolicy,
    paths: &[super::landlock::ExpandedPath],
) -> Result<Vec<String>, MxcTranslationError> {
    let mut represented = Vec::new();

    for path in paths {
        let required =
            path.required || matches!(policy.compatibility, Compatibility::HardRequirement);

        if path.mount_path != path.path {
            if required {
                return Err(MxcTranslationError::Filesystem(format!(
                    "required path '{}' resolves to '{}' but MXC config cannot represent a distinct mount alias '{}'",
                    path.original,
                    path.path.display(),
                    path.mount_path.display()
                )));
            }
            continue;
        }

        if !path.path.exists() && !required {
            continue;
        }

        if !path.path.exists() {
            return Err(MxcTranslationError::Filesystem(format!(
                "required path '{}' does not exist after expansion to '{}'",
                path.original,
                path.path.display()
            )));
        }

        represented.push(path_to_string(&path.path)?);
    }

    Ok(represented)
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn validate_mxc_filesystem_overlays(
    policy: &super::landlock::ExpandedFilesystemPolicy,
    workspace: &Path,
) -> Result<(), String> {
    for read_only in &policy.read_only {
        for read_write in &policy.read_write {
            if read_only.path == read_write.path {
                return Err(format!(
                    "read-only path '{}' expanded to '{}' also appears as read-write path '{}' expanded to '{}'; this filesystem policy is ambiguous under MXC Bubblewrap overlays",
                    read_only.original,
                    read_only.path.display(),
                    read_write.original,
                    read_write.path.display()
                ));
            }

            if read_only.path != Path::new("/")
                && path_contains_or_equal(&read_only.path, &read_write.path)
            {
                return Err(format!(
                    "read-only path '{}' expanded to '{}' contains read-write path '{}' expanded to '{}'; current MXC Bubblewrap overlay order would shadow the read-write grant",
                    read_only.original,
                    read_only.path.display(),
                    read_write.original,
                    read_write.path.display()
                ));
            }
        }
    }

    for deny in &policy.deny {
        if path_contains_or_equal(workspace, &deny.path)
            || path_contains_or_equal(&deny.path, workspace)
        {
            return Err(format!(
                "deny path '{}' expanded to '{}' conflicts with the sandbox workspace '{}'",
                deny.original,
                deny.path.display(),
                workspace.display()
            ));
        }

        for allowed in policy.read_only.iter().chain(policy.read_write.iter()) {
            if path_contains_or_equal(&deny.path, &allowed.path) {
                return Err(format!(
                    "deny path '{}' expanded to '{}' contains allowed path '{}' expanded to '{}'; this filesystem policy is ambiguous under MXC Bubblewrap overlays",
                    deny.original,
                    deny.path.display(),
                    allowed.original,
                    allowed.path.display()
                ));
            }
        }
    }
    Ok(())
}

fn prepare_mxc_pty_bridge_launch(
    config: &SandboxConfig,
    spec: &mut MxcExecutionSpec,
) -> Result<(MxcPtyBridge, String, Vec<String>), SandboxError> {
    let bridge = MxcPtyBridge::new(config.id, &config.workspace_dir)?;
    let helper = match &config.pty_bridge_helper {
        Some(helper) => helper.clone(),
        None => std::env::current_exe().map_err(|err| {
            SandboxError::IsolationFailed(format!("MXC PTY bridge helper path: {err}"))
        })?,
    };
    let helper_path = path_to_string(&helper).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC PTY bridge helper path: {err}"))
    })?;
    let socket_path = path_to_string(&bridge.socket_path).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC PTY bridge socket path: {err}"))
    })?;

    ensure_seccomp_support_path_not_denied(&spec.filesystem, "PTY bridge helper", &helper_path)?;
    ensure_seccomp_support_path_not_denied(&spec.filesystem, "PTY bridge socket", &socket_path)?;
    ensure_mxc_pty_helper_visible(&mut spec.filesystem, &helper_path);

    let mut args = vec![
        "__axis-pty-bridge".to_string(),
        "--socket".to_string(),
        socket_path,
        "--".to_string(),
        config.command.clone(),
    ];
    args.extend(config.args.clone());
    spec.process.command_line = shell_command_line(&helper_path, &args);

    Ok((bridge, helper_path, args))
}

fn ensure_mxc_pty_helper_visible(filesystem: &mut MxcFilesystem, helper_path: &str) {
    let helper = Path::new(helper_path);
    let already_visible = filesystem
        .readwrite_paths
        .iter()
        .chain(filesystem.readonly_paths.iter())
        .any(|path| path_contains_or_equal(Path::new(path), helper));
    if !already_visible {
        push_unique(&mut filesystem.readonly_paths, helper_path.to_string());
    }
}

fn expanded_paths_grant_root_read(
    read_only: &[super::landlock::ExpandedPath],
    read_write: &[super::landlock::ExpandedPath],
) -> bool {
    read_only
        .iter()
        .chain(read_write.iter())
        .any(|path| path.path == Path::new("/"))
}

fn path_contains_or_equal(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

fn prepare_mxc_seccomp_launch<F>(
    policy: &Policy,
    spec: &mut MxcExecutionSpec,
    resolve_seccomp_launcher: F,
    command: &str,
    args: &[String],
) -> Result<tempfile::NamedTempFile, SandboxError>
where
    F: FnOnce() -> Result<MxcSeccompLauncher, SandboxError>,
{
    let filter = super::seccomp::prepare_seccomp_with_options(
        &policy.process,
        mxc_seccomp_options_for_policy(policy),
    )
    .map_err(SandboxError::IsolationFailed)?;
    let seccomp_launcher = resolve_seccomp_launcher()?;
    let filter_file = write_private_seccomp_filter(&filter)?;
    let filter_path = path_to_string(filter_file.path())
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter path: {err}")))?;
    let launcher_path = path_to_string(seccomp_launcher.path()).map_err(|err| {
        SandboxError::IsolationFailed(format!("MXC seccomp launcher path: {err}"))
    })?;

    ensure_seccomp_support_path_not_denied(&spec.filesystem, "launcher", &launcher_path)?;
    ensure_seccomp_support_path_not_denied(&spec.filesystem, "filter", &filter_path)?;
    push_unique(&mut spec.filesystem.readonly_paths, launcher_path.clone());
    push_unique(&mut spec.filesystem.readonly_paths, filter_path.clone());
    spec.process.command_line =
        seccomp_launcher_command_line(&launcher_path, &filter_path, command, args);

    Ok(filter_file)
}

fn ensure_seccomp_support_path_not_denied(
    filesystem: &MxcFilesystem,
    label: &str,
    path: &str,
) -> Result<(), SandboxError> {
    let path = Path::new(path);
    for denied in &filesystem.denied_paths {
        let denied = Path::new(denied);
        if path_contains_or_equal(denied, path) {
            return Err(SandboxError::IsolationFailed(format!(
                "MXC seccomp {label} path '{}' is covered by denied path '{}'",
                path.display(),
                denied.display()
            )));
        }
    }
    Ok(())
}

fn mxc_seccomp_options_for_policy(policy: &Policy) -> super::seccomp::SeccompOptions {
    let options = match policy.network.mode {
        NetworkMode::Block => super::seccomp::SeccompOptions::deny_network_socket_domains(),
        NetworkMode::Allow | NetworkMode::Proxy => super::seccomp::SeccompOptions::default(),
    };

    // MXC owns the containment lifecycle outside the payload's process group
    // and PID namespace, so agent CLIs may use process-group setup and
    // same-process thread signaling for tool execution/runtime support.
    options
        .allow_process_group_syscalls()
        .allow_thread_signal_syscalls()
}

fn write_private_seccomp_filter(
    filter: &super::seccomp::PreparedSeccompFilter,
) -> Result<tempfile::NamedTempFile, SandboxError> {
    let mut file = tempfile::Builder::new()
        .prefix("axis-mxc-seccomp-")
        .suffix(".bpf")
        .tempfile()
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.write_all(&filter.export_bpf_bytes())
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.flush()
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|err| SandboxError::IsolationFailed(format!("MXC seccomp filter: {err}")))?;
    Ok(file)
}

fn prepare_seccomp_filter_for_identity(
    file: &tempfile::NamedTempFile,
    identity: &super::identity::ResolvedIdentity,
) -> Result<(), SandboxError> {
    let fd = file.as_file().as_raw_fd();
    let mut stat = fstat_seccomp_filter(fd, identity, "before ownership update")?;
    if stat.st_uid != identity.uid || stat.st_gid != identity.gid {
        let chown_ret = unsafe { libc::fchown(fd, identity.uid, identity.gid) };
        if chown_ret < 0 {
            return Err(SandboxError::IsolationFailed(format!(
                "MXC seccomp filter: cannot assign private filter to run_as_user '{}': {}",
                identity.username,
                std::io::Error::last_os_error()
            )));
        }
        stat = fstat_seccomp_filter(fd, identity, "after ownership update")?;
    }

    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC seccomp filter: private filter must be a regular file for run_as_user '{}'",
            identity.username
        )));
    }

    let chmod_ret = unsafe { libc::fchmod(fd, 0o400) };
    if chmod_ret < 0 {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC seccomp filter: cannot restrict private filter for run_as_user '{}': {}",
            identity.username,
            std::io::Error::last_os_error()
        )));
    }

    let stat = fstat_seccomp_filter(fd, identity, "after permission update")?;
    if stat.st_uid != identity.uid || stat.st_gid != identity.gid {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC seccomp filter: private filter is owned by {}:{}, expected {}:{} for run_as_user '{}'",
            stat.st_uid, stat.st_gid, identity.uid, identity.gid, identity.username
        )));
    }
    if stat.st_mode & 0o777 != 0o400 {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC seccomp filter: private filter mode is {:o}, expected 400 for run_as_user '{}'",
            stat.st_mode & 0o777,
            identity.username
        )));
    }
    Ok(())
}

fn fstat_seccomp_filter(
    fd: i32,
    identity: &super::identity::ResolvedIdentity,
    phase: &str,
) -> Result<libc::stat, SandboxError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let stat_ret = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if stat_ret < 0 {
        return Err(SandboxError::IsolationFailed(format!(
            "MXC seccomp filter: cannot verify private filter {phase} for run_as_user '{}': {}",
            identity.username,
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { stat.assume_init() })
}

fn seccomp_launcher_command_line(
    launcher_path: &str,
    filter_path: &str,
    command: &str,
    args: &[String],
) -> String {
    [
        shell_quote_arg(launcher_path),
        "--filter".into(),
        shell_quote_arg(filter_path),
        "--".into(),
    ]
    .into_iter()
    .chain(std::iter::once(shell_quote_arg(command)))
    .chain(args.iter().map(|arg| shell_quote_arg(arg)))
    .collect::<Vec<_>>()
    .join(" ")
}

fn mxc_network_translation_mode(
    network: &super::strategy::NetworkStrategy,
) -> MxcNetworkTranslationMode {
    if matches!(network, super::strategy::NetworkStrategy::Proxy { .. }) {
        MxcNetworkTranslationMode::StrictProxyEnforcedByAxis
    } else {
        MxcNetworkTranslationMode::Standalone
    }
}

fn translate_network(
    policy: &Policy,
    mode: MxcNetworkTranslationMode,
) -> Result<MxcNetwork, MxcTranslationError> {
    let (default_policy, proxy) = match policy.network.mode {
        NetworkMode::Allow => {
            reject_endpoint_policies(policy, "allow")?;
            (MxcNetworkDefaultPolicy::Allow, None)
        }
        NetworkMode::Block => {
            reject_endpoint_policies(policy, "block")?;
            (MxcNetworkDefaultPolicy::Block, None)
        }
        NetworkMode::Proxy if mode == MxcNetworkTranslationMode::Standalone => {
            return Err(MxcTranslationError::ProxyModeUnsupported(
                "MXC Bubblewrap proxy mode is cooperative env-var routing and does not preserve AXIS strict proxy isolation".into(),
            ));
        }
        NetworkMode::Proxy => (MxcNetworkDefaultPolicy::Allow, None),
    };

    Ok(MxcNetwork {
        default_policy,
        proxy,
    })
}

fn reject_endpoint_policies(
    policy: &Policy,
    mode: &'static str,
) -> Result<(), MxcTranslationError> {
    if policy.network.policies.is_empty() {
        Ok(())
    } else {
        Err(MxcTranslationError::EndpointPoliciesInNonProxyMode { mode })
    }
}

fn translate_env(env: &[(String, String)]) -> Result<Vec<String>, MxcTranslationError> {
    let mut filtered = env.to_vec();
    axis_core::sandbox_env::retain_linux_sandbox_env(&mut filtered);

    filtered
        .into_iter()
        .map(|(key, value)| {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(MxcTranslationError::InvalidEnv(key));
            }
            if value.contains('\0') {
                return Err(MxcTranslationError::InvalidEnv(key));
            }
            Ok(format!("{key}={value}"))
        })
        .collect()
}

fn apply_proxy_env_to_spec(spec: &mut MxcExecutionSpec, proxy: &super::strategy::ProxyStrategy) {
    let super::strategy::ProxyStrategy::Required {
        sandbox_addr, port, ..
    } = proxy
    else {
        return;
    };

    spec.process.env.retain(|entry| {
        entry
            .split_once('=')
            .map(|(key, _)| !axis_core::sandbox_env::is_proxy_env_key(key))
            .unwrap_or(true)
    });
    spec.process.env.extend(
        super::proxy_env_vars(sandbox_addr, *port)
            .into_iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
}

fn allowed_proxy_env(proxy: &super::strategy::ProxyStrategy) -> Vec<(String, String)> {
    let super::strategy::ProxyStrategy::Required {
        sandbox_addr, port, ..
    } = proxy
    else {
        return Vec::new();
    };

    super::proxy_env_vars(sandbox_addr, *port)
}

fn translate_timeout(timeout_sec: Option<u64>) -> Result<Option<u32>, MxcTranslationError> {
    let Some(seconds) = timeout_sec else {
        return Ok(None);
    };
    let millis = seconds
        .checked_mul(1000)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(MxcTranslationError::TimeoutOverflow { seconds })?;
    Ok(Some(millis))
}

fn shell_command_line(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .map(shell_quote_arg)
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'_'
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b','
                    | b'='
                    | b'+'
                    | b'@'
                    | b'%'
            )
        })
    {
        return arg.to_string();
    }

    let mut quoted = String::from("'");
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn path_to_string(path: &Path) -> Result<String, MxcTranslationError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| MxcTranslationError::NonUtf8Path(path.display().to_string()))
}

fn production_executor_candidates() -> Vec<PathBuf> {
    production_executor_candidates_for_path(std::env::var_os("PATH").as_deref())
}

fn helper_executor_candidates() -> impl Iterator<Item = PathBuf> {
    MXC_EXECUTOR_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(MXC_EXECUTOR_NAME))
}

fn production_executor_candidates_for_path(path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    push_current_exe_dir_candidate(&mut candidates, &mut seen, MXC_EXECUTOR_NAME);

    for dir in MXC_EXECUTOR_DIRS {
        push_candidate(
            &mut candidates,
            &mut seen,
            Path::new(dir).join(MXC_EXECUTOR_NAME),
        );
    }

    if let Some(path) = path {
        for dir in std::env::split_paths(path) {
            if dir.as_os_str().is_empty() || !dir.is_absolute() {
                continue;
            }
            push_candidate(&mut candidates, &mut seen, dir.join(MXC_EXECUTOR_NAME));
        }
    }

    candidates
}

fn production_seccomp_launcher_candidates() -> Vec<PathBuf> {
    production_seccomp_launcher_candidates_for_path(std::env::var_os("PATH").as_deref())
}

fn production_seccomp_launcher_candidates_for_path(path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    push_current_exe_dir_candidate(&mut candidates, &mut seen, AXIS_SECCOMP_LAUNCHER_NAME);

    for dir in AXIS_SECCOMP_LAUNCHER_DIRS {
        push_candidate(
            &mut candidates,
            &mut seen,
            Path::new(dir).join(AXIS_SECCOMP_LAUNCHER_NAME),
        );
    }

    if let Some(path) = path {
        for dir in std::env::split_paths(path) {
            if dir.as_os_str().is_empty() || !dir.is_absolute() {
                continue;
            }
            push_candidate(
                &mut candidates,
                &mut seen,
                dir.join(AXIS_SECCOMP_LAUNCHER_NAME),
            );
        }
    }

    candidates
}

fn push_current_exe_dir_candidate(
    candidates: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    name: &str,
) {
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        push_candidate(candidates, seen, dir.join(name));
        if dir.file_name().is_some_and(|name| name == "deps")
            && let Some(parent) = dir.parent()
        {
            push_candidate(candidates, seen, parent.join(name));
        }
    }
}

fn push_candidate(candidates: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, candidate: PathBuf) {
    if seen.insert(candidate.clone()) {
        candidates.push(candidate);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorPathMode {
    Production,
    PrivilegedHelper,
    #[allow(dead_code)]
    TestInjected,
}

fn validate_executor_path(
    path: &Path,
    validation_mode: ExecutorPathMode,
) -> Result<(), MxcExecutorError> {
    validate_safe_executable_path(path, validation_mode)
        .map_err(|reason| unsafe_candidate(path, reason))
}

fn validate_safe_executable_path(
    path: &Path,
    validation_mode: ExecutorPathMode,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }

    // SAFETY: geteuid(2) has no preconditions and only reads process state.
    let trusted_uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|err| {
            if current == path && err.kind() == std::io::ErrorKind::NotFound {
                "candidate does not exist".to_string()
            } else {
                format!("could not inspect '{}': {err}", current.display())
            }
        })?;

        if metadata.file_type().is_symlink() {
            return Err(format!(
                "path component '{}' is a symlink",
                current.display()
            ));
        }
        let mode_bits = metadata.permissions().mode();
        let uid = metadata.uid();
        let injected_sticky_ancestor = current != path
            && metadata.is_dir()
            && allows_sticky_writable_ancestor(mode_bits, validation_mode);
        if current != Path::new("/")
            && !executor_component_owner_allowed(
                uid,
                trusted_uid,
                injected_sticky_ancestor,
                validation_mode,
            )
        {
            let required_owner = if matches!(validation_mode, ExecutorPathMode::PrivilegedHelper) {
                "root"
            } else {
                "root or the current user"
            };
            return Err(format!(
                "path component '{}' is not owned by {required_owner}",
                current.display(),
            ));
        }

        if current == path {
            if !metadata.is_file() {
                return Err("candidate is not a regular file".into());
            }
            if mode_bits & 0o111 == 0 {
                return Err("candidate is not executable".into());
            }
            if mode_bits & 0o022 != 0 {
                return Err(format!(
                    "path component '{}' is group- or world-writable",
                    current.display()
                ));
            }
        } else if !metadata.is_dir() {
            return Err(format!(
                "path component '{}' is not a directory",
                current.display()
            ));
        } else if mode_bits & 0o022 != 0
            && !allows_sticky_writable_ancestor(mode_bits, validation_mode)
        {
            return Err(format!(
                "path component '{}' is group- or world-writable",
                current.display()
            ));
        }
    }

    Ok(())
}

fn executor_component_owner_allowed(
    uid: u32,
    trusted_uid: u32,
    injected_sticky_ancestor: bool,
    validation_mode: ExecutorPathMode,
) -> bool {
    match validation_mode {
        ExecutorPathMode::PrivilegedHelper => uid == 0,
        ExecutorPathMode::Production | ExecutorPathMode::TestInjected => {
            uid == 0 || uid == trusted_uid || injected_sticky_ancestor
        }
    }
}

fn allows_sticky_writable_ancestor(mode_bits: u32, validation_mode: ExecutorPathMode) -> bool {
    matches!(validation_mode, ExecutorPathMode::TestInjected) && mode_bits & 0o1000 != 0
}

fn unsafe_candidate(path: &Path, reason: impl Into<String>) -> MxcExecutorError {
    MxcExecutorError::UnsafeCandidate {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn validate_spec_env_for_launch(
    spec: &MxcExecutionSpec,
    allowed_proxy_env: &[(String, String)],
) -> Result<(), MxcExecutorError> {
    let mut parsed = Vec::with_capacity(spec.process.env.len());
    for entry in &spec.process.env {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(MxcExecutorError::MalformedEnv);
        };
        parsed.push((key.to_string(), value.to_string()));
    }

    let original = parsed.clone();
    let mut retained = parsed;
    axis_core::sandbox_env::retain_linux_sandbox_env(&mut retained);
    let mut allowed_proxy_env = allowed_proxy_env.to_vec();

    for (key, value) in &original {
        if take_env_match(&mut retained, key, value)
            || take_env_match(&mut allowed_proxy_env, key, value)
        {
            continue;
        }
        return Err(MxcExecutorError::FilteredEnv { key: key.clone() });
    }

    Ok(())
}

fn take_env_match(entries: &mut Vec<(String, String)>, key: &str, value: &str) -> bool {
    let Some(index) = entries
        .iter()
        .position(|(entry_key, entry_value)| entry_key == key && entry_value == value)
    else {
        return false;
    };
    entries.remove(index);
    true
}

fn wait_child_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<ExitStatus, MxcExecutorError> {
    let started = Instant::now();
    let process_group = child.id() as i32;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| MxcExecutorError::Spawn(err.to_string()))?
        {
            return Ok(status);
        }

        if started.elapsed() >= timeout {
            if process_group > 0 {
                kill_process_group_until_stopped(process_group, Duration::from_millis(500));
            }
            let _ = child.kill();
            let _ = child.wait();
            if process_group > 0 {
                kill_process_group_until_stopped(process_group, Duration::from_millis(500));
            }
            return Err(MxcExecutorError::Timeout {
                timeout_ms: timeout.as_millis(),
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn read_limited_output(file: &mut File) -> Result<String, MxcExecutorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_DRY_RUN_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| MxcExecutorError::ConfigIo(err.to_string()))?;

    if bytes.len() > MAX_DRY_RUN_OUTPUT_BYTES as usize {
        bytes.truncate(MAX_DRY_RUN_OUTPUT_BYTES as usize);
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn cleanup_tmpdir_on_setup_failure(workspace: &Path, tmpdir_active: bool) -> Option<String> {
    if !tmpdir_active {
        return None;
    }
    super::landlock::cleanup_tmpdir(workspace).err()
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

async fn wait_runtime_child_with_timeout(
    mut child: Child,
    timeout_sec: Option<u64>,
) -> Result<ExitStatus, io::Error> {
    let pid = child.id() as i32;
    let mut wait_task = tokio::task::spawn_blocking(move || child.wait());

    let Some(timeout_sec) = timeout_sec else {
        return join_child_wait(wait_task.await);
    };

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_sec));
    tokio::pin!(timeout);
    tokio::select! {
        result = &mut wait_task => join_child_wait(result),
        _ = &mut timeout => {
            tracing::warn!("MXC sandbox child pid={pid} exceeded timeout of {timeout_sec}s");
            signal_process_group(pid);
            let reap_grace = Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
            match tokio::time::timeout(reap_grace, &mut wait_task).await {
                Ok(result) => {
                    let result = join_child_wait(result);
                    kill_process_group_until_stopped(pid, Duration::from_millis(500));
                    result
                }
                Err(_) => {
                    signal_process_group(pid);
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "MXC child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after SIGKILL"
                        ),
                    ))
                }
            }
        }
    }
}

fn join_child_wait(
    result: Result<Result<ExitStatus, io::Error>, tokio::task::JoinError>,
) -> Result<ExitStatus, io::Error> {
    result.map_err(|err| io::Error::other(format!("wait task: {err}")))?
}

fn wait_for_killed_child(child: &mut Child, pid: i32) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(POST_TIMEOUT_REAP_GRACE_SEC);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(-1),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                tracing::warn!(
                    "MXC sandbox child pid={pid} did not exit within {POST_TIMEOUT_REAP_GRACE_SEC}s after destroy SIGKILL"
                );
                return -1;
            }
            Err(err) => {
                tracing::warn!("MXC sandbox child pid={pid}: wait after destroy failed: {err}");
                return -1;
            }
        }
    }
}

fn kill_process_group(pid: i32) {
    signal_process_group(pid);
    unsafe { while libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) > 0 {} }
}

fn signal_process_group(pid: i32) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

fn kill_process_group_until_stopped(pid: i32, grace: Duration) {
    let deadline = Instant::now() + grace;
    loop {
        kill_process_group(pid);
        if !process_group_exists(pid) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn process_group_exists(pid: i32) -> bool {
    let ret = unsafe { libc::kill(-pid, 0) };
    ret == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::{resources, strategy};
    use axis_core::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkPolicy, ProcessPolicy, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::ffi::OsString;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn process_group_signal_leaves_group_leader_for_child_waiter() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 30");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let pid = child.id() as i32;

        signal_process_group(pid);
        let status = child.wait().unwrap();

        assert!(!status.success());
        kill_process_group(pid);
    }

    #[test]
    fn netns_helper_owner_pidfd_is_inherited_only_by_the_helper() {
        let mut guard = super::super::NetnsHelperOwnerPidFd::new().unwrap();
        let fd = guard.fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(format!("test -e /proc/self/fd/{fd}"));
        guard.configure_command(&mut command);
        let mut child = command.spawn().unwrap();
        guard.spawned();

        assert!(child.wait().unwrap().success());
        assert_eq!(guard.fd, -1);
    }

    fn policy(network_mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: network_mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn config(policy: Policy, workspace: PathBuf) -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy,
            command: "/usr/bin/python3".into(),
            args: vec!["-c".into(), "print('hello world')".into()],
            working_dir: None,
            workspace_dir: workspace,
            env: vec![
                ("PATH".into(), "/usr/bin".into()),
                ("CUSTOM".into(), "kept".into()),
                ("ANTHROPIC_API_KEY".into(), "secret".into()),
                ("HTTPS_PROXY".into(), "http://proxy-with-creds".into()),
            ],
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: true,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: None,
            backend_preflight: Default::default(),
            startup_trace: None,
        }
    }

    #[test]
    fn allow_mode_maps_to_mxc_allow_policy() {
        let workspace = tempfile::tempdir().unwrap();
        let spec = translate_sandbox_config(&config(
            policy(NetworkMode::Allow),
            workspace.path().to_path_buf(),
        ))
        .unwrap();

        assert_eq!(spec.version, shared_mxc::MXC_CONFIG_VERSION);
        assert_eq!(spec.platform, MXC_LINUX_PLATFORM);
        assert_eq!(spec.containment, MXC_BUBBLEWRAP_CONTAINMENT);
        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Allow);
    }

    #[test]
    fn block_mode_maps_to_mxc_block_policy() {
        let workspace = tempfile::tempdir().unwrap();
        let spec = translate_sandbox_config(&config(
            policy(NetworkMode::Block),
            workspace.path().to_path_buf(),
        ))
        .unwrap();

        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Block);
    }

    #[test]
    fn mxc_seccomp_allows_agent_process_groups_without_weakening_network_block() {
        let allow_policy = policy(NetworkMode::Allow);
        let allow_options = mxc_seccomp_options_for_policy(&allow_policy);
        assert!(allow_options.allows_process_group_syscalls());
        assert!(allow_options.allows_thread_signal_syscalls());
        assert!(!allow_options.denies_non_unix_socket_domains());

        let block_policy = policy(NetworkMode::Block);
        let block_options = mxc_seccomp_options_for_policy(&block_policy);
        assert!(block_options.allows_process_group_syscalls());
        assert!(block_options.allows_thread_signal_syscalls());
        assert!(block_options.denies_non_unix_socket_domains());
    }

    #[test]
    fn hard_requirement_bubblewrap_spec_fails_without_root_read_acknowledgement() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem.compatibility = Compatibility::HardRequirement;

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.path().into()))
            .unwrap_err();

        assert_eq!(err, MxcTranslationError::FilesystemDefaultDenyUnsupported);
        assert!(err.to_string().contains("host root read-only"));
    }

    #[test]
    fn endpoint_policies_are_rejected_in_non_proxy_modes() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy());

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.path().into()))
            .unwrap_err();

        assert_eq!(
            err,
            MxcTranslationError::EndpointPoliciesInNonProxyMode { mode: "allow" }
        );
    }

    #[test]
    fn endpoint_policies_are_rejected_in_block_mode() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.network.policies.push(endpoint_policy());

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.path().into()))
            .unwrap_err();

        assert_eq!(
            err,
            MxcTranslationError::EndpointPoliciesInNonProxyMode { mode: "block" }
        );
    }

    #[test]
    fn proxy_mode_fails_closed_in_initial_translator() {
        let workspace = tempfile::tempdir().unwrap();
        let err = MxcExecutionSpec::from_sandbox_config(&config(
            policy(NetworkMode::Proxy),
            workspace.path().into(),
        ))
        .unwrap_err();

        assert!(matches!(err, MxcTranslationError::ProxyModeUnsupported(_)));
        assert!(err.to_string().contains("cooperative"));
    }

    #[test]
    fn proxy_mode_maps_to_allow_when_strict_axis_proxy_is_preplanned() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );

        let spec = MxcExecutionSpec::from_sandbox_config_with_network_mode(
            &config,
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis,
        )
        .unwrap();

        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Allow);
        assert!(spec.network.proxy.is_none());
    }

    #[test]
    fn production_network_resolution_keeps_allow_and_block_out_of_strict_planning() {
        let workspace = tempfile::tempdir().unwrap();
        let allow_config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let block_config = config(
            mxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );

        let allow = resolve_mxc_network_strategy_with_strict_proxy(&allow_config, |_, _, _, _| {
            panic!("allow mode must not invoke strict proxy planning")
        })
        .unwrap();
        let block = resolve_mxc_network_strategy_with_strict_proxy(&block_config, |_, _, _, _| {
            panic!("block mode must not invoke strict proxy planning")
        })
        .unwrap();

        assert_eq!(
            allow,
            (
                strategy::NetworkStrategy::AllowHost,
                strategy::ProxyStrategy::None,
            )
        );
        assert_eq!(
            block,
            (
                strategy::NetworkStrategy::BlockedBySeccomp,
                strategy::ProxyStrategy::None,
            )
        );
    }

    #[test]
    fn production_proxy_resolution_uses_strict_planning_without_binary_restrictions() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let proxy_addr = super::super::netns::proxy_bind_addr(id, proxy_port);
        let expected = native_mxc_proxy_strategies(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(proxy_addr);

        let resolved = resolve_mxc_network_strategy_with_strict_proxy(
            &config,
            |policy, resolved_id, resolved_port, resolved_addr| {
                assert!(!policy_requires_connect_attribution(policy));
                assert_eq!(resolved_id, id);
                assert_eq!(resolved_port, proxy_port);
                assert_eq!(resolved_addr, Some(proxy_addr));
                Ok(expected.clone())
            },
        )
        .unwrap();

        assert_eq!(resolved, expected);
        assert_eq!(
            mxc_network_translation_mode(&resolved.0),
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis
        );
    }

    #[test]
    fn production_proxy_resolution_fails_closed_when_strict_planning_fails() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );

        let err = resolve_mxc_network_strategy(&config).unwrap_err();
        let message = err.to_string();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(message.contains("proxy mode requires a non-zero proxy port"));
        assert!(!message.contains("cooperative"));
    }

    #[test]
    fn production_proxy_resolution_uses_strict_planning_with_binary_restrictions() {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_281;
        let proxy_addr = super::super::netns::proxy_bind_addr(id, proxy_port);
        let expected = native_mxc_proxy_strategies(id, proxy_port);
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(proxy_addr);
        config.connect_attribution = Some(ConnectAttributionStore::default());

        let resolved = resolve_mxc_network_strategy_with_strict_proxy(
            &config,
            |policy, resolved_id, resolved_port, resolved_addr| {
                assert!(policy_requires_connect_attribution(policy));
                assert_eq!(resolved_id, id);
                assert_eq!(resolved_port, proxy_port);
                assert_eq!(resolved_addr, Some(proxy_addr));
                Ok(expected.clone())
            },
        )
        .unwrap();

        assert_eq!(resolved, expected);
        assert_eq!(
            mxc_network_translation_mode(&resolved.0),
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis
        );
    }

    #[test]
    fn lxc_container_config_maps_distribution_lifecycle_and_mount_contract() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        let launch = lxc_launch_for_workspace(workspace.path());

        let spec =
            MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime()).unwrap();

        assert_eq!(spec.version, shared_mxc::MXC_CONFIG_VERSION);
        assert_eq!(spec.platform, MXC_LINUX_PLATFORM);
        assert_eq!(spec.containment, MXC_LXC_CONTAINMENT);
        assert_eq!(spec.process.cwd, "/workspace");
        assert_eq!(spec.network.default_policy, MxcNetworkDefaultPolicy::Block);
        assert!(
            spec.filesystem
                .readwrite_paths
                .iter()
                .any(|path| path == &path_string(workspace.path()))
        );
        assert_eq!(
            spec.lifecycle,
            Some(MxcLifecycle {
                destroy_on_exit: true,
                preserve_policy: false
            })
        );
        assert_eq!(
            spec.lxc,
            Some(MxcLxcConfig {
                distribution: "alpine".into(),
                release: "3.23".into()
            })
        );

        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["containment"], "lxc");
        assert_eq!(json["lxc"]["distribution"], "alpine");
        assert_eq!(json["lxc"]["release"], "3.23");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert_eq!(json["lifecycle"]["preservePolicy"], false);
    }

    #[test]
    fn lxc_container_config_rejects_missing_lxc_dependency_before_translation() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launch = lxc_launch_for_workspace(workspace.path());

        let err = MxcExecutionSpec::from_lxc_container_config(
            &config,
            &launch,
            &lxc_runtime_without_lxc(),
        )
        .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("before spawn"));
        assert!(err.to_string().contains(host_dependency::LINUX_LXC));
        assert!(err.to_string().contains("missing host dependency"));
    }

    #[test]
    fn lxc_container_config_rejects_proxy_until_axis_strict_proxy_adapter_exists() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        let launch = lxc_launch_for_workspace(workspace.path());

        let err =
            MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_proxy_runtime())
                .unwrap_err();

        assert!(matches!(err, MxcTranslationError::ProxyModeUnsupported(_)));
        assert!(err.to_string().contains("strict proxy"));
        assert!(err.to_string().contains("network namespace"));
    }

    #[test]
    fn lxc_container_config_rejects_endpoint_policies_outside_strict_proxy() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = lxc_representable_policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy());
        let config = config(policy, workspace.path().into());
        let launch = lxc_launch_for_workspace(workspace.path());

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("endpoint policies"));
        assert!(err.to_string().contains("strict proxy"));
    }

    #[test]
    fn lxc_container_config_rejects_bind_mount_aliases() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let mut launch = lxc_launch_for_workspace(workspace.path());
        launch.bind_mounts[0].container_path = "/workspace".into();

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("container path alias"));
    }

    #[test]
    fn lxc_container_config_rejects_ungranted_bind_mounts() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = workspace.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let mut launch = lxc_launch_for_workspace(workspace.path());
        launch.bind_mounts = vec![ContainerBindMount {
            host_path: path_string(&outside),
            container_path: path_string(&outside),
            access: ContainerMountAccess::ReadWrite,
        }];

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("not granted"));
    }

    #[test]
    fn lxc_container_config_rejects_persistent_container_state() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let mut launch = lxc_launch_for_workspace(workspace.path());
        launch.destroy_on_exit = false;

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("container.destroy_on_exit"));
    }

    #[test]
    fn lxc_container_config_rejects_non_lxc_rootfs_source() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            lxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let mut launch = lxc_launch_for_workspace(workspace.path());
        launch.rootfs = ContainerRootfsSource::ExistingRootfs {
            path: path_string(workspace.path()),
        };

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("container.rootfs"));
    }

    #[test]
    fn lxc_container_config_rejects_host_root_grants() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launch = lxc_launch_for_workspace(workspace.path());

        let err = MxcExecutionSpec::from_lxc_container_config(&config, &launch, &lxc_runtime())
            .unwrap_err();

        assert!(matches!(err, MxcTranslationError::Container(_)));
        assert!(err.to_string().contains("host root grants"));
    }

    #[test]
    fn proxy_mode_allows_unrestricted_helper_launch_for_mxc() {
        let id = SandboxId::new();
        let policy = mxc_representable_policy(NetworkMode::Proxy);
        let (network, _) = helper_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let config = config(policy, workspace.path().into());

        assert!(validate_mxc_network_strategy(&config, &network).is_ok());
    }

    #[test]
    fn proxy_mode_rejects_binary_restricted_policy_without_attribution_store() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let (network, _) = native_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, 31_280));

        let err = validate_mxc_network_strategy(&config, &network).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("attribution store"));
    }

    #[test]
    fn proxy_mode_rejects_binary_restricted_policy_when_connect_is_blocked() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        policy.process.blocked_syscalls = vec!["connect".into()];
        let (network, _) = native_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, 31_280));
        config.connect_attribution = Some(ConnectAttributionStore::default());

        let err = validate_mxc_network_strategy(&config, &network).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("connect-time attribution"));
        assert!(
            err.to_string()
                .contains("blocked_syscalls includes connect")
        );
    }

    #[test]
    fn proxy_mode_rejects_binary_restricted_helper_launch_for_mxc() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let (network, _) = helper_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, 31_280));
        config.connect_attribution = Some(ConnectAttributionStore::default());

        let err = validate_mxc_network_strategy(&config, &network).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("axis-netns-helper launch"));
        assert!(err.to_string().contains("connect-time attribution"));
    }

    #[test]
    fn mxc_helper_launch_spec_uses_mxc_executor_contract_without_proxy_env() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let executor_path = executor.path().to_path_buf();
        let launcher = fake_seccomp_launcher(&root);
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (network, proxy) = helper_mxc_proxy_strategies(id, proxy_port);
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        policy.process.max_processes = 17;
        policy.process.max_memory_mb = 64;
        policy.process.blocked_syscalls = vec!["clone3".into()];
        let mut config = config(policy.clone(), workspace.path().into());
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();
        let config_fd = 42;
        let destroy_token =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        let spec = sandbox
            .mxc_helper_launch_spec(config_fd, None, destroy_token.clone())
            .unwrap();

        assert_eq!(
            spec.launch_kind,
            super::super::netns::HelperLaunchKind::MxcExecutor
        );
        assert_eq!(spec.mxc_config_fd, Some(config_fd));
        assert_eq!(spec.workspace_dir, workspace.path().to_path_buf());
        assert_eq!(spec.command, executor_path.to_string_lossy());
        assert_eq!(
            spec.args,
            vec![
                "--experimental".to_string(),
                "--config".to_string(),
                format!("/proc/self/fd/{config_fd}")
            ]
        );
        assert_eq!(
            spec.env,
            vec![
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
                ("LC_ALL".to_string(), "C".to_string())
            ]
        );
        assert!(spec.env.iter().all(|(key, _)| {
            !axis_core::sandbox_env::is_secret_env_key(key)
                && !axis_core::sandbox_env::is_proxy_env_key(key)
        }));
        assert_eq!(spec.destroy_token, destroy_token);
        assert_eq!(spec.rlimits, super::super::netns::HelperRlimits::default());
        assert_eq!(spec.filesystem.read_only, policy.filesystem.read_only);
        assert_eq!(spec.filesystem.read_write, policy.filesystem.read_write);
        assert_eq!(spec.filesystem.deny, policy.filesystem.deny);
        assert!(matches!(
            spec.filesystem.compatibility,
            Compatibility::HardRequirement
        ));
        assert_eq!(spec.process.max_processes, policy.process.max_processes);
        assert_eq!(spec.process.max_memory_mb, policy.process.max_memory_mb);
        assert_eq!(
            spec.process.cpu_rate_percent,
            policy.process.cpu_rate_percent
        );
        assert_eq!(spec.process.run_as_user, policy.process.run_as_user);
        assert_eq!(
            spec.process.blocked_syscalls,
            policy.process.blocked_syscalls
        );
        assert_eq!(spec.process.timeout_sec, policy.process.timeout_sec);
    }

    #[test]
    fn proxy_mode_allows_binary_restricted_policy_with_native_attribution() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let (network, _) = native_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, 31_280));
        config.connect_attribution = Some(ConnectAttributionStore::default());

        assert!(validate_mxc_network_strategy(&config, &network).is_ok());
        assert!(mxc_connect_attribution_required(&config, &network).unwrap());
    }

    #[test]
    fn capability_preflight_accepts_planner_approved_mxc_boundary() {
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let (network, _) = no_proxy_network_strategy();

        validate_mxc_linux_capability_plan(
            &config,
            &network,
            &no_resource_limits_strategy(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn capability_preflight_rejects_missing_binary_attribution_before_executor() {
        let id = SandboxId::new();
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/curl".into(),
        }];
        policy.network.policies.push(endpoint);
        let (network, _) = native_mxc_proxy_strategies(id, 31_280);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, 31_280));

        let err = validate_mxc_linux_capability_plan(
            &config,
            &network,
            &no_resource_limits_strategy(),
            false,
        )
        .unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("before executor invocation"));
        assert!(err.to_string().contains("network.binary_attribution"));
        assert!(
            err.to_string()
                .contains(host_dependency::LINUX_SECCOMP_NOTIFY)
        );
    }

    #[test]
    fn proxy_mode_constructs_binary_restricted_native_attribution_backend() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let launcher = fake_seccomp_launcher(&root);
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: "/usr/bin/python3".into(),
        }];
        policy.network.policies.push(endpoint);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        config.connect_attribution = Some(ConnectAttributionStore::default());

        let sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();

        assert!(sandbox.notify_connect);
        assert!(sandbox.connect_attribution.is_some());
    }

    #[test]
    fn empty_command_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.command.clear();

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert_eq!(err, MxcTranslationError::EmptyCommand);
    }

    #[test]
    fn process_command_line_is_shell_quoted_and_cwd_defaults_to_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.command = "python3".into();
        config.args = vec![
            "-c".into(),
            "print('hello world')".into(),
            String::new(),
            "a'b".into(),
        ];

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(
            spec.process.command_line,
            "python3 -c 'print('\\''hello world'\\'')' '' 'a'\\''b'"
        );
        assert_eq!(spec.process.cwd, workspace.path().to_string_lossy());
    }

    #[test]
    fn explicit_working_directory_is_used() {
        let workspace = tempfile::tempdir().unwrap();
        let cwd = workspace.path().join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.working_dir = Some(cwd.clone());

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.cwd, cwd.to_string_lossy());
    }

    #[test]
    fn non_utf8_working_directory_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.working_dir = Some(PathBuf::from(OsString::from_vec(vec![0xff])));

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert!(matches!(err, MxcTranslationError::NonUtf8Path(_)));
    }

    #[test]
    fn env_translation_strips_secrets_and_proxy_vars_but_keeps_custom_values() {
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        assert_eq!(spec.process.env, vec!["PATH=/usr/bin", "CUSTOM=kept"]);
    }

    #[test]
    fn invalid_environment_keys_and_values_are_rejected() {
        let workspace = tempfile::tempdir().unwrap();
        for (key, value) in [
            (String::new(), "value".into()),
            ("BAD=KEY".into(), "value".into()),
            ("BAD\0KEY".into(), "value".into()),
            ("BAD_VALUE".into(), "value\0".into()),
        ] {
            let mut config = config(policy(NetworkMode::Block), workspace.path().into());
            config.env = vec![(key.clone(), value)];

            let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

            assert!(matches!(err, MxcTranslationError::InvalidEnv(_)));
        }
    }

    #[test]
    fn filesystem_policy_maps_existing_paths_and_skips_missing_best_effort_paths() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let ro = root.path().join("ro");
        let rw = root.path().join("rw");
        let denied = root.path().join("denied");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&ro).unwrap();
        std::fs::create_dir(&rw).unwrap();
        std::fs::create_dir(&denied).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![
                ro.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-ro")
                    .to_string_lossy()
                    .into_owned(),
            ],
            read_write: vec![
                "{workspace}".into(),
                rw.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-rw")
                    .to_string_lossy()
                    .into_owned(),
            ],
            deny: vec![
                denied.to_string_lossy().into_owned(),
                root.path()
                    .join("missing-denied")
                    .to_string_lossy()
                    .into_owned(),
            ],
            compatibility: Compatibility::BestEffort,
            workspace_read_only: false,
        };

        let spec = translate_sandbox_config(&config(policy, workspace.clone())).unwrap();

        assert_eq!(spec.filesystem.readonly_paths, vec![path_string(&ro)]);
        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(&workspace), path_string(&rw)]
        );
        assert_eq!(spec.filesystem.denied_paths, vec![path_string(&denied)]);
    }

    #[test]
    fn default_filesystem_adds_implicit_workspace_readwrite_path() {
        let workspace = tempfile::tempdir().unwrap();

        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(workspace.path())]
        );
    }

    #[test]
    fn full_spec_allows_explicit_root_read_grant_for_mxc_bubblewrap() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into()],
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let spec =
            MxcExecutionSpec::from_sandbox_config(&config(policy, workspace.clone())).unwrap();

        assert!(
            !spec
                .filesystem
                .readonly_paths
                .iter()
                .any(|path| path == "/"),
            "root read acknowledgement must not become a late MXC readonly bind"
        );
        assert!(
            spec.filesystem
                .readwrite_paths
                .iter()
                .any(|path| path == &path_string(&workspace))
        );
        assert!(spec.filesystem.denied_paths.is_empty());
    }

    #[test]
    fn hard_requirement_denied_paths_fail_closed_for_mxc_bubblewrap_masks() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("outside-denied");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&denied).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into()],
            read_write: vec!["{workspace}".into()],
            deny: vec![denied.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            workspace_read_only: false,
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
        assert!(err.to_string().contains("hard deny semantics"));
    }

    #[test]
    fn readonly_parent_containing_readwrite_child_fails_closed_for_mxc_bubblewrap_order() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let readonly_parent = root.path().join("readonly-parent");
        let readwrite_child = readonly_parent.join("readwrite-child");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&readonly_parent).unwrap();
        std::fs::create_dir(&readwrite_child).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into(), readonly_parent.to_string_lossy().into_owned()],
            read_write: vec![
                "{workspace}".into(),
                readwrite_child.to_string_lossy().into_owned(),
            ],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(
            err.to_string()
                .contains("would shadow the read-write grant")
        );
    }

    #[test]
    fn deny_path_containing_allowed_path_fails_closed_for_mxc_bubblewrap() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("denied-parent");
        let allowed = denied.join("allowed-child");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&denied).unwrap();
        std::fs::create_dir(&allowed).unwrap();
        let mut policy = policy(NetworkMode::Allow);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into(), allowed.to_string_lossy().into_owned()],
            read_write: vec!["{workspace}".into()],
            deny: vec![denied.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            workspace_read_only: false,
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
        assert!(err.to_string().contains("contains allowed path"));
    }

    #[test]
    fn explicit_workspace_policy_does_not_duplicate_implicit_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{workspace}".into());

        let spec = translate_sandbox_config(&config(policy, workspace.path().into())).unwrap();

        assert_eq!(
            spec.filesystem.readwrite_paths,
            vec![path_string(workspace.path())]
        );
    }

    #[test]
    fn best_effort_symlink_alias_is_skipped_until_mxc_can_represent_mount_aliases() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy
            .filesystem
            .read_only
            .push(alias.to_string_lossy().into_owned());

        let spec = translate_sandbox_config(&config(policy, workspace)).unwrap();

        assert!(spec.filesystem.readonly_paths.is_empty());
    }

    #[test]
    fn hard_requirement_missing_path_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![root.path().join("missing").to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
    }

    #[test]
    fn hard_requirement_symlink_alias_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        let mut policy = policy(NetworkMode::Block);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![alias.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };

        let err = MxcExecutionSpec::from_sandbox_config(&config(policy, workspace)).unwrap_err();

        assert!(matches!(err, MxcTranslationError::Filesystem(_)));
        assert!(err.to_string().contains("mount alias"));
    }

    #[test]
    fn timeout_maps_seconds_to_milliseconds() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.timeout_sec = Some(2);

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.timeout, Some(2000));
    }

    #[test]
    fn policy_timeout_is_used_when_config_timeout_is_absent() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(3);

        let spec = translate_sandbox_config(&config(policy, workspace.path().into())).unwrap();

        assert_eq!(spec.process.timeout, Some(3000));
    }

    #[test]
    fn config_timeout_overrides_policy_timeout() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(3);
        let mut config = config(policy, workspace.path().into());
        config.timeout_sec = Some(2);

        let spec = translate_sandbox_config(&config).unwrap();

        assert_eq!(spec.process.timeout, Some(2000));
    }

    #[test]
    fn timeout_overflow_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(policy(NetworkMode::Block), workspace.path().into());
        config.timeout_sec = Some(u64::MAX);

        let err = MxcExecutionSpec::from_sandbox_config(&config).unwrap_err();

        assert!(matches!(err, MxcTranslationError::TimeoutOverflow { .. }));
    }

    #[test]
    fn serialized_json_uses_mxc_field_names() {
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let json = serde_json::to_value(&spec).unwrap();

        assert_eq!(json["process"]["commandLine"], spec.process.command_line);
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(json["filesystem"]["readwritePaths"].is_array());
        assert!(json["filesystem"]["readonlyPaths"].is_array());
        assert!(json["filesystem"]["deniedPaths"].is_array());
    }

    #[test]
    fn executor_from_path_accepts_safe_executable() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        let executor = MxcExecutor::from_injected_path(&executable).unwrap();

        assert_eq!(executor.path(), executable);
        let command = executor.command();
        assert_eq!(command.get_program(), OsStr::new("/bin/sh"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [&*injected_executor_script_path(&executable)]
        );
    }

    #[test]
    fn executor_from_path_rejects_unsafe_candidates() {
        let root = secure_tempdir();

        let missing = root.path().join("missing");
        assert_unsafe_candidate(&missing, "does not exist");

        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert_unsafe_candidate(&directory, "regular file");

        let non_executable = root.path().join("non-executable");
        write_executable(&non_executable, "#!/bin/sh\nexit 0\n", 0o600);
        assert_unsafe_candidate(&non_executable, "not executable");

        let group_writable = root.path().join("group-writable");
        write_executable(&group_writable, "#!/bin/sh\nexit 0\n", 0o720);
        assert_unsafe_candidate(&group_writable, "group- or world-writable");

        let world_writable = root.path().join("world-writable");
        write_executable(&world_writable, "#!/bin/sh\nexit 0\n", 0o702);
        assert_unsafe_candidate(&world_writable, "group- or world-writable");
    }

    #[test]
    fn executor_from_path_rejects_writable_ancestor() {
        let root = secure_tempdir();
        let writable_dir = root.path().join("writable");
        fs::create_dir(&writable_dir).unwrap();
        fs::set_permissions(&writable_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let executable = writable_dir.join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        assert_unsafe_candidate(&executable, "group- or world-writable");
    }

    #[test]
    fn helper_executor_owner_policy_requires_root_for_every_component() {
        let user_uid = 1000;

        assert!(executor_component_owner_allowed(
            0,
            user_uid,
            false,
            ExecutorPathMode::PrivilegedHelper
        ));
        assert!(!executor_component_owner_allowed(
            user_uid,
            user_uid,
            false,
            ExecutorPathMode::PrivilegedHelper
        ));
        assert!(!executor_component_owner_allowed(
            user_uid,
            user_uid,
            true,
            ExecutorPathMode::PrivilegedHelper
        ));
        assert!(executor_component_owner_allowed(
            user_uid,
            user_uid,
            false,
            ExecutorPathMode::Production
        ));
        assert!(executor_component_owner_allowed(
            user_uid,
            2000,
            true,
            ExecutorPathMode::TestInjected
        ));
    }

    #[test]
    fn executor_resolver_uses_first_safe_candidate_and_reports_unavailable() {
        let root = secure_tempdir();
        let unsafe_candidate = root.path().join("unsafe-lxc-exec");
        write_executable(&unsafe_candidate, "#!/bin/sh\nexit 0\n", 0o777);
        let safe_candidate = root.path().join("safe-lxc-exec");
        write_executable(&safe_candidate, "#!/bin/sh\nexit 0\n", 0o700);

        let executor = MxcExecutor::resolve_from_injected_candidates([
            unsafe_candidate,
            safe_candidate.clone(),
        ])
        .unwrap();

        assert_eq!(executor.path(), safe_candidate);
        assert_eq!(
            MxcExecutor::resolve_from_candidates([root.path().join("missing")]).unwrap_err(),
            MxcExecutorError::Unavailable
        );
    }

    #[test]
    fn production_executor_candidates_prefer_current_exe_dir_then_package_paths() {
        let candidates = production_executor_candidates_for_path(Some(OsStr::new(
            "/home/test/.local/bin:relative:/usr/bin:/opt/axis/bin",
        )));

        let current_exe = std::env::current_exe().unwrap();
        let current_dir = current_exe.parent().unwrap();
        assert_eq!(candidates[0], current_dir.join(MXC_EXECUTOR_NAME));
        let mut stable_start = 1;
        if current_dir.file_name().is_some_and(|name| name == "deps") {
            let parent = current_dir.parent().unwrap();
            assert_eq!(candidates[1], parent.join(MXC_EXECUTOR_NAME));
            stable_start = 2;
        }

        let stable_dirs = MXC_EXECUTOR_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(MXC_EXECUTOR_NAME))
            .collect::<Vec<_>>();
        assert_eq!(
            &candidates[stable_start..stable_start + stable_dirs.len()],
            stable_dirs.as_slice()
        );
        assert!(candidates.contains(&Path::new("/home/test/.local/bin").join(MXC_EXECUTOR_NAME)));
        assert!(candidates.contains(&Path::new("/opt/axis/bin").join(MXC_EXECUTOR_NAME)));
        assert!(!candidates.contains(&Path::new("relative").join(MXC_EXECUTOR_NAME)));
        assert_eq!(
            candidates
                .iter()
                .filter(|path| path.as_path() == Path::new("/usr/bin").join(MXC_EXECUTOR_NAME))
                .count(),
            1
        );
    }

    #[test]
    fn helper_executor_candidates_use_only_stable_install_locations() {
        let candidates = helper_executor_candidates().collect::<Vec<_>>();
        let expected = MXC_EXECUTOR_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(MXC_EXECUTOR_NAME))
            .collect::<Vec<_>>();

        assert_eq!(candidates, expected);
    }

    #[test]
    fn production_seccomp_launcher_candidates_prefer_current_exe_dir_then_package_paths() {
        let candidates = production_seccomp_launcher_candidates_for_path(Some(OsStr::new(
            "/home/test/.local/bin:relative:/usr/bin:/opt/axis/bin",
        )));

        let current_exe = std::env::current_exe().unwrap();
        let current_dir = current_exe.parent().unwrap();
        assert_eq!(candidates[0], current_dir.join(AXIS_SECCOMP_LAUNCHER_NAME));
        let mut stable_start = 1;
        if current_dir.file_name().is_some_and(|name| name == "deps") {
            let parent = current_dir.parent().unwrap();
            assert_eq!(candidates[1], parent.join(AXIS_SECCOMP_LAUNCHER_NAME));
            stable_start = 2;
        }

        let stable_dirs = AXIS_SECCOMP_LAUNCHER_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(AXIS_SECCOMP_LAUNCHER_NAME))
            .collect::<Vec<_>>();
        assert_eq!(
            &candidates[stable_start..stable_start + stable_dirs.len()],
            stable_dirs.as_slice()
        );
        for dir in AXIS_SECCOMP_LAUNCHER_DIRS {
            assert!(
                candidates.contains(&Path::new(dir).join(AXIS_SECCOMP_LAUNCHER_NAME)),
                "missing packaged seccomp launcher dir: {dir}"
            );
        }
        assert!(
            candidates
                .contains(&Path::new("/home/test/.local/bin").join(AXIS_SECCOMP_LAUNCHER_NAME))
        );
        assert!(candidates.contains(&Path::new("/opt/axis/bin").join(AXIS_SECCOMP_LAUNCHER_NAME)));
        assert!(!candidates.contains(&Path::new("relative").join(AXIS_SECCOMP_LAUNCHER_NAME)));
    }

    #[test]
    fn production_resolver_rejects_sticky_tmp_candidates() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        let err = MxcExecutor::resolve_from_candidates([executable]).unwrap_err();

        assert_eq!(err, MxcExecutorError::Unavailable);
    }

    #[test]
    fn dry_run_success_uses_private_config_path_without_secret_leakage() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let argv_path = root.path().join("argv");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 printf '%s\\n' \"$@\" > {}\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&argv_path),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let result = executor
            .dry_run(&spec, Duration::from_secs(1))
            .expect("fake executor should report dry-run success");

        let argv = fs::read_to_string(argv_path).unwrap();
        let config_json = fs::read_to_string(config_copy).unwrap();
        assert!(argv.contains("--experimental"));
        assert!(argv.contains("--dry-run"));
        assert!(argv.contains("--config"));
        for captured in [&argv, &config_json, &result.stdout, &result.stderr] {
            assert!(!captured.contains("ANTHROPIC_API_KEY"));
            assert!(!captured.contains("proxy-with-creds"));
            assert!(!captured.contains("secret"));
        }
    }

    #[test]
    fn dry_run_clears_inherited_parent_environment() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 if [ \"${{ANTHROPIC_API_KEY+x}}\" = x ]; then\n\
                   echo inherited-secret-leaked >&2\n\
                   exit 9\n\
                 fi\n\
                 echo '{}'\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let result = with_parent_secret_env(|| {
            executor
                .dry_run(&spec, Duration::from_secs(1))
                .expect("dry-run should not inherit provider secrets")
        });

        assert!(!result.stderr.contains("inherited-secret-leaked"));
    }

    #[test]
    fn dry_run_failure_reports_status_without_reflecting_output() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            "#!/bin/sh\necho super-secret-token\nexit 7\n",
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();

        assert_eq!(err, MxcExecutorError::DryRunFailed { code: Some(7) });
        assert!(!err.to_string().contains("super-secret-token"));
    }

    #[test]
    fn dry_run_malformed_success_output_is_rejected() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\necho unexpected\nexit 0\n", 0o700);
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();

        assert_eq!(err, MxcExecutorError::MalformedDryRunOutput);
    }

    #[test]
    fn dry_run_timeout_kills_executor() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let descendant_pid = root.path().join("descendant.pid");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\nsleep 5 &\necho $! > {}\nwait\n",
                shell_quote_path(&descendant_pid)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        let err = executor
            .dry_run(&spec, Duration::from_millis(200))
            .unwrap_err();

        assert_eq!(err, MxcExecutorError::Timeout { timeout_ms: 200 });
        let pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_process_stopped(pid);
    }

    #[test]
    fn dry_run_rejects_manual_specs_with_filtered_or_malformed_env() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut spec =
            translate_sandbox_config(&config(policy(NetworkMode::Block), workspace.path().into()))
                .unwrap();

        spec.process
            .env
            .push("ANTHROPIC_API_KEY=super-secret".into());
        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            err,
            MxcExecutorError::FilteredEnv {
                key: "ANTHROPIC_API_KEY".into()
            }
        );

        spec.process.env = vec!["ANTHROPIC_API_KEY-super-secret".into()];
        let err = executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err();
        assert_eq!(err, MxcExecutorError::MalformedEnv);
        assert!(!err.to_string().contains("super-secret"));
    }

    #[test]
    fn dry_run_allows_only_axis_generated_proxy_env_when_authorized() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (_network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let allowed_proxy_env = allowed_proxy_env(&proxy);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        let mut spec = MxcExecutionSpec::from_sandbox_config_with_network_mode(
            &config,
            MxcNetworkTranslationMode::StrictProxyEnforcedByAxis,
        )
        .unwrap();
        apply_proxy_env_to_spec(&mut spec, &proxy);
        let expected_proxy = format!(
            "HTTP_PROXY=http://{}:{proxy_port}",
            super::super::netns::proxy_netns_allocation(id, proxy_port).host_addr
        );

        assert!(spec.process.env.contains(&expected_proxy));
        assert!(
            !spec
                .process
                .env
                .iter()
                .any(|entry| entry.contains("proxy-with-creds"))
        );

        executor
            .dry_run_with_allowed_env(&spec, Duration::from_secs(1), &allowed_proxy_env)
            .unwrap();
        assert_eq!(
            executor.dry_run(&spec, Duration::from_secs(1)).unwrap_err(),
            MxcExecutorError::FilteredEnv {
                key: "HTTP_PROXY".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn default_mxc_launch_skips_dry_run_preflight() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let dry_marker = root.path().join("dry-count");
        let run_marker = root.path().join("run-count");
        write_counting_mxc_executor(&executable, &dry_marker, &run_marker, 0o700);
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let trace = crate::sandbox::StartupTrace::new();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.startup_trace = Some(trace.clone());

        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        assert!(
            !dry_marker.exists(),
            "normal MXC construction must not spawn --dry-run"
        );
        assert!(
            !run_marker.exists(),
            "normal MXC construction must not spawn the runtime executor"
        );
        assert!(
            !trace
                .phases()
                .iter()
                .any(|phase| phase.phase == "backend.preflight.mxc_dry_run"),
            "normal MXC construction must not record dry-run preflight"
        );

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert!(
            !dry_marker.exists(),
            "normal MXC launch must skip --dry-run"
        );
        assert_eq!(fs::read_to_string(run_marker).unwrap(), "run\n");
        assert!(
            !trace
                .phases()
                .iter()
                .any(|phase| phase.phase == "backend.preflight.mxc_dry_run"),
            "normal MXC launch metrics must not include dry-run preflight"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn explicit_mxc_dry_run_preflight_runs_before_start() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let dry_marker = root.path().join("dry-count");
        let run_marker = root.path().join("run-count");
        write_counting_mxc_executor(&executable, &dry_marker, &run_marker, 0o700);
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let trace = crate::sandbox::StartupTrace::new();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.backend_preflight = BackendPreflight::DryRun;
        config.startup_trace = Some(trace.clone());

        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        assert_eq!(fs::read_to_string(&dry_marker).unwrap(), "dry\n");
        assert!(
            !run_marker.exists(),
            "dry-run preflight must not start user code"
        );
        assert!(
            trace
                .phases()
                .iter()
                .any(|phase| phase.phase == "backend.preflight.mxc_dry_run"),
            "explicit dry-run preflight should be visible in startup metrics"
        );

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(fs::read_to_string(dry_marker).unwrap(), "dry\n");
        assert_eq!(fs::read_to_string(run_marker).unwrap(), "run\n");
    }

    #[test]
    fn explicit_mxc_dry_run_preflight_reports_malformed_output() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let run_marker = root.path().join("run-count");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo unexpected\n\
                   exit 0\n\
                 fi\n\
                 echo run >> {}\n",
                shell_quote_path(&run_marker)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.backend_preflight = BackendPreflight::DryRun;

        let err = match MxcLinuxSandbox::new_with_executor(&config, executor, launcher) {
            Ok(_) => panic!("expected malformed MXC dry-run validation to fail"),
            Err(err) => err,
        };

        match err {
            SandboxError::IsolationFailed(message) => {
                assert!(message.contains("MXC Linux dry-run validation failed"));
                assert!(
                    message.contains(
                        "MXC dry-run exited successfully without reporting validation success"
                    ),
                    "unexpected dry-run validation error: {message}"
                );
                assert!(
                    !message.contains("unexpected"),
                    "dry-run output should not be reflected in errors: {message}"
                );
            }
            other => panic!("expected dry-run validation failure, got {other:?}"),
        }
        assert!(
            !run_marker.exists(),
            "dry-run validation failure must happen before user code"
        );
    }

    #[test]
    fn proxy_mode_keeps_provider_credentials_out_of_mxc_launch_state() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let argv_path = root.path().join("argv");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 printf '%s\\n' \"$@\" > {}\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&argv_path),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let allowed_proxy_env = allowed_proxy_env(&proxy);
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        policy.network.policies.push(inference_endpoint_policy());
        policy
            .inference
            .routes
            .push(axis_core::policy::InferenceRoute {
                name: "mock-provider".into(),
                provider: Some("openai".into()),
                endpoint: Some("http://inference.local/v1/chat/completions".into()),
                model: None,
                api_key_env: Some("OPENAI_API_KEY".into()),
                protocols: Vec::new(),
            });
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.env = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("CUSTOM".into(), "kept".into()),
            ("OPENAI_API_KEY".into(), "provider-secret".into()),
            ("HTTPS_PROXY".into(), "http://proxy-with-creds".into()),
        ];
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(allocation.proxy_addr);
        config.backend_preflight = BackendPreflight::DryRun;

        let _sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .expect("MXC construction should accept only sanitized env and Axis proxy env");

        let argv = fs::read_to_string(argv_path).unwrap();
        let config_json = fs::read_to_string(config_copy).unwrap();
        let captured_config: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        let captured_env = captured_config["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let mut expected_env = vec!["PATH=/usr/bin".to_string(), "CUSTOM=kept".to_string()];
        expected_env.extend(
            allowed_proxy_env
                .iter()
                .map(|(key, value)| format!("{key}={value}")),
        );
        assert_eq!(captured_env, expected_env);

        let forbidden = [
            "OPENAI_API_KEY",
            "provider-secret",
            "proxy-with-creds",
            "api.openai.com",
            "mock-provider",
            "Authorization",
        ];
        for captured in [&argv, &config_json] {
            for needle in forbidden {
                assert!(
                    !captured.contains(needle),
                    "MXC launch state leaked provider boundary value {needle}: {captured}"
                );
            }
        }
    }

    #[test]
    fn seccomp_launch_rewrites_command_and_mounts_private_filter_readonly() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        config.command = "/bin/sh".into();
        config.args = vec!["-c".into(), "echo '$PATH'".into()];
        config.backend_preflight = BackendPreflight::DryRun;

        let sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher.clone())
            .expect("fake MXC dry-run should accept rewritten command");

        let config_json = fs::read_to_string(config_copy).unwrap();
        let json: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        let command_line = json["process"]["commandLine"].as_str().unwrap();
        assert!(command_line.contains("axis-seccomp-launcher"));
        assert!(command_line.contains("--filter"));
        assert!(command_line.contains("-- /bin/sh -c 'echo '\\''$PATH'\\'''"));
        assert!(!command_line.contains("ANTHROPIC_API_KEY"));
        assert!(!command_line.contains("proxy-with-creds"));

        let readonly_paths = json["filesystem"]["readonlyPaths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(readonly_paths.contains(&launcher.path().to_str().unwrap()));
        let filter_path = readonly_paths
            .iter()
            .copied()
            .find(|path| path.contains("axis-mxc-seccomp-") && path.ends_with(".bpf"))
            .expect("MXC config should mount the private seccomp filter readonly");
        assert!(
            Path::new(filter_path).exists(),
            "filter file must stay alive while sandbox is alive"
        );

        drop(sandbox);
        assert!(
            !Path::new(filter_path).exists(),
            "filter file should be removed when sandbox state is dropped"
        );
    }

    #[test]
    fn interactive_terminal_wraps_pty_bridge_inside_seccomp_launcher() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let bridge_helper = root.path().join("axis");
        write_executable(&bridge_helper, "#!/bin/sh\nexit 127\n", 0o700);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        config.command = "/bin/sh".into();
        config.args = vec!["-c".into(), "test -t 0 && test -t 1".into()];
        config.capture_output = false;
        config.interactive_terminal = true;
        config.pty_bridge_helper = Some(bridge_helper.clone());
        config.backend_preflight = BackendPreflight::DryRun;

        let sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher.clone())
            .expect("fake MXC dry-run should accept PTY bridge launch");

        let config_json = fs::read_to_string(config_copy).unwrap();
        let json: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        let command_line = json["process"]["commandLine"].as_str().unwrap();
        assert!(sandbox.pty_bridge.is_some());
        assert!(command_line.starts_with(&shell_quote_path(launcher.path())));
        assert!(command_line.contains("--filter"));
        assert!(command_line.contains("__axis-pty-bridge --socket"));
        assert!(command_line.contains("-- /bin/sh -c 'test -t 0 && test -t 1'"));
        assert!(
            command_line.contains(&shell_quote_path(&bridge_helper)),
            "command line should invoke the caller supplied bridge helper: {command_line}"
        );
    }

    #[test]
    fn non_interactive_terminal_does_not_prepare_pty_bridge() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" > {}\n\
                 echo '{}'\n",
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        config.command = "/bin/sh".into();
        config.args = vec!["-c".into(), "test ! -t 0".into()];
        config.capture_output = false;
        config.backend_preflight = BackendPreflight::DryRun;

        let sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher)
            .expect("fake MXC dry-run should accept non-interactive launch");

        assert!(sandbox.pty_bridge.is_none());
        assert!(
            !workspace.path().join(".axis-pty").exists(),
            "non-interactive MXC construction must not create PTY runtime state"
        );
        let config_json = fs::read_to_string(config_copy).unwrap();
        let json: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        let command_line = json["process"]["commandLine"].as_str().unwrap();
        assert!(!command_line.contains("__axis-pty-bridge"));
        assert!(command_line.contains("-- /bin/sh -c 'test ! -t 0'"));
    }

    #[test]
    fn invalid_seccomp_policy_fails_before_executor_resolution() {
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.process.blocked_syscalls = vec!["not_a_real_syscall".into()];
        let config = config(policy, workspace.path().into());

        let result = MxcLinuxSandbox::new_with_resolvers(
            &config,
            |_| panic!("executor must not be resolved after seccomp preparation failure"),
            || panic!("launcher must not be resolved after seccomp preparation failure"),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        );
        let Err(err) = result else {
            panic!("expected seccomp preparation failure");
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("unknown syscall"));
    }

    #[test]
    fn denied_seccomp_launcher_path_fails_before_executor_resolution() {
        let root = secure_tempdir();
        let workspace = root.path().join("workspace");
        let denied = root.path().join("denied");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&denied).unwrap();
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
        let launcher_path = denied.join("axis-seccomp-launcher");
        write_executable(&launcher_path, "#!/bin/sh\nexit 127\n", 0o700);
        let launcher = MxcSeccompLauncher::from_injected_path(&launcher_path).unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.filesystem.compatibility = Compatibility::BestEffort;
        policy
            .filesystem
            .deny
            .push(denied.to_string_lossy().into_owned());
        let config = config(policy, workspace);

        let result = MxcLinuxSandbox::new_with_resolvers(
            &config,
            |_| panic!("executor must not be resolved when seccomp support path is denied"),
            || Ok(launcher),
            || Ok(no_proxy_network_strategy()),
            || Ok(no_resource_limits_strategy()),
        );
        let Err(err) = result else {
            panic!("expected denied seccomp launcher path failure");
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("seccomp launcher path"));
        assert!(err.to_string().contains("covered by denied path"));
    }

    #[test]
    fn run_as_user_rejects_missing_and_root_users_before_support_resolution() {
        for (username, expected) in [
            ("root", "must not resolve to UID or GID 0"),
            ("axis-definitely-missing-run-as-user", "does not exist"),
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let mut policy = mxc_representable_policy(NetworkMode::Allow);
            policy.process.run_as_user = Some(username.into());
            let config = config(policy, workspace.path().into());

            let result = MxcLinuxSandbox::new_with_resolvers(
                &config,
                |_| panic!("executor must not be resolved after invalid run_as_user"),
                || panic!("seccomp launcher must not be resolved after invalid run_as_user"),
                || panic!("network strategy must not be resolved after invalid run_as_user"),
                || panic!("resource strategy must not be resolved after invalid run_as_user"),
            );
            let Err(err) = result else {
                panic!("expected invalid run_as_user '{username}' to fail");
            };

            assert!(matches!(err, SandboxError::IsolationFailed(_)));
            assert!(err.to_string().contains("MXC run_as_user"));
            assert!(
                err.to_string().contains(expected),
                "unexpected error for {username}: {err}"
            );
        }
    }

    #[test]
    fn seccomp_filter_for_identity_is_owner_private() {
        let mut filter = tempfile::NamedTempFile::new().unwrap();
        filter.write_all(b"filter").unwrap();
        filter.flush().unwrap();
        filter
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        let identity = super::super::identity::ResolvedIdentity {
            username: "current-user".into(),
            uid: super::super::identity::current_euid(),
            gid: super::super::identity::current_egid(),
            home: None,
        };

        prepare_seccomp_filter_for_identity(&filter, &identity).unwrap();

        let metadata = filter.as_file().metadata().unwrap();
        assert_eq!(metadata.uid(), identity.uid);
        assert_eq!(metadata.gid(), identity.gid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    }

    #[test]
    fn sealed_mxc_config_fd_avoids_stdio_slots_when_stdio_is_closed() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        config.write_all(b"{}").unwrap();
        config.flush().unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                libc::close(0);
                libc::close(1);
                libc::close(2);
            }
            let ok = match sealed_mxc_config_fd(&config) {
                Ok(fd) => {
                    let ok = fd >= 3;
                    unsafe {
                        libc::close(fd);
                    }
                    ok
                }
                Err(_) => false,
            };
            unsafe {
                libc::_exit(if ok { 0 } else { 1 });
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "sealed config fd was not duplicated above stdio: status={status}"
        );
    }

    #[test]
    fn mxc_run_as_user_exec_boundary_sets_no_new_privs() {
        let identity = super::super::identity::ResolvedIdentity {
            username: "current-user".into(),
            uid: super::super::identity::current_euid(),
            gid: super::super::identity::current_egid(),
            home: None,
        };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            let ok = set_no_new_privs_for_mxc_run_as_user(Some(&identity)).is_ok()
                && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
            unsafe {
                libc::_exit(if ok { 0 } else { 1 });
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "MXC run_as_user child did not set no_new_privs: status={status}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_captures_output_exit_code_and_removes_private_config() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_path_record = root.path().join("config-path");
        let config_copy = root.path().join("config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 printf '%s\\n' \"$config\" > {}\n\
                 cat \"$config\" > {}\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 if IFS= read -r _line; then\n\
                   echo stdin was not closed >&2\n\
                   exit 8\n\
                 fi\n\
                 echo mxc-stdout\n\
                 echo mxc-stderr >&2\n\
                 exit 7\n",
                shell_quote_path(&config_path_record),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.capture_output = true;

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 7);
        assert_eq!(
            fs::read_to_string(workspace.path().join("stdout.log")).unwrap(),
            "mxc-stdout\n"
        );
        assert_eq!(
            fs::read_to_string(workspace.path().join("stderr.log")).unwrap(),
            "mxc-stderr\n"
        );
        let config_path = fs::read_to_string(config_path_record).unwrap();
        let config_path = config_path.trim();
        assert!(
            config_path.starts_with(std::env::temp_dir().to_string_lossy().as_ref())
                && config_path.contains("axis-mxc-")
                && config_path.ends_with(".json"),
            "runtime MXC config should be passed by private temp path, got {config_path:?}"
        );
        assert!(sandbox.config_file.is_none());
        let config_json = fs::read_to_string(config_copy).unwrap();
        assert!(!config_json.contains("ANTHROPIC_API_KEY"));
        assert!(!config_json.contains("proxy-with-creds"));
        assert!(!config_json.contains("secret"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_runtime_run_as_user_applies_identity_before_process_rlimit() {
        if super::super::identity::current_euid() != 0 {
            eprintln!("MXC run_as_user runtime test requires euid 0 (test skipped)");
            return;
        }
        let Ok(username) = std::env::var("AXIS_TEST_RUN_AS_USER") else {
            eprintln!("AXIS_TEST_RUN_AS_USER not set (test skipped)");
            return;
        };
        let target = match super::super::identity::resolve_run_as_user(
            &username,
            &super::super::identity::SystemUserLookup,
        ) {
            Ok(identity) => identity,
            Err(err) => {
                eprintln!("cannot use AXIS_TEST_RUN_AS_USER='{username}': {err} (test skipped)");
                return;
            }
        };

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let executable = root.path().join("lxc-exec");
        let workspace = tempfile::tempdir().unwrap();
        let config_copy = workspace.path().join("run-config-copy");
        let uid_path = workspace.path().join("uid");
        let gid_path = workspace.path().join("gid");
        let limits_path = workspace.path().join("limits");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 if [ \"$mode\" = dry ]; then\n\
                   cat \"$config\" >/dev/null\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 cat \"$config\" > {}\n\
                 id -u > {}\n\
                 id -g > {}\n\
                 cat /proc/self/limits > {}\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&config_copy),
                shell_quote_path(&uid_path),
                shell_quote_path(&gid_path),
                shell_quote_path(&limits_path),
            ),
            0o755,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let launcher = fake_seccomp_launcher(&root);
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.process.run_as_user = Some(username);
        policy.process.max_processes = 4096;
        policy.process.max_memory_mb = 0;
        policy.process.cpu_rate_percent = 0;
        policy.filesystem.read_write.push("{tmpdir}".into());
        let mut config = config(policy, workspace.path().into());
        config.capture_output = false;
        let resource_strategy = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: false,
            process_limit: strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };

        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            resource_strategy,
        )
        .unwrap();
        let workspace_metadata = fs::metadata(workspace.path()).unwrap();
        assert_eq!(workspace_metadata.uid(), target.uid);
        assert_eq!(workspace_metadata.gid(), target.gid);
        let tmpdir_metadata =
            fs::metadata(super::super::landlock::sandbox_tmpdir(workspace.path())).unwrap();
        assert_eq!(tmpdir_metadata.uid(), target.uid);
        assert_eq!(tmpdir_metadata.gid(), target.gid);
        let filter_metadata = sandbox
            .seccomp_filter_file
            .as_ref()
            .unwrap()
            .as_file()
            .metadata()
            .unwrap();
        assert_eq!(filter_metadata.uid(), target.uid);
        assert_eq!(filter_metadata.gid(), target.gid);
        assert_eq!(filter_metadata.permissions().mode() & 0o777, 0o400);

        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(
            fs::read_to_string(uid_path).unwrap().trim(),
            target.uid.to_string()
        );
        assert_eq!(
            fs::read_to_string(gid_path).unwrap().trim(),
            target.gid.to_string()
        );
        let limits = fs::read_to_string(limits_path).unwrap();
        let max_processes = limits
            .lines()
            .find(|line| line.starts_with("Max processes"))
            .expect("process limits should include Max processes");
        assert!(
            max_processes.split_whitespace().any(|part| part == "4096"),
            "RLIMIT_NPROC should be lowered for the target user: {max_processes}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_non_capture_mode_does_not_create_daemon_logs() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let marker = root.path().join("ran");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 echo ran > {}\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&marker)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.capture_output = false;

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert!(marker.exists());
        assert!(!workspace.path().join("stdout.log").exists());
        assert!(!workspace.path().join("stderr.log").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_interactive_bridge_cleans_socket_dir_without_connection() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 exit 0\n",
                MXC_DRY_RUN_SUCCESS,
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.capture_output = false;
        config.interactive_terminal = true;
        let bridge_root = workspace.path().join(".axis-pty");
        let bridge_dir = workspace
            .path()
            .join(".axis-pty")
            .join(config.id.to_string());

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        assert!(bridge_dir.exists());

        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert!(
            !bridge_dir.exists(),
            "PTY bridge runtime directory should be removed after wait"
        );
        assert!(
            !bridge_root.exists(),
            "PTY bridge runtime parent should be removed when empty"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_parent_death_guard_kills_interactive_executor_group_and_cleans_runtime_dirs() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let descendant_pid = root.path().join("descendant.pid");
        let publication_ready = root.path().join("descendant.ready");
        let publication_release = root.path().join("descendant.release");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 : > {}\n\
                 : > {}\n\
                 while [ ! -e {} ]; do sleep 1; done\n\
                 sleep 30 &\n\
                 echo $! > {}\n\
                 wait\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&descendant_pid),
                shell_quote_path(&publication_ready),
                shell_quote_path(&publication_release),
                shell_quote_path(&descendant_pid)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let mut config = config(policy, workspace.path().into());
        config.capture_output = false;
        config.interactive_terminal = true;
        let bridge_root = workspace.path().join(".axis-pty");
        let bridge_dir = bridge_root.join(config.id.to_string());

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        assert!(
            bridge_dir.exists(),
            "PTY bridge runtime directory should exist while sandbox runs"
        );

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while !publication_ready.exists() {
            if Instant::now() >= ready_deadline {
                SandboxImpl::destroy(&mut sandbox).ok();
                panic!("MXC executor did not expose the empty pid publication state");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut publication_released = false;
        let pid = loop {
            let contents = fs::read_to_string(&descendant_pid).unwrap_or_else(|error| {
                SandboxImpl::destroy(&mut sandbox).ok();
                panic!("failed to inspect MXC executor descendant pid: {error}");
            });
            if !publication_released {
                if !contents.is_empty() {
                    SandboxImpl::destroy(&mut sandbox).ok();
                    panic!("MXC executor descendant pid was published before release");
                }
                fs::write(&publication_release, b"release\n").unwrap_or_else(|error| {
                    SandboxImpl::destroy(&mut sandbox).ok();
                    panic!("failed to release MXC executor descendant pid publication: {error}");
                });
                publication_released = true;
            }
            if let Ok(pid) = contents.trim().parse::<i32>()
                && pid > 0
            {
                break pid;
            }
            if Instant::now() >= deadline {
                SandboxImpl::destroy(&mut sandbox).ok();
                let contents = fs::read_to_string(&descendant_pid).unwrap_or_default();
                panic!(
                    "MXC executor descendant pid was not recorded as a positive integer; last contents: {contents:?}"
                );
            }
            thread::sleep(Duration::from_millis(20));
        };

        sandbox
            .parent_death_guard
            .as_mut()
            .expect("MXC start should install a parent-death guard")
            .trigger_owner_death_for_test();
        if let Some(mut child) = sandbox.child.take() {
            let process_group = child.id() as i32;
            sandbox.exit_code = Some(wait_for_killed_child(&mut child, process_group));
        }
        sandbox.cleanup_after_stop().unwrap();

        let stopped_deadline = Instant::now() + Duration::from_secs(10);
        while process_is_running(pid) {
            if Instant::now() >= stopped_deadline {
                panic!("MXC executor descendant process {pid} survived parent-death guard");
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !bridge_dir.exists(),
            "PTY bridge runtime directory should be removed during cleanup"
        );
        assert!(
            !bridge_root.exists(),
            "PTY bridge runtime parent should be removed when empty"
        );
        assert!(!tmpdir.exists(), "MXC cleanup should remove AXIS tmpdir");
    }

    #[test]
    fn mxc_pty_bridge_connected_cleanup_removes_runtime_tree() {
        let workspace = tempfile::tempdir().unwrap();
        let mut bridge = MxcPtyBridge::new(SandboxId::new(), workspace.path()).unwrap();
        let bridge_root = workspace.path().join(".axis-pty");

        bridge.start().unwrap();
        assert_eq!(
            fs::metadata(&bridge_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&bridge.runtime_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let stream = UnixStream::connect(&bridge.socket_path).unwrap();
        drop(stream);

        assert_eq!(bridge.cleanup(), None);
        assert!(
            !bridge.socket_path.exists(),
            "PTY bridge socket should be removed after connected cleanup"
        );
        assert!(
            !bridge.runtime_dir.exists(),
            "PTY bridge runtime directory should be removed after connected cleanup"
        );
        assert!(
            !bridge_root.exists(),
            "PTY bridge runtime parent should be removed after connected cleanup"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_marks_unexpected_fds_close_on_exec_before_mxc_executor() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let marker_path = root.path().join("fd-leak-marker");
        let mut marker = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&marker_path)
            .unwrap();
        let marker_fd = marker.as_raw_fd();
        clear_cloexec(marker_fd);
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 if sh -c 'printf leaked >&{marker_fd}' 2>/dev/null; then\n\
                   exit 37\n\
                 fi\n\
                 exit 0\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        marker.flush().unwrap();

        assert_eq!(code, 0);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), "");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_drops_capabilities_before_mxc_executor() {
        if !Path::new("/proc/self/status").exists() {
            eprintln!("/proc/self/status unavailable (test skipped)");
            return;
        }

        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let marker_path = root.path().join("cap-status");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 grep -E '^(CapInh|CapPrm|CapEff|CapAmb):' /proc/self/status > {}\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&marker_path)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let cap_status = fs::read_to_string(marker_path).unwrap_or_default();

        assert_eq!(code, 0);
        for label in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let expected = format!("{label}:\t0000000000000000");
            assert!(
                cap_status.contains(&expected),
                "unexpected MXC executor capability status: {cap_status}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_timeout_kills_executor_process_group_and_cleans_tmpdir() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let descendant_pid = root.path().join("descendant.pid");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 sleep 30 &\n\
                 echo $! > {}\n\
                 wait\n",
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(&descendant_pid)
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let mut config = config(policy, workspace.path().into());
        config.timeout_sec = Some(1);

        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, -1);
        let pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_process_stopped(pid);
        assert!(!tmpdir.exists(), "MXC wait should clean AXIS tmpdir");
    }

    #[test]
    fn runtime_start_failure_cleans_native_proxy_netns() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_280;
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();
        sandbox.netns_override = Some(MxcNetnsOverride {
            name: "axis-test-netns".into(),
            fd: tempfile::tempfile().unwrap().into_raw_fd(),
            cleanup: Ok(()),
        });
        fs::create_dir(workspace.path().join("stdout.log")).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(sandbox.netns_name.is_none());
    }

    #[test]
    fn runtime_spawn_failure_cleans_native_proxy_netns_after_setns_error() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = 31_281;
        let (network, proxy) = native_mxc_proxy_strategies(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(super::super::netns::proxy_bind_addr(id, proxy_port));
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network,
            proxy,
            no_resource_limits_strategy(),
        )
        .unwrap();
        sandbox.netns_override = Some(MxcNetnsOverride {
            name: "axis-test-netns".into(),
            fd: tempfile::tempfile().unwrap().into_raw_fd(),
            cleanup: Ok(()),
        });

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("enter network namespace"));
        assert!(sandbox.netns_name.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn runtime_try_wait_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let deadline = Instant::now() + Duration::from_secs(5);
        let err = loop {
            match SandboxImpl::try_wait(&mut sandbox) {
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => panic!("MXC executor did not exit before try_wait deadline"),
                Ok(Some(code)) => {
                    panic!("try_wait should report netns cleanup failure, got code {code}")
                }
                Err(err) => break err,
            }
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn runtime_destroy_reports_netns_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "sleep 30");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        inject_failing_netns_cleanup(&mut sandbox);

        let err = SandboxImpl::destroy(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("netns cleanup failed"));
        assert!(
            sandbox.netns_name.is_some(),
            "failed cleanup should leave netns name inspectable"
        );
    }

    #[test]
    fn helper_token_cleanup_clears_mxc_netns_state_when_destroy_succeeds() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        sandbox.netns_name = Some("axis-test-helper-netns".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token());
        let sandbox_id = sandbox.id;

        let cleanup =
            sandbox.cleanup_netns_with_helper_token("axis-test-helper-netns", |id, token| {
                assert_eq!(id, sandbox_id);
                assert_eq!(token, helper_test_token());
                Ok(super::super::netns::HelperCleanupOutcome::Destroyed)
            });

        assert!(cleanup.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
    }

    #[test]
    fn helper_token_cleanup_accepts_mxc_authenticated_completed_outcome() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        sandbox.netns_name = Some("axis-test-helper-netns".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token());

        let cleanup = sandbox.cleanup_netns_with_helper_token("axis-test-helper-netns", |_, _| {
            Ok(super::super::netns::HelperCleanupOutcome::AlreadyCompleted)
        });

        assert!(cleanup.is_none());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
    }

    #[test]
    fn helper_token_cleanup_preserves_mxc_retry_state_on_destroy_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        sandbox.netns_name = Some("axis-test-helper-netns".into());
        sandbox.netns_helper_destroy_token = Some(helper_test_token());

        let cleanup = sandbox
            .cleanup_netns_with_helper_token("axis-test-helper-netns", |_, _| {
                Err("iptables cleanup failed".into())
            })
            .expect("failed helper cleanup should be reported");

        assert!(cleanup.contains("axis-test-helper-netns"));
        assert!(cleanup.contains("iptables cleanup failed"));
        assert_eq!(
            sandbox.netns_name.as_deref(),
            Some("axis-test-helper-netns")
        );
        assert_eq!(
            sandbox.netns_helper_destroy_token.as_deref(),
            Some(helper_test_token().as_str())
        );
    }

    #[test]
    fn runtime_start_failure_cleans_tmpdir() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Allow);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let config = config(policy, workspace.path().into());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        let filter_path = sandbox
            .seccomp_filter_file
            .as_ref()
            .map(|file| file.path().to_path_buf())
            .expect("MXC setup should create private seccomp filter");
        assert!(
            filter_path.exists(),
            "private seccomp filter should exist before start"
        );
        std::fs::remove_file(&executable).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(!tmpdir.exists(), "start failure should clean AXIS tmpdir");
        assert!(
            !filter_path.exists(),
            "start failure should remove private seccomp filter"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lxc_runtime_captures_output_exit_code_and_removes_private_config() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        let config_path_record = root.path().join("lxc-config-path");
        let config_copy = root.path().join("lxc-config-copy");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 printf '%s\\n' \"$config\" > {}\n\
                 cat \"$config\" > {}\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 if IFS= read -r _line; then\n\
                   echo stdin was not closed >&2\n\
                   exit 8\n\
                 fi\n\
                 echo lxc-stdout\n\
                 echo lxc-stderr >&2\n\
                 exit 7\n",
                shell_quote_path(&config_path_record),
                shell_quote_path(&config_copy),
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            lxc_representable_policy(NetworkMode::Block),
            workspace.path().into(),
        );
        config.capture_output = true;
        let launch = lxc_launch_for_workspace(workspace.path());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_lxc_container_with_executor(
            &config,
            launch,
            lxc_runtime(),
            executor,
            launcher,
        )
        .unwrap();

        assert_eq!(sandbox.spec.containment, MXC_LXC_CONTAINMENT);
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 7);
        assert_eq!(
            fs::read_to_string(workspace.path().join("stdout.log")).unwrap(),
            "lxc-stdout\n"
        );
        assert_eq!(
            fs::read_to_string(workspace.path().join("stderr.log")).unwrap(),
            "lxc-stderr\n"
        );
        let config_path = fs::read_to_string(config_path_record).unwrap();
        let config_path = config_path.trim();
        assert!(
            config_path.starts_with(std::env::temp_dir().to_string_lossy().as_ref())
                && config_path.contains("axis-mxc-")
                && config_path.ends_with(".json"),
            "runtime LXC config should be passed by private temp path, got {config_path:?}"
        );
        assert!(sandbox.config_file.is_none());
        assert!(sandbox.seccomp_filter_file.is_none());
        let config_json = fs::read_to_string(config_copy).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        assert_eq!(parsed["containment"], "lxc");
        assert_eq!(parsed["lxc"]["distribution"], "alpine");
        assert_eq!(parsed["lxc"]["release"], "3.23");
        assert_eq!(parsed["lifecycle"]["destroyOnExit"], true);
        assert!(!config_json.contains("ANTHROPIC_API_KEY"));
        assert!(!config_json.contains("proxy-with-creds"));
        assert!(!config_json.contains("secret"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lxc_runtime_timeout_kills_executor_process_group_and_cleans_tmpdir() {
        let root = secure_tempdir();
        let descendant_pid = root.path().join("lxc-descendant.pid");
        let executor = fake_mxc_runtime_executor(
            &root,
            &format!(
                "sleep 30 &\n\
                 echo $! > {}\n\
                 wait",
                shell_quote_path(&descendant_pid)
            ),
        );
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = lxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let mut config = config(policy, workspace.path().into());
        config.timeout_sec = Some(1);
        let launch = lxc_launch_for_workspace(workspace.path());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_lxc_container_with_executor(
            &config,
            launch,
            lxc_runtime(),
            executor,
            launcher,
        )
        .unwrap();

        assert!(tmpdir.exists(), "MXC LXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, -1);
        let pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_process_stopped(pid);
        assert!(!tmpdir.exists(), "MXC LXC wait should clean AXIS tmpdir");
    }

    #[test]
    fn lxc_runtime_start_failure_cleans_tmpdir_and_private_seccomp_filter() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = lxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let config = config(policy, workspace.path().into());
        let launch = lxc_launch_for_workspace(workspace.path());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_lxc_container_with_executor(
            &config,
            launch,
            lxc_runtime(),
            executor,
            launcher,
        )
        .unwrap();
        let filter_path = sandbox
            .seccomp_filter_file
            .as_ref()
            .map(|file| file.path().to_path_buf())
            .expect("MXC LXC setup should create private seccomp filter");

        assert!(tmpdir.exists(), "MXC LXC setup should create AXIS tmpdir");
        assert!(
            filter_path.exists(),
            "private seccomp filter should exist before LXC start"
        );
        std::fs::remove_file(&executable).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(!tmpdir.exists(), "start failure should clean AXIS tmpdir");
        assert!(
            !filter_path.exists(),
            "start failure should remove private seccomp filter"
        );
    }

    #[test]
    fn lxc_runtime_destroy_is_idempotent_and_cleans_tmpdir() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "sleep 30");
        let workspace = tempfile::tempdir().unwrap();
        let mut policy = lxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let config = config(policy, workspace.path().into());
        let launch = lxc_launch_for_workspace(workspace.path());
        let launcher = fake_seccomp_launcher(&root);
        let mut sandbox = MxcLinuxSandbox::new_lxc_container_with_executor(
            &config,
            launch,
            lxc_runtime(),
            executor,
            launcher,
        )
        .unwrap();

        assert!(tmpdir.exists(), "MXC LXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        SandboxImpl::destroy(&mut sandbox).unwrap();
        assert!(!tmpdir.exists(), "destroy should clean AXIS tmpdir");
        assert!(sandbox.child.is_none());
        assert!(sandbox.config_file.is_none());
        assert!(sandbox.seccomp_filter_file.is_none());

        SandboxImpl::destroy(&mut sandbox).unwrap();
        assert!(
            !tmpdir.exists(),
            "repeated destroy should leave tmpdir clean"
        );
    }

    #[test]
    fn resource_strategy_allows_process_rlimit_fallback_only_with_run_as_user() {
        let process_fallback = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::RlimitNprocWithDedicatedUser,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };
        let mut policy = ProcessPolicy::default();

        let err = validate_mxc_resource_strategy(&policy, &process_fallback).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("dedicated run_as_user"));

        policy.run_as_user = Some("sandbox-user".into());
        validate_mxc_resource_strategy(&policy, &process_fallback).unwrap();

        let memory_only = strategy::ResourceStrategy::RlimitFallback {
            memory_limit: true,
            process_limit: strategy::ProcessLimitFallback::NotRequested,
            cpu_limit: strategy::CpuLimitFallback::NotRequested,
        };
        validate_mxc_resource_strategy(&ProcessPolicy::default(), &memory_only).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_enters_cgroup_before_mxc_executor_runs() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 exit 0\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        let pid = SandboxImpl::start(&mut sandbox).unwrap();

        assert_eq!(
            fs::read_to_string(cgroup_path.join("cgroup.procs"))
                .unwrap()
                .trim(),
            pid.to_string()
        );
        fs::write(cgroup_path.join("cgroup.procs"), "").unwrap();
        assert_eq!(SandboxImpl::wait(&mut sandbox).await.unwrap(), 0);
        assert!(!cgroup_path.exists(), "MXC cgroup should be cleaned");
    }

    #[test]
    fn runtime_start_failure_cleans_cgroup() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);
        fs::create_dir(workspace.path().join("stdout.log")).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::SpawnFailed(_)));
        assert!(
            !cgroup_path.exists(),
            "start failure should clean cgroup; error={err}; remaining={:?}",
            remaining_dir_entries(&cgroup_path)
        );
    }

    #[test]
    fn runtime_start_failure_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!("#!/bin/sh\necho '{}'\n", MXC_DRY_RUN_SUCCESS),
            0o700,
        );
        let executor = MxcExecutor::from_injected_path(&executable).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        fs::write(cgroup_path.join("cgroup.procs"), "1234\n").unwrap();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            strategy::ResourceStrategy::CgroupsV2 {
                support: strategy::CgroupV2Support::Writable,
            },
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);
        fs::remove_file(&executable).unwrap();

        let err = SandboxImpl::start(&mut sandbox).unwrap_err();

        assert!(err.to_string().contains("cleanup failed"));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[test]
    fn runtime_try_wait_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let err = loop {
            match SandboxImpl::try_wait(&mut sandbox) {
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => panic!("MXC executor did not exit before try_wait deadline"),
                Ok(Some(code)) => {
                    panic!("try_wait should report cgroup cleanup failure, got code {code}")
                }
                Err(err) => break err,
            }
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[test]
    fn runtime_destroy_reports_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "sleep 30");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        SandboxImpl::start(&mut sandbox).unwrap();

        let err = SandboxImpl::destroy(&mut sandbox).unwrap_err();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_wait_error_preserves_cgroup_cleanup_failure() {
        let root = secure_tempdir();
        let executor = fake_mxc_runtime_executor(&root, "exit 0");
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let launcher = fake_seccomp_launcher(&root);
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup = temp_cgroup(cgroup_root.path(), &config);
        let cgroup_path = cgroup.path().to_path_buf();
        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_resource_strategy(
            &config,
            executor,
            launcher,
            cgroup_resource_strategy(),
        )
        .unwrap();
        sandbox.cgroup_override = Some(cgroup);

        let pid = SandboxImpl::start(&mut sandbox).unwrap();
        reap_child(pid);

        let err = SandboxImpl::wait(&mut sandbox).await.unwrap_err();
        let message = err.to_string();
        let expected_wait_error = std::io::Error::from_raw_os_error(libc::ECHILD).to_string();

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(message.contains("process cleanup failed after wait error"));
        assert!(
            message.contains(&expected_wait_error),
            "wait error was not preserved in '{message}'"
        );
        assert!(message.contains("cgroup cleanup failed"));
        assert!(
            cgroup_path.exists(),
            "failed cleanup should leave cgroup inspectable"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_allow_and_block_runtime_parity() {
        if !real_mxc_process_tests_enabled() {
            eprintln!("AXIS_REAL_MXC_PROCESS_TESTS=1 not set (test skipped)");
            return;
        }
        if test_mxc_executor().is_err() {
            eprintln!(
                "safe lxc-exec unavailable; set AXIS_TEST_MXC_EXECUTOR for a test helper (test skipped)"
            );
            return;
        }
        if test_mxc_seccomp_launcher().is_err() {
            eprintln!(
                "axis-seccomp-launcher unavailable; set AXIS_TEST_AXIS_SECCOMP_LAUNCHER for a test helper (test skipped)"
            );
            return;
        }
        if find_on_path("bwrap").is_none() {
            eprintln!("bubblewrap unavailable for MXC backend (test skipped)");
            return;
        }
        if fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() != "1")
            .unwrap_or(true)
        {
            eprintln!("unprivileged user namespaces unavailable (test skipped)");
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

        let root = tempfile::tempdir().unwrap();
        let ro_dir = root.path().join("ro");
        let rw_dir = root.path().join("rw");
        let denied_dir = root.path().join("denied");
        let allow_workspace = root.path().join("allow-workspace");
        let block_workspace = root.path().join("block-workspace");
        for dir in [
            &ro_dir,
            &rw_dir,
            &denied_dir,
            &allow_workspace,
            &block_workspace,
        ] {
            std::fs::create_dir(dir).unwrap();
        }
        let ro_file = ro_dir.join("ro.txt");
        let denied_file = denied_dir.join("secret.txt");
        std::fs::write(&ro_file, "read-only").unwrap();
        std::fs::write(&denied_file, "denied").unwrap();

        let allow_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        allow_listener.set_nonblocking(true).unwrap();
        let allow_port = allow_listener.local_addr().unwrap().port();
        let mut allow_config = config(
            mxc_filesystem_policy(NetworkMode::Allow, &ro_dir, &rw_dir, &denied_dir),
            allow_workspace.clone(),
        );
        allow_config.command = python.to_string_lossy().into_owned();
        allow_config.args = vec!["-c".into(), real_mxc_allow_probe().into()];
        allow_config.working_dir = Some(allow_workspace.clone());
        allow_config.capture_output = true;
        allow_config.timeout_sec = Some(10);
        allow_config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CUSTOM".into(), "kept".into()),
            ("RO_FILE".into(), ro_file.to_string_lossy().into_owned()),
            ("RW_DIR".into(), rw_dir.to_string_lossy().into_owned()),
            (
                "DENIED_FILE".into(),
                denied_file.to_string_lossy().into_owned(),
            ),
            (
                "DENIED_DIR".into(),
                denied_dir.to_string_lossy().into_owned(),
            ),
            ("ALLOW_PORT".into(), allow_port.to_string()),
            ("ANTHROPIC_API_KEY".into(), "secret".into()),
            ("HTTPS_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut allow_sandbox = real_mxc_sandbox_for_test(&allow_config).unwrap();
        SandboxImpl::start(&mut allow_sandbox).unwrap();
        let allow_code = SandboxImpl::wait(&mut allow_sandbox).await.unwrap();
        let allow_stderr =
            fs::read_to_string(allow_workspace.join("stderr.log")).unwrap_or_default();
        assert_eq!(
            allow_code, 0,
            "MXC allow-mode probe failed:\n{allow_stderr}"
        );
        assert!(
            listener_observed_probe(&allow_listener),
            "MXC allow-mode sandbox did not reach host loopback listener"
        );
        assert_eq!(
            fs::read_to_string(allow_workspace.join("stdout.log")).unwrap(),
            "allow-stdout\n"
        );
        assert_eq!(fs::read_to_string(rw_dir.join("rw.txt")).unwrap(), "rw");
        assert_eq!(
            fs::read_to_string(allow_workspace.join("workspace.txt")).unwrap(),
            "workspace"
        );
        assert!(
            !denied_dir.join("new.txt").exists(),
            "MXC deniedPath tmpfs mask must not write through to the host path"
        );
        allow_sandbox.destroy().unwrap();

        let block_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let block_port = block_listener.local_addr().unwrap().port();
        let mut block_config = config(
            mxc_filesystem_policy(NetworkMode::Block, &ro_dir, &rw_dir, &denied_dir),
            block_workspace.clone(),
        );
        block_config.command = python.to_string_lossy().into_owned();
        block_config.args = vec!["-c".into(), real_mxc_block_probe().into()];
        block_config.working_dir = Some(block_workspace.clone());
        block_config.capture_output = true;
        block_config.timeout_sec = Some(10);
        block_config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("BLOCK_PORT".into(), block_port.to_string()),
            ("HTTP_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut block_sandbox = real_mxc_sandbox_for_test(&block_config).unwrap();
        SandboxImpl::start(&mut block_sandbox).unwrap();
        let block_code = SandboxImpl::wait(&mut block_sandbox).await.unwrap();
        let block_stderr =
            fs::read_to_string(block_workspace.join("stderr.log")).unwrap_or_default();
        assert_eq!(
            block_code, 0,
            "MXC block-mode probe failed:\n{block_stderr}"
        );
        assert_eq!(
            fs::read_to_string(block_workspace.join("stdout.log")).unwrap(),
            "block-stdout\n"
        );
        assert!(block_workspace.join("block-ok").exists());
        block_sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_payload_cannot_read_axis_config_fd() {
        if !real_mxc_process_tests_enabled() {
            eprintln!("AXIS_REAL_MXC_PROCESS_TESTS=1 not set (test skipped)");
            return;
        }
        if test_mxc_executor().is_err() {
            eprintln!(
                "safe lxc-exec unavailable; set AXIS_TEST_MXC_EXECUTOR for a test helper (test skipped)"
            );
            return;
        }
        if test_mxc_seccomp_launcher().is_err() {
            eprintln!(
                "axis-seccomp-launcher unavailable; set AXIS_TEST_AXIS_SECCOMP_LAUNCHER for a test helper (test skipped)"
            );
            return;
        }
        if find_on_path("bwrap").is_none() {
            eprintln!("bubblewrap unavailable for MXC backend (test skipped)");
            return;
        }
        if fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() != "1")
            .unwrap_or(true)
        {
            eprintln!("unprivileged user namespaces unavailable (test skipped)");
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };

        let workspace = tempfile::tempdir().unwrap();
        let mut config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), real_mxc_config_fd_probe().into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(10);
        config.env = vec![("PATH".into(), "/usr/bin:/bin".into())];

        let mut sandbox = real_mxc_sandbox_for_test(&config).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr = fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "MXC config fd probe failed:\n{stderr}");
        assert!(workspace.path().join("config-fd-ok").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_timeout_cleans_tmpdir() {
        if !real_mxc_process_tests_enabled() {
            eprintln!("AXIS_REAL_MXC_PROCESS_TESTS=1 not set (test skipped)");
            return;
        }
        if test_mxc_executor().is_err() {
            eprintln!(
                "safe lxc-exec unavailable; set AXIS_TEST_MXC_EXECUTOR for a test helper (test skipped)"
            );
            return;
        }
        if test_mxc_seccomp_launcher().is_err() {
            eprintln!(
                "axis-seccomp-launcher unavailable; set AXIS_TEST_AXIS_SECCOMP_LAUNCHER for a test helper (test skipped)"
            );
            return;
        }
        if find_on_path("bwrap").is_none() {
            eprintln!("bubblewrap unavailable for MXC backend (test skipped)");
            return;
        }
        if fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
            .map(|value| value.trim() != "1")
            .unwrap_or(true)
        {
            eprintln!("unprivileged user namespaces unavailable (test skipped)");
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };

        let workspace = tempfile::tempdir().unwrap();
        let mut policy = mxc_representable_policy(NetworkMode::Block);
        policy.filesystem.read_write.push("{tmpdir}".into());
        let tmpdir = crate::linux::landlock::sandbox_tmpdir(workspace.path());
        let mut config = config(policy, workspace.path().into());
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), "import time; time.sleep(30)".into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(1);
        config.env = vec![("PATH".into(), "/usr/bin:/bin".into())];

        let mut sandbox = real_mxc_sandbox_for_test(&config).unwrap();
        assert!(tmpdir.exists(), "MXC setup should create AXIS tmpdir");
        SandboxImpl::start(&mut sandbox).unwrap();
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, -1, "MXC timeout should report killed child");
        assert!(!tmpdir.exists(), "MXC timeout should clean AXIS tmpdir");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_native_proxy_reaches_only_axis_proxy_address() {
        if std::env::var("AXIS_REAL_MXC_PROXY_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_MXC_PROXY_TESTS=1 not set (test skipped)");
            return;
        }
        if test_mxc_executor().is_err() {
            panic!(
                "AXIS_REAL_MXC_PROXY_TESTS=1 requires a safe lxc-exec or AXIS_TEST_MXC_EXECUTOR"
            );
        }
        if test_mxc_seccomp_launcher().is_err() {
            panic!(
                "AXIS_REAL_MXC_PROXY_TESTS=1 requires axis-seccomp-launcher or AXIS_TEST_AXIS_SECCOMP_LAUNCHER"
            );
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            panic!("AXIS_REAL_MXC_PROXY_TESTS=1 requires python3 on PATH");
        };

        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = free_tcp_port_with_adjacent_port();
        let denied_port = proxy_port + 1;
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        let mut config = config(
            mxc_representable_policy(NetworkMode::Proxy),
            workspace.path().into(),
        );
        config.id = id;
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), real_mxc_proxy_probe().into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(10);
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(allocation.proxy_addr);
        config.policy.process.max_processes = 0;
        config.policy.process.max_memory_mb = 0;
        config.policy.process.cpu_rate_percent = 0;
        config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "AXIS_EXPECT_PROXY_HOST".into(),
                allocation.host_addr.to_string(),
            ),
            ("AXIS_EXPECT_PROXY_PORT".into(), proxy_port.to_string()),
            ("AXIS_DENIED_HOST_PORT".into(), denied_port.to_string()),
            ("HTTP_PROXY".into(), "http://proxy-with-creds".into()),
        ];

        let mut sandbox = real_mxc_sandbox_for_test(&config).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let listener = TcpListener::bind((allocation.host_addr, proxy_port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let denied_listener = TcpListener::bind((allocation.host_addr, denied_port)).unwrap();
        denied_listener.set_nonblocking(true).unwrap();
        assert!(
            listener_observed_probe(&listener),
            "MXC proxy sandbox did not reach host-veth proxy listener"
        );
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr = fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "MXC proxy probe failed:\n{stderr}");
        assert!(
            !listener_observed_probe_with_timeout(&denied_listener, Duration::from_millis(500)),
            "MXC proxy sandbox reached non-proxy host-veth port"
        );
        assert!(workspace.path().join("mxc-proxy-ok").exists());
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_mxc_helper_launch_reaches_proxy_and_denies_direct_bypass() {
        if std::env::var("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH").as_deref() != Ok("1") {
            eprintln!("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 not set (test skipped)");
            return;
        }
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("MXC netns helper launch proof requires non-root euid (test skipped)");
            return;
        }
        if !super::super::netns::helper_available() {
            panic!(
                "AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 but {} is not an available setuid-root helper",
                super::super::netns::helper_path().display()
            );
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            panic!("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires python3 on PATH");
        };
        let baseline = Command::new(&python)
            .arg("-c")
            .arg("pass")
            .status()
            .expect("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires python3 to start");
        assert!(
            baseline.success(),
            "AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires a working python3"
        );

        let executor = MxcExecutor::resolve_for_helper_launch().unwrap_or_else(|err| {
            panic!("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires lxc-exec: {err}")
        });
        assert!(
            root_owned_executable_for_test(executor.path()),
            "AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires root-owned lxc-exec, got {}",
            executor.path().display()
        );
        let launcher = test_mxc_seccomp_launcher().unwrap_or_else(|err| {
            panic!("AXIS_TEST_MXC_NETNS_HELPER_LAUNCH=1 requires axis-seccomp-launcher: {err}")
        });
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = free_tcp_port_with_adjacent_port();
        let denied_port = proxy_port + 1;
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        let (network_strategy, proxy_strategy) = helper_mxc_proxy_strategies(id, proxy_port);
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        policy.process.max_processes = 0;
        policy.process.max_memory_mb = 0;
        policy.process.cpu_rate_percent = 0;
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), real_mxc_helper_proxy_probe().into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(10);
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(allocation.proxy_addr);
        config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "AXIS_EXPECT_PROXY_HOST".into(),
                allocation.host_addr.to_string(),
            ),
            ("AXIS_EXPECT_PROXY_PORT".into(), proxy_port.to_string()),
            ("AXIS_DENIED_HOST_PORT".into(), denied_port.to_string()),
            (
                "HTTPS_PROXY".into(),
                "http://stale-proxy-with-secret".into(),
            ),
        ];

        let mut sandbox = MxcLinuxSandbox::new_with_executor_and_strategies(
            &config,
            executor,
            launcher,
            network_strategy,
            proxy_strategy,
            no_resource_limits_strategy(),
        )
        .unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        let helper_token = sandbox
            .netns_helper_destroy_token
            .clone()
            .expect("MXC helper launch should record a destroy token");
        let listener = TcpListener::bind((allocation.host_addr, proxy_port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let denied_listener = TcpListener::bind((allocation.host_addr, denied_port)).unwrap();
        denied_listener.set_nonblocking(true).unwrap();
        assert!(
            listener_observed_probe(&listener),
            "host-veth proxy listener did not observe MXC helper-launched sandbox"
        );
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr = fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();

        assert_eq!(code, 0, "MXC helper proxy probe failed:\n{stderr}");
        assert!(
            !listener_observed_probe_with_timeout(&denied_listener, Duration::from_millis(500)),
            "host-veth denied listener observed direct non-proxy egress"
        );
        assert!(workspace.path().join("mxc-proxy-ok").exists());
        assert!(sandbox.netns_name.is_none());
        assert!(sandbox.netns_helper_destroy_token.is_none());
        let stale_destroy = super::super::netns::destroy_netns_with_helper_token(id, &helper_token);
        assert!(stale_destroy.is_err(), "helper state survived wait");
        sandbox.destroy().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_mxc_outer_connect_attribution_records_connecting_executable_before_exec() {
        if std::env::var("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION").as_deref() != Ok("1") {
            eprintln!(
                "seccomp notify attribution proof skipped; set AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1"
            );
            return;
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            panic!("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1 requires python3 on PATH");
        };
        let Some(shell) = find_on_path("sh") else {
            panic!("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1 requires sh on PATH");
        };

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let store = ConnectAttributionStore::default();
        let root = secure_tempdir();
        let probe = root.path().join("connect_then_exec.py");
        let host_literal = serde_json::to_string(&proxy_addr.ip().to_string()).unwrap();
        let shell_literal = serde_json::to_string(&shell.to_string_lossy()).unwrap();
        fs::write(
            &probe,
            format!(
                r#"
import os
import socket

sock = socket.create_connection(({host_literal}, {port}), timeout=5)
os.dup2(sock.fileno(), 3)
os.set_inheritable(3, True)
os.execv({shell_literal}, [{shell_literal}, "-c", "sleep 1"])
"#,
                port = proxy_addr.port()
            ),
        )
        .unwrap();
        let executor = fake_mxc_runtime_executor(
            &root,
            &format!("{} {}", shell_quote_path(&python), shell_quote_path(&probe)),
        );
        let launcher = fake_seccomp_launcher(&root);
        let workspace = tempfile::tempdir().unwrap();
        let config = config(
            mxc_representable_policy(NetworkMode::Allow),
            workspace.path().into(),
        );
        let mut sandbox = MxcLinuxSandbox::new_with_executor(&config, executor, launcher).unwrap();
        sandbox.notify_connect = true;
        sandbox.proxy_addr = Some(proxy_addr);
        sandbox.connect_attribution = Some(store.clone());

        SandboxImpl::start(&mut sandbox).unwrap();
        let (_stream, peer_addr) = accept_with_deadline(&listener, Duration::from_secs(5));
        let record = consume_attribution_with_deadline(&store, sandbox.id, peer_addr, proxy_addr);
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        let canonical_shell = std::fs::canonicalize(&shell).unwrap_or(shell);
        assert_ne!(
            record.executable_path, canonical_shell,
            "MXC attribution used post-connect exec identity"
        );
        assert_eq!(record.executable_path, python);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_real_mxc_binary_restricted_proxy_authorizes_connect_attribution() {
        if std::env::var("AXIS_REAL_MXC_PROXY_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_MXC_PROXY_TESTS=1 not set (test skipped)");
            return;
        }
        if std::env::var("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION").as_deref() != Ok("1") {
            eprintln!(
                "seccomp notify attribution proof skipped; set AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1"
            );
            return;
        }
        if test_mxc_executor().is_err() {
            panic!(
                "AXIS_REAL_MXC_PROXY_TESTS=1 requires a safe lxc-exec or AXIS_TEST_MXC_EXECUTOR"
            );
        }
        if test_mxc_seccomp_launcher().is_err() {
            panic!(
                "AXIS_REAL_MXC_PROXY_TESTS=1 requires axis-seccomp-launcher or AXIS_TEST_AXIS_SECCOMP_LAUNCHER"
            );
        }

        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            panic!("AXIS_REAL_MXC_PROXY_TESTS=1 requires python3 on PATH");
        };

        run_real_mxc_binary_restricted_proxy_case(
            &python,
            python.to_string_lossy().as_ref(),
            "200",
            "allowed",
        )
        .await;
        run_real_mxc_binary_restricted_proxy_case(
            &python,
            "/usr/bin/not-the-python-used-by-this-test",
            "403",
            "wrong-binary-denied",
        )
        .await;
    }

    async fn run_real_mxc_binary_restricted_proxy_case(
        python: &Path,
        allowed_binary: &str,
        expected_status: &str,
        marker_name: &str,
    ) {
        let workspace = tempfile::tempdir().unwrap();
        let id = SandboxId::new();
        let proxy_port = free_tcp_port_with_adjacent_port();
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        let mut policy = mxc_representable_policy(NetworkMode::Proxy);
        let mut endpoint = inference_endpoint_policy();
        endpoint.binaries = vec![BinaryMatch {
            path: allowed_binary.into(),
        }];
        policy.network.policies.push(endpoint);
        policy.process.max_processes = 0;
        policy.process.max_memory_mb = 0;
        policy.process.cpu_rate_percent = 0;
        let store = ConnectAttributionStore::default();
        let mut config = config(policy, workspace.path().into());
        config.id = id;
        config.command = python.to_string_lossy().into_owned();
        config.args = vec!["-c".into(), real_mxc_proxy_connect_probe().into()];
        config.working_dir = Some(workspace.path().into());
        config.capture_output = true;
        config.timeout_sec = Some(10);
        config.proxy_port = proxy_port;
        config.proxy_addr = Some(allocation.proxy_addr);
        config.connect_attribution = Some(store.clone());
        config.env = vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "AXIS_EXPECT_PROXY_HOST".into(),
                allocation.host_addr.to_string(),
            ),
            ("AXIS_EXPECT_PROXY_PORT".into(), proxy_port.to_string()),
            ("AXIS_EXPECT_CONNECT_STATUS".into(), expected_status.into()),
            ("AXIS_MARKER".into(), marker_name.into()),
        ];

        let mut sandbox = real_mxc_sandbox_for_test(&config).unwrap();
        SandboxImpl::start(&mut sandbox).unwrap();
        let upstream = start_single_connection_mock_tcp_server().await;
        let proxy_task = start_test_axis_proxy(
            id,
            allocation.proxy_addr,
            config.policy.clone(),
            upstream,
            store.clone(),
        )
        .await;
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();
        let stderr = fs::read_to_string(workspace.path().join("stderr.log")).unwrap_or_default();
        proxy_task.abort();

        assert_eq!(
            code, 0,
            "MXC attribution proxy probe failed for {marker_name}:\n{stderr}"
        );
        assert!(workspace.path().join(marker_name).exists());
        sandbox.destroy().unwrap();
    }

    fn endpoint_policy() -> EndpointPolicy {
        EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "github.com".into(),
                port: 443,
                access: Access::ReadWrite,
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        }
    }

    fn inference_endpoint_policy() -> EndpointPolicy {
        EndpointPolicy {
            name: "inference".into(),
            endpoints: vec![Endpoint {
                host: "inference.local".into(),
                port: 443,
                access: Access::ReadWrite,
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        }
    }

    fn mxc_representable_policy(network_mode: NetworkMode) -> Policy {
        let mut policy = policy(network_mode);
        policy.filesystem = FilesystemPolicy {
            read_only: vec!["/".into()],
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };
        policy
    }

    fn lxc_representable_policy(network_mode: NetworkMode) -> Policy {
        let mut policy = policy(network_mode);
        policy.filesystem = FilesystemPolicy {
            read_write: vec!["{workspace}".into()],
            compatibility: Compatibility::HardRequirement,
            ..FilesystemPolicy::default()
        };
        policy
    }

    fn lxc_runtime() -> RuntimeProbeSnapshot {
        RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_LXC, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present)
    }

    fn lxc_proxy_runtime() -> RuntimeProbeSnapshot {
        lxc_runtime()
            .with_dependency(host_dependency::LINUX_NETNS, DependencyState::Present)
            .with_dependency(
                host_dependency::LINUX_SECCOMP_NOTIFY,
                DependencyState::Present,
            )
    }

    fn lxc_runtime_without_lxc() -> RuntimeProbeSnapshot {
        RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_CGROUP_V2, DependencyState::Present)
    }

    fn lxc_launch_for_workspace(workspace: &Path) -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::LxcDistributionRelease {
                distribution: "alpine".into(),
                release: "3.23".into(),
            },
            storage_path: None,
            working_dir: Some("/workspace".into()),
            bind_mounts: vec![ContainerBindMount {
                host_path: path_string(workspace),
                container_path: path_string(workspace),
                access: ContainerMountAccess::ReadWrite,
            }],
            destroy_on_exit: true,
        }
    }

    fn mxc_filesystem_policy(
        network_mode: NetworkMode,
        ro_dir: &Path,
        rw_dir: &Path,
        denied_dir: &Path,
    ) -> Policy {
        let mut policy = mxc_representable_policy(network_mode);
        policy.filesystem.compatibility = Compatibility::BestEffort;
        policy
            .filesystem
            .read_only
            .push(ro_dir.to_string_lossy().into_owned());
        policy
            .filesystem
            .read_write
            .push(rw_dir.to_string_lossy().into_owned());
        policy
            .filesystem
            .deny
            .push(denied_dir.to_string_lossy().into_owned());
        policy
    }

    fn native_mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        mxc_proxy_strategies(
            id,
            proxy_port,
            strategy::ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
        )
    }

    fn helper_mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        mxc_proxy_strategies(
            id,
            proxy_port,
            strategy::ProxyNetworkSetup::AxisNetnsHelperLaunch,
        )
    }

    fn mxc_proxy_strategies(
        id: SandboxId,
        proxy_port: u16,
        setup: strategy::ProxyNetworkSetup,
    ) -> (strategy::NetworkStrategy, strategy::ProxyStrategy) {
        let allocation = super::super::netns::proxy_netns_allocation(id, proxy_port);
        (
            strategy::NetworkStrategy::Proxy {
                setup,
                firewall: Some(strategy::FirewallTool::Iptables),
                host_addr: allocation.host_addr,
                sandbox_addr: allocation.sandbox_addr,
                proxy_port,
            },
            strategy::ProxyStrategy::Required {
                bind_addr: allocation.host_addr,
                sandbox_addr: allocation.host_addr,
                port: proxy_port,
            },
        )
    }

    #[test]
    fn helper_network_selects_helper_compatible_executor_resolution() {
        let id = SandboxId::new();
        let (native, _) = native_mxc_proxy_strategies(id, 3128);
        let (helper, _) = helper_mxc_proxy_strategies(id, 3128);

        assert!(!network_requires_helper_executor(&native));
        assert!(network_requires_helper_executor(&helper));
        assert!(!network_requires_helper_executor(
            &strategy::NetworkStrategy::AllowHost
        ));
        assert!(!network_requires_helper_executor(
            &strategy::NetworkStrategy::BlockedBySeccomp
        ));
        assert!(!network_requires_helper_executor(
            &strategy::NetworkStrategy::BlockedByBubblewrap
        ));
    }

    fn test_mxc_executor_from_env(path: Option<OsString>) -> Result<MxcExecutor, MxcExecutorError> {
        match path {
            Some(path) => MxcExecutor::from_injected_path(PathBuf::from(path)),
            None => MxcExecutor::resolve(),
        }
    }

    fn test_mxc_executor() -> Result<MxcExecutor, MxcExecutorError> {
        test_mxc_executor_from_env(std::env::var_os("AXIS_TEST_MXC_EXECUTOR"))
    }

    fn exact_opt_in_enabled(value: Option<&OsStr>) -> bool {
        value == Some(OsStr::new("1"))
    }

    fn real_mxc_process_tests_enabled() -> bool {
        exact_opt_in_enabled(std::env::var_os("AXIS_REAL_MXC_PROCESS_TESTS").as_deref())
    }

    #[test]
    fn real_mxc_process_test_gate_requires_exact_opt_in() {
        assert!(exact_opt_in_enabled(Some(OsStr::new("1"))));
        assert!(!exact_opt_in_enabled(None));
        assert!(!exact_opt_in_enabled(Some(OsStr::new("0"))));
        assert!(!exact_opt_in_enabled(Some(OsStr::new("true"))));
    }

    fn test_mxc_seccomp_launcher_from_env(
        path: Option<OsString>,
    ) -> Result<MxcSeccompLauncher, MxcSeccompLauncherError> {
        match path {
            Some(path) => MxcSeccompLauncher::from_injected_path(PathBuf::from(path)),
            None => MxcSeccompLauncher::resolve(),
        }
    }

    fn test_mxc_seccomp_launcher() -> Result<MxcSeccompLauncher, MxcSeccompLauncherError> {
        test_mxc_seccomp_launcher_from_env(std::env::var_os("AXIS_TEST_AXIS_SECCOMP_LAUNCHER"))
    }

    fn real_mxc_sandbox_for_test(config: &SandboxConfig) -> Result<MxcLinuxSandbox, SandboxError> {
        let executor = test_mxc_executor().map_err(|err| {
            SandboxError::IsolationFailed(format!("MXC Linux executor unavailable: {err}"))
        })?;
        let launcher = test_mxc_seccomp_launcher().map_err(|err| {
            SandboxError::IsolationFailed(format!("MXC Linux seccomp launcher unavailable: {err}"))
        })?;
        let (network_strategy, proxy_strategy) = resolve_mxc_network_strategy(config)?;
        let resource_strategy = resolve_mxc_resource_strategy(&config.policy.process)?;

        MxcLinuxSandbox::new_with_executor_and_strategies(
            config,
            executor,
            launcher,
            network_strategy,
            proxy_strategy,
            resource_strategy,
        )
    }

    async fn start_single_connection_mock_tcp_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"ok").await;
            }
        });
        addr
    }

    async fn start_test_axis_proxy(
        sandbox_id: SandboxId,
        bind_addr: SocketAddr,
        policy: Policy,
        inference_endpoint: SocketAddr,
        connect_attribution: ConnectAttributionStore,
    ) -> tokio::task::JoinHandle<()> {
        let config = axis_proxy::proxy::ProxyConfig {
            sandbox_id,
            bind_addr,
            policy,
            enable_leak_detection: false,
            inference_endpoint: Some(inference_endpoint),
            connect_attribution: Some(connect_attribution),
            enable_identity_diagnostics: false,
            timing_tx: None,
        };
        let mut proxy = axis_proxy::proxy::AxisProxy::new(config).unwrap();
        let actual_bind_addr = proxy.bind().await.unwrap();
        assert_eq!(actual_bind_addr, bind_addr);
        tokio::spawn(async move {
            let _ = proxy.run().await;
        })
    }

    fn temp_cgroup(root: &Path, config: &SandboxConfig) -> resources::CgroupHandle {
        let cgroup = resources::create_cgroup_at(root, config.id, &config.policy.process)
            .expect("temp cgroup should be created");
        fs::write(cgroup.path().join("cgroup.procs"), "").unwrap();
        cgroup
    }

    fn cgroup_resource_strategy() -> strategy::ResourceStrategy {
        strategy::ResourceStrategy::CgroupsV2 {
            support: strategy::CgroupV2Support::Writable,
        }
    }

    fn inject_failing_netns_cleanup(sandbox: &mut MxcLinuxSandbox) {
        sandbox.netns_name = Some("axis-test-netns".into());
        sandbox.netns_cleanup_result = Some(Err("destroy failed".into()));
    }

    fn helper_test_token() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    fn fake_mxc_runtime_executor(root: &tempfile::TempDir, run_script: &str) -> MxcExecutor {
        let executable = root.path().join("lxc-exec");
        write_executable(
            &executable,
            &format!(
                "#!/bin/sh\n\
                 mode=run\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                 done\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 {run_script}\n",
                MXC_DRY_RUN_SUCCESS
            ),
            0o700,
        );
        MxcExecutor::from_injected_path(&executable).unwrap()
    }

    fn write_counting_mxc_executor(
        executable: &Path,
        dry_marker: &Path,
        run_marker: &Path,
        mode: u32,
    ) {
        write_executable(
            executable,
            &format!(
                "#!/bin/sh\n\
                 set -eu\n\
                 mode=run\n\
                 config=''\n\
                 previous=''\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$arg\" = '--dry-run' ]; then mode=dry; fi\n\
                   if [ \"$previous\" = '--config' ]; then config=\"$arg\"; fi\n\
                   previous=\"$arg\"\n\
                 done\n\
                 test -n \"$config\"\n\
                 cat \"$config\" >/dev/null\n\
                 if [ \"$mode\" = dry ]; then\n\
                   echo dry >> {}\n\
                   echo '{}'\n\
                   exit 0\n\
                 fi\n\
                 echo run >> {}\n",
                shell_quote_path(dry_marker),
                MXC_DRY_RUN_SUCCESS,
                shell_quote_path(run_marker)
            ),
            mode,
        );
    }

    fn reap_child(pid: u32) {
        loop {
            let ret = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
            if ret == pid as libc::pid_t {
                return;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("waitpid({pid}) failed: {err}");
        }
    }

    fn remaining_dir_entries(path: &Path) -> Vec<String> {
        match fs::read_dir(path) {
            Ok(entries) => entries
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .unwrap_or_else(|err| format!("<error: {err}>"))
                })
                .collect(),
            Err(err) => vec![format!("<read_dir: {err}>")],
        }
    }

    fn clear_cloexec(fd: i32) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert!(ret >= 0, "F_SETFD failed: {}", io::Error::last_os_error());
    }

    fn path_string(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn write_executable(path: &Path, script: &str, mode: u32) {
        if path.file_name() == Some(OsStr::new("lxc-exec"))
            && script.starts_with("#!/bin/sh\n")
            && mode & 0o111 != 0
            && mode & 0o022 == 0
        {
            write_file(&injected_executor_script_path(path), script, 0o600);
            write_file(path, script, mode);
            return;
        }
        write_file(path, script, mode);
    }

    fn write_file(path: &Path, contents: &str, mode: u32) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn fake_seccomp_launcher(root: &tempfile::TempDir) -> MxcSeccompLauncher {
        let executable = root.path().join("axis-seccomp-launcher");
        write_executable(&executable, "#!/bin/sh\nexit 127\n", 0o700);
        MxcSeccompLauncher::from_injected_path(&executable).unwrap()
    }

    #[test]
    fn real_mxc_test_executor_override_uses_injected_path_validation() {
        let root = secure_tempdir();
        let executable = root.path().join("lxc-exec");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        assert!(
            MxcExecutor::from_path(&executable).is_err(),
            "production validation should reject test helpers under writable temp ancestors"
        );
        let executor =
            test_mxc_executor_from_env(Some(executable.clone().into_os_string())).unwrap();

        assert_eq!(executor.path(), executable);
    }

    #[test]
    fn real_mxc_test_seccomp_launcher_override_uses_injected_path_validation() {
        let root = secure_tempdir();
        let executable = root.path().join("axis-seccomp-launcher");
        write_executable(&executable, "#!/bin/sh\nexit 0\n", 0o700);

        assert!(
            MxcSeccompLauncher::from_path(&executable).is_err(),
            "production validation should reject test helpers under writable temp ancestors"
        );
        let launcher =
            test_mxc_seccomp_launcher_from_env(Some(executable.clone().into_os_string())).unwrap();

        assert_eq!(launcher.path(), executable);
    }

    fn secure_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn assert_unsafe_candidate(path: &Path, expected_reason: &str) {
        let err = MxcExecutor::from_injected_path(path).unwrap_err();
        let MxcExecutorError::UnsafeCandidate { reason, .. } = err else {
            panic!("expected unsafe candidate error, got {err:?}");
        };
        assert!(
            reason.contains(expected_reason),
            "expected reason containing '{expected_reason}', got '{reason}'"
        );
    }

    fn shell_quote_path(path: &Path) -> String {
        shell_quote_arg(&path.to_string_lossy())
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

    fn root_owned_executable_for_test(path: &Path) -> bool {
        if !path.is_absolute() {
            return false;
        }
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            let Ok(metadata) = fs::symlink_metadata(&current) else {
                return false;
            };
            if metadata.file_type().is_symlink() {
                return false;
            }
            let mode = metadata.permissions().mode();
            if current != Path::new("/") && metadata.uid() != 0 {
                return false;
            }
            if mode & 0o022 != 0 {
                return false;
            }
            if current == path {
                return metadata.is_file() && mode & 0o111 != 0;
            }
            if !metadata.is_dir() {
                return false;
            }
        }
        false
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
        listener_observed_probe_with_timeout(listener, Duration::from_secs(3))
    }

    fn listener_observed_probe_with_timeout(listener: &TcpListener, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((_stream, _addr)) => return true,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("listener accept failed: {err}"),
            }
        }
    }

    fn accept_with_deadline(
        listener: &TcpListener,
        timeout: Duration,
    ) -> (std::net::TcpStream, SocketAddr) {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok(result) => return result,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        panic!("listener accept timed out");
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("listener accept failed: {err}"),
            }
        }
    }

    fn consume_attribution_with_deadline(
        store: &ConnectAttributionStore,
        sandbox_id: SandboxId,
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    ) -> axis_core::connect_attribution::ConnectAttributionRecord {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match store.consume(sandbox_id, peer_addr, proxy_addr) {
                Ok(record) => return record,
                Err(axis_core::connect_attribution::ConnectAttributionError::Missing {
                    ..
                }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("connect attribution record missing: {err}"),
            }
        }
    }

    fn real_mxc_allow_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys

assert os.environ["CUSTOM"] == "kept"
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(10)
assert sys.stdin.read() == ""

ro_file = pathlib.Path(os.environ["RO_FILE"])
rw_dir = pathlib.Path(os.environ["RW_DIR"])
denied_file = pathlib.Path(os.environ["DENIED_FILE"])
denied_dir = pathlib.Path(os.environ["DENIED_DIR"])
assert ro_file.read_text() == "read-only"
try:
    ro_file.write_text("mutated")
except OSError:
    pass
else:
    print("read-only file was writable", file=sys.stderr)
    sys.exit(11)
rw_dir.joinpath("rw.txt").write_text("rw")
pathlib.Path("workspace.txt").write_text("workspace")
try:
    denied_file.read_text()
except OSError:
    pass
else:
    print("denied file was readable", file=sys.stderr)
    sys.exit(12)
denied_dir.joinpath("new.txt").write_text("masked-write")

sock = socket.create_connection(("127.0.0.1", int(os.environ["ALLOW_PORT"])), 3)
sock.sendall(b"allow-probe")
sock.close()
print("allow-stdout")
"#
    }

    fn real_mxc_block_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys

for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
    if key in os.environ:
        print(f"unexpected proxy env: {key}", file=sys.stderr)
        sys.exit(20)

port = int(os.environ["BLOCK_PORT"])
for address in (("127.0.0.1", port), ("::1", port)):
    try:
        sock = socket.create_connection(address, 1)
    except OSError:
        pass
    else:
        sock.close()
        print(f"network connection unexpectedly succeeded: {address}", file=sys.stderr)
        sys.exit(21)

left, right = socket.socketpair()
left.close()
right.close()
pathlib.Path("block-ok").write_text("ok")
print("block-stdout")
"#
    }

    fn real_mxc_config_fd_probe() -> &'static str {
        r#"
import os
import pathlib
import sys

leaks = []
for name in os.listdir("/proc/self/fd"):
    try:
        fd = int(name)
    except ValueError:
        continue
    if fd <= 2:
        continue

    proc_path = f"/proc/self/fd/{fd}"
    try:
        target = os.readlink(proc_path)
    except OSError:
        target = "<unreadable-link>"

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

    try:
        dup = os.open(proc_path, flags)
    except OSError:
        continue
    try:
        try:
            os.lseek(dup, 0, os.SEEK_SET)
        except OSError:
            pass
        try:
            data = os.read(dup, 65536)
        except OSError:
            continue
    finally:
        os.close(dup)

    if b'"version":"0.6.0-alpha"' in data and b'"containment":"bubblewrap"' in data:
        leaks.append((fd, target))

if leaks:
    print(f"MXC config fd leaked into payload: {leaks}", file=sys.stderr)
    sys.exit(31)

pathlib.Path("config-fd-ok").write_text("ok")
"#
    }

    fn real_mxc_proxy_probe() -> &'static str {
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

deadline = time.time() + 3
while True:
    try:
        sock = socket.create_connection((host, port), 0.25)
    except OSError:
        if time.time() >= deadline:
            raise
        time.sleep(0.05)
    else:
        break
sock.sendall(b"mxc-proxy-probe")
sock.close()

try:
    denied = socket.create_connection((host, denied_port), 1)
except OSError:
    pass
else:
    denied.close()
    print("direct non-proxy host-veth port was reachable", file=sys.stderr)
    sys.exit(30)

pathlib.Path("mxc-proxy-ok").write_text("ok")
"#
    }

    fn real_mxc_helper_proxy_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys
import time

status = pathlib.Path("/proc/self/status").read_text()
if "NoNewPrivs:\t1" not in status:
    print("helper-launched MXC target did not inherit no_new_privs", file=sys.stderr)
    sys.exit(31)

host = os.environ["AXIS_EXPECT_PROXY_HOST"]
port = int(os.environ["AXIS_EXPECT_PROXY_PORT"])
denied_port = int(os.environ["AXIS_DENIED_HOST_PORT"])
expected_proxy = f"http://{host}:{port}"
for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    assert os.environ.get(key) == expected_proxy, (key, os.environ.get(key), expected_proxy)
for key in ("NO_PROXY", "no_proxy"):
    assert os.environ.get(key) == "localhost,127.0.0.1,::1", (key, os.environ.get(key))

deadline = time.time() + 3
while True:
    try:
        sock = socket.create_connection((host, port), 0.25)
    except OSError:
        if time.time() >= deadline:
            raise
        time.sleep(0.05)
    else:
        break
sock.sendall(b"mxc-proxy-probe")
sock.close()

try:
    denied = socket.create_connection((host, denied_port), 1)
except OSError:
    pass
else:
    denied.close()
    print("direct non-proxy host-veth port was reachable", file=sys.stderr)
    sys.exit(30)

pathlib.Path("mxc-proxy-ok").write_text("ok")
"#
    }

    fn real_mxc_proxy_connect_probe() -> &'static str {
        r#"
import os
import pathlib
import socket
import sys
import time

host = os.environ["AXIS_EXPECT_PROXY_HOST"]
port = int(os.environ["AXIS_EXPECT_PROXY_PORT"])
expected_status = os.environ["AXIS_EXPECT_CONNECT_STATUS"]
marker = os.environ["AXIS_MARKER"]

deadline = time.time() + 5
while True:
    try:
        sock = socket.create_connection((host, port), 0.25)
    except OSError:
        if time.time() >= deadline:
            raise
        time.sleep(0.05)
    else:
        break
sock.sendall(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
status = b""
while not status.endswith(b"\n"):
    chunk = sock.recv(1)
    if not chunk:
        break
    status += chunk
status_text = status.decode("utf-8", "replace")
if expected_status not in status_text:
    print(f"expected CONNECT status containing {expected_status}, got {status_text!r}", file=sys.stderr)
    sys.exit(41)
pathlib.Path(marker).write_text("ok")
sock.close()
"#
    }

    fn with_parent_secret_env<T>(f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        struct EnvGuard(Option<OsString>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                // SAFETY: guarded by ENV_LOCK for the duration of the test.
                unsafe {
                    if let Some(value) = &self.0 {
                        std::env::set_var("ANTHROPIC_API_KEY", value);
                    } else {
                        std::env::remove_var("ANTHROPIC_API_KEY");
                    }
                }
            }
        }

        let previous = std::env::var_os("ANTHROPIC_API_KEY");
        // SAFETY: this test serializes process-environment mutation with a
        // module-local mutex and restores the variable before releasing it.
        unsafe {
            std::env::set_var("ANTHROPIC_API_KEY", "inherited-secret");
        }
        let _env_guard = EnvGuard(previous);
        f()
    }

    fn assert_process_stopped(pid: i32) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while process_is_running(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_is_running(pid), "process {pid} is still running");
    }

    fn process_is_running(pid: i32) -> bool {
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some((_, rest)) = stat.rsplit_once(") ")
            && let Some(state) = rest.split_whitespace().next()
        {
            return state != "Z";
        }

        // SAFETY: kill(pid, 0) performs existence/permission probing only and
        // does not deliver a signal.
        unsafe { libc::kill(pid, 0) == 0 }
    }
}
