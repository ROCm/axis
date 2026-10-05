// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows MXC ProcessContainer runtime adapter.
//!
//! AXIS owns policy validation and lifecycle. MXC owns the Windows process
//! isolation primitive. Policy surfaces that have not been proven exact are
//! rejected before the executor is resolved or user code is spawned.

use crate::sandbox::{BackendPreflight, SandboxConfig, SandboxError, SandboxImpl};
use axis_core::capability::{DependencyState, PlannerOptions, RuntimeProbeSnapshot};
use axis_core::capability_map::{BackendCapabilityMapId, host_dependency};
use axis_core::mxc_config::{self, MxcProcessWireConfig};
use axis_core::policy::{Compatibility, NetworkMode};
use axis_core::process_backend::{
    ProcessBackendFilesystemSpec, ProcessLaunchOptions, build_process_backend_execution_spec,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

const MXC_DRY_RUN_SUCCESS: &str = "Dry run completed. Result: validation passed";
const MAX_DRY_RUN_OUTPUT_BYTES: u64 = 64 * 1024;
const EXECUTOR_NAMES: &[&str] = &["wxc-exec.exe", "wxc.exe", "mxc-exec.exe"];

#[derive(Debug, Error, PartialEq, Eq)]
enum MxcWindowsError {
    #[error("no packaged Windows MXC executor was found beside AXIS or in a stable install path")]
    ExecutorUnavailable,
    #[error("unsafe Windows MXC executor candidate '{}': {reason}", path.display())]
    UnsafeExecutor { path: PathBuf, reason: String },
    #[error("Windows MXC ProcessContainer policy is unsupported: {0}")]
    UnsupportedPolicy(String),
    #[error("Windows MXC config generation failed: {0}")]
    Config(String),
    #[error("Windows MXC executor failed: {0}")]
    Executor(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MxcWindowsExecutor {
    path: PathBuf,
}

impl MxcWindowsExecutor {
    fn resolve() -> Result<Self, MxcWindowsError> {
        if let Some(path) = std::env::var_os("AXIS_MXC_EXECUTOR") {
            return Self::from_path(PathBuf::from(path));
        }
        if std::env::var_os("AXIS_RUN_MXC_PROCESS_E2E").as_deref() == Some(OsStr::new("1"))
            && let Some(path) = std::env::var_os("AXIS_TEST_MXC_EXECUTOR")
        {
            return Self::from_path(PathBuf::from(path));
        }
        Self::resolve_from_candidates(production_executor_candidates())
    }

    fn resolve_from_candidates<I, P>(candidates: I) -> Result<Self, MxcWindowsError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for candidate in candidates {
            if let Ok(executor) = Self::from_path(candidate) {
                return Ok(executor);
            }
        }
        Err(MxcWindowsError::ExecutorUnavailable)
    }

    fn from_path<P: Into<PathBuf>>(path: P) -> Result<Self, MxcWindowsError> {
        let path = path.into();
        validate_executor_path(&path, true)?;
        Ok(Self {
            path: fs::canonicalize(&path).map_err(|err| MxcWindowsError::UnsafeExecutor {
                path: path.clone(),
                reason: err.to_string(),
            })?,
        })
    }

    #[cfg(test)]
    fn from_test_path<P: Into<PathBuf>>(path: P) -> Result<Self, MxcWindowsError> {
        let path = path.into();
        validate_executor_path(&path, false)?;
        Ok(Self {
            path: fs::canonicalize(&path).map_err(|err| MxcWindowsError::UnsafeExecutor {
                path: path.clone(),
                reason: err.to_string(),
            })?,
        })
    }

    fn write_private_config(
        &self,
        config: &MxcProcessWireConfig,
    ) -> Result<tempfile::NamedTempFile, MxcWindowsError> {
        let json =
            serde_json::to_vec(config).map_err(|err| MxcWindowsError::Config(err.to_string()))?;
        let mut file = tempfile::Builder::new()
            .prefix("axis-mxc-windows-")
            .suffix(".json")
            .tempfile()
            .map_err(|err| MxcWindowsError::Config(err.to_string()))?;
        file.write_all(&json)
            .and_then(|()| file.flush())
            .map_err(|err| MxcWindowsError::Config(err.to_string()))?;
        Ok(file)
    }

    fn dry_run(
        &self,
        config: &MxcProcessWireConfig,
        timeout: Duration,
    ) -> Result<(), MxcWindowsError> {
        let config = self.write_private_config(config)?;
        let mut stdout_file =
            tempfile::tempfile().map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
        let mut stderr_file =
            tempfile::tempfile().map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
        let stdout = stdout_file
            .try_clone()
            .map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
        let stderr = stderr_file
            .try_clone()
            .map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
        let mut command = Command::new(&self.path);
        configure_executor_invocation(&mut command, config.path(), true);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        configure_executor_environment(&mut command, &self.path);
        let child = command
            .spawn()
            .map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
        let status = wait_child_with_timeout(child, timeout)?;
        let stdout = read_limited_output(&mut stdout_file)?;
        let stderr = read_limited_output(&mut stderr_file)?;
        if !status.success() {
            return Err(MxcWindowsError::Executor(format!(
                "dry-run exited with {:?}: {}",
                status.code(),
                stderr.trim()
            )));
        }
        if !stdout.contains(MXC_DRY_RUN_SUCCESS) {
            return Err(MxcWindowsError::Executor(
                "dry-run did not report validation success".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) struct MxcWindowsSandbox {
    id: axis_core::types::SandboxId,
    wire_config: MxcProcessWireConfig,
    executor: MxcWindowsExecutor,
    child: Option<MxcExecutorChild>,
    job: Option<super::job_object::JobHandle>,
    config_file: Option<tempfile::NamedTempFile>,
    exit_code: Option<i32>,
    workspace_dir: PathBuf,
    capture_output: bool,
    timeout_sec: Option<u64>,
}

enum MxcExecutorChild {
    Standard(Child),
}

impl MxcExecutorChild {
    fn id(&self) -> u32 {
        match self {
            Self::Standard(child) => child.id(),
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match self {
            Self::Standard(child) => {
                Ok(child.try_wait()?.map(|status| status.code().unwrap_or(-1)))
            }
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Standard(child) => child.kill(),
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        match self {
            Self::Standard(child) => Ok(child.wait()?.code().unwrap_or(-1)),
        }
    }
}

impl MxcWindowsSandbox {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        let wire_config = build_windows_processcontainer_config(config)
            .map_err(|err| SandboxError::IsolationFailed(err.to_string()))?;
        let executor = MxcWindowsExecutor::resolve()
            .map_err(|err| SandboxError::IsolationFailed(err.to_string()))?;
        if config.backend_preflight == BackendPreflight::DryRun {
            executor
                .dry_run(&wire_config, Duration::from_secs(5))
                .map_err(|err| SandboxError::IsolationFailed(err.to_string()))?;
        }
        Ok(Self::from_parts(config, wire_config, executor))
    }

    fn from_parts(
        config: &SandboxConfig,
        wire_config: MxcProcessWireConfig,
        executor: MxcWindowsExecutor,
    ) -> Self {
        Self {
            id: config.id,
            wire_config,
            executor,
            child: None,
            job: None,
            config_file: None,
            exit_code: None,
            workspace_dir: config.workspace_dir.clone(),
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec.or(config.policy.process.timeout_sec),
        }
    }

    #[cfg(test)]
    fn new_with_executor(
        config: &SandboxConfig,
        executor: MxcWindowsExecutor,
    ) -> Result<Self, SandboxError> {
        let wire_config = build_windows_processcontainer_config(config)
            .map_err(|err| SandboxError::IsolationFailed(err.to_string()))?;
        Ok(Self::from_parts(config, wire_config, executor))
    }

    fn cleanup_after_stop(&mut self) {
        // Closing the Job Object is the final process-tree kill boundary.
        self.job.take();
        self.config_file.take();
    }

    fn terminate_tree(&mut self) -> Result<(), SandboxError> {
        // Drop the job first so every process still assigned to it is killed.
        self.job.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait()?;
        }
        self.config_file.take();
        Ok(())
    }
}

impl SandboxImpl for MxcWindowsSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        if self.child.is_some() || self.exit_code.is_some() {
            return Err(SandboxError::SpawnFailed(
                "Windows MXC backend is already started".into(),
            ));
        }
        let config = self
            .executor
            .write_private_config(&self.wire_config)
            .map_err(|err| SandboxError::IsolationFailed(err.to_string()))?;
        let job = super::job_object::create_kill_on_close_job(&format!("axis-mxc-{}", self.id))
            .map_err(|err| SandboxError::IsolationFailed(format!("MXC Job Object: {err}")))?;
        let mut command = Command::new(&self.executor.path);
        configure_executor_invocation(&mut command, config.path(), false);
        command.current_dir(&self.workspace_dir);
        configure_executor_environment(&mut command, &self.executor.path);
        if self.capture_output {
            command.stdin(Stdio::null());
            let stdout = File::create(self.workspace_dir.join("stdout.log"))
                .map_err(|err| SandboxError::SpawnFailed(format!("stdout log: {err}")))?;
            let stderr = File::create(self.workspace_dir.join("stderr.log"))
                .map_err(|err| SandboxError::SpawnFailed(format!("stderr log: {err}")))?;
            command
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
        }
        let mut child =
            MxcExecutorChild::Standard(command.spawn().map_err(|err| {
                SandboxError::SpawnFailed(format!("Windows MXC executor: {err}"))
            })?);
        let pid = child.id();
        if let Err(err) = super::job_object::assign_process_to_job(&job, pid) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::IsolationFailed(format!(
                "MXC Job Object assignment: {err}"
            )));
        }
        self.config_file = Some(config);
        self.job = Some(job);
        self.child = Some(child);
        tracing::info!(
            "sandbox {} started via MXC ProcessContainer, pid={pid}",
            self.id
        );
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async move {
            if let Some(code) = self.exit_code {
                return Ok(code);
            }
            let deadline = self
                .timeout_sec
                .map(|seconds| Instant::now() + Duration::from_secs(seconds));
            loop {
                let status = self
                    .child
                    .as_mut()
                    .ok_or_else(|| SandboxError::SpawnFailed("no Windows MXC child".into()))?
                    .try_wait()?;
                if let Some(code) = status {
                    self.child.take();
                    self.exit_code = Some(code);
                    self.cleanup_after_stop();
                    return Ok(code);
                }
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    self.terminate_tree()?;
                    self.exit_code = Some(-1);
                    return Err(SandboxError::IsolationFailed(format!(
                        "Windows MXC process timed out after {} seconds",
                        self.timeout_sec.unwrap_or_default()
                    )));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if let Some(code) = self.exit_code {
            return Ok(Some(code));
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let Some(code) = child.try_wait()? else {
            return Ok(None);
        };
        self.child.take();
        self.exit_code = Some(code);
        self.cleanup_after_stop();
        Ok(Some(code))
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        self.terminate_tree()?;
        tracing::info!("sandbox {} destroyed via MXC ProcessContainer", self.id);
        Ok(())
    }
}

fn build_windows_processcontainer_config(
    config: &SandboxConfig,
) -> Result<MxcProcessWireConfig, MxcWindowsError> {
    validate_unproven_policy_surfaces(config)?;
    validate_tier_policy(config.interactive_terminal)?;
    let translated_filesystem = translate_filesystem_policy(config)?;
    let filesystem = normalize_basecontainer_filesystem(translated_filesystem)?;
    let mut effective_policy = config.policy.clone();
    effective_policy.filesystem.read_only = filesystem.read_only.clone();
    effective_policy.filesystem.read_write = filesystem.read_write.clone();
    // BaseContainer keeps its stronger default-deny boundary, so redundant
    // denies are removed after overlap validation.
    effective_policy.filesystem.deny.clear();
    let environment = sanitized_environment(&config.env)?;
    let working_dir = path_string(
        config
            .working_dir
            .as_deref()
            .unwrap_or(&config.workspace_dir),
    )?;
    let strict_proxy = matches!(config.policy.network.mode, NetworkMode::Proxy);
    let proxy_addr = if strict_proxy {
        Some(config.proxy_addr.ok_or_else(|| {
            MxcWindowsError::UnsupportedPolicy(
                "strict Windows proxy policy requires an AXIS proxy endpoint before launch".into(),
            )
        })?)
    } else {
        None
    };
    let wfp_dependency =
        if crate::windows::wfp::broker_available(crate::windows::wfp::DEFAULT_PIPE_NAME) {
            DependencyState::Present
        } else {
            DependencyState::Missing
        };
    let runtime = RuntimeProbeSnapshot::new()
        .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
        .with_dependency(
            host_dependency::WINDOWS_PROCESS_CONTAINER,
            DependencyState::Present,
        )
        .with_dependency(host_dependency::WINDOWS_JOBOBJECT, DependencyState::Present)
        .with_dependency(host_dependency::WINDOWS_WFP_BROKER, wfp_dependency);
    let mut spec = build_process_backend_execution_spec(
        &effective_policy,
        BackendCapabilityMapId::MxcWindowsProcessContainer,
        ProcessLaunchOptions {
            command: config.command.clone(),
            args: config.args.clone(),
            working_dir: Some(working_dir),
            environment,
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec,
        },
        &runtime,
        &PlannerOptions::new(),
    )
    .map_err(|err| MxcWindowsError::UnsupportedPolicy(err.to_string()))?;
    spec.filesystem = filesystem;
    let wire = mxc_config::build_mxc_process_config(
        windows_command_line(&config.command, &config.args),
        &spec,
        mxc_config::MxcProcessConfigOptions {
            container_id: Some(format!("axis-{}", config.id)),
            strict_proxy_enforced_by_axis: strict_proxy,
            proxy_url: proxy_addr.map(|addr| format!("http://{addr}")),
            axis_wfp: strict_proxy.then(|| mxc_config::MxcAxisWfpConfig {
                pipe_name: crate::windows::wfp::DEFAULT_PIPE_NAME.into(),
                lease_id: config.id.0.to_string(),
            }),
            ..Default::default()
        },
    )
    .map_err(|err| MxcWindowsError::Config(err.to_string()))?;
    Ok(wire)
}

fn validate_tier_policy(interactive_terminal: bool) -> Result<(), MxcWindowsError> {
    if interactive_terminal {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "interactive ConPTY is unsupported because Experimental_CreateProcessInSandbox rejects PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE with ERROR_INVALID_HANDLE on supported BaseContainer builds; AXIS does not downgrade to AppContainer/DACL to obtain terminal support"
                .into(),
        ));
    }
    Ok(())
}

fn configure_executor_invocation(command: &mut Command, config_path: &Path, dry_run: bool) {
    command.args(executor_arguments(config_path, dry_run));
}

fn executor_arguments(config_path: &Path, dry_run: bool) -> Vec<OsString> {
    let mut arguments = Vec::new();
    if dry_run {
        arguments.push("--dry-run".into());
    }
    arguments.push("--config".into());
    arguments.push(config_path.as_os_str().to_owned());
    arguments
}

fn validate_unproven_policy_surfaces(config: &SandboxConfig) -> Result<(), MxcWindowsError> {
    if config.interactive_terminal && config.capture_output {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "interactive ConPTY mode requires direct host terminal I/O; daemon-side PTY capture is not yet selected by the public launch API".into(),
        ));
    }
    if config.policy.gpu.enabled || config.policy.amd.is_some() {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "GPU and AMD extensions are not integrated with MXC ProcessContainer".into(),
        ));
    }
    if config.policy.process.run_as_user.is_some() {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "process.run_as_user names a host/Unix account and has no sound BaseContainer mapping; use process.identity: isolated for portable identity intent"
                .into(),
        ));
    }
    validate_scoped_ssh_policy(config)?;
    if inference_requested(config) && !matches!(config.policy.network.mode, NetworkMode::Proxy) {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "managed inference on Windows requires strict proxy mode so the AXIS broker is the only reachable inference and credential boundary".into(),
        ));
    }
    Ok(())
}

fn validate_scoped_ssh_policy(config: &SandboxConfig) -> Result<(), MxcWindowsError> {
    if config.policy.ssh.allowed_keys.is_empty() {
        return Ok(());
    }
    if !matches!(config.policy.network.mode, NetworkMode::Proxy) {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "scoped SSH on Windows requires strict proxy mode so custom clients cannot bypass destination policy"
                .into(),
        ));
    }
    if !config.policy.ssh.generate_config || !config.policy.ssh.generate_known_hosts {
        return Err(MxcWindowsError::UnsupportedPolicy(
            "scoped SSH on Windows requires generated config and known_hosts".into(),
        ));
    }

    let mut allowed_hosts: Option<BTreeSet<String>> = None;
    for key in &config.policy.ssh.allowed_keys {
        if key.allowed_hosts.is_empty() {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "scoped SSH key '{}' must declare at least one literal allowed host",
                key.name
            )));
        }
        let hosts = key
            .allowed_hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if hosts.iter().any(|host| {
            host.chars()
                .any(|character| matches!(character, '*' | '?' | '[' | ']'))
        }) {
            return Err(MxcWindowsError::UnsupportedPolicy(
                "Windows scoped SSH requires literal host names; wildcard key scopes are not enforceable at the CONNECT boundary"
                    .into(),
            ));
        }
        if let Some(existing) = &allowed_hosts {
            if existing != &hosts {
                return Err(MxcWindowsError::UnsupportedPolicy(
                    "Windows scoped SSH requires every projected key to share the same allowed-host set; raw private keys cannot enforce different key-to-host mappings"
                        .into(),
                ));
            }
        } else {
            allowed_hosts = Some(hosts);
        }
    }

    let network_ssh_hosts = config
        .policy
        .network
        .policies
        .iter()
        .flat_map(|policy| &policy.endpoints)
        .filter(|endpoint| endpoint.port == 22)
        .map(|endpoint| endpoint.host.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if allowed_hosts.as_ref() != Some(&network_ssh_hosts) {
        return Err(MxcWindowsError::UnsupportedPolicy(format!(
            "scoped SSH allowed hosts must exactly match strict network endpoints on port 22 (keys={:?}, network={network_ssh_hosts:?})",
            allowed_hosts.unwrap_or_default()
        )));
    }
    Ok(())
}

fn inference_requested(config: &SandboxConfig) -> bool {
    config.policy.inference.default_provider.is_some()
        || !config.policy.inference.routes.is_empty()
        || config.policy.inference.token_budget.is_some()
}

fn sanitized_environment(
    entries: &[(String, String)],
) -> Result<BTreeMap<String, String>, MxcWindowsError> {
    let mut seen = HashSet::new();
    let mut environment = BTreeMap::new();
    for (key, value) in entries {
        if key.trim().is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0')
        {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "invalid environment entry {key:?}"
            )));
        }
        let normalized = key.to_ascii_uppercase();
        if !seen.insert(normalized) {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "duplicate case-insensitive environment key {key:?}"
            )));
        }
        if axis_core::sandbox_env::is_secret_env_key(key)
            || axis_core::sandbox_env::is_proxy_env_key(key)
        {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "filtered environment key {key:?} cannot cross the MXC boundary"
            )));
        }
        environment.insert(key.clone(), value.clone());
    }
    Ok(environment)
}

fn translate_filesystem_policy(
    config: &SandboxConfig,
) -> Result<ProcessBackendFilesystemSpec, MxcWindowsError> {
    Ok(ProcessBackendFilesystemSpec {
        read_only: translate_path_list(config, &config.policy.filesystem.read_only)?,
        read_write: translate_path_list(config, &config.policy.filesystem.read_write)?,
        deny: translate_path_list(config, &config.policy.filesystem.deny)?,
    })
}

/// BaseContainer denies every path that is not covered by an explicit grant.
/// A deny outside all grants is therefore redundant and is removed before the
/// shared capability planner runs. Any overlap remains unrepresentable by the
/// current BaseContainer API and fails closed.
fn normalize_basecontainer_filesystem(
    mut filesystem: ProcessBackendFilesystemSpec,
) -> Result<ProcessBackendFilesystemSpec, MxcWindowsError> {
    if filesystem.deny.is_empty() {
        return Ok(filesystem);
    }

    let grants = filesystem
        .read_only
        .iter()
        .chain(filesystem.read_write.iter())
        .map(|path| windows_path_key(path))
        .collect::<Result<Vec<_>, _>>()?;

    for denied in &filesystem.deny {
        let denied_key = windows_path_key(denied)?;
        for (granted, granted_key) in filesystem
            .read_only
            .iter()
            .chain(filesystem.read_write.iter())
            .zip(grants.iter())
        {
            if component_prefix(granted_key, &denied_key)
                || component_prefix(&denied_key, granted_key)
            {
                return Err(MxcWindowsError::UnsupportedPolicy(format!(
                    "filesystem deny {denied:?} overlaps BaseContainer grant {granted:?}; nested deny semantics are not available"
                )));
            }
        }
        tracing::debug!(
            path = denied,
            "filesystem deny is redundant under BaseContainer default-deny"
        );
    }

    filesystem.deny.clear();
    Ok(filesystem)
}

fn windows_path_key(path: &str) -> Result<Vec<OsString>, MxcWindowsError> {
    reject_ambiguous_windows_path(path)?;
    let lexical = normalize_absolute_windows_path(Path::new(path))?;
    let canonical = canonicalize_with_nonexistent_suffix(&lexical)?;
    Ok(canonical
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect())
}

fn reject_ambiguous_windows_path(path: &str) -> Result<(), MxcWindowsError> {
    let normalized = path.replace('/', "\\");
    let upper = normalized.to_ascii_uppercase();
    if upper.starts_with("\\\\.\\")
        || upper.starts_with("\\\\?\\GLOBALROOT")
        || upper.starts_with("\\\\?\\GLOBAL??")
    {
        return Err(MxcWindowsError::UnsupportedPolicy(format!(
            "filesystem path {path:?} uses an unsupported Windows device namespace"
        )));
    }

    for component in Path::new(path).components() {
        if matches!(component, Component::Normal(_))
            && component
                .as_os_str()
                .encode_wide()
                .any(|unit| unit == b':' as u16)
        {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "filesystem path {path:?} contains an alternate data stream"
            )));
        }
    }
    Ok(())
}

fn normalize_absolute_windows_path(path: &Path) -> Result<PathBuf, MxcWindowsError> {
    if !path.is_absolute() {
        return Err(MxcWindowsError::UnsupportedPolicy(format!(
            "filesystem path {path:?} is not absolute"
        )));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("\\")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(MxcWindowsError::UnsupportedPolicy(format!(
                        "filesystem path {path:?} escapes its Windows root"
                    )));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn canonicalize_with_nonexistent_suffix(path: &Path) -> Result<PathBuf, MxcWindowsError> {
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let leaf = ancestor.file_name().ok_or_else(|| {
            MxcWindowsError::UnsupportedPolicy(format!(
                "filesystem path {:?} has no resolvable Windows ancestor",
                path
            ))
        })?;
        suffix.push(leaf.to_os_string());
        if !ancestor.pop() {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "filesystem path {:?} has no resolvable Windows ancestor",
                path
            )));
        }
    }

    let mut canonical = fs::canonicalize(&ancestor).map_err(|err| {
        MxcWindowsError::UnsupportedPolicy(format!(
            "cannot canonicalize filesystem path ancestor {:?}: {err}",
            ancestor
        ))
    })?;
    for component in suffix.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn component_prefix(prefix: &[OsString], path: &[OsString]) -> bool {
    prefix.len() <= path.len()
        && prefix
            .iter()
            .zip(path)
            .all(|(left, right)| windows_component_eq(left, right))
}

fn windows_component_eq(left: &OsStr, right: &OsStr) -> bool {
    use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    unsafe { CompareStringOrdinal(&left, &right, true) == CSTR_EQUAL }
}

fn translate_path_list(
    config: &SandboxConfig,
    paths: &[String],
) -> Result<Vec<String>, MxcWindowsError> {
    let mut translated = Vec::new();
    for path in paths {
        if path.starts_with('/') {
            if matches!(
                config.policy.filesystem.compatibility,
                Compatibility::BestEffort
            ) {
                tracing::debug!("skipping Unix-only filesystem policy path on Windows: {path}");
                continue;
            }
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "Unix-only filesystem path {path:?} is a hard requirement on Windows"
            )));
        }
        let expanded = expand_policy_path(config, path)?;
        if !Path::new(&expanded).is_absolute() {
            return Err(MxcWindowsError::UnsupportedPolicy(format!(
                "filesystem path {path:?} did not resolve to an absolute Windows path"
            )));
        }
        if !translated.iter().any(|existing| existing == &expanded) {
            translated.push(expanded);
        }
    }
    Ok(translated)
}

fn expand_policy_path(config: &SandboxConfig, path: &str) -> Result<String, MxcWindowsError> {
    let workspace = path_string(&config.workspace_dir)?;
    let tmpdir = path_string(&config.workspace_dir.join(".axis-tmp"))?;
    let mut expanded = path
        .replace("{workspace}", &workspace)
        .replace("{tmpdir}", &tmpdir);
    if expanded == "~" || expanded.starts_with("~/") || expanded.starts_with("~\\") {
        let home = std::env::var("USERPROFILE").map_err(|_| {
            MxcWindowsError::UnsupportedPolicy(
                "USERPROFILE is required to expand '~' filesystem policy paths".into(),
            )
        })?;
        expanded = if expanded == "~" {
            home
        } else {
            PathBuf::from(home)
                .join(&expanded[2..])
                .to_string_lossy()
                .into_owned()
        };
    }
    Ok(expanded)
}

fn windows_command_line(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .map(quote_windows_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.into();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn configure_executor_environment(command: &mut Command, executor: &Path) {
    command.env_clear();
    command.envs(executor_environment(executor));
}

fn executor_environment(executor: &Path) -> Vec<(OsString, OsString)> {
    let mut environment = Vec::new();
    for key in [
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            environment.push((key.into(), value));
        }
    }
    let mut path_entries = Vec::new();
    if let Some(parent) = executor.parent() {
        path_entries.push(parent.to_path_buf());
    }
    if let Some(system_root) = std::env::var_os("SYSTEMROOT") {
        let system_root = PathBuf::from(system_root);
        path_entries.push(system_root.join("System32"));
        path_entries.push(system_root);
    }
    if let Ok(path) = std::env::join_paths(path_entries) {
        environment.push(("PATH".into(), path));
    }
    environment
}

fn production_executor_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(directory) = current_exe.parent()
    {
        candidates.extend(EXECUTOR_NAMES.iter().map(|name| directory.join(name)));
    }
    for variable in ["ProgramFiles", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(variable) {
            let directory = PathBuf::from(root).join("axis").join("bin");
            candidates.extend(EXECUTOR_NAMES.iter().map(|name| directory.join(name)));
        }
    }
    candidates
}

fn validate_executor_path(path: &Path, production: bool) -> Result<(), MxcWindowsError> {
    if !path.is_absolute() {
        return Err(MxcWindowsError::UnsafeExecutor {
            path: path.into(),
            reason: "path is not absolute".into(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| MxcWindowsError::UnsafeExecutor {
        path: path.into(),
        reason: err.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(MxcWindowsError::UnsafeExecutor {
            path: path.into(),
            reason: "candidate is not a regular, non-symlink file".into(),
        });
    }
    if production
        && !path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(MxcWindowsError::UnsafeExecutor {
            path: path.into(),
            reason: "production executor must be an .exe".into(),
        });
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<String, MxcWindowsError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| MxcWindowsError::UnsupportedPolicy(format!("non-UTF-8 path: {path:?}")))
}

fn wait_child_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<ExitStatus, MxcWindowsError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MxcWindowsError::Executor(err.to_string()));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(MxcWindowsError::Executor(format!(
                "timed out after {}ms",
                timeout.as_millis()
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_limited_output(file: &mut File) -> Result<String, MxcWindowsError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_DRY_RUN_OUTPUT_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|err| MxcWindowsError::Executor(err.to_string()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        Access, ChildProcessPolicy, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, InferenceRoute, NetworkMode, NetworkPolicy, Policy, ProcessIdentity,
        ProcessPolicy, RuntimePolicy, SshKeySpec, SshPolicy,
    };

    #[test]
    fn windows_command_line_quotes_createprocess_arguments() {
        assert_eq!(windows_command_line("cmd", &[]), "cmd");
        assert_eq!(
            windows_command_line("C:\\Program Files\\tool.exe", &["a b".into(), "".into()]),
            "\"C:\\Program Files\\tool.exe\" \"a b\" \"\""
        );
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(
            quote_windows_argument("C:\\path with space\\"),
            "\"C:\\path with space\\\\\""
        );
    }

    #[test]
    fn processcontainer_config_is_fail_closed_and_sanitized() {
        let root = tempfile::tempdir().unwrap();
        let config = sandbox_config(root.path());
        let wire = build_windows_processcontainer_config(&config).unwrap();
        let json = serde_json::to_value(wire).unwrap();
        assert_eq!(json["containment"], "processcontainer");
        assert_eq!(json["platform"], "windows");
        assert_eq!(json["processContainer"]["leastPrivilege"], true);
        assert_eq!(json["fallback"]["allowDaclMutation"], false);
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(
            json["filesystem"]["readwritePaths"][0],
            root.path().to_string_lossy().as_ref()
        );
        assert_eq!(
            json["process"]["env"],
            serde_json::json!(["PATH=safe-path"])
        );
    }

    #[test]
    fn processcontainer_serializes_child_only_job_resources() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.process.max_processes = 8;
        config.policy.process.max_memory_mb = 512;
        config.policy.process.cpu_rate_percent = 25;

        let wire = build_windows_processcontainer_config(&config).unwrap();
        let json = serde_json::to_value(wire).unwrap();

        assert_eq!(json["processContainer"]["resources"]["maxProcesses"], 8);
        assert_eq!(json["processContainer"]["resources"]["maxMemoryMb"], 512);
        assert_eq!(json["processContainer"]["resources"]["cpuRatePercent"], 25);
    }

    #[test]
    fn portable_identity_and_child_denial_map_without_linux_nouns() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.process.identity = ProcessIdentity::Isolated;
        config.policy.process.child_processes = ChildProcessPolicy::Deny;
        config.policy.process.max_processes = 32;

        let wire = build_windows_processcontainer_config(&config).unwrap();
        let json = serde_json::to_value(wire).unwrap();
        assert_eq!(json["processContainer"]["leastPrivilege"], true);
        assert_eq!(json["processContainer"]["resources"]["maxProcesses"], 1);

        config.policy.process.run_as_user = Some("sandbox-user".into());
        let error = build_windows_processcontainer_config(&config).unwrap_err();
        assert!(error.to_string().contains("process.identity: isolated"));
    }

    #[test]
    fn processcontainer_removes_denies_outside_all_grants_as_redundant() {
        let root = tempfile::tempdir().unwrap();
        let denied_root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.filesystem.deny = vec![denied_root.path().to_string_lossy().into_owned()];

        let wire = build_windows_processcontainer_config(&config).unwrap();

        assert!(wire.filesystem.denied_paths.is_empty());
    }

    #[test]
    fn processcontainer_rejects_deny_nested_beneath_grant_case_insensitively() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("Secrets");
        fs::create_dir(&nested).unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.filesystem.deny = vec![nested.to_string_lossy().to_ascii_uppercase()];

        let error = build_windows_processcontainer_config(&config).unwrap_err();

        assert!(error.to_string().contains("nested deny semantics"));
    }

    #[test]
    fn processcontainer_rejects_deny_ancestor_of_grant() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let mut config = sandbox_config(&workspace);
        config.policy.filesystem.deny = vec![root.path().to_string_lossy().into_owned()];

        let error = build_windows_processcontainer_config(&config).unwrap_err();

        assert!(error.to_string().contains("nested deny semantics"));
    }

    #[test]
    fn processcontainer_rejects_nonexistent_deny_reached_through_junction_alias() {
        let root = tempfile::tempdir().unwrap();
        let alias_root = tempfile::tempdir().unwrap();
        let junction = alias_root.path().join("workspace-alias");
        let status = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "test junction creation failed");
        let mut config = sandbox_config(root.path());
        config.policy.filesystem.deny = vec![
            junction
                .join("future")
                .join("secret.txt")
                .to_string_lossy()
                .into_owned(),
        ];

        let error = build_windows_processcontainer_config(&config).unwrap_err();

        assert!(error.to_string().contains("nested deny semantics"));
    }

    #[test]
    fn processcontainer_rejects_ads_and_device_namespace_deny_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut ads = sandbox_config(root.path());
        ads.policy.filesystem.deny = vec![format!("{}:secret", root.path().display())];
        let ads_error = build_windows_processcontainer_config(&ads).unwrap_err();
        assert!(ads_error.to_string().contains("alternate data stream"));

        let mut device = sandbox_config(root.path());
        device.policy.filesystem.deny = vec![r"\\.\C:\axis-secret".into()];
        let device_error = build_windows_processcontainer_config(&device).unwrap_err();
        assert!(
            device_error
                .to_string()
                .contains("unsupported Windows device namespace")
        );
    }

    #[test]
    fn processcontainer_rejects_secret_environment() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.env.push(("OPENAI_API_KEY".into(), "secret".into()));
        let error = build_windows_processcontainer_config(&config).unwrap_err();
        assert!(error.to_string().contains("filtered environment key"));
    }

    #[test]
    fn hard_requirement_rejects_unix_paths_on_windows() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.filesystem.compatibility = Compatibility::HardRequirement;
        config.policy.filesystem.read_only.push("/usr".into());
        let error = build_windows_processcontainer_config(&config).unwrap_err();
        assert!(error.to_string().contains("Unix-only filesystem path"));
    }

    #[test]
    fn interactive_terminal_rejects_instead_of_downgrading() {
        let error = validate_tier_policy(true).unwrap_err();
        assert!(error.to_string().contains("ERROR_INVALID_HANDLE"));
        assert!(error.to_string().contains("AppContainer/DACL"));
        validate_tier_policy(false).unwrap();
    }

    #[test]
    fn managed_inference_requires_strict_proxy_but_is_not_windows_rejected() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.inference.routes.push(InferenceRoute {
            name: "provider".into(),
            endpoint: Some("https://api.example.test".into()),
            provider: Some("openai-compatible".into()),
            model: None,
            api_key_env: Some("AXIS_TEST_PROVIDER_KEY".into()),
            protocols: vec!["openai-chat".into()],
        });

        let error = validate_unproven_policy_surfaces(&config).unwrap_err();
        assert!(error.to_string().contains("requires strict proxy mode"));

        config.policy.network.mode = NetworkMode::Proxy;
        validate_unproven_policy_surfaces(&config).unwrap();
        validate_tier_policy(false).unwrap();
    }

    #[test]
    fn scoped_ssh_requires_exact_shared_host_and_network_sets() {
        let root = tempfile::tempdir().unwrap();
        let mut config = sandbox_config(root.path());
        config.policy.network.mode = NetworkMode::Proxy;
        config.policy.network.policies.push(EndpointPolicy {
            name: "ssh".into(),
            endpoints: vec![Endpoint {
                host: "git.example.test".into(),
                port: 22,
                access: Access::ReadWrite,
                protocol: Some("tcp".into()),
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        });
        config.policy.ssh = SshPolicy {
            allowed_keys: vec![SshKeySpec {
                name: "deploy".into(),
                private_key: "C:\\keys\\deploy".into(),
                allowed_hosts: vec!["git.example.test".into()],
            }],
            generate_known_hosts: true,
            generate_config: true,
        };
        validate_scoped_ssh_policy(&config).unwrap();

        config.policy.ssh.allowed_keys.push(SshKeySpec {
            name: "other".into(),
            private_key: "C:\\keys\\other".into(),
            allowed_hosts: vec!["other.example.test".into()],
        });
        let error = validate_scoped_ssh_policy(&config).unwrap_err();
        assert!(error.to_string().contains("same allowed-host set"));
    }

    #[test]
    fn executor_invocation_uses_upstream_tier_dispatcher() {
        let mut command = Command::new("wxc-exec.exe");
        configure_executor_invocation(&mut command, Path::new("C:\\temp\\policy.json"), true);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(args, ["--dry-run", "--config", "C:\\temp\\policy.json"]);
        let mut command = Command::new("wxc-exec.exe");
        configure_executor_invocation(&mut command, Path::new("C:\\temp\\policy.json"), false);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args, ["--config", "C:\\temp\\policy.json"]);
    }

    #[test]
    fn executor_environment_keeps_dacl_state_roots_but_not_credentials() {
        let mut command = Command::new("wxc-exec.exe");
        configure_executor_environment(&mut command, Path::new("C:\\axis\\bin\\wxc-exec.exe"));
        let keys = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|_| key.to_string_lossy().to_ascii_uppercase()))
            .collect::<HashSet<_>>();

        assert!(keys.contains("LOCALAPPDATA"));
        assert!(keys.contains("USERPROFILE"));
        assert!(!keys.contains("OPENAI_API_KEY"));
    }

    #[tokio::test]
    async fn fake_executor_receives_private_config_and_cleans_lifecycle_state() {
        let root = tempfile::tempdir().unwrap();
        let config_copy = root.path().join("received-config.json");
        let executor_path = root.path().join("fake-mxc.cmd");
        write_fake_executor(&executor_path, &config_copy);
        let executor = MxcWindowsExecutor::from_test_path(&executor_path).unwrap();
        let mut config = sandbox_config(root.path());
        config.capture_output = true;
        let mut sandbox = MxcWindowsSandbox::new_with_executor(&config, executor).unwrap();

        let pid = SandboxImpl::start(&mut sandbox).unwrap();
        assert!(pid > 0);
        let code = SandboxImpl::wait(&mut sandbox).await.unwrap();

        assert_eq!(code, 0);
        assert!(sandbox.child.is_none());
        assert!(sandbox.job.is_none());
        assert!(sandbox.config_file.is_none());
        assert!(
            fs::read_to_string(root.path().join("stdout.log"))
                .unwrap()
                .contains(MXC_DRY_RUN_SUCCESS)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(config_copy).unwrap()).unwrap();
        assert_eq!(json["containment"], "processcontainer");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(!serde_json::to_string(&json).unwrap().contains("secret"));
    }

    #[test]
    fn fake_executor_dry_run_validates_the_same_wire_config() {
        let root = tempfile::tempdir().unwrap();
        let config_copy = root.path().join("dry-run-config.json");
        let executor_path = root.path().join("fake-mxc.cmd");
        write_fake_executor(&executor_path, &config_copy);
        let executor = MxcWindowsExecutor::from_test_path(&executor_path).unwrap();
        let config = sandbox_config(root.path());
        let wire = build_windows_processcontainer_config(&config).unwrap();

        executor.dry_run(&wire, Duration::from_secs(2)).unwrap();

        let received: serde_json::Value =
            serde_json::from_slice(&fs::read(config_copy).unwrap()).unwrap();
        assert_eq!(received["containerId"], format!("axis-{}", config.id));
    }

    #[tokio::test]
    async fn timeout_kills_fake_executor_and_cleans_private_state() {
        let root = tempfile::tempdir().unwrap();
        let executor_path = root.path().join("slow-mxc.cmd");
        fs::write(
            &executor_path,
            "@echo off\r\nping 127.0.0.1 -n 30 >nul\r\nexit /b 0\r\n",
        )
        .unwrap();
        let executor = MxcWindowsExecutor::from_test_path(&executor_path).unwrap();
        let mut config = sandbox_config(root.path());
        config.timeout_sec = Some(1);
        let mut sandbox = MxcWindowsSandbox::new_with_executor(&config, executor).unwrap();

        SandboxImpl::start(&mut sandbox).unwrap();
        let error = SandboxImpl::wait(&mut sandbox).await.unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(sandbox.child.is_none());
        assert!(sandbox.job.is_none());
        assert!(sandbox.config_file.is_none());
    }

    #[test]
    fn missing_executor_candidates_fail_without_host_fallback() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-wxc.exe");
        let error = MxcWindowsExecutor::resolve_from_candidates([missing]).unwrap_err();
        assert_eq!(error, MxcWindowsError::ExecutorUnavailable);
    }

    fn write_fake_executor(path: &Path, config_copy: &Path) {
        let config_copy = config_copy.to_string_lossy().replace('%', "%%");
        let script = format!(
            "@echo off\r\nsetlocal\r\nset CONFIG=\r\n:parse\r\nif \"%~1\"==\"\" goto run\r\nif /I \"%~1\"==\"--config\" (\r\n  set \"CONFIG=%~2\"\r\n  shift\r\n  shift\r\n  goto parse\r\n)\r\nshift\r\ngoto parse\r\n:run\r\ncopy /Y \"%CONFIG%\" \"{config_copy}\" >nul\r\necho {MXC_DRY_RUN_SUCCESS}\r\nexit /b 0\r\n"
        );
        fs::write(path, script).unwrap();
    }

    fn sandbox_config(workspace: &Path) -> SandboxConfig {
        SandboxConfig {
            id: axis_core::types::SandboxId::new(),
            policy: Policy {
                version: 1,
                name: "windows-mxc-test".into(),
                runtime: RuntimePolicy::default(),
                filesystem: FilesystemPolicy {
                    read_only: vec!["/usr".into()],
                    read_write: vec!["{workspace}".into()],
                    deny: Vec::new(),
                    compatibility: Compatibility::BestEffort,
                    workspace_read_only: false,
                },
                process: ProcessPolicy {
                    max_processes: 0,
                    max_memory_mb: 0,
                    cpu_rate_percent: 0,
                    run_as_user: None,
                    blocked_syscalls: Vec::new(),
                    identity: Default::default(),
                    child_processes: Default::default(),
                    timeout_sec: None,
                },
                network: NetworkPolicy {
                    mode: NetworkMode::Block,
                    policies: Vec::new(),
                },
                inference: InferencePolicy::default(),
                gpu: GpuPolicy::default(),
                ssh: SshPolicy::default(),
                amd: None,
            },
            command: "cmd.exe".into(),
            args: vec!["/c".into(), "echo ok".into()],
            working_dir: Some(workspace.into()),
            workspace_dir: workspace.into(),
            env: vec![("PATH".into(), "safe-path".into())],
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: false,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: None,
            backend_preflight: BackendPreflight::InProcess,
            startup_trace: None,
        }
    }
}
