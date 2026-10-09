// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox trait and configuration.

use axis_core::connect_attribution::ConnectAttributionStore;
use axis_core::policy::{Policy, RuntimeContainment, RuntimeProvider};
use axis_core::types::{SandboxId, SandboxStatus};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox creation failed: {0}")]
    CreationFailed(String),

    #[error("sandbox not found: {0}")]
    NotFound(SandboxId),

    #[error("isolation setup failed: {0}")]
    IsolationFailed(String),

    #[error("process spawn failed: {0}")]
    SpawnFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("platform not supported: {0}")]
    Unsupported(String),
}

/// Configuration for creating a new sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub id: SandboxId,
    pub policy: Policy,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub workspace_dir: PathBuf,
    pub env: Vec<(String, String)>,
    pub proxy_port: u16,
    pub proxy_addr: Option<std::net::SocketAddr>,
    pub connect_attribution: Option<ConnectAttributionStore>,
    /// Capture stdout/stderr to files in workspace (for daemon mode).
    /// When false, child inherits parent's stdio (for standalone/run mode).
    pub capture_output: bool,
    /// Attach an interactive terminal to the sandboxed command when the
    /// selected backend needs an explicit PTY transport.
    pub interactive_terminal: bool,
    /// Optional executable that serves the hidden PTY bridge subcommand.
    /// When unset, backends that need a bridge use the current executable.
    pub pty_bridge_helper: Option<PathBuf>,
    /// Maximum wall-clock time before auto-destroy (seconds). None = no timeout.
    pub timeout_sec: Option<u64>,
    /// Optional backend-executor validation before start(). Normal launches
    /// rely on AXIS in-process validation and leave this as the default.
    pub backend_preflight: BackendPreflight,
    /// Optional phase recorder for benchmark instrumentation. Normal runtime
    /// paths leave this unset so launch behavior is unchanged.
    pub startup_trace: Option<StartupTrace>,
}

/// Backend validation mode for sandbox construction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BackendPreflight {
    /// Validate policies and translated launch state in AXIS without spawning
    /// the selected backend executor.
    #[default]
    InProcess,
    /// Ask the selected backend executor to validate its serialized launch
    /// state before start(). Backends that support this may spawn a helper.
    DryRun,
}

/// Opt-in startup phase timing recorder used by benchmarks.
#[derive(Debug, Clone, Default)]
pub struct StartupTrace {
    phases: Arc<Mutex<Vec<StartupPhaseTiming>>>,
}

/// One measured startup phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupPhaseTiming {
    pub phase: &'static str,
    pub duration: Duration,
}

impl StartupTrace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, phase: &'static str, duration: Duration) {
        self.phases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(StartupPhaseTiming { phase, duration });
    }

    pub fn phases(&self) -> Vec<StartupPhaseTiming> {
        self.phases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

pub(crate) fn record_startup_result<T, E>(
    trace: &Option<StartupTrace>,
    phase: &'static str,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let start = Instant::now();
    let result = f();
    if let Some(trace) = trace {
        trace.record(phase, start.elapsed());
    }
    result
}

/// Platform-independent sandbox handle.
///
/// Each platform (Linux, Windows) provides its own implementation.
pub struct Sandbox {
    pub id: SandboxId,
    pub status: SandboxStatus,
    pub pid: Option<u32>,
    pub workspace_dir: PathBuf,
    inner: Box<dyn SandboxImpl>,
    /// Symlinks created for agent state containment (cleaned up on destroy).
    agent_symlinks: Vec<(PathBuf, PathBuf)>,
    /// Captured stdout from the child process (when capture_output=true).
    pub stdout: Option<std::process::ChildStdout>,
    /// Captured stderr from the child process (when capture_output=true).
    pub stderr: Option<std::process::ChildStderr>,
    /// Captured stdin for writing input to the child process.
    pub stdin: Option<std::process::ChildStdin>,
    /// ConPTY read handle (Windows) — merged TTY output with ANSI codes.
    pub pty_read: Option<std::fs::File>,
}

impl Sandbox {
    /// Create a new sandbox with platform-specific isolation.
    pub fn create(config: SandboxConfig) -> Result<Self, SandboxError> {
        let backend = platform_backend_for_policy(&config.policy)?;
        Self::create_inner_with_backend(config, true, backend)
    }

    /// Create an isolated process for an already prepared managed workspace.
    ///
    /// This skips agent workspace symlink setup/cleanup so short-lived daemon
    /// exec commands do not disturb symlinks owned by the primary sandbox.
    pub fn create_for_exec(config: SandboxConfig) -> Result<Self, SandboxError> {
        let backend = platform_backend_for_policy(&config.policy)?;
        Self::create_inner_with_backend(config, false, backend)
    }

    fn create_inner_with_backend(
        mut config: SandboxConfig,
        manage_agent_workspace: bool,
        backend: PlatformBackendSelection,
    ) -> Result<Self, SandboxError> {
        let trace = config.startup_trace.clone();
        record_startup_result(&trace, "front_door.policy_validation", || {
            config
                .policy
                .validate()
                .map_err(|e| SandboxError::CreationFailed(format!("invalid sandbox policy: {e}")))
        })?;
        record_startup_result(&trace, "front_door.platform_availability", || {
            ensure_platform_backend_available(backend)
        })?;

        let agent_symlinks =
            record_startup_result(&trace, "support_files.agent_workspace", || {
                prepare_managed_agent_workspace(&mut config, manage_agent_workspace, backend)
            })?;

        let inner = match record_startup_result(&trace, "backend.prepare", || {
            create_platform_sandbox_with_backend(&config, backend)
        }) {
            Ok(inner) => inner,
            Err(err) => {
                cleanup_prepared_agent_workspace_on_setup_failure(&agent_symlinks);
                return Err(err);
            }
        };
        Ok(Self {
            id: config.id,
            status: SandboxStatus::Creating,
            pid: None,
            workspace_dir: config.workspace_dir,
            inner,
            agent_symlinks,
            stdout: None,
            stderr: None,
            stdin: None,
            pty_read: None,
        })
    }

    /// Start the sandboxed process.
    pub fn start(&mut self) -> Result<(), SandboxError> {
        let pid = self.inner.start()?;
        self.pid = Some(pid);
        // Take captured stdio handles from the platform impl.
        self.stdout = self.inner.take_stdout();
        self.stderr = self.inner.take_stderr();
        self.stdin = self.inner.take_stdin();
        self.pty_read = self.inner.take_pty_read();
        self.status = SandboxStatus::Running;
        Ok(())
    }

    /// Wait for the sandboxed process to exit. Returns the exit code.
    pub async fn wait(&mut self) -> Result<i32, SandboxError> {
        let code = self.inner.wait().await?;
        self.status = SandboxStatus::Stopped;
        Ok(code)
    }

    /// Reap the sandboxed process if it has already exited.
    pub fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if !matches!(self.status, SandboxStatus::Running) {
            return Ok(None);
        }
        let Some(code) = self.inner.try_wait()? else {
            return Ok(None);
        };
        self.status = SandboxStatus::Stopped;
        Ok(Some(code))
    }

    /// Terminate the sandboxed process and clean up resources.
    pub fn destroy(&mut self) -> Result<(), SandboxError> {
        self.inner.destroy()?;
        // Restore original directories by removing symlinks.
        crate::workspace::cleanup_agent_symlinks(&self.agent_symlinks);
        self.status = SandboxStatus::Stopped;
        Ok(())
    }
}

fn prepare_managed_agent_workspace(
    config: &mut SandboxConfig,
    manage_agent_workspace: bool,
    backend: PlatformBackendSelection,
) -> Result<Vec<(PathBuf, PathBuf)>, SandboxError> {
    if uses_mxc_managed_home(config, backend) {
        prepare_mxc_managed_home_workspace(config)?;
        return Ok(Vec::new());
    }

    if !manage_agent_workspace {
        let agent_symlinks = Vec::new();
        if let Err(err) = rewrite_read_write_paths_for_agent_targets(
            &config.policy.name,
            &mut config.policy.filesystem.read_write,
            &agent_symlinks,
        ) {
            return Err(SandboxError::CreationFailed(format!(
                "agent workspace preparation: {err}"
            )));
        }
        prepare_existing_scoped_ssh_for_exec(config)?;
        return Ok(agent_symlinks);
    }

    let mut agent_symlinks = crate::workspace::prepare_agent_workspace(
        &config.policy.name,
        &config.policy.filesystem.read_write,
    )
    .map_err(|e| SandboxError::CreationFailed(format!("agent workspace preparation: {e}")))?;

    if let Err(err) = rewrite_read_write_paths_for_agent_targets(
        &config.policy.name,
        &mut config.policy.filesystem.read_write,
        &agent_symlinks,
    ) {
        crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
        return Err(SandboxError::CreationFailed(format!(
            "agent workspace preparation: {err}"
        )));
    }

    if !config.policy.ssh.allowed_keys.is_empty() {
        let ssh_dir = crate::workspace::ssh_workspace_path(&config.policy.name);
        match crate::workspace::link_scoped_ssh_workspace(&ssh_dir) {
            Ok(link) => agent_symlinks.push(link),
            Err(err) => {
                crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                return Err(SandboxError::CreationFailed(format!(
                    "scoped SSH workspace: {err}"
                )));
            }
        }

        match crate::workspace::prepare_ssh_workspace(&config.policy.name, &config.policy.ssh) {
            Ok(Some(prepared_ssh_dir)) => {
                if let Err(err) = push_unique_policy_path(
                    &mut config.policy.filesystem.read_write,
                    &prepared_ssh_dir,
                )
                .and_then(|()| {
                    remove_policy_path(
                        &mut config.policy.filesystem.deny,
                        &agent_symlinks
                            .last()
                            .expect("SSH symlink should have been recorded")
                            .0,
                    )
                }) {
                    crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                    return Err(SandboxError::CreationFailed(format!(
                        "scoped SSH workspace: {err}"
                    )));
                }
            }
            Ok(None) => {}
            Err(err) => {
                crate::workspace::cleanup_agent_symlinks(&agent_symlinks);
                return Err(SandboxError::CreationFailed(format!(
                    "scoped SSH workspace: {err}"
                )));
            }
        }
    }

    Ok(agent_symlinks)
}

fn cleanup_prepared_agent_workspace_on_setup_failure(agent_symlinks: &[(PathBuf, PathBuf)]) {
    crate::workspace::cleanup_agent_symlinks(agent_symlinks);
}

fn uses_mxc_managed_home(config: &SandboxConfig, backend: PlatformBackendSelection) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(
            effective_linux_backend(backend),
            PlatformBackendSelection::LinuxMxc
        ) && !config.policy.ssh.allowed_keys.is_empty()
    }

    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(target_os = "windows")]
        {
            let _ = config;
            matches!(backend, PlatformBackendSelection::WindowsMxc)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = backend;
            let _ = config;
            false
        }
    }
}

fn prepare_mxc_managed_home_workspace(config: &mut SandboxConfig) -> Result<(), SandboxError> {
    let policy_name = config.policy.name.clone();
    crate::workspace::with_managed_home_setup_lock(&policy_name, || {
        let managed_home = crate::workspace::prepare_managed_home_workspace(
            &policy_name,
            &config.policy.filesystem.read_write,
        )?;
        let ssh_dir = managed_home.join(".ssh");
        push_unique_policy_path(&mut config.policy.filesystem.read_write, &managed_home)?;
        rewrite_read_write_paths_for_mxc_managed_home_targets(
            &policy_name,
            &mut config.policy.filesystem.read_write,
        )?;
        reject_unmanaged_home_grants_for_mxc_managed_home(config)?;
        if !config.policy.ssh.allowed_keys.is_empty() {
            crate::workspace::prepare_ssh_workspace_at(&policy_name, &config.policy.ssh, &ssh_dir)
                .map_err(|err| format!("scoped SSH workspace: {err}"))?;
            push_unique_policy_path(&mut config.policy.filesystem.read_only, &ssh_dir)?;
        }
        set_managed_home_env(&mut config.env, &managed_home)?;
        Ok(())
    })
    .map_err(|err| SandboxError::CreationFailed(format!("managed home workspace: {err}")))
}

fn set_managed_home_env(
    env: &mut Vec<(String, String)>,
    managed_home: &Path,
) -> Result<(), String> {
    let home = policy_path_string(managed_home)?;
    let xdg_config_home = policy_path_string(&managed_home.join(".config"))?;
    let xdg_data_home = policy_path_string(&managed_home.join(".local/share"))?;
    let xdg_cache_home = policy_path_string(&managed_home.join(".cache"))?;
    upsert_env(env, "HOME", home.clone());
    upsert_env(env, "XDG_CONFIG_HOME", xdg_config_home);
    upsert_env(env, "XDG_DATA_HOME", xdg_data_home);
    upsert_env(env, "XDG_CACHE_HOME", xdg_cache_home);
    #[cfg(target_os = "windows")]
    {
        let appdata = managed_home.join("AppData").join("Roaming");
        let local_appdata = managed_home.join("AppData").join("Local");
        for directory in [
            managed_home.join(".config"),
            managed_home.join(".local").join("share"),
            managed_home.join(".cache"),
            appdata.clone(),
            local_appdata.clone(),
        ] {
            std::fs::create_dir_all(&directory).map_err(|err| {
                format!(
                    "create managed Windows home directory '{}': {err}",
                    directory.display()
                )
            })?;
        }

        upsert_env(env, "USERPROFILE", home.clone());
        upsert_env(env, "APPDATA", policy_path_string(&appdata)?);
        upsert_env(env, "LOCALAPPDATA", policy_path_string(&local_appdata)?);
        if home.as_bytes().get(1) == Some(&b':') {
            upsert_env(env, "HOMEDRIVE", home[..2].to_string());
            upsert_env(env, "HOMEPATH", home[2..].to_string());
        }
    }
    Ok(())
}

fn upsert_env(env: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, existing)) = env.iter_mut().find(|(existing_key, _)| existing_key == key) {
        *existing = value;
    } else {
        env.push((key.into(), value));
    }
}

fn prepare_existing_scoped_ssh_for_exec(config: &mut SandboxConfig) -> Result<(), SandboxError> {
    if config.policy.ssh.allowed_keys.is_empty() {
        return Ok(());
    }

    let ssh_dir = crate::workspace::ssh_workspace_path(&config.policy.name);
    match crate::workspace::scoped_ssh_link_points_to(&ssh_dir) {
        Ok(true) => {
            let ssh_link = crate::workspace::scoped_ssh_link_path().map_err(|err| {
                SandboxError::CreationFailed(format!("scoped SSH workspace: {err}"))
            })?;
            push_unique_policy_path(&mut config.policy.filesystem.read_write, &ssh_dir)
                .and_then(|()| remove_policy_path(&mut config.policy.filesystem.deny, &ssh_link))
                .map_err(|err| SandboxError::CreationFailed(format!("scoped SSH workspace: {err}")))
        }
        Ok(false) => Err(SandboxError::CreationFailed(
            "scoped SSH workspace is not prepared for exec".into(),
        )),
        Err(err) => Err(SandboxError::CreationFailed(format!(
            "scoped SSH workspace: {err}"
        ))),
    }
}

fn rewrite_read_write_paths_for_agent_targets(
    policy_name: &str,
    read_write_paths: &mut Vec<String>,
    symlinks: &[(PathBuf, PathBuf)],
) -> Result<(), String> {
    for path in read_write_paths.iter_mut() {
        let expanded = crate::workspace::expand_home_or_absolute_path(path)?;
        let mut target = expanded.as_ref().and_then(|expanded| {
            symlinks
                .iter()
                .find_map(|(link, target)| (expanded == link).then_some(target.clone()))
        });
        if target.is_none() {
            target = crate::workspace::agent_state_mapping_for_policy_path(policy_name, path)?
                .map(|(_, target)| target);
        }

        if let Some(target) = target {
            *path = policy_path_string(&target)?;
        }
    }

    for path in read_write_paths.clone() {
        if let Some((_, target)) =
            crate::workspace::agent_state_mapping_for_policy_path(policy_name, &path)?
        {
            push_unique_policy_path(read_write_paths, &target)?;
        }
    }

    Ok(())
}

fn rewrite_read_write_paths_for_mxc_managed_home_targets(
    policy_name: &str,
    read_write_paths: &mut [String],
) -> Result<(), String> {
    for path in read_write_paths.iter_mut() {
        if let Some((_, target)) =
            crate::workspace::managed_home_agent_state_mapping_for_policy_path(policy_name, path)?
        {
            *path = policy_path_string(&target)?;
        }
    }

    Ok(())
}

fn reject_unmanaged_home_grants_for_mxc_managed_home(config: &SandboxConfig) -> Result<(), String> {
    let lexical_home = crate::workspace::user_home_path()?;
    let home = normalize_existing_or_absolute_path(&lexical_home)?;
    let agent_root = normalize_existing_or_absolute_path(&crate::workspace::agent_state_root(
        &config.policy.name,
    ))?;
    let private_setup = normalize_existing_or_absolute_path(
        &crate::workspace::ssh_workspace_staging_parent_checked(&config.policy.name)?,
    )?;
    let generated_ssh = normalize_existing_or_absolute_path(
        &crate::workspace::managed_home_path(&config.policy.name).join(".ssh"),
    )?;
    let workspace = normalize_existing_or_absolute_path(&config.workspace_dir)?;
    let tmpdir = normalize_existing_or_absolute_path(&sandbox_tmpdir_path(&config.workspace_dir))?;
    let host_temp = normalize_existing_or_absolute_path(&std::env::temp_dir())?;
    let guard = ManagedHomeGrantGuard {
        home: &home,
        agent_root: &agent_root,
        private_setup: &private_setup,
        generated_ssh: &generated_ssh,
        workspace: &workspace,
        tmpdir: &tmpdir,
        host_temp: &host_temp,
        raw_workspace: &config.workspace_dir,
        lexical_home: &lexical_home,
    };
    reject_unmanaged_home_grants("read_only", &config.policy.filesystem.read_only, &guard)?;
    reject_unmanaged_home_grants("read_write", &config.policy.filesystem.read_write, &guard)
}

struct ManagedHomeGrantGuard<'a> {
    home: &'a Path,
    agent_root: &'a Path,
    private_setup: &'a Path,
    generated_ssh: &'a Path,
    workspace: &'a Path,
    tmpdir: &'a Path,
    host_temp: &'a Path,
    raw_workspace: &'a Path,
    lexical_home: &'a Path,
}

fn reject_unmanaged_home_grants(
    section: &str,
    paths: &[String],
    guard: &ManagedHomeGrantGuard<'_>,
) -> Result<(), String> {
    for path in paths {
        let expanded =
            expand_managed_home_guard_path(path, guard.raw_workspace, guard.lexical_home)?;
        if paths_overlap(&expanded, guard.private_setup) {
            return Err(format!(
                "MXC managed HOME cannot grant private agent setup {section} path '{}' (expanded '{}')",
                path,
                expanded.display()
            ));
        }
        if section == "read_write" && path_contains_or_equal(guard.generated_ssh, &expanded) {
            return Err(format!(
                "MXC managed HOME cannot grant generated SSH {section} path '{}' (expanded '{}')",
                path,
                expanded.display()
            ));
        }
        if expanded.starts_with(guard.home)
            && !path_contains_or_equal(guard.agent_root, &expanded)
            && !path_contains_or_equal(guard.workspace, &expanded)
            && !path_contains_or_equal(guard.tmpdir, &expanded)
            && !is_allowed_host_temp_grant(&expanded, guard)
        {
            return Err(format!(
                "MXC managed HOME cannot grant real home {section} path '{}' (expanded '{}')",
                path,
                expanded.display()
            ));
        }
    }
    Ok(())
}

fn is_allowed_host_temp_grant(expanded: &Path, guard: &ManagedHomeGrantGuard<'_>) -> bool {
    cfg!(target_os = "windows")
        && path_contains_or_equal(guard.home, guard.host_temp)
        && path_contains_or_equal(guard.host_temp, expanded)
}

fn expand_managed_home_guard_path(
    path: &str,
    workspace: &Path,
    home: &Path,
) -> Result<PathBuf, String> {
    let mut expanded = if path == "~" {
        home.to_string_lossy().into_owned()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest).to_string_lossy().into_owned()
    } else if path.starts_with('~') {
        return Err(format!(
            "unsupported home path '{path}': only '~' and '~/' are supported"
        ));
    } else {
        path.to_string()
    };

    expanded = expanded.replace("{workspace}", &workspace.to_string_lossy());
    expanded = expanded.replace(
        "{tmpdir}",
        &sandbox_tmpdir_path(workspace).to_string_lossy(),
    );

    normalize_existing_or_absolute_path(&PathBuf::from(expanded))
}

fn sandbox_tmpdir_path(workspace: &Path) -> PathBuf {
    workspace.join(".axis-tmp")
}

fn normalize_existing_or_absolute_path(path: &Path) -> Result<PathBuf, String> {
    let normalized = normalize_absolute_path(path)?;
    if let Ok(canonical) = std::fs::canonicalize(&normalized) {
        return normalize_absolute_path(&canonical);
    }

    let mut existing_prefix = normalized.clone();
    let mut missing_suffix = Vec::new();
    while !existing_prefix.exists() {
        let part = existing_prefix.file_name().ok_or_else(|| {
            format!(
                "policy path '{}' has no resolvable ancestor",
                path.display()
            )
        })?;
        missing_suffix.push(part.to_os_string());
        if !existing_prefix.pop() {
            return Err(format!(
                "policy path '{}' has no resolvable ancestor",
                path.display()
            ));
        }
    }

    let mut resolved = std::fs::canonicalize(&existing_prefix).unwrap_or(existing_prefix);
    for part in missing_suffix.into_iter().rev() {
        resolved.push(part);
    }
    normalize_absolute_path(&resolved)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "policy path '{}' must be absolute after expansion",
            path.display()
        ));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    if normalized.as_os_str().is_empty() {
        Ok(PathBuf::from(std::path::MAIN_SEPARATOR_STR))
    } else {
        Ok(normalized)
    }
}

fn path_contains_or_equal(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_contains_or_equal(left, right) || path_contains_or_equal(right, left)
}

fn remove_policy_path(paths: &mut Vec<String>, remove: &Path) -> Result<(), String> {
    let mut retained = Vec::with_capacity(paths.len());
    for path in paths.drain(..) {
        let should_remove = crate::workspace::expand_home_or_absolute_path(&path)?
            .is_some_and(|expanded| expanded == *remove);
        if !should_remove {
            retained.push(path);
        }
    }
    *paths = retained;
    Ok(())
}

fn push_unique_policy_path(paths: &mut Vec<String>, path: &Path) -> Result<(), String> {
    let path = policy_path_string(path)?;
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
    Ok(())
}

fn policy_path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("policy path '{}' is not valid UTF-8", path.display()))
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlatformBackendSelection {
    Default,
    #[cfg(target_os = "linux")]
    LinuxNative,
    #[cfg(target_os = "linux")]
    LinuxMxc,
    #[cfg(target_os = "linux")]
    LinuxVxn,
    #[cfg(target_os = "windows")]
    WindowsMxc,
}

fn platform_backend_for_policy(policy: &Policy) -> Result<PlatformBackendSelection, SandboxError> {
    match policy.runtime.containment {
        RuntimeContainment::Process => process_backend_for_provider(policy.runtime.provider),
    }
}

fn process_backend_for_provider(
    provider: RuntimeProvider,
) -> Result<PlatformBackendSelection, SandboxError> {
    match provider {
        #[cfg(target_os = "linux")]
        RuntimeProvider::Auto | RuntimeProvider::Mxc => Ok(PlatformBackendSelection::LinuxMxc),
        #[cfg(target_os = "linux")]
        RuntimeProvider::AxisNative => Ok(PlatformBackendSelection::LinuxNative),
        #[cfg(target_os = "linux")]
        RuntimeProvider::Vxn => Ok(PlatformBackendSelection::LinuxVxn),

        #[cfg(target_os = "windows")]
        RuntimeProvider::Auto | RuntimeProvider::Mxc => Ok(PlatformBackendSelection::WindowsMxc),
        #[cfg(target_os = "windows")]
        RuntimeProvider::AxisNative => Err(SandboxError::Unsupported(
            "runtime provider 'axis_native' is disabled on Windows because the legacy native path does not currently enforce AXIS policy; use 'auto' or 'mxc'".into(),
        )),
        #[cfg(target_os = "windows")]
        RuntimeProvider::Vxn => Err(SandboxError::Unsupported(
            "runtime provider 'vxn' requires Linux/Xen (dom0); it is not available on Windows".into(),
        )),

        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        RuntimeProvider::Auto | RuntimeProvider::AxisNative => {
            Ok(PlatformBackendSelection::Default)
        }
        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        RuntimeProvider::Mxc => Err(SandboxError::Unsupported(format!(
            "runtime provider 'mxc' is not available on {}",
            std::env::consts::OS
        ))),
        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        RuntimeProvider::Vxn => Err(SandboxError::Unsupported(format!(
            "runtime provider 'vxn' requires Linux/Xen (dom0); it is not available on {}",
            std::env::consts::OS
        ))),
    }
}

fn ensure_platform_backend_available(
    backend: PlatformBackendSelection,
) -> Result<(), SandboxError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = backend;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        match backend {
            PlatformBackendSelection::WindowsMxc => Ok(()),
            _ => Err(SandboxError::Unsupported(
                "native Windows containment is unavailable; select the MXC process backend".into(),
            )),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = backend;
        Err(SandboxError::Unsupported(format!(
            "platform '{}' is not yet supported",
            std::env::consts::OS
        )))
    }
}

/// Platform-specific sandbox implementation trait.
pub(crate) trait SandboxImpl: Send {
    /// Start the isolated process. Returns the PID.
    fn start(&mut self) -> Result<u32, SandboxError>;

    /// Wait for the process to exit.
    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>;

    /// Reap the child process if it has already exited without blocking.
    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError>;

    /// Take captured stdout handle (if capture_output was enabled).
    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        None
    }

    /// Take captured stderr handle (if capture_output was enabled).
    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        None
    }

    /// Take captured stdin handle for writing input to the child.
    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        None
    }

    /// Take ConPTY read handle (Windows only — provides merged TTY output).
    fn take_pty_read(&mut self) -> Option<std::fs::File> {
        None
    }

    /// Kill the process and clean up isolation resources.
    fn destroy(&mut self) -> Result<(), SandboxError>;
}

fn create_platform_sandbox_with_backend(
    config: &SandboxConfig,
    backend: PlatformBackendSelection,
) -> Result<Box<dyn SandboxImpl>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        match effective_linux_backend(backend) {
            PlatformBackendSelection::LinuxNative => {
                Ok(Box::new(crate::linux::LinuxSandbox::new(config)?))
            }
            PlatformBackendSelection::LinuxMxc => {
                Ok(Box::new(crate::linux::mxc::MxcLinuxSandbox::new(config)?))
            }
            PlatformBackendSelection::LinuxVxn => {
                Ok(Box::new(crate::linux::vxn::VxnSandbox::new(config)?))
            }
            PlatformBackendSelection::Default => unreachable!("Linux default backend is resolved"),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = backend;
        Ok(Box::new(crate::macos::MacosSandbox::new(config)?))
    }

    #[cfg(target_os = "windows")]
    {
        match backend {
            PlatformBackendSelection::WindowsMxc => Ok(Box::new(
                crate::windows::mxc::MxcWindowsSandbox::new(config)?,
            )),
            PlatformBackendSelection::Default => Err(SandboxError::Unsupported(
                "legacy native Windows host execution is disabled".into(),
            )),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = backend;
        let _ = config;
        Err(SandboxError::Unsupported(format!(
            "platform '{}' is not yet supported",
            std::env::consts::OS
        )))
    }
}

#[cfg(target_os = "linux")]
fn effective_linux_backend(backend: PlatformBackendSelection) -> PlatformBackendSelection {
    match backend {
        PlatformBackendSelection::Default | PlatformBackendSelection::LinuxMxc => {
            PlatformBackendSelection::LinuxMxc
        }
        PlatformBackendSelection::LinuxNative => PlatformBackendSelection::LinuxNative,
        PlatformBackendSelection::LinuxVxn => PlatformBackendSelection::LinuxVxn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use axis_core::policy::Compatibility;
    #[cfg(unix)]
    use axis_core::policy::SshKeySpec;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, ProcessPolicy,
        RuntimeProvider, SshPolicy,
    };
    use std::path::Path;

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy: Policy {
                version: 1,
                name: "test".into(),
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
            },
            command: "true".into(),
            args: Vec::new(),
            working_dir: None,
            workspace_dir: std::env::temp_dir().join("axis-sandbox-validation-test"),
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
        }
    }

    #[cfg(target_os = "linux")]
    fn native_process_backend_selection() -> PlatformBackendSelection {
        PlatformBackendSelection::LinuxNative
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn native_process_backend_selection() -> PlatformBackendSelection {
        PlatformBackendSelection::Default
    }

    #[test]
    fn create_rejects_invalid_manual_resource_policy_before_platform_setup() {
        let mut config = test_config();
        config.policy.process.cpu_rate_percent = 101;

        let err = match Sandbox::create(config) {
            Ok(_) => panic!("invalid resource policy should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::CreationFailed(_)));
        assert!(err.to_string().contains("cpu_rate_percent"));
    }

    #[test]
    fn create_for_exec_rejects_invalid_manual_resource_policy_before_platform_setup() {
        let mut config = test_config();
        config.policy.process.cpu_rate_percent = 101;

        let err = match Sandbox::create_for_exec(config) {
            Ok(_) => panic!("invalid resource policy should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::CreationFailed(_)));
        assert!(err.to_string().contains("cpu_rate_percent"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_mxc_uses_physical_managed_home_and_profile_directories() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "windows-managed-home-test".into();
            config.workspace_dir = workspace.path().to_path_buf();
            config.policy.filesystem.read_write = vec!["{workspace}".into(), "~/.codex".into()];

            let symlinks = prepare_managed_agent_workspace(
                &mut config,
                true,
                PlatformBackendSelection::WindowsMxc,
            )
            .unwrap();
            let managed_home = home
                .path()
                .join(".axis")
                .join("agents")
                .join("windows-managed-home-test")
                .join("home");
            let managed_codex = managed_home.join(".codex");

            assert!(symlinks.is_empty());
            assert!(managed_codex.is_dir());
            assert!(!managed_codex.is_symlink());
            assert!(managed_home.join("AppData/Roaming").is_dir());
            assert!(managed_home.join("AppData/Local").is_dir());
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&managed_home.to_string_lossy().into_owned()),
                "read_write={:?}, expected={}",
                config.policy.filesystem.read_write,
                managed_home.display()
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&managed_codex.to_string_lossy().into_owned())
            );

            let env_value = |name: &str| {
                config
                    .env
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(env_value("HOME"), managed_home.to_str());
            assert_eq!(env_value("USERPROFILE"), managed_home.to_str());
            assert_eq!(
                env_value("APPDATA"),
                managed_home.join("AppData").join("Roaming").to_str()
            );
            assert_eq!(
                env_value("LOCALAPPDATA"),
                managed_home.join("AppData").join("Local").to_str()
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_runtime_provider_selects_linux_backend() {
        let mut policy = test_config().policy;
        assert_eq!(
            platform_backend_for_policy(&policy).unwrap(),
            PlatformBackendSelection::LinuxMxc
        );

        policy.runtime.provider = RuntimeProvider::Mxc;
        assert_eq!(
            platform_backend_for_policy(&policy).unwrap(),
            PlatformBackendSelection::LinuxMxc
        );

        policy.runtime.provider = RuntimeProvider::AxisNative;
        assert_eq!(
            platform_backend_for_policy(&policy).unwrap(),
            PlatformBackendSelection::LinuxNative
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn process_runtime_provider_selects_windows_backend() {
        let mut policy = test_config().policy;
        assert_eq!(
            platform_backend_for_policy(&policy).unwrap(),
            PlatformBackendSelection::WindowsMxc
        );

        policy.runtime.provider = RuntimeProvider::Mxc;
        assert_eq!(
            platform_backend_for_policy(&policy).unwrap(),
            PlatformBackendSelection::WindowsMxc
        );

        policy.runtime.provider = RuntimeProvider::AxisNative;
        let error = platform_backend_for_policy(&policy).unwrap_err();
        assert!(error.to_string().contains("disabled on Windows"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_windows_default_cannot_spawn_directly() {
        let error =
            create_platform_sandbox_with_backend(&test_config(), PlatformBackendSelection::Default)
                .err()
                .expect("legacy Windows host execution must reject");
        assert!(error.to_string().contains("host execution is disabled"));
    }

    #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
    #[test]
    fn mxc_runtime_provider_is_rejected_without_platform_backend() {
        let mut policy = test_config().policy;
        policy.runtime.provider = RuntimeProvider::Mxc;

        let err = platform_backend_for_policy(&policy).unwrap_err();

        assert!(matches!(err, SandboxError::Unsupported(_)));
        assert!(err.to_string().contains("provider 'mxc'"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_workspace_preparation_rewrites_known_paths_and_ignores_unknown_home_paths() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_write = vec![
                "~/.codex".into(),
                "~/Documents".into(),
                "~/.unknown-agent".into(),
                "{workspace}".into(),
            ];

            let symlinks = prepare_managed_agent_workspace(
                &mut config,
                true,
                native_process_backend_selection(),
            )
            .unwrap();
            let codex_link = home.path().join(".codex");
            let codex_target = home.path().join(".axis/agents/agent-codex/codex");

            assert_eq!(symlinks, vec![(codex_link.clone(), codex_target.clone())]);
            assert!(codex_link.is_symlink());
            assert_eq!(std::fs::read_link(&codex_link).unwrap(), codex_target);
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&codex_target.to_string_lossy().into_owned()),
                "backend policy should grant the contained target, not only the symlink alias"
            );
            assert!(
                !config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&"~/.codex".into()),
                "backend policy should not rely on MXC representing symlink aliases"
            );
            assert!(
                !home.path().join("Documents").is_symlink(),
                "broad user directories must not be redirected"
            );
            assert!(
                !home.path().join(".unknown-agent").exists(),
                "unknown agent state paths must not be redirected"
            );

            crate::workspace::cleanup_agent_symlinks(&symlinks);
            assert!(!codex_link.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn scoped_ssh_preparation_uses_generated_ssh_dir_and_removes_real_home_deny() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_dir = home.path().join("keys");
            std::fs::create_dir(&key_dir).unwrap();
            let key_path = key_dir.join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.deny = vec!["~/.ssh".into(), "~/.aws".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let symlinks = prepare_managed_agent_workspace(
                &mut config,
                true,
                native_process_backend_selection(),
            )
            .unwrap();
            let ssh_link = home.path().join(".ssh");
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");

            assert!(ssh_link.is_symlink());
            assert_eq!(std::fs::read_link(&ssh_link).unwrap(), ssh_dir);
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("id_ed25519")).unwrap(),
                "private-key"
            );
            let generated_config = std::fs::read_to_string(ssh_dir.join("config")).unwrap();
            assert!(generated_config.contains("Host github.com"));
            assert!(generated_config.contains("IdentityFile ~/.ssh/id_ed25519"));
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&ssh_dir.to_string_lossy().into_owned()),
                "scoped SSH target must be writable inside the backend sandbox"
            );
            assert!(
                !config.policy.filesystem.deny.contains(&"~/.ssh".into()),
                "the backend policy must not deny the generated ~/.ssh symlink target"
            );
            assert!(config.policy.filesystem.deny.contains(&"~/.aws".into()));

            crate::workspace::cleanup_agent_symlinks(&symlinks);
            assert!(!ssh_link.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn scoped_ssh_preparation_refuses_to_replace_real_user_ssh() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_managed_agent_workspace(
                &mut config,
                true,
                native_process_backend_selection(),
            )
            .unwrap_err();

            assert!(matches!(err, SandboxError::CreationFailed(_)));
            assert!(
                err.to_string()
                    .contains("refusing to replace existing ~/.ssh")
            );
            assert!(real_ssh.is_dir());
            assert!(!real_ssh.is_symlink());
            assert_eq!(
                std::fs::read_to_string(real_ssh.join("id_ed25519")).unwrap(),
                "real-private-key"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_cleans_agent_symlink_when_mxc_backend_setup_fails() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.policy.network.mode = NetworkMode::Proxy;
            config.policy.filesystem.read_write = vec!["~/.codex".into()];
            config.workspace_dir = workspace.path().join("workspace");
            disable_resource_limits(&mut config);

            let err = match Sandbox::create_inner_with_backend(
                config,
                true,
                PlatformBackendSelection::LinuxMxc,
            ) {
                Ok(_) => panic!("MXC backend setup should fail before launch"),
                Err(err) => err,
            };

            assert!(matches!(err, SandboxError::IsolationFailed(_)));
            assert!(err.to_string().contains("MXC Linux"));
            assert!(
                !home.path().join(".codex").exists(),
                "agent symlink should be cleaned when backend setup fails"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn exec_workspace_preparation_rewrites_known_paths_without_creating_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let primary_symlinks =
                crate::workspace::prepare_agent_workspace("agent-codex", &["~/.codex".into()])
                    .unwrap();
            let codex_link = home.path().join(".codex");
            let codex_target = home.path().join(".axis/agents/agent-codex/codex");

            let mut config = test_config();
            config.policy.name = "agent-codex".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_write = vec!["~/.codex".into()];

            let exec_symlinks = prepare_managed_agent_workspace(
                &mut config,
                false,
                native_process_backend_selection(),
            )
            .unwrap();

            assert!(exec_symlinks.is_empty());
            assert!(codex_link.is_symlink());
            assert_eq!(
                config.policy.filesystem.read_write,
                vec![codex_target.to_string_lossy().into_owned()]
            );

            crate::workspace::cleanup_agent_symlinks(&primary_symlinks);
        });
    }

    #[cfg(unix)]
    #[test]
    fn exec_scoped_ssh_reuses_existing_generated_link_without_replacing_home_ssh() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_dir = crate::workspace::ssh_workspace_path("agent-ssh");
            let ssh_link_pair = crate::workspace::link_scoped_ssh_workspace(&ssh_dir).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            std::fs::create_dir_all(&config.workspace_dir).unwrap();
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key-for-exec".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let exec_symlinks = prepare_managed_agent_workspace(
                &mut config,
                false,
                native_process_backend_selection(),
            )
            .unwrap();

            assert!(exec_symlinks.is_empty());
            assert!(home.path().join(".ssh").is_symlink());
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&ssh_dir.to_string_lossy().into_owned())
            );
            assert!(!config.policy.filesystem.deny.contains(&"~/.ssh".into()));

            crate::workspace::cleanup_agent_symlinks(&[ssh_link_pair]);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_uses_managed_home_without_replacing_real_ssh() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            std::fs::create_dir_all(&config.workspace_dir).unwrap();
            config.policy.filesystem.compatibility = Compatibility::BestEffort;
            config.policy.filesystem.read_write = vec![
                "{workspace}".into(),
                "~/.claude".into(),
                "~/.local/share/claude".into(),
                "~/.config".into(),
                "~/.axis".into(),
                "~/.codex".into(),
            ];
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let symlinks = prepare_managed_agent_workspace(
                &mut config,
                true,
                PlatformBackendSelection::LinuxMxc,
            )
            .unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");
            let agent_axis_target = home.path().join(".axis/agents/agent-ssh/axis");
            let claude_target = home.path().join(".axis/agents/agent-ssh/claude");
            let claude_share_target = home.path().join(".axis/agents/agent-ssh/claude-share");
            let config_target = home.path().join(".axis/agents/agent-ssh/config");
            let codex_target = home.path().join(".axis/agents/agent-ssh/codex");
            let managed_ssh = managed_home.join(".ssh");

            assert!(symlinks.is_empty());
            assert!(real_ssh.is_dir());
            assert!(!real_ssh.is_symlink());
            assert!(!home.path().join(".codex").exists());
            assert!(!home.path().join(".claude").exists());
            assert!(!home.path().join(".local").exists());
            assert_eq!(
                std::fs::read_to_string(managed_home.join(".ssh/id_ed25519")).unwrap(),
                "real-private-key"
            );
            let generated_config =
                std::fs::read_to_string(managed_home.join(".ssh/config")).unwrap();
            assert!(generated_config.contains("Host github.com"));
            assert!(generated_config.contains("IdentityFile ~/.ssh/id_ed25519"));
            assert!(generated_config.contains("Host *"));
            assert!(generated_config.contains("IdentityFile /dev/null"));
            assert!(!generated_config.contains(real_ssh.to_str().unwrap()));
            assert_eq!(
                std::fs::read_link(managed_home.join(".axis")).unwrap(),
                agent_axis_target
            );
            assert_eq!(
                std::fs::read_link(managed_home.join(".claude")).unwrap(),
                claude_target
            );
            assert_eq!(
                std::fs::read_link(managed_home.join(".local/share/claude")).unwrap(),
                claude_share_target
            );
            assert_eq!(
                std::fs::read_link(managed_home.join(".config")).unwrap(),
                config_target
            );
            assert_eq!(
                std::fs::read_link(managed_home.join(".codex")).unwrap(),
                codex_target
            );
            assert_eq!(
                config
                    .env
                    .iter()
                    .find(|(key, _)| key == "HOME")
                    .map(|(_, value)| value.as_str()),
                Some(managed_home.to_str().unwrap())
            );
            let env_value = |name: &str| {
                config
                    .env
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            assert_eq!(env_value("HOME"), Some(managed_home.to_str().unwrap()));
            assert_eq!(
                env_value("XDG_CONFIG_HOME"),
                Some(managed_home.join(".config").to_str().unwrap())
            );
            assert_eq!(
                env_value("XDG_DATA_HOME"),
                Some(managed_home.join(".local/share").to_str().unwrap())
            );
            assert_eq!(
                env_value("XDG_CACHE_HOME"),
                Some(managed_home.join(".cache").to_str().unwrap())
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&managed_home.to_string_lossy().into_owned()),
                "MXC backend policy should grant the managed HOME"
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&agent_axis_target.to_string_lossy().into_owned()),
                "known ~/.axis state must be rewritten to a policy-owned target"
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&claude_share_target.to_string_lossy().into_owned()),
                "known Claude share state must be rewritten to a policy-owned target"
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&codex_target.to_string_lossy().into_owned()),
                "known agent state target should remain mounted separately"
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_only
                    .contains(&managed_ssh.to_string_lossy().into_owned()),
                "generated managed SSH state must be readonly in the sandbox"
            );
            assert!(
                !config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&managed_ssh.to_string_lossy().into_owned()),
                "generated managed SSH state must not be directly writable"
            );
            assert!(
                !config.policy.filesystem.read_write.iter().any(|path| {
                    path == "~/.axis"
                        || path == "~/.local/share/claude"
                        || path == "~/.claude"
                        || path == "~/.config"
                        || path == "~/.codex"
                        || path == home.path().join(".axis").to_string_lossy().as_ref()
                        || path
                            == home
                                .path()
                                .join(".local/share/claude")
                                .to_string_lossy()
                                .as_ref()
                }),
                "MXC backend policy must not retain real home agent-state grants"
            );
            assert!(
                config.policy.filesystem.deny.contains(&"~/.ssh".into()),
                "real user ~/.ssh should remain denied"
            );
            let spec = crate::linux::mxc::translate_sandbox_config_for_test(&config).unwrap();
            assert!(
                spec.filesystem
                    .readwrite_paths
                    .contains(&managed_home.to_string_lossy().into_owned())
            );
            assert!(
                spec.filesystem
                    .readonly_paths
                    .contains(&managed_ssh.to_string_lossy().into_owned()),
                "MXC must mount generated SSH state readonly after the writable HOME bind"
            );
            assert!(
                !spec
                    .filesystem
                    .readwrite_paths
                    .contains(&managed_ssh.to_string_lossy().into_owned()),
                "MXC must not mount generated SSH state readwrite"
            );
            assert!(
                spec.filesystem
                    .readwrite_paths
                    .contains(&agent_axis_target.to_string_lossy().into_owned())
            );
            assert!(
                spec.filesystem
                    .readwrite_paths
                    .contains(&claude_share_target.to_string_lossy().into_owned())
            );
            assert!(!spec.filesystem.readwrite_paths.iter().any(|path| {
                path == home.path().join(".axis").to_string_lossy().as_ref()
                    || path
                        == home
                            .path()
                            .join(".local/share/claude")
                            .to_string_lossy()
                            .as_ref()
            }));
            assert!(
                spec.process
                    .env
                    .contains(&format!("HOME={}", managed_home.display()))
            );
            assert!(spec.process.env.contains(&format!(
                "XDG_CONFIG_HOME={}",
                managed_home.join(".config").display()
            )));
            assert!(spec.process.env.contains(&format!(
                "XDG_DATA_HOME={}",
                managed_home.join(".local/share").display()
            )));
            assert!(spec.process.env.contains(&format!(
                "XDG_CACHE_HOME={}",
                managed_home.join(".cache").display()
            )));
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_exec_scoped_ssh_reuses_managed_home_without_real_home_symlink() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            std::fs::create_dir_all(&config.workspace_dir).unwrap();
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let symlinks = prepare_managed_agent_workspace(
                &mut config,
                false,
                PlatformBackendSelection::LinuxMxc,
            )
            .unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");
            let managed_ssh = managed_home.join(".ssh");

            assert!(symlinks.is_empty());
            assert!(real_ssh.is_dir());
            assert!(!real_ssh.is_symlink());
            assert_eq!(
                std::fs::read_to_string(managed_home.join(".ssh/id_ed25519")).unwrap(),
                "real-private-key"
            );
            assert_eq!(
                config
                    .env
                    .iter()
                    .find(|(key, _)| key == "HOME")
                    .map(|(_, value)| value.as_str()),
                Some(managed_home.to_str().unwrap())
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_only
                    .contains(&managed_ssh.to_string_lossy().into_owned())
            );
            let spec = crate::linux::mxc::translate_sandbox_config_for_test(&config).unwrap();
            assert!(
                spec.filesystem
                    .readonly_paths
                    .contains(&managed_ssh.to_string_lossy().into_owned())
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_leaves_existing_real_ssh_symlink_untouched() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh_target = home.path().join("real-ssh-target");
            std::fs::create_dir(&real_ssh_target).unwrap();
            let key_path = real_ssh_target.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();
            std::os::unix::fs::symlink(&real_ssh_target, home.path().join(".ssh")).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            prepare_managed_agent_workspace(&mut config, true, PlatformBackendSelection::LinuxMxc)
                .unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");

            assert!(home.path().join(".ssh").is_symlink());
            assert_eq!(
                std::fs::read_link(home.path().join(".ssh")).unwrap(),
                real_ssh_target
            );
            assert_eq!(
                std::fs::read_to_string(managed_home.join(".ssh/id_ed25519")).unwrap(),
                "real-private-key"
            );
            assert!(
                config.policy.filesystem.deny.contains(&"~/.ssh".into()),
                "real user ~/.ssh symlink should remain denied"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_missing_key_uses_managed_home_without_real_home_grants() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_write = vec!["~/.axis/agents/agent-ssh".into()];
            config.policy.filesystem.deny = vec!["~/.ssh".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            prepare_managed_agent_workspace(&mut config, true, PlatformBackendSelection::LinuxMxc)
                .unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");
            let agent_axis_target = home.path().join(".axis/agents/agent-ssh/axis");

            assert!(managed_home.join(".ssh").is_dir());
            assert!(!managed_home.join(".ssh/id_ed25519").exists());
            assert!(!managed_home.join(".ssh/config").exists());
            assert_eq!(
                std::fs::read_link(managed_home.join(".axis/agents/agent-ssh")).unwrap(),
                agent_axis_target
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&agent_axis_target.to_string_lossy().into_owned())
            );
            assert!(
                !config.policy.filesystem.read_write.iter().any(|path| {
                    path == "~/.axis/agents/agent-ssh"
                        || path
                            == home
                                .path()
                                .join(".axis/agents/agent-ssh")
                                .to_string_lossy()
                                .as_ref()
                }),
                "missing SSH keys must not leave the real policy state root mounted"
            );
            assert!(
                config.policy.filesystem.deny.contains(&"~/.ssh".into()),
                "real user ~/.ssh should remain denied even when configured keys are missing"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_unmanaged_real_home_grants_before_copying_keys() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();

            for grant in ["~/.ssh", "~/.axis/cache", "~/.local", "~/Documents"] {
                let workspace = tempfile::tempdir().unwrap();
                let mut config = test_config();
                config.policy.name = format!("agent-{}", grant.replace(['~', '/', '.'], "_"));
                config.workspace_dir = workspace.path().join("workspace");
                config.policy.filesystem.read_write = vec![grant.into()];
                config.policy.ssh = SshPolicy {
                    allowed_keys: vec![SshKeySpec {
                        name: "github".into(),
                        private_key: "~/.ssh/id_ed25519".into(),
                        allowed_hosts: vec!["github.com".into()],
                    }],
                    generate_config: true,
                    generate_known_hosts: false,
                };

                let err = prepare_managed_agent_workspace(
                    &mut config,
                    true,
                    PlatformBackendSelection::LinuxMxc,
                )
                .unwrap_err();
                let managed_home = home
                    .path()
                    .join(".axis/agents")
                    .join(&config.policy.name)
                    .join("home");

                assert!(matches!(err, SandboxError::CreationFailed(_)));
                assert!(
                    err.to_string()
                        .contains("cannot grant real home read_write path"),
                    "unexpected error for {grant}: {err}"
                );
                assert!(
                    !managed_home.join(".ssh/id_ed25519").exists(),
                    "invalid grant {grant} must be rejected before copying SSH keys"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_unmanaged_real_home_read_only_grants() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.filesystem.read_only = vec!["~/Documents".into()];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_managed_agent_workspace(
                &mut config,
                true,
                PlatformBackendSelection::LinuxMxc,
            )
            .unwrap_err();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");

            assert!(matches!(err, SandboxError::CreationFailed(_)));
            assert!(
                err.to_string()
                    .contains("cannot grant real home read_only path")
            );
            assert!(!managed_home.join(".ssh/id_ed25519").exists());
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_private_setup_grants_before_copying_keys() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();
            let agent_root = home.path().join(".axis/agents/agent-ssh");
            let private_setup = agent_root.join("ssh-staging");

            let grants = [
                (
                    "read_write",
                    "~/.axis/agents/agent-ssh/ssh-staging".to_string(),
                    "private setup root",
                ),
                (
                    "read_only",
                    private_setup.join("nested").to_string_lossy().into_owned(),
                    "private setup child",
                ),
                (
                    "read_write",
                    "{workspace}/../.axis/agents/agent-ssh/ssh-staging".to_string(),
                    "token-expanded private setup root",
                ),
            ];

            for (index, (section, grant, label)) in grants.into_iter().enumerate() {
                let workspace = home.path().join(format!("workspace-{index}"));
                std::fs::create_dir(&workspace).unwrap();
                let mut config = test_config();
                config.policy.name = "agent-ssh".into();
                config.workspace_dir = workspace;
                match section {
                    "read_write" => config.policy.filesystem.read_write = vec![grant.clone()],
                    "read_only" => config.policy.filesystem.read_only = vec![grant.clone()],
                    _ => unreachable!(),
                }
                config.policy.ssh = SshPolicy {
                    allowed_keys: vec![SshKeySpec {
                        name: "github".into(),
                        private_key: "~/.ssh/id_ed25519".into(),
                        allowed_hosts: vec!["github.com".into()],
                    }],
                    generate_config: true,
                    generate_known_hosts: false,
                };

                let err = prepare_managed_agent_workspace(
                    &mut config,
                    true,
                    PlatformBackendSelection::LinuxMxc,
                )
                .unwrap_err();
                let managed_home = home.path().join(".axis/agents/agent-ssh/home");

                assert!(matches!(err, SandboxError::CreationFailed(_)));
                assert!(
                    err.to_string()
                        .contains(&format!("cannot grant private agent setup {section} path")),
                    "unexpected error for {label} grant {grant}: {err}"
                );
                assert!(
                    !managed_home.join(".ssh/id_ed25519").exists(),
                    "private setup grant {label} must be rejected before copying SSH keys"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_generated_ssh_readwrite_grants_before_copying_keys() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();
            let generated_ssh = home.path().join(".axis/agents/agent-ssh/home/.ssh");

            let grants = [
                (
                    generated_ssh.to_string_lossy().into_owned(),
                    "generated SSH root",
                ),
                (
                    generated_ssh
                        .join("id_ed25519")
                        .to_string_lossy()
                        .into_owned(),
                    "generated SSH child",
                ),
                (
                    "{workspace}/../.axis/agents/agent-ssh/home/.ssh/config".to_string(),
                    "token-expanded generated SSH child",
                ),
            ];

            for (index, (grant, label)) in grants.into_iter().enumerate() {
                let workspace = home.path().join(format!("workspace-ssh-{index}"));
                std::fs::create_dir(&workspace).unwrap();
                let mut config = test_config();
                config.policy.name = "agent-ssh".into();
                config.workspace_dir = workspace;
                config.policy.filesystem.read_write = vec![grant.clone()];
                config.policy.ssh = SshPolicy {
                    allowed_keys: vec![SshKeySpec {
                        name: "github".into(),
                        private_key: "~/.ssh/id_ed25519".into(),
                        allowed_hosts: vec!["github.com".into()],
                    }],
                    generate_config: true,
                    generate_known_hosts: false,
                };

                let err = prepare_managed_agent_workspace(
                    &mut config,
                    true,
                    PlatformBackendSelection::LinuxMxc,
                )
                .unwrap_err();

                assert!(matches!(err, SandboxError::CreationFailed(_)));
                assert!(
                    err.to_string()
                        .contains("cannot grant generated SSH read_write path"),
                    "unexpected error for {label} grant {grant}: {err}"
                );
                assert!(
                    !generated_ssh.join("id_ed25519").exists(),
                    "generated SSH readwrite grant {label} must be rejected before copying keys"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_token_expanded_real_home_escape_before_copying_keys() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();
            let workspace = home.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();

            for grant in [
                "{workspace}/../.axis/cache",
                "{workspace}/../.axis/cache/nested",
                "{workspace}/../.local",
                "{workspace}/../Documents",
            ] {
                let mut config = test_config();
                config.policy.name = format!("agent-{}", grant.replace(['{', '}', '/', '.'], "_"));
                config.workspace_dir = workspace.clone();
                config.policy.filesystem.read_write = vec![grant.into()];
                config.policy.ssh = SshPolicy {
                    allowed_keys: vec![SshKeySpec {
                        name: "github".into(),
                        private_key: "~/.ssh/id_ed25519".into(),
                        allowed_hosts: vec!["github.com".into()],
                    }],
                    generate_config: true,
                    generate_known_hosts: false,
                };

                let err = prepare_managed_agent_workspace(
                    &mut config,
                    true,
                    PlatformBackendSelection::LinuxMxc,
                )
                .unwrap_err();
                let managed_home = home
                    .path()
                    .join(".axis/agents")
                    .join(&config.policy.name)
                    .join("home");

                assert!(
                    err.to_string()
                        .contains("cannot grant real home read_write path"),
                    "unexpected error for {grant}: {err}"
                );
                assert!(
                    !managed_home.join(".ssh/id_ed25519").exists(),
                    "token-expanded grant {grant} must be rejected before copying SSH keys"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_allows_workspace_and_tmpdir_token_grants() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();
            let workspace = home.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.clone();
            config.policy.filesystem.read_write = vec![
                "{workspace}".into(),
                "{workspace}/state".into(),
                "{tmpdir}".into(),
                "{tmpdir}/cache".into(),
            ];
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            prepare_managed_agent_workspace(&mut config, true, PlatformBackendSelection::LinuxMxc)
                .unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");

            assert_eq!(
                std::fs::read_to_string(managed_home.join(".ssh/id_ed25519")).unwrap(),
                "real-private-key"
            );
            assert!(
                config
                    .policy
                    .filesystem
                    .read_write
                    .contains(&"{workspace}".into())
                    && config
                        .policy
                        .filesystem
                        .read_write
                        .contains(&"{tmpdir}".into())
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_symlinked_home_real_home_grants() {
        let real_home = tempfile::tempdir().unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let home_link = link_parent.path().join("home-link");
        std::os::unix::fs::symlink(real_home.path(), &home_link).unwrap();

        with_home(&home_link, || {
            let real_ssh = home_link.join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            std::fs::write(real_ssh.join("id_ed25519"), "real-private-key").unwrap();

            for grant in [
                "~/Documents".to_string(),
                "~/.ssh".to_string(),
                real_home.path().join(".ssh").to_string_lossy().into_owned(),
            ] {
                let workspace = tempfile::tempdir().unwrap();
                let mut config = test_config();
                config.policy.name = format!("agent-{}", grant.replace(['~', '/', '.'], "_"));
                config.workspace_dir = workspace.path().join("workspace");
                config.policy.filesystem.read_write = vec![grant.clone()];
                config.policy.ssh = SshPolicy {
                    allowed_keys: vec![SshKeySpec {
                        name: "github".into(),
                        private_key: "~/.ssh/id_ed25519".into(),
                        allowed_hosts: vec!["github.com".into()],
                    }],
                    generate_config: true,
                    generate_known_hosts: false,
                };

                let err = prepare_managed_agent_workspace(
                    &mut config,
                    true,
                    PlatformBackendSelection::LinuxMxc,
                )
                .unwrap_err();
                let managed_home = home_link
                    .join(".axis/agents")
                    .join(&config.policy.name)
                    .join("home");

                assert!(
                    err.to_string()
                        .contains("cannot grant real home read_write path"),
                    "unexpected error for {grant}: {err}"
                );
                assert!(
                    !managed_home.join(".ssh/id_ed25519").exists(),
                    "symlinked HOME grant {grant} must be rejected before copying SSH keys"
                );
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_preexisting_managed_home_symlink() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let outside = home.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            let agent_root = home.path().join(".axis/agents/agent-ssh");
            std::fs::create_dir_all(&agent_root).unwrap();
            std::os::unix::fs::symlink(&outside, agent_root.join("home")).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_managed_agent_workspace(
                &mut config,
                true,
                PlatformBackendSelection::LinuxMxc,
            )
            .unwrap_err();

            assert!(matches!(err, SandboxError::CreationFailed(_)));
            assert!(err.to_string().contains("must not contain symlinks"));
            assert!(!outside.join(".ssh/id_ed25519").exists());
            assert_eq!(
                std::fs::read_to_string(real_ssh.join("id_ed25519")).unwrap(),
                "real-private-key"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_rejects_preexisting_managed_ssh_symlink() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let managed_home = home.path().join(".axis/agents/agent-ssh/home");
            std::fs::create_dir_all(&managed_home).unwrap();
            let outside = home.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, managed_home.join(".ssh")).unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_managed_agent_workspace(
                &mut config,
                true,
                PlatformBackendSelection::LinuxMxc,
            )
            .unwrap_err();

            assert!(matches!(err, SandboxError::CreationFailed(_)));
            assert!(err.to_string().contains("must not be a symlink"));
            assert!(!outside.join("id_ed25519").exists());
            assert_eq!(
                std::fs::read_to_string(real_ssh.join("id_ed25519")).unwrap(),
                "real-private-key"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mxc_scoped_ssh_preserves_generated_ssh_on_backend_setup_failure() {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let real_ssh = home.path().join(".ssh");
            std::fs::create_dir(&real_ssh).unwrap();
            let key_path = real_ssh.join("id_ed25519");
            std::fs::write(&key_path, "real-private-key").unwrap();

            let mut config = test_config();
            config.policy.name = "agent-ssh".into();
            config.policy.network.mode = NetworkMode::Proxy;
            config.workspace_dir = workspace.path().join("workspace");
            config.policy.ssh = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "~/.ssh/id_ed25519".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = match Sandbox::create_inner_with_backend(
                config,
                true,
                PlatformBackendSelection::LinuxMxc,
            ) {
                Ok(_) => panic!("MXC backend setup should fail for unsupported proxy mode"),
                Err(err) => err,
            };
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");

            assert!(matches!(err, SandboxError::IsolationFailed(_)));
            assert!(real_ssh.is_dir());
            assert!(!real_ssh.is_symlink());
            assert_eq!(
                std::fs::read_to_string(real_ssh.join("id_ed25519")).unwrap(),
                "real-private-key"
            );
            assert_eq!(
                std::fs::read_to_string(managed_home.join(".ssh/id_ed25519")).unwrap(),
                "real-private-key",
                "backend setup failure should not delete shared generated SSH state"
            );
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_create_for_exec_uses_mxc_linux_backend_by_default() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");
        config.policy.filesystem.compatibility = Compatibility::HardRequirement;
        disable_resource_limits(&mut config);

        let err = match Sandbox::create_for_exec(config) {
            Ok(_) => panic!("default MXC backend should reject unsupported filesystem semantics"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("MXC Linux backend unsupported"));
        assert!(err.to_string().contains("default-deny"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_create_uses_mxc_linux_backend_by_default() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");
        config.policy.filesystem.compatibility = Compatibility::HardRequirement;
        disable_resource_limits(&mut config);

        let err = match Sandbox::create(config) {
            Ok(_) => panic!("default MXC backend should reject unsupported filesystem semantics"),
            Err(err) => err,
        };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("MXC Linux backend unsupported"));
        assert!(err.to_string().contains("default-deny"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_linux_mxc_backend_fails_closed_before_spawn() {
        let workspace = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.workspace_dir = workspace.path().join("workspace");
        config.policy.filesystem.compatibility = Compatibility::HardRequirement;
        disable_resource_limits(&mut config);

        let err =
            match create_platform_sandbox_with_backend(&config, PlatformBackendSelection::LinuxMxc)
            {
                Ok(_) => panic!("MXC backend should reject unsupported filesystem semantics"),
                Err(err) => err,
            };

        assert!(matches!(err, SandboxError::IsolationFailed(_)));
        assert!(err.to_string().contains("MXC Linux backend unsupported"));
        assert!(err.to_string().contains("default-deny"));
    }

    #[cfg(target_os = "linux")]
    fn disable_resource_limits(config: &mut SandboxConfig) {
        config.policy.process.max_processes = 0;
        config.policy.process.max_memory_mb = 0;
        config.policy.process.cpu_rate_percent = 0;
    }

    fn with_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        crate::test_support::with_home(home, f)
    }
}
