// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Workspace preparation — creates contained agent state directories
//! under ~/.axis/agents/<policy-name>/ with symlinks from the paths
//! agents expect (e.g., ~/.claude, ~/.codex).
//!
//! This ensures all agent-writable data is contained in a single
//! directory tree that can be inspected, backed up, and destroyed.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
    fn GetTokenInformation(
        token: isize,
        information_class: u32,
        information: *mut std::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut std::ffi::c_void, text: *mut *mut u16) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> isize;
    fn CloseHandle(handle: isize) -> i32;
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

/// Agent state directory mappings.
/// Maps the path agents expect to write to → the directory name under .axis/agents/<name>/.
const AGENT_DIR_MAPPINGS: &[(&str, &str)] = &[
    (".claude", "claude"),
    (".local/share/claude", "claude-share"),
    (".codex", "codex"),
    (".openclaw", "openclaw"),
    (".ironclaw", "ironclaw"),
    (".hermes", "hermes"),
];

/// Shared user directories that must not be replaced with agent state aliases.
const NEVER_SYMLINK: &[&str] = &[
    ".config", // Shared configuration can contain unrelated credentials.
    "Library", // macOS ~/Library is huge and has circular revlinks
    ".local",  // Too broad — contains many unrelated things
    "AppData", // Windows equivalent of ~/Library
    "Documents",
    "Desktop",
    "Downloads",
];

/// Prepare the agent workspace: create ~/.axis/agents/<name>/ and symlink
/// agent-expected directories to it.
///
/// Returns the list of (symlink_path, target_path) pairs that were created.
pub fn prepare_agent_workspace(
    policy_name: &str,
    read_write_paths: &[String],
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let home = user_home()?;

    let agent_root = agent_state_root_checked(policy_name)?;
    create_axis_private_dir(&agent_root, 0o700, "agent state root")?;

    let mut symlinks = Vec::new();

    for rw_path in read_write_paths {
        let Some((symlink_path, contained_dir)) =
            agent_state_mapping_for_policy_path_with_home(rw_path, &home, &agent_root)?
        else {
            continue;
        };

        // Create the contained directory.
        std::fs::create_dir_all(&contained_dir)
            .map_err(|e| format!("cannot create {}: {e}", contained_dir.display()))?;

        // If the expected path already exists and is not a symlink, skip it
        // (don't clobber real user data).
        if symlink_path.exists() {
            if symlink_path.is_symlink() {
                // Remove old symlink and recreate.
                let _ = std::fs::remove_file(&symlink_path);
            } else {
                // Real directory exists — move contents to contained dir,
                // then replace with symlink.
                tracing::info!(
                    "workspace: moving {} -> {}",
                    symlink_path.display(),
                    contained_dir.display()
                );
                // Only move if contained dir is empty (first run).
                if contained_dir
                    .read_dir()
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(true)
                {
                    // Copy contents recursively.
                    copy_dir_contents(&symlink_path, &contained_dir)?;
                }
                // Rename original to .bak, then create symlink.
                let relative = symlink_path.strip_prefix(&home).unwrap_or(&symlink_path);
                let backup = home.join(format!("{}.axis-backup", relative.display()));
                if !backup.exists() {
                    let _ = std::fs::rename(&symlink_path, &backup);
                } else {
                    let _ = std::fs::remove_dir_all(&symlink_path);
                }
            }
        }

        // Create parent directory for the symlink.
        if let Some(parent) = symlink_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Create symlink: ~/.claude -> ~/.axis/agents/<policy>/claude
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&contained_dir, &symlink_path).map_err(|e| {
                format!(
                    "symlink {} -> {}: {e}",
                    symlink_path.display(),
                    contained_dir.display()
                )
            })?;
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&contained_dir, &symlink_path).map_err(|e| {
                format!(
                    "symlink {} -> {}: {e}",
                    symlink_path.display(),
                    contained_dir.display()
                )
            })?;
        }

        tracing::info!(
            "workspace: {} -> {}",
            symlink_path.display(),
            contained_dir.display()
        );
        symlinks.push((symlink_path, contained_dir));
    }

    Ok(symlinks)
}

fn contained_agent_dir_for_relative(relative: &Path, agent_root: &Path) -> Option<PathBuf> {
    AGENT_DIR_MAPPINGS
        .iter()
        .find(|(expected, _)| relative == Path::new(expected))
        .map(|(_, contained)| agent_root.join(contained))
}

/// Remove symlinks created by prepare_agent_workspace.
pub fn cleanup_agent_symlinks(symlinks: &[(PathBuf, PathBuf)]) {
    for (symlink_path, _) in symlinks {
        if symlink_path.is_symlink() {
            let _ = std::fs::remove_file(symlink_path);
            // Restore backup if it exists.
            let backup = PathBuf::from(format!("{}.axis-backup", symlink_path.display()));
            if backup.exists() {
                let _ = std::fs::rename(&backup, symlink_path);
            }
        }
    }
}

/// Get the agent state root directory.
pub fn agent_state_root(policy_name: &str) -> PathBuf {
    agent_state_root_checked(policy_name).unwrap_or_else(|_| {
        user_home()
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".axis")
            .join("agents")
            .join("invalid-policy-name")
    })
}

/// Get the scoped SSH directory for a policy.
pub fn ssh_workspace_path(policy_name: &str) -> PathBuf {
    agent_state_root(policy_name).join("ssh")
}

/// Get the AXIS-managed home directory for a policy.
pub fn managed_home_path(policy_name: &str) -> PathBuf {
    agent_state_root(policy_name).join("home")
}

/// Prepare a separate XDG config directory when the policy grants it explicitly.
pub(crate) fn prepare_agent_config(
    policy_name: &str,
    read_write_paths: &[String],
) -> Result<Option<PathBuf>, String> {
    // The legacy config/ target may contain copies of the user's credentials.
    let config_home = agent_state_root_checked(policy_name)?.join("xdg-config");
    let granted = read_write_paths.iter().try_fold(false, |found, path| {
        let expanded = expand_home_or_absolute_path(path)?;
        Ok::<_, String>(found || expanded.as_ref() == Some(&config_home))
    })?;
    if !granted {
        return Ok(None);
    }
    create_axis_private_dir(&config_home, 0o700, "agent config directory")?;
    Ok(Some(config_home))
}

/// Prepare an AXIS-owned home directory for backends that cannot represent
/// host-path mount aliases such as binding generated SSH state at ~/.ssh.
pub(crate) fn prepare_managed_home_workspace(
    policy_name: &str,
    read_write_paths: &[String],
) -> Result<PathBuf, String> {
    let real_home = user_home()?;
    let agent_root = agent_state_root_checked(policy_name)?;
    let managed_home = agent_root.join("home");
    create_axis_private_dir(&managed_home, 0o700, "managed home")?;

    for rw_path in read_write_paths {
        let Some((expected_home_path, contained_dir)) =
            managed_home_agent_state_mapping_for_policy_path_with_home(
                rw_path,
                &real_home,
                &agent_root,
            )?
        else {
            continue;
        };
        create_axis_private_dir(&contained_dir, 0o700, "agent state directory")?;

        let relative = expected_home_path
            .strip_prefix(&real_home)
            .map_err(|e| format!("managed home path '{}': {e}", expected_home_path.display()))?;
        let managed_path = managed_home.join(relative);
        if let Some(parent) = managed_path.parent() {
            create_axis_private_dir(parent, 0o700, "managed home parent")?;
        }
        if normalize_path(contained_dir.clone()) == normalize_path(managed_path.clone()) {
            // Windows MXC uses physical directories inside the managed HOME.
            // It must not depend on developer-mode/admin symlink privileges.
            continue;
        }
        if managed_path.is_symlink() {
            std::fs::remove_file(&managed_path).map_err(|e| {
                format!(
                    "remove managed home symlink '{}': {e}",
                    managed_path.display()
                )
            })?;
        } else if managed_path.exists() {
            return Err(format!(
                "managed home path '{}' already exists and is not an AXIS symlink",
                managed_path.display()
            ));
        }
        symlink_dir(&contained_dir, &managed_path)?;
    }

    #[cfg(unix)]
    if let Some(config_home) = prepare_agent_config(policy_name, read_write_paths)? {
        let managed_config = managed_home.join(".config");
        if managed_config.is_symlink() {
            std::fs::remove_file(&managed_config)
                .map_err(|err| format!("remove managed config alias: {err}"))?;
        } else if managed_config.exists() {
            return Err("managed config alias must not replace an existing directory".into());
        }
        symlink_dir(&config_home, &managed_config)?;
    }

    Ok(managed_home)
}

pub(crate) fn with_managed_home_setup_lock<T>(
    policy_name: &str,
    action: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let _lock = AgentStateSetupLock::acquire(policy_name)?;
    action()
}

#[cfg(target_os = "linux")]
struct AgentStateSetupLock {
    file: std::fs::File,
}

#[cfg(target_os = "linux")]
impl AgentStateSetupLock {
    fn acquire(policy_name: &str) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let agent_root = agent_state_root_checked(policy_name)?;
        create_axis_private_dir(&agent_root, 0o700, "agent setup root")?;
        let lock_path = agent_root.join(".setup.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|err| format!("open agent setup lock '{}': {err}", lock_path.display()))?;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(format!(
                "lock agent setup '{}': {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }
}

#[cfg(target_os = "linux")]
impl Drop for AgentStateSetupLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;

        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(target_os = "linux"))]
struct AgentStateSetupLock;

#[cfg(not(target_os = "linux"))]
impl AgentStateSetupLock {
    fn acquire(_policy_name: &str) -> Result<Self, String> {
        Ok(Self)
    }
}

/// Create ~/.ssh as a symlink to the scoped SSH directory.
///
/// This refuses to replace any existing ~/.ssh path, including an existing
/// symlink, because doing so could hide or disturb the user's real SSH state.
pub fn link_scoped_ssh_workspace(ssh_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let home = user_home()?;
    let ssh_link = home.join(".ssh");
    if ssh_link.exists() || ssh_link.is_symlink() {
        return Err(format!(
            "refusing to replace existing ~/.ssh at {}",
            ssh_link.display()
        ));
    }
    create_axis_private_dir(ssh_dir, 0o700, "scoped SSH directory")?;

    symlink_dir(ssh_dir, &ssh_link)?;

    Ok((ssh_link, ssh_dir.to_path_buf()))
}

pub(crate) fn expand_home_or_absolute_path(path: &str) -> Result<Option<PathBuf>, String> {
    let home = user_home()?;
    expand_home_or_absolute_path_with_home(path, &home)
}

pub(crate) fn user_home_path() -> Result<PathBuf, String> {
    user_home()
}

pub(crate) fn scoped_ssh_link_path() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".ssh"))
}

pub(crate) fn agent_state_mapping_for_policy_path(
    policy_name: &str,
    path: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let home = user_home()?;
    let agent_root = agent_state_root_checked(policy_name)?;
    agent_state_mapping_for_policy_path_with_home(path, &home, &agent_root)
}

pub(crate) fn managed_home_agent_state_mapping_for_policy_path(
    policy_name: &str,
    path: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let home = user_home()?;
    let agent_root = agent_state_root_checked(policy_name)?;
    managed_home_agent_state_mapping_for_policy_path_with_home(path, &home, &agent_root)
}

pub(crate) fn scoped_ssh_link_points_to(ssh_dir: &Path) -> Result<bool, String> {
    let home = user_home()?;
    let ssh_link = home.join(".ssh");
    if !ssh_link.is_symlink() {
        return Ok(false);
    }
    let target = std::fs::read_link(&ssh_link)
        .map_err(|e| format!("read scoped SSH symlink '{}': {e}", ssh_link.display()))?;
    let target = if target.is_absolute() {
        target
    } else {
        ssh_link
            .parent()
            .unwrap_or_else(|| Path::new(std::path::MAIN_SEPARATOR_STR))
            .join(target)
    };
    Ok(normalize_path(target) == normalize_path(ssh_dir.to_path_buf()))
}

/// Prepare a scoped SSH directory for the sandbox.
///
/// Creates a `.ssh/` directory in the agent's containment root with:
/// - Only the specified private keys (copied, not symlinked)
/// - A generated `config` file restricting key→host mappings
/// - A generated `known_hosts` with only allowed host fingerprints
///
/// Returns the path to the sandbox .ssh directory.
pub fn prepare_ssh_workspace(
    policy_name: &str,
    ssh_policy: &axis_core::policy::SshPolicy,
) -> Result<Option<PathBuf>, String> {
    let ssh_dir = agent_state_root_checked(policy_name)?.join("ssh");
    prepare_ssh_workspace_at_with_permissions(
        policy_name,
        ssh_policy,
        &ssh_dir,
        set_private_permissions,
    )
}

pub(crate) fn prepare_ssh_workspace_at(
    policy_name: &str,
    ssh_policy: &axis_core::policy::SshPolicy,
    ssh_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    prepare_ssh_workspace_at_with_permissions(
        policy_name,
        ssh_policy,
        ssh_dir,
        set_private_permissions,
    )
}

fn prepare_ssh_workspace_at_with_permissions<F>(
    policy_name: &str,
    ssh_policy: &axis_core::policy::SshPolicy,
    ssh_dir: &Path,
    mut set_permissions: F,
) -> Result<Option<PathBuf>, String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    if ssh_policy.allowed_keys.is_empty() {
        return Ok(None);
    }

    validate_policy_name_component(policy_name)?;
    let ssh_parent = ssh_dir
        .parent()
        .ok_or_else(|| format!("scoped SSH directory '{}' has no parent", ssh_dir.display()))?;
    let staging_parent = ssh_workspace_staging_parent_checked(policy_name)?;
    create_axis_private_dir_with_permissions(
        ssh_parent,
        0o700,
        "scoped SSH parent directory",
        &mut set_permissions,
    )?;
    create_axis_private_dir_with_permissions(
        &staging_parent,
        0o700,
        "scoped SSH staging directory",
        &mut set_permissions,
    )?;
    let staging_dir = tempfile::Builder::new()
        .prefix(".ssh.")
        .tempdir_in(&staging_parent)
        .map_err(|err| {
            format!(
                "create temporary scoped SSH directory under '{}': {err}",
                staging_parent.display()
            )
        })?;
    set_permissions(staging_dir.path(), 0o700)?;

    let home = user_home()?;
    let prepared_keys = prepare_ssh_keys(ssh_policy, &home)?;

    populate_ssh_workspace(
        ssh_policy,
        staging_dir.path(),
        &prepared_keys,
        &mut set_permissions,
    )?;

    replace_generated_ssh_dir(ssh_dir, staging_dir)?;
    Ok(Some(ssh_dir.to_path_buf()))
}

struct PreparedSshKey<'a> {
    spec: &'a axis_core::policy::SshKeySpec,
    src_path: PathBuf,
    key_filename: String,
    exists: bool,
}

fn prepare_ssh_keys<'a>(
    ssh_policy: &'a axis_core::policy::SshPolicy,
    home: &Path,
) -> Result<Vec<PreparedSshKey<'a>>, String> {
    let mut generated_key_files = HashSet::new();
    let mut prepared = Vec::with_capacity(ssh_policy.allowed_keys.len());

    for key_spec in &ssh_policy.allowed_keys {
        for host in &key_spec.allowed_hosts {
            validate_ssh_config_token("host pattern", host)?;
        }
        let src_path = expand_home_or_absolute_path_with_home(&key_spec.private_key, home)?
            .ok_or_else(|| {
                format!(
                    "ssh: key '{}' path must be absolute or start with ~/; got {}",
                    key_spec.name, key_spec.private_key
                )
            })?;
        let key_filename = src_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("key_{}", key_spec.name));
        validate_ssh_config_token("key filename", &key_filename)?;
        let exists = src_path.exists();
        if exists && !generated_key_files.insert(key_filename.clone()) {
            return Err(format!(
                "ssh: multiple allowed keys would generate '{}'",
                key_filename
            ));
        }
        prepared.push(PreparedSshKey {
            spec: key_spec,
            src_path,
            key_filename,
            exists,
        });
    }

    Ok(prepared)
}

fn populate_ssh_workspace<F>(
    ssh_policy: &axis_core::policy::SshPolicy,
    ssh_dir: &Path,
    prepared_keys: &[PreparedSshKey<'_>],
    set_permissions: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    // Copy each allowed key.
    let mut config_entries = Vec::new();
    for prepared_key in prepared_keys {
        if !prepared_key.exists {
            tracing::warn!(
                "ssh: key '{}' not found at {}",
                prepared_key.spec.name,
                prepared_key.src_path.display()
            );
            continue;
        }
        let key_filename = &prepared_key.key_filename;
        let dst_path = ssh_dir.join(key_filename);
        copy_file_create_new(&prepared_key.src_path, &dst_path)
            .map_err(|e| format!("copy key '{}': {e}", prepared_key.spec.name))?;

        if let Err(err) = set_permissions(&dst_path, 0o600) {
            let _ = std::fs::remove_file(&dst_path);
            return Err(err);
        }

        // Copy public key too if it exists.
        let pub_src = PathBuf::from(format!("{}.pub", prepared_key.src_path.display()));
        if pub_src.exists() {
            let pub_dst = ssh_dir.join(format!("{key_filename}.pub"));
            let _ = copy_file_create_new(&pub_src, &pub_dst);
        }

        tracing::info!(
            "ssh: exposed key '{}' for hosts {:?}",
            prepared_key.spec.name,
            prepared_key.spec.allowed_hosts
        );

        // Build SSH config entry.
        let hosts = if prepared_key.spec.allowed_hosts.is_empty() {
            "*".to_string()
        } else {
            prepared_key.spec.allowed_hosts.join(" ")
        };
        config_entries.push((hosts, key_filename.clone()));
    }

    // Generate SSH config.
    if ssh_policy.generate_config && !config_entries.is_empty() {
        #[cfg(windows)]
        install_windows_ssh_proxy_helper(ssh_dir, set_permissions)?;
        let mut config = String::new();
        config.push_str("# Auto-generated by AXIS — only allowed SSH hosts\n");
        config.push_str("# Do not edit — this file is managed by the sandbox.\n\n");

        for (hosts, key_file) in &config_entries {
            config.push_str(&format!("Host {hosts}\n"));
            config.push_str(&format!("    IdentityFile ~/.ssh/{key_file}\n"));
            config.push_str("    IdentitiesOnly yes\n");
            config.push_str("    BatchMode yes\n");
            config.push_str("    PasswordAuthentication no\n");
            config.push_str("    KbdInteractiveAuthentication no\n");
            config.push_str("    PreferredAuthentications publickey\n");
            config.push_str("    StrictHostKeyChecking yes\n");
            config.push_str("    UserKnownHostsFile ~/.ssh/known_hosts\n");
            config.push_str(if cfg!(windows) {
                "    GlobalKnownHostsFile NUL\n"
            } else {
                "    GlobalKnownHostsFile /dev/null\n"
            });
            config.push_str("    ForwardAgent no\n");
            config.push_str("    ForwardX11 no\n");
            config.push_str("    ClearAllForwardings yes\n");
            #[cfg(windows)]
            config.push_str("    ProxyCommand \"%d/.ssh/axis-ssh-proxy.exe\" %h %p\n");
            config.push('\n');
        }

        // Block all other hosts.
        config.push_str("# Deny all other SSH connections\n");
        config.push_str("Host *\n");
        config.push_str(if cfg!(windows) {
            "    IdentityFile NUL\n"
        } else {
            "    IdentityFile /dev/null\n"
        });
        config.push_str("    IdentitiesOnly yes\n");
        config.push_str("    BatchMode yes\n");
        config.push_str("    PasswordAuthentication no\n");
        config.push_str("    KbdInteractiveAuthentication no\n");
        config.push_str("    ForwardAgent no\n");
        config.push_str("    ForwardX11 no\n");
        config.push_str("    ClearAllForwardings yes\n");

        write_file_create_new(&ssh_dir.join("config"), config.as_bytes())
            .map_err(|e| format!("write ssh config: {e}"))?;
    }

    // Generate known_hosts via ssh-keyscan for allowed hosts.
    if ssh_policy.generate_known_hosts {
        let mut all_hosts: Vec<String> = ssh_policy
            .allowed_keys
            .iter()
            .flat_map(|k| k.allowed_hosts.iter().cloned())
            .filter(|h| !h.contains('*')) // skip wildcards
            .collect();
        all_hosts.sort();
        all_hosts.dedup();

        if !all_hosts.is_empty() {
            let output = ssh_keyscan_command()?.args(&all_hosts).output();

            match output {
                Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                    write_file_create_new(&ssh_dir.join("known_hosts"), &output.stdout)
                        .map_err(|e| format!("write known_hosts: {e}"))?;
                    tracing::info!("ssh: generated known_hosts for {} hosts", all_hosts.len());
                }
                Ok(output) => {
                    return Err(format!(
                        "ssh-keyscan failed for scoped hosts (status {:?}): {}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                Err(error) => return Err(format!("launch ssh-keyscan: {error}")),
            }
        }
    }

    // Create marker file.
    let _ = write_file_create_new(
        &ssh_dir.join(".axis-managed"),
        b"This SSH directory is managed by AXIS.\n",
    );

    Ok(())
}

fn ssh_keyscan_command() -> Result<std::process::Command, String> {
    #[cfg(windows)]
    if std::env::var_os("AXIS_RUN_WINDOWS_SSH_E2E").as_deref() == Some(std::ffi::OsStr::new("1"))
        && let Some(path) = std::env::var_os("AXIS_TEST_SSH_KEYSCAN")
    {
        let path = PathBuf::from(path);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("test ssh-keyscan override '{}': {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "test ssh-keyscan override '{}' must be a regular file",
                path.display()
            ));
        }
        return Ok(std::process::Command::new(path));
    }
    Ok(std::process::Command::new("ssh-keyscan"))
}

#[cfg(all(windows, not(test)))]
fn install_windows_ssh_proxy_helper<F>(
    ssh_dir: &Path,
    set_permissions: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    let source = std::env::current_exe()
        .map_err(|error| format!("resolve AXIS executable for SSH helper: {error}"))?
        .with_file_name("axis-ssh-proxy.exe");
    let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
        format!(
            "SSH proxy helper '{}' is unavailable: {error}",
            source.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "SSH proxy helper '{}' must be a regular file",
            source.display()
        ));
    }
    let destination = ssh_dir.join("axis-ssh-proxy.exe");
    copy_file_create_new(&source, &destination)
        .map_err(|error| format!("copy Windows SSH proxy helper: {error}"))?;
    set_permissions(&destination, 0o500)
}

#[cfg(all(windows, test))]
fn install_windows_ssh_proxy_helper<F>(
    ssh_dir: &Path,
    set_permissions: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    let destination = ssh_dir.join("axis-ssh-proxy.exe");
    write_file_create_new(&destination, b"unit-test-helper")
        .map_err(|error| format!("write test SSH proxy helper: {error}"))?;
    set_permissions(&destination, 0o500)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("set permissions {mode:o} on '{}': {e}", path.display()))
}

#[cfg(windows)]
fn set_private_permissions(path: &Path, _mode: u32) -> Result<(), String> {
    let user_sid = current_process_user_sid()?;
    let system_sid = "S-1-5-18";
    let inheritance = if path.is_dir() { "(OI)(CI)" } else { "" };
    let user_grant = format!("*{user_sid}:{inheritance}F");
    let system_grant = format!("*{system_sid}:{inheritance}F");
    let system_root = std::env::var_os("SystemRoot")
        .ok_or_else(|| "SystemRoot is unavailable while hardening SSH state".to_string())?;
    let icacls = PathBuf::from(system_root)
        .join("System32")
        .join("icacls.exe");
    let output = std::process::Command::new(&icacls)
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(user_grant)
        .arg(system_grant)
        .output()
        .map_err(|error| format!("launch '{}': {error}", icacls.display()))?;
    if !output.status.success() {
        return Err(format!(
            "harden Windows ACL on '{}': {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn current_process_user_sid() -> Result<String, String> {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    let mut token = 0isize;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "OpenProcessToken for SSH ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    struct TokenGuard(isize);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _token_guard = TokenGuard(token);
    let mut required = 0u32;
    unsafe {
        let _ = GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required < std::mem::size_of::<usize>() as u32 {
        return Err("GetTokenInformation(TokenUser) returned an invalid size".into());
    }
    let mut buffer = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(format!(
            "GetTokenInformation(TokenUser): {}",
            std::io::Error::last_os_error()
        ));
    }
    let sid = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<*mut std::ffi::c_void>()) };
    let mut text = std::ptr::null_mut::<u16>();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(format!(
            "ConvertSidToStringSidW: {}",
            std::io::Error::last_os_error()
        ));
    }
    struct LocalGuard(*mut u16);
    impl Drop for LocalGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(self.0.cast());
            }
        }
    }
    let _text_guard = LocalGuard(text);
    let length = (0..)
        .find(|&index| unsafe { *text.add(index) } == 0)
        .ok_or_else(|| "unterminated SID text".to_string())?;
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, length)
    }))
}

fn symlink_dir(target: &Path, link: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .map_err(|e| format!("symlink {} -> {}: {e}", link.display(), target.display()))?;
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
            .map_err(|e| format!("symlink {} -> {}: {e}", link.display(), target.display()))?;
    }
    Ok(())
}

fn create_axis_private_dir(path: &Path, mode: u32, label: &str) -> Result<(), String> {
    let mut set_permissions = set_private_permissions;
    create_axis_private_dir_with_permissions(path, mode, label, &mut set_permissions)
}

fn create_axis_private_dir_with_permissions<F>(
    path: &Path,
    mode: u32,
    label: &str,
    set_permissions: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Path, u32) -> Result<(), String>,
{
    create_axis_dir_all_rejecting_symlinks(path, label)?;
    set_permissions(path, mode)?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} '{}': {err}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{label} '{}' must be a real directory",
            path.display()
        ));
    }
    Ok(())
}

fn create_axis_dir_all_rejecting_symlinks(path: &Path, label: &str) -> Result<(), String> {
    let home = user_home()?;
    let relative = path.strip_prefix(&home).map_err(|_| {
        format!(
            "{label} '{}' must be under the user home '{}'",
            path.display(),
            home.display()
        )
    })?;

    let mut current = home;
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                current.push(name);
                ensure_real_directory_component(&current, label)?;
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "{label} '{}' contains unsupported path components",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn ensure_real_directory_component(path: &Path, label: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "{label} '{}' must not contain symlinks",
                    path.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(format!("{label} '{}' must be a directory", path.display()));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|err| format!("inspect {label} '{}': {err}", path.display()))?;
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "{label} '{}' must not contain symlinks",
                        path.display()
                    ));
                }
                if !metadata.is_dir() {
                    return Err(format!("{label} '{}' must be a directory", path.display()));
                }
            }
            Err(create_err) => {
                return Err(format!("create {label} '{}': {create_err}", path.display()));
            }
        },
        Err(err) => return Err(format!("inspect {label} '{}': {err}", path.display())),
    }
    Ok(())
}

fn reset_generated_ssh_dir(ssh_dir: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(ssh_dir)
        .map_err(|err| format!("read ssh dir '{}': {err}", ssh_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read ssh dir '{}': {err}", ssh_dir.display()))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|err| format!("inspect generated ssh path '{}': {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "generated ssh path '{}' must not be a symlink",
                path.display()
            ));
        }
        if metadata.is_dir() {
            return Err(format!(
                "generated ssh path '{}' must not be a directory",
                path.display()
            ));
        }
        std::fs::remove_file(&path).map_err(|err| {
            format!(
                "remove stale generated ssh path '{}': {err}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn replace_generated_ssh_dir(ssh_dir: &Path, staging_dir: tempfile::TempDir) -> Result<(), String> {
    remove_replaceable_generated_ssh_dir(ssh_dir)?;
    let staging_path = staging_dir.keep();
    match std::fs::rename(&staging_path, ssh_dir) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_dir_all(&staging_path);
            Err(format!(
                "replace generated ssh dir '{}' from '{}': {err}",
                ssh_dir.display(),
                staging_path.display()
            ))
        }
    }
}

fn remove_replaceable_generated_ssh_dir(ssh_dir: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(ssh_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("inspect ssh dir '{}': {err}", ssh_dir.display())),
    };

    if metadata.file_type().is_symlink() {
        return Err(format!(
            "generated ssh path '{}' must not be a symlink",
            ssh_dir.display()
        ));
    }
    if metadata.is_dir() {
        reset_generated_ssh_dir(ssh_dir)?;
        std::fs::remove_dir(ssh_dir)
            .map_err(|err| format!("remove generated ssh dir '{}': {err}", ssh_dir.display()))?;
    } else {
        return Err(format!(
            "generated ssh path '{}' must be a directory",
            ssh_dir.display()
        ));
    }
    Ok(())
}

fn copy_file_create_new(src: &Path, dst: &Path) -> std::io::Result<u64> {
    let mut input = std::fs::File::open(src)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;
    std::io::copy(&mut input, &mut output)
}

fn write_file_create_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)
}

fn validate_ssh_config_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || byte == b'/' || byte == b'\\')
    {
        return Err(format!(
            "ssh: {label} '{value}' is not safe for generated config"
        ));
    }
    Ok(())
}

fn user_home() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .ok_or_else(|| "cannot determine HOME directory".to_string())?;
    if !home.is_absolute() {
        return Err(format!(
            "HOME directory is not absolute: {}",
            home.display()
        ));
    }
    Ok(normalize_path(home))
}

fn agent_state_root_checked(policy_name: &str) -> Result<PathBuf, String> {
    validate_policy_name_component(policy_name)?;
    Ok(user_home()?.join(".axis").join("agents").join(policy_name))
}

pub(crate) fn ssh_workspace_staging_parent_checked(policy_name: &str) -> Result<PathBuf, String> {
    Ok(agent_state_root_checked(policy_name)?.join("ssh-staging"))
}

fn validate_policy_name_component(policy_name: &str) -> Result<(), String> {
    axis_core::policy::validate_policy_name_component(policy_name).map_err(|err| err.to_string())
}

fn expand_home_or_absolute_path_with_home(
    path: &str,
    home: &Path,
) -> Result<Option<PathBuf>, String> {
    let expanded = if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path.starts_with('~') {
        return Err(format!(
            "unsupported home path '{path}': only '~' and '~/' are supported"
        ));
    } else {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            path
        } else {
            return Ok(None);
        }
    };

    Ok(Some(normalize_path(expanded)))
}

fn agent_state_mapping_for_policy_path_with_home(
    path: &str,
    home: &Path,
    agent_root: &Path,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let Some(expanded) = expand_home_or_absolute_path_with_home(path, home)? else {
        return Ok(None);
    };

    // Skip non-home paths (workspace, tmpdir, etc.).
    if !expanded.starts_with(home) {
        return Ok(None);
    }

    // Never symlink ~/.axis itself (that's the containment root).
    if expanded == home.join(".axis") || expanded.starts_with(home.join(".axis")) {
        return Ok(None);
    }

    // Never symlink large/dangerous directories.
    let rel_check = expanded.strip_prefix(home).unwrap_or(&expanded);
    if NEVER_SYMLINK
        .iter()
        .any(|&blocked| rel_check == Path::new(blocked) || rel_check.starts_with(blocked))
    {
        return Ok(None);
    }

    let relative = match expanded.strip_prefix(home) {
        Ok(relative) => relative.to_path_buf(),
        Err(_) => return Ok(None),
    };
    let Some(contained_dir) = contained_agent_dir_for_relative(&relative, agent_root) else {
        return Ok(None);
    };

    Ok(Some((home.join(relative), contained_dir)))
}

fn managed_home_agent_state_mapping_for_policy_path_with_home(
    path: &str,
    home: &Path,
    agent_root: &Path,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let Some(expanded) = expand_home_or_absolute_path_with_home(path, home)? else {
        return Ok(None);
    };

    if !expanded.starts_with(home) {
        return Ok(None);
    }

    let relative = match expanded.strip_prefix(home) {
        Ok(relative) => relative.to_path_buf(),
        Err(_) => return Ok(None),
    };
    // Keep managed-HOME AXIS state separate from private setup siblings such as ssh-staging.
    let mapped_agent_state = if relative == Path::new(".axis") || expanded == agent_root {
        Some(agent_root.join("axis"))
    } else {
        contained_agent_dir_for_relative(&relative, agent_root)
    };
    if mapped_agent_state.is_none() {
        return Ok(None);
    }
    #[cfg(target_os = "windows")]
    let contained_dir = if expanded == agent_root {
        mapped_agent_state
    } else {
        Some(agent_root.join("home").join(&relative))
    };
    #[cfg(not(target_os = "windows"))]
    let contained_dir = mapped_agent_state;
    let Some(contained_dir) = contained_dir else {
        return Ok(None);
    };

    Ok(Some((home.join(relative), contained_dir)))
}

fn normalize_path(path: PathBuf) -> PathBuf {
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
    normalized
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for entry in entries.flatten() {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            std::fs::create_dir_all(&dst_path).ok();
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            let _ = std::fs::copy(&src_path, &dst_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{SshKeySpec, SshPolicy};
    #[cfg(target_os = "linux")]
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };
    #[cfg(target_os = "linux")]
    use std::time::Duration;

    #[test]
    fn agent_state_root_is_under_home() {
        let root = agent_state_root("test-policy");
        let root_str = root.to_string_lossy().replace('\\', "/");
        assert!(
            root_str.contains(".axis/agents/test-policy"),
            "expected .axis/agents/test-policy in {root_str}"
        );
    }

    #[test]
    fn mapping_covers_known_agents() {
        let agents = ["claude", "codex", "openclaw", "ironclaw", "hermes"];
        for agent in agents {
            assert!(
                AGENT_DIR_MAPPINGS.iter().any(|(_, name)| *name == agent),
                "missing mapping for {agent}"
            );
        }
    }

    #[test]
    fn only_known_agent_state_paths_are_contained() {
        let temporary_home = tempfile::tempdir().unwrap();
        let home = temporary_home.path();
        let agent_root = home.join(".axis/agents/test");
        let absolute_agent_root = agent_root.to_string_lossy();

        assert_eq!(
            contained_agent_dir_for_relative(Path::new(".codex"), &agent_root),
            Some(agent_root.join("codex"))
        );
        assert_eq!(
            contained_agent_dir_for_relative(Path::new(".config"), &agent_root),
            None
        );
        assert_eq!(
            contained_agent_dir_for_relative(Path::new("fixture/project"), &agent_root),
            None
        );
        assert_eq!(
            agent_state_mapping_for_policy_path_with_home(
                "~/.axis/agents/test",
                home,
                &agent_root,
            )
            .unwrap(),
            None,
            "a policy-owned state root is a grant target, not a home alias"
        );
        assert_eq!(
            managed_home_agent_state_mapping_for_policy_path_with_home(
                "~/.axis/agents/test",
                home,
                &agent_root,
            )
            .unwrap(),
            Some((home.join(".axis/agents/test"), agent_root.join("axis"))),
            "managed HOME setup must redirect the explicit policy-owned root"
        );
        assert_eq!(
            managed_home_agent_state_mapping_for_policy_path_with_home(
                &absolute_agent_root,
                home,
                &agent_root,
            )
            .unwrap(),
            Some((home.join(".axis/agents/test"), agent_root.join("axis"))),
            "absolute agent-root grants must not expose private setup siblings"
        );
    }

    #[test]
    fn workspace_preparation_rejects_unsafe_policy_names() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            for name in [
                ".",
                "..",
                "../escape",
                "/absolute",
                "nested/name",
                "nested\\name",
            ] {
                let err = prepare_agent_workspace(name, &["~/.codex".into()]).unwrap_err();
                assert!(
                    err.contains("policy name"),
                    "expected policy name error for {name:?}, got {err}"
                );
                let mapping_err =
                    agent_state_mapping_for_policy_path(name, "~/.codex").unwrap_err();
                assert!(
                    mapping_err.contains("policy name"),
                    "expected mapping policy name error for {name:?}, got {mapping_err}"
                );
            }
        });
    }

    #[test]
    fn agent_config_is_separate_from_host_legacy_and_other_agent_config() {
        let home = tempfile::tempdir().unwrap();
        with_home(home.path(), || {
            let host_config = home.path().join(".config");
            std::fs::create_dir_all(host_config.join("gh")).unwrap();
            std::fs::write(host_config.join("gh/hosts.yml"), "fake-host-token").unwrap();
            for name in ["first", "second"] {
                let root = agent_state_root(name);
                std::fs::create_dir_all(root.join("config/gh")).unwrap();
                std::fs::write(root.join("config/gh/hosts.yml"), "fake-legacy-token").unwrap();
                let grants = vec![format!("~/.axis/agents/{name}/xdg-config")];
                assert!(prepare_agent_workspace(name, &grants).unwrap().is_empty());
                let config = prepare_agent_config(name, &grants).unwrap().unwrap();
                assert_eq!(config, root.join("xdg-config"));
                assert_eq!(std::fs::read_dir(&config).unwrap().count(), 0);
                std::fs::write(config.join("settings"), name).unwrap();
                prepare_agent_config(name, &grants).unwrap();
                assert_eq!(
                    std::fs::read_to_string(config.join("settings")).unwrap(),
                    name
                );
                assert!(!host_config.is_symlink());
            }
            assert_eq!(
                std::fs::read_to_string(host_config.join("gh/hosts.yml")).unwrap(),
                "fake-host-token"
            );
            assert!(!home.path().join(".config.axis-backup").exists());
        });
    }

    #[test]
    fn shared_config_is_never_migrated_by_workspace_preparation() {
        let home = tempfile::tempdir().unwrap();
        with_home(home.path(), || {
            let config = home.path().join(".config");
            std::fs::create_dir(&config).unwrap();
            std::fs::write(config.join("credential"), "fake-token").unwrap();
            let grants = vec!["~/.config".into()];
            assert!(prepare_agent_workspace("test", &grants).unwrap().is_empty());
            assert!(prepare_agent_config("test", &grants).unwrap().is_none());
            assert!(!config.is_symlink());
            assert!(!agent_state_root("test").join("config").exists());
            assert_eq!(
                std::fs::read_to_string(config.join("credential")).unwrap(),
                "fake-token"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn agent_config_rejects_symlinks_to_host_or_legacy_credentials() {
        let home = tempfile::tempdir().unwrap();
        with_home(home.path(), || {
            let root = agent_state_root("test");
            std::fs::create_dir_all(&root).unwrap();
            for target in [home.path().join(".config"), root.join("config")] {
                std::fs::create_dir_all(&target).unwrap();
                std::fs::write(target.join("credential"), "fake-token").unwrap();
                std::os::unix::fs::symlink(&target, root.join("xdg-config")).unwrap();
                let err = prepare_agent_config("test", &["~/.axis/agents/test/xdg-config".into()])
                    .unwrap_err();
                assert!(err.contains("symlink"));
                assert_eq!(
                    std::fs::read_to_string(target.join("credential")).unwrap(),
                    "fake-token"
                );
                std::fs::remove_file(root.join("xdg-config")).unwrap();
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn managed_home_config_alias_does_not_reuse_legacy_config() {
        let home = tempfile::tempdir().unwrap();
        with_home(home.path(), || {
            let root = agent_state_root("test");
            let managed = root.join("home");
            std::fs::create_dir_all(&managed).unwrap();
            std::fs::create_dir(root.join("config")).unwrap();
            std::fs::write(root.join("config/credential"), "fake-legacy-token").unwrap();
            std::os::unix::fs::symlink(root.join("config"), managed.join(".config")).unwrap();
            let grants = vec!["~/.axis/agents/test/xdg-config".into()];
            prepare_managed_home_workspace("test", &grants).unwrap();
            assert_eq!(
                std::fs::read_link(managed.join(".config")).unwrap(),
                root.join("xdg-config")
            );
            assert!(!managed.join(".config/credential").exists());
            assert_eq!(
                std::fs::read_to_string(root.join("config/credential")).unwrap(),
                "fake-legacy-token"
            );
        });
    }

    #[test]
    fn workspace_preparation_creates_policy_root_without_aliases() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let policy_root = home.path().join(".axis/agents/agent-base-deny");
            let created = prepare_agent_workspace(
                "agent-base-deny",
                &["~/.axis/agents/agent-base-deny".into()],
            )
            .unwrap();

            assert!(created.is_empty());
            assert!(policy_root.is_dir());
            assert!(!policy_root.is_symlink());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&policy_root)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_unsafe_policy_names() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            for name in ["../escape", "/absolute", "nested/name"] {
                let err = prepare_ssh_workspace(name, &ssh_policy).unwrap_err();
                assert!(
                    err.contains("policy name"),
                    "expected policy name error for {name:?}, got {err}"
                );
            }
        });
    }

    #[test]
    fn ssh_workspace_preparation_removes_stale_generated_files() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(&ssh_dir).unwrap();
            std::fs::write(ssh_dir.join("old_key"), "stale-key").unwrap();
            std::fs::write(ssh_dir.join("config"), "stale-config").unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap();

            assert!(!ssh_dir.join("old_key").exists());
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("id_ed25519")).unwrap(),
                "private-key"
            );
            let generated_config = std::fs::read_to_string(ssh_dir.join("config")).unwrap();
            assert!(generated_config.contains("Host github.com"));
            assert!(!generated_config.contains("stale-config"));
            assert_no_staging_ssh_dirs(ssh_dir.parent().unwrap());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_stages_outside_destination_parent() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let managed_home = home.path().join(".axis/agents/agent-ssh/home");
            let ssh_dir = managed_home.join(".ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap();

            let staging_parent = ssh_workspace_staging_parent_checked("agent-ssh").unwrap();
            assert!(
                !staging_parent.starts_with(&managed_home),
                "staging parent must not be inside the writable managed HOME"
            );
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("id_ed25519")).unwrap(),
                "private-key"
            );
            assert_no_staging_ssh_dirs(&managed_home);
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_home_setup_lock_serializes_same_policy_setup() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let active = Arc::new(AtomicUsize::new(0));
            let failures = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(4));

            std::thread::scope(|scope| {
                for _ in 0..4 {
                    let active = Arc::clone(&active);
                    let failures = Arc::clone(&failures);
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        with_managed_home_setup_lock("agent-ssh", || {
                            if active.fetch_add(1, Ordering::SeqCst) != 0 {
                                failures.fetch_add(1, Ordering::SeqCst);
                            }
                            std::thread::sleep(Duration::from_millis(20));
                            active.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                    });
                }
            });

            assert_eq!(failures.load(Ordering::SeqCst), 0);
            assert_eq!(active.load(Ordering::SeqCst), 0);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_home_setup_lock_rejects_symlink_lock_file() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let agent_root = home.path().join(".axis/agents/agent-ssh");
            std::fs::create_dir_all(&agent_root).unwrap();
            let outside = home.path().join("outside-lock-target");
            std::fs::write(&outside, "outside").unwrap();
            std::os::unix::fs::symlink(&outside, agent_root.join(".setup.lock")).unwrap();

            let err = with_managed_home_setup_lock("agent-ssh", || Ok(())).unwrap_err();

            assert!(
                err.contains("open agent setup lock"),
                "unexpected lock error: {err}"
            );
            assert_eq!(std::fs::read_to_string(outside).unwrap(), "outside");
        });
    }

    #[cfg(unix)]
    #[test]
    fn ssh_workspace_preparation_rejects_stale_generated_symlink() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let outside = home.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            let target = outside.join("id_ed25519");
            std::fs::write(&target, "outside-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(&ssh_dir).unwrap();
            std::os::unix::fs::symlink(&target, ssh_dir.join("id_ed25519")).unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("must not be a symlink"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "outside-key");
            assert_eq!(std::fs::read_to_string(&key_path).unwrap(), "private-key");
            assert_no_staging_ssh_dirs(ssh_dir.parent().unwrap());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[cfg(unix)]
    #[test]
    fn ssh_workspace_preparation_rejects_generated_ssh_dir_symlink() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let outside = home.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(ssh_dir.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside, &ssh_dir).unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("must not be a symlink"));
            assert!(ssh_dir.is_symlink());
            assert!(!outside.join("id_ed25519").exists());
            assert!(!outside.join("config").exists());
            assert_eq!(std::fs::read_to_string(&key_path).unwrap(), "private-key");
            assert_no_staging_ssh_dirs(ssh_dir.parent().unwrap());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_stale_generated_directory() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(ssh_dir.join("stale-directory")).unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("must not be a directory"));
            assert!(ssh_dir.join("stale-directory").is_dir());
            assert!(!ssh_dir.join("id_ed25519").exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_existing_generated_ssh_file() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(ssh_dir.parent().unwrap()).unwrap();
            std::fs::write(&ssh_dir, "unexpected-file").unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("must be a directory"));
            assert_eq!(
                std::fs::read_to_string(&ssh_dir).unwrap(),
                "unexpected-file"
            );
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_unsafe_generated_key_filename() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("key filename"));
            assert!(!ssh_dir.join("config").exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_unsafe_generated_host_pattern() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com\nHost *".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("host pattern"));
            assert!(!ssh_dir.join("id_ed25519").exists());
            assert!(!ssh_dir.join("config").exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_validates_all_hosts_before_copying_any_key() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let first_key_path = home.path().join("id_ed25519");
            let second_key_path = home.path().join("id_ed25519_second");
            std::fs::write(&first_key_path, "first-private-key").unwrap();
            std::fs::write(&second_key_path, "second-private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![
                    SshKeySpec {
                        name: "github".into(),
                        private_key: first_key_path.to_string_lossy().into_owned(),
                        allowed_hosts: vec!["github.com".into()],
                    },
                    SshKeySpec {
                        name: "bad".into(),
                        private_key: second_key_path.to_string_lossy().into_owned(),
                        allowed_hosts: vec!["bad.example\nHost *".into()],
                    },
                ],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("host pattern"));
            assert!(!ssh_dir.join("id_ed25519").exists());
            assert!(!ssh_dir.join("id_ed25519_second").exists());
            assert!(!ssh_dir.join("config").exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_validates_known_hosts_inputs_for_missing_keys() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "bad".into(),
                    private_key: "~/.ssh/missing-key".into(),
                    allowed_hosts: vec!["bad.example\nHost *".into()],
                }],
                generate_config: false,
                generate_known_hosts: true,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("host pattern"));
            assert!(!ssh_dir.exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_rejects_option_like_known_hosts_input() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["-p".into()],
                }],
                generate_config: false,
                generate_known_hosts: true,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("host pattern"));
            assert!(!ssh_dir.exists());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_preserves_existing_files_when_validation_fails() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            std::fs::create_dir_all(&ssh_dir).unwrap();
            std::fs::write(ssh_dir.join("id_ed25519"), "stale-private-key").unwrap();
            std::fs::write(ssh_dir.join("config"), "stale-config").unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com\nHost *".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let err = prepare_ssh_workspace_at("agent-ssh", &ssh_policy, &ssh_dir).unwrap_err();

            assert!(err.contains("host pattern"));
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("id_ed25519")).unwrap(),
                "stale-private-key"
            );
            assert_eq!(
                std::fs::read_to_string(ssh_dir.join("config")).unwrap(),
                "stale-config"
            );
            assert_no_staging_ssh_dirs(ssh_dir.parent().unwrap());
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_fails_when_directory_permissions_cannot_be_hardened() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: "/tmp/nonexistent-key".into(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let err = prepare_ssh_workspace_at_with_permissions(
                "agent-ssh",
                &ssh_policy,
                &ssh_dir,
                |_path, mode| Err(format!("permission hook failed for {mode:o}")),
            )
            .unwrap_err();

            assert!(err.contains("permission hook failed for 700"));
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    #[test]
    fn ssh_workspace_preparation_fails_and_removes_key_when_key_permissions_cannot_be_hardened() {
        let home = tempfile::tempdir().unwrap();

        with_home(home.path(), || {
            let key_path = home.path().join("id_ed25519");
            std::fs::write(&key_path, "private-key").unwrap();
            let ssh_policy = SshPolicy {
                allowed_keys: vec![SshKeySpec {
                    name: "github".into(),
                    private_key: key_path.to_string_lossy().into_owned(),
                    allowed_hosts: vec!["github.com".into()],
                }],
                generate_config: true,
                generate_known_hosts: false,
            };

            let ssh_dir = home.path().join(".axis/agents/agent-ssh/ssh");
            let err = prepare_ssh_workspace_at_with_permissions(
                "agent-ssh",
                &ssh_policy,
                &ssh_dir,
                |_path, mode| {
                    if mode == 0o600 {
                        Err("key permission hook failed".into())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();

            assert!(err.contains("key permission hook failed"));
            assert!(
                !home
                    .path()
                    .join(".axis/agents/agent-ssh/ssh/id_ed25519")
                    .exists(),
                "copied private key should be removed after chmod failure"
            );
            assert_no_staging_ssh_dirs_for_policy("agent-ssh");
        });
    }

    fn with_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        crate::test_support::with_home(home, f)
    }

    fn assert_no_staging_ssh_dirs(parent: &Path) {
        let entries = std::fs::read_dir(parent)
            .unwrap_or_else(|err| panic!("read staging parent '{}': {err}", parent.display()));
        for entry in entries {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with(".ssh."),
                "staging SSH directory was not cleaned: {}",
                entry.path().display()
            );
        }
    }

    fn assert_no_staging_ssh_dirs_for_policy(policy_name: &str) {
        let staging_parent = ssh_workspace_staging_parent_checked(policy_name).unwrap();
        if staging_parent.exists() {
            assert_no_staging_ssh_dirs(&staging_parent);
        }
    }
}
