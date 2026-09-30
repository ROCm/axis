// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM filesystem isolation (Linux kernel 5.13+).
//!
//! Applies declarative read-only and read-write path allowlists to the
//! calling process using the Landlock ABI V2+ syscalls. Landlock is a
//! default-deny model: any path not explicitly granted access is blocked.

use axis_core::policy::{Compatibility, FilesystemPolicy};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::io::RawFd;
use std::path::{Component, Path, PathBuf};

// ── Landlock syscall numbers (x86_64, also used via asm-generic) ──────────

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// ── Landlock constants ────────────────────────────────────────────────────

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// Filesystem access rights (Landlock ABI V1+)
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
// ABI V2+
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
// ABI V3+
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const SANDBOX_TMPDIR_NAME: &str = ".axis-tmp";
const WORKSPACE_PLACEHOLDER: &str = "{workspace}";
const TMPDIR_PLACEHOLDER: &str = "{tmpdir}";

/// Read-only access rights.
const ACCESS_READ: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

/// Full read-write access rights.
const ACCESS_READ_WRITE: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

const ACCESS_FILE: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE;

// ── Landlock structs (must match kernel ABI) ──────────────────────────────

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: RawFd,
}

// ── Syscall wrappers ──────────────────────────────────────────────────────

unsafe fn landlock_create_ruleset(
    attr: *const LandlockRulesetAttr,
    size: usize,
    flags: u32,
) -> libc::c_long {
    unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr, size, flags) }
}

unsafe fn landlock_add_rule(
    ruleset_fd: RawFd,
    rule_type: u32,
    rule_attr: *const LandlockPathBeneathAttr,
    flags: u32,
) -> libc::c_long {
    unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            rule_type,
            rule_attr,
            flags,
        )
    }
}

unsafe fn landlock_restrict_self(ruleset_fd: RawFd, flags: u32) -> libc::c_long {
    unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, flags) }
}

#[derive(Debug)]
pub(crate) struct PreparedLandlockRuleset {
    fd: RawFd,
}

impl PreparedLandlockRuleset {
    pub(crate) fn restrict_current_process(&self) -> Result<(), i32> {
        let ret = unsafe { landlock_restrict_self(self.fd, 0) };
        if ret < 0 {
            Err(current_errno())
        } else {
            Ok(())
        }
    }
}

impl Drop for PreparedLandlockRuleset {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TmpdirSetup {
    Create,
    AlreadyPrepared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpandedPath {
    pub(crate) original: String,
    pub(crate) path: PathBuf,
    pub(crate) mount_path: PathBuf,
    pub(crate) required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpandedFilesystemPolicy {
    pub(crate) read_only: Vec<ExpandedPath>,
    pub(crate) read_write: Vec<ExpandedPath>,
    pub(crate) deny: Vec<ExpandedPath>,
    pub(crate) tmpdir_required: bool,
}

pub(crate) fn sandbox_tmpdir(workspace: &Path) -> PathBuf {
    workspace.join(SANDBOX_TMPDIR_NAME)
}

pub(crate) fn policy_uses_tmpdir(policy: &FilesystemPolicy) -> bool {
    policy
        .read_only
        .iter()
        .chain(policy.read_write.iter())
        .chain(policy.deny.iter())
        .any(|path| path.contains(TMPDIR_PLACEHOLDER))
}

pub(crate) fn create_tmpdir(workspace: &Path) -> Result<(), String> {
    let tmpdir = sandbox_tmpdir(workspace);
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&tmpdir)
        .map_err(|e| format!("cannot create exclusive tmpdir {}: {e}", tmpdir.display()))
}

pub(crate) fn cleanup_tmpdir(workspace: &Path) -> Result<(), String> {
    let tmpdir = sandbox_tmpdir(workspace);
    if tmpdir.exists() {
        std::fs::remove_dir_all(&tmpdir)
            .map_err(|e| format!("cannot remove tmpdir {}: {e}", tmpdir.display()))?;
    }
    Ok(())
}

pub(crate) fn expand_and_validate_filesystem_policy(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<ExpandedFilesystemPolicy, String> {
    if !workspace.exists() {
        return Err(format!(
            "workspace directory does not exist: {}",
            workspace.display()
        ));
    }
    let expanded = expand_filesystem_policy(policy, workspace)?;
    validate_allow_path_overlaps(&expanded)?;
    validate_workspace_read_only_overlaps(&expanded, workspace)?;
    validate_deny_paths(&expanded, workspace)?;
    Ok(expanded)
}

/// Detect the highest supported Landlock ABI version.
pub(crate) fn detect_abi_version() -> Result<i32, String> {
    let ret =
        unsafe { landlock_create_ruleset(std::ptr::null(), 0, LANDLOCK_CREATE_RULESET_VERSION) };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ENOSYS) {
            return Err("landlock not supported on this kernel".into());
        }
        if errno.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Err("landlock disabled by boot parameter".into());
        }
        return Err(format!("landlock version check failed: {errno}"));
    }
    Ok(ret as i32)
}

pub(crate) fn prepare_landlock(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<PreparedLandlockRuleset, String> {
    prepare_landlock_with_tmpdir_setup(policy, workspace, TmpdirSetup::Create)
}

pub(crate) fn prepare_landlock_with_tmpdir_setup(
    policy: &FilesystemPolicy,
    workspace: &Path,
    tmpdir_setup: TmpdirSetup,
) -> Result<PreparedLandlockRuleset, String> {
    let expanded = expand_and_validate_filesystem_policy(policy, workspace)?;

    // Detect ABI version.
    let abi = detect_abi_version()?;
    tracing::info!("landlock: ABI version {abi}");
    let handled = handled_access_for_abi(abi)?;

    if expanded.tmpdir_required {
        match tmpdir_setup {
            TmpdirSetup::Create => create_tmpdir(workspace)?,
            TmpdirSetup::AlreadyPrepared => validate_prepared_tmpdir(workspace)?,
        }
    }

    match build_ruleset(policy, workspace, &expanded, handled) {
        Ok(ruleset) => Ok(ruleset),
        Err(e) => {
            if expanded.tmpdir_required
                && let Err(cleanup) = cleanup_tmpdir(workspace)
            {
                return Err(format!("{e}; tmpdir cleanup failed: {cleanup}"));
            }
            Err(e)
        }
    }
}

fn validate_prepared_tmpdir(workspace: &Path) -> Result<(), String> {
    let tmpdir = sandbox_tmpdir(workspace);
    let metadata = std::fs::symlink_metadata(&tmpdir).map_err(|e| {
        format!(
            "prepared tmpdir {} cannot be inspected: {e}",
            tmpdir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "prepared tmpdir {} must be a real directory",
            tmpdir.display()
        ));
    }
    Ok(())
}

fn handled_access_for_abi(abi: i32) -> Result<u64, String> {
    if abi < 3 {
        return Err(format!(
            "Landlock ABI {abi} cannot enforce the AXIS filesystem contract; require Landlock ABI >= 3"
        ));
    }
    Ok(ACCESS_READ_WRITE)
}

fn build_ruleset(
    policy: &FilesystemPolicy,
    workspace: &Path,
    expanded: &ExpandedFilesystemPolicy,
    handled: u64,
) -> Result<PreparedLandlockRuleset, String> {
    // 1. Create ruleset.
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
    };
    let ruleset_fd =
        unsafe { landlock_create_ruleset(&attr, std::mem::size_of::<LandlockRulesetAttr>(), 0) };
    if ruleset_fd < 0 {
        return Err(format!(
            "landlock_create_ruleset failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ruleset = PreparedLandlockRuleset {
        fd: ruleset_fd as RawFd,
    };
    set_close_on_exec(ruleset.fd)?;

    // 2. Add rules for read-only paths.
    let read_access = ACCESS_READ & handled;
    for path in &expanded.read_only {
        add_policy_path_rule(
            ruleset.fd,
            path,
            read_access,
            &policy.compatibility,
            "read-only",
        )?;
    }

    // 3. Add rules for read-write paths (including workspace).
    let write_access = handled; // all handled rights
    for path in &expanded.read_write {
        add_policy_path_rule(
            ruleset.fd,
            path,
            write_access,
            &policy.compatibility,
            "read-write",
        )?;
    }

    // Add the workspace grant. Default is read-write (the agent's cwd); an opt-in
    // `workspace_read_only` policy grants it READ-ONLY instead, so a read-only
    // lease can read its code without modifying it. A nested `{tmpdir}` read-write
    // rule still applies (Landlock unions the more-specific grant), leaving a
    // writable scratch under the read-only workspace.
    let workspace = normalize_existing_or_absolute_path(workspace)?;
    let ws_str = workspace.to_string_lossy().to_string();
    let (ws_access, ws_label) = if policy.workspace_read_only {
        (read_access, "workspace (read-only)")
    } else {
        (write_access, "workspace")
    };
    add_required_path_rule(ruleset.fd, &ws_str, ws_access, ws_label)?;

    let ro = policy.read_only.len();
    let rw = policy.read_write.len() + if policy.workspace_read_only { 0 } else { 1 };
    tracing::info!("landlock: prepared ruleset — {ro} read-only, {rw} read-write paths");
    Ok(ruleset)
}

/// Apply Landlock filesystem restrictions to the current process.
pub fn apply_landlock(policy: &FilesystemPolicy, workspace: &Path) -> Result<(), String> {
    let ruleset = prepare_landlock(policy, workspace)?;
    ruleset.restrict_current_process().map_err(|errno| {
        format!(
            "landlock_restrict_self failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;
    tracing::info!("landlock: applied");
    Ok(())
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn add_policy_path_rule(
    ruleset_fd: RawFd,
    path: &ExpandedPath,
    access: u64,
    compat: &Compatibility,
    label: &str,
) -> Result<(), String> {
    let path_str = path.path.to_string_lossy();
    let effective_compat = if path.required {
        Compatibility::HardRequirement
    } else {
        compat.clone()
    };

    match add_path_rule(ruleset_fd, &path_str, access, &effective_compat) {
        Ok(()) => Ok(()),
        Err(e) => match effective_compat {
            Compatibility::BestEffort => {
                tracing::warn!(
                    "landlock: skipping {label} path '{}' expanded to '{}': {e}",
                    path.original,
                    path.path.display()
                );
                Ok(())
            }
            Compatibility::HardRequirement => Err(format!(
                "landlock: hard-required {label} path '{}' expanded to '{}' cannot be added: {e}",
                path.original,
                path.path.display()
            )),
        },
    }
}

fn add_required_path_rule(
    ruleset_fd: RawFd,
    path: &str,
    access: u64,
    label: &str,
) -> Result<(), String> {
    add_path_rule(ruleset_fd, path, access, &Compatibility::HardRequirement)
        .map_err(|e| format!("landlock: required {label} path '{path}' cannot be added: {e}"))
}

/// Add a path-beneath rule to the ruleset.
fn add_path_rule(
    ruleset_fd: RawFd,
    path: &str,
    access: u64,
    compat: &Compatibility,
) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path).map_err(|e| format!("invalid path '{path}': {e}"))?;

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match compat {
            Compatibility::BestEffort => Err(format!(
                "cannot open '{path}': {err} (skipped, best-effort)"
            )),
            Compatibility::HardRequirement => {
                Err(format!("cannot open '{path}': {err} (hard requirement)"))
            }
        };
    }

    let access = match access_for_open_path(fd, access) {
        Ok(access) => access,
        Err(err) => {
            unsafe { libc::close(fd) };
            return Err(format!("cannot inspect '{path}': {err}"));
        }
    };

    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe { landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) };

    unsafe { libc::close(fd) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        // EINVAL can mean the access rights aren't supported — best-effort skip.
        if err.raw_os_error() == Some(libc::EINVAL) {
            return Err(format!("unsupported access for '{path}': {err}"));
        }
        return Err(format!("landlock_add_rule for '{path}' failed: {err}"));
    }

    Ok(())
}

fn access_for_open_path(fd: RawFd, requested: u64) -> Result<u64, std::io::Error> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        Ok(requested)
    } else {
        Ok(requested & ACCESS_FILE)
    }
}

fn set_close_on_exec(fd: RawFd) -> Result<(), String> {
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if ret < 0 {
        Err(format!(
            "fcntl(FD_CLOEXEC) failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn expand_filesystem_policy(
    policy: &FilesystemPolicy,
    workspace: &Path,
) -> Result<ExpandedFilesystemPolicy, String> {
    let read_only = expand_policy_paths(&policy.read_only, workspace)?;
    let read_write = expand_policy_paths(&policy.read_write, workspace)?;
    let deny = expand_policy_paths(&policy.deny, workspace)?;
    let tmpdir_required = read_only
        .iter()
        .chain(read_write.iter())
        .chain(deny.iter())
        .any(|path| path.required);

    Ok(ExpandedFilesystemPolicy {
        read_only,
        read_write,
        deny,
        tmpdir_required,
    })
}

fn expand_policy_paths(paths: &[String], workspace: &Path) -> Result<Vec<ExpandedPath>, String> {
    paths
        .iter()
        .map(|path| expand_policy_path(path, workspace))
        .collect()
}

fn expand_policy_path(path: &str, workspace: &Path) -> Result<ExpandedPath, String> {
    let required = path.contains(TMPDIR_PLACEHOLDER);
    let mount_path = expand_mount_path(path, workspace)?;
    let expanded = normalize_existing_or_absolute_path(&mount_path)?;
    Ok(ExpandedPath {
        original: path.to_string(),
        path: expanded,
        mount_path,
        required,
    })
}

fn validate_deny_paths(policy: &ExpandedFilesystemPolicy, workspace: &Path) -> Result<(), String> {
    let workspace = normalize_existing_or_absolute_path(workspace)?;
    for deny in &policy.deny {
        if path_contains_or_equal(&workspace, &deny.path)
            || path_contains_or_equal(&deny.path, &workspace)
        {
            return Err(format!(
                "deny path '{}' expanded to '{}' conflicts with the sandbox workspace '{}'",
                deny.original,
                deny.path.display(),
                workspace.display()
            ));
        }

        for allow in policy
            .read_only
            .iter()
            .map(|path| ("read-only", path))
            .chain(policy.read_write.iter().map(|path| ("read-write", path)))
        {
            let (label, allowed) = allow;
            if path_contains_or_equal(&allowed.path, &deny.path) {
                return Err(format!(
                    "deny path '{}' expanded to '{}' is under allowed {label} path '{}' expanded to '{}'; Landlock cannot subtract deny paths from broad allows",
                    deny.original,
                    deny.path.display(),
                    allowed.original,
                    allowed.path.display()
                ));
            }
            if path_contains_or_equal(&deny.path, &allowed.path) {
                return Err(format!(
                    "deny path '{}' expanded to '{}' contains allowed {label} path '{}' expanded to '{}'; this filesystem policy is ambiguous under Landlock",
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

fn validate_allow_path_overlaps(policy: &ExpandedFilesystemPolicy) -> Result<(), String> {
    for read_only in &policy.read_only {
        for read_write in &policy.read_write {
            if path_contains_or_equal(&read_write.path, &read_only.path) {
                return Err(format!(
                    "read-only path '{}' expanded to '{}' is under read-write path '{}' expanded to '{}'; Landlock unions overlapping allow rules",
                    read_only.original,
                    read_only.path.display(),
                    read_write.original,
                    read_write.path.display()
                ));
            }
            if path_contains_or_equal(&read_only.path, &read_write.path) {
                return Err(format!(
                    "read-write path '{}' expanded to '{}' is under read-only path '{}' expanded to '{}'; overlapping allow rules would make the policy ambiguous",
                    read_write.original,
                    read_write.path.display(),
                    read_only.original,
                    read_only.path.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_workspace_read_only_overlaps(
    policy: &ExpandedFilesystemPolicy,
    workspace: &Path,
) -> Result<(), String> {
    let workspace = normalize_existing_or_absolute_path(workspace)?;
    for read_only in &policy.read_only {
        if path_contains_or_equal(&workspace, &read_only.path) {
            return Err(format!(
                "read-only path '{}' expanded to '{}' is under the implicit read-write workspace '{}'",
                read_only.original,
                read_only.path.display(),
                workspace.display()
            ));
        }
        if path_contains_or_equal(&read_only.path, &workspace) {
            return Err(format!(
                "read-only path '{}' expanded to '{}' contains the implicit read-write workspace '{}'",
                read_only.original,
                read_only.path.display(),
                workspace.display()
            ));
        }
    }
    Ok(())
}

fn path_contains_or_equal(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

/// Expand Linux policy paths to absolute sandbox host paths.
#[cfg(test)]
fn expand_path(path: &str, workspace: &Path) -> Result<PathBuf, String> {
    expand_path_with_home(path, workspace, None)
}

#[cfg(test)]
fn expand_path_with_home(
    path: &str,
    workspace: &Path,
    home_override: Option<&Path>,
) -> Result<PathBuf, String> {
    let mount_path = expand_mount_path_with_home(path, workspace, home_override)?;
    normalize_existing_or_absolute_path(&mount_path)
}

fn expand_mount_path(path: &str, workspace: &Path) -> Result<PathBuf, String> {
    expand_mount_path_with_home(path, workspace, None)
}

fn expand_mount_path_with_home(
    path: &str,
    workspace: &Path,
    home_override: Option<&Path>,
) -> Result<PathBuf, String> {
    let mut expanded = if path == "~" {
        home_path(home_override)?.to_string_lossy().into_owned()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home_path(home_override)?
            .join(rest)
            .to_string_lossy()
            .into_owned()
    } else if path.starts_with('~') {
        return Err(format!(
            "unsupported home path '{path}': only '~' and '~/' are supported"
        ));
    } else {
        path.to_string()
    };

    expanded = expanded.replace(WORKSPACE_PLACEHOLDER, &workspace.to_string_lossy());
    expanded = expanded.replace(
        TMPDIR_PLACEHOLDER,
        &sandbox_tmpdir(workspace).to_string_lossy(),
    );

    let expanded = PathBuf::from(expanded);
    normalize_absolute_path(&expanded)
}

fn home_path(home_override: Option<&Path>) -> Result<PathBuf, String> {
    let home = match home_override {
        Some(home) => home.to_path_buf(),
        None => std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set for '~' path expansion".to_string())?,
    };
    if !home.is_absolute() {
        return Err(format!("HOME path is not absolute: {}", home.display()));
    }
    Ok(home)
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
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {
                return Err(format!(
                    "linux policy path '{}' must not contain a non-linux prefix",
                    path.display()
                ));
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        Ok(PathBuf::from("/"))
    } else {
        Ok(normalized)
    }
}

fn normalize_existing_or_absolute_path(path: &Path) -> Result<PathBuf, String> {
    let normalized = normalize_absolute_path(path)?;
    if let Ok(canonical) = std::fs::canonicalize(&normalized) {
        return normalize_absolute_path(&canonical);
    }

    let mut existing_prefix = PathBuf::from("/");
    let mut probe = PathBuf::from("/");
    let mut missing_suffix = Vec::new();
    let mut missing = false;

    for component in normalized.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) if !missing => {
                probe.push(part);
                if probe.exists() {
                    existing_prefix = probe.clone();
                } else {
                    missing = true;
                    missing_suffix.push(part.to_os_string());
                }
            }
            Component::Normal(part) => missing_suffix.push(part.to_os_string()),
            Component::CurDir | Component::ParentDir => {}
            Component::Prefix(_) => {
                return Err(format!(
                    "linux policy path '{}' must not contain a non-linux prefix",
                    path.display()
                ));
            }
        }
    }

    let mut resolved = std::fs::canonicalize(&existing_prefix).unwrap_or(existing_prefix);
    for part in missing_suffix {
        resolved.push(part);
    }
    normalize_absolute_path(&resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn detect_landlock_abi() {
        match detect_abi_version() {
            Ok(v) => {
                assert!(v >= 1, "expected ABI v1+, got {v}");
                eprintln!("Landlock ABI version: {v}");
            }
            Err(e) => {
                eprintln!("Landlock not available: {e} (test skipped)");
            }
        }
    }

    fn contract_landlock_available() -> bool {
        match detect_abi_version() {
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

    #[test]
    fn handled_access_requires_abi_three_for_contract_semantics() {
        let err = handled_access_for_abi(2).unwrap_err();
        assert!(err.contains("require Landlock ABI >= 3"));
        assert_eq!(handled_access_for_abi(3).unwrap(), ACCESS_READ_WRITE);
    }

    #[test]
    fn file_rules_exclude_directory_only_access_rights() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("file");
        std::fs::write(&file_path, b"data").unwrap();
        let directory = std::fs::File::open(dir.path()).unwrap();
        let file = std::fs::File::open(&file_path).unwrap();
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();

        assert_eq!(
            access_for_open_path(directory.as_raw_fd(), ACCESS_READ_WRITE).unwrap(),
            ACCESS_READ_WRITE
        );
        assert_eq!(
            access_for_open_path(file.as_raw_fd(), ACCESS_READ_WRITE).unwrap(),
            ACCESS_FILE
        );
        assert_eq!(
            access_for_open_path(null.as_raw_fd(), ACCESS_READ_WRITE).unwrap(),
            ACCESS_FILE
        );
        assert_eq!(
            access_for_open_path(file.as_raw_fd(), ACCESS_READ).unwrap(),
            ACCESS_READ & ACCESS_FILE
        );
        assert_eq!(
            access_for_open_path(-1, ACCESS_READ_WRITE)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn expand_path_supports_absolute_workspace_tmpdir_and_home() {
        let ws = Path::new("/home/user/sandbox");
        assert_eq!(
            expand_path("/usr/bin", ws).unwrap(),
            PathBuf::from("/usr/bin")
        );
        assert_eq!(
            expand_path("{workspace}/data", ws).unwrap(),
            PathBuf::from("/home/user/sandbox/data")
        );
        assert_eq!(
            expand_path("{tmpdir}/axis", ws).unwrap(),
            PathBuf::from("/home/user/sandbox/.axis-tmp/axis")
        );
        assert_eq!(
            expand_path_with_home("~/keys", ws, Some(Path::new("/home/user"))).unwrap(),
            PathBuf::from("/home/user/keys")
        );
    }

    #[test]
    fn expand_path_rejects_relative_and_unsupported_home_forms() {
        let ws = Path::new("/home/user/sandbox");

        let relative = expand_path("relative/path", ws).unwrap_err();
        assert!(relative.contains("must be absolute"));

        let unsupported_home =
            expand_path_with_home("~other/.ssh", ws, Some(Path::new("/home/user"))).unwrap_err();
        assert!(unsupported_home.contains("unsupported home path"));
    }

    #[test]
    fn expand_path_normalizes_dot_and_parent_components() {
        let ws = Path::new("/home/user/sandbox");

        assert_eq!(
            expand_path("{workspace}/a/../b/./c", ws).unwrap(),
            PathBuf::from("/home/user/sandbox/b/c")
        );
    }

    #[test]
    fn expand_path_canonicalizes_existing_symlink_targets() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(
            expand_path(&link.to_string_lossy(), dir.path()).unwrap(),
            target
        );
    }

    #[test]
    fn expanded_policy_preserves_mount_alias_for_symlink_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let policy = FilesystemPolicy {
            read_only: vec![link.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let expanded = expand_filesystem_policy(&policy, dir.path()).unwrap();

        assert_eq!(expanded.read_only[0].path, target);
        assert_eq!(expanded.read_only[0].mount_path, link);
    }

    #[test]
    fn expand_path_canonicalizes_existing_symlink_parent_for_missing_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(
            expand_path(&link.join("future").to_string_lossy(), dir.path()).unwrap(),
            target.join("future")
        );
    }

    #[test]
    fn tmpdir_placeholder_marks_path_required() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_write: vec!["{tmpdir}".into()],
            ..Default::default()
        };

        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        assert!(expanded.tmpdir_required);
        assert!(expanded.read_write[0].required);
        assert_eq!(
            expanded.read_write[0].path,
            PathBuf::from("/home/user/sandbox/.axis-tmp")
        );
    }

    #[test]
    fn deny_outside_allows_is_valid() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["/usr".into()],
            deny: vec!["/home/user/.ssh".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        validate_deny_paths(&expanded, ws).unwrap();
    }

    #[test]
    fn read_write_parent_cannot_widen_read_only_child() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["/home/user/secrets".into()],
            read_write: vec!["/home/user".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_allow_path_overlaps(&expanded).unwrap_err();

        assert!(err.contains("is under read-write path"));
    }

    #[test]
    fn read_write_child_under_read_only_parent_is_rejected_as_ambiguous() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["/home/user".into()],
            read_write: vec!["/home/user/cache".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_allow_path_overlaps(&expanded).unwrap_err();

        assert!(err.contains("overlapping allow rules"));
    }

    #[test]
    fn read_only_child_under_implicit_workspace_is_rejected() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["{workspace}/secrets".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_workspace_read_only_overlaps(&expanded, ws).unwrap_err();

        assert!(err.contains("implicit read-write workspace"));
    }

    #[test]
    fn read_only_parent_containing_implicit_workspace_is_rejected() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["/home/user".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_workspace_read_only_overlaps(&expanded, ws).unwrap_err();

        assert!(err.contains("contains the implicit read-write workspace"));
    }

    #[test]
    fn deny_under_allowed_path_is_rejected() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_only: vec!["/usr".into()],
            deny: vec!["/usr/share/secret".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_deny_paths(&expanded, ws).unwrap_err();

        assert!(err.contains("under allowed read-only path"));
    }

    #[test]
    fn deny_under_symlink_resolved_allow_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let target = dir.path().join("home-target");
        let link = dir.path().join("cache-link");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(target.join(".ssh")).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let policy = FilesystemPolicy {
            read_write: vec![link.to_string_lossy().into()],
            deny: vec![target.join(".ssh").to_string_lossy().into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, &workspace).unwrap();

        let err = validate_deny_paths(&expanded, &workspace).unwrap_err();

        assert!(err.contains("under allowed read-write path"));
    }

    #[test]
    fn deny_containing_allowed_path_is_rejected() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            read_write: vec!["/opt/project".into()],
            deny: vec!["/opt".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_deny_paths(&expanded, ws).unwrap_err();

        assert!(err.contains("contains allowed read-write path"));
    }

    #[test]
    fn deny_under_symlink_resolved_workspace_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_target = dir.path().join("workspace-target");
        let workspace_link = dir.path().join("workspace-link");
        std::fs::create_dir_all(workspace_target.join("secret")).unwrap();
        std::os::unix::fs::symlink(&workspace_target, &workspace_link).unwrap();
        let policy = FilesystemPolicy {
            deny: vec![workspace_target.join("secret").to_string_lossy().into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, &workspace_link).unwrap();

        let err = validate_deny_paths(&expanded, &workspace_link).unwrap_err();

        assert!(err.contains("conflicts with the sandbox workspace"));
    }

    #[test]
    fn deny_under_symlink_resolved_workspace_with_missing_leaf_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_target = dir.path().join("workspace-target");
        let workspace_link = dir.path().join("workspace-link");
        std::fs::create_dir_all(&workspace_target).unwrap();
        std::os::unix::fs::symlink(&workspace_target, &workspace_link).unwrap();
        let policy = FilesystemPolicy {
            deny: vec![
                workspace_link
                    .join("future-secret")
                    .to_string_lossy()
                    .into(),
            ],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, &workspace_link).unwrap();

        let err = validate_deny_paths(&expanded, &workspace_link).unwrap_err();

        assert!(err.contains("conflicts with the sandbox workspace"));
    }

    #[test]
    fn deny_workspace_path_is_rejected() {
        let ws = Path::new("/home/user/sandbox");
        let policy = FilesystemPolicy {
            deny: vec!["{workspace}/secret".into()],
            ..Default::default()
        };
        let expanded = expand_filesystem_policy(&policy, ws).unwrap();

        let err = validate_deny_paths(&expanded, ws).unwrap_err();

        assert!(err.contains("conflicts with the sandbox workspace"));
    }

    #[test]
    fn cleanup_tmpdir_removes_sandbox_owned_tmpdir() {
        let dir = tempfile::tempdir().unwrap();
        let tmpdir = sandbox_tmpdir(dir.path());
        create_tmpdir(dir.path()).unwrap();
        std::fs::write(tmpdir.join("scratch"), b"scratch").unwrap();

        cleanup_tmpdir(dir.path()).unwrap();

        assert!(!tmpdir.exists());
        cleanup_tmpdir(dir.path()).unwrap();
    }

    #[test]
    fn create_tmpdir_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tmpdir = sandbox_tmpdir(dir.path());

        create_tmpdir(dir.path()).unwrap();

        let mode = std::fs::metadata(&tmpdir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn create_tmpdir_rejects_preexisting_path() {
        let dir = tempfile::tempdir().unwrap();
        let tmpdir = sandbox_tmpdir(dir.path());
        std::fs::create_dir_all(&tmpdir).unwrap();

        let err = create_tmpdir(dir.path()).unwrap_err();

        assert!(err.contains("cannot create exclusive tmpdir"));
    }

    #[test]
    fn policy_uses_tmpdir_detects_all_filesystem_sections() {
        for policy in [
            FilesystemPolicy {
                read_only: vec!["{tmpdir}/ro".into()],
                ..Default::default()
            },
            FilesystemPolicy {
                read_write: vec!["{tmpdir}/rw".into()],
                ..Default::default()
            },
            FilesystemPolicy {
                deny: vec!["{tmpdir}/deny".into()],
                ..Default::default()
            },
        ] {
            assert!(policy_uses_tmpdir(&policy));
        }
        assert!(!policy_uses_tmpdir(&FilesystemPolicy::default()));
    }

    #[test]
    fn apply_landlock_with_valid_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_only: vec!["/usr".into(), "/lib".into()],
            read_write: vec![dir.path().to_string_lossy().into()],
            deny: vec!["~/.ssh".into()],
            ..Default::default()
        };
        // This may fail on kernels without Landlock — that's OK in CI.
        // We only call this from pre_exec in real sandboxes.
        let result = apply_landlock(&policy, dir.path());
        match result {
            Ok(()) => eprintln!("Landlock applied successfully"),
            Err(e) => eprintln!("Landlock not applied (expected in some CI): {e}"),
        }
    }

    #[test]
    fn hard_requirement_prepare_fails_when_required_path_missing() {
        if !contract_landlock_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_only: vec!["/axis/definitely/missing/landlock/path".into()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let err = prepare_landlock(&policy, dir.path()).unwrap_err();

        assert!(err.contains("hard-required read-only path"));
    }

    #[test]
    fn best_effort_prepare_skips_missing_policy_path() {
        if !contract_landlock_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_only: vec!["/axis/definitely/missing/landlock/path".into()],
            compatibility: Compatibility::BestEffort,
            ..Default::default()
        };

        let ruleset = prepare_landlock(&policy, dir.path()).unwrap();
        drop(ruleset);
    }

    #[test]
    fn hard_requirement_prepare_accepts_file_and_character_device_rules() {
        if !contract_landlock_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let read_only = dir.path().join("read-only");
        let read_write = dir.path().join("read-write");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(&read_only, b"read-only").unwrap();
        std::fs::write(&read_write, b"read-write").unwrap();
        let policy = FilesystemPolicy {
            read_only: vec![read_only.to_string_lossy().into_owned()],
            read_write: vec![
                read_write.to_string_lossy().into_owned(),
                "/dev/null".into(),
            ],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let ruleset = prepare_landlock(&policy, &workspace).unwrap();
        drop(ruleset);
    }

    #[test]
    fn prepare_landlock_creates_sandbox_tmpdir_when_placeholder_is_used() {
        if !contract_landlock_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_write: vec!["{tmpdir}".into()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let ruleset = prepare_landlock(&policy, dir.path()).unwrap();
        drop(ruleset);

        assert!(sandbox_tmpdir(dir.path()).is_dir());
    }

    #[test]
    fn prepare_landlock_cleans_tmpdir_after_later_rule_failure() {
        if !contract_landlock_available() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_write: vec![
                "{tmpdir}".into(),
                "/axis/definitely/missing/landlock/path".into(),
            ],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let err = prepare_landlock(&policy, dir.path()).unwrap_err();

        assert!(err.contains("hard-required read-write path"));
        assert!(!sandbox_tmpdir(dir.path()).exists());
    }
}
