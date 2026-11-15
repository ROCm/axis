// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux UID/GID identity handling.

use super::landlock;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Component, Path, PathBuf};

const SANDBOX_TMPDIR_NAME: &str = ".axis-tmp";
const CAP_CHOWN: u32 = 0;
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_FOWNER: u32 = 3;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;

// run_as_user chowns and chmods the workspace and tmpdir to the target
// identity, then reopens them; a non-root caller needs all five.
const fn identity_switch_capabilities() -> u64 {
    (1_u64 << CAP_CHOWN)
        | (1_u64 << CAP_DAC_OVERRIDE)
        | (1_u64 << CAP_FOWNER)
        | (1_u64 << CAP_SETGID)
        | (1_u64 << CAP_SETUID)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedIdentity {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserRecord {
    pub uid: u32,
    pub gid: u32,
    pub home: Option<PathBuf>,
}

pub(crate) trait UserLookup {
    fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>, String>;
}

pub(crate) struct SystemUserLookup;

impl UserLookup for SystemUserLookup {
    fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>, String> {
        nix::unistd::User::from_name(username)
            .map_err(|e| e.to_string())
            .map(|user| {
                user.map(|user| UserRecord {
                    uid: user.uid.as_raw(),
                    gid: user.gid.as_raw(),
                    home: Some(user.dir),
                })
            })
    }
}

pub(crate) fn resolve_run_as_user(
    username: &str,
    lookup: &dyn UserLookup,
) -> Result<ResolvedIdentity, String> {
    resolve_run_as_user_with_process_ids(username, lookup, current_process_ids()?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIds {
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    effective_capabilities: u64,
}

impl ProcessIds {
    fn contains_uid(self, uid: u32) -> bool {
        [self.real_uid, self.effective_uid, self.saved_uid].contains(&uid)
    }

    fn contains_gid(self, gid: u32) -> bool {
        [self.real_gid, self.effective_gid, self.saved_gid].contains(&gid)
    }
}

fn resolve_run_as_user_with_process_ids(
    username: &str,
    lookup: &dyn UserLookup,
    process_ids: ProcessIds,
) -> Result<ResolvedIdentity, String> {
    if username.trim().is_empty() {
        return Err("run_as_user must not be empty".into());
    }

    let user = lookup
        .lookup_user(username)
        .map_err(|e| format!("cannot resolve run_as_user '{username}': {e}"))?
        .ok_or_else(|| format!("run_as_user '{username}' does not exist"))?;

    if user.uid == 0 || user.gid == 0 {
        return Err(format!(
            "run_as_user '{username}' must not resolve to UID or GID 0"
        ));
    }

    if process_ids.contains_uid(user.uid) {
        return Err(format!(
            "run_as_user '{username}' matches the caller UID state; AXIS requires a dedicated target UID"
        ));
    }

    if process_ids.contains_gid(user.gid) {
        return Err(format!(
            "run_as_user '{username}' matches the caller GID state; AXIS requires a dedicated target GID"
        ));
    }

    let required_capabilities = identity_switch_capabilities();
    if process_ids.effective_uid != 0
        && process_ids.effective_capabilities & required_capabilities != required_capabilities
    {
        return Err(format!(
            "run_as_user '{username}' requires root, or CAP_SETUID, CAP_SETGID, CAP_CHOWN, CAP_FOWNER and CAP_DAC_OVERRIDE; current effective UID is {}",
            process_ids.effective_uid
        ));
    }

    Ok(ResolvedIdentity {
        username: username.to_string(),
        uid: user.uid,
        gid: user.gid,
        home: user.home,
    })
}

#[cfg(test)]
pub(crate) fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
pub(crate) fn current_egid() -> u32 {
    unsafe { libc::getegid() }
}

fn current_process_ids() -> Result<ProcessIds, String> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    let uid_ret = unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) };
    if uid_ret < 0 {
        return Err(format!(
            "cannot inspect process UID state: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    let gid_ret = unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) };
    if gid_ret < 0 {
        return Err(format!(
            "cannot inspect process GID state: {}",
            std::io::Error::last_os_error()
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("cannot inspect process capabilities: {error}"))?;
    let effective_capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or_else(|| "cannot inspect process capabilities: CapEff is missing".to_string())
        .and_then(|value| {
            u64::from_str_radix(value, 16)
                .map_err(|error| format!("cannot inspect process capabilities: {error}"))
        })?;

    Ok(ProcessIds {
        real_uid,
        effective_uid,
        saved_uid,
        real_gid,
        effective_gid,
        saved_gid,
        effective_capabilities,
    })
}

pub(crate) fn prepare_workspace_for_identity(
    workspace: &Path,
    identity: &ResolvedIdentity,
) -> Result<(), String> {
    ensure_owned_private_directory(workspace, identity, "workspace")
}

pub(crate) fn create_tmpdir_for_identity(
    workspace: &Path,
    identity: &ResolvedIdentity,
) -> Result<(), String> {
    let workspace_fd = open_directory_tree_no_symlinks(workspace).map_err(|e| {
        format!(
            "workspace '{}' cannot be opened safely for tmpdir setup: {e}",
            workspace.display()
        )
    })?;
    let name = CString::new(SANDBOX_TMPDIR_NAME).expect("static tmpdir name has no NUL");
    let ret = unsafe { libc::mkdirat(workspace_fd.raw(), name.as_ptr(), 0o700) };
    if ret < 0 {
        return Err(format!(
            "cannot create exclusive tmpdir '{}': {}",
            landlock::sandbox_tmpdir(workspace).display(),
            std::io::Error::last_os_error()
        ));
    }

    let result = (|| {
        let tmpdir_fd = openat_directory_no_follow(workspace_fd.raw(), &name)?;
        ensure_owned_private_directory_fd(
            tmpdir_fd.raw(),
            &landlock::sandbox_tmpdir(workspace),
            identity,
            "tmpdir",
        )
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(workspace_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
    result
}

fn ensure_owned_private_directory(
    path: &Path,
    identity: &ResolvedIdentity,
    label: &str,
) -> Result<(), String> {
    let fd = open_directory_tree_no_symlinks(path).map_err(|e| {
        format!(
            "{label} '{}' cannot be opened safely for run_as_user setup: {e}",
            path.display()
        )
    })?;
    ensure_owned_private_directory_fd(fd.raw(), path, identity, label)
}

fn ensure_owned_private_directory_fd(
    fd: RawFd,
    path: &Path,
    identity: &ResolvedIdentity,
    label: &str,
) -> Result<(), String> {
    let metadata = fstat_directory(fd, path, label)?;
    if !is_directory_mode(metadata.st_mode) {
        return Err(format!(
            "{label} '{}' must be a directory for run_as_user setup",
            path.display()
        ));
    }

    if metadata.st_uid != identity.uid || metadata.st_gid != identity.gid {
        fchown_fd(fd, identity.uid, identity.gid).map_err(|e| {
            format!(
                "{label} '{}' cannot be assigned to run_as_user '{}': {e}",
                path.display(),
                identity.username
            )
        })?;
    }

    fchmod_fd(fd, 0o700).map_err(|e| {
        format!(
            "{label} '{}' cannot be restricted for run_as_user '{}': {e}",
            path.display(),
            identity.username
        )
    })?;

    let updated = fstat_directory(fd, path, label)?;
    if updated.st_uid != identity.uid || updated.st_gid != identity.gid {
        return Err(format!(
            "{label} '{}' is owned by {}:{}, expected {}:{} for run_as_user '{}'",
            path.display(),
            updated.st_uid,
            updated.st_gid,
            identity.uid,
            identity.gid,
            identity.username
        ));
    }
    if updated.st_mode & 0o777 != 0o700 {
        return Err(format!(
            "{label} '{}' mode is {:o}, expected 700 for run_as_user '{}'",
            path.display(),
            updated.st_mode & 0o777,
            identity.username
        ));
    }

    Ok(())
}

struct DirectoryFd(RawFd);

impl DirectoryFd {
    fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for DirectoryFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn open_directory_tree_no_symlinks(path: &Path) -> Result<DirectoryFd, String> {
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }

    let root = CString::new("/").expect("root path has no NUL");
    let mut fd = open_directory_no_follow(&root)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes()).map_err(|e| {
                    format!(
                        "path component in '{}' contains an interior NUL: {e}",
                        path.display()
                    )
                })?;
                fd = openat_directory_no_follow(fd.raw(), &name)?;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "path '{}' must not contain parent directory components",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "linux path '{}' must not contain a non-linux prefix",
                    path.display()
                ));
            }
        }
    }
    Ok(fd)
}

fn open_directory_no_follow(path: &CString) -> Result<DirectoryFd, String> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(DirectoryFd(fd))
    }
}

fn openat_directory_no_follow(parent_fd: RawFd, name: &CString) -> Result<DirectoryFd, String> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(DirectoryFd(fd))
    }
}

fn fstat_directory(fd: RawFd, path: &Path, label: &str) -> Result<libc::stat, String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let ret = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if ret < 0 {
        Err(format!(
            "{label} '{}' cannot be inspected: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

fn is_directory_mode(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}

fn fchown_fd(fd: RawFd, uid: u32, gid: u32) -> Result<(), String> {
    let ret = unsafe { libc::fchown(fd, uid, gid) };
    if ret < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn fchmod_fd(fd: RawFd, mode: libc::mode_t) -> Result<(), String> {
    let ret = unsafe { libc::fchmod(fd, mode) };
    if ret < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct FakeLookup {
        users: HashMap<String, UserRecord>,
        error: Option<String>,
    }

    impl UserLookup for FakeLookup {
        fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>, String> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.users.get(username).cloned())
        }
    }

    fn fake_lookup(users: &[(&str, u32, u32)]) -> FakeLookup {
        FakeLookup {
            users: users
                .iter()
                .map(|(name, uid, gid)| {
                    (
                        (*name).to_string(),
                        UserRecord {
                            uid: *uid,
                            gid: *gid,
                            home: Some(PathBuf::from(format!("/home/{name}"))),
                        },
                    )
                })
                .collect(),
            error: None,
        }
    }

    fn identity(uid: u32, gid: u32) -> ResolvedIdentity {
        ResolvedIdentity {
            username: "sandbox-user".into(),
            uid,
            gid,
            home: Some(PathBuf::from("/home/sandbox-user")),
        }
    }

    fn root_process_ids() -> ProcessIds {
        ProcessIds {
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            effective_capabilities: 0,
        }
    }

    fn setuid_root_process_ids(real_uid: u32, real_gid: u32) -> ProcessIds {
        ProcessIds {
            real_uid,
            effective_uid: 0,
            saved_uid: 0,
            real_gid,
            effective_gid: 0,
            saved_gid: 0,
            effective_capabilities: 0,
        }
    }

    #[test]
    fn resolve_run_as_user_rejects_missing_lookup_and_root_records() {
        let lookup = fake_lookup(&[("root-alias", 0, 1), ("root-group", 1000, 0)]);

        let missing = resolve_run_as_user_with_process_ids("missing", &lookup, root_process_ids())
            .unwrap_err();
        assert!(missing.contains("does not exist"));

        let root_alias =
            resolve_run_as_user_with_process_ids("root-alias", &lookup, root_process_ids())
                .unwrap_err();
        assert!(root_alias.contains("UID or GID 0"));

        let root_group =
            resolve_run_as_user_with_process_ids("root-group", &lookup, root_process_ids())
                .unwrap_err();
        assert!(root_group.contains("UID or GID 0"));
    }

    #[test]
    fn resolve_run_as_user_rejects_caller_uid_gid_state_and_unprivileged_switch() {
        let lookup = fake_lookup(&[("sandbox-user", 1000, 1000), ("other", 2000, 2000)]);

        let same_uid = resolve_run_as_user_with_process_ids(
            "sandbox-user",
            &lookup,
            setuid_root_process_ids(1000, 3000),
        )
        .unwrap_err();
        assert!(same_uid.contains("caller UID state"));

        let same_gid = resolve_run_as_user_with_process_ids(
            "sandbox-user",
            &lookup,
            setuid_root_process_ids(3000, 1000),
        )
        .unwrap_err();
        assert!(same_gid.contains("caller GID state"));

        let unprivileged = resolve_run_as_user_with_process_ids(
            "other",
            &lookup,
            ProcessIds {
                real_uid: 1000,
                effective_uid: 1000,
                saved_uid: 1000,
                real_gid: 1000,
                effective_gid: 1000,
                saved_gid: 1000,
                effective_capabilities: 0,
            },
        )
        .unwrap_err();
        assert!(unprivileged.contains("requires root"));
    }

    #[test]
    fn resolve_run_as_user_rejects_each_saved_and_effective_caller_id_match() {
        let lookup = fake_lookup(&[("sandbox-user", 1000, 1000)]);

        let cases = [
            (
                "effective uid",
                ProcessIds {
                    real_uid: 2000,
                    effective_uid: 1000,
                    saved_uid: 3000,
                    real_gid: 2000,
                    effective_gid: 0,
                    saved_gid: 3000,
                    effective_capabilities: 0,
                },
                "caller UID state",
            ),
            (
                "saved uid",
                ProcessIds {
                    real_uid: 2000,
                    effective_uid: 0,
                    saved_uid: 1000,
                    real_gid: 2000,
                    effective_gid: 0,
                    saved_gid: 3000,
                    effective_capabilities: 0,
                },
                "caller UID state",
            ),
            (
                "effective gid",
                ProcessIds {
                    real_uid: 2000,
                    effective_uid: 0,
                    saved_uid: 3000,
                    real_gid: 2000,
                    effective_gid: 1000,
                    saved_gid: 3000,
                    effective_capabilities: 0,
                },
                "caller GID state",
            ),
            (
                "saved gid",
                ProcessIds {
                    real_uid: 2000,
                    effective_uid: 0,
                    saved_uid: 3000,
                    real_gid: 2000,
                    effective_gid: 0,
                    saved_gid: 1000,
                    effective_capabilities: 0,
                },
                "caller GID state",
            ),
        ];

        for (label, process_ids, expected) in cases {
            let err = resolve_run_as_user_with_process_ids("sandbox-user", &lookup, process_ids)
                .unwrap_err();
            assert!(err.contains(expected), "{label}: {err}");
        }
    }

    #[test]
    fn resolve_run_as_user_accepts_non_root_target_from_root_parent() {
        let lookup = fake_lookup(&[("sandbox-user", 1000, 1000)]);

        let resolved =
            resolve_run_as_user_with_process_ids("sandbox-user", &lookup, root_process_ids())
                .unwrap();

        assert_eq!(resolved.uid, 1000);
        assert_eq!(resolved.gid, 1000);
        assert_eq!(resolved.username, "sandbox-user");
    }

    #[test]
    fn resolve_run_as_user_accepts_non_root_parent_with_identity_switch_capabilities() {
        let lookup = fake_lookup(&[("sandbox-user", 2000, 2000)]);
        let process_ids = non_root_process_ids(identity_switch_capabilities());

        let resolved =
            resolve_run_as_user_with_process_ids("sandbox-user", &lookup, process_ids).unwrap();

        assert_eq!(resolved.uid, 2000);
        assert_eq!(resolved.gid, 2000);
    }

    #[test]
    fn resolve_run_as_user_rejects_non_root_parent_with_only_setuid_and_setgid() {
        let lookup = fake_lookup(&[("sandbox-user", 2000, 2000)]);
        let process_ids = non_root_process_ids((1_u64 << CAP_SETUID) | (1_u64 << CAP_SETGID));

        let err =
            resolve_run_as_user_with_process_ids("sandbox-user", &lookup, process_ids).unwrap_err();

        assert!(err.contains("CAP_CHOWN, CAP_FOWNER and CAP_DAC_OVERRIDE"));
    }

    #[test]
    fn resolve_run_as_user_rejects_non_root_parent_missing_any_identity_switch_capability() {
        let lookup = fake_lookup(&[("sandbox-user", 2000, 2000)]);
        for cap in [
            CAP_CHOWN,
            CAP_DAC_OVERRIDE,
            CAP_FOWNER,
            CAP_SETGID,
            CAP_SETUID,
        ] {
            let process_ids =
                non_root_process_ids(identity_switch_capabilities() & !(1_u64 << cap));

            let err = resolve_run_as_user_with_process_ids("sandbox-user", &lookup, process_ids)
                .unwrap_err();

            assert!(
                err.contains("requires root"),
                "capability {cap} was not required"
            );
        }
    }

    fn non_root_process_ids(effective_capabilities: u64) -> ProcessIds {
        ProcessIds {
            real_uid: 1000,
            effective_uid: 1000,
            saved_uid: 1000,
            real_gid: 1000,
            effective_gid: 1000,
            saved_gid: 1000,
            effective_capabilities,
        }
    }

    #[test]
    fn prepare_workspace_rejects_symlink_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = prepare_workspace_for_identity(&link, &identity(current_euid(), current_egid()))
            .unwrap_err();

        assert!(err.contains("cannot be opened safely"));
    }

    #[test]
    fn prepare_workspace_sets_owner_private_directory_mode() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o755)).unwrap();

        prepare_workspace_for_identity(&workspace, &identity(current_euid(), current_egid()))
            .unwrap();

        let metadata = std::fs::metadata(&workspace).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), current_euid());
        assert_eq!(metadata.gid(), current_egid());
    }

    #[test]
    fn create_tmpdir_for_identity_sets_owner_private_directory_mode() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        create_tmpdir_for_identity(&workspace, &identity(current_euid(), current_egid())).unwrap();

        let tmpdir = landlock::sandbox_tmpdir(&workspace);
        let metadata = std::fs::metadata(&tmpdir).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), current_euid());
        assert_eq!(metadata.gid(), current_egid());
    }

    #[test]
    fn create_tmpdir_for_identity_rejects_preexisting_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let target = temp.path().join("target");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, landlock::sandbox_tmpdir(&workspace)).unwrap();

        let err = create_tmpdir_for_identity(&workspace, &identity(current_euid(), current_egid()))
            .unwrap_err();

        assert!(err.contains("cannot create exclusive tmpdir"));
    }
}
