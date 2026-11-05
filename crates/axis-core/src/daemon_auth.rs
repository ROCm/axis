// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared secret that authenticates `axisd` clients.
//!
//! `axisd` keeps a random token in a file only the user can read. The CLI and
//! the desktop apps read it and send it with every IPC request and gateway
//! call. Sandboxes run as the same user, so the file must stay outside every
//! sandbox's filesystem view: launches whose grants cover [`token_dir`] are
//! refused, and the macOS Seatbelt profile denies it explicitly.
//!
//! Tests that create sandboxes or tokens must call
//! [`override_token_dir_for_tests`] first, or they use the real directory.

use std::io;
use std::path::{Path, PathBuf};

pub const TOKEN_FILE_NAME: &str = "axisd.token";
/// JSON field carrying the token in IPC requests.
pub const IPC_TOKEN_FIELD: &str = "token";
/// WebSocket subprotocol prefix carrying the token. Browsers cannot set
/// headers on a WebSocket handshake.
pub const WS_TOKEN_PROTOCOL_PREFIX: &str = "axis-token.";
/// Subprotocol the gateway selects, so the token is never echoed back.
pub const WS_PROTOCOL: &str = "axis.v1";

const TOKEN_LEN: usize = 64;

static TOKEN_DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Directory holding the token file: `~/.axis/run` on Unix and
/// `%LOCALAPPDATA%\axis` on Windows, resolved through symlinks. The home and
/// LocalAppData directories come from the user account, never from the
/// environment, so axisd, the CLI, and launch checks always agree on it.
pub fn token_dir() -> Option<PathBuf> {
    if let Some(dir) = TOKEN_DIR_OVERRIDE.get() {
        return Some(dir.clone());
    }
    let base = account_base_dir().filter(|dir| dir.is_absolute())?;
    let dir = if cfg!(windows) {
        base.join("axis")
    } else {
        base.join(".axis").join("run")
    };
    Some(resolve_existing_prefix(&dir))
}

/// `path` with its longest existing ancestor resolved through symlinks, so a
/// path that does not exist yet still compares by where it will be created.
pub fn resolve_existing_prefix(path: &Path) -> PathBuf {
    path.ancestors()
        .find_map(|ancestor| {
            let resolved = std::fs::canonicalize(ancestor).ok()?;
            Some(resolved.join(path.strip_prefix(ancestor).ok()?))
        })
        .unwrap_or_else(|| path.to_path_buf())
}

/// Points [`token_dir`] at `dir` for the rest of this process. Tests only:
/// unlike an environment variable, other processes are not affected.
#[doc(hidden)]
pub fn override_token_dir_for_tests(dir: PathBuf) {
    let _ = TOKEN_DIR_OVERRIDE.set(dir);
}

/// The account's home directory.
#[cfg(unix)]
fn account_base_dir() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain data; getpwuid_r fills it from `buf`.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf.len()` is its size.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into `buf`, which is still alive.
    let home = unsafe { CStr::from_ptr(entry.pw_dir) };
    Some(PathBuf::from(OsStr::from_bytes(home.to_bytes())))
}

/// The account's LocalAppData directory.
#[cfg(windows)]
fn account_base_dir() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

    // SAFETY: the returned string is copied, then freed exactly once.
    unsafe {
        let raw = SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None).ok()?;
        let dir = std::ffi::OsString::from_wide(raw.as_wide());
        CoTaskMemFree(Some(raw.0 as *const _));
        Some(PathBuf::from(dir))
    }
}

fn token_dir_or_err() -> io::Result<PathBuf> {
    token_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot locate the axisd token: the user account has no home or LocalAppData \
             directory",
        )
    })
}

/// Reads the token `axisd` wrote.
pub fn read_token() -> io::Result<String> {
    read_token_in(&token_dir_or_err()?)
}

/// Writes a fresh token, replacing any previous one. Called by `axisd` on
/// start, so a leaked token stops working when the daemon restarts.
pub fn create_token() -> io::Result<String> {
    create_token_in(&token_dir_or_err()?)
}

/// Deletes the token file if it still holds `token`. Called by `axisd` on
/// shutdown; a newer daemon's token is left alone.
pub fn remove_token(token: &str) {
    if let Ok(dir) = token_dir_or_err() {
        remove_token_in(&dir, token);
    }
}

pub fn read_token_in(dir: &Path) -> io::Result<String> {
    let token = std::fs::read_to_string(dir.join(TOKEN_FILE_NAME))?;
    let token = token.trim();
    if is_well_formed(token) {
        Ok(token.to_string())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed axisd token",
        ))
    }
}

pub fn create_token_in(dir: &Path) -> io::Result<String> {
    create_private_dir(dir)?;
    let token = generate_token();
    let tmp = dir.join(format!(".{TOKEN_FILE_NAME}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    write_private_file(&tmp, &token)?;
    // rename replaces the old file atomically (a symlink there is replaced,
    // not followed), so readers see the old token or the new one, never a
    // partial file.
    if let Err(e) = std::fs::rename(&tmp, dir.join(TOKEN_FILE_NAME)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(token)
}

pub fn remove_token_in(dir: &Path, token: &str) {
    if read_token_in(dir).is_ok_and(|current| current == token) {
        let _ = std::fs::remove_file(dir.join(TOKEN_FILE_NAME));
    }
}

/// Compares tokens in constant time.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let (expected, presented) = (expected.as_bytes(), presented.as_bytes());
    !expected.is_empty()
        && expected.len() == presented.len()
        && expected
            .iter()
            .zip(presented)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

/// 64 hex characters (244 random bits). UUID v4 draws from the OS CSPRNG.
fn generate_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_LEN && token.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("axisd token directory {} is a symlink", dir.display()),
        ));
    }
    // chmod fails unless this user owns the directory.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn write_private_file(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_start_replaces_the_token_privately() {
        let dir = tempfile::tempdir().unwrap();
        let token_dir = dir.path().join("axis");
        std::fs::create_dir(&token_dir).unwrap();
        std::fs::write(token_dir.join(TOKEN_FILE_NAME), "f".repeat(64)).unwrap();

        let first = create_token_in(&token_dir).unwrap();
        let second = create_token_in(&token_dir).unwrap();
        assert!(is_well_formed(&second));
        assert_ne!(first, second);
        assert_eq!(read_token_in(&token_dir).unwrap(), second);
        assert_eq!(
            std::fs::read_dir(&token_dir).unwrap().count(),
            1,
            "temp file left"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&token_dir), 0o700);
            assert_eq!(mode(&token_dir.join(TOKEN_FILE_NAME)), 0o600);
        }
    }

    #[test]
    fn shutdown_removes_only_its_own_token() {
        let dir = tempfile::tempdir().unwrap();
        let old = create_token_in(dir.path()).unwrap();
        let new = create_token_in(dir.path()).unwrap();
        remove_token_in(dir.path(), &old);
        assert_eq!(
            read_token_in(dir.path()).unwrap(),
            new,
            "removed a newer daemon's token"
        );
        remove_token_in(dir.path(), &new);
        assert!(!dir.path().join(TOKEN_FILE_NAME).exists());
    }

    #[test]
    fn tokens_are_random() {
        assert_ne!(generate_token(), generate_token());
    }

    #[test]
    fn token_matches_only_the_exact_token() {
        let token = generate_token();
        assert!(token_matches(&token, &token));
        assert!(!token_matches(&token, &token[1..]));
        assert!(!token_matches(&token, &generate_token()));
        assert!(!token_matches(&token, ""));
        assert!(!token_matches("", ""));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_token_dir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("axis");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_token_in(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn missing_paths_resolve_through_symlinked_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            resolve_existing_prefix(&link.join("missing/axis")),
            std::fs::canonicalize(&real).unwrap().join("missing/axis")
        );
    }
}
