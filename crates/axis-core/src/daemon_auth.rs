// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared secret that authenticates `axisd` clients.
//!
//! `axisd` keeps a random token in a file only the user can read. The CLI and
//! the desktop apps read it and send it with every IPC request and gateway
//! call. Sandboxes run as the same user, so the file must stay outside every
//! sandbox's filesystem view: launches whose grants cover [`token_dir`] are
//! refused, and the macOS Seatbelt profile denies it explicitly.

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

/// Directory holding the token file.
#[cfg(windows)]
pub fn token_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .filter(|dir| !dir.is_empty())
        .map(|dir| PathBuf::from(dir).join("axis"))
}

/// Directory holding the token file. macOS ignores `XDG_RUNTIME_DIR`: apps
/// started from Finder do not inherit it, and they must find the same file.
#[cfg(unix)]
pub fn token_dir() -> Option<PathBuf> {
    if cfg!(target_os = "linux")
        && let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty())
    {
        return Some(PathBuf::from(runtime).join("axis"));
    }
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".axis").join("run"))
}

fn token_dir_or_err() -> io::Result<PathBuf> {
    token_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot locate the axisd token: HOME, XDG_RUNTIME_DIR, or LOCALAPPDATA is unset",
        )
    })
}

/// Reads the token `axisd` wrote.
pub fn read_token() -> io::Result<String> {
    read_token_in(&token_dir_or_err()?)
}

/// Returns the existing token, creating it on first use. Called by `axisd`.
pub fn load_or_create_token() -> io::Result<String> {
    load_or_create_token_in(&token_dir_or_err()?)
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

pub fn load_or_create_token_in(dir: &Path) -> io::Result<String> {
    create_private_dir(dir)?;
    let path = dir.join(TOKEN_FILE_NAME);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if metadata.is_file() {
            restrict_file(&path)?;
            if let Ok(token) = read_token_in(dir) {
                return Ok(token);
            }
        }
        std::fs::remove_file(&path)?;
    }

    let token = generate_token();
    let tmp = dir.join(format!(".{TOKEN_FILE_NAME}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    write_private_file(&tmp, &token)?;
    // hard_link never replaces an existing file, so daemons starting at the
    // same time settle on one token.
    let linked = std::fs::hard_link(&tmp, &path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(token),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read_token_in(dir),
        Err(e) => Err(e),
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
    // chmod fails unless this user owns the directory.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict_file(_path: &Path) -> io::Result<()> {
    Ok(())
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
    fn token_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let token_dir = dir.path().join("axis");
        let token = load_or_create_token_in(&token_dir).unwrap();
        assert!(is_well_formed(&token));
        assert_eq!(load_or_create_token_in(&token_dir).unwrap(), token);
        assert_eq!(read_token_in(&token_dir).unwrap(), token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&token_dir), 0o700);
            assert_eq!(mode(&token_dir.join(TOKEN_FILE_NAME)), 0o600);
        }
    }

    #[test]
    fn malformed_token_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(TOKEN_FILE_NAME), "short").unwrap();
        assert!(read_token_in(dir.path()).is_err());
        let token = load_or_create_token_in(dir.path()).unwrap();
        assert!(is_well_formed(&token));
        assert_eq!(read_token_in(dir.path()).unwrap(), token);
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
}
