// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host name resolution that `network.mode: allow` implies on the native
//! backend.
//!
//! On systemd-resolved hosts, systemd's `nss-resolve` module (`resolve` in
//! `/etc/nsswitch.conf`) resolves names through the Varlink socket
//! [`RESOLVER_SOCKET`], and `/etc/resolv.conf` is usually a symlink into the
//! same runtime directory. The native backend denies pathname Unix connect to
//! host sockets (on Landlock ABI 9+ always, below ABI 9 outside read-write
//! grants) and grants only the files a policy names, so a sandbox that may
//! reach the network could not resolve a host name through the host resolver.
//!
//! When the workload shares the host network (`network.mode: allow`), it can
//! already query the host's stub resolver on loopback and any DNS server. The
//! resolver socket adds no network reach. It is a different interface to the
//! same resolver, though: it can ask for answers from the cache only, and its
//! replies name the interface a lookup used. The sandbox then may connect to
//! that one socket, and read the file `/etc/resolv.conf` resolves to when the
//! policy already lets it read `/etc/resolv.conf`. In `proxy` mode nothing is
//! added, because the resolver would be a DNS channel around the proxy, and in
//! `block` mode nothing is added because the workload has no network.
//!
//! systemd-resolved replaces its configuration files by rename when the DNS
//! configuration changes, and recreates its socket when it restarts, while its
//! runtime directory persists (`RuntimeDirectoryPreserve=yes`). So when
//! `/etc/resolv.conf` points into the resolver's own runtime directory,
//! Landlock grants read access to the files in that directory, which survives
//! a replaced file; elsewhere, and on the Bubblewrap fallback (which would
//! otherwise expose every socket in the directory), it is the one file, on
//! the inode it has at launch. How long the socket grant lives depends on the
//! layer that applies it (see `landlock.rs`, `connect_attribution.rs`,
//! `bwrap.rs`), and the design is in `docs/native-host-resolver.md`.
//!
//! An explicit `deny:` entry covering a path keeps it denied. Detection here
//! decides what to grant and logs, at debug level, why it grants nothing; the
//! layer that applies a grant logs it, or logs why it could not.

use super::landlock::{ExpandedFilesystemPolicy, path_contains_or_equal};
use axis_core::policy::{FilesystemPolicy, NetworkMode};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

/// systemd-resolved's Varlink endpoint for host name lookups.
pub(crate) const RESOLVER_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";
/// The resolver configuration glibc and other stub resolvers read.
pub(crate) const RESOLVER_CONFIG: &str = "/etc/resolv.conf";

/// What the sandbox may reach of the host resolver, beyond its policy grants.
/// Empty unless the policy uses `network.mode: allow`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostResolver {
    socket: Option<PathBuf>,
    config: Option<ResolverConfig>,
}

/// Read access the resolver configuration needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolverConfig {
    /// The resolver's runtime directory `dir`, which holds `file`, the file
    /// `/etc/resolv.conf` resolves to. Where the layer can grant a directory
    /// (Landlock), the files in `dir` may be read, so a file the resolver
    /// replaces stays readable; elsewhere only `file` is granted.
    Directory { dir: PathBuf, file: PathBuf },
    /// The file `/etc/resolv.conf` resolves to, outside the resolver's runtime
    /// directory. Readable until it is replaced.
    File(PathBuf),
}

impl ResolverConfig {
    /// The file `/etc/resolv.conf` resolves to.
    pub(crate) fn file(&self) -> &Path {
        match self {
            Self::Directory { file, .. } | Self::File(file) => file,
        }
    }
}

impl HostResolver {
    pub(crate) fn for_policy_at(
        mode: &NetworkMode,
        filesystem: &FilesystemPolicy,
        workspace: &Path,
        socket: &Path,
        config: &Path,
    ) -> Result<Self, String> {
        if !matches!(mode, NetworkMode::Allow) {
            return Ok(Self::default());
        }
        let expanded = super::landlock::expand_filesystem_policy(filesystem, workspace)?;
        Ok(Self {
            socket: resolver_socket(socket, &expanded),
            config: resolver_config(config, socket, &expanded),
        })
    }

    /// The resolver socket, canonical, if the sandbox may connect to it.
    pub(crate) fn socket(&self) -> Option<&Path> {
        self.socket.as_deref()
    }

    /// The resolver configuration, canonical, if the sandbox may read it.
    pub(crate) fn config(&self) -> Option<&ResolverConfig> {
        self.config.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(socket: Option<PathBuf>, config: Option<ResolverConfig>) -> Self {
        Self { socket, config }
    }
}

/// Logs why allow mode grants no host resolver path, so a failing lookup in
/// the sandbox can be traced to it with `RUST_LOG=axis_sandbox=debug`. Debug,
/// not info: on a host without systemd-resolved every allow-mode launch would
/// log it, although nothing is wrong there.
fn declined(path: &Path, why: &str) {
    tracing::debug!(
        "network.mode allow: host resolver path '{}' not granted: {why}",
        path.display()
    );
}

fn resolver_socket(socket: &Path, expanded: &ExpandedFilesystemPolicy) -> Option<PathBuf> {
    let Ok(canonical) = std::fs::canonicalize(socket) else {
        declined(socket, "it does not exist");
        return None;
    };
    let is_socket = std::fs::symlink_metadata(&canonical)
        .is_ok_and(|metadata| metadata.file_type().is_socket());
    if !is_socket {
        declined(socket, "it is not a socket");
        return None;
    }
    if denied(expanded, &canonical) {
        declined(socket, "a deny: entry covers it");
        return None;
    }
    Some(canonical)
}

/// Read access for the file `config` resolves to, when `config` is a symlink,
/// the policy lets the sandbox read `config`, and the target is a regular
/// file. A grant on the symlink's directory does not reach a target elsewhere,
/// so without this the grant would not be enough to read it. When the target
/// lies in the directory of `socket`, the resolver's runtime directory, the
/// directory is granted, unless a `deny:` entry lies in it or contains it.
fn resolver_config(
    config: &Path,
    socket: &Path,
    expanded: &ExpandedFilesystemPolicy,
) -> Option<ResolverConfig> {
    let target = std::fs::canonicalize(config).ok()?;
    if target == config {
        // A regular file: the policy's own grants decide.
        return None;
    }
    if !std::fs::metadata(&target).is_ok_and(|metadata| metadata.is_file()) {
        declined(&target, "it is not a regular file");
        return None;
    }
    // A grant on the symlink itself expands to its target, so the path as
    // written is compared too; a grant through a symlinked directory is
    // compared by its canonical path.
    let readable = expanded
        .read_only
        .iter()
        .chain(expanded.read_write.iter())
        .any(|grant| {
            path_contains_or_equal(&grant.mount_path, config)
                || path_contains_or_equal(&grant.path, config)
        });
    if !readable {
        declined(&target, "no grant covers /etc/resolv.conf");
        return None;
    }
    if denied(expanded, &target) {
        declined(&target, "a deny: entry covers it");
        return None;
    }
    let runtime_dir = socket
        .parent()
        .and_then(|dir| std::fs::canonicalize(dir).ok());
    match (target.parent(), runtime_dir) {
        (Some(parent), Some(runtime_dir))
            if parent == runtime_dir && !deny_inside(expanded, &runtime_dir) =>
        {
            Some(ResolverConfig::Directory {
                dir: runtime_dir,
                file: target,
            })
        }
        _ => Some(ResolverConfig::File(target)),
    }
}

/// Whether a `deny:` entry covers `canonical`. Deny entries expand to their
/// canonical path when it exists, so comparing canonical paths also catches a
/// deny written through a symlink (including a deny of `/etc/resolv.conf`
/// itself, which expands to its target).
fn denied(expanded: &ExpandedFilesystemPolicy, canonical: &Path) -> bool {
    expanded
        .deny
        .iter()
        .any(|deny| path_contains_or_equal(&deny.path, canonical))
}

/// Whether a `deny:` entry lies inside `dir`. One that covers `dir` covers the
/// target too, which `denied` has already refused.
fn deny_inside(expanded: &ExpandedFilesystemPolicy, dir: &Path) -> bool {
    expanded
        .deny
        .iter()
        .any(|deny| path_contains_or_equal(dir, &deny.path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    struct Host {
        _dir: tempfile::TempDir,
        etc: PathBuf,
        run: PathBuf,
        socket: PathBuf,
        config: PathBuf,
        target: PathBuf,
        workspace: PathBuf,
        _listener: UnixListener,
    }

    /// A host layout like systemd-resolved's: `etc/resolv.conf` links to
    /// `run/stub-resolv.conf`, beside the resolver socket.
    fn host() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let etc = root.join("etc");
        let run = root.join("run");
        let workspace = root.join("workspace");
        for path in [&etc, &run, &workspace] {
            std::fs::create_dir(path).unwrap();
        }
        let socket = run.join("io.systemd.Resolve");
        let listener = UnixListener::bind(&socket).unwrap();
        let target = run.join("stub-resolv.conf");
        std::fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        let config = etc.join("resolv.conf");
        std::os::unix::fs::symlink(&target, &config).unwrap();
        Host {
            _dir: dir,
            etc,
            run,
            socket,
            config,
            target,
            workspace,
            _listener: listener,
        }
    }

    fn resolver(host: &Host, mode: NetworkMode, policy: FilesystemPolicy) -> HostResolver {
        HostResolver::for_policy_at(&mode, &policy, &host.workspace, &host.socket, &host.config)
            .unwrap()
    }

    fn paths(paths: &[&Path]) -> Vec<String> {
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    }

    fn grants(read_only: &[&Path]) -> FilesystemPolicy {
        FilesystemPolicy {
            read_only: paths(read_only),
            ..FilesystemPolicy::default()
        }
    }

    fn allow(host: &Host, policy: FilesystemPolicy) -> HostResolver {
        resolver(host, NetworkMode::Allow, policy)
    }

    fn directory(host: &Host) -> Option<ResolverConfig> {
        Some(ResolverConfig::Directory {
            dir: host.run.clone(),
            file: host.target.clone(),
        })
    }

    #[test]
    fn allow_mode_reaches_the_resolver_socket_and_runtime_directory() {
        let host = host();
        let resolver = allow(&host, grants(&[&host.etc]));
        assert_eq!(resolver.socket(), Some(host.socket.as_path()));
        assert_eq!(resolver.config(), directory(&host).as_ref());
    }

    #[test]
    fn proxy_and_block_modes_add_nothing() {
        let host = host();
        for mode in [NetworkMode::Proxy, NetworkMode::Block] {
            assert_eq!(
                resolver(&host, mode, grants(&[&host.etc])),
                HostResolver::default()
            );
        }
    }

    #[test]
    fn config_needs_a_read_or_write_grant_covering_resolv_conf() {
        let host = host();
        let without_grant = allow(&host, grants(&[]));
        assert_eq!(without_grant.socket(), Some(host.socket.as_path()));
        assert_eq!(without_grant.config(), None);

        // A grant on the symlink itself.
        assert_eq!(
            allow(&host, grants(&[&host.config])).config(),
            directory(&host).as_ref()
        );
        let read_write = FilesystemPolicy {
            read_write: paths(&[&host.etc]),
            ..FilesystemPolicy::default()
        };
        assert_eq!(allow(&host, read_write).config(), directory(&host).as_ref());
    }

    #[test]
    fn a_grant_through_a_symlinked_directory_covers_resolv_conf() {
        let host = host();
        let alias = host.workspace.join("etc-alias");
        std::os::unix::fs::symlink(&host.etc, &alias).unwrap();
        assert_eq!(
            allow(&host, grants(&[&alias])).config(),
            directory(&host).as_ref()
        );
    }

    #[test]
    fn deny_on_the_resolver_directory_wins() {
        let host = host();
        let policy = FilesystemPolicy {
            deny: paths(&[&host.run]),
            ..grants(&[&host.etc])
        };
        assert_eq!(allow(&host, policy), HostResolver::default());
    }

    #[test]
    fn deny_of_resolv_conf_under_a_grant_of_its_directory_keeps_the_config_denied() {
        let host = host();
        // The deny expands to the symlink's target, outside the grant, so the
        // policy is valid; the resolver must still honour it.
        let policy = FilesystemPolicy {
            deny: paths(&[&host.config]),
            ..grants(&[&host.etc])
        };
        crate::linux::landlock::expand_and_validate_filesystem_policy(&policy, &host.workspace)
            .unwrap();
        let resolver = allow(&host, policy);
        assert_eq!(resolver.config(), None);
        assert_eq!(resolver.socket(), Some(host.socket.as_path()));
    }

    #[test]
    fn deny_inside_the_runtime_directory_narrows_the_config_grant_to_the_file() {
        let host = host();
        let netif = host.run.join("netif");
        std::fs::create_dir(&netif).unwrap();
        let policy = FilesystemPolicy {
            deny: paths(&[&netif]),
            ..grants(&[&host.etc])
        };
        assert_eq!(
            allow(&host, policy).config(),
            Some(&ResolverConfig::File(host.target.clone()))
        );
    }

    #[test]
    fn config_outside_the_runtime_directory_is_granted_as_a_file() {
        let host = host();
        let elsewhere = host.workspace.join("resolv.conf.real");
        std::fs::write(&elsewhere, "nameserver 192.0.2.1\n").unwrap();
        std::fs::remove_file(&host.config).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &host.config).unwrap();
        assert_eq!(
            allow(&host, grants(&[&host.etc])).config(),
            Some(&ResolverConfig::File(elsewhere))
        );
    }

    #[test]
    fn non_socket_at_the_resolver_path_is_not_granted() {
        let host = host();
        std::fs::remove_file(&host.socket).unwrap();
        std::fs::write(&host.socket, "").unwrap();
        assert_eq!(allow(&host, grants(&[])).socket(), None);
    }

    #[test]
    fn regular_resolv_conf_needs_no_extra_grant() {
        let host = host();
        std::fs::remove_file(&host.config).unwrap();
        std::fs::write(&host.config, "nameserver 192.0.2.1\n").unwrap();
        assert_eq!(allow(&host, grants(&[&host.etc])).config(), None);
    }
}
