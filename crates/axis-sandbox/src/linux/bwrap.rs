// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bubblewrap fallback construction for Linux sandboxing.

use super::resolver::{HostResolver, ResolverConfig};
use axis_core::policy::{Compatibility, FilesystemPolicy};
use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

const BWRAP_COMMAND_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BubblewrapNetwork {
    /// Shares the host network, and binds the host resolver it implies.
    AllowHost {
        resolver: HostResolver,
    },
    Block,
}

#[derive(Debug)]
pub(crate) struct BubblewrapPlan {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    bind_fds: Vec<OwnedFd>,
}

impl BubblewrapPlan {
    pub(crate) fn inherited_fds(&self) -> Vec<RawFd> {
        self.bind_fds.iter().map(AsRawFd::as_raw_fd).collect()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BubblewrapPlanInput<'a> {
    pub(crate) filesystem: &'a FilesystemPolicy,
    pub(crate) workspace: &'a Path,
    pub(crate) working_dir: Option<&'a Path>,
    pub(crate) network: BubblewrapNetwork,
    pub(crate) env: &'a [(String, String)],
    pub(crate) command: &'a str,
    pub(crate) command_args: &'a [String],
    pub(crate) seccomp_fd: RawFd,
}

pub(crate) fn available() -> bool {
    executable_path().is_ok()
}

pub(crate) fn executable_path() -> Result<PathBuf, String> {
    for dir in BWRAP_COMMAND_DIRS {
        let candidate = Path::new(dir).join("bwrap");
        if safe_root_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err("cannot find safe root-owned bubblewrap executable in fixed system paths".into())
}

pub(crate) fn build_plan(input: BubblewrapPlanInput<'_>) -> Result<BubblewrapPlan, String> {
    build_plan_inner(input, executable_path)
}

fn build_plan_inner(
    input: BubblewrapPlanInput<'_>,
    program_resolver: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<BubblewrapPlan, String> {
    if input.command.is_empty() {
        return Err("bubblewrap command must not be empty".into());
    }
    let workspace_mount = normalize_absolute_mount_path(input.workspace, "workspace")?;
    validate_env(input.env)?;

    let expanded =
        super::landlock::expand_and_validate_filesystem_policy(input.filesystem, input.workspace)?;
    let program = program_resolver()?;
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-ipc".into(),
        "--unshare-pid".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--clearenv".into(),
        "--seccomp".into(),
        input.seccomp_fd.to_string(),
    ];

    if matches!(input.network, BubblewrapNetwork::Block) {
        args.push("--unshare-net".into());
    }

    let mut mounted = HashSet::new();
    let mut bind_fds = Vec::new();
    for path in &expanded.read_only {
        let required = hard_required(input.filesystem, path.required);
        push_expanded_bind(
            &mut args,
            "--ro-bind-fd",
            required,
            &mut bind_fds,
            &mut mounted,
            path,
        )?;
    }

    for path in &expanded.read_write {
        let required = hard_required(input.filesystem, path.required);
        push_expanded_bind(
            &mut args,
            "--bind-fd",
            required,
            &mut bind_fds,
            &mut mounted,
            path,
        )?;
    }

    let workspace_source = canonicalize_required(input.workspace, "workspace")?;
    push_required_bind_fd(
        &mut args,
        "--bind-fd",
        &workspace_source,
        &workspace_source,
        &mut bind_fds,
        &mut mounted,
        "workspace",
    )?;
    if workspace_source != input.workspace {
        push_required_bind_fd(
            &mut args,
            "--bind-fd",
            &workspace_source,
            &workspace_mount,
            &mut bind_fds,
            &mut mounted,
            "workspace",
        )?;
    }
    if expanded.tmpdir_required {
        let tmpdir = super::landlock::sandbox_tmpdir(input.workspace);
        push_required_bind_fd(
            &mut args,
            "--bind-fd",
            &canonicalize_required(&tmpdir, "tmpdir")?,
            &tmpdir,
            &mut bind_fds,
            &mut mounted,
            "tmpdir",
        )?;
    }

    if let BubblewrapNetwork::AllowHost { resolver } = &input.network {
        push_resolver_binds(&mut args, &mut bind_fds, &mut mounted, &expanded, resolver)?;
    }

    let working_dir = match input.working_dir {
        Some(path) => normalize_absolute_mount_path(path, "working directory")?,
        None => workspace_mount,
    };
    args.push("--chdir".into());
    args.push(working_dir.to_string_lossy().into_owned());

    for (key, value) in input.env {
        args.push("--setenv".into());
        args.push(key.clone());
        args.push(value.clone());
    }

    args.push("--".into());
    args.push(input.command.to_string());
    args.extend(input.command_args.iter().cloned());

    Ok(BubblewrapPlan {
        program,
        args,
        bind_fds,
    })
}

/// Binds the host resolver read-only (see `resolver.rs`): the file
/// `/etc/resolv.conf` resolves to and the resolver socket, each on its own,
/// skipping a path a policy grant already mounts. The fallback has no Landlock
/// rule or `connect()` supervisor, and a socket on a read-only mount accepts
/// connections, so the resolver's directory is never bound: that would expose
/// every other socket in it. A bound file is the inode it had at launch, so a
/// configuration the resolver replaces stays at its old contents, and a socket
/// the resolver recreates on restart stops answering. A path that cannot be
/// opened is skipped with a warning; it stays absent.
fn push_resolver_binds(
    args: &mut Vec<String>,
    bind_fds: &mut Vec<OwnedFd>,
    mounted: &mut HashSet<PathBuf>,
    expanded: &super::landlock::ExpandedFilesystemPolicy,
    resolver: &HostResolver,
) -> Result<(), String> {
    let granted = |path: &Path| {
        expanded
            .read_only
            .iter()
            .chain(expanded.read_write.iter())
            .any(|grant| super::landlock::path_contains_or_equal(&grant.path, path))
    };
    for path in resolver
        .config()
        .map(ResolverConfig::file)
        .into_iter()
        .chain(resolver.socket())
        .filter(|path| !granted(path))
    {
        let bound_before = bind_fds.len();
        let mut state = BindFdState { bind_fds, mounted };
        push_bind_fd(
            args,
            &mut state,
            BindFdSpec {
                flag: "--ro-bind-fd",
                source: path,
                dest: path,
                required: false,
                label: "host resolver",
            },
        )?;
        if bind_fds.len() > bound_before {
            tracing::info!(
                "bubblewrap: network.mode allow: host resolver path '{}' bound read-only",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn create_seccomp_fd(
    filter: &super::seccomp::PreparedSeccompFilter,
) -> Result<RawFd, String> {
    let name = std::ffi::CString::new("axis-bwrap-seccomp")
        .map_err(|e| format!("bubblewrap seccomp memfd name: {e}"))?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if fd < 0 {
        return Err(format!(
            "bubblewrap seccomp memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if let Err(e) = write_all(fd, &filter.export_bpf_bytes()) {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if offset < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("bubblewrap seccomp fd rewind failed: {error}"));
    }
    Ok(fd)
}

fn validate_env(env: &[(String, String)]) -> Result<(), String> {
    for (key, value) in env {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(format!("invalid bubblewrap environment key '{key}'"));
        }
    }
    Ok(())
}

fn hard_required(policy: &FilesystemPolicy, path_required: bool) -> bool {
    path_required || matches!(policy.compatibility, Compatibility::HardRequirement)
}

fn push_expanded_bind(
    args: &mut Vec<String>,
    flag: &str,
    required: bool,
    bind_fds: &mut Vec<OwnedFd>,
    mounted: &mut HashSet<PathBuf>,
    path: &super::landlock::ExpandedPath,
) -> Result<(), String> {
    let mut state = BindFdState { bind_fds, mounted };
    push_bind_fd(
        args,
        &mut state,
        BindFdSpec {
            flag,
            source: &path.path,
            dest: &path.path,
            required,
            label: &path.original,
        },
    )?;
    if path.mount_path != path.path {
        push_bind_fd(
            args,
            &mut state,
            BindFdSpec {
                flag,
                source: &path.path,
                dest: &path.mount_path,
                required,
                label: &path.original,
            },
        )?;
    }
    Ok(())
}

fn push_required_bind_fd(
    args: &mut Vec<String>,
    flag: &str,
    source: &Path,
    dest: &Path,
    bind_fds: &mut Vec<OwnedFd>,
    mounted: &mut HashSet<PathBuf>,
    label: &str,
) -> Result<(), String> {
    let mut state = BindFdState { bind_fds, mounted };
    push_bind_fd(
        args,
        &mut state,
        BindFdSpec {
            flag,
            source,
            dest,
            required: true,
            label,
        },
    )
}

struct BindFdState<'a> {
    bind_fds: &'a mut Vec<OwnedFd>,
    mounted: &'a mut HashSet<PathBuf>,
}

struct BindFdSpec<'a> {
    flag: &'a str,
    source: &'a Path,
    dest: &'a Path,
    required: bool,
    label: &'a str,
}

fn push_bind_fd(
    args: &mut Vec<String>,
    state: &mut BindFdState<'_>,
    spec: BindFdSpec<'_>,
) -> Result<(), String> {
    let dest = spec.dest.to_path_buf();
    if state.mounted.insert(dest.clone()) {
        let Some(fd) = open_bind_fd(spec.source, spec.required, spec.label)? else {
            return Ok(());
        };
        let rendered_fd = fd.as_raw_fd().to_string();
        let rendered_dest = dest.to_string_lossy().into_owned();
        args.push(spec.flag.into());
        args.push(rendered_fd);
        args.push(rendered_dest);
        state.bind_fds.push(fd);
    }
    Ok(())
}

fn canonicalize_required(path: &Path, label: &str) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|e| {
        format!(
            "bubblewrap: required {label} '{}' cannot be resolved: {e}",
            path.display()
        )
    })
}

fn normalize_absolute_mount_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "bubblewrap {label} must be absolute: {}",
            path.display()
        ));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => normalized.push(Path::new("/")),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::Prefix(_) => {
                return Err(format!(
                    "bubblewrap {label} must be a Linux path: {}",
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

fn open_bind_fd(path: &Path, required: bool, label: &str) -> Result<Option<OwnedFd>, String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| {
        format!(
            "bubblewrap: bind source '{}' for {label} contains an interior NUL: {e}",
            path.display()
        )
    })?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd >= 0 {
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
    }

    let error = std::io::Error::last_os_error();
    if required {
        Err(format!(
            "bubblewrap: required bind source '{}' for {label} cannot be opened: {error}",
            path.display()
        ))
    } else {
        tracing::warn!(
            "bubblewrap: skipping best-effort bind source '{}' for {label}: {error}",
            path.display()
        );
        Ok(None)
    }
}

fn write_all(fd: RawFd, bytes: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let ret = unsafe {
            libc::write(
                fd,
                bytes[offset..].as_ptr() as *const libc::c_void,
                bytes.len() - offset,
            )
        };
        if ret < 0 {
            return Err(format!(
                "bubblewrap seccomp fd write failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if ret == 0 {
            return Err("bubblewrap seccomp fd write made no progress".into());
        }
        offset += ret as usize;
    }
    Ok(())
}

fn safe_root_executable(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        if current == path {
            return metadata.is_file() && metadata.mode() & 0o111 != 0;
        }
        if !metadata.is_dir() {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BWRAP_PROGRAM: &str = "/usr/bin/bwrap";

    fn build_test_plan(input: BubblewrapPlanInput<'_>) -> Result<BubblewrapPlan, String> {
        build_plan_inner(input, || Ok(PathBuf::from(TEST_BWRAP_PROGRAM)))
    }

    #[test]
    fn minimal_block_plan_uses_pid_proc_dev_net_seccomp_and_workspace_bind() {
        let workspace = tempfile::tempdir().unwrap();
        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &FilesystemPolicy::default(),
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::Block,
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap();

        assert_eq!(plan.program, PathBuf::from(TEST_BWRAP_PROGRAM));
        assert_arg(&plan.args, "--unshare-pid");
        assert_arg(&plan.args, "--proc");
        assert_arg(&plan.args, "--dev");
        assert_arg(&plan.args, "--unshare-net");
        assert_pair(&plan.args, "--seccomp", "7");
        assert_fd_bind(&plan.args, "--bind-fd", workspace.path());
        assert_eq!(
            plan.inherited_fds().len(),
            expected_workspace_mounts(workspace.path())
        );
        assert_pair(&plan.args, "--chdir", &workspace.path().to_string_lossy());
        assert_eq!(plan.args.last().unwrap(), "/bin/true");
    }

    struct ResolverFixture {
        workspace: tempfile::TempDir,
        host: tempfile::TempDir,
        config: PathBuf,
        socket: PathBuf,
        _listener: std::os::unix::net::UnixListener,
    }

    impl ResolverFixture {
        fn new() -> Self {
            let workspace = tempfile::tempdir().unwrap();
            let host = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(host.path()).unwrap();
            let config = root.join("stub-resolv.conf");
            std::fs::write(&config, "nameserver 127.0.0.53\n").unwrap();
            let socket = root.join("io.systemd.Resolve");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            Self {
                workspace,
                host,
                config,
                socket,
                _listener: listener,
            }
        }

        fn root(&self) -> PathBuf {
            std::fs::canonicalize(self.host.path()).unwrap()
        }

        fn plan(&self, policy: &FilesystemPolicy, network: BubblewrapNetwork) -> BubblewrapPlan {
            build_test_plan(BubblewrapPlanInput {
                filesystem: policy,
                workspace: self.workspace.path(),
                working_dir: None,
                network,
                env: &[],
                command: "/bin/true",
                command_args: &[],
                seccomp_fd: 7,
            })
            .unwrap()
        }
    }

    fn allow_with(socket: Option<PathBuf>, config: Option<ResolverConfig>) -> BubblewrapNetwork {
        BubblewrapNetwork::AllowHost {
            resolver: HostResolver::for_test(socket, config),
        }
    }

    #[test]
    fn allow_plan_binds_resolver_files_read_only() {
        let fixture = ResolverFixture::new();
        let policy = FilesystemPolicy::default();
        let network = allow_with(
            Some(fixture.socket.clone()),
            Some(ResolverConfig::File(fixture.config.clone())),
        );
        let plan = fixture.plan(&policy, network);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &fixture.config);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &fixture.socket);
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &fixture.root());
        assert_no_fd_bind(&plan.args, "--bind-fd", &fixture.config);
        assert_no_fd_bind(&plan.args, "--bind-fd", &fixture.socket);
        assert_eq!(
            plan.inherited_fds().len(),
            2 + expected_workspace_mounts(fixture.workspace.path())
        );

        let plan = fixture.plan(&policy, BubblewrapNetwork::Block);
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &fixture.config);
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &fixture.socket);
    }

    #[test]
    fn allow_plan_never_binds_the_resolver_directory() {
        let fixture = ResolverFixture::new();
        let sibling = fixture.root().join("io.systemd.Resolve.Monitor");
        let _sibling = std::os::unix::net::UnixListener::bind(&sibling).unwrap();
        let network = allow_with(
            Some(fixture.socket.clone()),
            Some(ResolverConfig::Directory {
                dir: fixture.root(),
                file: fixture.config.clone(),
            }),
        );
        let plan = fixture.plan(&FilesystemPolicy::default(), network);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &fixture.config);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &fixture.socket);
        for unbound in [fixture.root(), sibling] {
            assert_no_fd_bind(&plan.args, "--ro-bind-fd", &unbound);
            assert_no_fd_bind(&plan.args, "--bind-fd", &unbound);
        }
        let root = fixture.root();
        assert!(
            !plan.args.iter().any(|arg| Path::new(arg).starts_with(&root)
                && ![&fixture.config, &fixture.socket].contains(&&PathBuf::from(arg))),
            "only the resolver file and socket are mounted from its directory: {:?}",
            plan.args
        );
    }

    #[test]
    fn allow_plan_leaves_granted_resolver_paths_to_the_grant() {
        let fixture = ResolverFixture::new();
        let policy = FilesystemPolicy {
            read_write: vec![fixture.root().to_string_lossy().into_owned()],
            ..Default::default()
        };
        let network = allow_with(
            Some(fixture.socket.clone()),
            Some(ResolverConfig::File(fixture.config.clone())),
        );
        let plan = fixture.plan(&policy, network);
        assert_fd_bind(&plan.args, "--bind-fd", &fixture.root());
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &fixture.config);
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &fixture.socket);
    }

    #[test]
    fn allow_plan_skips_a_missing_resolver_path() {
        let fixture = ResolverFixture::new();
        let missing = fixture.root().join("missing.conf");
        let network = allow_with(
            Some(fixture.socket.clone()),
            Some(ResolverConfig::File(missing.clone())),
        );
        let plan = fixture.plan(&FilesystemPolicy::default(), network);
        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &missing);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &fixture.socket);
    }

    #[test]
    fn coding_plan_maps_read_only_and_read_write_paths() {
        let workspace = tempfile::tempdir().unwrap();
        let ro = tempfile::tempdir().unwrap();
        let rw = tempfile::tempdir().unwrap();
        let policy = FilesystemPolicy {
            read_only: vec![ro.path().to_string_lossy().into_owned()],
            read_write: vec![rw.path().to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };
        let env = vec![(
            "HOME".into(),
            workspace.path().to_string_lossy().into_owned(),
        )];

        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &policy,
            workspace: workspace.path(),
            working_dir: Some(workspace.path()),
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &env,
            command: "/bin/sh",
            command_args: &["-c".into(), "true".into()],
            seccomp_fd: 9,
        })
        .unwrap();

        assert!(!plan.args.iter().any(|arg| arg == "--unshare-net"));
        assert_fd_bind(&plan.args, "--ro-bind-fd", ro.path());
        assert_fd_bind(&plan.args, "--bind-fd", rw.path());
        assert_fd_bind(&plan.args, "--bind-fd", workspace.path());
        assert_eq!(
            plan.inherited_fds().len(),
            2 + expected_workspace_mounts(workspace.path())
        );
        assert_pair(&plan.args, "--setenv", "HOME");
        assert!(
            plan.args
                .ends_with(&["/bin/sh".into(), "-c".into(), "true".into()])
        );
    }

    #[test]
    fn symlinked_policy_path_mounts_canonical_target_and_original_alias() {
        let workspace = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        let policy = FilesystemPolicy {
            read_only: vec![alias.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &policy,
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap();

        assert_fd_bind(&plan.args, "--ro-bind-fd", &target);
        assert_fd_bind(&plan.args, "--ro-bind-fd", &alias);
        assert_eq!(
            plan.inherited_fds().len(),
            2 + expected_workspace_mounts(workspace.path())
        );
    }

    #[test]
    fn symlinked_workspace_mounts_canonical_target_and_original_alias() {
        let root = tempfile::tempdir().unwrap();
        let workspace_target = root.path().join("workspace-target");
        let workspace_alias = root.path().join("workspace-alias");
        std::fs::create_dir_all(&workspace_target).unwrap();
        std::os::unix::fs::symlink(&workspace_target, &workspace_alias).unwrap();

        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &FilesystemPolicy::default(),
            workspace: &workspace_alias,
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap();

        assert_fd_bind(&plan.args, "--bind-fd", &workspace_target);
        assert_fd_bind(&plan.args, "--bind-fd", &workspace_alias);
        assert_eq!(plan.inherited_fds().len(), 2);
    }

    #[test]
    fn relative_workspace_fails_closed() {
        let err = build_test_plan(BubblewrapPlanInput {
            filesystem: &FilesystemPolicy::default(),
            workspace: Path::new("relative-workspace"),
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap_err();

        assert!(err.contains("workspace must be absolute"));
    }

    #[test]
    fn non_normalized_absolute_workspace_uses_normalized_mount_destination() {
        let root = tempfile::tempdir().unwrap();
        let intermediate = root.path().join("intermediate");
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&intermediate).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let noisy_workspace = intermediate.join("..").join("workspace");

        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &FilesystemPolicy::default(),
            workspace: &noisy_workspace,
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap();

        assert_fd_bind(&plan.args, "--bind-fd", &workspace);
        assert_no_fd_bind(&plan.args, "--bind-fd", &noisy_workspace);
        assert_pair(&plan.args, "--chdir", &workspace.to_string_lossy());
    }

    #[test]
    fn best_effort_missing_bind_is_skipped() {
        let workspace = tempfile::tempdir().unwrap();
        let runtime_root = tempfile::tempdir().unwrap();
        let missing = runtime_root.path().join("missing-runtime");
        let policy = FilesystemPolicy {
            read_only: vec![missing.to_string_lossy().into_owned()],
            compatibility: Compatibility::BestEffort,
            ..Default::default()
        };

        let plan = build_test_plan(BubblewrapPlanInput {
            filesystem: &policy,
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap();

        assert_no_fd_bind(&plan.args, "--ro-bind-fd", &missing);
        assert_fd_bind(&plan.args, "--bind-fd", workspace.path());
        assert_eq!(
            plan.inherited_fds().len(),
            expected_workspace_mounts(workspace.path())
        );
    }

    #[test]
    fn hard_required_missing_bind_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let runtime_root = tempfile::tempdir().unwrap();
        let missing = runtime_root.path().join("missing-runtime");
        let policy = FilesystemPolicy {
            read_only: vec![missing.to_string_lossy().into_owned()],
            compatibility: Compatibility::HardRequirement,
            ..Default::default()
        };

        let err = build_test_plan(BubblewrapPlanInput {
            filesystem: &policy,
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::AllowHost {
                resolver: HostResolver::default(),
            },
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap_err();

        assert!(err.contains("required bind source"));
    }

    #[test]
    fn deny_under_allowed_path_fails_closed() {
        let workspace = tempfile::tempdir().unwrap();
        let allowed = tempfile::tempdir().unwrap();
        let denied = allowed.path().join("secret");
        std::fs::create_dir_all(&denied).unwrap();
        let policy = FilesystemPolicy {
            read_only: vec![allowed.path().to_string_lossy().into_owned()],
            deny: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let err = build_test_plan(BubblewrapPlanInput {
            filesystem: &policy,
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::Block,
            env: &[],
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap_err();

        assert!(err.contains("under allowed read-only path"));
    }

    #[test]
    fn environment_keys_are_validated_before_spawn() {
        let workspace = tempfile::tempdir().unwrap();
        let env = vec![("BAD=KEY".into(), "value".into())];

        let err = build_test_plan(BubblewrapPlanInput {
            filesystem: &FilesystemPolicy::default(),
            workspace: workspace.path(),
            working_dir: None,
            network: BubblewrapNetwork::Block,
            env: &env,
            command: "/bin/true",
            command_args: &[],
            seccomp_fd: 7,
        })
        .unwrap_err();

        assert!(err.contains("invalid bubblewrap environment"));
    }

    fn assert_arg(args: &[String], expected: &str) {
        assert!(args.iter().any(|arg| arg == expected), "missing {expected}");
    }

    fn assert_pair(args: &[String], flag: &str, value: &str) {
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == flag && pair[1] == value),
            "missing {flag} {value}"
        );
    }

    fn assert_fd_bind(args: &[String], flag: &str, path: &Path) {
        let rendered = path.to_string_lossy();
        assert!(
            args.windows(3).any(|triple| triple[0] == flag
                && triple[1].parse::<RawFd>().is_ok()
                && triple[2] == rendered),
            "missing {flag} FD {rendered}"
        );
    }

    fn assert_no_fd_bind(args: &[String], flag: &str, path: &Path) {
        let rendered = path.to_string_lossy();
        assert!(
            !args
                .windows(3)
                .any(|triple| triple[0] == flag && triple[2] == rendered),
            "unexpected {flag} FD {rendered}"
        );
    }

    fn expected_workspace_mounts(workspace: &Path) -> usize {
        if std::fs::canonicalize(workspace).unwrap() == workspace {
            1
        } else {
            2
        }
    }
}
