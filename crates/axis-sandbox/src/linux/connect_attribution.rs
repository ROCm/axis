// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux seccomp-notify connect attribution.

use axis_core::connect_attribution::{
    ConnectAttributionRecord, ConnectAttributionSource, ConnectAttributionStore,
};
use axis_core::types::SandboxId;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::thread::JoinHandle;

const SYS_CONNECT: i32 = 42;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const SECCOMP_IOC_MAGIC: u64 = b'!' as u64;
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong =
    iowr(SECCOMP_IOC_MAGIC, 0, size_of::<SeccompNotif>() as u64);
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong =
    iowr(SECCOMP_IOC_MAGIC, 1, size_of::<SeccompNotifResp>() as u64);
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong =
    ior(SECCOMP_IOC_MAGIC, 2, size_of::<u64>() as u64);

const IOC_NRBITS: u64 = 8;
const IOC_TYPEBITS: u64 = 8;
const IOC_SIZEBITS: u64 = 14;
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;

const fn ior(type_: u64, nr: u64, size: u64) -> libc::c_ulong {
    (IOC_READ << IOC_DIRSHIFT | type_ << IOC_TYPESHIFT | nr << IOC_NRSHIFT | size << IOC_SIZESHIFT)
        as libc::c_ulong
}

const fn iowr(type_: u64, nr: u64, size: u64) -> libc::c_ulong {
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT
        | type_ << IOC_TYPESHIFT
        | nr << IOC_NRSHIFT
        | size << IOC_SIZESHIFT) as libc::c_ulong
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[derive(Debug)]
pub(crate) struct SeccompListenerPair {
    parent_fd: Option<i32>,
    child_fd: Option<i32>,
}

impl SeccompListenerPair {
    pub(crate) fn new() -> io::Result<Self> {
        let mut fds = [0; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            parent_fd: Some(fds[0]),
            child_fd: Some(fds[1]),
        })
    }

    pub(crate) fn child_fd(&self) -> Option<i32> {
        self.child_fd
    }

    pub(crate) fn close_child_in_parent(&mut self) {
        close_fd(self.child_fd.take());
    }

    pub(crate) fn recv_listener_fd(&mut self) -> io::Result<i32> {
        let fd =
            recv_fd(self.parent_fd.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "closed listener pair")
            })?)?;
        close_fd(self.parent_fd.take());
        Ok(fd)
    }
}

impl Drop for SeccompListenerPair {
    fn drop(&mut self) {
        close_fd(self.parent_fd.take());
        close_fd(self.child_fd.take());
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectSupervisorConfig {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) attribution: Option<ConnectAttributionTarget>,
    pub(crate) unix: UnixConnectPolicy,
}

/// Binary-restricted proxy policies: inet connects may only reach the proxy and
/// are recorded with the connecting executable.
#[derive(Debug, Clone)]
pub(crate) struct ConnectAttributionTarget {
    pub(crate) proxy_addr: SocketAddr,
    pub(crate) store: ConnectAttributionStore,
}

#[derive(Debug, Clone)]
pub(crate) enum UnixConnectPolicy {
    /// The kernel decides in the sandboxed task's own context (Landlock
    /// `RESOLVE_UNIX` and the task's mount namespace apply).
    Kernel,
    /// Pathname connects may reach only sockets beneath these directories.
    Beneath(UnixSocketRoots),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnixSocketRoots {
    roots: Vec<(u64, u64)>,
    connector: Credentials,
    deny_abstract: bool,
}

/// The identity the sandboxed task connects as. The supervisor connects with
/// its own credentials, so it re-checks the permissions this identity has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: Vec<u32>,
}

impl Credentials {
    pub(crate) fn current_process() -> io::Result<Self> {
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut groups = vec![0 as libc::gid_t; count as usize];
        let count = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        groups.truncate(count as usize);
        Ok(Self {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            groups,
        })
    }

    fn may(&self, metadata: &libc::stat, access: u32) -> bool {
        let mode = metadata.st_mode;
        let bits = if metadata.st_uid == self.uid {
            mode >> 6
        } else if metadata.st_gid == self.gid || self.groups.contains(&metadata.st_gid) {
            mode >> 3
        } else {
            mode
        };
        bits & access == access
    }
}

impl UnixSocketRoots {
    /// `deny_abstract` is for kernels whose Landlock cannot scope abstract
    /// Unix sockets to the sandbox.
    pub(crate) fn new(
        paths: &[PathBuf],
        connector: Credentials,
        deny_abstract: bool,
    ) -> io::Result<Self> {
        let mut roots = Vec::with_capacity(paths.len());
        for path in paths {
            let metadata = match std::fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if metadata.is_dir() {
                roots.push((metadata.dev(), metadata.ino()));
            }
        }
        Ok(Self {
            roots,
            connector,
            deny_abstract,
        })
    }

    fn contains(&self, metadata: &libc::stat) -> bool {
        self.roots.contains(&(metadata.st_dev, metadata.st_ino))
    }
}

enum NotifyOutcome {
    Return(i64),
    Errno(i32),
    Continue,
}

impl From<Result<i64, i32>> for NotifyOutcome {
    fn from(result: Result<i64, i32>) -> Self {
        match result {
            Ok(value) => Self::Return(value),
            Err(errno) => Self::Errno(errno),
        }
    }
}

pub(crate) struct ConnectAttributionSupervisor {
    stop_fd: Option<i32>,
    join: Option<JoinHandle<()>>,
}

impl ConnectAttributionSupervisor {
    pub(crate) fn start(listener_fd: i32, config: ConnectSupervisorConfig) -> io::Result<Self> {
        let stop_fd = eventfd()?;
        let thread_stop_fd = dup_cloexec(stop_fd)?;
        let join = std::thread::Builder::new()
            .name(format!("axis-connect-attribution-{}", config.sandbox_id))
            .spawn(move || supervisor_loop(listener_fd, thread_stop_fd, config))
            .map_err(io::Error::other)?;
        Ok(Self {
            stop_fd: Some(stop_fd),
            join: Some(join),
        })
    }

    pub(crate) fn stop(&mut self) {
        if let Some(stop_fd) = self.stop_fd.take() {
            let value = 1u64.to_ne_bytes();
            unsafe {
                libc::write(stop_fd, value.as_ptr() as *const libc::c_void, value.len());
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            close_fd(Some(stop_fd));
        }
    }
}

impl Drop for ConnectAttributionSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn send_listener_fd(socket_fd: i32, listener_fd: i32) -> Result<(), i32> {
    send_fd(socket_fd, listener_fd)
}

fn supervisor_loop(listener_fd: i32, stop_fd: i32, config: ConnectSupervisorConfig) {
    let mut poll_fds = [
        libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if ret < 0 {
            if current_errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if poll_fds[1].revents != 0 {
            break;
        }
        if (poll_fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
            break;
        }
        if (poll_fds[0].revents & libc::POLLIN) == 0 {
            continue;
        }

        match recv_notification(listener_fd) {
            Ok(notif) => handle_notification(listener_fd, notif, &config),
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
            Err(e) => {
                tracing::warn!(
                    "sandbox {}: seccomp notify receive failed: {e}",
                    config.sandbox_id
                );
            }
        }
    }

    close_fd(Some(listener_fd));
    close_fd(Some(stop_fd));
}

fn handle_notification(listener_fd: i32, notif: SeccompNotif, config: &ConnectSupervisorConfig) {
    let outcome = match process_notification(listener_fd, notif, config) {
        Ok(outcome) => outcome,
        Err(errno) => NotifyOutcome::Errno(errno),
    };
    let response = match outcome {
        NotifyOutcome::Return(value) => SeccompNotifResp {
            id: notif.id,
            val: value,
            error: 0,
            flags: 0,
        },
        NotifyOutcome::Errno(errno) => SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: -errno,
            flags: 0,
        },
        NotifyOutcome::Continue => SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        },
    };
    if let Err(e) = send_response(listener_fd, response) {
        tracing::warn!(
            "sandbox {}: seccomp notify response failed: {e}",
            config.sandbox_id
        );
    }
}

fn process_notification(
    listener_fd: i32,
    notif: SeccompNotif,
    config: &ConnectSupervisorConfig,
) -> Result<NotifyOutcome, i32> {
    if notif.data.arch != AUDIT_ARCH_X86_64 || notif.data.nr != SYS_CONNECT {
        return Err(libc::EPERM);
    }
    validate_notification(listener_fd, notif.id)?;

    let pid = notif.pid;
    let socket_fd = child_socket_fd(notif.data.args[0])?;
    let remote = read_remote_sockaddr(pid, notif.data.args[1], notif.data.args[2])?;

    Ok(match (remote.addr, &config.attribution) {
        (RemoteSockaddrKind::Inet(target), Some(attribution))
            if !socket_addr_matches(target, attribution.proxy_addr) =>
        {
            NotifyOutcome::Errno(libc::EPERM)
        }
        (RemoteSockaddrKind::Inet(target), Some(attribution)) => supervise_proxy_connect(
            pid,
            socket_fd,
            target,
            &remote.bytes,
            config.sandbox_id,
            attribution,
        )
        .into(),
        (RemoteSockaddrKind::Unix, _) => match (&config.unix, unix_target(&remote.bytes)) {
            (UnixConnectPolicy::Beneath(roots), UnixTarget::Pathname(path)) => {
                supervise_unix_pathname_connect(pid, socket_fd, path, roots, &|| {
                    validate_notification(listener_fd, notif.id)
                })
                .into()
            }
            (UnixConnectPolicy::Beneath(roots), UnixTarget::Abstract) if roots.deny_abstract => {
                NotifyOutcome::Errno(libc::EACCES)
            }
            _ => NotifyOutcome::Continue,
        },
        (RemoteSockaddrKind::Unsupported, Some(_)) => NotifyOutcome::Errno(libc::EAFNOSUPPORT),
        (RemoteSockaddrKind::Inet(_) | RemoteSockaddrKind::Unsupported, None) => {
            NotifyOutcome::Continue
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
enum UnixTarget<'a> {
    Pathname(&'a [u8]),
    Abstract,
    Unnamed,
}

fn unix_target(sockaddr: &[u8]) -> UnixTarget<'_> {
    let path = sockaddr
        .get(size_of::<libc::sa_family_t>()..)
        .unwrap_or_default();
    match path.first() {
        None => UnixTarget::Unnamed,
        Some(0) => UnixTarget::Abstract,
        Some(_) => {
            let len = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            UnixTarget::Pathname(&path[..len])
        }
    }
}

/// Connects the sandboxed task's socket to a pathname Unix socket only when the
/// socket the path resolves to, in the task's own root and cwd, lies beneath an
/// allowed directory and the task's identity could reach it. The connect goes
/// through the resolved inode, so the path cannot be swapped after the check.
/// The peer sees the supervisor's credentials (`SO_PEERCRED`), not the task's.
fn supervise_unix_pathname_connect(
    pid: u32,
    socket_fd: i32,
    path: &[u8],
    roots: &UnixSocketRoots,
    still_pending: &dyn Fn() -> Result<(), i32>,
) -> Result<i64, i32> {
    let target = open_unix_target(pid, path, roots, still_pending)?;
    let local_fd = duplicate_child_fd(pid, socket_fd).map_err(io_errno)?;
    let mut sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let proc_path = format!("/proc/self/fd/{}", target.as_raw_fd());
    for (dst, src) in sockaddr.sun_path.iter_mut().zip(proc_path.bytes()) {
        *dst = src as libc::c_char;
    }
    let len = size_of::<libc::sa_family_t>() + proc_path.len() + 1;
    let bytes = unsafe {
        std::slice::from_raw_parts(&sockaddr as *const libc::sockaddr_un as *const u8, len)
    };
    let result = connect_duplicate_fd(local_fd, bytes);
    close_fd(Some(local_fd));
    result
}

const MAX_UNIX_TARGET_DEPTH: usize = 256;

fn open_unix_target(
    pid: u32,
    path: &[u8],
    roots: &UnixSocketRoots,
    still_pending: &dyn Fn() -> Result<(), i32>,
) -> Result<OwnedFd, i32> {
    let proc_pid = procfs_pid(pid).map_err(io_errno)?;
    let root_fd = open_path(
        libc::AT_FDCWD,
        format!("/proc/{proc_pid}/root").as_bytes(),
        libc::O_DIRECTORY,
        0,
    )?;
    let root = fstat(root_fd.as_raw_fd())?;
    let (start, resolve) = if path.first() == Some(&b'/') {
        (root_fd, libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS)
    } else {
        let cwd = open_path(
            libc::AT_FDCWD,
            format!("/proc/{proc_pid}/cwd").as_bytes(),
            libc::O_DIRECTORY,
            0,
        )?;
        (cwd, libc::RESOLVE_NO_MAGICLINKS)
    };
    // The task may have died and its PID been reused while /proc was opened.
    still_pending()?;
    let split = path.iter().rposition(|&b| b == b'/');
    let (parent, name) = match split {
        Some(0) => (&b"/"[..], &path[1..]),
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (&b"."[..], path),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return Err(libc::ECONNREFUSED);
    }
    let parent = open_path(start.as_raw_fd(), parent, libc::O_DIRECTORY, resolve)?;
    let target = open_path(
        parent.as_raw_fd(),
        name,
        libc::O_NOFOLLOW,
        libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_BENEATH,
    )?;
    let metadata = fstat(target.as_raw_fd())?;
    match metadata.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => {}
        libc::S_IFLNK => return Err(libc::EACCES),
        _ => return Err(libc::ECONNREFUSED),
    }
    if !roots.connector.may(&metadata, 0o2) {
        return Err(libc::EACCES);
    }

    let mut dir = parent;
    for _ in 0..MAX_UNIX_TARGET_DEPTH {
        let metadata = fstat(dir.as_raw_fd())?;
        if !roots.connector.may(&metadata, 0o1) {
            return Err(libc::EACCES);
        }
        if roots.contains(&metadata) {
            return Ok(target);
        }
        if same_inode(&metadata, &root) {
            return Err(libc::EACCES);
        }
        let up = open_path(dir.as_raw_fd(), b"..", libc::O_DIRECTORY, 0)?;
        if same_inode(&fstat(up.as_raw_fd())?, &metadata) {
            return Err(libc::EACCES);
        }
        dir = up;
    }
    Err(libc::EACCES)
}

/// Notification PIDs are in the supervisor's PID namespace, which may differ
/// from the one `/proc` is mounted for. A pidfd's fdinfo reports the PID in the
/// namespace of the procfs it is read through.
fn procfs_pid(pid: u32) -> io::Result<u32> {
    let pidfd = pidfd_open(pid)?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}"));
    close_fd(Some(pidfd));
    fdinfo?
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<i64>().ok())
        .and_then(|value| u32::try_from(value).ok())
        .filter(|&value| value > 0)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))
}

fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn open_path(dirfd: i32, path: &[u8], flags: i32, resolve: u64) -> Result<OwnedFd, i32> {
    let path = std::ffi::CString::new(path).map_err(|_| libc::EINVAL)?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC | flags) as u64;
    how.resolve = resolve;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const libc::open_how,
            size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        Err(match current_errno() {
            libc::ENOENT => libc::ENOENT,
            libc::ENOTDIR => libc::ENOTDIR,
            _ => libc::EACCES,
        })
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

fn fstat(fd: i32) -> Result<libc::stat, i32> {
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        Err(current_errno())
    } else {
        Ok(unsafe { metadata.assume_init() })
    }
}

fn supervise_proxy_connect(
    pid: u32,
    socket_fd: i32,
    proxy_addr: SocketAddr,
    sockaddr: &[u8],
    sandbox_id: SandboxId,
    config: &ConnectAttributionTarget,
) -> Result<i64, i32> {
    let local_fd = duplicate_child_fd(pid, socket_fd).map_err(io_errno)?;
    let result =
        supervise_proxy_connect_on_fd(pid, local_fd, proxy_addr, sockaddr, sandbox_id, config);
    close_fd(Some(local_fd));
    result
}

fn supervise_proxy_connect_on_fd(
    pid: u32,
    local_fd: i32,
    proxy_addr: SocketAddr,
    sockaddr: &[u8],
    sandbox_id: SandboxId,
    config: &ConnectAttributionTarget,
) -> Result<i64, i32> {
    ensure_tcp_stream_socket(local_fd).map_err(io_errno)?;
    let (path, sha256) = process_exe_fingerprint(pid).map_err(io_errno)?;
    let connect_result = connect_duplicate_fd(local_fd, sockaddr);
    let should_record = matches!(connect_result, Ok(0))
        || matches!(connect_result, Err(errno) if errno == libc::EINPROGRESS);
    if should_record {
        let peer_addr = getsockname_inet(local_fd).map_err(io_errno)?;
        config
            .store
            .insert(ConnectAttributionRecord {
                sandbox_id,
                peer_addr,
                proxy_addr,
                pid,
                executable_path: path,
                executable_sha256: sha256,
                source: ConnectAttributionSource::SeccompNotify,
            })
            .map_err(|_| libc::EPERM)?;
    }
    connect_result
}

fn child_socket_fd(raw: u64) -> Result<i32, i32> {
    i32::try_from(raw).map_err(|_| libc::EBADF)
}

fn recv_notification(listener_fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = MaybeUninit::<SeccompNotif>::zeroed();
    let ret = unsafe { libc::ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { notif.assume_init() })
    }
}

fn send_response(listener_fd: i32, mut response: SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &mut response as *mut SeccompNotifResp,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn validate_notification(listener_fd: i32, mut id: u64) -> Result<(), i32> {
    let ret = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &mut id as *mut u64,
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteSockaddrKind {
    Inet(SocketAddr),
    Unix,
    Unsupported,
}

#[derive(Debug)]
struct RemoteSockaddr {
    bytes: Vec<u8>,
    addr: RemoteSockaddrKind,
}

fn read_remote_sockaddr(pid: u32, remote_ptr: u64, remote_len: u64) -> Result<RemoteSockaddr, i32> {
    if remote_ptr == 0 || remote_len < size_of::<libc::sa_family_t>() as u64 {
        return Err(libc::EFAULT);
    }
    let len = usize::try_from(remote_len)
        .ok()
        .filter(|len| *len <= size_of::<libc::sockaddr_storage>())
        .ok_or(libc::EINVAL)?;
    let mut bytes = vec![0u8; len];
    process_read(pid, remote_ptr, &mut bytes).map_err(io_errno)?;
    let addr = parse_sockaddr(&bytes);
    Ok(RemoteSockaddr { bytes, addr })
}

fn process_read(pid: u32, remote_ptr: u64, bytes: &mut [u8]) -> io::Result<()> {
    let mut local = libc::iovec {
        iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut remote = libc::iovec {
        iov_base: remote_ptr as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            pid as libc::pid_t,
            &mut local as *mut libc::iovec,
            1usize,
            &mut remote as *mut libc::iovec,
            1usize,
            0usize,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret as usize != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short process_vm_readv for sockaddr",
        ));
    }
    Ok(())
}

fn parse_sockaddr(bytes: &[u8]) -> RemoteSockaddrKind {
    if bytes.len() < size_of::<libc::sa_family_t>() {
        return RemoteSockaddrKind::Unsupported;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        libc::AF_INET if bytes.len() >= size_of::<libc::sockaddr_in>() => {
            let addr = unsafe { read_unaligned::<libc::sockaddr_in>(bytes) };
            let port = u16::from_be(addr.sin_port);
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            RemoteSockaddrKind::Inet(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if bytes.len() >= size_of::<libc::sockaddr_in6>() => {
            let addr = unsafe { read_unaligned::<libc::sockaddr_in6>(bytes) };
            let port = u16::from_be(addr.sin6_port);
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            RemoteSockaddrKind::Inet(SocketAddr::new(IpAddr::V6(ip), port))
        }
        libc::AF_UNIX => RemoteSockaddrKind::Unix,
        _ => RemoteSockaddrKind::Unsupported,
    }
}

unsafe fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    let mut value = MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            value.as_mut_ptr() as *mut u8,
            size_of::<T>(),
        );
        value.assume_init()
    }
}

fn duplicate_child_fd(pid: u32, fd: i32) -> io::Result<i32> {
    let pidfd = pidfd_open(pid)?;
    let duplicated = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0u32) };
    let error = io::Error::last_os_error();
    close_fd(Some(pidfd));
    if duplicated < 0 {
        Err(error)
    } else {
        Ok(duplicated as i32)
    }
}

fn ensure_tcp_stream_socket(fd: i32) -> io::Result<()> {
    let socket_type = socket_int_option(fd, libc::SOL_SOCKET, libc::SO_TYPE)?;
    if socket_type != libc::SOCK_STREAM {
        return Err(io::Error::from_raw_os_error(libc::EPROTOTYPE));
    }

    let protocol = socket_int_option(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)?;
    if protocol != libc::IPPROTO_TCP {
        return Err(io::Error::from_raw_os_error(libc::EPROTONOSUPPORT));
    }
    Ok(())
}

fn socket_int_option(fd: i32, level: i32, name: i32) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::c_int>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected getsockopt integer option size",
        ));
    }
    Ok(value)
}

fn pidfd_open(pid: u32) -> io::Result<i32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}

fn connect_duplicate_fd(fd: i32, sockaddr: &[u8]) -> Result<i64, i32> {
    let ret = unsafe {
        libc::connect(
            fd,
            sockaddr.as_ptr() as *const libc::sockaddr,
            sockaddr.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(current_errno())
    } else {
        Ok(ret as i64)
    }
}

fn getsockname_inet(fd: i32) -> io::Result<SocketAddr> {
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd,
            storage.as_mut_ptr() as *mut libc::sockaddr,
            &mut len as *mut libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr() as *const u8, len as usize) };
    match parse_sockaddr(bytes) {
        RemoteSockaddrKind::Inet(addr) => Ok(addr),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "getsockname did not return an inet socket address",
        )),
    }
}

fn process_exe_fingerprint(pid: u32) -> io::Result<(PathBuf, String)> {
    let exe_link = PathBuf::from(format!("/proc/{pid}/exe"));
    let mut file = File::open(&exe_link)?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let path = std::fs::read_link(fd_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let sha256 = Sha256::digest(&bytes);
    Ok((path, hex_encode(sha256)))
}

fn socket_addr_matches(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port() && ip_addr_matches(left.ip(), right.ip())
}

fn ip_addr_matches(left: IpAddr, right: IpAddr) -> bool {
    if left == right {
        return true;
    }
    match (left, right) {
        (IpAddr::V6(left), IpAddr::V4(right)) => left.to_ipv4_mapped() == Some(right),
        (IpAddr::V4(left), IpAddr::V6(right)) => right.to_ipv4_mapped() == Some(left),
        _ => false,
    }
}

fn eventfd() -> io::Result<i32> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn dup_cloexec(fd: i32) -> io::Result<i32> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(duplicated)
    }
}

fn send_fd(socket_fd: i32, fd_to_send: i32) -> Result<(), i32> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(size_of::<i32>() as libc::c_uint) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr);
        if cmsg.is_null() {
            return Err(libc::EINVAL);
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as libc::c_uint) as usize;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut i32, fd_to_send);
        msg.msg_controllen = (*cmsg).cmsg_len;
        let ret = libc::sendmsg(socket_fd, &msg as *const libc::msghdr, 0);
        if ret < 0 {
            Err(current_errno())
        } else {
            Ok(())
        }
    }
}

fn recv_fd(socket_fd: i32) -> io::Result<i32> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(size_of::<i32>() as libc::c_uint) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    let ret = unsafe {
        libc::recvmsg(
            socket_fd,
            &mut msg as *mut libc::msghdr,
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "listener fd channel closed",
        ));
    }
    if ret != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "listener fd message has unexpected payload length",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "listener fd control message was truncated",
        ));
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len != libc::CMSG_LEN(size_of::<i32>() as libc::c_uint) as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "listener fd message missing valid SCM_RIGHTS payload",
            ));
        }
        Ok(std::ptr::read(libc::CMSG_DATA(cmsg) as *const i32))
    }
}

fn close_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe {
            libc::close(fd);
        }
    }
}

fn io_errno(error: io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::seccomp;
    use axis_core::policy::ProcessPolicy;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn parse_sockaddr_accepts_ipv4_and_ipv6() {
        let v4 = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 3128u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be(),
            },
            sin_zero: [0; 8],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &v4 as *const libc::sockaddr_in as *const u8,
                size_of::<libc::sockaddr_in>(),
            )
        };
        assert_eq!(
            parse_sockaddr(bytes),
            RemoteSockaddrKind::Inet("127.0.0.1:3128".parse().unwrap())
        );

        let v6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &v6 as *const libc::sockaddr_in6 as *const u8,
                size_of::<libc::sockaddr_in6>(),
            )
        };
        assert_eq!(
            parse_sockaddr(bytes),
            RemoteSockaddrKind::Inet("[::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn socket_addr_match_allows_ipv4_mapped_addresses_only_with_same_port() {
        assert!(socket_addr_matches(
            "127.0.0.1:3128".parse().unwrap(),
            "[::ffff:127.0.0.1]:3128".parse().unwrap()
        ));
        assert!(!socket_addr_matches(
            "127.0.0.1:3129".parse().unwrap(),
            "[::ffff:127.0.0.1]:3128".parse().unwrap()
        ));
    }

    #[test]
    fn listener_fd_pair_transfers_fd_once() {
        let mut pair = SeccompListenerPair::new().unwrap();
        let child_fd = pair.child_fd().unwrap();
        let (read_end, mut write_end) = UnixStream::pair().unwrap();
        let read_fd = read_end.into_raw_fd();
        send_listener_fd(child_fd, read_fd).unwrap();
        close_fd(Some(child_fd));
        pair.child_fd = None;
        close_fd(Some(read_fd));

        let received = pair.recv_listener_fd().unwrap();
        assert!(
            fd_cloexec(received),
            "received listener fd should be close-on-exec"
        );
        write_end.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(received, byte.as_mut_ptr() as *mut libc::c_void, byte.len()) };
        assert_eq!(n, 1);
        assert_eq!(byte, [b'x']);
        close_fd(Some(received));
    }

    #[test]
    fn listener_fd_pair_rejects_message_without_fd() {
        let mut pair = SeccompListenerPair::new().unwrap();
        let child_fd = pair.child_fd().unwrap();
        let byte = [b'x'];
        let sent = unsafe {
            libc::send(
                child_fd,
                byte.as_ptr() as *const libc::c_void,
                byte.len(),
                0,
            )
        };
        assert_eq!(sent, 1);

        let err = pair.recv_listener_fd().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("SCM_RIGHTS"));
    }

    #[test]
    fn process_exe_fingerprint_hashes_current_executable() {
        let pid = std::process::id();
        let (path, sha256) = process_exe_fingerprint(pid).unwrap();
        assert!(!path.as_os_str().is_empty());
        assert_eq!(sha256.len(), 64);
        assert!(sha256.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn tcp_stream_socket_validation_rejects_udp_datagrams() {
        let tcp_fd = open_socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(ensure_tcp_stream_socket(tcp_fd).is_ok());
        close_fd(Some(tcp_fd));

        let udp_fd = open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let err = ensure_tcp_stream_socket(udp_fd).unwrap_err();
        close_fd(Some(udp_fd));
        assert_eq!(err.raw_os_error(), Some(libc::EPROTOTYPE));
    }

    #[test]
    fn read_remote_sockaddr_rejects_invalid_remote_shape() {
        let pid = std::process::id();
        assert_eq!(
            read_remote_sockaddr(pid, 0, size_of::<libc::sa_family_t>() as u64).unwrap_err(),
            libc::EFAULT
        );
        assert_eq!(read_remote_sockaddr(pid, 1, 1).unwrap_err(), libc::EFAULT);
        assert_eq!(
            read_remote_sockaddr(pid, 1, size_of::<libc::sockaddr_storage>() as u64 + 1)
                .unwrap_err(),
            libc::EINVAL
        );
    }

    #[test]
    fn gated_seccomp_notify_records_connecting_executable_before_fd_handoff_exec() {
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

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let sandbox_id = SandboxId::new();
        let store = ConnectAttributionStore::default();
        let mut pair = SeccompListenerPair::new().unwrap();
        let child_socket_fd = pair.child_fd().unwrap();
        let filter = seccomp::prepare_seccomp_with_options(
            &ProcessPolicy::default(),
            seccomp::SeccompOptions::default().notify_connect(),
        )
        .unwrap();

        let mut child = {
            let mut cmd = Command::new(&python);
            cmd.arg("-c")
                .arg(
                    r#"
import os
import socket

host = os.environ["AXIS_TEST_PROXY_HOST"]
port = int(os.environ["AXIS_TEST_PROXY_PORT"])
shell = os.environ["AXIS_TEST_ALLOWED_SHELL"]

sock = socket.create_connection((host, port), timeout=5)
os.dup2(sock.fileno(), 3)
os.set_inheritable(3, True)
os.execv(shell, [shell, "-c", "sleep 1"])
"#,
                )
                .env("AXIS_TEST_PROXY_HOST", proxy_addr.ip().to_string())
                .env("AXIS_TEST_PROXY_PORT", proxy_addr.port().to_string())
                .env("AXIS_TEST_ALLOWED_SHELL", &shell)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                cmd.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    match filter.apply_current_process_with_listener() {
                        Ok(listener_fd) => {
                            if let Err(errno) = send_listener_fd(child_socket_fd, listener_fd) {
                                libc::close(listener_fd);
                                libc::close(child_socket_fd);
                                return Err(io::Error::from_raw_os_error(errno));
                            }
                            libc::close(listener_fd);
                            libc::close(child_socket_fd);
                            Ok(())
                        }
                        Err(errno) => {
                            libc::close(child_socket_fd);
                            Err(io::Error::from_raw_os_error(errno))
                        }
                    }
                });
            }
            cmd.spawn().unwrap()
        };

        pair.close_child_in_parent();
        let listener_fd = pair.recv_listener_fd().unwrap();
        let mut supervisor = ConnectAttributionSupervisor::start(
            listener_fd,
            ConnectSupervisorConfig {
                sandbox_id,
                attribution: Some(ConnectAttributionTarget {
                    proxy_addr,
                    store: store.clone(),
                }),
                unix: UnixConnectPolicy::Kernel,
            },
        )
        .unwrap();

        let (accepted, peer_addr) = accept_with_deadline(&listener, Duration::from_secs(5));
        let record = consume_with_deadline(&store, sandbox_id, peer_addr, proxy_addr);
        drop(accepted);
        supervisor.stop();
        let _ = child.kill();
        let _ = child.wait();

        let canonical_shell = std::fs::canonicalize(&shell).unwrap_or(shell);
        assert_ne!(
            record.executable_path, canonical_shell,
            "connect-time attribution used post-connect exec identity"
        );
        assert_eq!(record.executable_path, python);
    }

    #[test]
    fn gated_seccomp_notify_limits_unix_connect_to_allowed_roots() {
        if std::env::var("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION").as_deref() != Ok("1") {
            eprintln!(
                "seccomp notify unix supervision proof skipped; set AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1"
            );
            return;
        }
        let Some(python) = find_on_path("python3") else {
            panic!("AXIS_TEST_SECCOMP_NOTIFY_ATTRIBUTION=1 requires python3 on PATH");
        };

        let fixture = UnixFixture::new();
        let abstract_name = format!("axis-test-{}", SandboxId::new());
        let abstract_listener = {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
                .unwrap();
            std::os::unix::net::UnixListener::bind_addr(&addr).unwrap()
        };
        let mut pair = SeccompListenerPair::new().unwrap();
        let child_socket_fd = pair.child_fd().unwrap();
        let filter = seccomp::prepare_seccomp_with_options(
            &ProcessPolicy::default(),
            seccomp::SeccompOptions::default().notify_connect(),
        )
        .unwrap();

        let mut cmd = Command::new(&python);
        cmd.arg("-c")
            .arg(
                r#"
import errno
import os
import socket
import sys

def connect(addr):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(addr)
        return 0
    except OSError as e:
        return e.errno
    finally:
        s.close()

results = [
    connect(os.environ["AXIS_TEST_ALLOWED"]),
    connect(os.environ["AXIS_TEST_OUTSIDE"]),
    connect("\0" + os.environ["AXIS_TEST_ABSTRACT"]),
]
expected = [0, errno.EACCES, errno.EACCES]
print(results, file=sys.stderr)
sys.exit(0 if results == expected else 1)
"#,
            )
            .env(
                "AXIS_TEST_ALLOWED",
                fixture.dir.path().join("allowed/nested/in.sock"),
            )
            .env(
                "AXIS_TEST_OUTSIDE",
                fixture.dir.path().join("outside/out.sock"),
            )
            .env("AXIS_TEST_ABSTRACT", &abstract_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let result = filter
                    .apply_current_process_with_listener()
                    .and_then(|listener_fd| {
                        let sent = send_listener_fd(child_socket_fd, listener_fd);
                        libc::close(listener_fd);
                        sent
                    });
                libc::close(child_socket_fd);
                result.map_err(io::Error::from_raw_os_error)
            });
        }
        let child = cmd.spawn().unwrap();
        pair.close_child_in_parent();
        let listener_fd = pair.recv_listener_fd().unwrap();
        let mut supervisor = ConnectAttributionSupervisor::start(
            listener_fd,
            ConnectSupervisorConfig {
                sandbox_id: SandboxId::new(),
                attribution: None,
                unix: UnixConnectPolicy::Beneath(fixture.roots.clone()),
            },
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        supervisor.stop();
        drop(abstract_listener);

        assert!(
            output.status.success(),
            "supervised unix connects: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn procfs_pid_reports_pid_in_procfs_namespace() {
        let child = Command::new("sleep").arg("5").spawn().unwrap();
        let mut child = child;
        assert_eq!(procfs_pid(child.id()).unwrap(), child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            procfs_pid(child.id()).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn unix_target_classifies_pathname_abstract_and_unnamed() {
        let family = (libc::AF_UNIX as libc::sa_family_t).to_ne_bytes();
        let addr = |path: &[u8]| [&family[..], path].concat();

        assert_eq!(unix_target(&family), UnixTarget::Unnamed);
        assert_eq!(unix_target(&addr(b"\0bus")), UnixTarget::Abstract);
        assert_eq!(
            unix_target(&addr(b"/run/s.sock")),
            UnixTarget::Pathname(b"/run/s.sock")
        );
        assert_eq!(
            unix_target(&addr(b"rel.sock\0trailing")),
            UnixTarget::Pathname(b"rel.sock")
        );
    }

    #[test]
    fn credentials_check_owner_group_then_other_bits() {
        let creds = Credentials {
            uid: 1000,
            gid: 1000,
            groups: vec![20],
        };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_uid = 1000;
        st.st_gid = 0;
        st.st_mode = libc::S_IFSOCK | 0o077;
        assert!(!creds.may(&st, 0o2), "owner bits must decide for the owner");

        st.st_uid = 0;
        st.st_gid = 20;
        st.st_mode = libc::S_IFSOCK | 0o620;
        assert!(creds.may(&st, 0o2));
        st.st_mode = libc::S_IFSOCK | 0o602;
        assert!(!creds.may(&st, 0o2), "group bits must decide for a member");

        st.st_gid = 0;
        assert!(creds.may(&st, 0o2));
        st.st_mode = libc::S_IFSOCK | 0o660;
        assert!(!creds.may(&st, 0o2));

        let root = Credentials {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
        };
        st.st_uid = 1000;
        st.st_gid = 1000;
        st.st_mode = libc::S_IFSOCK | 0o600;
        assert!(!root.may(&st, 0o2), "root gets no DAC override");
    }

    struct UnixFixture {
        dir: tempfile::TempDir,
        roots: UnixSocketRoots,
        _listeners: Vec<std::os::unix::net::UnixListener>,
    }

    impl UnixFixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let allowed = dir.path().join("allowed");
            let outside = dir.path().join("outside");
            std::fs::create_dir_all(allowed.join("nested")).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let listeners = vec![
                std::os::unix::net::UnixListener::bind(allowed.join("nested/in.sock")).unwrap(),
                std::os::unix::net::UnixListener::bind(outside.join("out.sock")).unwrap(),
            ];
            std::fs::write(allowed.join("file"), b"").unwrap();
            std::os::unix::fs::symlink(&outside, allowed.join("dir-link")).unwrap();
            std::os::unix::fs::symlink(outside.join("out.sock"), allowed.join("sock-link"))
                .unwrap();
            let roots = UnixSocketRoots::new(
                &[allowed, dir.path().join("missing")],
                Credentials::current_process().unwrap(),
                true,
            )
            .unwrap();
            Self {
                dir,
                roots,
                _listeners: listeners,
            }
        }

        fn path(&self, relative: &str) -> Vec<u8> {
            self.dir
                .path()
                .join(relative)
                .into_os_string()
                .into_encoded_bytes()
        }

        fn connect(&self, path: &[u8]) -> Result<i64, i32> {
            let fd = open_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let result =
                supervise_unix_pathname_connect(std::process::id(), fd, path, &self.roots, &|| {
                    Ok(())
                });
            close_fd(Some(fd));
            result
        }
    }

    #[test]
    fn unix_connect_supervision_allows_sockets_beneath_roots() {
        let fixture = UnixFixture::new();
        assert_eq!(
            fixture.connect(&fixture.path("allowed/nested/in.sock")),
            Ok(0)
        );
        assert_eq!(
            fixture.connect(&fixture.path("allowed/./nested/../nested/in.sock")),
            Ok(0)
        );
    }

    #[test]
    fn unix_connect_supervision_allows_relative_paths_from_cwd() {
        let fixture = UnixFixture::new();
        let cwd = std::env::current_dir().unwrap();
        let depth = std::fs::canonicalize(&cwd).unwrap().components().count() - 1;
        let target = std::fs::canonicalize(fixture.dir.path()).unwrap();
        let relative = format!(
            "{}{}/allowed/nested/in.sock",
            "../".repeat(depth),
            target.strip_prefix("/").unwrap().display()
        );
        assert_eq!(fixture.connect(relative.as_bytes()), Ok(0));
    }

    #[test]
    fn unix_connect_supervision_denies_sockets_outside_roots() {
        let fixture = UnixFixture::new();
        for path in [
            fixture.path("outside/out.sock"),
            fixture.path("allowed/../outside/out.sock"),
            fixture.path("allowed/dir-link/out.sock"),
            fixture.path("allowed/sock-link"),
        ] {
            assert_eq!(
                fixture.connect(&path),
                Err(libc::EACCES),
                "{}",
                String::from_utf8_lossy(&path)
            );
        }
    }

    #[test]
    fn unix_connect_supervision_denies_magic_links() {
        let fixture = UnixFixture::new();
        let outside = File::open(fixture.dir.path().join("outside")).unwrap();
        let via_fd = format!("/proc/self/fd/{}/out.sock", outside.as_raw_fd());
        let via_root = format!(
            "/proc/self/root{}",
            fixture.dir.path().join("outside/out.sock").display()
        );
        assert_eq!(fixture.connect(via_fd.as_bytes()), Err(libc::EACCES));
        assert_eq!(fixture.connect(via_root.as_bytes()), Err(libc::EACCES));
    }

    #[test]
    fn unix_connect_supervision_rechecks_connector_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = UnixFixture::new();
        let socket = fixture.dir.path().join("allowed/nested/in.sock");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(
            fixture.connect(&fixture.path("allowed/nested/in.sock")),
            Err(libc::EACCES)
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o700)).unwrap();

        let nested = fixture.dir.path().join("allowed/nested");
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = fixture.connect(&fixture.path("allowed/nested/in.sock"));
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(libc::EACCES));
    }

    #[test]
    fn unix_connect_supervision_refuses_non_sockets_and_missing_paths() {
        let fixture = UnixFixture::new();
        assert_eq!(
            fixture.connect(&fixture.path("allowed/file")),
            Err(libc::ECONNREFUSED)
        );
        assert_eq!(
            fixture.connect(&fixture.path("allowed/missing.sock")),
            Err(libc::ENOENT)
        );
        assert_eq!(
            fixture.connect(&fixture.path("allowed/nested/..")),
            Err(libc::ECONNREFUSED)
        );
    }

    #[test]
    fn unix_socket_roots_skip_missing_and_non_directory_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"").unwrap();
        let roots = UnixSocketRoots::new(
            &[
                dir.path().join("file"),
                dir.path().join("missing"),
                dir.path().to_path_buf(),
            ],
            Credentials::current_process().unwrap(),
            false,
        )
        .unwrap();
        let metadata = std::fs::metadata(dir.path()).unwrap();
        assert_eq!(roots.roots, vec![(metadata.dev(), metadata.ino())]);
    }

    fn accept_with_deadline(
        listener: &std::net::TcpListener,
        timeout: Duration,
    ) -> (std::net::TcpStream, SocketAddr) {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok(result) => return result,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("listener accept failed: {e}"),
            }
        }
    }

    fn consume_with_deadline(
        store: &ConnectAttributionStore,
        sandbox_id: SandboxId,
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    ) -> ConnectAttributionRecord {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match store.consume(sandbox_id, peer_addr, proxy_addr) {
                Ok(record) => return record,
                Err(axis_core::connect_attribution::ConnectAttributionError::Missing {
                    ..
                }) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("connect attribution record missing: {e}"),
            }
        }
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

    fn open_socket(domain: i32, socket_type: i32, protocol: i32) -> i32 {
        let fd = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, protocol) };
        assert!(fd >= 0, "socket failed: {}", io::Error::last_os_error());
        fd
    }

    fn fd_cloexec(fd: i32) -> bool {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
        flags & libc::FD_CLOEXEC != 0
    }
}
