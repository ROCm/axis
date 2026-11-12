// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! seccomp-BPF syscall filtering — default-deny whitelist mode.
//!
//! Builds a BPF program that ALLOWS only explicitly whitelisted syscalls
//! and BLOCKS everything else with EPERM. This is the strongest seccomp
//! mode — a compromised sandbox process cannot use any syscall not on
//! the whitelist.

use axis_core::policy::{Policy, ProcessPolicy};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;

// ── seccomp constants ─────────────────────────────────────────────────────

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_K: u16 = 0x00;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const ARG_SIZE: u32 = 8;

const AF_UNIX: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_TYPE_MASK: u32 = 0xf;

const SYS_SOCKET: u32 = 41;
const SYS_CONNECT: u32 = 42;
const SYS_SOCKETPAIR: u32 = 53;
const SYS_CLONE: u32 = 56;
const SYS_KILL: u32 = 62;
const SYS_SETPGID: u32 = 109;
const SYS_SETSID: u32 = 112;
const SYS_TKILL: u32 = 200;
const SYS_SCHED_SETAFFINITY: u32 = 203;
const SYS_TGKILL: u32 = 234;
const SYS_UNSHARE: u32 = 272;
const SYS_SET_ROBUST_LIST: u32 = 273;
const SYS_TIMERFD_CREATE: u32 = 283;
const SYS_TIMERFD_SETTIME: u32 = 286;
const SYS_TIMERFD_GETTIME: u32 = 287;
const SYS_EXECVEAT: u32 = 322;
const SYS_CLONE3: u32 = 435;

const EXECVEAT_FLAGS_ARG: usize = 4;
const AT_EMPTY_PATH: u32 = 0x1000;
const DANGEROUS_UNSHARE_FLAGS: u32 = libc::CLONE_NEWNS as u32
    | libc::CLONE_NEWUTS as u32
    | libc::CLONE_NEWIPC as u32
    | libc::CLONE_NEWUSER as u32
    | libc::CLONE_NEWPID as u32
    | libc::CLONE_NEWNET as u32
    | libc::CLONE_NEWCGROUP as u32;

/// Syscalls that are always allowed in default-deny mode.
/// These are the minimum set needed for Python, shell, and most userspace
/// programs to function. Carefully curated to avoid sandbox escape vectors.
const WHITELIST: &[(u32, &str)] = &[
    // File I/O
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (28, "madvise"),
    (32, "dup"),
    (33, "dup2"),
    (34, "pause"),
    (35, "nanosleep"),
    (37, "alarm"),
    (38, "setitimer"),
    (39, "getpid"),
    (40, "sendfile"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (48, "shutdown"),
    (49, "bind"),
    (50, "listen"),
    (51, "getsockname"),
    (52, "getpeername"),
    (53, "socketpair"),
    (54, "setsockopt"),
    (55, "getsockopt"),
    (56, "clone"), // namespace flags are blocked by conditional rules
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (63, "uname"),
    (72, "fcntl"),
    (73, "flock"),
    (74, "fsync"),
    (75, "fdatasync"),
    (76, "truncate"),
    (77, "ftruncate"),
    (78, "getdents"),
    (79, "getcwd"),
    (80, "chdir"),
    (81, "fchdir"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (89, "readlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (92, "chown"),
    (93, "fchown"),
    (95, "umask"),
    (96, "gettimeofday"),
    (97, "getrlimit"),
    (98, "getrusage"),
    (99, "sysinfo"),
    (100, "times"),
    (102, "getuid"),
    (104, "getgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (110, "getppid"),
    (111, "getpgrp"),
    (115, "getgroups"),
    (124, "getsid"),
    (131, "sigaltstack"),
    (137, "statfs"),
    (138, "fstatfs"),
    (140, "getpriority"),
    (144, "sched_setscheduler"),
    (145, "sched_getscheduler"),
    (146, "sched_get_priority_max"),
    (147, "sched_get_priority_min"),
    (157, "prctl"),
    (158, "arch_prctl"),
    (186, "gettid"),
    (202, "futex"),
    (204, "sched_getaffinity"),
    (217, "getdents64"),
    (218, "set_tid_address"),
    (228, "clock_gettime"),
    (229, "clock_getres"),
    (230, "clock_nanosleep"),
    (231, "exit_group"),
    (232, "epoll_wait"),
    (233, "epoll_ctl"),
    (257, "openat"),
    (258, "mkdirat"),
    (260, "fchownat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (268, "fchmodat"),
    (269, "faccessat"),
    (270, "pselect6"),
    (271, "ppoll"),
    (SYS_SET_ROBUST_LIST, "set_robust_list"),
    (280, "utimensat"),
    (281, "epoll_pwait"),
    (SYS_TIMERFD_CREATE, "timerfd_create"),
    (284, "eventfd"),
    (SYS_TIMERFD_SETTIME, "timerfd_settime"),
    (SYS_TIMERFD_GETTIME, "timerfd_gettime"),
    (288, "accept4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (302, "prlimit64"),
    (309, "getcpu"),
    (316, "renameat2"),
    (318, "getrandom"),
    (322, "execveat"),
    (332, "statx"),
    (334, "rseq"),
    (436, "close_range"),
    (439, "faccessat2"),
    (448, "process_mrelease"),
];

/// Landlock does not check xattr calls, and an `open` with access mode 3 passes
/// it with no rights, so even the fd-based reads would reach paths the policy
/// denies. `EOPNOTSUPP` makes tools treat the file as having no ACLs instead of
/// reporting an error.
const UNSUPPORTED_XATTR_SYSCALLS: &[(u32, &str)] = &[
    (188, "setxattr"),
    (189, "lsetxattr"),
    (190, "fsetxattr"),
    (191, "getxattr"),
    (192, "lgetxattr"),
    (193, "fgetxattr"),
    (194, "listxattr"),
    (195, "llistxattr"),
    (196, "flistxattr"),
    (197, "removexattr"),
    (198, "lremovexattr"),
    (199, "fremovexattr"),
    (463, "setxattrat"),
    (464, "getxattrat"),
    (465, "listxattrat"),
    (466, "removexattrat"),
];

/// Each pair is an allowed syscall and its fd or `*at` variant, which reaches
/// the same checks. A policy that blocks the first by name blocks the second
/// too, as it did when the variant was not allowlisted.
const FD_AND_AT_VARIANTS: &[(&str, &str)] = &[
    ("chdir", "fchdir"),
    ("chmod", "fchmod"),
    ("chown", "fchown"),
    ("link", "linkat"),
    ("symlink", "symlinkat"),
    ("close", "close_range"),
];

/// Allowed only when the policy asks for AMD GPU passthrough. The ROCm runtime
/// pins its helper threads with `pthread_setaffinity_np` and stops initializing
/// when that is refused; `sched_setaffinity` can name any thread of the same
/// user, so it stays out of the default whitelist. The NUMA memory-policy
/// calls stay denied: ROCm treats a refused `mbind` as success (as under
/// Docker's default profile) and skips binding when NUMA is unavailable.
const GPU_RUNTIME_SYSCALLS: &[(u32, &str)] = &[(SYS_SCHED_SETAFFINITY, "sched_setaffinity")];

/// BPF instruction.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProg {
    len: u16,
    filter: *const BpfInsn,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedSeccompFilter {
    insns: Vec<BpfInsn>,
}

impl PreparedSeccompFilter {
    pub(crate) fn apply_current_process(&self) -> Result<(), i32> {
        self.apply_current_process_with_flags(libc::SECCOMP_FILTER_FLAG_TSYNC as libc::c_long)
            .map(|_| ())
    }

    pub(crate) fn apply_current_process_with_listener(&self) -> Result<i32, i32> {
        self.apply_current_process_with_flags(
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
        )
    }

    fn apply_current_process_with_flags(&self, flags: libc::c_long) -> Result<i32, i32> {
        let prog = BpfProg {
            len: self.insns.len() as u16,
            filter: self.insns.as_ptr(),
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                1 as libc::c_long, // SECCOMP_SET_MODE_FILTER
                flags,
                &prog as *const BpfProg as libc::c_long,
            )
        };

        if ret < 0 {
            Err(current_errno())
        } else {
            Ok(ret as i32)
        }
    }

    pub(crate) fn export_bpf_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.insns.len() * std::mem::size_of::<BpfInsn>());
        for insn in &self.insns {
            bytes.extend_from_slice(&insn.code.to_ne_bytes());
            bytes.push(insn.jt);
            bytes.push(insn.jf);
            bytes.extend_from_slice(&insn.k.to_ne_bytes());
        }
        bytes
    }

    fn from_bpf_bytes(bytes: &[u8]) -> Result<Self, String> {
        const BPF_INSN_SIZE: usize = std::mem::size_of::<BpfInsn>();

        if bytes.is_empty() {
            return Err("seccomp filter is empty".into());
        }
        if !bytes.len().is_multiple_of(BPF_INSN_SIZE) {
            return Err(format!(
                "seccomp filter has invalid byte length {}, expected a multiple of {BPF_INSN_SIZE}",
                bytes.len()
            ));
        }

        let instruction_count = bytes.len() / BPF_INSN_SIZE;
        if instruction_count > u16::MAX as usize {
            return Err(format!(
                "seccomp filter has {instruction_count} instructions, maximum is {}",
                u16::MAX
            ));
        }

        let mut insns = Vec::with_capacity(instruction_count);
        for chunk in bytes.chunks_exact(BPF_INSN_SIZE) {
            insns.push(BpfInsn {
                code: u16::from_ne_bytes([chunk[0], chunk[1]]),
                jt: chunk[2],
                jf: chunk[3],
                k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            });
        }

        Ok(Self { insns })
    }
}

fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterDecision {
    Allow,
    Errno(i32),
    UserNotify,
    KillProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlagDenyRule {
    syscall_nr: u32,
    arg_index: usize,
    mask: u32,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyscallErrnoRule {
    syscall_nr: u32,
    errno: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SocketDomainPolicy {
    AllowAll,
    DenyAllExcept(Vec<u32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeccompOptions {
    socket_domain_policy: SocketDomainPolicy,
    notify_connect: bool,
    deny_unix_datagram_sockets: bool,
    allow_process_group_syscalls: bool,
    allow_thread_signal_syscalls: bool,
    allow_gpu_runtime_syscalls: bool,
}

impl Default for SeccompOptions {
    fn default() -> Self {
        Self {
            socket_domain_policy: SocketDomainPolicy::AllowAll,
            notify_connect: false,
            deny_unix_datagram_sockets: false,
            allow_process_group_syscalls: false,
            allow_thread_signal_syscalls: false,
            allow_gpu_runtime_syscalls: false,
        }
    }
}

/// Whether the policy asks for AMD GPU passthrough (`amd.gpu_passthrough`).
pub(crate) fn gpu_passthrough(policy: &Policy) -> bool {
    policy.amd.as_ref().is_some_and(|amd| amd.gpu_passthrough)
}

impl SeccompOptions {
    #[allow(dead_code)]
    pub(crate) fn deny_network_socket_domains() -> Self {
        Self {
            socket_domain_policy: SocketDomainPolicy::DenyAllExcept(vec![AF_UNIX]),
            notify_connect: false,
            deny_unix_datagram_sockets: false,
            allow_process_group_syscalls: false,
            allow_thread_signal_syscalls: false,
            allow_gpu_runtime_syscalls: false,
        }
    }

    pub(crate) fn notify_connect(mut self) -> Self {
        self.notify_connect = true;
        self
    }

    /// Refuses `socket` and `socketpair` for `AF_UNIX` `SOCK_DGRAM`. Connect
    /// supervision cannot see the destination a datagram socket names in
    /// `sendto` or `sendmsg`.
    pub(crate) fn deny_unix_datagram_sockets(mut self) -> Self {
        self.deny_unix_datagram_sockets = true;
        self
    }

    pub(crate) fn allow_process_group_syscalls(mut self) -> Self {
        self.allow_process_group_syscalls = true;
        self
    }

    pub(crate) fn allow_thread_signal_syscalls(mut self) -> Self {
        self.allow_thread_signal_syscalls = true;
        self
    }

    pub(crate) fn allow_gpu_runtime_syscalls(mut self) -> Self {
        self.allow_gpu_runtime_syscalls = true;
        self
    }

    /// The GPU runtime syscalls when the policy asks for GPU passthrough.
    pub(crate) fn for_gpu_passthrough(self, policy: &Policy) -> Self {
        if gpu_passthrough(policy) {
            self.allow_gpu_runtime_syscalls()
        } else {
            self
        }
    }

    #[cfg(test)]
    pub(crate) fn denies_non_unix_socket_domains(&self) -> bool {
        matches!(
            &self.socket_domain_policy,
            SocketDomainPolicy::DenyAllExcept(allowed_domains)
                if allowed_domains.as_slice() == [AF_UNIX]
        )
    }

    #[cfg(test)]
    pub(crate) fn allows_process_group_syscalls(&self) -> bool {
        self.allow_process_group_syscalls
    }

    #[cfg(test)]
    pub(crate) fn allows_thread_signal_syscalls(&self) -> bool {
        self.allow_thread_signal_syscalls
    }

    #[cfg(test)]
    pub(crate) fn allows_gpu_runtime_syscalls(&self) -> bool {
        self.allow_gpu_runtime_syscalls
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeccompFilterSpec {
    allowed_syscalls: Vec<u32>,
    socket_domain_policy: SocketDomainPolicy,
    notify_connect: bool,
    deny_unix_datagram_sockets: bool,
    syscall_errno_rules: Vec<SyscallErrnoRule>,
    flag_deny_rules: Vec<FlagDenyRule>,
}

impl SeccompFilterSpec {
    fn from_policy(policy: &ProcessPolicy, options: SeccompOptions) -> Result<Self, String> {
        let mut allowed_syscalls: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        let mut blocked_syscalls = Vec::new();

        if options.allow_process_group_syscalls {
            allowed_syscalls.extend([SYS_SETPGID, SYS_SETSID]);
        }
        if options.allow_thread_signal_syscalls {
            allowed_syscalls.push(SYS_TGKILL);
        }
        if options.allow_gpu_runtime_syscalls {
            allowed_syscalls.extend(GPU_RUNTIME_SYSCALLS.iter().map(|(nr, _)| *nr));
        }

        for name in &policy.blocked_syscalls {
            if UNSUPPORTED_XATTR_SYSCALLS
                .iter()
                .any(|(_, xattr)| *xattr == name.as_str())
            {
                return Err(format!(
                    "blocked_syscalls cannot name '{name}': AXIS always refuses extended attribute syscalls with EOPNOTSUPP"
                ));
            }
            let nr = syscall_number(name)
                .ok_or_else(|| format!("unknown syscall in blocked_syscalls: '{name}'"))?;
            blocked_syscalls.push(nr);
            blocked_syscalls.extend(
                FD_AND_AT_VARIANTS
                    .iter()
                    .filter(|(base, _)| *base == name.as_str())
                    .filter_map(|(_, variant)| syscall_number(variant)),
            );
        }
        allowed_syscalls.retain(|nr| !blocked_syscalls.contains(nr));

        allowed_syscalls.sort();
        allowed_syscalls.dedup();

        let notify_connect =
            options.notify_connect && allowed_syscalls.binary_search(&SYS_CONNECT).is_ok();

        let mut syscall_errno_rules: Vec<SyscallErrnoRule> = UNSUPPORTED_XATTR_SYSCALLS
            .iter()
            .map(|(nr, _)| SyscallErrnoRule {
                syscall_nr: *nr,
                errno: libc::EOPNOTSUPP,
            })
            .collect();
        if !blocked_syscalls.contains(&SYS_CLONE3) {
            syscall_errno_rules.push(SyscallErrnoRule {
                syscall_nr: SYS_CLONE3,
                errno: libc::ENOSYS,
            });
        }

        Ok(Self {
            allowed_syscalls,
            socket_domain_policy: options.socket_domain_policy,
            notify_connect,
            deny_unix_datagram_sockets: options.deny_unix_datagram_sockets,
            syscall_errno_rules,
            flag_deny_rules: vec![
                FlagDenyRule {
                    syscall_nr: SYS_CLONE,
                    arg_index: 0,
                    mask: DANGEROUS_UNSHARE_FLAGS,
                    reason: "dangerous namespace clone",
                },
                FlagDenyRule {
                    syscall_nr: SYS_UNSHARE,
                    arg_index: 0,
                    mask: DANGEROUS_UNSHARE_FLAGS,
                    reason: "dangerous namespace unshare",
                },
                FlagDenyRule {
                    syscall_nr: SYS_EXECVEAT,
                    arg_index: EXECVEAT_FLAGS_ARG,
                    mask: AT_EMPTY_PATH,
                    reason: "execveat AT_EMPTY_PATH",
                },
            ],
        })
    }

    #[allow(dead_code)]
    fn decision_for(&self, arch: u32, syscall_nr: u32, args: [u64; 6]) -> FilterDecision {
        if arch != AUDIT_ARCH_X86_64 {
            return FilterDecision::KillProcess;
        }

        if self.denies_socket_domain(syscall_nr, args[0] as u32) {
            return FilterDecision::Errno(libc::EPERM);
        }

        if self.deny_unix_datagram_sockets
            && matches!(syscall_nr, SYS_SOCKET | SYS_SOCKETPAIR)
            && args[0] as u32 == AF_UNIX
            && (args[1] as u32) & SOCK_TYPE_MASK == SOCK_DGRAM
        {
            return FilterDecision::Errno(libc::EACCES);
        }

        if self.notify_connect && syscall_nr == SYS_CONNECT {
            return FilterDecision::UserNotify;
        }

        for rule in &self.syscall_errno_rules {
            if rule.syscall_nr == syscall_nr {
                return FilterDecision::Errno(rule.errno);
            }
        }

        for rule in &self.flag_deny_rules {
            if rule.syscall_nr == syscall_nr && ((args[rule.arg_index] as u32) & rule.mask) != 0 {
                return FilterDecision::Errno(libc::EPERM);
            }
        }

        if self.allowed_syscalls.binary_search(&syscall_nr).is_ok() {
            FilterDecision::Allow
        } else {
            FilterDecision::Errno(libc::EPERM)
        }
    }

    #[allow(dead_code)]
    fn denies_socket_domain(&self, syscall_nr: u32, domain: u32) -> bool {
        if !matches!(syscall_nr, SYS_SOCKET | SYS_SOCKETPAIR) {
            return false;
        }
        match &self.socket_domain_policy {
            SocketDomainPolicy::AllowAll => false,
            SocketDomainPolicy::DenyAllExcept(allowed_domains) => {
                !allowed_domains.contains(&domain)
            }
        }
    }

    fn to_bpf(&self) -> Vec<BpfInsn> {
        let mut insns = Vec::new();

        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
        insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        append_socket_domain_denies(&mut insns, &self.socket_domain_policy);
        if self.deny_unix_datagram_sockets {
            for syscall_nr in [SYS_SOCKET, SYS_SOCKETPAIR] {
                append_unix_datagram_deny(&mut insns, syscall_nr);
            }
        }
        for rule in &self.flag_deny_rules {
            append_flag_deny(&mut insns, *rule);
        }
        for rule in &self.syscall_errno_rules {
            append_syscall_return(&mut insns, rule.syscall_nr, errno_return_for(rule.errno));
        }
        if self.notify_connect {
            append_syscall_return(&mut insns, SYS_CONNECT, user_notify_return());
        }

        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        let n_allowed = self.allowed_syscalls.len();
        for (i, nr) in self.allowed_syscalls.iter().enumerate() {
            let remaining = n_allowed - i - 1;
            insns.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                *nr,
                checked_skip(remaining + 1),
                0,
            ));
        }

        insns.push(errno_return());
        insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        insns
    }
}

fn append_syscall_return(insns: &mut Vec<BpfInsn>, syscall_nr: u32, ret: BpfInsn) {
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
    insns.push(ret);
}

fn append_socket_domain_denies(insns: &mut Vec<BpfInsn>, policy: &SocketDomainPolicy) {
    match policy {
        SocketDomainPolicy::AllowAll => {}
        SocketDomainPolicy::DenyAllExcept(allowed_domains) => {
            for syscall_nr in [SYS_SOCKET, SYS_SOCKETPAIR] {
                append_socket_domain_deny_all_except(insns, syscall_nr, allowed_domains);
            }
        }
    };
}

fn append_socket_domain_deny_all_except(
    insns: &mut Vec<BpfInsn>,
    syscall_nr: u32,
    allowed_domains: &[u32],
) {
    if allowed_domains.is_empty() {
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1));
        insns.push(errno_return());
        return;
    }

    let body_len = 1 + allowed_domains.len() + 1;
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        syscall_nr,
        0,
        checked_skip(body_len),
    ));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_low_offset(0)));
    for (i, domain) in allowed_domains.iter().enumerate() {
        let remaining_allowed_checks = allowed_domains.len() - i - 1;
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *domain,
            checked_skip(remaining_allowed_checks + 1),
            0,
        ));
    }
    insns.push(errno_return());
}

fn append_unix_datagram_deny(insns: &mut Vec<BpfInsn>, syscall_nr: u32) {
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 6));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_low_offset(0)));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 4));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, arg_low_offset(1)));
    insns.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 0, 1));
    insns.push(errno_return_for(libc::EACCES));
}

fn append_flag_deny(insns: &mut Vec<BpfInsn>, rule: FlagDenyRule) {
    let body_len = 3;
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        rule.syscall_nr,
        0,
        checked_skip(body_len),
    ));
    insns.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        arg_low_offset(rule.arg_index),
    ));
    insns.push(bpf_jump(BPF_JMP | BPF_JSET | BPF_K, rule.mask, 0, 1));
    insns.push(errno_return());
}

fn errno_return() -> BpfInsn {
    errno_return_for(libc::EPERM)
}

fn errno_return_for(errno: i32) -> BpfInsn {
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (errno as u32 & 0xFFFF))
}

fn user_notify_return() -> BpfInsn {
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
}

fn checked_skip(len: usize) -> u8 {
    u8::try_from(len).expect("seccomp BPF conditional block too large")
}

fn arg_low_offset(index: usize) -> u32 {
    SECCOMP_DATA_ARGS_OFFSET + (index as u32 * ARG_SIZE)
}

pub(crate) fn prepare_seccomp(policy: &ProcessPolicy) -> Result<PreparedSeccompFilter, String> {
    prepare_seccomp_with_options(policy, SeccompOptions::default())
}

pub(crate) fn prepare_seccomp_with_options(
    policy: &ProcessPolicy,
    options: SeccompOptions,
) -> Result<PreparedSeccompFilter, String> {
    let spec = SeccompFilterSpec::from_policy(policy, options)?;
    let insns = spec.to_bpf();

    tracing::info!(
        "seccomp: prepared default-deny mode — {} syscalls whitelisted, {} BPF instructions",
        spec.allowed_syscalls.len(),
        insns.len(),
    );
    Ok(PreparedSeccompFilter { insns })
}

/// Apply seccomp-BPF in default-deny whitelist mode.
///
/// Only syscalls in the whitelist are allowed. Everything else returns EPERM.
pub fn apply_seccomp(policy: &ProcessPolicy) -> Result<(), String> {
    let filter = prepare_seccomp(policy)?;
    filter.apply_current_process().map_err(|errno| {
        format!(
            "seccomp(SET_MODE_FILTER) failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;
    tracing::info!("seccomp: applied default-deny mode");
    Ok(())
}

/// Launcher flag that scopes abstract Unix connect to the payload with
/// Landlock before the filter is applied. Launchers that predate it reject it
/// as an unexpected first argument, so the launch fails instead of running
/// unscoped.
pub(crate) const LAUNCHER_SCOPE_ABSTRACT_UNIX_FLAG: &str = "--scope-abstract-unix";

pub fn launcher_main_from_env() -> i32 {
    match run_launcher_from_args(std::env::args_os().skip(1)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("axis-seccomp-launcher: {err}");
            126
        }
    }
}

fn run_launcher_from_args<I>(args: I) -> Result<i32, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter().peekable();
    let scope_abstract_unix = args
        .next_if(|arg| arg.as_os_str() == LAUNCHER_SCOPE_ABSTRACT_UNIX_FLAG)
        .is_some();
    let flag = args
        .next()
        .ok_or_else(|| "missing --filter argument".to_string())?;
    if flag.as_os_str() != "--filter" {
        return Err(format!(
            "expected --filter argument, got '{}'",
            flag.to_string_lossy()
        ));
    }

    let filter_path = args
        .next()
        .ok_or_else(|| "missing seccomp filter path".to_string())?;
    let separator = args
        .next()
        .ok_or_else(|| "missing -- command separator".to_string())?;
    if separator.as_os_str() != "--" {
        return Err(format!(
            "expected -- command separator, got '{}'",
            separator.to_string_lossy()
        ));
    }

    let command = args.collect::<Vec<_>>();
    if command.is_empty() {
        return Err("missing payload command".into());
    }

    let filter_bytes = std::fs::read(&filter_path).map_err(|err| {
        format!(
            "failed to read seccomp filter '{}': {err}",
            filter_path.to_string_lossy()
        )
    })?;
    let filter = PreparedSeccompFilter::from_bpf_bytes(&filter_bytes)?;
    let argv = command
        .iter()
        .map(|arg| {
            CString::new(arg.as_os_str().as_bytes()).map_err(|_| {
                format!(
                    "payload argument contains NUL byte: '{}'",
                    arg.to_string_lossy()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv_ptrs = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());

    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs < 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if scope_abstract_unix {
        super::landlock::restrict_current_process_to_abstract_unix_scope()?;
    }
    filter.apply_current_process().map_err(|errno| {
        format!(
            "seccomp(SET_MODE_FILTER) failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    })?;

    unsafe {
        libc::execvp(argv[0].as_ptr(), argv_ptrs.as_ptr());
    }

    Err(format!(
        "failed to exec payload '{}': {}",
        command[0].to_string_lossy(),
        std::io::Error::last_os_error()
    ))
}

fn current_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Map syscall name to x86_64 number.
fn syscall_number(name: &str) -> Option<u32> {
    WHITELIST
        .iter()
        .chain(GPU_RUNTIME_SYSCALLS)
        .find(|(_, n)| *n == name)
        .map(|(nr, _)| *nr)
        .or({
            // Also map commonly-blocked names that aren't in the whitelist.
            match name {
                "ptrace" => Some(101),
                "mount" => Some(165),
                "umount2" => Some(166),
                "bpf" => Some(321),
                "io_uring_setup" => Some(425),
                "memfd_create" => Some(319),
                "process_vm_readv" => Some(310),
                "process_vm_writev" => Some(311),
                "userfaultfd" => Some(323),
                "kexec_load" => Some(246),
                "reboot" => Some(169),
                "pivot_root" => Some(155),
                "chroot" => Some(161),
                "kill" => Some(SYS_KILL),
                "setpgid" => Some(SYS_SETPGID),
                "setsid" => Some(SYS_SETSID),
                "tkill" => Some(SYS_TKILL),
                "tgkill" => Some(SYS_TGKILL),
                "unshare" => Some(272),
                "clone3" => Some(SYS_CLONE3),
                _ => None,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus};

    const DOCUMENTED_NETWORK_SOCKET_DOMAINS: &[u32] = &[
        2,  // AF_INET
        10, // AF_INET6
        16, // AF_NETLINK
        17, // AF_PACKET
        29, // AF_CAN
        31, // AF_BLUETOOTH
        36, // AF_IEEE802154
        39, // AF_NFC
        40, // AF_VSOCK
        44, // AF_XDP
    ];

    const PROBE_DENIED: i32 = 0;
    const PROBE_ALLOWED: i32 = 1;
    const PROBE_UNEXPECTED_ERRNO: i32 = 2;
    const PROBE_SECCOMP_SETUP_FAILED: i32 = 101;
    const PROBE_NO_NEW_PRIVS_FAILED: i32 = 102;
    const PROBE_SIGNALLED: i32 = 128;

    #[test]
    fn whitelist_has_essential_syscalls() {
        let nrs: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        assert!(nrs.contains(&0), "read missing");
        assert!(nrs.contains(&1), "write missing");
        assert!(nrs.contains(&59), "execve missing");
        assert!(nrs.contains(&231), "exit_group missing");
        assert!(nrs.contains(&9), "mmap missing");
        assert!(nrs.contains(&56), "clone missing");
        assert!(
            nrs.contains(&SYS_SET_ROBUST_LIST),
            "set_robust_list missing"
        );
    }

    #[test]
    fn whitelist_excludes_dangerous() {
        let nrs: Vec<u32> = WHITELIST.iter().map(|(nr, _)| *nr).collect();
        assert!(!nrs.contains(&101), "ptrace should not be in whitelist");
        assert!(!nrs.contains(&165), "mount should not be in whitelist");
        assert!(!nrs.contains(&321), "bpf should not be in whitelist");
        assert!(
            !nrs.contains(&425),
            "io_uring_setup should not be in whitelist"
        );
        assert!(!nrs.contains(&169), "reboot should not be in whitelist");
        assert!(
            !nrs.contains(&SYS_CLONE3),
            "clone3 should not be in whitelist"
        );
        assert!(!nrs.contains(&SYS_KILL), "kill should not be in whitelist");
        assert!(
            !nrs.contains(&SYS_TKILL),
            "tkill should not be in whitelist"
        );
        assert!(
            !nrs.contains(&SYS_TGKILL),
            "tgkill should not be in whitelist"
        );
        assert!(
            !nrs.contains(&SYS_SETPGID),
            "setpgid should not be in whitelist"
        );
        assert!(
            !nrs.contains(&SYS_SETSID),
            "setsid should not be in whitelist"
        );
    }

    #[test]
    fn policy_can_remove_from_whitelist() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["fork".into(), "execve".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        assert!(
            !spec.allowed_syscalls.contains(&57),
            "fork should be removed"
        );
        assert!(
            !spec.allowed_syscalls.contains(&59),
            "execve should be removed"
        );
        assert!(spec.allowed_syscalls.contains(&0), "read should remain");
    }

    #[test]
    fn unknown_blocked_syscall_is_fatal() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["not_a_real_syscall".into()],
            ..Default::default()
        };

        let err = prepare_seccomp(&policy).unwrap_err();

        assert!(err.contains("unknown syscall"));
    }

    #[test]
    fn decision_kills_wrong_architecture() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        assert_eq!(spec.decision_for(0, 0, [0; 6]), FilterDecision::KillProcess);
    }

    #[test]
    fn decision_denies_documented_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [
            "ptrace",
            "mount",
            "umount2",
            "bpf",
            "io_uring_setup",
            "process_vm_readv",
            "process_vm_writev",
            "userfaultfd",
        ] {
            let nr = syscall_number(syscall).unwrap();
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{syscall} should be denied"
            );
        }
    }

    #[test]
    fn clone3_defaults_to_enosys_for_thread_runtime_fallback() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::ENOSYS)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::ENOSYS)
        );
        assert!(!spec.allowed_syscalls.contains(&SYS_CLONE3));
    }

    #[test]
    fn policy_blocked_clone3_preserves_hard_eperm_denial() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["clone3".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
    }

    #[test]
    fn unix_datagram_socket_deny_only_refuses_unix_datagram_sockets() {
        let default =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        let denying = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().deny_unix_datagram_sockets(),
        )
        .unwrap();
        let af_inet = libc::AF_INET as u64;
        let dgram = libc::SOCK_DGRAM as u64;
        let stream = libc::SOCK_STREAM as u64;
        let flags = (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64;

        for syscall in [SYS_SOCKET, SYS_SOCKETPAIR] {
            for (spec, domain, socket_type, expected) in [
                (
                    &denying,
                    AF_UNIX as u64,
                    dgram,
                    FilterDecision::Errno(libc::EACCES),
                ),
                (
                    &denying,
                    AF_UNIX as u64,
                    dgram | flags,
                    FilterDecision::Errno(libc::EACCES),
                ),
                (
                    &denying,
                    AF_UNIX as u64,
                    stream | flags,
                    FilterDecision::Allow,
                ),
                (
                    &denying,
                    AF_UNIX as u64,
                    libc::SOCK_SEQPACKET as u64,
                    FilterDecision::Allow,
                ),
                (&denying, af_inet, dgram, FilterDecision::Allow),
                (&default, AF_UNIX as u64, dgram, FilterDecision::Allow),
            ] {
                let args = [domain, socket_type, 0, 0, 0, 0];
                assert_eq!(
                    spec.decision_for(AUDIT_ARCH_X86_64, syscall, args),
                    expected,
                    "syscall {syscall} domain {domain} type {socket_type:#x}"
                );
                assert_eq!(
                    bpf_decision_for(spec, AUDIT_ARCH_X86_64, syscall, args),
                    expected,
                    "bpf syscall {syscall} domain {domain} type {socket_type:#x}"
                );
            }
        }
    }

    #[test]
    fn decision_denies_broad_signal_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_KILL, SYS_TKILL, SYS_TGKILL] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "signal syscall {syscall} should be denied"
            );
        }
    }

    #[test]
    fn decision_allows_thread_signal_syscalls_when_pid_boundary_allows_it() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().allow_thread_signal_syscalls(),
        )
        .unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_TGKILL, [0; 6]),
            FilterDecision::Allow,
            "tgkill should be allowed when the runtime PID boundary owns signal scope"
        );
        for syscall in [SYS_KILL, SYS_TKILL] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "broader signal syscall {syscall} should remain denied"
            );
        }
    }

    #[test]
    fn policy_blocked_tgkill_overrides_thread_signal_option() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["tgkill".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(
            &policy,
            SeccompOptions::default().allow_thread_signal_syscalls(),
        )
        .unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_TGKILL, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
    }

    #[test]
    fn gpu_runtime_syscalls_are_denied_without_gpu_passthrough() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for (nr, name) in GPU_RUNTIME_SYSCALLS {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, *nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{name} should be denied without GPU passthrough"
            );
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, *nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{name} should be denied by generated BPF without GPU passthrough"
            );
        }
    }

    #[test]
    fn gpu_runtime_syscalls_are_allowed_with_gpu_passthrough() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().allow_gpu_runtime_syscalls(),
        )
        .unwrap();

        for (nr, name) in GPU_RUNTIME_SYSCALLS {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, *nr, [0; 6]),
                FilterDecision::Allow,
                "{name} should be allowed with GPU passthrough"
            );
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, *nr, [0; 6]),
                FilterDecision::Allow,
                "{name} should be allowed by generated BPF with GPU passthrough"
            );
        }
        for syscall in ["ptrace", "mount", "bpf", "process_vm_readv"] {
            let nr = syscall_number(syscall).unwrap();
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{syscall} should stay denied with GPU passthrough"
            );
        }
        for nr in [237, 238, 239] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "NUMA memory-policy syscall {nr} should stay denied with GPU passthrough"
            );
        }
    }

    #[test]
    fn policy_blocked_gpu_runtime_syscall_overrides_gpu_passthrough() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["sched_setaffinity".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(
            &policy,
            SeccompOptions::default().allow_gpu_runtime_syscalls(),
        )
        .unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_SCHED_SETAFFINITY, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_SCHED_SETAFFINITY, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
    }

    #[test]
    fn gpu_runtime_syscalls_follow_amd_gpu_passthrough() {
        let plain = Policy::from_yaml("version: 1\nname: plain\n").unwrap();
        let off =
            Policy::from_yaml("version: 1\nname: off\namd:\n  gpu_passthrough: false\n").unwrap();
        let gpu =
            Policy::from_yaml("version: 1\nname: gpu\namd:\n  gpu_passthrough: true\n").unwrap();

        assert!(
            !SeccompOptions::default()
                .for_gpu_passthrough(&plain)
                .allows_gpu_runtime_syscalls()
        );
        assert!(
            !SeccompOptions::default()
                .for_gpu_passthrough(&off)
                .allows_gpu_runtime_syscalls()
        );
        assert!(
            SeccompOptions::default()
                .for_gpu_passthrough(&gpu)
                .allows_gpu_runtime_syscalls()
        );
        assert!(
            SeccompOptions::deny_network_socket_domains()
                .for_gpu_passthrough(&gpu)
                .denies_non_unix_socket_domains()
        );
    }

    #[test]
    fn runtime_sched_setaffinity_needs_gpu_passthrough() {
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                SeccompOptions::default(),
                probe_sched_setaffinity_self,
            ),
            PROBE_DENIED
        );
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                SeccompOptions::default().allow_gpu_runtime_syscalls(),
                probe_sched_setaffinity_self,
            ),
            PROBE_ALLOWED
        );
    }

    #[test]
    fn decision_denies_process_group_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "process group syscall {syscall} should be denied"
            );
        }
    }

    #[test]
    fn decision_allows_process_group_syscalls_when_lifecycle_boundary_allows_it() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().allow_process_group_syscalls(),
        )
        .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Allow,
                "process group syscall {syscall} should be allowed when the runtime lifecycle boundary owns cleanup"
            );
        }
    }

    #[test]
    fn decision_denies_policy_blocked_syscall() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["getpid".into()],
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, 39, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn decision_allows_timerfd_runtime_primitives() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_TIMERFD_CREATE, SYS_TIMERFD_SETTIME, SYS_TIMERFD_GETTIME] {
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Allow,
                "timerfd runtime syscall {syscall} should be allowed"
            );
        }
    }

    const FD_AND_AT_SYSCALLS: &[(&str, libc::c_long)] = &[
        ("fchmod", libc::SYS_fchmod),
        ("fchown", libc::SYS_fchown),
        ("getgroups", libc::SYS_getgroups),
        ("fchdir", libc::SYS_fchdir),
        ("linkat", libc::SYS_linkat),
        ("symlinkat", libc::SYS_symlinkat),
        ("close_range", libc::SYS_close_range),
    ];

    const UNSUPPORTED_XATTR: &[(&str, libc::c_long)] = &[
        ("setxattr", libc::SYS_setxattr),
        ("lsetxattr", libc::SYS_lsetxattr),
        ("fsetxattr", libc::SYS_fsetxattr),
        ("getxattr", libc::SYS_getxattr),
        ("lgetxattr", libc::SYS_lgetxattr),
        ("fgetxattr", libc::SYS_fgetxattr),
        ("listxattr", libc::SYS_listxattr),
        ("llistxattr", libc::SYS_llistxattr),
        ("flistxattr", libc::SYS_flistxattr),
        ("removexattr", libc::SYS_removexattr),
        ("lremovexattr", libc::SYS_lremovexattr),
        ("fremovexattr", libc::SYS_fremovexattr),
        ("setxattrat", SYS_SETXATTRAT),
        ("getxattrat", SYS_GETXATTRAT),
        ("listxattrat", SYS_LISTXATTRAT),
        ("removexattrat", SYS_REMOVEXATTRAT),
    ];

    // The pinned libc has no constants for the Linux 6.13 xattr syscalls.
    const SYS_SETXATTRAT: libc::c_long = 463;
    const SYS_GETXATTRAT: libc::c_long = 464;
    const SYS_LISTXATTRAT: libc::c_long = 465;
    const SYS_REMOVEXATTRAT: libc::c_long = 466;

    /// The option sets the Linux backends build their filters with.
    fn backend_seccomp_options() -> Vec<(&'static str, SeccompOptions)> {
        use super::super::seccomp_options_for_network;
        use super::super::strategy::NetworkStrategy;

        let native_allow = || seccomp_options_for_network(&NetworkStrategy::AllowHost, false);
        let native_block =
            || seccomp_options_for_network(&NetworkStrategy::BlockedBySeccomp, false);
        let netns_helper = || {
            SeccompOptions::default()
                .notify_connect()
                .deny_unix_datagram_sockets()
        };
        let mxc = |policy_yaml: &str| {
            super::super::mxc::mxc_seccomp_options_for_policy(
                &Policy::from_yaml(policy_yaml).unwrap(),
            )
        };
        vec![
            ("native", native_allow()),
            ("native block mode", native_block()),
            (
                "native connect supervision",
                seccomp_options_for_network(&NetworkStrategy::BlockedBySeccomp, true),
            ),
            (
                "native GPU passthrough",
                native_allow().allow_gpu_runtime_syscalls(),
            ),
            (
                "native block mode with GPU passthrough",
                native_block().allow_gpu_runtime_syscalls(),
            ),
            ("netns helper", netns_helper()),
            (
                "netns helper with GPU passthrough",
                netns_helper().allow_gpu_runtime_syscalls(),
            ),
            (
                "MXC",
                mxc("version: 1\nname: mxc\nnetwork:\n  mode: allow\n"),
            ),
            (
                "MXC block mode",
                mxc("version: 1\nname: mxc\nnetwork:\n  mode: block\n"),
            ),
            (
                "MXC block mode with GPU passthrough",
                mxc(
                    "version: 1\nname: mxc\nnetwork:\n  mode: block\namd:\n  gpu_passthrough: true\n",
                ),
            ),
        ]
    }

    #[test]
    fn xattr_and_fd_and_at_tables_match_libc_numbers() {
        for &(syscall, nr) in FD_AND_AT_SYSCALLS {
            assert_eq!(syscall_number(syscall), Some(nr as u32), "{syscall}");
        }

        let mut table: Vec<(&str, u32)> = UNSUPPORTED_XATTR_SYSCALLS
            .iter()
            .map(|&(nr, syscall)| (syscall, nr))
            .collect();
        let mut expected: Vec<(&str, u32)> = UNSUPPORTED_XATTR
            .iter()
            .map(|&(syscall, nr)| (syscall, nr as u32))
            .collect();
        table.sort();
        expected.sort();
        assert_eq!(table, expected);
    }

    #[test]
    fn every_backend_allows_fd_and_at_syscalls() {
        for (backend, options) in backend_seccomp_options() {
            let spec = SeccompFilterSpec::from_policy(&ProcessPolicy::default(), options).unwrap();

            for &(syscall, nr) in FD_AND_AT_SYSCALLS {
                let nr = nr as u32;
                assert_eq!(
                    spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Allow,
                    "{backend}: {syscall} should be allowed"
                );
                assert_eq!(
                    bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Allow,
                    "{backend}: {syscall} should be allowed by generated BPF"
                );
            }
        }
    }

    #[test]
    fn every_backend_refuses_unconfined_xattr_syscalls_as_unsupported() {
        for (backend, options) in backend_seccomp_options() {
            let spec = SeccompFilterSpec::from_policy(&ProcessPolicy::default(), options).unwrap();

            for &(syscall, nr) in UNSUPPORTED_XATTR {
                let nr = nr as u32;
                assert!(
                    !spec.allowed_syscalls.contains(&nr),
                    "{backend}: {syscall} must not be allowlisted"
                );
                assert_eq!(
                    spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Errno(libc::EOPNOTSUPP),
                    "{backend}: {syscall} should fail with EOPNOTSUPP"
                );
                assert_eq!(
                    bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Errno(libc::EOPNOTSUPP),
                    "{backend}: {syscall} should fail with EOPNOTSUPP in generated BPF"
                );
            }
        }
    }

    #[test]
    fn policy_can_block_fd_and_at_syscalls() {
        let policy = ProcessPolicy {
            blocked_syscalls: FD_AND_AT_SYSCALLS
                .iter()
                .map(|(syscall, _)| (*syscall).to_string())
                .collect(),
            ..Default::default()
        };
        let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

        for &(syscall, nr) in FD_AND_AT_SYSCALLS {
            let nr = nr as u32;
            assert_eq!(
                spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "policy-blocked {syscall} should be denied"
            );
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "policy-blocked {syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn policy_blocking_a_syscall_also_blocks_its_fd_or_at_variant() {
        for &(base, variant) in FD_AND_AT_VARIANTS {
            let policy = ProcessPolicy {
                blocked_syscalls: vec![base.to_string()],
                ..Default::default()
            };
            let spec = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default()).unwrap();

            for syscall in [base, variant] {
                let nr = syscall_number(syscall).unwrap();
                assert_eq!(
                    spec.decision_for(AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Errno(libc::EPERM),
                    "blocking {base} should deny {syscall}"
                );
                assert_eq!(
                    bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                    FilterDecision::Errno(libc::EPERM),
                    "blocking {base} should deny {syscall} in generated BPF"
                );
            }
        }
    }

    #[test]
    fn policy_naming_unsupported_xattr_syscall_is_rejected() {
        for &(syscall, _) in UNSUPPORTED_XATTR {
            let policy = ProcessPolicy {
                blocked_syscalls: vec![syscall.to_string()],
                ..Default::default()
            };
            let err = SeccompFilterSpec::from_policy(&policy, SeccompOptions::default())
                .expect_err("blocking an xattr syscall must fail rather than be shadowed");
            assert!(
                err.contains(&format!("blocked_syscalls cannot name '{syscall}'"))
                    && err.contains("EOPNOTSUPP"),
                "{err}"
            );
        }
    }

    #[test]
    fn socket_domain_policy_denies_network_domains_but_allows_unix() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::deny_network_socket_domains(),
        )
        .unwrap();

        for domain in DOCUMENTED_NETWORK_SOCKET_DOMAINS
            .iter()
            .copied()
            .chain([9_999])
        {
            assert_eq!(
                spec.decision_for(
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKET,
                    [domain as u64, 0, 0, 0, 0, 0]
                ),
                FilterDecision::Errno(libc::EPERM),
                "socket domain {domain} should be denied"
            );
        }
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                [AF_UNIX as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Allow
        );
    }

    #[test]
    fn connect_notification_is_opt_in() {
        let default_spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        assert_eq!(
            default_spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Allow
        );

        let notify_spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().notify_connect(),
        )
        .unwrap();
        assert_eq!(
            notify_spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::UserNotify
        );
        assert_eq!(
            notify_spec.decision_for(AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn connect_notification_respects_policy_blocked_connect() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["connect".into()],
            ..Default::default()
        };
        let spec =
            SeccompFilterSpec::from_policy(&policy, SeccompOptions::default().notify_connect())
                .unwrap();

        assert!(!spec.allowed_syscalls.contains(&SYS_CONNECT));
        assert!(!spec.notify_connect);
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Errno(libc::EPERM)
        );
    }

    #[test]
    fn conditional_rules_deny_dangerous_clone_and_unshare_flags() {
        let mut spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        spec.allowed_syscalls.push(SYS_UNSHARE);
        spec.allowed_syscalls.sort();

        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Allow
        );
        assert_eq!(
            spec.decision_for(
                AUDIT_ARCH_X86_64,
                SYS_UNSHARE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_UNSHARE, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_denies_security_sensitive_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [
            "ptrace",
            "mount",
            "umount2",
            "bpf",
            "io_uring_setup",
            "process_vm_readv",
            "process_vm_writev",
            "userfaultfd",
        ] {
            let nr = syscall_number(syscall).unwrap();
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, nr, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "{syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_denies_broad_signal_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_KILL, SYS_TKILL, SYS_TGKILL] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "signal syscall {syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_allows_thread_signal_syscalls_when_pid_boundary_allows_it() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().allow_thread_signal_syscalls(),
        )
        .unwrap();

        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_TGKILL, [0; 6]),
            FilterDecision::Allow,
            "tgkill should be allowed by generated BPF when the runtime PID boundary owns signal scope"
        );
        for syscall in [SYS_KILL, SYS_TKILL] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "broader signal syscall {syscall} should remain denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_denies_process_group_escape_syscalls() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Errno(libc::EPERM),
                "process group syscall {syscall} should be denied by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_allows_process_group_syscalls_when_lifecycle_boundary_allows_it() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().allow_process_group_syscalls(),
        )
        .unwrap();

        for syscall in [SYS_SETPGID, SYS_SETSID] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Allow,
                "process group syscall {syscall} should be allowed by generated BPF when the runtime lifecycle boundary owns cleanup"
            );
        }
    }

    #[test]
    fn generated_bpf_allows_timerfd_runtime_primitives() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();

        for syscall in [SYS_TIMERFD_CREATE, SYS_TIMERFD_SETTIME, SYS_TIMERFD_GETTIME] {
            assert_eq!(
                bpf_decision_for(&spec, AUDIT_ARCH_X86_64, syscall, [0; 6]),
                FilterDecision::Allow,
                "timerfd runtime syscall {syscall} should be allowed by generated BPF"
            );
        }
    }

    #[test]
    fn generated_bpf_applies_conditional_flag_rules() {
        let mut spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        spec.allowed_syscalls.push(SYS_UNSHARE);
        spec.allowed_syscalls.sort();

        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::CLONE_NEWNS as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_CLONE,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Allow
        );
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_UNSHARE,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_UNSHARE, [0; 6]),
            FilterDecision::Allow
        );

        let mut args = [0u64; 6];
        args[EXECVEAT_FLAGS_ARG] = AT_EMPTY_PATH as u64;
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_EXECVEAT, args),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            bpf_decision_for(&spec, AUDIT_ARCH_X86_64, SYS_EXECVEAT, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_denies_network_socket_domains_when_requested() {
        let spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::deny_network_socket_domains(),
        )
        .unwrap();

        for domain in DOCUMENTED_NETWORK_SOCKET_DOMAINS
            .iter()
            .copied()
            .chain([9_999])
        {
            assert_eq!(
                bpf_decision_for(
                    &spec,
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKET,
                    [domain as u64, 0, 0, 0, 0, 0],
                ),
                FilterDecision::Errno(libc::EPERM),
                "socket domain {domain} should be denied by generated BPF"
            );
            assert_eq!(
                bpf_decision_for(
                    &spec,
                    AUDIT_ARCH_X86_64,
                    SYS_SOCKETPAIR,
                    [domain as u64, 0, 0, 0, 0, 0],
                ),
                FilterDecision::Errno(libc::EPERM),
                "socketpair domain {domain} should be denied by generated BPF"
            );
        }
        assert_eq!(
            bpf_decision_for(
                &spec,
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                [AF_UNIX as u64, 0, 0, 0, 0, 0],
            ),
            FilterDecision::Allow
        );
    }

    #[test]
    fn generated_bpf_connect_notification_is_opt_in() {
        let default_spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        assert_eq!(
            bpf_decision_for(&default_spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::Allow
        );

        let notify_spec = SeccompFilterSpec::from_policy(
            &ProcessPolicy::default(),
            SeccompOptions::default().notify_connect(),
        )
        .unwrap();
        assert_eq!(
            bpf_decision_for(&notify_spec, AUDIT_ARCH_X86_64, SYS_CONNECT, [0; 6]),
            FilterDecision::UserNotify
        );
        assert_eq!(
            bpf_decision_for(&notify_spec, AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn exported_bpf_roundtrip_preserves_action_matrix() {
        let default_filter = prepare_seccomp(&ProcessPolicy::default()).unwrap();
        let imported_default =
            PreparedSeccompFilter::from_bpf_bytes(&default_filter.export_bpf_bytes()).unwrap();

        assert_eq!(
            prepared_bpf_decision_for(&imported_default, AUDIT_ARCH_X86_64, 0, [0; 6]),
            FilterDecision::Allow,
            "read should remain whitelisted after BPF export/import"
        );
        assert_eq!(
            prepared_bpf_decision_for(&imported_default, 0, 0, [0; 6]),
            FilterDecision::KillProcess,
            "wrong architecture should keep kill action after BPF export/import"
        );
        assert_eq!(
            prepared_bpf_decision_for(&imported_default, AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::ENOSYS),
            "clone3 runtime fallback should keep ENOSYS after BPF export/import"
        );
        let mut execveat_args = [0_u64; 6];
        execveat_args[EXECVEAT_FLAGS_ARG] = AT_EMPTY_PATH as u64;
        assert_eq!(
            prepared_bpf_decision_for(
                &imported_default,
                AUDIT_ARCH_X86_64,
                SYS_EXECVEAT,
                execveat_args
            ),
            FilterDecision::Errno(libc::EPERM),
            "execveat AT_EMPTY_PATH denial should survive BPF export/import"
        );

        let blocked_policy = ProcessPolicy {
            blocked_syscalls: vec!["getpid".into(), "clone3".into()],
            ..Default::default()
        };
        let blocked_filter = prepare_seccomp(&blocked_policy).unwrap();
        let imported_blocked =
            PreparedSeccompFilter::from_bpf_bytes(&blocked_filter.export_bpf_bytes()).unwrap();
        assert_eq!(
            prepared_bpf_decision_for(&imported_blocked, AUDIT_ARCH_X86_64, 39, [0; 6]),
            FilterDecision::Errno(libc::EPERM),
            "policy-blocked whitelisted syscall should keep EPERM after BPF export/import"
        );
        assert_eq!(
            prepared_bpf_decision_for(&imported_blocked, AUDIT_ARCH_X86_64, SYS_CLONE3, [0; 6]),
            FilterDecision::Errno(libc::EPERM),
            "explicitly blocked clone3 should override ENOSYS after BPF export/import"
        );

        let network_filter = prepare_seccomp_with_options(
            &ProcessPolicy::default(),
            SeccompOptions::deny_network_socket_domains(),
        )
        .unwrap();
        let imported_network =
            PreparedSeccompFilter::from_bpf_bytes(&network_filter.export_bpf_bytes()).unwrap();
        assert_eq!(
            prepared_bpf_decision_for(
                &imported_network,
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                [libc::AF_INET as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Errno(libc::EPERM),
            "block-mode network sockets should stay denied after BPF export/import"
        );
        assert_eq!(
            prepared_bpf_decision_for(
                &imported_network,
                AUDIT_ARCH_X86_64,
                SYS_SOCKETPAIR,
                [AF_UNIX as u64, 0, 0, 0, 0, 0]
            ),
            FilterDecision::Allow,
            "AF_UNIX socketpair should stay allowed after BPF export/import"
        );
    }

    #[test]
    fn conditional_rules_deny_execveat_empty_path() {
        let spec =
            SeccompFilterSpec::from_policy(&ProcessPolicy::default(), SeccompOptions::default())
                .unwrap();
        let mut args = [0u64; 6];
        args[EXECVEAT_FLAGS_ARG] = AT_EMPTY_PATH as u64;

        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_EXECVEAT, args),
            FilterDecision::Errno(libc::EPERM)
        );
        assert_eq!(
            spec.decision_for(AUDIT_ARCH_X86_64, SYS_EXECVEAT, [0; 6]),
            FilterDecision::Allow
        );
    }

    #[test]
    fn runtime_execveat_empty_path_flag_is_denied_by_kernel_filter() {
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                SeccompOptions::default(),
                probe_execveat_empty_path,
            ),
            PROBE_DENIED
        );
    }

    #[test]
    fn runtime_clone3_returns_enosys_for_thread_runtime_fallback() {
        assert_eq!(
            run_seccomp_errno_probe(
                &ProcessPolicy::default(),
                SeccompOptions::default(),
                probe_clone3_unavailable,
                libc::ENOSYS,
            ),
            PROBE_ALLOWED
        );
    }

    #[test]
    fn runtime_fd_and_at_syscalls_reach_the_kernel() {
        for (name, probe) in [
            (
                "fchmod",
                probe_fchmod_pipe_to_current_mode as unsafe fn() -> libc::c_long,
            ),
            ("fchown", probe_fchown_pipe_to_self),
            ("getgroups", probe_getgroups),
            ("fchdir", probe_fchdir_cwd),
            ("close_range", probe_close_range_pipe),
        ] {
            assert_eq!(
                run_seccomp_probe(&ProcessPolicy::default(), SeccompOptions::default(), probe),
                PROBE_ALLOWED,
                "{name} should pass the kernel filter"
            );
        }
        for (name, probe) in [
            (
                "linkat",
                probe_linkat_empty_paths as unsafe fn() -> libc::c_long,
            ),
            ("symlinkat", probe_symlinkat_empty_path),
        ] {
            assert_eq!(
                run_seccomp_errno_probe(
                    &ProcessPolicy::default(),
                    SeccompOptions::default(),
                    probe,
                    libc::ENOENT,
                ),
                PROBE_ALLOWED,
                "{name} should get the kernel's own answer"
            );
        }
    }

    #[test]
    fn runtime_unconfined_xattr_syscalls_return_eopnotsupp() {
        for (name, probe) in [
            (
                "xattr reads",
                probe_xattr_reads as unsafe fn() -> libc::c_long,
            ),
            ("fsetxattr", probe_fsetxattr_pipe),
        ] {
            assert_eq!(
                run_seccomp_errno_probe(
                    &ProcessPolicy::default(),
                    SeccompOptions::default(),
                    probe,
                    libc::EOPNOTSUPP,
                ),
                PROBE_ALLOWED,
                "{name} should fail with EOPNOTSUPP"
            );
        }
    }

    #[test]
    fn runtime_socket_domain_filter_denies_ip_sockets_and_preserves_unix() {
        let options = SeccompOptions::deny_network_socket_domains();

        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                options.clone(),
                probe_inet_socket
            ),
            PROBE_DENIED
        );
        assert_eq!(
            run_seccomp_probe(
                &ProcessPolicy::default(),
                options.clone(),
                probe_inet6_socket
            ),
            PROBE_DENIED
        );
        assert_eq!(
            run_seccomp_probe(&ProcessPolicy::default(), options, probe_unix_socketpair),
            PROBE_ALLOWED
        );
    }

    #[test]
    fn runtime_shell_smoke_under_filter() {
        let Some(status) = run_with_seccomp("/bin/sh", &["-c", "true"], &ProcessPolicy::default())
        else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(status.success(), "shell smoke failed: {status}");
    }

    #[test]
    fn runtime_python_smoke_under_filter_when_available() {
        let Some(python) = find_on_path("python3") else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&python).arg("-c").arg("pass").status() else {
            eprintln!("python3 baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("python3 baseline failed (test skipped)");
            return;
        }

        let status = run_with_seccomp(&python, &["-c", "pass"], &ProcessPolicy::default())
            .expect("python3 should exist after baseline check");

        assert!(status.success(), "python smoke failed: {status}");
    }

    #[test]
    fn runtime_node_smoke_under_filter_when_available() {
        let Some(node) = find_on_path("node") else {
            eprintln!("node unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&node)
            .arg("-e")
            .arg("console.log('node-seccomp-baseline')")
            .status()
        else {
            eprintln!("node baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("node baseline failed (test skipped)");
            return;
        }

        let status = run_with_seccomp(
            &node,
            &["-e", "console.log('node-seccomp-smoke')"],
            &ProcessPolicy::default(),
        )
        .expect("node should exist after baseline check");

        assert!(status.success(), "node smoke failed: {status}");
    }

    #[test]
    fn runtime_configured_blocked_syscall_denies_process() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["write".into()],
            ..Default::default()
        };
        let Some(status) = run_with_seccomp("/bin/sh", &["-c", "echo denied"], &policy) else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(
            !status.success(),
            "write-blocked shell unexpectedly succeeded"
        );
    }

    #[test]
    fn seccomp_launcher_shell_smoke_under_filter() {
        let Some(status) = run_with_seccomp_launcher(
            "/bin/sh",
            &["-c", "true"],
            &ProcessPolicy::default(),
            SeccompOptions::default(),
        ) else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(status.success(), "launcher shell smoke failed: {status}");
    }

    #[test]
    fn seccomp_launcher_python_smoke_under_filter_when_available() {
        let Some(python) = find_on_path("python3") else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&python).arg("-c").arg("pass").status() else {
            eprintln!("python3 baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("python3 baseline failed (test skipped)");
            return;
        }

        let status = run_with_seccomp_launcher(
            &python,
            &["-c", "pass"],
            &ProcessPolicy::default(),
            SeccompOptions::default(),
        )
        .expect("python3 should exist after baseline check");

        assert!(status.success(), "launcher python smoke failed: {status}");
    }

    #[test]
    fn seccomp_launcher_node_smoke_under_filter_when_available() {
        let Some(node) = find_on_path("node") else {
            eprintln!("node unavailable (test skipped)");
            return;
        };
        let Ok(baseline) = Command::new(&node)
            .arg("-e")
            .arg("console.log('node-seccomp-launcher-baseline')")
            .status()
        else {
            eprintln!("node baseline failed to start (test skipped)");
            return;
        };
        if !baseline.success() {
            eprintln!("node baseline failed (test skipped)");
            return;
        }

        let status = run_with_seccomp_launcher(
            &node,
            &["-e", "console.log('node-seccomp-launcher-smoke')"],
            &ProcessPolicy::default(),
            SeccompOptions::default(),
        )
        .expect("node should exist after baseline check");

        assert!(status.success(), "launcher node smoke failed: {status}");
    }

    #[test]
    fn seccomp_launcher_configured_blocked_syscall_denies_process() {
        let policy = ProcessPolicy {
            blocked_syscalls: vec!["write".into()],
            ..Default::default()
        };
        let Some(status) = run_with_seccomp_launcher(
            "/bin/sh",
            &["-c", "echo denied"],
            &policy,
            SeccompOptions::default(),
        ) else {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        };

        assert!(
            !status.success(),
            "launcher write-blocked shell unexpectedly succeeded"
        );
    }

    #[test]
    fn seccomp_launcher_rejects_malformed_filter_before_exec() {
        let filter = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(filter.path(), [0_u8; 3]).unwrap();

        let err = run_launcher_from_args([
            OsString::from("--filter"),
            filter.path().as_os_str().to_owned(),
            OsString::from("--"),
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("true"),
        ])
        .unwrap_err();

        assert!(err.contains("invalid byte length"));
    }

    #[test]
    fn seccomp_launcher_accepts_abstract_unix_scope_only_before_filter() {
        let filter = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(filter.path(), [0_u8; 3]).unwrap();

        let err = run_launcher_from_args([
            OsString::from(LAUNCHER_SCOPE_ABSTRACT_UNIX_FLAG),
            OsString::from("--filter"),
            filter.path().as_os_str().to_owned(),
            OsString::from("--"),
            OsString::from("/bin/true"),
        ])
        .unwrap_err();
        assert!(err.contains("invalid byte length"), "{err}");

        let err = run_launcher_from_args([
            OsString::from("--filter"),
            filter.path().as_os_str().to_owned(),
            OsString::from(LAUNCHER_SCOPE_ABSTRACT_UNIX_FLAG),
            OsString::from("/bin/true"),
        ])
        .unwrap_err();
        assert!(err.contains("expected -- command separator"), "{err}");
    }

    fn run_with_seccomp(
        program: &str,
        args: &[&str],
        policy: &ProcessPolicy,
    ) -> Option<ExitStatus> {
        if !std::path::Path::new(program).exists() {
            return None;
        }

        let filter = prepare_seccomp(policy).expect("test policy should prepare seccomp");
        let mut cmd = Command::new(program);
        cmd.args(args);
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                filter
                    .apply_current_process()
                    .map_err(std::io::Error::from_raw_os_error)
            });
        }
        Some(cmd.status().expect("seccomp runtime child should start"))
    }

    fn run_with_seccomp_launcher(
        program: &str,
        args: &[&str],
        policy: &ProcessPolicy,
        options: SeccompOptions,
    ) -> Option<ExitStatus> {
        if !std::path::Path::new(program).exists() {
            return None;
        }

        let filter = prepare_seccomp_with_options(policy, options).expect("test policy prepares");
        let mut filter_file = tempfile::NamedTempFile::new().unwrap();
        filter_file.write_all(&filter.export_bpf_bytes()).unwrap();
        filter_file.flush().unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            let mut launcher_args = vec![
                OsString::from("--filter"),
                filter_file.path().as_os_str().to_owned(),
                OsString::from("--"),
                OsString::from(program),
            ];
            launcher_args.extend(args.iter().map(|arg| OsString::from(*arg)));
            let code = run_launcher_from_args(launcher_args).unwrap_or(126);
            unsafe {
                libc::_exit(code);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed for seccomp launcher");
        Some(ExitStatus::from_raw(status))
    }

    fn run_seccomp_probe(
        policy: &ProcessPolicy,
        options: SeccompOptions,
        probe: unsafe fn() -> libc::c_long,
    ) -> i32 {
        let filter =
            prepare_seccomp_with_options(policy, options).expect("test policy should prepare");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    libc::_exit(PROBE_NO_NEW_PRIVS_FAILED);
                }
            }
            if filter.apply_current_process().is_err() {
                unsafe {
                    libc::_exit(PROBE_SECCOMP_SETUP_FAILED);
                }
            }

            let ret = unsafe { probe() };
            if ret == -1 {
                let errno = current_errno();
                let code = if errno == libc::EPERM {
                    PROBE_DENIED
                } else {
                    PROBE_UNEXPECTED_ERRNO
                };
                unsafe {
                    libc::_exit(code);
                }
            }

            unsafe {
                libc::_exit(PROBE_ALLOWED);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed for seccomp probe");

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            PROBE_SIGNALLED
        }
    }

    fn run_seccomp_errno_probe(
        policy: &ProcessPolicy,
        options: SeccompOptions,
        probe: unsafe fn() -> libc::c_long,
        expected_errno: i32,
    ) -> i32 {
        let filter =
            prepare_seccomp_with_options(policy, options).expect("test policy should prepare");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    libc::_exit(PROBE_NO_NEW_PRIVS_FAILED);
                }
            }
            if filter.apply_current_process().is_err() {
                unsafe {
                    libc::_exit(PROBE_SECCOMP_SETUP_FAILED);
                }
            }

            let ret = unsafe { probe() };
            if ret == -1 {
                let code = if current_errno() == expected_errno {
                    PROBE_ALLOWED
                } else {
                    PROBE_UNEXPECTED_ERRNO
                };
                unsafe {
                    libc::_exit(code);
                }
            }

            unsafe {
                libc::_exit(PROBE_UNEXPECTED_ERRNO);
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed for seccomp errno probe");

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            PROBE_SIGNALLED
        }
    }

    unsafe fn probe_execveat_empty_path() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_EXECVEAT as libc::c_long,
                -1,
                c"".as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                AT_EMPTY_PATH,
            )
        }
    }

    unsafe fn probe_clone3_unavailable() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_CLONE3 as libc::c_long,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        }
    }

    unsafe fn probe_inet_socket() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_SOCKET as libc::c_long,
                libc::AF_INET,
                libc::SOCK_STREAM,
                0,
            )
        }
    }

    unsafe fn probe_inet6_socket() -> libc::c_long {
        unsafe {
            libc::syscall(
                SYS_SOCKET as libc::c_long,
                libc::AF_INET6,
                libc::SOCK_STREAM,
                0,
            )
        }
    }

    /// Re-applies the calling thread's own CPU mask, as `pthread_setaffinity_np` would.
    unsafe fn probe_sched_setaffinity_self() -> libc::c_long {
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        if unsafe { libc::sched_getaffinity(0, size, &mut mask) } != 0 {
            unsafe { libc::_exit(PROBE_UNEXPECTED_ERRNO) }
        }
        unsafe {
            libc::syscall(
                SYS_SCHED_SETAFFINITY as libc::c_long,
                0,
                size,
                &mask as *const libc::cpu_set_t,
            )
        }
    }

    /// The caller owns a fresh pipe, so the kernel permits `fchmod`/`fchown` on it.
    unsafe fn probe_pipe_read_end() -> libc::c_int {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            unsafe { libc::_exit(PROBE_UNEXPECTED_ERRNO) }
        }
        fds[0]
    }

    unsafe fn probe_fchmod_pipe_to_current_mode() -> libc::c_long {
        let fd = unsafe { probe_pipe_read_end() };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            unsafe { libc::_exit(PROBE_UNEXPECTED_ERRNO) }
        }
        unsafe { libc::syscall(libc::SYS_fchmod, fd, st.st_mode & 0o7777) }
    }

    unsafe fn probe_fchown_pipe_to_self() -> libc::c_long {
        let fd = unsafe { probe_pipe_read_end() };
        unsafe { libc::syscall(libc::SYS_fchown, fd, libc::geteuid(), libc::getegid()) }
    }

    unsafe fn probe_getgroups() -> libc::c_long {
        unsafe { libc::syscall(libc::SYS_getgroups, 0, std::ptr::null_mut::<libc::gid_t>()) }
    }

    unsafe fn probe_fchdir_cwd() -> libc::c_long {
        let fd = unsafe {
            libc::open(
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            unsafe { libc::_exit(PROBE_UNEXPECTED_ERRNO) }
        }
        unsafe { libc::syscall(libc::SYS_fchdir, fd) }
    }

    unsafe fn probe_close_range_pipe() -> libc::c_long {
        let fd = unsafe { probe_pipe_read_end() };
        unsafe { libc::syscall(libc::SYS_close_range, fd, fd, 0) }
    }

    /// Empty paths make the kernel answer `ENOENT` without creating anything.
    unsafe fn probe_linkat_empty_paths() -> libc::c_long {
        unsafe {
            libc::syscall(
                libc::SYS_linkat,
                libc::AT_FDCWD,
                c"".as_ptr(),
                libc::AT_FDCWD,
                c"".as_ptr(),
                0,
            )
        }
    }

    unsafe fn probe_symlinkat_empty_path() -> libc::c_long {
        unsafe {
            libc::syscall(
                libc::SYS_symlinkat,
                c"axis-probe".as_ptr(),
                libc::AT_FDCWD,
                c"".as_ptr(),
            )
        }
    }

    /// Fails with `EOPNOTSUPP` only if every read does. Unfiltered, the kernel
    /// answers these with `ENODATA` or an empty list, and the `*xattrat` calls
    /// with `ENOENT` for the empty path or `ENOSYS` before Linux 6.13.
    unsafe fn probe_xattr_reads() -> libc::c_long {
        let fd = unsafe { probe_pipe_read_end() };
        let mut path_buf = [0u8; 32];
        let path = super::super::proc_self_fd_path(fd, &mut path_buf);
        let name = c"user.axis-probe".as_ptr();
        let list = std::ptr::null_mut::<libc::c_char>();
        let value = std::ptr::null_mut::<libc::c_void>();
        let reads: [&dyn Fn() -> libc::c_long; 8] = [
            &|| unsafe { libc::syscall(libc::SYS_getxattr, path, name, value, 0) },
            &|| unsafe { libc::syscall(libc::SYS_lgetxattr, path, name, value, 0) },
            &|| unsafe { libc::syscall(libc::SYS_fgetxattr, fd, name, value, 0) },
            &|| unsafe { libc::syscall(libc::SYS_listxattr, path, list, 0) },
            &|| unsafe { libc::syscall(libc::SYS_llistxattr, path, list, 0) },
            &|| unsafe { libc::syscall(libc::SYS_flistxattr, fd, list, 0) },
            &|| unsafe { libc::syscall(SYS_GETXATTRAT, fd, c"".as_ptr(), 0, name, value, 0) },
            &|| unsafe { libc::syscall(SYS_LISTXATTRAT, fd, c"".as_ptr(), 0, list, 0) },
        ];
        for read in reads {
            let ret = read();
            if ret != -1 || current_errno() != libc::EOPNOTSUPP {
                return ret;
            }
        }
        -1
    }

    /// The kernel itself answers `EPERM` here, so `EOPNOTSUPP` comes from the filter.
    unsafe fn probe_fsetxattr_pipe() -> libc::c_long {
        let fd = unsafe { probe_pipe_read_end() };
        unsafe {
            libc::syscall(
                libc::SYS_fsetxattr,
                fd,
                c"user.axis-probe".as_ptr(),
                c"1".as_ptr(),
                1,
                0,
            )
        }
    }

    unsafe fn probe_unix_socketpair() -> libc::c_long {
        let mut fds = [0; 2];
        unsafe {
            libc::syscall(
                SYS_SOCKETPAIR as libc::c_long,
                AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr(),
            )
        }
    }

    fn bpf_decision_for(
        spec: &SeccompFilterSpec,
        arch: u32,
        syscall_nr: u32,
        args: [u64; 6],
    ) -> FilterDecision {
        decode_seccomp_action(interpret_bpf(&spec.to_bpf(), arch, syscall_nr, args))
    }

    fn prepared_bpf_decision_for(
        filter: &PreparedSeccompFilter,
        arch: u32,
        syscall_nr: u32,
        args: [u64; 6],
    ) -> FilterDecision {
        decode_seccomp_action(interpret_bpf(&filter.insns, arch, syscall_nr, args))
    }

    fn interpret_bpf(insns: &[BpfInsn], arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;

        loop {
            let insn = insns
                .get(pc)
                .unwrap_or_else(|| panic!("seccomp BPF program fell off at pc {pc}"));
            match insn.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    accumulator = load_seccomp_word(insn.k, arch, syscall_nr, args);
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    let skip = if accumulator == insn.k {
                        insn.jt
                    } else {
                        insn.jf
                    };
                    pc += 1 + usize::from(skip);
                }
                code if code == (BPF_JMP | BPF_JSET | BPF_K) => {
                    let skip = if (accumulator & insn.k) != 0 {
                        insn.jt
                    } else {
                        insn.jf
                    };
                    pc += 1 + usize::from(skip);
                }
                code if code == (BPF_ALU | BPF_AND | BPF_K) => {
                    accumulator &= insn.k;
                    pc += 1;
                }
                code if code == (BPF_RET | BPF_K) => return insn.k,
                other => panic!("unsupported seccomp BPF opcode {other:#x} at pc {pc}"),
            }
        }
    }

    fn load_seccomp_word(offset: u32, arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
        match offset {
            SECCOMP_DATA_NR_OFFSET => syscall_nr,
            SECCOMP_DATA_ARCH_OFFSET => arch,
            offset
                if (SECCOMP_DATA_ARGS_OFFSET..SECCOMP_DATA_ARGS_OFFSET + ARG_SIZE * 6)
                    .contains(&offset) =>
            {
                let relative = offset - SECCOMP_DATA_ARGS_OFFSET;
                let arg = args[(relative / ARG_SIZE) as usize];
                match relative % ARG_SIZE {
                    0 => arg as u32,
                    4 => (arg >> 32) as u32,
                    _ => panic!("unaligned seccomp argument load offset {offset}"),
                }
            }
            _ => panic!("unsupported seccomp data load offset {offset}"),
        }
    }

    fn decode_seccomp_action(action: u32) -> FilterDecision {
        if action == SECCOMP_RET_KILL_PROCESS {
            FilterDecision::KillProcess
        } else if action == SECCOMP_RET_ALLOW {
            FilterDecision::Allow
        } else if action == SECCOMP_RET_USER_NOTIF {
            FilterDecision::UserNotify
        } else if (action & 0xffff_0000) == SECCOMP_RET_ERRNO {
            FilterDecision::Errno((action & 0xffff) as i32)
        } else {
            panic!("unsupported seccomp return action {action:#x}")
        }
    }

    fn find_on_path(binary: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
        None
    }
}
