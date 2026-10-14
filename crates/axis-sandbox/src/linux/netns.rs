// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace + veth pair creation for sandbox network isolation.
//!
//! Creates a network namespace with a veth pair routing all sandbox traffic
//! through the AXIS proxy. All bypass attempts are logged and rejected.
//!
//! Strategy: use `ip` commands which handle the netns/veth/iptables setup.
//! This requires either root (via setuid helper) or CAP_NET_ADMIN.
//! For unprivileged sandboxes, we use `unshare --net` in the pre_exec path
//! and set up the namespace from the parent.

use axis_core::policy::{FilesystemPolicy, ProcessPolicy};
use axis_core::types::SandboxId;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

const PROXY_NET_A: u8 = 10;
const PROXY_PREFIX_LEN: u8 = 30;
const PROXY_SUBNET_COUNT: u32 = 1 << 22;
const AXIS_NETNS_HELPER_PATH: &str = "/usr/libexec/axis/axis-netns-helper";
const HELPER_STATE_DIR: &str = "/run/axis/netns";
const HELPER_SYNC_OK: &str = "OK\n";
const MAX_ACTIVE_HELPER_NETNS_PER_UID: usize = 32;
const HELPER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const HELPER_COMMAND_KILL_TIMEOUT: Duration = Duration::from_millis(500);
const HELPER_POLL_INTERVAL: Duration = Duration::from_millis(20);
const HELPER_PAYLOAD_EXIT_TIMEOUT: Duration = Duration::from_millis(500);
const HELPER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const HELPER_STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const HELPER_EXIT_ALREADY_COMPLETED: i32 = 10;
const HELPER_CONTROL_PLANE_MIN_NOFILE: libc::rlim_t = 64;
const HELPER_CONTROL_PLANE_MIN_FSIZE: libc::rlim_t = 1024 * 1024;
const HELPER_CONTROL_PLANE_MIN_CPU: libc::rlim_t = 60;
const HELPER_CONTROL_PLANE_MIN_AS: libc::rlim_t = 256 * 1024 * 1024;
const HELPER_CONTROL_PLANE_MIN_DATA: libc::rlim_t = 64 * 1024 * 1024;
const HELPER_CONTROL_PLANE_MIN_NPROC: libc::rlim_t = 64;
const MXC_EXECUTOR_NAME: &str = "lxc-exec";
const MXC_HELPER_EXECUTOR_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNetnsAllocation {
    pub sandbox_id: SandboxId,
    pub namespace: String,
    pub veth_host: String,
    pub veth_sandbox: String,
    pub host_addr: Ipv4Addr,
    pub sandbox_addr: Ipv4Addr,
    pub host_cidr: String,
    pub sandbox_cidr: String,
    pub subnet_cidr: String,
    pub proxy_addr: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HelperLaunchSpec {
    #[serde(default)]
    pub launch_kind: HelperLaunchKind,
    #[serde(default)]
    pub mxc_config_fd: Option<RawFd>,
    pub workspace_dir: std::path::PathBuf,
    pub filesystem: FilesystemPolicy,
    pub process: ProcessPolicy,
    pub rlimits: HelperRlimits,
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub destroy_token: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperLaunchKind {
    #[default]
    DirectProcess,
    MxcExecutor,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HelperRlimits {
    pub address_space_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetnsCommand {
    program: String,
    args: Vec<String>,
    ignore_missing_link: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CreatedNetnsResources {
    namespace: bool,
    host_veth: bool,
}

impl CreatedNetnsResources {
    fn record_command_success(&mut self, command_index: usize) {
        match command_index {
            0 => self.namespace = true,
            1 => self.host_veth = true,
            _ => {}
        }
    }

    fn complete() -> Self {
        Self {
            namespace: true,
            host_veth: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetnsCommandPaths {
    ip: String,
    iptables: String,
    sysctl: String,
}

impl NetnsCommandPaths {
    #[cfg(test)]
    fn path_names() -> Self {
        Self {
            ip: "ip".into(),
            iptables: "iptables".into(),
            sysctl: "sysctl".into(),
        }
    }

    fn fixed_system_paths() -> Result<Self, String> {
        Ok(Self {
            ip: fixed_system_command("ip")?,
            iptables: fixed_system_command("iptables")?,
            sysctl: fixed_system_command("sysctl")?,
        })
    }
}

trait CommandRunner {
    fn run(&mut self, command: &NetnsCommand, owner_guard_fd: Option<RawFd>) -> Result<(), String>;
}

struct ProcessCommandRunner;

impl ProcessCommandRunner {
    const COMMAND_UID: PrivilegedCommandUid = PrivilegedCommandUid::Preserve;
}

impl CommandRunner for ProcessCommandRunner {
    fn run(&mut self, command: &NetnsCommand, owner_guard_fd: Option<RawFd>) -> Result<(), String> {
        run_netns_command(command, owner_guard_fd, Self::COMMAND_UID)
    }
}

struct PrivilegedCommandRunner {
    paths: NetnsCommandPaths,
}

impl PrivilegedCommandRunner {
    const COMMAND_UID: PrivilegedCommandUid = PrivilegedCommandUid::NormalizeRoot;

    fn new() -> Result<Self, String> {
        ensure_helper_privileged()?;
        set_no_new_privs()?;
        Ok(Self {
            paths: NetnsCommandPaths::fixed_system_paths()?,
        })
    }
}

impl CommandRunner for PrivilegedCommandRunner {
    fn run(&mut self, command: &NetnsCommand, owner_guard_fd: Option<RawFd>) -> Result<(), String> {
        run_netns_command(command, owner_guard_fd, Self::COMMAND_UID)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivilegedCommandUid {
    Preserve,
    NormalizeRoot,
}

fn run_netns_command(
    command: &NetnsCommand,
    owner_guard_fd: Option<RawFd>,
    command_uid: PrivilegedCommandUid,
) -> Result<(), String> {
    match run_privileged_command_in_namespace(
        &command.program,
        &command.args,
        owner_guard_fd,
        HELPER_COMMAND_TIMEOUT,
        command_uid,
    ) {
        Err(_) if command.ignore_missing_link && command_host_link_is_absent(command) => Ok(()),
        result => result,
    }
}

fn command_host_link_is_absent(command: &NetnsCommand) -> bool {
    let [action, operation, interface] = command.args.as_slice() else {
        return false;
    };
    action == "link"
        && operation == "del"
        && std::fs::symlink_metadata(std::path::Path::new("/sys/class/net").join(interface))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Create a network namespace with veth pair and iptables rules.
///
/// The namespace routes all traffic through the AXIS proxy.
/// Returns the namespace name on success.
pub fn create_netns(sandbox_id: SandboxId, proxy_port: u16) -> Result<String, String> {
    let allocation = proxy_netns_allocation(sandbox_id, proxy_port);

    let strategy = detect_strategy();
    tracing::info!(
        "netns: using strategy '{strategy}' for namespace '{}'",
        allocation.namespace
    );

    match strategy {
        NetnsStrategy::IpNetns => {
            let paths = NetnsCommandPaths::fixed_system_paths()?;
            let mut runner = ProcessCommandRunner;
            match create_with_runner_and_paths(&allocation, &paths, &mut runner) {
                Ok(name) => Ok(name),
                Err(e) => Err(e),
            }
        }
        NetnsStrategy::Bubblewrap => {
            // Bubblewrap mode: network isolation is all-or-nothing (no proxy).
            // The sandbox gets --unshare-net which creates an isolated netns
            // with no connectivity at all.
            tracing::info!("netns: bubblewrap mode — sandbox will have no network access");
            Ok(allocation.namespace)
        }
        NetnsStrategy::Unavailable => {
            Err("no network namespace strategy available (need ip command or bubblewrap)".into())
        }
    }
}

pub fn proxy_bind_addr(sandbox_id: SandboxId, proxy_port: u16) -> SocketAddr {
    proxy_netns_allocation(sandbox_id, proxy_port).proxy_addr
}

pub fn proxy_netns_allocation(sandbox_id: SandboxId, proxy_port: u16) -> ProxyNetnsAllocation {
    let sandbox_name = sandbox_id.to_string();
    let namespace = format!("axis-{sandbox_name}");
    let veth_host = veth_host_name(&sandbox_name);
    let veth_sandbox = veth_sandbox_name(&sandbox_name);
    let subnet_index = subnet_index(sandbox_id);
    let network_host_bits = subnet_index << 2;
    let host_addr = proxy_addr_from_host_bits(network_host_bits + 1);
    let sandbox_addr = proxy_addr_from_host_bits(network_host_bits + 2);
    let network_addr = proxy_addr_from_host_bits(network_host_bits);
    ProxyNetnsAllocation {
        sandbox_id,
        namespace,
        veth_host,
        veth_sandbox,
        host_addr,
        sandbox_addr,
        host_cidr: format!("{host_addr}/{PROXY_PREFIX_LEN}"),
        sandbox_cidr: format!("{sandbox_addr}/{PROXY_PREFIX_LEN}"),
        subnet_cidr: format!("{network_addr}/{PROXY_PREFIX_LEN}"),
        proxy_addr: SocketAddr::new(host_addr.into(), proxy_port),
    }
}

fn subnet_index(sandbox_id: SandboxId) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in sandbox_id.0.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % PROXY_SUBNET_COUNT
}

fn proxy_addr_from_host_bits(host_bits: u32) -> Ipv4Addr {
    debug_assert!(host_bits < (1 << 24));
    Ipv4Addr::new(
        PROXY_NET_A,
        (host_bits >> 16) as u8,
        (host_bits >> 8) as u8,
        host_bits as u8,
    )
}

#[cfg(test)]
fn create_with_runner(
    allocation: &ProxyNetnsAllocation,
    runner: &mut dyn CommandRunner,
) -> Result<String, String> {
    create_with_runner_and_paths(allocation, &NetnsCommandPaths::path_names(), runner)
}

fn create_with_runner_and_paths(
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<String, String> {
    let mut created = CreatedNetnsResources::default();
    for (index, command) in create_command_plan_with_paths(allocation, paths)
        .into_iter()
        .enumerate()
    {
        if let Err(e) = runner.run(&command, None) {
            let cleanup = rollback_created_resources(allocation, created, paths, runner);
            return Err(append_cleanup_error(e, cleanup));
        }
        created.record_command_success(index);
    }

    tracing::info!(
        "netns: created '{}' with veth {}<->{}, proxy={}",
        allocation.namespace,
        allocation.veth_host,
        allocation.veth_sandbox,
        allocation.proxy_addr
    );
    Ok(allocation.namespace.clone())
}

#[cfg(test)]
fn create_command_plan(allocation: &ProxyNetnsAllocation) -> Vec<NetnsCommand> {
    create_command_plan_with_paths(allocation, &NetnsCommandPaths::path_names())
}

fn create_command_plan_with_paths(
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
) -> Vec<NetnsCommand> {
    let ns = &allocation.namespace;
    let host = &allocation.veth_host;
    let sandbox = &allocation.veth_sandbox;
    let proxy_port = allocation.proxy_addr.port().to_string();
    let bypass_log_prefix = super::bypass_audit::bypass_log_prefix(allocation.sandbox_id);
    vec![
        ip_with_paths(paths, ["netns", "add", ns]),
        ip_with_paths(
            paths,
            ["link", "add", host, "type", "veth", "peer", "name", sandbox],
        ),
        ip_with_paths(paths, ["link", "set", sandbox, "netns", ns]),
        ip_with_paths(paths, ["addr", "add", &allocation.host_cidr, "dev", host]),
        ip_with_paths(paths, ["link", "set", host, "up"]),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.ip,
                "addr",
                "add",
                &allocation.sandbox_cidr,
                "dev",
                sandbox,
            ],
        ),
        ip_with_paths(
            paths,
            ["netns", "exec", ns, &paths.ip, "link", "set", sandbox, "up"],
        ),
        ip_with_paths(
            paths,
            ["netns", "exec", ns, &paths.ip, "link", "set", "lo", "up"],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.sysctl,
                "-w",
                "net.ipv6.conf.all.disable_ipv6=1",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.sysctl,
                "-w",
                "net.ipv6.conf.default.disable_ipv6=1",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.ip,
                "route",
                "add",
                "default",
                "via",
                &allocation.host_addr.to_string(),
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-j",
                "ACCEPT",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-d",
                &allocation.host_addr.to_string(),
                "-p",
                "tcp",
                "--dport",
                &proxy_port,
                "-j",
                "ACCEPT",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-j",
                "LOG",
                "--log-prefix",
                &bypass_log_prefix,
                "--log-level",
                "4",
            ],
        ),
        ip_with_paths(
            paths,
            [
                "netns",
                "exec",
                ns,
                &paths.iptables,
                "-A",
                "OUTPUT",
                "-j",
                "REJECT",
            ],
        ),
    ]
}

/// Destroy a network namespace and clean up its veth pair.
pub fn destroy_netns(ns_name: &str) -> Result<(), String> {
    match detect_strategy() {
        NetnsStrategy::IpNetns => {
            let paths = NetnsCommandPaths::fixed_system_paths()?;
            let mut runner = ProcessCommandRunner;
            destroy_with_runner_and_paths(ns_name, &paths, &mut runner)
        }
        NetnsStrategy::Bubblewrap | NetnsStrategy::Unavailable => {
            Err("no network namespace cleanup strategy available".into())
        }
    }
}

#[cfg(test)]
fn destroy_with_runner(ns_name: &str, runner: &mut dyn CommandRunner) -> Result<(), String> {
    let sandbox_name = sandbox_name_from_netns(ns_name);
    let mut failures = Vec::new();
    for command in destroy_command_plan(ns_name, sandbox_name) {
        if let Err(e) = runner.run(&command, None) {
            if command.ignore_missing_link && is_missing_link_error(&e) {
                tracing::debug!("netns cleanup command ignored absent link: {e}");
                continue;
            }
            tracing::debug!("netns cleanup command failed: {e}");
            failures.push(e);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
fn destroy_command_plan(ns_name: &str, sandbox_name: &str) -> Vec<NetnsCommand> {
    destroy_command_plan_with_paths(ns_name, sandbox_name, &NetnsCommandPaths::path_names())
}

fn destroy_command_plan_with_paths(
    ns_name: &str,
    sandbox_name: &str,
    paths: &NetnsCommandPaths,
) -> Vec<NetnsCommand> {
    vec![
        ip_with_paths(paths, ["netns", "del", ns_name]),
        ip_ignore_missing_link_with_paths(paths, ["link", "del", &veth_host_name(sandbox_name)]),
    ]
}

fn rollback_created_resources(
    allocation: &ProxyNetnsAllocation,
    created: CreatedNetnsResources,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if created.host_veth {
        let command =
            ip_ignore_missing_link_with_paths(paths, ["link", "del", &allocation.veth_host]);
        if let Err(error) = runner.run(&command, None)
            && !is_missing_link_error(&error)
        {
            failures.push(error);
        }
    }
    if created.namespace {
        let command = ip_with_paths(paths, ["netns", "del", &allocation.namespace]);
        if let Err(error) = runner.run(&command, None) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Enter an existing network namespace (for axis exec).
/// Returns an fd to the namespace that can be used with setns().
pub fn enter_netns(ns_name: &str) -> Result<i32, String> {
    let ns_path = format!("/var/run/netns/{ns_name}");
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(ns_path.as_str()).unwrap().as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot open netns '{ns_name}': {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

/// Run a command, returning Ok on success or Err with stderr on failure.
#[cfg(test)]
fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{program} {} failed: {stderr}", args.join(" ")))
    }
}

#[cfg(test)]
fn run_cmd_cleared_env_with_timeout(
    program: &str,
    args: &[String],
    owner_guard_fd: Option<RawFd>,
    timeout: Duration,
) -> Result<(), String> {
    let status = run_cmd_cleared_env_status_with_timeout(program, args, owner_guard_fd, timeout)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "privileged command '{program}' failed with status {status}"
        ))
    }
}

fn run_cmd_cleared_env_status_with_timeout(
    program: &str,
    args: &[String],
    owner_guard_fd: Option<RawFd>,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    unsafe {
        command.pre_exec(|| {
            super::mark_unexpected_child_fds_close_on_exec()
                .map_err(std::io::Error::from_raw_os_error)
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to run privileged command '{program}': {e}"))?;
    let child_pid = libc::pid_t::try_from(child.id())
        .map_err(|_| format!("privileged command '{program}' returned an invalid process id"))?;
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(e) => return Err(format!("wait for privileged command '{program}': {e}")),
        }

        if let Some(fd) = owner_guard_fd
            && let Err(owner_error) = ensure_owner_guard_alive(fd)
        {
            let termination = terminate_command_process_group(&mut child, child_pid, program);
            return Err(match termination {
                Ok(()) => owner_error,
                Err(error) => format!("{owner_error}; {error}"),
            });
        }

        if Instant::now() >= deadline {
            let termination = terminate_command_process_group(&mut child, child_pid, program);
            let timeout_error = format!(
                "privileged command '{program}' exceeded its {} ms deadline",
                timeout.as_millis()
            );
            return Err(match termination {
                Ok(()) => timeout_error,
                Err(error) => format!("{timeout_error}; {error}"),
            });
        }

        std::thread::sleep(
            HELPER_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn run_privileged_command_in_namespace(
    program: &str,
    args: &[String],
    owner_guard_fd: Option<RawFd>,
    timeout: Duration,
    command_uid: PrivilegedCommandUid,
) -> Result<(), String> {
    let mut launcher = Clone3CommandNamespaceLauncher { command_uid };
    run_privileged_command_in_namespace_with(program, args, owner_guard_fd, timeout, &mut launcher)
}

trait CommandNamespaceLauncher {
    fn launch(&mut self, program: &str, args: &[String]) -> Result<libc::pid_t, String>;

    fn try_wait(&mut self, pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error>;

    fn terminate(&mut self, pid: libc::pid_t) -> Result<(), String>;
}

struct Clone3CommandNamespaceLauncher {
    command_uid: PrivilegedCommandUid,
}

impl CommandNamespaceLauncher for Clone3CommandNamespaceLauncher {
    fn launch(&mut self, program: &str, args: &[String]) -> Result<libc::pid_t, String> {
        let helper_guard_fd = open_self_pidfd()?;
        let init_pid = match clone_pid_namespace_init() {
            Ok(pid) => pid,
            Err(error) => {
                close_fds(&[helper_guard_fd]);
                return Err(error);
            }
        };
        if init_pid == 0 {
            run_command_namespace_init_with(
                program,
                args,
                helper_guard_fd,
                true,
                self.command_uid == PrivilegedCommandUid::NormalizeRoot,
            );
        }
        close_fds(&[helper_guard_fd]);
        Ok(init_pid)
    }

    fn try_wait(&mut self, pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
        try_wait_for_child(pid)
    }

    fn terminate(&mut self, pid: libc::pid_t) -> Result<(), String> {
        terminate_namespace_init(pid)
    }
}

fn run_privileged_command_in_namespace_with<L: CommandNamespaceLauncher>(
    program: &str,
    args: &[String],
    owner_guard_fd: Option<RawFd>,
    timeout: Duration,
    launcher: &mut L,
) -> Result<(), String> {
    let command = format_privileged_command(program, args);
    let init_pid = launcher.launch(program, args)?;

    let deadline = Instant::now() + timeout;
    loop {
        match launcher.try_wait(init_pid) {
            Ok(Some(status)) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => {
                return Ok(());
            }
            Ok(Some(status)) => {
                return Err(format!(
                    "privileged command '{command}' failed with status {}",
                    helper_wait_status_code(status)
                ));
            }
            Ok(None) => {}
            Err(error) => {
                let wait_error = format!("wait for privileged command namespace init: {error}");
                let termination = launcher.terminate(init_pid);
                return Err(match termination {
                    Ok(()) => wait_error,
                    Err(error) => format!("{wait_error}; {error}"),
                });
            }
        }

        if let Some(fd) = owner_guard_fd
            && let Err(owner_error) = ensure_owner_guard_alive(fd)
        {
            let termination = launcher.terminate(init_pid);
            return Err(match termination {
                Ok(()) => owner_error,
                Err(error) => format!("{owner_error}; {error}"),
            });
        }
        if Instant::now() >= deadline {
            let termination = launcher.terminate(init_pid);
            let timeout_error = format!(
                "privileged command '{command}' exceeded its {} ms deadline",
                timeout.as_millis()
            );
            return Err(match termination {
                Ok(()) => timeout_error,
                Err(error) => format!("{timeout_error}; {error}"),
            });
        }
        std::thread::sleep(
            HELPER_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn format_privileged_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_command_namespace_init_with(
    program: &str,
    args: &[String],
    helper_guard_fd: RawFd,
    terminate_after_primary: bool,
    normalize_root_uid: bool,
) -> ! {
    if arm_parent_death_signal(helper_guard_fd).is_err() {
        unsafe { libc::_exit(126) };
    }
    close_fds(&[helper_guard_fd]);
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        unsafe { libc::_exit(126) };
    }
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(126) };
    }
    if super::mark_unexpected_child_fds_close_on_exec().is_err() {
        unsafe { libc::_exit(126) };
    }

    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if normalize_root_uid {
                // Netfilter rejects setuid callers (exit 111), so trusted
                // system tools must not inherit the helper's mixed UID state.
                normalize_privileged_command_uid().map_err(std::io::Error::from_raw_os_error)?;
            }
            super::mark_unexpected_child_fds_close_on_exec()
                .map_err(std::io::Error::from_raw_os_error)
        });
    }
    let primary = match command.spawn() {
        Ok(child) => child.id() as libc::pid_t,
        Err(_) => unsafe { libc::_exit(126) },
    };
    let result = reap_namespace_children_with(primary, terminate_after_primary);
    unsafe { libc::_exit(result.exit_code) };
}

fn normalize_privileged_command_uid() -> Result<(), i32> {
    normalize_privileged_command_uid_with(unsafe { libc::geteuid() }, || {
        let result = unsafe { libc::setresuid(0, 0, 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(super::current_errno())
        }
    })
}

fn normalize_privileged_command_uid_with<F>(effective_uid: u32, set_root_ids: F) -> Result<(), i32>
where
    F: FnOnce() -> Result<(), i32>,
{
    if effective_uid != 0 {
        return Err(libc::EPERM);
    }
    set_root_ids()
}

fn try_wait_for_child(pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(Some(status));
        }
        if waited == 0 {
            return Ok(None);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

fn terminate_namespace_init(pid: libc::pid_t) -> Result<(), String> {
    let killed = unsafe { libc::kill(pid, libc::SIGKILL) };
    if killed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(format!(
            "terminate command PID namespace init {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let deadline = Instant::now() + HELPER_COMMAND_KILL_TIMEOUT;
    loop {
        match try_wait_for_child(pid) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(HELPER_POLL_INTERVAL),
            Ok(None) => {
                return Err(format!(
                    "command PID namespace init {pid} did not exit after SIGKILL"
                ));
            }
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn terminate_command_process_group(
    child: &mut std::process::Child,
    child_pid: libc::pid_t,
    program: &str,
) -> Result<(), String> {
    let mut failures = Vec::new();
    let group_kill = unsafe { libc::kill(-child_pid, libc::SIGKILL) };
    if group_kill < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        failures.push(format!(
            "terminate privileged command group for '{program}': {}",
            std::io::Error::last_os_error()
        ));
    }
    if let Err(error) = child.kill()
        && error.raw_os_error() != Some(libc::ESRCH)
    {
        failures.push(format!("terminate privileged command '{program}': {error}"));
    }

    let deadline = Instant::now() + HELPER_COMMAND_KILL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(HELPER_POLL_INTERVAL),
            Ok(None) => {
                failures.push(format!(
                    "privileged command '{program}' did not exit after SIGKILL"
                ));
                break;
            }
            Err(error) => {
                failures.push(format!("reap privileged command '{program}': {error}"));
                break;
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Check which netns creation strategy is available on this system.
pub fn detect_strategy() -> NetnsStrategy {
    // Check if `ip netns` is available and we have permission.
    if let Ok(paths) = NetnsCommandPaths::fixed_system_paths()
        && let Ok(output) = Command::new(&paths.ip)
            .args(["netns", "list"])
            .env_clear()
            .output()
        && output.status.success()
    {
        return NetnsStrategy::IpNetns;
    }

    // Check for bubblewrap.
    if which("bwrap") {
        return NetnsStrategy::Bubblewrap;
    }

    NetnsStrategy::Unavailable
}

fn which(binary: &str) -> bool {
    Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn helper_available() -> bool {
    let helper = helper_path();
    if !safe_root_executable(helper) {
        return false;
    }

    Command::new(helper)
        .arg("check")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub(crate) fn helper_path() -> &'static std::path::Path {
    std::path::Path::new(AXIS_NETNS_HELPER_PATH)
}

pub(super) fn fixed_system_tool_available(binary: &str) -> bool {
    fixed_system_command(binary).is_ok()
}

pub(crate) fn new_destroy_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub(crate) fn create_launch_spec_fd(spec: &HelperLaunchSpec) -> Result<RawFd, String> {
    let bytes = serde_json::to_vec(spec).map_err(|e| format!("helper launch spec: {e}"))?;
    create_sealed_memfd("axis-netns-launch", "helper launch spec", &bytes)
}

pub(crate) fn create_mxc_config_fd(bytes: &[u8]) -> Result<RawFd, String> {
    create_sealed_memfd("axis-mxc-config", "MXC helper config", bytes)
}

fn create_sealed_memfd(name: &str, label: &str, bytes: &[u8]) -> Result<RawFd, String> {
    let name = std::ffi::CString::new(name).map_err(|e| format!("{label} memfd name: {e}"))?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if fd < 0 {
        return Err(format!(
            "{label} memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if let Err(errno) = super::write_all_fd(fd, bytes) {
        unsafe {
            libc::close(fd);
        }
        return Err(format!(
            "{label} write failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if offset < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("{label} rewind failed: {error}"));
    }

    if let Err(e) = seal_memfd(fd, label) {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

fn seal_memfd(fd: RawFd, label: &str) -> Result<(), String> {
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let ret = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
    if ret < 0 {
        Err(format!(
            "{label} seal failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn read_helper_sync(read_fd: RawFd) -> Result<(), String> {
    read_helper_sync_with_timeout(read_fd, HELPER_STARTUP_TIMEOUT)
}

fn read_helper_sync_with_timeout(read_fd: RawFd, timeout: Duration) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 256];
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            close_fds(&[read_fd]);
            return Err(format!(
                "helper setup status exceeded its {} ms deadline",
                timeout.as_millis()
            ));
        }
        let mut poll_fd = libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms.max(1)) };
        if polled == 0 {
            close_fds(&[read_fd]);
            return Err(format!(
                "helper setup status exceeded its {} ms deadline",
                timeout.as_millis()
            ));
        }
        if polled < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            close_fds(&[read_fd]);
            return Err(format!("poll helper setup status failed: {error}"));
        }

        let ret = unsafe {
            libc::read(
                read_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            close_fds(&[read_fd]);
            return Err(format!("helper sync read failed: {error}"));
        }
        if ret == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..ret as usize]);
        if bytes.len() > 4096 {
            close_fds(&[read_fd]);
            return Err("helper sync message exceeded 4096 bytes".into());
        }
    }
    close_fds(&[read_fd]);

    let message = String::from_utf8_lossy(&bytes);
    if message == HELPER_SYNC_OK {
        Ok(())
    } else if let Some(error) = message.strip_prefix("ERR ") {
        Err(error.trim_end().to_string())
    } else if message.is_empty() {
        Err("helper exited before reporting setup status".into())
    } else {
        Err(format!("invalid helper setup status: {message:?}"))
    }
}

pub(crate) fn destroy_netns_with_helper_token(
    sandbox_id: SandboxId,
    destroy_token: &str,
) -> Result<HelperCleanupOutcome, String> {
    if !valid_destroy_token(destroy_token) {
        return Err("invalid helper destroy token".into());
    }
    let id = sandbox_id.to_string();
    let args = vec!["destroy-token".to_string(), id, destroy_token.to_string()];
    let program = helper_path().to_string_lossy();
    let status = run_cmd_cleared_env_status_with_timeout(
        program.as_ref(),
        &args,
        None,
        HELPER_COMMAND_TIMEOUT,
    )?;
    match status.code() {
        Some(0) => Ok(HelperCleanupOutcome::Destroyed),
        Some(HELPER_EXIT_ALREADY_COMPLETED) => Ok(HelperCleanupOutcome::AlreadyCompleted),
        _ => Err(format!(
            "privileged helper cleanup command failed with status {status}"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperCleanupOutcome {
    Destroyed,
    AlreadyCompleted,
}

fn valid_destroy_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sandbox_name_from_netns(ns_name: &str) -> &str {
    ns_name.strip_prefix("axis-").unwrap_or(ns_name)
}

fn veth_host_name(sandbox_name: &str) -> String {
    format!("axh{}", veth_suffix(sandbox_name))
}

fn veth_sandbox_name(sandbox_name: &str) -> String {
    format!("axs{}", veth_suffix(sandbox_name))
}

fn veth_suffix(sandbox_name: &str) -> String {
    let suffix: String = sandbox_name
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(12)
        .collect();
    if suffix.is_empty() {
        "000000000000".into()
    } else {
        suffix
    }
}

fn ip_with_paths(
    paths: &NetnsCommandPaths,
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> NetnsCommand {
    NetnsCommand {
        program: paths.ip.clone(),
        args: args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect(),
        ignore_missing_link: false,
    }
}

fn ip_ignore_missing_link_with_paths(
    paths: &NetnsCommandPaths,
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> NetnsCommand {
    NetnsCommand {
        ignore_missing_link: true,
        ..ip_with_paths(paths, args)
    }
}

fn is_missing_link_error(error: &str) -> bool {
    error.contains("Cannot find device")
        || error.contains("does not exist")
        || error.contains("No such device")
}

/// Available strategies for network namespace creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsStrategy {
    /// Use `ip netns` commands (requires CAP_NET_ADMIN or root).
    IpNetns,
    /// Use bubblewrap --unshare-net (no proxy, just network isolation).
    Bubblewrap,
    /// No strategy available.
    Unavailable,
}

impl std::fmt::Display for NetnsStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpNetns => write!(f, "ip netns (CAP_NET_ADMIN)"),
            Self::Bubblewrap => write!(f, "bubblewrap (--unshare-net)"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

pub fn helper_main_from_env() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run_helper_from_args(&args) {
        Ok(outcome) => helper_command_exit_code(outcome),
        Err(e) => {
            eprintln!("axis-netns-helper: {e}");
            1
        }
    }
}

fn helper_command_exit_code(outcome: HelperCommandOutcome) -> i32 {
    match outcome {
        HelperCommandOutcome::Success
        | HelperCommandOutcome::Cleanup(HelperCleanupOutcome::Destroyed) => 0,
        HelperCommandOutcome::Cleanup(HelperCleanupOutcome::AlreadyCompleted) => {
            HELPER_EXIT_ALREADY_COMPLETED
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperCommandOutcome {
    Success,
    Cleanup(HelperCleanupOutcome),
}

fn run_helper_from_args(args: &[String]) -> Result<HelperCommandOutcome, String> {
    let action = parse_helper_action(args)?;
    ensure_helper_effective_root()?;
    normalize_helper_control_plane_rlimits()?;
    if matches!(action, HelperAction::Check) {
        NetnsCommandPaths::fixed_system_paths()?;
        return Ok(HelperCommandOutcome::Success);
    }
    let mut runner = PrivilegedCommandRunner::new()?;
    let paths = runner.paths.clone();
    run_helper_action_with_runner(action, &paths, &mut runner)
}

#[cfg(test)]
fn run_helper_with_runner(
    args: &[String],
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<HelperCommandOutcome, String> {
    let action = parse_helper_action(args)?;
    run_helper_action_with_runner(action, paths, runner)
}

fn run_helper_action_with_runner(
    action: HelperAction,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<HelperCommandOutcome, String> {
    match action {
        HelperAction::Check => Ok(HelperCommandOutcome::Success),
        HelperAction::Destroy { sandbox_id } => {
            ensure_helper_real_root()?;
            let namespace = format!("axis-{sandbox_id}");
            destroy_with_runner_and_paths(&namespace, paths, runner)?;
            Ok(HelperCommandOutcome::Success)
        }
        HelperAction::DestroyToken {
            sandbox_id,
            destroy_token,
        } => destroy_helper_owned_netns(sandbox_id, &destroy_token, paths, runner)
            .map(HelperCommandOutcome::Cleanup),
        HelperAction::Launch {
            sandbox_id,
            proxy_port,
            spec_fd,
            sync_fd,
            cgroup_procs_fd,
            owner_guard_fd,
        } => {
            launch_with_helper_action(
                HelperLaunchRequest {
                    sandbox_id,
                    proxy_port,
                    spec_fd,
                    sync_fd,
                    cgroup_procs_fd,
                    owner_guard_fd,
                },
                paths,
                runner,
            )?;
            Ok(HelperCommandOutcome::Success)
        }
    }
}

fn destroy_with_runner_and_paths(
    ns_name: &str,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let sandbox_name = sandbox_name_from_netns(ns_name);
    let mut failures = Vec::new();
    for command in destroy_command_plan_with_paths(ns_name, sandbox_name, paths) {
        if let Err(e) = runner.run(&command, None) {
            if command.ignore_missing_link && is_missing_link_error(&e) {
                continue;
            }
            failures.push(e);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperAction {
    Check,
    Destroy {
        sandbox_id: SandboxId,
    },
    DestroyToken {
        sandbox_id: SandboxId,
        destroy_token: String,
    },
    Launch {
        sandbox_id: SandboxId,
        proxy_port: u16,
        spec_fd: RawFd,
        sync_fd: RawFd,
        cgroup_procs_fd: Option<RawFd>,
        owner_guard_fd: RawFd,
    },
}

fn parse_helper_action(args: &[String]) -> Result<HelperAction, String> {
    let Some(action) = args.first().map(String::as_str) else {
        return Err(helper_usage());
    };

    match action {
        "check" if args.len() == 1 => Ok(HelperAction::Check),
        "destroy" if args.len() == 2 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            Ok(HelperAction::Destroy { sandbox_id })
        }
        "destroy-token" if args.len() == 3 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            let destroy_token = parse_destroy_token(&args[2])?;
            Ok(HelperAction::DestroyToken {
                sandbox_id,
                destroy_token,
            })
        }
        "launch" if args.len() == 7 => {
            let sandbox_id = parse_canonical_sandbox_id(&args[1])?;
            let proxy_port = parse_proxy_port(&args[2])?;
            let spec_fd = parse_fd_arg("spec fd", &args[3])?;
            let sync_fd = parse_fd_arg("sync fd", &args[4])?;
            let cgroup_procs_fd = parse_optional_fd_arg("cgroup procs fd", &args[5])?;
            let owner_guard_fd = parse_fd_arg("owner guard fd", &args[6])?;
            Ok(HelperAction::Launch {
                sandbox_id,
                proxy_port,
                spec_fd,
                sync_fd,
                cgroup_procs_fd,
                owner_guard_fd,
            })
        }
        "check" | "destroy" | "destroy-token" | "launch" => Err(helper_usage()),
        other => Err(format!("unknown action '{other}'; {}", helper_usage())),
    }
}

fn helper_usage() -> String {
    "usage: axis-netns-helper check | destroy <sandbox-uuid> | destroy-token <sandbox-uuid> <token> | launch <sandbox-uuid> <proxy-port> <spec-fd> <sync-fd> <cgroup-procs-fd-or--1> <owner-guard-fd>"
        .into()
}

fn parse_canonical_sandbox_id(value: &str) -> Result<SandboxId, String> {
    let id = SandboxId::from_str(value).map_err(|e| format!("invalid sandbox id: {e}"))?;
    if id.to_string() != value {
        return Err("sandbox id must be a canonical lowercase UUID".into());
    }
    Ok(id)
}

fn parse_proxy_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|e| format!("invalid proxy port '{value}': {e}"))?;
    if port == 0 {
        return Err("proxy port must be non-zero".into());
    }
    Ok(port)
}

fn parse_destroy_token(value: &str) -> Result<String, String> {
    if valid_destroy_token(value) {
        Ok(value.to_string())
    } else {
        Err("destroy token must be 64 hexadecimal characters".into())
    }
}

fn parse_fd_arg(label: &str, value: &str) -> Result<RawFd, String> {
    let fd = value
        .parse::<RawFd>()
        .map_err(|e| format!("invalid {label} '{value}': {e}"))?;
    if fd < 3 {
        return Err(format!("{label} must be an inherited fd >= 3"));
    }
    Ok(fd)
}

fn parse_optional_fd_arg(label: &str, value: &str) -> Result<Option<RawFd>, String> {
    if value == "-1" {
        Ok(None)
    } else {
        parse_fd_arg(label, value).map(Some)
    }
}

fn validate_helper_launch_fds(
    spec_fd: RawFd,
    sync_fd: RawFd,
    cgroup_procs_fd: Option<RawFd>,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    let mut fds = vec![
        ("spec", spec_fd),
        ("sync", sync_fd),
        ("owner guard", owner_guard_fd),
    ];
    if let Some(fd) = cgroup_procs_fd {
        fds.push(("cgroup procs", fd));
    }
    for (index, (label, fd)) in fds.iter().enumerate() {
        if let Some((other_label, _)) = fds[..index].iter().find(|(_, other_fd)| other_fd == fd) {
            return Err(format!(
                "helper launch {label} fd must be distinct from {other_label} fd"
            ));
        }
    }
    Ok(())
}

fn validate_owner_pidfd(fd: RawFd) -> Result<(), String> {
    let parent_before = unsafe { libc::getppid() };
    let fdinfo_path = format!("/proc/self/fdinfo/{fd}");
    let fdinfo = std::fs::read_to_string(&fdinfo_path)
        .map_err(|error| format!("read owner pidfd metadata '{fdinfo_path}': {error}"))?;
    let target_pid = parse_owner_pidfd_target(&fdinfo)?;
    let parent_after = unsafe { libc::getppid() };
    if parent_before != parent_after {
        return Err("AXIS owner exited while the helper validated its pidfd".into());
    }
    if target_pid != parent_after {
        return Err(format!(
            "owner pidfd target {target_pid} does not match helper parent {parent_after}"
        ));
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    Err(format!(
        "owner pidfd must refer to the live helper parent: {}",
        std::io::Error::last_os_error()
    ))
}

fn parse_owner_pidfd_target(fdinfo: &str) -> Result<libc::pid_t, String> {
    let mut target_pid = None;
    for line in fdinfo.lines() {
        let Some(value) = line.strip_prefix("Pid:") else {
            continue;
        };
        if target_pid.is_some() {
            return Err("owner pidfd metadata contains duplicate Pid fields".into());
        }
        let pid = value
            .trim()
            .parse::<libc::pid_t>()
            .map_err(|_| "owner pidfd metadata contains a malformed Pid field".to_string())?;
        if pid <= 0 {
            return Err("owner pidfd metadata does not identify a live process".into());
        }
        target_pid = Some(pid);
    }
    target_pid.ok_or_else(|| "owner pidfd metadata is missing the Pid field".into())
}

fn ensure_owner_guard_alive(fd: RawFd) -> Result<(), String> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        let ret = unsafe { libc::poll(&mut poll_fd, 1, 0) };
        if ret == 0 {
            return Ok(());
        }
        if ret > 0 {
            return Err("AXIS owner is no longer supervising the helper launch".into());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(errno_message("poll owner guard fd"));
        }
    }
}

fn validate_owner_guard_for_spec(
    spec: &HelperLaunchSpec,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    if spec.mxc_config_fd == Some(owner_guard_fd) {
        return Err("owner guard fd must be distinct from the MXC config fd".into());
    }
    Ok(())
}

struct HelperLaunchRequest {
    sandbox_id: SandboxId,
    proxy_port: u16,
    spec_fd: RawFd,
    sync_fd: RawFd,
    cgroup_procs_fd: Option<RawFd>,
    owner_guard_fd: RawFd,
}

fn launch_with_helper_action(
    request: HelperLaunchRequest,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<(), String> {
    let HelperLaunchRequest {
        sandbox_id,
        proxy_port,
        spec_fd,
        sync_fd,
        cgroup_procs_fd,
        owner_guard_fd,
    } = request;
    validate_helper_launch_fds(spec_fd, sync_fd, cgroup_procs_fd, owner_guard_fd)?;
    let spec = read_launch_spec(spec_fd)?;
    validate_owner_guard_for_spec(&spec, owner_guard_fd)?;
    validate_owner_pidfd(owner_guard_fd)?;
    ensure_owner_guard_alive(owner_guard_fd)?;
    let owner = helper_owner();
    validate_launch_spec(sandbox_id, proxy_port, owner, &spec)?;
    if let Some(fd) = cgroup_procs_fd {
        validate_cgroup_procs_fd(fd, sandbox_id)?;
    }
    ensure_helper_launch_authorized(owner)?;
    create_helper_state(sandbox_id, owner.uid, &spec.destroy_token, owner_guard_fd)?;

    let allocation = proxy_netns_allocation(sandbox_id, proxy_port);
    if let Err(e) =
        create_helper_allocation_with_state(sandbox_id, &allocation, paths, runner, owner_guard_fd)
    {
        write_helper_error(sync_fd, &e);
        return Err(e);
    }
    if let Err(e) = ensure_owner_guard_alive(owner_guard_fd) {
        let cleanup = cleanup_helper_allocation_after_failure(
            sandbox_id,
            &allocation,
            CreatedNetnsResources::complete(),
            paths,
            runner,
            "owner death during setup",
        );
        let error = append_cleanup_error(e, cleanup);
        write_helper_error(sync_fd, &error);
        return Err(error);
    }

    let payload_boundary = match spawn_payload_namespace(
        sandbox_id,
        &allocation,
        owner,
        cgroup_procs_fd,
        owner_guard_fd,
        sync_fd,
        &spec,
    ) {
        Ok(boundary) => boundary,
        Err(e) => {
            let cleanup = cleanup_helper_allocation_after_failure(
                sandbox_id,
                &allocation,
                CreatedNetnsResources::complete(),
                paths,
                runner,
                "payload boundary failure",
            );
            let error = append_cleanup_error(e, cleanup);
            write_helper_error(sync_fd, &error);
            return Err(error);
        }
    };

    unsafe {
        libc::close(sync_fd);
        if let Some(fd) = spec.mxc_config_fd {
            libc::close(fd);
        }
        if let Some(fd) = cgroup_procs_fd {
            libc::close(fd);
        }
    }
    let (exit_code, owner_death_error) =
        wait_for_helper_child_or_owner_death(payload_boundary.pid, owner_guard_fd);
    let mut lifecycle_failed = false;
    if let Some(error) = owner_death_error {
        tracing::warn!("netns helper owner-death termination encountered an error: {error}");
        lifecycle_failed = true;
    }
    if let Err(cleanup) = cleanup_helper_allocation_after_target_exit(
        sandbox_id,
        payload_boundary,
        &allocation,
        paths,
        runner,
        owner_guard_fd,
    ) {
        tracing::warn!(
            "netns helper cleanup after target exit failed; preserving helper state for retry: {cleanup}"
        );
        lifecycle_failed = true;
    }
    unsafe {
        libc::close(owner_guard_fd);
    };
    std::process::exit(if lifecycle_failed { 125 } else { exit_code });
}

fn spawn_payload_namespace(
    sandbox_id: SandboxId,
    allocation: &ProxyNetnsAllocation,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    owner_guard_fd: RawFd,
    sync_fd: RawFd,
    spec: &HelperLaunchSpec,
) -> Result<HelperProcessIdentity, String> {
    let (start_read_fd, start_write_fd) = cloexec_pipe()?;
    let helper_guard_fd = open_self_pidfd()?;
    let child = match clone_pid_namespace_init() {
        Ok(pid) => pid,
        Err(error) => {
            close_fds(&[start_read_fd, start_write_fd, helper_guard_fd]);
            return Err(error);
        }
    };

    if child == 0 {
        close_fds(&[start_write_fd, owner_guard_fd]);
        run_payload_namespace_init(
            start_read_fd,
            helper_guard_fd,
            allocation,
            owner,
            cgroup_procs_fd,
            sync_fd,
            spec,
        );
    }

    close_fds(&[start_read_fd, helper_guard_fd]);
    let start_result = (|| {
        let identity = read_process_identity(child)?;
        record_helper_payload_boundary(sandbox_id, identity, owner_guard_fd)?;
        ensure_owner_guard_alive(owner_guard_fd)?;
        super::write_all_fd(start_write_fd, &[1]).map_err(|errno| {
            format!(
                "release payload namespace init failed: {}",
                std::io::Error::from_raw_os_error(errno)
            )
        })?;
        Ok::<HelperProcessIdentity, String>(identity)
    })();
    close_fds(&[start_write_fd]);
    match start_result {
        Ok(identity) => Ok(identity),
        Err(error) => {
            let abort = abort_payload_namespace_child(child);
            Err(match abort {
                Ok(()) => error,
                Err(abort_error) => format!("{error}; {abort_error}"),
            })
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

fn clone_pid_namespace_init() -> Result<libc::pid_t, String> {
    let args = payload_namespace_clone_args();
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if result >= 0 {
        Ok(result)
    } else {
        Err(clone_pid_namespace_error(super::current_errno()))
    }
}

fn clone_pid_namespace_error(errno: i32) -> String {
    match errno {
        libc::ENOSYS => {
            "clone3 PID namespace containment is unavailable on this Linux kernel".into()
        }
        libc::EPERM | libc::EACCES => format!(
            "clone3 PID namespace containment was denied: {}",
            std::io::Error::from_raw_os_error(errno)
        ),
        _ => format!(
            "clone3 PID namespace containment failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ),
    }
}

fn payload_namespace_clone_args() -> CloneArgs {
    CloneArgs {
        flags: libc::CLONE_NEWPID as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    }
}

fn open_self_pidfd() -> Result<RawFd, String> {
    let pid = unsafe { libc::getpid() };
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if fd < 0 {
        Err(format!(
            "open helper parent pidfd: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(fd)
    }
}

fn arm_parent_death_signal(parent_guard_fd: RawFd) -> Result<(), String> {
    let parent_before = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } < 0 {
        return Err(errno_message("arm helper parent-death signal"));
    }
    let parent_after = unsafe { libc::getppid() };
    if parent_before != parent_after {
        return Err("helper parent exited while PID namespace init armed its death signal".into());
    }
    ensure_owner_guard_alive(parent_guard_fd)
        .map_err(|_| "helper parent exited before PID namespace init startup".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NamespaceReapResult {
    exit_code: i32,
    reaped_descendants: usize,
    reaped_while_primary_alive: usize,
    drained: bool,
}

fn reap_namespace_children(primary_pid: libc::pid_t) -> NamespaceReapResult {
    reap_namespace_children_with(primary_pid, true)
}

fn reap_namespace_children_with(
    primary_pid: libc::pid_t,
    terminate_after_primary: bool,
) -> NamespaceReapResult {
    let mut reaped_descendants = 0;
    let mut reaped_while_primary_alive = 0;
    let primary_status = loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited == primary_pid {
            break Some(status);
        }
        if waited > 0 {
            reaped_descendants += 1;
            reaped_while_primary_alive += 1;
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break None;
    };

    let deadline = Instant::now() + HELPER_PAYLOAD_EXIT_TIMEOUT;
    let mut drained = false;
    loop {
        if terminate_after_primary {
            let killed = unsafe { libc::kill(-1, libc::SIGKILL) };
            if killed < 0
                && !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH) | Some(libc::EPERM)
                )
            {
                break;
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if waited > 0 {
            reaped_descendants += 1;
            continue;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                drained = true;
                break;
            }
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(HELPER_POLL_INTERVAL);
    }

    NamespaceReapResult {
        exit_code: primary_status.map(helper_wait_status_code).unwrap_or(127),
        reaped_descendants,
        reaped_while_primary_alive,
        drained,
    }
}

fn run_payload_namespace_init(
    start_fd: RawFd,
    helper_guard_fd: RawFd,
    allocation: &ProxyNetnsAllocation,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    sync_fd: RawFd,
    spec: &HelperLaunchSpec,
) -> ! {
    if let Err(error) = arm_parent_death_signal(helper_guard_fd) {
        close_fds(&[helper_guard_fd]);
        write_helper_error(sync_fd, &error);
        unsafe { libc::_exit(126) };
    }
    if spec.launch_kind == HelperLaunchKind::DirectProcess {
        close_fds(&[helper_guard_fd]);
    }
    if unsafe { libc::setsid() } < 0 {
        write_helper_error(sync_fd, &errno_message("create payload session"));
        unsafe { libc::_exit(126) };
    }
    if let Err(error) = wait_for_payload_start(start_fd) {
        close_fds(&[start_fd]);
        write_helper_error(sync_fd, &error);
        unsafe { libc::_exit(126) };
    }
    close_fds(&[start_fd]);

    let config_holder_pid = match spec.launch_kind {
        HelperLaunchKind::DirectProcess => None,
        HelperLaunchKind::MxcExecutor => match host_pid_from_proc_status() {
            Ok(pid) => Some(pid),
            Err(error) => {
                close_fds(&[helper_guard_fd]);
                write_helper_error(sync_fd, &error);
                unsafe { libc::_exit(126) };
            }
        },
    };
    let config_ready = match config_holder_pid {
        Some(_) => match cloexec_pipe() {
            Ok(fds) => Some(fds),
            Err(error) => {
                close_fds(&[helper_guard_fd]);
                write_helper_error(sync_fd, &error);
                unsafe { libc::_exit(126) };
            }
        },
        None => None,
    };
    let payload = unsafe { libc::fork() };
    if payload < 0 {
        if spec.launch_kind == HelperLaunchKind::MxcExecutor {
            close_fds(&[helper_guard_fd]);
        }
        if let Some((read_fd, write_fd)) = config_ready {
            close_fds(&[read_fd, write_fd]);
        }
        write_helper_error(sync_fd, &errno_message("fork helper payload"));
        unsafe { libc::_exit(126) };
    }
    if payload == 0 {
        if spec.launch_kind == HelperLaunchKind::MxcExecutor {
            close_fds(&[helper_guard_fd]);
        }
        let mut exec_spec = spec.clone();
        if let Some((read_fd, write_fd)) = config_ready {
            close_fds(&[write_fd]);
            if let Err(error) = wait_for_payload_start(read_fd) {
                close_fds(&[read_fd]);
                write_helper_error(sync_fd, &format!("MXC config holder setup: {error}"));
                unsafe { libc::_exit(126) };
            }
            close_fds(&[read_fd]);
            let Some(holder_pid) = config_holder_pid else {
                write_helper_error(sync_fd, "MXC config holder PID is missing");
                unsafe { libc::_exit(126) };
            };
            if let Err(error) = point_mxc_config_at_holder(&mut exec_spec, holder_pid) {
                write_helper_error(sync_fd, &error);
                unsafe { libc::_exit(126) };
            }
        }
        let setup_result = match exec_spec.launch_kind {
            HelperLaunchKind::DirectProcess => apply_helper_launch_isolation(
                &allocation.namespace,
                owner,
                cgroup_procs_fd,
                &exec_spec,
            ),
            HelperLaunchKind::MxcExecutor => apply_mxc_helper_launch_isolation(
                &allocation.namespace,
                owner,
                cgroup_procs_fd,
                &exec_spec,
            ),
        };
        if let Err(error) = setup_result {
            write_helper_error(sync_fd, &error);
            unsafe { libc::_exit(126) };
        }
        if let Err(error) = write_helper_ok(sync_fd) {
            eprintln!("axis-netns-helper: {error}");
            unsafe { libc::_exit(126) };
        }
        let error = exec_helper_target(&exec_spec).unwrap_err();
        eprintln!("axis-netns-helper: {error}");
        unsafe { libc::_exit(127) };
    }

    if let Some((read_fd, write_fd)) = config_ready {
        close_fds(&[read_fd]);
        if let Err(error) = prepare_mxc_config_holder(owner, helper_guard_fd) {
            close_fds(&[helper_guard_fd]);
            close_fds(&[write_fd]);
            write_helper_error(sync_fd, &error);
            unsafe { libc::_exit(126) };
        }
        close_fds(&[helper_guard_fd]);
        if let Err(errno) = super::write_all_fd(write_fd, &[1]) {
            close_fds(&[write_fd]);
            write_helper_error(
                sync_fd,
                &format!(
                    "release MXC config reader failed: {}",
                    std::io::Error::from_raw_os_error(errno)
                ),
            );
            unsafe { libc::_exit(126) };
        }
        close_fds(&[write_fd]);
    }
    close_fds(&[sync_fd]);
    if let Some(fd) = cgroup_procs_fd {
        close_fds(&[fd]);
    }
    let result = reap_namespace_children(payload);
    if let Some(fd) = spec.mxc_config_fd {
        close_fds(&[fd]);
    }
    unsafe { libc::_exit(result.exit_code) };
}

fn host_pid_from_proc_status() -> Result<libc::pid_t, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read payload namespace process status: {error}"))?;
    parse_host_pid_from_proc_status(&status)
}

fn parse_host_pid_from_proc_status(status: &str) -> Result<libc::pid_t, String> {
    let nspid = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or_else(|| "payload namespace process status is missing NSpid".to_string())?;
    let pid = nspid
        .split_whitespace()
        .next()
        .ok_or_else(|| "payload namespace process status has an empty NSpid".to_string())?
        .parse::<libc::pid_t>()
        .map_err(|_| "payload namespace process status has a malformed NSpid".to_string())?;
    if pid <= 0 {
        return Err("payload namespace process status has a non-positive NSpid".into());
    }
    Ok(pid)
}

fn point_mxc_config_at_holder(
    spec: &mut HelperLaunchSpec,
    holder_pid: libc::pid_t,
) -> Result<(), String> {
    if holder_pid <= 0 {
        return Err("MXC config holder PID must be positive".into());
    }
    let config_fd = spec
        .mxc_config_fd
        .ok_or_else(|| "MXC helper launch is missing its config fd".to_string())?;
    if spec.args.len() != 3 || spec.args[2] != format!("/proc/self/fd/{config_fd}") {
        return Err("MXC helper launch config fd path changed after validation".into());
    }
    spec.args[2] = format!("/proc/{holder_pid}/fd/{config_fd}");
    Ok(())
}

fn prepare_mxc_config_holder(owner: HelperOwner, parent_guard_fd: RawFd) -> Result<(), String> {
    drop_to_owner(owner)?;
    set_no_new_privs()?;
    if let Err(errno) = super::drop_process_capabilities() {
        return Err(format!(
            "drop MXC config holder capabilities failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    // MXC reads this sealed descriptor before Bubblewrap replaces /proc. The
    // same-UID supervisor is already inside the sandbox PID namespace.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } < 0 {
        return Err(errno_message("make MXC config holder readable by executor"));
    }
    arm_parent_death_signal(parent_guard_fd)
        .map_err(|error| format!("rearm MXC config holder parent-death signal: {error}"))
}

fn wait_for_payload_start(fd: RawFd) -> Result<(), String> {
    let mut byte = 0u8;
    loop {
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 && byte == 1 {
            return Ok(());
        }
        if read == 0 {
            return Err("payload namespace init was not authorized to start".into());
        }
        if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(errno_message("wait for payload namespace authorization"));
    }
}

fn abort_payload_namespace_child(child: libc::pid_t) -> Result<(), String> {
    let mut guarded_child = PidfdGuardedChild::open(child)?;
    let (_, error) = finish_helper_child_after_owner_death(
        child,
        &mut guarded_child,
        Instant::now() + HELPER_PAYLOAD_EXIT_TIMEOUT,
        None,
    );
    error.map_or(Ok(()), Err)
}

fn cloexec_pipe() -> Result<(RawFd, RawFd), String> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        Err(errno_message("create helper coordination pipe"))
    } else {
        Ok((fds[0], fds[1]))
    }
}

fn close_fds(fds: &[RawFd]) {
    for fd in fds {
        unsafe {
            libc::close(*fd);
        }
    }
}

fn create_helper_allocation_with_state(
    sandbox_id: SandboxId,
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    let mut created = CreatedNetnsResources::default();
    for (index, command) in create_command_plan_with_paths(allocation, paths)
        .into_iter()
        .enumerate()
    {
        if let Err(e) = runner.run(&command, Some(owner_guard_fd)) {
            let cleanup = cleanup_helper_allocation_after_failure(
                sandbox_id,
                allocation,
                created,
                paths,
                runner,
                "create failure",
            );
            return Err(append_cleanup_error(e, cleanup));
        }
        created.record_command_success(index);
        if let Err(error) = record_helper_created_resources(sandbox_id, created, owner_guard_fd) {
            let cleanup = cleanup_helper_allocation_after_failure(
                sandbox_id,
                allocation,
                created,
                paths,
                runner,
                "state update failure",
            );
            return Err(append_cleanup_error(error, cleanup));
        }
    }
    Ok(())
}

fn cleanup_helper_allocation_after_failure(
    sandbox_id: SandboxId,
    allocation: &ProxyNetnsAllocation,
    created: CreatedNetnsResources,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
    reason: &str,
) -> Result<(), String> {
    let _lock = lock_helper_state_dir_unowned(HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    if let Err(cleanup) = rollback_created_resources(allocation, created, paths, runner) {
        tracing::warn!(
            "netns helper cleanup after {reason} failed; preserving helper state for retry: {cleanup}"
        );
        Err(cleanup)
    } else {
        remove_helper_state(sandbox_id)
    }
}

fn append_cleanup_error(primary: String, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => primary,
        Err(error) => format!("{primary}; cleanup failed: {error}"),
    }
}

fn cleanup_helper_allocation_after_target_exit(
    sandbox_id: SandboxId,
    payload_boundary: HelperProcessIdentity,
    allocation: &ProxyNetnsAllocation,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    let _lock = lock_helper_state_dir_unowned(HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    cleanup_helper_allocation_after_target_exit_with(
        HelperCleanupContext {
            sandbox_id,
            payload_boundary,
            allocation,
            paths,
            runner,
        },
        DefaultHelperCleanupHooks,
        || ensure_owner_guard_alive(owner_guard_fd).is_ok(),
    )
}

struct HelperCleanupContext<'a> {
    sandbox_id: SandboxId,
    payload_boundary: HelperProcessIdentity,
    allocation: &'a ProxyNetnsAllocation,
    paths: &'a NetnsCommandPaths,
    runner: &'a mut dyn CommandRunner,
}

trait HelperCleanupHooks {
    fn terminate_payload_boundary(&mut self, identity: HelperProcessIdentity)
    -> Result<(), String>;

    fn destroy_resources(
        &mut self,
        allocation: &ProxyNetnsAllocation,
        paths: &NetnsCommandPaths,
        runner: &mut dyn CommandRunner,
    ) -> Result<(), String>;

    fn finalize_state(&mut self, sandbox_id: SandboxId, owner_alive: bool) -> Result<(), String>;
}

struct DefaultHelperCleanupHooks;

impl HelperCleanupHooks for DefaultHelperCleanupHooks {
    fn terminate_payload_boundary(
        &mut self,
        identity: HelperProcessIdentity,
    ) -> Result<(), String> {
        terminate_payload_boundary(identity)
    }

    fn destroy_resources(
        &mut self,
        allocation: &ProxyNetnsAllocation,
        paths: &NetnsCommandPaths,
        runner: &mut dyn CommandRunner,
    ) -> Result<(), String> {
        rollback_created_resources(allocation, CreatedNetnsResources::complete(), paths, runner)
    }

    fn finalize_state(&mut self, sandbox_id: SandboxId, owner_alive: bool) -> Result<(), String> {
        if owner_alive {
            record_helper_cleanup_completed_locked(sandbox_id)
        } else {
            remove_helper_state(sandbox_id)
        }
    }
}

fn cleanup_helper_allocation_after_target_exit_with<H, F>(
    ctx: HelperCleanupContext<'_>,
    mut hooks: H,
    owner_alive: F,
) -> Result<(), String>
where
    H: HelperCleanupHooks,
    F: FnOnce() -> bool,
{
    hooks.terminate_payload_boundary(ctx.payload_boundary)?;
    hooks.destroy_resources(ctx.allocation, ctx.paths, ctx.runner)?;
    hooks.finalize_state(ctx.sandbox_id, owner_alive())?;
    Ok(())
}

fn destroy_helper_owned_netns(
    sandbox_id: SandboxId,
    destroy_token: &str,
    paths: &NetnsCommandPaths,
    runner: &mut dyn CommandRunner,
) -> Result<HelperCleanupOutcome, String> {
    let owner = helper_owner();
    let _lock = lock_helper_state_dir_unowned(HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    let state = validate_helper_state(sandbox_id, owner.uid, destroy_token)?;
    if state.cleanup_completed {
        remove_helper_state(sandbox_id)?;
        return Ok(HelperCleanupOutcome::AlreadyCompleted);
    }
    ensure_helper_state_proves_namespace_ownership(&state)?;
    if let Some(payload_boundary) = state.payload_boundary {
        terminate_payload_boundary(payload_boundary)?;
    }
    let allocation = proxy_netns_allocation(sandbox_id, 1);
    let destroy_result =
        rollback_created_resources(&allocation, state.created_resources, paths, runner);
    if let Err(error) = destroy_result
        && !helper_allocation_is_absent(sandbox_id, state.created_resources)?
    {
        return Err(error);
    }
    remove_helper_state(sandbox_id)?;
    Ok(HelperCleanupOutcome::Destroyed)
}

fn ensure_helper_state_proves_namespace_ownership(state: &HelperState) -> Result<(), String> {
    if state.created_resources.namespace {
        Ok(())
    } else {
        Err(
            "helper state does not prove namespace ownership; preserving state and quota for administrative recovery"
                .into(),
        )
    }
}

fn helper_allocation_is_absent(
    sandbox_id: SandboxId,
    created: CreatedNetnsResources,
) -> Result<bool, String> {
    let sandbox_name = sandbox_id.to_string();
    let mut paths = Vec::new();
    if created.namespace {
        paths.push(std::path::Path::new("/var/run/netns").join(format!("axis-{sandbox_name}")));
    }
    if created.host_veth {
        paths.push(std::path::Path::new("/sys/class/net").join(veth_host_name(&sandbox_name)));
    }
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect helper resource {} during cleanup retry: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(true)
}

fn read_launch_spec(fd: RawFd) -> Result<HelperLaunchSpec, String> {
    validate_sealed_launch_spec_fd(fd)?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let ret = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(format!("helper launch spec read failed: {error}"));
        }
        if ret == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..ret as usize]);
        if bytes.len() > 1024 * 1024 {
            unsafe {
                libc::close(fd);
            }
            return Err("helper launch spec exceeded 1 MiB".into());
        }
    }
    unsafe {
        libc::close(fd);
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("helper launch spec parse failed: {e}"))
}

fn validate_sealed_launch_spec_fd(fd: RawFd) -> Result<(), String> {
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "helper launch spec fd must support seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err("helper launch spec fd must be sealed against writes and size changes".into());
    }
    Ok(())
}

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

fn validate_cgroup_procs_fd(fd: RawFd, sandbox_id: SandboxId) -> Result<(), String> {
    let mut statfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let ret = unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!(
            "inspect cgroup procs fd {fd} filesystem: {}",
            std::io::Error::last_os_error()
        ));
    }
    let statfs = unsafe { statfs.assume_init() };
    if statfs.f_type != CGROUP2_SUPER_MAGIC {
        return Err(format!(
            "cgroup procs fd {fd} must reference a cgroup v2 filesystem"
        ));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "inspect cgroup procs fd {fd} flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let access_mode = flags & libc::O_ACCMODE;
    if access_mode != libc::O_WRONLY && access_mode != libc::O_RDWR {
        return Err(format!("cgroup procs fd {fd} must be writable"));
    }

    let path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
    let target =
        std::fs::read_link(&path).map_err(|e| format!("inspect cgroup procs fd {fd}: {e}"))?;
    let expected = std::path::Path::new("/sys/fs/cgroup")
        .join(format!("axis-{sandbox_id}"))
        .join("cgroup.procs");
    if target != expected {
        return Err(format!(
            "cgroup procs fd {fd} must reference {}, got {}",
            expected.display(),
            target.display()
        ));
    }
    Ok(())
}

fn validate_launch_spec(
    sandbox_id: SandboxId,
    proxy_port: u16,
    owner: HelperOwner,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if spec.command.is_empty() {
        return Err("helper launch command must not be empty".into());
    }
    if !valid_destroy_token(&spec.destroy_token) {
        return Err("helper launch destroy token is invalid".into());
    }
    if spec.process.run_as_user.is_some() {
        return Err("helper launch with run_as_user is not implemented yet".into());
    }
    if super::landlock::policy_uses_tmpdir(&spec.filesystem) {
        return Err("helper launch with {tmpdir} filesystem policy is not implemented yet".into());
    }
    if proxy_netns_allocation(sandbox_id, proxy_port)
        .proxy_addr
        .port()
        != proxy_port
    {
        return Err("helper launch proxy allocation mismatch".into());
    }
    match spec.launch_kind {
        HelperLaunchKind::DirectProcess => {
            if spec.mxc_config_fd.is_some() {
                return Err("direct helper launch must not inherit an MXC config fd".into());
            }
            Ok(())
        }
        HelperLaunchKind::MxcExecutor => validate_mxc_helper_launch_spec(owner, spec),
    }
}

fn validate_mxc_helper_launch_spec(
    _owner: HelperOwner,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if spec.args.len() != 3 || spec.args[0] != "--experimental" || spec.args[1] != "--config" {
        return Err(
            "MXC helper launch must execute lxc-exec with '--experimental --config <file>'".into(),
        );
    }
    let config_fd = spec
        .mxc_config_fd
        .ok_or_else(|| "MXC helper launch requires a sealed config fd".to_string())?;
    if config_fd < 3 {
        return Err("MXC helper config fd must be an inherited fd >= 3".into());
    }
    let expected_config_path = format!("/proc/self/fd/{config_fd}");
    if spec.args[2] != expected_config_path {
        return Err(format!(
            "MXC helper launch config path must be {expected_config_path}"
        ));
    }
    validate_sealed_fd(config_fd, "MXC helper config fd")?;
    validate_mxc_executor_path(std::path::Path::new(&spec.command))?;
    for (key, _) in &spec.env {
        if axis_core::sandbox_env::is_secret_env_key(key)
            || axis_core::sandbox_env::is_proxy_env_key(key)
        {
            return Err(format!(
                "MXC helper launch environment contains forbidden key '{key}'"
            ));
        }
    }
    Ok(())
}

fn validate_sealed_fd(fd: RawFd, label: &str) -> Result<(), String> {
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "{label} must support seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err(format!(
            "{label} must be sealed against writes and size changes"
        ));
    }
    Ok(())
}

fn validate_helper_executable_path(path: &std::path::Path, label: &str) -> Result<(), String> {
    validate_helper_path_components(path, label)
}

fn validate_mxc_executor_path(path: &std::path::Path) -> Result<(), String> {
    validate_helper_executable_path(path, "MXC executor")?;
    if !mxc_executor_helper_path_allowed(path) {
        return Err(format!(
            "MXC executor path {} must be a trusted lxc-exec install path",
            path.display()
        ));
    }
    Ok(())
}

fn mxc_executor_helper_path_allowed(path: &std::path::Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(MXC_EXECUTOR_NAME))
        && path.parent().is_some_and(|parent| {
            MXC_HELPER_EXECUTOR_DIRS
                .iter()
                .any(|dir| parent == std::path::Path::new(dir))
        })
}

fn validate_helper_path_components(path: &std::path::Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute"));
    }

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|e| format!("{label} path component {}: {e}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} path component {} must not be a symlink",
                current.display()
            ));
        }

        if current == path {
            validate_helper_leaf(path, &metadata, label)?;
        } else if !metadata.is_dir() {
            return Err(format!(
                "{label} path component {} must be a directory",
                current.display()
            ));
        } else {
            let mode = metadata.permissions().mode();
            if current != std::path::Path::new("/") && metadata.uid() != 0 {
                return Err(format!(
                    "{label} path component {} must be owned by root",
                    current.display()
                ));
            }
            if mode & 0o022 != 0 {
                return Err(format!(
                    "{label} path component {} must not be group- or world-writable",
                    current.display()
                ));
            }
        }
    }

    Ok(())
}

fn validate_helper_leaf(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
    label: &str,
) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "{label} path {} must be a regular file",
            path.display()
        ));
    }

    let mode = metadata.permissions().mode();
    if metadata.uid() != 0 {
        return Err(format!(
            "{label} path {} must be owned by root",
            path.display()
        ));
    }
    if mode & 0o111 == 0 {
        return Err(format!(
            "{label} path {} must be executable",
            path.display()
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "{label} path {} must not be group- or world-writable",
            path.display()
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HelperOwner {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HelperProcessIdentity {
    pid: libc::pid_t,
    start_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperState {
    owner_uid: u32,
    destroy_token: String,
    created_resources: CreatedNetnsResources,
    payload_boundary: Option<HelperProcessIdentity>,
    cleanup_completed: bool,
}

fn helper_owner() -> HelperOwner {
    HelperOwner {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    }
}

fn ensure_helper_launch_authorized(owner: HelperOwner) -> Result<(), String> {
    validate_helper_launch_authorization(owner.uid, unsafe { libc::geteuid() })
}

fn validate_helper_launch_authorization(real_uid: u32, effective_uid: u32) -> Result<(), String> {
    if effective_uid != 0 {
        return Err(format!(
            "axis-netns-helper launch requires effective UID 0; current effective UID is {effective_uid}"
        ));
    }
    if real_uid == 0 {
        return Err(
            "axis-netns-helper launch requires a non-root real UID; root callers must use native netns setup".into(),
        );
    }
    Ok(())
}

fn apply_helper_launch_isolation(
    namespace: &str,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if let Some(fd) = cgroup_procs_fd {
        if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
            unsafe {
                libc::close(fd);
            }
            return Err(format!(
                "enter cgroup failed: {}",
                std::io::Error::from_raw_os_error(errno)
            ));
        }
        unsafe {
            libc::close(fd);
        }
    }

    let netns_fd = enter_netns(namespace)?;
    let setns_ret = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
    unsafe {
        libc::close(netns_fd);
    }
    if setns_ret < 0 {
        return Err(errno_message("enter network namespace"));
    }

    let prepared_landlock =
        super::landlock::prepare_landlock(&spec.filesystem, &spec.workspace_dir)?;
    let seccomp_options = super::seccomp::SeccompOptions::default();
    let prepared_seccomp =
        super::seccomp::prepare_seccomp_with_options(&spec.process, seccomp_options)?;

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(errno_message("set no_new_privs"));
    }
    if let Err(errno) = prepared_landlock.restrict_current_process() {
        return Err(format!(
            "apply Landlock failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    drop_to_owner(owner)?;

    if let Err(errno) = apply_helper_rlimits(spec.rlimits) {
        return Err(format!(
            "apply resource limits failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::drop_process_capabilities() {
        return Err(format!(
            "drop capabilities failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::mark_unexpected_child_fds_close_on_exec() {
        return Err(format!(
            "mark inherited fds close-on-exec failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = prepared_seccomp.apply_current_process() {
        return Err(format!(
            "apply seccomp failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    Ok(())
}

fn apply_mxc_helper_launch_isolation(
    namespace: &str,
    owner: HelperOwner,
    cgroup_procs_fd: Option<RawFd>,
    spec: &HelperLaunchSpec,
) -> Result<(), String> {
    if let Some(fd) = cgroup_procs_fd {
        if let Err(errno) = super::enter_cgroup_from_child_fd(fd) {
            unsafe {
                libc::close(fd);
            }
            return Err(format!(
                "enter cgroup failed: {}",
                std::io::Error::from_raw_os_error(errno)
            ));
        }
        unsafe {
            libc::close(fd);
        }
    }

    let netns_fd = enter_netns(namespace)?;
    let setns_ret = unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) };
    unsafe {
        libc::close(netns_fd);
    }
    if setns_ret < 0 {
        return Err(errno_message("enter network namespace"));
    }

    drop_to_owner(owner)?;

    set_no_new_privs()?;
    if let Err(errno) = apply_helper_rlimits(spec.rlimits) {
        return Err(format!(
            "apply resource limits failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::drop_process_capabilities() {
        return Err(format!(
            "drop capabilities failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }
    if let Err(errno) = super::mark_unexpected_child_fds_close_on_exec() {
        return Err(format!(
            "mark inherited fds close-on-exec failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ));
    }

    Ok(())
}

fn apply_helper_rlimits(limits: HelperRlimits) -> Result<(), i32> {
    if let Some(value) = limits.address_space_bytes {
        set_helper_resource_limit(libc::RLIMIT_AS, value)?;
    }
    if let Some(value) = limits.max_processes {
        set_helper_resource_limit(libc::RLIMIT_NPROC, value)?;
    }
    Ok(())
}

fn set_helper_resource_limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<(), i32> {
    if u128::from(value) > libc::rlim_t::MAX as u128 {
        return Err(libc::EINVAL);
    }
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    let ret = unsafe { libc::setrlimit(resource, &limit as *const libc::rlimit) };
    if ret < 0 {
        Err(super::current_errno())
    } else {
        Ok(())
    }
}

fn drop_to_owner(owner: HelperOwner) -> Result<(), String> {
    if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
        return Err(errno_message("clear supplementary groups"));
    }
    if unsafe { libc::setgid(owner.gid) } < 0 {
        return Err(errno_message("drop group id"));
    }
    if unsafe { libc::setuid(owner.uid) } < 0 {
        return Err(errno_message("drop user id"));
    }
    Ok(())
}

fn exec_helper_target(spec: &HelperLaunchSpec) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let err = Command::new(&spec.command)
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(key, value)| (key, value)))
        .exec();
    Err(format!("exec target '{}': {err}", spec.command))
}

#[cfg(test)]
fn wait_for_helper_child(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == pid {
            break;
        }
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 127;
        }
    }
    helper_wait_status_code(status)
}

fn wait_for_helper_child_or_owner_death(
    pid: libc::pid_t,
    owner_guard_fd: RawFd,
) -> (i32, Option<String>) {
    let mut child = match PidfdGuardedChild::open(pid) {
        Ok(child) => child,
        Err(error) => return (127, Some(error)),
    };
    loop {
        match child.try_wait(pid) {
            Ok(Some(status)) => return (helper_wait_status_code(status), None),
            Ok(None) => {}
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => {
                return (127, Some(format!("wait for helper target {pid}: {error}")));
            }
        }

        let mut poll_fd = libc::pollfd {
            fd: owner_guard_fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut poll_fd, 1, 100) };
        if polled == 0 {
            continue;
        }
        if polled < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        let initial_error = (polled < 0)
            .then(|| format!("poll owner guard fd: {}", std::io::Error::last_os_error()));
        return finish_helper_child_after_owner_death(
            pid,
            &mut child,
            Instant::now() + HELPER_PAYLOAD_EXIT_TIMEOUT,
            initial_error,
        );
    }
}

trait GuardedChildOps {
    fn try_wait(&mut self, pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error>;

    fn send_sigkill(&mut self, pid: libc::pid_t) -> Result<(), String>;

    fn wait_for_exit(&mut self, deadline: Instant) -> Result<(), String>;
}

struct PidfdGuardedChild {
    pidfd: RawFd,
}

impl PidfdGuardedChild {
    fn open(pid: libc::pid_t) -> Result<Self, String> {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
        if pidfd < 0 {
            Err(format!(
                "open helper target pidfd for {pid}: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(Self { pidfd })
        }
    }
}

impl GuardedChildOps for PidfdGuardedChild {
    fn try_wait(&mut self, pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
        try_wait_for_child(pid)
    }

    fn send_sigkill(&mut self, pid: libc::pid_t) -> Result<(), String> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd,
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!(
                "kill helper target {pid} through pidfd: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn wait_for_exit(&mut self, deadline: Instant) -> Result<(), String> {
        wait_for_pidfd_exit(self.pidfd, deadline)
    }
}

impl Drop for PidfdGuardedChild {
    fn drop(&mut self) {
        close_fds(&[self.pidfd]);
    }
}

fn finish_helper_child_after_owner_death<O: GuardedChildOps>(
    pid: libc::pid_t,
    child: &mut O,
    deadline: Instant,
    initial_error: Option<String>,
) -> (i32, Option<String>) {
    let mut errors = initial_error.into_iter().collect::<Vec<_>>();
    loop {
        match child.try_wait(pid) {
            Ok(Some(status)) => return helper_child_finish_result(status, errors),
            Ok(None) => break,
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => {
                errors.push(format!("reap helper target {pid} before SIGKILL: {error}"));
                break;
            }
        }
    }

    if let Err(error) = child.send_sigkill(pid) {
        errors.push(error);
    }
    loop {
        match child.try_wait(pid) {
            Ok(Some(status)) => return helper_child_finish_result(status, errors),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(HELPER_POLL_INTERVAL),
            Ok(None) => {
                errors.push(format!(
                    "helper target {pid} did not exit within {} ms after SIGKILL",
                    HELPER_PAYLOAD_EXIT_TIMEOUT.as_millis()
                ));
                return (127, Some(errors.join("; ")));
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) => {
                errors.push(format!("reap helper target {pid} after SIGKILL: {error}"));
                if let Err(error) = child.wait_for_exit(deadline) {
                    errors.push(format!(
                        "confirm helper target {pid} exit through pidfd: {error}"
                    ));
                }
                return (127, Some(errors.join("; ")));
            }
        }
    }
}

fn helper_child_finish_result(status: libc::c_int, errors: Vec<String>) -> (i32, Option<String>) {
    let error = (!errors.is_empty()).then(|| errors.join("; "));
    (helper_wait_status_code(status), error)
}

fn helper_wait_status_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        127
    }
}

fn read_process_identity(pid: libc::pid_t) -> Result<HelperProcessIdentity, String> {
    if pid <= 1 {
        return Err(format!("payload boundary process id {pid} is unsafe"));
    }
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&path)
        .map_err(|error| format!("read payload boundary identity '{path}': {error}"))?;
    let start_time = parse_process_stat_start_time(&stat)
        .ok_or_else(|| format!("payload boundary identity '{path}' is malformed"))?;
    Ok(HelperProcessIdentity { pid, start_time })
}

fn parse_process_stat_start_time(stat: &str) -> Option<u64> {
    let end = stat.rfind(") ")?;
    let mut fields = stat[end + 2..].split_whitespace();
    fields.nth(19)?.parse().ok()
}

fn terminate_payload_boundary(identity: HelperProcessIdentity) -> Result<(), String> {
    if identity.pid <= 1 || identity.start_time == 0 {
        return Err("refusing to signal an invalid payload boundary identity".into());
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0) as RawFd };
    if pidfd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!(
                "open payload boundary pidfd for {}: {error}",
                identity.pid
            ))
        };
    }

    let current_identity = match read_process_identity(identity.pid) {
        Ok(current) => current,
        Err(error) => {
            let exited = pidfd_has_exited(pidfd);
            close_fds(&[pidfd]);
            return match exited {
                Ok(true) => Ok(()),
                Ok(false) | Err(_) => Err(error),
            };
        }
    };
    if current_identity != identity {
        close_fds(&[pidfd]);
        return Ok(());
    }

    let signal_result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if signal_result < 0 {
        let error = std::io::Error::last_os_error();
        close_fds(&[pidfd]);
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!(
                "terminate payload boundary {}: {error}",
                identity.pid
            ))
        };
    }

    let deadline = Instant::now() + HELPER_PAYLOAD_EXIT_TIMEOUT;
    let result = wait_for_pidfd_exit(pidfd, deadline).map_err(|error| {
        format!(
            "payload boundary {} did not terminate cleanly: {error}",
            identity.pid
        )
    });
    close_fds(&[pidfd]);
    result
}

fn wait_for_pidfd_exit(pidfd: RawFd, deadline: Instant) -> Result<(), String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("deadline exceeded".into());
        }
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms.max(1)) };
        if polled > 0 {
            return Ok(());
        }
        if polled == 0 {
            return Err("deadline exceeded".into());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(errno_message("poll payload boundary pidfd"));
        }
    }
}

fn pidfd_has_exited(pidfd: RawFd) -> Result<bool, String> {
    let mut poll_fd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        let polled = unsafe { libc::poll(&mut poll_fd, 1, 0) };
        if polled >= 0 {
            return Ok(polled > 0);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(errno_message("poll payload boundary pidfd"));
        }
    }
}

fn write_helper_ok(sync_fd: RawFd) -> Result<(), String> {
    let result = super::write_all_fd(sync_fd, HELPER_SYNC_OK.as_bytes()).map_err(|errno| {
        format!(
            "helper sync success write failed: {}",
            std::io::Error::from_raw_os_error(errno)
        )
    });
    unsafe {
        libc::close(sync_fd);
    }
    result
}

fn write_helper_error(sync_fd: RawFd, message: &str) {
    let mut rendered = String::from("ERR ");
    rendered.push_str(message);
    rendered.push('\n');
    let _ = super::write_all_fd(sync_fd, rendered.as_bytes());
    unsafe {
        libc::close(sync_fd);
    }
}

fn errno_message(label: &str) -> String {
    format!("{label} failed: {}", std::io::Error::last_os_error())
}

fn helper_state_path(sandbox_id: SandboxId) -> std::path::PathBuf {
    std::path::Path::new(HELPER_STATE_DIR).join(sandbox_id.to_string())
}

fn create_helper_state(
    sandbox_id: SandboxId,
    owner_uid: u32,
    destroy_token: &str,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    if !valid_destroy_token(destroy_token) {
        return Err("invalid helper destroy token".into());
    }
    ensure_helper_state_dir()?;
    let _lock = lock_helper_state_dir(owner_guard_fd, HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    enforce_active_namespace_quota_locked(owner_uid)?;
    let path = helper_state_path(sandbox_id);
    write_helper_state_file_atomic(
        &path,
        &HelperState {
            owner_uid,
            destroy_token: destroy_token.to_string(),
            created_resources: CreatedNetnsResources::default(),
            payload_boundary: None,
            cleanup_completed: false,
        },
        AtomicStateWriteMode::Create,
    )
}

fn record_helper_created_resources(
    sandbox_id: SandboxId,
    created_resources: CreatedNetnsResources,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    let _lock = lock_helper_state_dir(owner_guard_fd, HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    let path = helper_state_path(sandbox_id);
    let mut state = read_helper_state_file(&path)?;
    state.created_resources = created_resources;
    write_helper_state_file_atomic(&path, &state, AtomicStateWriteMode::Replace)
}

fn record_helper_payload_boundary(
    sandbox_id: SandboxId,
    payload_boundary: HelperProcessIdentity,
    owner_guard_fd: RawFd,
) -> Result<(), String> {
    let _lock = lock_helper_state_dir(owner_guard_fd, HELPER_STATE_LOCK_TIMEOUT)?;
    cleanup_stale_helper_state_temps_locked(std::path::Path::new(HELPER_STATE_DIR))?;
    let path = helper_state_path(sandbox_id);
    let mut state = read_helper_state_file(&path)?;
    state.payload_boundary = Some(payload_boundary);
    write_helper_state_file_atomic(&path, &state, AtomicStateWriteMode::Replace)
}

fn record_helper_cleanup_completed_locked(sandbox_id: SandboxId) -> Result<(), String> {
    let path = helper_state_path(sandbox_id);
    let mut state = read_helper_state_file(&path)?;
    state.created_resources = CreatedNetnsResources::default();
    state.payload_boundary = None;
    state.cleanup_completed = true;
    write_helper_state_file_atomic(&path, &state, AtomicStateWriteMode::Replace)
}

fn validate_helper_state(
    sandbox_id: SandboxId,
    owner_uid: u32,
    destroy_token: &str,
) -> Result<HelperState, String> {
    ensure_helper_state_dir()?;
    let path = helper_state_path(sandbox_id);
    let state = read_helper_state_file(&path)?;
    validate_helper_state_authentication(state, owner_uid, destroy_token)
}

fn validate_helper_state_authentication(
    state: HelperState,
    owner_uid: u32,
    destroy_token: &str,
) -> Result<HelperState, String> {
    if state.owner_uid != owner_uid {
        return Err("helper destroy owner does not match namespace owner".into());
    }
    if state.destroy_token != destroy_token {
        return Err("helper destroy token does not match namespace owner".into());
    }
    Ok(state)
}

fn read_helper_state_file(path: &std::path::Path) -> Result<HelperState, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("read helper state {}: {e}", path.display()))?;
    let mut lines = contents.lines();
    let recorded_uid = lines
        .next()
        .ok_or_else(|| format!("helper state {} is missing owner uid", path.display()))?
        .parse::<u32>()
        .map_err(|e| format!("helper state {} owner uid: {e}", path.display()))?;
    let recorded_token = lines
        .next()
        .ok_or_else(|| format!("helper state {} is missing destroy token", path.display()))?
        .to_string();
    let resources = lines.next().ok_or_else(|| {
        format!(
            "helper state {} is missing resource ownership",
            path.display()
        )
    })?;
    let mut resource_fields = resources.split_whitespace();
    if resource_fields.next() != Some("resources") {
        return Err(format!(
            "helper state {} resource ownership is malformed",
            path.display()
        ));
    }
    let parse_flag = |value: Option<&str>| match value {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(format!(
            "helper state {} resource ownership is malformed",
            path.display()
        )),
    };
    let created_resources = CreatedNetnsResources {
        namespace: parse_flag(resource_fields.next())?,
        host_veth: parse_flag(resource_fields.next())?,
    };
    let cleanup_completed = match resource_fields.next() {
        Some(value) => parse_flag(Some(value))?,
        None => false,
    };
    if resource_fields.next().is_some()
        || (created_resources.host_veth && !created_resources.namespace)
        || (created_resources.namespace && cleanup_completed)
    {
        return Err(format!(
            "helper state {} resource ownership is inconsistent",
            path.display()
        ));
    }
    let payload_boundary = lines
        .next()
        .map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("payload") {
                return Err(format!(
                    "helper state {} payload identity is malformed",
                    path.display()
                ));
            }
            let pid = fields
                .next()
                .ok_or_else(|| {
                    format!(
                        "helper state {} payload identity is malformed",
                        path.display()
                    )
                })?
                .parse::<libc::pid_t>()
                .map_err(|e| format!("helper state {} payload process id: {e}", path.display()))?;
            let start_time = fields
                .next()
                .ok_or_else(|| {
                    format!(
                        "helper state {} payload identity is malformed",
                        path.display()
                    )
                })?
                .parse::<u64>()
                .map_err(|e| format!("helper state {} payload start time: {e}", path.display()))?;
            if fields.next().is_some() || pid <= 1 || start_time == 0 {
                return Err(format!(
                    "helper state {} payload identity is unsafe",
                    path.display()
                ));
            }
            Ok(HelperProcessIdentity { pid, start_time })
        })
        .transpose()?;
    if payload_boundary.is_some() && (!created_resources.namespace || cleanup_completed) {
        return Err(format!(
            "helper state {} records a payload without namespace ownership",
            path.display()
        ));
    }
    if lines.next().is_some() {
        return Err(format!(
            "helper state {} contains unexpected trailing data",
            path.display()
        ));
    }
    if !valid_destroy_token(&recorded_token) {
        return Err(format!(
            "helper state {} contains an invalid destroy token",
            path.display()
        ));
    }
    Ok(HelperState {
        owner_uid: recorded_uid,
        destroy_token: recorded_token,
        created_resources,
        payload_boundary,
        cleanup_completed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicStateWriteMode {
    Create,
    Replace,
}

#[cfg(test)]
fn write_helper_state_file(path: &std::path::Path, state: &HelperState) -> Result<(), String> {
    write_helper_state_file_atomic(path, state, AtomicStateWriteMode::Replace)
}

fn write_helper_state_file_atomic(
    path: &std::path::Path,
    state: &HelperState,
    mode: AtomicStateWriteMode,
) -> Result<(), String> {
    write_helper_state_file_atomic_with(path, state, mode, |_| Ok(()))
}

fn write_helper_state_file_atomic_with<F>(
    path: &std::path::Path,
    state: &HelperState,
    mode: AtomicStateWriteMode,
    before_install: F,
) -> Result<(), String>
where
    F: FnOnce(&std::path::Path) -> Result<(), String>,
{
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| format!("helper state path {} has no parent", path.display()))?;
    let temp_path = parent.join(format!(
        ".tmp-u{}-{}",
        state.owner_uid,
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| format!("create helper state temp {}: {e}", temp_path.display()))?;
    let write_result = writeln!(file, "{}", state.owner_uid)
        .and_then(|_| writeln!(file, "{}", state.destroy_token))
        .and_then(|_| {
            writeln!(
                file,
                "resources {} {} {}",
                u8::from(state.created_resources.namespace),
                u8::from(state.created_resources.host_veth),
                u8::from(state.cleanup_completed)
            )
        })
        .and_then(|_| {
            if let Some(payload_boundary) = state.payload_boundary {
                writeln!(
                    file,
                    "payload {} {}",
                    payload_boundary.pid, payload_boundary.start_time
                )
            } else {
                Ok(())
            }
        });
    if let Err(error) = write_result.and_then(|_| file.sync_all()) {
        drop(file);
        let cleanup = std::fs::remove_file(&temp_path);
        return Err(match cleanup {
            Ok(()) => format!("write helper state {}: {error}", path.display()),
            Err(cleanup) => format!(
                "write helper state {}: {error}; remove temp {}: {cleanup}",
                path.display(),
                temp_path.display()
            ),
        });
    }
    drop(file);

    if let Err(error) = before_install(&temp_path) {
        let cleanup = std::fs::remove_file(&temp_path);
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => format!(
                "{error}; remove helper state temp {}: {cleanup}",
                temp_path.display()
            ),
        });
    }

    let rename_result = match mode {
        AtomicStateWriteMode::Create => rename_noreplace(&temp_path, path),
        AtomicStateWriteMode::Replace => std::fs::rename(&temp_path, path),
    };
    if let Err(error) = rename_result {
        let cleanup = std::fs::remove_file(&temp_path);
        return Err(match cleanup {
            Ok(()) => format!("install helper state {}: {error}", path.display()),
            Err(cleanup) => format!(
                "install helper state {}: {error}; remove temp {}: {cleanup}",
                path.display(),
                temp_path.display()
            ),
        });
    }
    sync_directory(parent).map_err(|error| {
        format!(
            "sync helper state directory {} after installing {}: {error}",
            parent.display(),
            path.display()
        )
    })
}

fn rename_noreplace(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn sync_directory(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

fn remove_helper_state(sandbox_id: SandboxId) -> Result<(), String> {
    remove_helper_state_file(&helper_state_path(sandbox_id))
}

fn remove_helper_state_file(path: &std::path::Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("helper state path {} has no parent", path.display()))?;
    std::fs::remove_file(path)
        .map_err(|error| format!("remove helper state {}: {error}", path.display()))?;
    sync_directory(parent).map_err(|error| {
        format!(
            "sync helper state directory {} after removing {}: {error}",
            parent.display(),
            path.display()
        )
    })
}

fn cleanup_stale_helper_state_temps_locked(state_dir: &std::path::Path) -> Result<usize, String> {
    let mut removed = 0;
    for entry in std::fs::read_dir(state_dir)
        .map_err(|e| format!("read helper state dir {}: {e}", state_dir.display()))?
    {
        let entry = entry
            .map_err(|e| format!("inspect helper state temp in {}: {e}", state_dir.display()))?;
        let file_name = entry.file_name();
        if !file_name.as_encoded_bytes().starts_with(b".tmp-") {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("inspect helper state temp {}: {e}", path.display()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            tracing::warn!("ignoring unsafe helper state temporary entry");
            continue;
        }
        std::fs::remove_file(&path)
            .map_err(|e| format!("remove stale helper state temp {}: {e}", path.display()))?;
        removed += 1;
    }
    if removed > 0 {
        sync_directory(state_dir).map_err(|e| {
            format!(
                "sync helper state directory {} after stale temp cleanup: {e}",
                state_dir.display()
            )
        })?;
    }
    Ok(removed)
}

fn ensure_helper_state_dir() -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    let state_dir = std::path::Path::new(HELPER_STATE_DIR);
    let mut current = std::path::PathBuf::new();
    for component in state_dir.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current).is_err() {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&current)
                .map_err(|e| format!("create helper state dir {}: {e}", current.display()))?;
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|e| format!("helper state dir {}: {e}", current.display()))?;
        if !safe_root_metadata(&metadata, SafePathKind::AncestorDirectory) {
            return Err(format!(
                "helper state dir component {} must be a root-owned non-writable real directory",
                current.display()
            ));
        }
    }
    Ok(())
}

fn lock_helper_state_dir(
    owner_guard_fd: RawFd,
    timeout: Duration,
) -> Result<std::fs::File, String> {
    lock_helper_state_file(
        &std::path::Path::new(HELPER_STATE_DIR).join(".lock"),
        owner_guard_fd,
        timeout,
    )
}

fn lock_helper_state_dir_unowned(timeout: Duration) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let lock_path = std::path::Path::new(HELPER_STATE_DIR).join(".lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| format!("open helper state lock {}: {e}", lock_path.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(file);
        }
        let error = super::current_errno();
        if error == libc::EINTR {
            continue;
        }
        if error != libc::EWOULDBLOCK {
            return Err(format!(
                "lock helper state dir {}: {}",
                lock_path.display(),
                std::io::Error::from_raw_os_error(error)
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "lock helper state dir {}: deadline exceeded after {} ms of contention",
                lock_path.display(),
                timeout.as_millis()
            ));
        }
        std::thread::sleep(
            HELPER_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn lock_helper_state_file(
    lock_path: &std::path::Path,
    owner_guard_fd: RawFd,
    timeout: Duration,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)
        .map_err(|e| format!("open helper state lock {}: {e}", lock_path.display()))?;
    wait_for_helper_state_lock_with(
        file.as_raw_fd(),
        owner_guard_fd,
        timeout,
        |fd| {
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                Ok(())
            } else {
                Err(super::current_errno())
            }
        },
        ensure_owner_guard_alive,
    )
    .map_err(|error| format!("lock helper state dir {}: {error}", lock_path.display()))?;
    Ok(file)
}

fn wait_for_helper_state_lock_with<T, O>(
    lock_fd: RawFd,
    owner_guard_fd: RawFd,
    timeout: Duration,
    mut try_lock: T,
    mut owner_alive: O,
) -> Result<(), String>
where
    T: FnMut(RawFd) -> Result<(), i32>,
    O: FnMut(RawFd) -> Result<(), String>,
{
    let deadline = Instant::now() + timeout;
    loop {
        owner_alive(owner_guard_fd)?;
        match try_lock(lock_fd) {
            Ok(()) => {
                owner_alive(owner_guard_fd)?;
                return Ok(());
            }
            Err(libc::EINTR) => continue,
            Err(libc::EWOULDBLOCK) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "deadline exceeded after {} ms of contention",
                        timeout.as_millis()
                    ));
                }
                std::thread::sleep(
                    HELPER_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(errno) => {
                return Err(std::io::Error::from_raw_os_error(errno).to_string());
            }
        }
    }
}

fn enforce_active_namespace_quota_locked(owner_uid: u32) -> Result<(), String> {
    let active = count_active_namespace_entries(std::path::Path::new(HELPER_STATE_DIR), owner_uid)?;

    if active >= MAX_ACTIVE_HELPER_NETNS_PER_UID {
        Err(format!(
            "helper netns quota exceeded for UID {owner_uid}: {active} active, limit {MAX_ACTIVE_HELPER_NETNS_PER_UID}"
        ))
    } else {
        Ok(())
    }
}

fn count_active_namespace_entries(
    state_dir: &std::path::Path,
    owner_uid: u32,
) -> Result<usize, String> {
    let entries = std::fs::read_dir(state_dir)
        .map_err(|e| format!("read helper state dir {}: {e}", state_dir.display()))?;
    let mut active = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return Err(format!(
                    "inspect helper state directory entry for UID {owner_uid}: {error}"
                ));
            }
        };
        if entry.file_name() == ".lock"
            || entry.file_name().as_encoded_bytes().starts_with(b".tmp-")
        {
            continue;
        }
        match read_helper_state_file(&entry.path()) {
            Ok(state) if state.owner_uid != owner_uid => {}
            Ok(_) => active += 1,
            Err(error) => {
                tracing::warn!(
                    "ignoring malformed helper state while counting UID {owner_uid} quota: {error}"
                );
            }
        }
    }
    Ok(active)
}

fn ensure_helper_effective_root() -> Result<(), String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        Err(format!(
            "axis-netns-helper requires effective UID 0; current effective UID is {euid}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_helper_real_root() -> Result<(), String> {
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 {
        Err(format!(
            "axis-netns-helper destroy requires real UID 0; current real UID is {ruid}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_helper_privileged() -> Result<(), String> {
    ensure_helper_effective_root()
}

fn normalize_helper_control_plane_rlimits() -> Result<(), String> {
    for (resource, minimum, label) in [
        (
            libc::RLIMIT_FSIZE,
            HELPER_CONTROL_PLANE_MIN_FSIZE,
            "file size",
        ),
        (libc::RLIMIT_CPU, HELPER_CONTROL_PLANE_MIN_CPU, "CPU time"),
        (
            libc::RLIMIT_AS,
            HELPER_CONTROL_PLANE_MIN_AS,
            "address space",
        ),
        (
            libc::RLIMIT_DATA,
            HELPER_CONTROL_PLANE_MIN_DATA,
            "data segment",
        ),
        (
            libc::RLIMIT_NPROC,
            HELPER_CONTROL_PLANE_MIN_NPROC,
            "process count",
        ),
    ] {
        raise_helper_control_plane_rlimit(resource, minimum, label)?;
    }

    raise_helper_control_plane_rlimit(
        libc::RLIMIT_NOFILE,
        HELPER_CONTROL_PLANE_MIN_NOFILE,
        "open files",
    )?;

    set_helper_control_plane_rlimit_pair(libc::RLIMIT_CORE, 0, 0, "core dump size")
}

fn raise_helper_control_plane_rlimit(
    resource: libc::__rlimit_resource_t,
    minimum: libc::rlim_t,
    label: &str,
) -> Result<(), String> {
    let mut current = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    if unsafe { libc::getrlimit(resource, current.as_mut_ptr()) } < 0 {
        return Err(format!(
            "read helper {label} limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    let current = unsafe { current.assume_init() };
    let normalized = normalized_helper_control_plane_rlimit(current, minimum);
    set_helper_control_plane_rlimit_pair(resource, normalized.rlim_cur, normalized.rlim_max, label)
}

fn normalized_helper_control_plane_rlimit(
    current: libc::rlimit,
    minimum: libc::rlim_t,
) -> libc::rlimit {
    let hard = current.rlim_max.max(minimum);
    libc::rlimit {
        rlim_cur: current.rlim_cur.max(minimum).min(hard),
        rlim_max: hard,
    }
}

fn set_helper_control_plane_rlimit_pair(
    resource: libc::__rlimit_resource_t,
    soft: libc::rlim_t,
    hard: libc::rlim_t,
    label: &str,
) -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    if unsafe { libc::setrlimit(resource, &limit) } < 0 {
        Err(format!(
            "normalize helper {label} limit: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn set_no_new_privs() -> Result<(), String> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

const FIXED_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

fn fixed_system_command(binary: &str) -> Result<String, String> {
    if binary.contains('/') {
        return Err(format!(
            "system command name must not contain '/': {binary}"
        ));
    }

    for dir in FIXED_COMMAND_DIRS {
        let candidate = std::path::Path::new(dir).join(binary);
        if safe_root_executable_or_trusted_symlink(&candidate) {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err(format!(
        "cannot find safe root-owned executable for {binary} in fixed system paths"
    ))
}

fn safe_root_executable(path: &std::path::Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        let kind = if current == path {
            SafePathKind::ExecutableFile
        } else {
            SafePathKind::AncestorDirectory
        };
        if !safe_root_metadata(&metadata, kind) {
            return false;
        }
        if current == path {
            return true;
        }
    }
    false
}

fn safe_root_executable_or_trusted_symlink(path: &std::path::Path) -> bool {
    if safe_root_executable(path) {
        return true;
    }
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    safe_root_executable(&resolved) && safe_root_path_or_symlink_chain(path)
}

fn safe_root_path_or_symlink_chain(path: &std::path::Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            if metadata.uid() != 0 {
                return false;
            }
            continue;
        }

        let kind = if current == path {
            SafePathKind::ExecutableFile
        } else {
            SafePathKind::AncestorDirectory
        };
        if !safe_root_metadata(&metadata, kind) {
            return false;
        }
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafePathKind {
    AncestorDirectory,
    ExecutableFile,
}

fn safe_root_metadata(metadata: &std::fs::Metadata, kind: SafePathKind) -> bool {
    if metadata.file_type().is_symlink()
        || !safe_root_owner_and_mode(metadata.uid(), metadata.mode())
    {
        return false;
    }

    match kind {
        SafePathKind::AncestorDirectory => metadata.is_dir(),
        SafePathKind::ExecutableFile => metadata.is_file() && metadata.mode() & 0o111 != 0,
    }
}

fn safe_root_owner_and_mode(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::os::unix::io::AsRawFd;
    use std::str::FromStr;
    use std::sync::Mutex;

    static COMMAND_BOUNDARY_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Default)]
    struct FakeRunner {
        commands: Vec<NetnsCommand>,
        fail_at: Option<usize>,
        failure_message: Option<String>,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &mut self,
            command: &NetnsCommand,
            _owner_guard_fd: Option<RawFd>,
        ) -> Result<(), String> {
            self.commands.push(command.clone());
            if self.fail_at == Some(self.commands.len()) {
                Err(self.failure_message.clone().unwrap_or_else(|| {
                    format!(
                        "forced failure: {} {}",
                        command.program,
                        command.args.join(" ")
                    )
                }))
            } else {
                Ok(())
            }
        }
    }

    struct ScriptedGuardedChild {
        waits: VecDeque<Result<Option<libc::c_int>, i32>>,
        signal_error: Option<String>,
        exit_wait_error: Option<String>,
        signals: usize,
    }

    impl GuardedChildOps for ScriptedGuardedChild {
        fn try_wait(&mut self, _pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
            self.waits
                .pop_front()
                .unwrap_or(Ok(None))
                .map_err(std::io::Error::from_raw_os_error)
        }

        fn send_sigkill(&mut self, _pid: libc::pid_t) -> Result<(), String> {
            self.signals += 1;
            match &self.signal_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn wait_for_exit(&mut self, _deadline: Instant) -> Result<(), String> {
            match &self.exit_wait_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }

    struct RootlessCommandNamespaceLauncher {
        fixture_path: Option<std::path::PathBuf>,
        primary_pid: Option<libc::pid_t>,
        terminate_calls: usize,
    }

    impl RootlessCommandNamespaceLauncher {
        fn new() -> Self {
            Self {
                fixture_path: None,
                primary_pid: None,
                terminate_calls: 0,
            }
        }
    }

    impl CommandNamespaceLauncher for RootlessCommandNamespaceLauncher {
        fn launch(&mut self, program: &str, args: &[String]) -> Result<libc::pid_t, String> {
            let helper_guard_fd = open_self_pidfd()?;
            let init = unsafe { libc::fork() };
            if init < 0 {
                close_fds(&[helper_guard_fd]);
                return Err(errno_message("fork rootless command namespace init"));
            }
            if init == 0 {
                run_command_namespace_init_with(program, args, helper_guard_fd, false, false);
            }
            close_fds(&[helper_guard_fd]);

            let fixture_path = command_boundary_fixture_path(init);
            wait_for_fixture_records(&fixture_path, 10);
            let records = read_command_boundary_fixture(&fixture_path);
            self.primary_pid = records.first().map(|record| record.0);
            self.fixture_path = Some(fixture_path);
            Ok(init)
        }

        fn try_wait(&mut self, pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
            try_wait_for_child(pid)
        }

        fn terminate(&mut self, init_pid: libc::pid_t) -> Result<(), String> {
            self.terminate_calls += 1;
            let primary_pid = self.primary_pid.ok_or_else(|| {
                "rootless namespace fixture did not publish its primary pid".to_string()
            })?;
            if unsafe { libc::kill(primary_pid, libc::SIGKILL) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(format!(
                    "terminate rootless namespace primary {primary_pid}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match try_wait_for_child(init_pid) {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(HELPER_POLL_INTERVAL)
                    }
                    Ok(None) => {
                        return Err(format!(
                            "rootless namespace init {init_pid} did not reap its descendants"
                        ));
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }

    struct ScriptedCommandNamespaceLauncher {
        launch: Option<Result<libc::pid_t, String>>,
        waits: VecDeque<Result<Option<libc::c_int>, i32>>,
        terminate_error: Option<String>,
        terminate_calls: usize,
    }

    impl CommandNamespaceLauncher for ScriptedCommandNamespaceLauncher {
        fn launch(&mut self, _program: &str, _args: &[String]) -> Result<libc::pid_t, String> {
            self.launch.take().unwrap()
        }

        fn try_wait(&mut self, _pid: libc::pid_t) -> Result<Option<libc::c_int>, std::io::Error> {
            self.waits
                .pop_front()
                .unwrap_or(Ok(None))
                .map_err(std::io::Error::from_raw_os_error)
        }

        fn terminate(&mut self, _pid: libc::pid_t) -> Result<(), String> {
            self.terminate_calls += 1;
            match &self.terminate_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn detect_strategy_returns_value() {
        let strategy = detect_strategy();
        eprintln!("detected netns strategy: {strategy}");
    }

    #[test]
    fn run_cmd_works() {
        assert!(run_cmd("true", &[]).is_ok());
        assert!(run_cmd("false", &[]).is_err());
    }

    #[test]
    fn bounded_command_times_out_and_reaps_fork_churn() {
        let _fixture_lock = COMMAND_BOUNDARY_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture_path = command_boundary_fixture_path(unsafe { libc::getpid() });
        let _ = std::fs::remove_file(&fixture_path);
        let program = std::env::current_exe().unwrap();
        let args = command_boundary_fixture_args();

        let error = run_cmd_cleared_env_with_timeout(
            program.to_str().unwrap(),
            &args,
            None,
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(error.contains("exceeded its 1000 ms deadline"), "{error}");
        let records = read_command_boundary_fixture(&fixture_path);
        assert_eq!(records.len(), 7, "fixture records: {records:?}");
        assert!(
            records
                .iter()
                .all(|(_, result, errno)| *result == 0 && *errno == 0)
        );
        for (pid, _, _) in &records {
            assert_process_disappears(*pid);
        }
        std::fs::remove_file(fixture_path).unwrap();
    }

    #[test]
    fn bounded_command_owner_death_interrupts_setup_and_reaps_children() {
        let _fixture_lock = COMMAND_BOUNDARY_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture_path = command_boundary_fixture_path(unsafe { libc::getpid() });
        let _ = std::fs::remove_file(&fixture_path);
        let owner = spawn_paused_test_process();
        let owner_pidfd = open_test_pidfd(owner);
        let path_for_killer = fixture_path.clone();
        let killer = std::thread::spawn(move || {
            wait_for_fixture_records(&path_for_killer, 7);
            assert_eq!(unsafe { libc::kill(owner, libc::SIGKILL) }, 0);
        });
        let program = std::env::current_exe().unwrap();

        let error = run_cmd_cleared_env_with_timeout(
            program.to_str().unwrap(),
            &command_boundary_fixture_args(),
            Some(owner_pidfd),
            Duration::from_secs(5),
        )
        .unwrap_err();

        killer.join().unwrap();
        assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);
        close_fds(&[owner_pidfd]);
        assert!(
            error.contains("AXIS owner is no longer supervising"),
            "{error}"
        );
        let records = read_command_boundary_fixture(&fixture_path);
        for (pid, _, _) in &records {
            assert_process_disappears(*pid);
        }
        std::fs::remove_file(fixture_path).unwrap();
    }

    #[test]
    fn bounded_command_preserves_normal_completion_and_hides_output() {
        let owner = spawn_paused_test_process();
        let owner_pidfd = open_test_pidfd(owner);
        let success = run_cmd_cleared_env_with_timeout(
            "/bin/sh",
            &["-c".into(), "exit 0".into()],
            Some(owner_pidfd),
            Duration::from_secs(1),
        );
        assert!(success.is_ok(), "{success:?}");

        let error = run_cmd_cleared_env_with_timeout(
            "/bin/sh",
            &[
                "-c".into(),
                "printf 'untrusted-secret-output' >&2; exit 19".into(),
            ],
            Some(owner_pidfd),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("status"));
        assert!(!error.contains("untrusted-secret-output"));

        assert_eq!(unsafe { libc::kill(owner, libc::SIGKILL) }, 0);
        assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);
        close_fds(&[owner_pidfd]);
    }

    #[test]
    fn owner_death_reap_handles_exit_before_and_after_signal() {
        let mut before_signal = ScriptedGuardedChild {
            waits: VecDeque::from([Ok(Some(test_exit_wait_status(19)))]),
            signal_error: None,
            exit_wait_error: None,
            signals: 0,
        };
        let result = finish_helper_child_after_owner_death(
            4242,
            &mut before_signal,
            Instant::now() + Duration::from_secs(1),
            None,
        );
        assert_eq!(result, (19, None));
        assert_eq!(before_signal.signals, 0);

        let mut after_signal = ScriptedGuardedChild {
            waits: VecDeque::from([Ok(None), Ok(Some(test_signal_wait_status(libc::SIGKILL)))]),
            signal_error: None,
            exit_wait_error: None,
            signals: 0,
        };
        let result = finish_helper_child_after_owner_death(
            4242,
            &mut after_signal,
            Instant::now() + Duration::from_secs(1),
            None,
        );
        assert_eq!(result, (128 + libc::SIGKILL, None));
        assert_eq!(after_signal.signals, 1);
    }

    #[test]
    fn owner_death_reap_is_bounded_and_reports_echild() {
        let mut timeout = ScriptedGuardedChild {
            waits: VecDeque::from([Ok(None)]),
            signal_error: None,
            exit_wait_error: None,
            signals: 0,
        };
        let (exit_code, error) =
            finish_helper_child_after_owner_death(4242, &mut timeout, Instant::now(), None);
        assert_eq!(exit_code, 127);
        assert!(error.unwrap().contains("did not exit"));
        assert_eq!(timeout.signals, 1);

        for waits in [
            VecDeque::from([Err(libc::ECHILD), Err(libc::ECHILD)]),
            VecDeque::from([Ok(None), Err(libc::ECHILD)]),
        ] {
            let mut child = ScriptedGuardedChild {
                waits,
                signal_error: None,
                exit_wait_error: None,
                signals: 0,
            };
            let (exit_code, error) = finish_helper_child_after_owner_death(
                4242,
                &mut child,
                Instant::now() + Duration::from_secs(1),
                None,
            );
            assert_eq!(exit_code, 127);
            assert!(error.unwrap().contains("No child processes"));
            assert_eq!(child.signals, 1);
        }
    }

    #[test]
    fn owner_death_reap_retries_eintr_and_aggregates_cleanup_errors() {
        let mut interrupted = ScriptedGuardedChild {
            waits: VecDeque::from([
                Err(libc::EINTR),
                Ok(None),
                Err(libc::EINTR),
                Ok(Some(test_exit_wait_status(0))),
            ]),
            signal_error: None,
            exit_wait_error: None,
            signals: 0,
        };
        assert_eq!(
            finish_helper_child_after_owner_death(
                4242,
                &mut interrupted,
                Instant::now() + Duration::from_secs(1),
                None,
            ),
            (0, None)
        );
        assert_eq!(interrupted.signals, 1);

        let mut failing = ScriptedGuardedChild {
            waits: VecDeque::from([Ok(None), Err(libc::EIO)]),
            signal_error: Some("pidfd signal failed".into()),
            exit_wait_error: Some("pidfd exit confirmation failed".into()),
            signals: 0,
        };
        let (exit_code, error) = finish_helper_child_after_owner_death(
            4242,
            &mut failing,
            Instant::now() + Duration::from_secs(1),
            Some("owner poll failed".into()),
        );
        assert_eq!(exit_code, 127);
        let error = error.unwrap();
        assert!(error.contains("owner poll failed"), "{error}");
        assert!(error.contains("pidfd signal failed"), "{error}");
        assert!(error.contains("Input/output error"), "{error}");
        assert!(error.contains("pidfd exit confirmation failed"), "{error}");
    }

    #[test]
    fn abort_payload_namespace_child_is_bounded_and_reaps_when_possible() {
        let exited = unsafe { libc::fork() };
        assert!(
            exited >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if exited == 0 {
            unsafe { libc::_exit(17) };
        }
        let exited_pidfd = open_test_pidfd(exited);
        wait_for_pidfd_exit(exited_pidfd, Instant::now() + Duration::from_secs(1)).unwrap();
        close_fds(&[exited_pidfd]);
        abort_payload_namespace_child(exited).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(exited, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );

        let running = spawn_paused_test_process();
        abort_payload_namespace_child(running).unwrap();
        assert_eq!(unsafe { libc::kill(running, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn helper_state_lock_state_machine_handles_contention_eintr_and_errors() {
        let mut attempts = VecDeque::from([Err(libc::EINTR), Err(libc::EWOULDBLOCK), Ok(())]);
        let mut owner_checks = 0;
        wait_for_helper_state_lock_with(
            10,
            11,
            Duration::from_millis(100),
            |_| attempts.pop_front().unwrap(),
            |_| {
                owner_checks += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(owner_checks, 4);

        let timeout = wait_for_helper_state_lock_with(
            10,
            11,
            Duration::ZERO,
            |_| Err(libc::EWOULDBLOCK),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(
            timeout.contains("deadline exceeded after 0 ms"),
            "{timeout}"
        );

        let error = wait_for_helper_state_lock_with(
            10,
            11,
            Duration::from_secs(1),
            |_| Err(libc::EIO),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("Input/output error"), "{error}");
    }

    #[test]
    fn helper_state_lock_stops_on_owner_death_and_releases_on_all_paths() {
        use std::os::unix::fs::OpenOptionsExt;

        let lock_dir = tempfile::tempdir().unwrap();
        let lock_path = lock_dir.path().join("helper-state.lock");
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        assert_eq!(unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX) }, 0);

        let owner = spawn_paused_test_process();
        let owner_pidfd = open_test_pidfd(owner);
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(unsafe { libc::kill(owner, libc::SIGKILL) }, 0);
        });
        let error =
            lock_helper_state_file(&lock_path, owner_pidfd, Duration::from_secs(1)).unwrap_err();
        killer.join().unwrap();
        assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);
        assert!(error.contains("no longer supervising"), "{error}");
        close_fds(&[owner_pidfd]);

        let live_owner_pidfd = open_test_pidfd(unsafe { libc::getpid() });
        let timeout =
            lock_helper_state_file(&lock_path, live_owner_pidfd, Duration::from_millis(40))
                .unwrap_err();
        assert!(timeout.contains("deadline exceeded"), "{timeout}");
        // Parallel tests fork, so explicitly unlock the shared open-file
        // description before dropping the holder.
        assert_eq!(unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(holder);

        let acquired =
            lock_helper_state_file(&lock_path, live_owner_pidfd, Duration::from_millis(100))
                .unwrap();
        assert_eq!(
            unsafe { libc::flock(acquired.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        drop(acquired);
        let final_lock =
            lock_helper_state_file(&lock_path, live_owner_pidfd, Duration::from_millis(100))
                .unwrap();
        drop(final_lock);
        close_fds(&[live_owner_pidfd]);
    }

    #[test]
    fn privileged_namespace_state_machine_maps_launch_wait_and_cleanup_errors() {
        let mut launch_failure = ScriptedCommandNamespaceLauncher {
            launch: Some(Err("clone containment failed".into())),
            waits: VecDeque::new(),
            terminate_error: None,
            terminate_calls: 0,
        };
        let error = run_privileged_command_in_namespace_with(
            "/bin/true",
            &[],
            None,
            Duration::from_secs(1),
            &mut launch_failure,
        )
        .unwrap_err();
        assert_eq!(error, "clone containment failed");

        let mut wait_failure = ScriptedCommandNamespaceLauncher {
            launch: Some(Ok(4242)),
            waits: VecDeque::from([Err(libc::ECHILD)]),
            terminate_error: None,
            terminate_calls: 0,
        };
        let error = run_privileged_command_in_namespace_with(
            "/bin/true",
            &[],
            None,
            Duration::from_secs(1),
            &mut wait_failure,
        )
        .unwrap_err();
        assert!(error.contains("No child processes"), "{error}");
        assert_eq!(wait_failure.terminate_calls, 1);

        let mut command_failure = ScriptedCommandNamespaceLauncher {
            launch: Some(Ok(4242)),
            waits: VecDeque::from([Ok(Some(test_exit_wait_status(19)))]),
            terminate_error: None,
            terminate_calls: 0,
        };
        let error = run_privileged_command_in_namespace_with(
            "/usr/sbin/ip",
            &["netns".into(), "add".into(), "axis-test".into()],
            None,
            Duration::from_secs(1),
            &mut command_failure,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "privileged command '/usr/sbin/ip netns add axis-test' failed with status 19"
        );
        assert_eq!(command_failure.terminate_calls, 0);

        let mut timeout_cleanup_failure = ScriptedCommandNamespaceLauncher {
            launch: Some(Ok(4242)),
            waits: VecDeque::from([Ok(None)]),
            terminate_error: Some("bounded cleanup failed".into()),
            terminate_calls: 0,
        };
        let error = run_privileged_command_in_namespace_with(
            "/bin/true",
            &[],
            None,
            Duration::ZERO,
            &mut timeout_cleanup_failure,
        )
        .unwrap_err();
        assert!(error.contains("exceeded its 0 ms deadline"), "{error}");
        assert!(error.contains("bounded cleanup failed"), "{error}");
        assert_eq!(timeout_cleanup_failure.terminate_calls, 1);
    }

    #[test]
    fn privileged_command_uid_normalization_requires_root_and_propagates_errors() {
        assert_eq!(
            ProcessCommandRunner::COMMAND_UID,
            PrivilegedCommandUid::Preserve
        );
        assert_eq!(
            PrivilegedCommandRunner::COMMAND_UID,
            PrivilegedCommandUid::NormalizeRoot
        );

        let mut calls = 0;
        let denied = normalize_privileged_command_uid_with(1000, || {
            calls += 1;
            Ok(())
        });
        assert_eq!(denied, Err(libc::EPERM));
        assert_eq!(calls, 0);

        let success = normalize_privileged_command_uid_with(0, || {
            calls += 1;
            Ok(())
        });
        assert_eq!(success, Ok(()));
        assert_eq!(calls, 1);

        let failure = normalize_privileged_command_uid_with(0, || Err(libc::EIO));
        assert_eq!(failure, Err(libc::EIO));
    }

    #[test]
    fn rootless_production_namespace_state_machine_handles_timeout_and_owner_death() {
        let _fixture_lock = COMMAND_BOUNDARY_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for owner_death in [false, true] {
            let mut launcher = RootlessCommandNamespaceLauncher::new();
            let owner = owner_death.then(spawn_paused_test_process);
            let owner_pidfd = owner.map(open_test_pidfd);
            if let Some(owner) = owner {
                assert_eq!(unsafe { libc::kill(owner, libc::SIGKILL) }, 0);
                assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);
            }
            let program = std::env::current_exe().unwrap();
            let result = run_privileged_command_in_namespace_with(
                program.to_str().unwrap(),
                &command_namespace_churn_fixture_args(),
                owner_pidfd,
                if owner_death {
                    Duration::from_secs(5)
                } else {
                    Duration::from_millis(75)
                },
                &mut launcher,
            );
            close_fds(&owner_pidfd.into_iter().collect::<Vec<_>>());

            let error = result.unwrap_err();
            if owner_death {
                assert!(
                    error.contains("AXIS owner is no longer supervising"),
                    "{error}"
                );
            } else {
                assert!(error.contains("exceeded its 75 ms deadline"), "{error}");
            }
            assert_eq!(launcher.terminate_calls, 1);
            let fixture_path = launcher.fixture_path.as_ref().unwrap();
            let records = read_command_boundary_fixture(fixture_path);
            assert!(records.len() >= 10, "insufficient fork churn: {records:?}");
            for (pid, _, _) in &records {
                assert_process_disappears(*pid);
            }
            std::fs::remove_file(fixture_path).unwrap();
        }
    }

    #[test]
    #[ignore = "process fixture launched by bounded-command lifecycle tests"]
    fn command_boundary_fixture() {
        use std::io::Write;

        let path = command_boundary_fixture_path(unsafe { libc::getppid() });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let record = format!("{} 0 0\n", unsafe { libc::getpid() });
        file.write_all(record.as_bytes()).unwrap();
        file.flush().unwrap();

        for _ in 0..6 {
            let child = unsafe { libc::fork() };
            assert!(
                child >= 0,
                "fork failed: {}",
                std::io::Error::last_os_error()
            );
            if child == 0 {
                let result = 0;
                let errno = 0;
                let record = format!("{} {result} {errno}\n", unsafe { libc::getpid() });
                file.write_all(record.as_bytes()).unwrap();
                file.flush().unwrap();
                loop {
                    unsafe { libc::pause() };
                }
            }
        }
        loop {
            unsafe { libc::pause() };
        }
    }

    #[test]
    #[ignore = "process fixture launched by privileged namespace state-machine tests"]
    fn command_namespace_churn_fixture() {
        use std::io::Write;

        let path = command_boundary_fixture_path(unsafe { libc::getppid() });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let record = format!("{} 0 0\n", unsafe { libc::getpid() });
        file.write_all(record.as_bytes()).unwrap();
        file.flush().unwrap();

        loop {
            let worker = unsafe { libc::fork() };
            if worker < 0 {
                unsafe { libc::_exit(123) };
            }
            if worker == 0 {
                let orphan = unsafe { libc::fork() };
                if orphan < 0 {
                    unsafe { libc::_exit(122) };
                }
                let record = format!("{} 0 0\n", unsafe { libc::getpid() });
                file.write_all(record.as_bytes()).unwrap();
                file.flush().unwrap();
                std::thread::sleep(Duration::from_millis(if orphan == 0 { 25 } else { 10 }));
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn veth_names_are_derived_from_sandbox_id_prefix() {
        assert_eq!(veth_host_name("1234567890abcdef"), "axh1234567890ab");
        assert_eq!(veth_sandbox_name("1234567890abcdef"), "axs1234567890ab");
        assert_eq!(veth_host_name("zzzz"), "axh000000000000");
    }

    #[test]
    fn proxy_allocation_is_deterministic_and_per_sandbox() {
        let first = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let second = SandboxId::from_str("00010000-0000-4000-8000-000000000001").unwrap();

        let first_alloc = proxy_netns_allocation(first, 3128);
        let second_alloc = proxy_netns_allocation(second, 3128);
        let first_alloc_again = proxy_netns_allocation(first, 3128);

        assert_eq!(first_alloc, first_alloc_again);
        assert_eq!(first_alloc.host_addr.octets()[0], PROXY_NET_A);
        assert_eq!(first_alloc.sandbox_addr.octets()[0], PROXY_NET_A);
        assert!(first_alloc.host_cidr.ends_with("/30"));
        assert_eq!(
            first_alloc.proxy_addr,
            SocketAddr::new(first_alloc.host_addr.into(), 3128)
        );
        assert_ne!(first_alloc.subnet_cidr, second_alloc.subnet_cidr);
        assert_ne!(first_alloc.veth_host, second_alloc.veth_host);
    }

    #[test]
    fn proxy_allocation_uses_full_uuid_not_just_first_two_bytes() {
        let first = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let same_prefix = SandboxId::from_str("00000000-0001-4000-8000-000000000002").unwrap();

        let first_alloc = proxy_netns_allocation(first, 3128);
        let same_prefix_alloc = proxy_netns_allocation(same_prefix, 3128);

        assert_eq!(&first.0.as_bytes()[..2], &same_prefix.0.as_bytes()[..2]);
        assert_ne!(first_alloc.subnet_cidr, same_prefix_alloc.subnet_cidr);
        assert_ne!(
            first_alloc.proxy_addr.ip(),
            same_prefix_alloc.proxy_addr.ip()
        );
    }

    #[test]
    fn helper_action_parser_accepts_only_typed_canonical_arguments() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let token = valid_test_token();

        assert_eq!(
            parse_helper_action(&strings(["check"])).unwrap(),
            HelperAction::Check
        );
        assert_eq!(
            parse_helper_action(&strings([
                "destroy",
                "00000000-0000-4000-8000-000000000001"
            ]))
            .unwrap(),
            HelperAction::Destroy { sandbox_id }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "destroy-token",
                "00000000-0000-4000-8000-000000000001",
                &token,
            ]))
            .unwrap(),
            HelperAction::DestroyToken {
                sandbox_id,
                destroy_token: token.clone(),
            }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "-1",
                "5",
            ]))
            .unwrap(),
            HelperAction::Launch {
                sandbox_id,
                proxy_port: 3128,
                spec_fd: 3,
                sync_fd: 4,
                cgroup_procs_fd: None,
                owner_guard_fd: 5,
            }
        );
        assert_eq!(
            parse_helper_action(&strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "5",
                "6",
            ]))
            .unwrap(),
            HelperAction::Launch {
                sandbox_id,
                proxy_port: 3128,
                spec_fd: 3,
                sync_fd: 4,
                cgroup_procs_fd: Some(5),
                owner_guard_fd: 6,
            }
        );
    }

    #[test]
    fn helper_action_parser_rejects_malicious_or_ambiguous_arguments() {
        for args in [
            strings([]),
            strings(["check", "extra"]),
            strings(["unknown"]),
            strings(["create", "00000000000040008000000000000001", "3128"]),
            strings(["create", "00000000-0000-4000-8000-000000000001", "0"]),
            strings(["create", "00000000-0000-4000-8000-000000000001", "65536"]),
            strings([
                "create",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "extra",
            ]),
            strings([
                "create",
                "00000000-0000-4000-8000-000000000001/../../x",
                "3128",
            ]),
            strings(["destroy", "axis-00000000-0000-4000-8000-000000000001"]),
            strings(["destroy", "00000000-0000-4000-8000-000000000001", "extra"]),
            strings([
                "destroy-token",
                "00000000-0000-4000-8000-000000000001",
                "not-token",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "2",
                "4",
                "-1",
                "5",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "1",
                "-1",
                "5",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "0",
                "3",
                "4",
                "-1",
                "5",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "2",
                "5",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "-1",
                "2",
            ]),
            strings([
                "launch",
                "00000000-0000-4000-8000-000000000001",
                "3128",
                "3",
                "4",
                "-1",
            ]),
        ] {
            assert!(
                parse_helper_action(&args).is_err(),
                "helper args should be rejected: {args:?}"
            );
        }
    }

    #[test]
    fn helper_launch_fd_validation_rejects_aliases() {
        assert!(validate_helper_launch_fds(3, 4, None, 5).is_ok());
        assert!(validate_helper_launch_fds(3, 4, Some(5), 6).is_ok());

        for result in [
            validate_helper_launch_fds(3, 3, None, 5),
            validate_helper_launch_fds(3, 4, None, 3),
            validate_helper_launch_fds(3, 4, Some(3), 5),
            validate_helper_launch_fds(3, 4, Some(5), 5),
        ] {
            assert!(result.unwrap_err().contains("must be distinct"));
        }
    }

    #[test]
    fn mxc_helper_launch_requires_a_distinct_owner_guard() {
        let direct = helper_launch_spec();
        validate_owner_guard_for_spec(&direct, 10).unwrap();

        let mut mxc = direct;
        mxc.launch_kind = HelperLaunchKind::MxcExecutor;
        mxc.mxc_config_fd = Some(9);
        assert!(
            validate_owner_guard_for_spec(&mxc, 9)
                .unwrap_err()
                .contains("distinct")
        );
        validate_owner_guard_for_spec(&mxc, 10).unwrap();
    }

    #[test]
    fn owner_pidfd_metadata_parser_requires_one_positive_pid() {
        assert_eq!(parse_owner_pidfd_target("Pid:\t123\n").unwrap(), 123);
        assert_eq!(
            parse_owner_pidfd_target("pos:\t0\nPid: 456\nNSpid:\t456\n").unwrap(),
            456
        );

        for (fdinfo, expected) in [
            ("pos:\t0\n", "missing"),
            ("Pid:\n", "malformed"),
            ("Pid:\tabc\n", "malformed"),
            ("Pid:\t2147483648\n", "malformed"),
            ("Pid:\t0\n", "live process"),
            ("Pid:\t-1\n", "live process"),
            ("Pid:\t1\nPid:\t2\n", "duplicate"),
        ] {
            let error = parse_owner_pidfd_target(fdinfo).unwrap_err();
            assert!(
                error.contains(expected),
                "unexpected error for {fdinfo:?}: {error}"
            );
        }
    }

    #[test]
    fn owner_pidfd_for_actual_parent_is_accepted() {
        let parent_pid = unsafe { libc::getpid() };
        let pidfd = open_test_pidfd(parent_pid);
        let validator = unsafe { libc::fork() };
        assert!(
            validator >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if validator == 0 {
            let valid =
                validate_owner_pidfd(pidfd).is_ok() && ensure_owner_guard_alive(pidfd).is_ok();
            unsafe {
                libc::close(pidfd);
                libc::_exit(if valid { 0 } else { 1 });
            }
        }
        unsafe {
            libc::close(pidfd);
        }
        assert_eq!(wait_for_helper_child(validator), 0);
    }

    #[test]
    fn owner_pidfd_for_live_non_parent_is_rejected() {
        let non_parent = unsafe { libc::fork() };
        assert!(
            non_parent >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if non_parent == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let pidfd = open_test_pidfd(non_parent);
        let validator = unsafe { libc::fork() };
        assert!(
            validator >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if validator == 0 {
            let rejected = validate_owner_pidfd(pidfd)
                .is_err_and(|error| error.contains("does not match helper parent"));
            unsafe {
                libc::close(pidfd);
                libc::_exit(if rejected { 0 } else { 1 });
            }
        }

        unsafe {
            libc::close(pidfd);
        }
        assert_eq!(wait_for_helper_child(validator), 0);
        unsafe {
            libc::kill(non_parent, libc::SIGKILL);
        }
        assert_eq!(wait_for_helper_child(non_parent), 128 + libc::SIGKILL);
    }

    #[test]
    fn dead_owner_pidfd_is_rejected_before_setup() {
        let owner = unsafe { libc::fork() };
        assert!(
            owner >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if owner == 0 {
            unsafe {
                libc::_exit(0);
            }
        }
        let pidfd = open_test_pidfd(owner);
        assert_eq!(wait_for_helper_child(owner), 0);

        let error = validate_owner_pidfd(pidfd).unwrap_err();
        unsafe {
            libc::close(pidfd);
        }
        assert!(
            error.contains("live process") || error.contains("does not match helper parent"),
            "unexpected dead-owner error: {error}"
        );
    }

    #[test]
    fn namespace_status_parser_returns_host_pid() {
        assert_eq!(
            parse_host_pid_from_proc_status("Name:\taxis\nNSpid:\t4321\t1\n").unwrap(),
            4321
        );
        for status in [
            "Name:\taxis\n",
            "NSpid:\t\n",
            "NSpid:\tnot-a-pid\n",
            "NSpid:\t0\n",
        ] {
            assert!(parse_host_pid_from_proc_status(status).is_err());
        }
    }

    #[test]
    fn mxc_config_holder_path_does_not_inherit_config_fd() {
        let config_fd = create_mxc_config_fd(b"{\"process\":{}}").unwrap();
        let mut spec = helper_launch_spec();
        spec.launch_kind = HelperLaunchKind::MxcExecutor;
        spec.mxc_config_fd = Some(config_fd);
        spec.args = vec![
            "--experimental".into(),
            "--config".into(),
            format!("/proc/self/fd/{config_fd}"),
        ];
        point_mxc_config_at_holder(&mut spec, unsafe { libc::getpid() }).unwrap();

        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!(
                "test \"$(cat '{}')\" = '{{\"process\":{{}}}}' && test ! -e /proc/self/fd/{config_fd}",
                spec.args[2]
            ))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                super::super::mark_unexpected_child_fds_close_on_exec()
                    .map_err(std::io::Error::from_raw_os_error)
            });
        }
        assert!(command.status().unwrap().success());

        let mut changed = spec.clone();
        changed.args[2] = "/proc/self/fd/999".into();
        assert!(
            point_mxc_config_at_holder(&mut changed, 123)
                .unwrap_err()
                .contains("changed after validation")
        );
        assert!(
            point_mxc_config_at_holder(&mut spec, 0)
                .unwrap_err()
                .contains("must be positive")
        );
        let mut missing_fd = spec.clone();
        missing_fd.mxc_config_fd = None;
        assert!(
            point_mxc_config_at_holder(&mut missing_fd, 123)
                .unwrap_err()
                .contains("missing its config fd")
        );
        close_fds(&[config_fd]);
    }

    #[test]
    fn parent_death_signal_rejects_an_exited_parent_guard() {
        let owner = unsafe { libc::fork() };
        assert!(
            owner >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if owner == 0 {
            unsafe { libc::_exit(0) };
        }
        let owner_pidfd = open_test_pidfd(owner);
        assert_eq!(wait_for_helper_child(owner), 0);

        let validator = unsafe { libc::fork() };
        assert!(
            validator >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if validator == 0 {
            let rejected = arm_parent_death_signal(owner_pidfd)
                .is_err_and(|error| error.contains("exited before"));
            close_fds(&[owner_pidfd]);
            unsafe { libc::_exit(if rejected { 0 } else { 1 }) };
        }

        close_fds(&[owner_pidfd]);
        assert_eq!(wait_for_helper_child(validator), 0);
    }

    #[test]
    fn owner_pidfd_exit_kills_and_reaps_payload_boundary() {
        let owner = unsafe { libc::fork() };
        assert!(
            owner >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if owner == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        let owner_pidfd = open_test_pidfd(owner);

        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                libc::close(owner_pidfd);
                loop {
                    libc::pause();
                }
            }
        }
        unsafe {
            libc::kill(owner, libc::SIGKILL);
        }
        assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);

        let (exit_code, error) = wait_for_helper_child_or_owner_death(child, owner_pidfd);
        unsafe {
            libc::close(owner_pidfd);
        }

        assert_eq!(exit_code, 128 + libc::SIGKILL);
        assert!(error.is_none(), "owner-death termination failed: {error:?}");
        let probe = unsafe { libc::kill(child, 0) };
        assert_eq!(probe, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn owner_guard_wait_preserves_normal_target_exit() {
        let owner_pidfd = open_test_pidfd(unsafe { libc::getpid() });
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                libc::_exit(23);
            }
        }

        let (exit_code, error) = wait_for_helper_child_or_owner_death(child, owner_pidfd);
        unsafe {
            libc::close(owner_pidfd);
        }

        assert_eq!(exit_code, 23);
        assert!(error.is_none());
    }

    #[test]
    fn helper_sigkill_terminates_armed_namespace_init() {
        let (result_read_fd, result_write_fd) = test_pipe();
        let helper = unsafe { libc::fork() };
        assert!(
            helper >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if helper == 0 {
            close_fds(&[result_read_fd]);
            let helper_guard_fd = open_self_pidfd().unwrap_or_else(|_| unsafe { libc::_exit(125) });
            let (ready_read_fd, ready_write_fd) =
                cloexec_pipe().unwrap_or_else(|_| unsafe { libc::_exit(124) });
            let init = unsafe { libc::fork() };
            if init < 0 {
                unsafe { libc::_exit(123) };
            }
            if init == 0 {
                close_fds(&[ready_read_fd, result_write_fd]);
                if arm_parent_death_signal(helper_guard_fd).is_err() {
                    unsafe { libc::_exit(122) };
                }
                close_fds(&[helper_guard_fd]);
                let _ = super::super::write_all_fd(ready_write_fd, &[1]);
                close_fds(&[ready_write_fd]);
                loop {
                    unsafe { libc::pause() };
                }
            }

            close_fds(&[helper_guard_fd, ready_write_fd]);
            let mut ready = [0u8; 1];
            read_exact_test_fd(ready_read_fd, &mut ready);
            close_fds(&[ready_read_fd]);
            let bytes = init.to_ne_bytes();
            let _ = super::super::write_all_fd(result_write_fd, &bytes);
            close_fds(&[result_write_fd]);
            loop {
                unsafe { libc::pause() };
            }
        }

        close_fds(&[result_write_fd]);
        let mut init_bytes = [0u8; std::mem::size_of::<libc::pid_t>()];
        read_exact_test_fd(result_read_fd, &mut init_bytes);
        close_fds(&[result_read_fd]);
        let init = libc::pid_t::from_ne_bytes(init_bytes);

        assert_eq!(unsafe { libc::kill(helper, libc::SIGKILL) }, 0);
        assert_eq!(wait_for_helper_child(helper), 128 + libc::SIGKILL);
        assert_process_disappears(init);
    }

    #[test]
    fn payload_boundary_termination_uses_stable_process_identity() {
        let child = spawn_paused_test_process();
        let identity = read_process_identity(child).unwrap();

        terminate_payload_boundary(identity).unwrap();
        assert_eq!(wait_for_helper_child(child), 128 + libc::SIGKILL);
        terminate_payload_boundary(identity).unwrap();
    }

    #[test]
    fn namespace_init_reaps_adopted_orphans_and_preserves_primary_status() {
        let (read_fd, write_fd) = test_pipe();
        let reaper = unsafe { libc::fork() };
        assert!(
            reaper >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if reaper == 0 {
            close_fds(&[read_fd]);
            if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
                unsafe { libc::_exit(125) };
            }
            let primary = unsafe { libc::fork() };
            if primary < 0 {
                unsafe { libc::_exit(124) };
            }
            if primary == 0 {
                for _ in 0..24 {
                    let worker = unsafe { libc::fork() };
                    if worker < 0 {
                        unsafe { libc::_exit(123) };
                    }
                    if worker == 0 {
                        let orphan = unsafe { libc::fork() };
                        if orphan < 0 {
                            unsafe { libc::_exit(122) };
                        }
                        unsafe { libc::_exit(0) };
                    }
                }
                std::thread::sleep(Duration::from_millis(300));
                unsafe { libc::_exit(23) };
            }

            let result = reap_namespace_children_with(primary, false);
            let record = [
                result.exit_code as u64,
                result.reaped_descendants as u64,
                result.reaped_while_primary_alive as u64,
                u64::from(result.drained),
            ];
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&record),
                )
            };
            let _ = super::super::write_all_fd(write_fd, bytes);
            close_fds(&[write_fd]);
            unsafe { libc::_exit(0) };
        }

        close_fds(&[write_fd]);
        let mut record = [0u64; 4];
        read_exact_test_fd(read_fd, unsafe {
            std::slice::from_raw_parts_mut(
                record.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(&record),
            )
        });
        close_fds(&[read_fd]);
        assert_eq!(wait_for_helper_child(reaper), 0);
        assert_eq!(record[0], 23);
        assert_eq!(record[1], 48);
        assert!(
            record[2] >= 24,
            "no adopted orphans were reaped early: {record:?}"
        );
        assert_eq!(record[3], 1);
    }

    #[test]
    fn namespace_init_reaps_orphans_after_session_and_process_group_changes() {
        let (read_fd, write_fd) = test_pipe();
        let reaper = unsafe { libc::fork() };
        assert!(
            reaper >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if reaper == 0 {
            close_fds(&[read_fd]);
            if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
                unsafe { libc::_exit(125) };
            }
            let primary = unsafe { libc::fork() };
            if primary < 0 {
                unsafe { libc::_exit(124) };
            }
            if primary == 0 {
                let mut movers = Vec::new();
                for change_session in [true, false] {
                    let mover = unsafe { libc::fork() };
                    if mover < 0 {
                        unsafe { libc::_exit(123) };
                    }
                    if mover == 0 {
                        let changed = if change_session {
                            unsafe { libc::setsid() }
                        } else {
                            unsafe { libc::setpgid(0, 0) }
                        };
                        if changed < 0 {
                            unsafe { libc::_exit(122) };
                        }
                        let orphan = unsafe { libc::fork() };
                        if orphan < 0 {
                            unsafe { libc::_exit(121) };
                        }
                        if orphan == 0 {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        unsafe { libc::_exit(0) };
                    }
                    movers.push(mover);
                }
                for mover in movers {
                    if wait_for_helper_child(mover) != 0 {
                        unsafe { libc::_exit(120) };
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
                unsafe { libc::_exit(31) };
            }

            let result = reap_namespace_children_with(primary, false);
            let record = [
                result.exit_code as u64,
                result.reaped_descendants as u64,
                result.reaped_while_primary_alive as u64,
                u64::from(result.drained),
            ];
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&record),
                )
            };
            let _ = super::super::write_all_fd(write_fd, bytes);
            close_fds(&[write_fd]);
            unsafe { libc::_exit(0) };
        }

        close_fds(&[write_fd]);
        let mut record = [0u64; 4];
        read_exact_test_fd(read_fd, unsafe {
            std::slice::from_raw_parts_mut(
                record.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(&record),
            )
        });
        close_fds(&[read_fd]);
        assert_eq!(wait_for_helper_child(reaper), 0);
        assert_eq!(record, [31, 2, 2, 1]);
    }

    #[test]
    fn namespace_init_drains_continuous_fork_churn_on_timeout_and_owner_termination() {
        for (signal, expected_exit) in [
            (libc::SIGTERM, 128 + libc::SIGTERM),
            (libc::SIGKILL, 128 + libc::SIGKILL),
        ] {
            let result = run_continuous_churn_reap_scenario(signal);
            assert_eq!(result.exit_code, expected_exit);
            assert!(
                result.reaped_descendants >= 10,
                "insufficient churn: {result:?}"
            );
            assert!(
                result.reaped_while_primary_alive > 0,
                "orphans accumulated until primary exit: {result:?}"
            );
            assert!(
                result.drained,
                "descendants survived termination: {result:?}"
            );
        }
    }

    #[test]
    fn payload_clone_requests_a_dedicated_pid_namespace() {
        let args = payload_namespace_clone_args();
        assert_eq!(args.flags, libc::CLONE_NEWPID as u64);
        assert_eq!(args.exit_signal, libc::SIGCHLD as u64);
        assert_eq!(args.pidfd, 0);
        assert_eq!(args.child_tid, 0);
        assert_eq!(args.parent_tid, 0);
        assert_eq!(args.stack, 0);
        assert_eq!(args.stack_size, 0);
        assert_eq!(args.tls, 0);
        assert_eq!(args.set_tid, 0);
        assert_eq!(args.set_tid_size, 0);
        assert_eq!(args.cgroup, 0);
    }

    #[test]
    fn clone_pid_namespace_errors_are_explicit_and_fail_closed() {
        let unavailable = clone_pid_namespace_error(libc::ENOSYS);
        assert!(unavailable.contains("unavailable"));
        assert!(unavailable.contains("clone3 PID namespace containment"));

        for errno in [libc::EPERM, libc::EACCES] {
            let denied = clone_pid_namespace_error(errno);
            assert!(denied.contains("denied"), "{denied}");
            assert!(denied.contains("clone3 PID namespace containment"));
        }

        let other = clone_pid_namespace_error(libc::EINVAL);
        assert!(other.contains("failed"));
        assert!(!other.contains("fallback"));
    }

    #[test]
    fn privileged_netns_ci_contract_requires_complete_ephemeral_proof() {
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workflow =
            std::fs::read_to_string(repository.join(".github/workflows/ci.yml")).unwrap();
        let job = workflow
            .split_once("  test-linux-netns-helper:")
            .unwrap()
            .1
            .split_once("\n  test-windows:")
            .unwrap()
            .0;
        for required in [
            "AXIS_RUN_PRIVILEGED_E2E: \"1\"",
            "AXIS_REQUIRE_NETNS_HELPER_E2E: \"1\"",
            "AXIS_REQUIRE_BUILT_AXIS_PROXY_E2E: \"1\"",
            "AXIS_REQUIRE_KMSG_AUDIT_E2E: \"1\"",
            "AXIS_PROVISION_KMSG_AUDIT_E2E: \"1\"",
            "libcap2-bin",
            "AXIS_EXPECT_MXC_EXECUTOR: /usr/bin/lxc-exec",
            "AXIS_MXC_EXECUTOR_BUILD: ${{ github.workspace }}/target/release/lxc-exec",
            "Restore helper user namespace restriction",
            "axis-netns-helper-apparmor-userns",
            "kernel.apparmor_restrict_unprivileged_userns=0",
            "bash e2e/linux/test_netns_helper_launch.sh --self-test",
            "ci_bounded_sudo test -e \"$executor\"",
            "ci_bounded_sudo test -L \"$executor\"",
        ] {
            assert!(
                job.contains(required),
                "privileged job missing {required:?}"
            );
        }
        assert!(
            !job.contains("rm -f \"$executor\""),
            "CI must not remove an executor it did not install"
        );

        let harness =
            std::fs::read_to_string(repository.join("e2e/linux/test_netns_helper_launch.sh"))
                .unwrap();
        for required in [
            "strict helper proof requires AXIS_EXPECT_MXC_EXECUTOR",
            "run_helper_lifecycle_case axis_native \"$failure_mode\"",
            "strict proxy through axis-netns-helper is unsupported",
            "refused MXC helper launch still ran its payload",
            "refused MXC helper launch left helper state behind",
            "failure_mode in owner-death helper-sigkill",
            "os.listdir(\"/proc/self/fd\")",
            "cleanup_helper_lifecycle_case",
            "lifecycle_resources_absent",
            "lifecycle-first-descendant",
            "lifecycle-second-descendant",
            "lifecycle-churner",
            "os.waitpid(worker, 0)",
            "did not sustain successful descendant churn",
            "did not execute trusted MXC binary",
            "bounded_sudo 2 test -e \"$path\"",
            "bounded_sudo 2 test -L \"$path\"",
            "bounded_sudo 5 install -o root -g root -m 0755 \"$executor_build\" \"$expected_executor\"",
            "INSTALLED_MXC_EXECUTOR=1",
            "if [ \"$INSTALLED_MXC_EXECUTOR\" -eq 1 ]",
            "bounded_sudo 5 rm -f \"$expected_executor\"",
            "while read -r pid start_time",
            "process_identity_matches \"$pid\" \"$start_time\"",
            "run_preflight_namespace_state_machine",
            "refusing to use preexisting preflight namespace",
            "provision_kmsg_audit_source",
            "install_kmsg_capability_binary",
            "cleanup_kmsg_capability_binary",
            "reject_kmsg_bundle_collisions",
            "\"$collision_check_fn\" \"$axisd_path\" \"kmsg-enabled axisd\" || return $?",
            "\"$collision_check_fn\" \"$launcher_path\" \"axis seccomp launcher\" || return $?",
            "bounded_sudo 5 install -o root -g root -m 0755 \"$1\" \"$2\"",
            "\"$KMSG_LAUNCHER_SOURCE\" \"$KMSG_LAUNCHER_INSTALL\"",
            "bounded_sudo 5 setcap cap_dac_read_search,cap_syslog=ep \"$1\"",
            "bounded_sudo 5 setcap -r \"$1\"",
            "os.open(\"/dev/kmsg\", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)",
            "audit_log_contains_matching_bypass",
            "provision_nf_log_all_netns",
            "restore_nf_log_all_netns",
            "net.netfilter.nf_log_all_netns=$1",
            "strict kmsg gate accepted an unavailable audit source",
            "-name \".tmp-u$(id -u)-*\" -print -quit",
        ] {
            assert!(
                harness.contains(required),
                "helper harness missing {required:?}"
            );
        }
        for forbidden in ["os.setsid()", "os.setpgid("] {
            assert!(
                !harness.contains(forbidden),
                "helper harness cannot exercise seccomp-blocked syscall {forbidden:?}"
            );
        }
        assert!(
            !harness.contains("grep -q \"network bypass attempt\""),
            "bypass proof must match one structured audit record"
        );
        for forbidden in ["kernel.dmesg_restrict=0", "chmod o+r /dev/kmsg"] {
            assert!(
                !harness.contains(forbidden),
                "helper harness must not relax host-wide kmsg access with {forbidden:?}"
            );
        }
        assert!(
            harness.matches("AXIS_REQUIRE_NETNS_HELPER_E2E").count() >= 3,
            "helper capability and preflight skips are not strict"
        );
        let snapshot = harness
            .split_once("snapshot_helper_states() {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(snapshot.contains("! -name .lock"));
        assert!(
            !snapshot.contains(".tmp-"),
            "helper lifecycle snapshots must include temporary state files"
        );
    }

    #[test]
    fn privileged_netns_strict_requirement_cannot_take_opt_in_skip() {
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = std::process::Command::new("bash")
            .arg(repository.join("e2e/linux/test_netns_helper_launch.sh"))
            .env("AXIS_REQUIRE_NETNS_HELPER_E2E", "1")
            .env_remove("AXIS_RUN_PRIVILEGED_E2E")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "ERROR: AXIS_REQUIRE_NETNS_HELPER_E2E=1 requires AXIS_RUN_PRIVILEGED_E2E=1\n"
        );
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn privileged_harness_rootless_self_test_exercises_collision_and_kmsg_gates() {
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = std::process::Command::new("bash")
            .arg(repository.join("e2e/linux/test_netns_helper_launch.sh"))
            .arg("--self-test")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "rootless harness self-test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("rootless preflight, kmsg capability, and audit matcher self-tests")
        );
    }

    #[test]
    fn privileged_executor_path_predicate_detects_files_and_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let regular = root.path().join("lxc-exec");
        let dangling = root.path().join("dangling-lxc-exec");
        let absent = root.path().join("absent-lxc-exec");
        std::fs::write(&regular, b"executor").unwrap();
        symlink(root.path().join("missing-target"), &dangling).unwrap();

        let occupied = |path: &std::path::Path| {
            std::process::Command::new("bash")
                .args(["-c", "[ -e \"$1\" ] || [ -L \"$1\" ]", "path-guard"])
                .arg(path)
                .status()
                .unwrap()
                .success()
        };
        assert!(occupied(&regular));
        assert!(occupied(&dangling));
        assert!(!occupied(&absent));
    }

    #[test]
    fn payload_boundary_termination_treats_pid_reuse_as_already_dead() {
        let child = spawn_paused_test_process();
        let mut identity = read_process_identity(child).unwrap();
        identity.start_time = identity.start_time.saturating_add(1);

        terminate_payload_boundary(identity).unwrap();
        assert_eq!(unsafe { libc::kill(child, 0) }, 0);

        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
        assert_eq!(wait_for_helper_child(child), 128 + libc::SIGKILL);
    }

    #[test]
    fn owner_guard_fd_is_not_inherited_across_exec() {
        let owner = spawn_paused_test_process();
        let owner_pidfd = open_test_pidfd(owner);
        let script = format!("test ! -e /proc/self/fd/{owner_pidfd}");

        let result = run_cmd_cleared_env_with_timeout(
            "/bin/sh",
            &["-c".into(), script],
            Some(owner_pidfd),
            Duration::from_secs(1),
        );

        assert!(result.is_ok(), "owner guard leaked across exec: {result:?}");
        assert_eq!(unsafe { libc::kill(owner, libc::SIGKILL) }, 0);
        assert_eq!(wait_for_helper_child(owner), 128 + libc::SIGKILL);
        close_fds(&[owner_pidfd]);
    }

    #[test]
    fn privileged_command_hides_production_helper_fds_without_closing_parent_copies() {
        let mut modeled_fds = Vec::new();
        let mut paired_fds = Vec::new();
        for _ in 0..5 {
            let (read_fd, write_fd) = test_pipe();
            clear_test_cloexec(read_fd);
            clear_test_cloexec(write_fd);
            modeled_fds.push(read_fd);
            paired_fds.push(write_fd);
        }
        let leaked_targets: Vec<(RawFd, String)> = modeled_fds
            .iter()
            .map(|fd| {
                (
                    *fd,
                    std::fs::read_link(format!("/proc/self/fd/{fd}"))
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect();
        let checks = leaked_targets
            .iter()
            .map(|(fd, target)| {
                format!(
                    "[ \"$(readlink /proc/self/fd/{fd} 2>/dev/null)\" != '{target}' ] || exit 42"
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let helper_guard_fd = open_self_pidfd().unwrap();
        let init = unsafe { libc::fork() };
        assert!(
            init >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if init == 0 {
            run_command_namespace_init_with(
                "/bin/sh",
                &["-c".into(), checks],
                helper_guard_fd,
                false,
                false,
            );
        }

        close_fds(&[helper_guard_fd]);
        assert_eq!(wait_for_helper_child(init), 0);
        for fd in modeled_fds.iter().chain(&paired_fds) {
            assert!(unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
        }
        close_fds(&modeled_fds);
        close_fds(&paired_fds);
    }

    #[test]
    fn helper_launch_spec_validation_rejects_unsafe_or_unsupported_specs() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let owner = helper_owner();
        let mut spec = helper_launch_spec();

        validate_launch_spec(sandbox_id, 3128, owner, &spec).unwrap();

        spec.command.clear();
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("command")
        );

        spec = helper_launch_spec();
        spec.destroy_token = "bad".into();
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("destroy token")
        );

        spec = helper_launch_spec();
        spec.process.run_as_user = Some("sandbox-user".into());
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("run_as_user")
        );

        spec = helper_launch_spec();
        spec.filesystem.read_write = vec!["{tmpdir}".into()];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("{tmpdir}")
        );

        spec = helper_launch_spec();
        spec.mxc_config_fd = Some(42);
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &spec)
                .unwrap_err()
                .contains("direct helper launch")
        );
    }

    #[test]
    fn mxc_helper_launch_spec_validation_requires_safe_executor_and_private_config() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let owner = helper_owner();
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let executor = root.path().join("lxc-exec");
        std::fs::write(&executor, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config_fd = create_mxc_config_fd(b"{}").unwrap();
        let mut spec = helper_launch_spec();
        spec.launch_kind = HelperLaunchKind::MxcExecutor;
        spec.mxc_config_fd = Some(config_fd);
        spec.command = executor.to_string_lossy().into_owned();
        spec.args = vec![
            "--experimental".into(),
            "--config".into(),
            format!("/proc/self/fd/{config_fd}"),
        ];
        spec.env = vec![("PATH".into(), "/usr/bin:/bin".into())];

        let owner_executable_error = validate_launch_spec(sandbox_id, 3128, owner, &spec)
            .expect_err("owner-controlled MXC executor must be rejected");
        assert!(
            owner_executable_error.contains("owned by root")
                || owner_executable_error.contains("group- or world-writable"),
            "unexpected owner executable error: {owner_executable_error}"
        );

        let root_non_mxc_executor = std::path::Path::new("/usr/bin/true");
        if safe_root_executable(root_non_mxc_executor) {
            spec.command = root_non_mxc_executor.to_string_lossy().into_owned();
            assert!(
                validate_launch_spec(sandbox_id, 3128, owner, &spec)
                    .unwrap_err()
                    .contains("trusted lxc-exec")
            );
        }

        let root_executor = MXC_HELPER_EXECUTOR_DIRS
            .iter()
            .map(|dir| std::path::Path::new(dir).join(MXC_EXECUTOR_NAME))
            .find(|path| safe_root_executable(path));
        let Some(root_executor) = root_executor else {
            eprintln!("root-owned lxc-exec unavailable (test remainder skipped)");
            unsafe {
                libc::close(config_fd);
            }
            return;
        };
        spec.command = root_executor.to_string_lossy().into_owned();
        validate_launch_spec(sandbox_id, 3128, owner, &spec).unwrap();

        let mut bad_args = spec.clone();
        bad_args.args = vec![format!("/proc/self/fd/{config_fd}")];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_args)
                .unwrap_err()
                .contains("--experimental --config")
        );

        let mut bad_config_path = spec.clone();
        bad_config_path.args[2] = format!("/proc/self/fd/{}", config_fd + 1);
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_config_path)
                .unwrap_err()
                .contains("config path")
        );

        let mut missing_config_fd = spec.clone();
        missing_config_fd.mxc_config_fd = None;
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &missing_config_fd)
                .unwrap_err()
                .contains("sealed config fd")
        );

        let (unsealed_read_fd, unsealed_write_fd) = test_pipe();
        let mut unsealed_config = spec.clone();
        unsealed_config.mxc_config_fd = Some(unsealed_read_fd);
        unsealed_config.args[2] = format!("/proc/self/fd/{unsealed_read_fd}");
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &unsealed_config)
                .unwrap_err()
                .contains("must support seals")
        );
        unsafe {
            libc::close(unsealed_read_fd);
            libc::close(unsealed_write_fd);
        }

        let mut bad_env = spec.clone();
        bad_env.env = vec![("HTTPS_PROXY".into(), "http://proxy-with-creds".into())];
        assert!(
            validate_launch_spec(sandbox_id, 3128, owner, &bad_env)
                .unwrap_err()
                .contains("forbidden key")
        );

        unsafe {
            libc::close(config_fd);
        }
    }

    #[test]
    fn mxc_helper_executor_path_allowlist_requires_lxc_exec_in_stable_dirs() {
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/local/bin/lxc-exec"
        )));
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/bin/lxc-exec"
        )));
        assert!(mxc_executor_helper_path_allowed(std::path::Path::new(
            "/bin/lxc-exec"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "/usr/bin/true"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "/opt/axis/bin/lxc-exec"
        )));
        assert!(!mxc_executor_helper_path_allowed(std::path::Path::new(
            "lxc-exec"
        )));
    }

    #[test]
    fn helper_launch_spec_fd_requires_memfd_seals() {
        let (read_fd, write_fd) = test_pipe();

        assert!(
            validate_sealed_launch_spec_fd(read_fd)
                .unwrap_err()
                .contains("seals")
        );

        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }

    #[test]
    fn cgroup_fd_validation_rejects_non_cgroup_paths() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();

        assert!(
            validate_cgroup_procs_fd(file.as_file().as_raw_fd(), sandbox_id)
                .unwrap_err()
                .contains("cgroup v2")
        );
    }

    #[test]
    fn gated_cgroup_fd_validation_accepts_axis_cgroup_procs_fd() {
        if std::env::var("AXIS_REAL_CGROUP_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_CGROUP_TESTS=1 not set (test skipped)");
            return;
        }

        let sandbox_id = SandboxId::new();
        let policy = ProcessPolicy {
            cpu_rate_percent: 0,
            ..ProcessPolicy::default()
        };
        let handle = super::super::resources::create_cgroup(sandbox_id, &policy)
            .expect("AXIS_REAL_CGROUP_TESTS=1 requires writable cgroup v2");
        let fd = handle.open_procs_fd().unwrap();

        let validation = validate_cgroup_procs_fd(fd, sandbox_id);
        unsafe {
            libc::close(fd);
        }
        let cleanup = handle.cleanup();

        assert!(
            validation.is_ok(),
            "cgroup fd validation failed: {validation:?}"
        );
        assert!(cleanup.is_ok(), "cgroup cleanup failed: {cleanup:?}");
    }

    #[test]
    fn helper_launch_authorization_allows_only_setuid_root_for_non_root_callers() {
        validate_helper_launch_authorization(1000, 0).unwrap();

        assert!(
            validate_helper_launch_authorization(1000, 1000)
                .unwrap_err()
                .contains("effective UID 0")
        );
        assert!(
            validate_helper_launch_authorization(0, 0)
                .unwrap_err()
                .contains("non-root real UID")
        );
    }

    #[test]
    fn helper_no_new_privs_setup_sets_sticky_exec_boundary_in_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let ok = set_no_new_privs().is_ok()
                && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
            unsafe {
                libc::_exit(if ok { 0 } else { 1 });
            }
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child did not set no_new_privs: status={status}"
        );
    }

    #[test]
    fn helper_state_round_trips_optional_payload_boundary() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path();
        let state = HelperState {
            owner_uid: 1000,
            destroy_token: valid_test_token(),
            created_resources: CreatedNetnsResources::complete(),
            payload_boundary: None,
            cleanup_completed: false,
        };

        write_helper_state_file(path, &state).unwrap();
        assert_eq!(read_helper_state_file(path).unwrap(), state);

        let state = HelperState {
            payload_boundary: Some(HelperProcessIdentity {
                pid: 4242,
                start_time: 99,
            }),
            ..state
        };
        write_helper_state_file(path, &state).unwrap();
        assert_eq!(read_helper_state_file(path).unwrap(), state);

        let completed = HelperState {
            created_resources: CreatedNetnsResources::default(),
            payload_boundary: None,
            cleanup_completed: true,
            ..state
        };
        write_helper_state_file(path, &completed).unwrap();
        let completed = read_helper_state_file(path).unwrap();
        assert_eq!(
            validate_helper_state_authentication(completed.clone(), 1000, &valid_test_token()),
            Ok(completed.clone())
        );
        assert!(
            validate_helper_state_authentication(completed.clone(), 2000, &valid_test_token())
                .unwrap_err()
                .contains("owner")
        );
        assert!(
            validate_helper_state_authentication(completed, 1000, &"b".repeat(64))
                .unwrap_err()
                .contains("token")
        );
        assert_eq!(
            helper_command_exit_code(HelperCommandOutcome::Cleanup(
                HelperCleanupOutcome::AlreadyCompleted
            )),
            HELPER_EXIT_ALREADY_COMPLETED
        );
    }

    #[test]
    fn atomic_helper_state_update_preserves_previous_version_until_install() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        let initial = HelperState {
            owner_uid: 1000,
            destroy_token: valid_test_token(),
            created_resources: CreatedNetnsResources::complete(),
            payload_boundary: None,
            cleanup_completed: false,
        };
        write_helper_state_file_atomic(&path, &initial, AtomicStateWriteMode::Create).unwrap();
        let updated = HelperState {
            payload_boundary: Some(HelperProcessIdentity {
                pid: 4242,
                start_time: 99,
            }),
            ..initial.clone()
        };

        let error = write_helper_state_file_atomic_with(
            &path,
            &updated,
            AtomicStateWriteMode::Replace,
            |temp_path| {
                assert!(
                    temp_path
                        .file_name()
                        .unwrap()
                        .as_encoded_bytes()
                        .starts_with(b".tmp-u1000-")
                );
                assert_eq!(read_helper_state_file(&path).unwrap(), initial);
                assert_eq!(read_helper_state_file(temp_path).unwrap(), updated);
                Err("injected helper kill before atomic install".into())
            },
        )
        .unwrap_err();

        assert!(error.contains("injected helper kill"));
        assert_eq!(read_helper_state_file(&path).unwrap(), initial);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn stale_temp_entries_are_cleaned_and_never_poison_user_quotas() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let own = directory.path().join("own");
        let other = directory.path().join("other");
        write_helper_state_file_atomic(
            &own,
            &HelperState {
                owner_uid: 1000,
                destroy_token: valid_test_token(),
                created_resources: CreatedNetnsResources::complete(),
                payload_boundary: None,
                cleanup_completed: false,
            },
            AtomicStateWriteMode::Create,
        )
        .unwrap();
        write_helper_state_file_atomic(
            &other,
            &HelperState {
                owner_uid: 2000,
                destroy_token: valid_test_token(),
                created_resources: CreatedNetnsResources::complete(),
                payload_boundary: None,
                cleanup_completed: false,
            },
            AtomicStateWriteMode::Create,
        )
        .unwrap();
        let attributed_temp = directory.path().join(".tmp-u1000-deadbeef");
        let legacy_temp = directory.path().join(".tmp-crash");
        let unsafe_temp = directory.path().join(".tmp-u1000-symlink");
        std::fs::write(&attributed_temp, b"").unwrap();
        std::fs::write(&legacy_temp, b"").unwrap();
        symlink(&own, &unsafe_temp).unwrap();
        std::fs::set_permissions(&attributed_temp, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&legacy_temp, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(directory.path().join("malformed"), b"1000\nnot-a-token\n").unwrap();
        std::fs::write(directory.path().join(".lock"), b"ignored").unwrap();

        assert_eq!(
            count_active_namespace_entries(directory.path(), 1000).unwrap(),
            1
        );
        assert_eq!(
            count_active_namespace_entries(directory.path(), 2000).unwrap(),
            1
        );
        assert_eq!(
            count_active_namespace_entries(directory.path(), 3000).unwrap(),
            0
        );
        assert_eq!(
            cleanup_stale_helper_state_temps_locked(directory.path()).unwrap(),
            2
        );
        assert!(!attributed_temp.exists());
        assert!(!legacy_temp.exists());
        assert!(
            unsafe_temp
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            count_active_namespace_entries(directory.path(), 1000).unwrap(),
            1
        );
    }

    #[test]
    fn zero_file_size_limit_cannot_repeatedly_poison_atomic_state() {
        assert_eq!(
            normalized_helper_control_plane_rlimit(
                libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                },
                HELPER_CONTROL_PLANE_MIN_FSIZE,
            ),
            libc::rlimit {
                rlim_cur: HELPER_CONTROL_PLANE_MIN_FSIZE,
                rlim_max: HELPER_CONTROL_PLANE_MIN_FSIZE,
            }
        );
        let directory = tempfile::tempdir().unwrap();
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let mut original = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
            if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, original.as_mut_ptr()) } < 0 {
                unsafe { libc::_exit(120) };
            }
            let original = unsafe { original.assume_init() };
            let poisoned = libc::rlimit {
                rlim_cur: 0,
                rlim_max: original.rlim_max,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &poisoned) } < 0 {
                unsafe { libc::_exit(121) };
            }
            if raise_helper_control_plane_rlimit(
                libc::RLIMIT_FSIZE,
                HELPER_CONTROL_PLANE_MIN_FSIZE,
                "file size",
            )
            .is_err()
            {
                unsafe { libc::_exit(122) };
            }
            for index in 0..(MAX_ACTIVE_HELPER_NETNS_PER_UID + 8) {
                let path = directory.path().join(format!("state-{index}"));
                let state = HelperState {
                    owner_uid: unsafe { libc::getuid() },
                    destroy_token: valid_test_token(),
                    created_resources: CreatedNetnsResources::default(),
                    payload_boundary: None,
                    cleanup_completed: false,
                };
                if write_helper_state_file_atomic(&path, &state, AtomicStateWriteMode::Create)
                    .and_then(|_| remove_helper_state_file(&path))
                    .is_err()
                {
                    unsafe { libc::_exit(123) };
                }
            }
            unsafe { libc::_exit(0) };
        }

        assert_eq!(wait_for_helper_child(child), 0);
        let entries = std::fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(entries, 0, "RLIMIT_FSIZE left quota-poisoning state");
    }

    #[test]
    fn crash_window_without_persisted_namespace_ownership_stays_quota_charged() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("incomplete");
        let state = HelperState {
            owner_uid: 1000,
            destroy_token: valid_test_token(),
            created_resources: CreatedNetnsResources::default(),
            payload_boundary: None,
            cleanup_completed: false,
        };
        write_helper_state_file_atomic(&path, &state, AtomicStateWriteMode::Create).unwrap();

        let error = ensure_helper_state_proves_namespace_ownership(&state).unwrap_err();

        assert!(error.contains("preserving state and quota"), "{error}");
        assert_eq!(
            count_active_namespace_entries(directory.path(), 1000),
            Ok(1)
        );
        assert!(path.exists());
    }

    #[test]
    fn normal_helper_completion_publishes_authenticated_structured_outcome() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                payload_boundary: HelperProcessIdentity {
                    pid: 4242,
                    start_time: 99,
                },
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_payload_boundary: false,
                fail_finalize_state: false,
            },
            || true,
        )
        .unwrap();

        assert_eq!(
            events.into_inner(),
            vec![
                "payload 4242:99".to_string(),
                format!("destroy {}", allocation.namespace),
                format!("complete {sandbox_id}"),
            ]
        );
    }

    #[test]
    fn helper_completion_after_owner_death_removes_state_instead_of_publishing_completion() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                payload_boundary: HelperProcessIdentity {
                    pid: 4242,
                    start_time: 99,
                },
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_payload_boundary: false,
                fail_finalize_state: false,
            },
            || false,
        )
        .unwrap();

        assert_eq!(
            events.into_inner(),
            vec![
                "payload 4242:99".to_string(),
                format!("destroy {}", allocation.namespace),
                format!("remove {sandbox_id}"),
            ]
        );
    }

    #[test]
    fn helper_target_exit_cleanup_stops_before_destroy_when_boundary_survives() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        let err = cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                payload_boundary: HelperProcessIdentity {
                    pid: 4242,
                    start_time: 99,
                },
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_payload_boundary: true,
                fail_finalize_state: false,
            },
            || true,
        )
        .unwrap_err();

        assert!(err.contains("payload boundary still has members"));
        assert_eq!(events.into_inner(), vec!["payload 4242:99".to_string()]);
    }

    #[test]
    fn helper_target_exit_cleanup_reports_state_removal_failure() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let events = RefCell::new(Vec::new());

        let error = cleanup_helper_allocation_after_target_exit_with(
            HelperCleanupContext {
                sandbox_id,
                payload_boundary: HelperProcessIdentity {
                    pid: 4242,
                    start_time: 99,
                },
                allocation: &allocation,
                paths: &paths,
                runner: &mut runner,
            },
            RecordingCleanupHooks {
                events: &events,
                fail_payload_boundary: false,
                fail_finalize_state: true,
            },
            || true,
        )
        .unwrap_err();

        assert!(error.contains("forced helper state removal failure"));
        assert_eq!(
            events.into_inner(),
            vec![
                "payload 4242:99".to_string(),
                format!("destroy {}", allocation.namespace),
                format!("complete {sandbox_id}"),
            ]
        );
    }

    struct RecordingCleanupHooks<'a> {
        events: &'a RefCell<Vec<String>>,
        fail_payload_boundary: bool,
        fail_finalize_state: bool,
    }

    impl HelperCleanupHooks for RecordingCleanupHooks<'_> {
        fn terminate_payload_boundary(
            &mut self,
            identity: HelperProcessIdentity,
        ) -> Result<(), String> {
            self.events
                .borrow_mut()
                .push(format!("payload {}:{}", identity.pid, identity.start_time));
            if self.fail_payload_boundary {
                Err("payload boundary still has members".into())
            } else {
                Ok(())
            }
        }

        fn destroy_resources(
            &mut self,
            allocation: &ProxyNetnsAllocation,
            _paths: &NetnsCommandPaths,
            _runner: &mut dyn CommandRunner,
        ) -> Result<(), String> {
            self.events
                .borrow_mut()
                .push(format!("destroy {}", allocation.namespace));
            Ok(())
        }

        fn finalize_state(
            &mut self,
            sandbox_id: SandboxId,
            owner_alive: bool,
        ) -> Result<(), String> {
            self.events.borrow_mut().push(format!(
                "{} {sandbox_id}",
                if owner_alive { "complete" } else { "remove" }
            ));
            if self.fail_finalize_state {
                Err("forced helper state removal failure".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn process_stat_parser_handles_command_names_with_spaces() {
        let mut fields = vec!["0"; 20];
        fields[19] = "987654";
        let stat = format!("123 (cmd with spaces) {}", fields.join(" "));
        assert_eq!(parse_process_stat_start_time(&stat), Some(987654));
        assert_eq!(parse_process_stat_start_time("malformed"), None);
    }

    #[test]
    fn helper_sync_reader_accepts_ok_and_reports_errors() {
        let (read_fd, write_fd) = test_pipe();
        super::super::write_all_fd(write_fd, HELPER_SYNC_OK.as_bytes()).unwrap();
        unsafe {
            libc::close(write_fd);
        }
        read_helper_sync(read_fd).unwrap();

        let (read_fd, write_fd) = test_pipe();
        super::super::write_all_fd(write_fd, b"ERR setup failed\n").unwrap();
        unsafe {
            libc::close(write_fd);
        }
        assert_eq!(read_helper_sync(read_fd).unwrap_err(), "setup failed");

        let (read_fd, write_fd) = test_pipe();
        unsafe {
            libc::close(write_fd);
        }
        assert!(
            read_helper_sync(read_fd)
                .unwrap_err()
                .contains("before reporting")
        );
    }

    #[test]
    fn helper_sync_reader_times_out_when_writer_stalls() {
        let (read_fd, write_fd) = test_pipe();
        let started = Instant::now();

        let error = read_helper_sync_with_timeout(read_fd, Duration::from_millis(40)).unwrap_err();

        close_fds(&[write_fd]);
        assert!(error.contains("deadline"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn helper_create_uses_fixed_paths_for_programs_and_nested_execs() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();

        create_with_runner_and_paths(&allocation, &paths, &mut runner).unwrap();

        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(!rendered.is_empty());
        assert!(
            runner
                .commands
                .iter()
                .all(|command| command.program == "/usr/sbin/ip")
        );
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/ip addr add"
        )));
        assert!(rendered
            .iter()
            .any(|cmd| cmd.contains("netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1")));
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/iptables -A OUTPUT -d"
        )));
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/iptables -A OUTPUT -j LOG"
        )));
        assert!(rendered.iter().any(|cmd| cmd.contains(
            "netns exec axis-00000000-0000-4000-8000-000000000001 /usr/sbin/iptables -A OUTPUT -j REJECT"
        )));
    }

    #[test]
    fn helper_create_does_not_delete_colliding_veth_with_fixed_paths() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let paths = fixed_test_paths();
        let mut runner = FakeRunner {
            fail_at: Some(2),
            ..Default::default()
        };

        let err = create_with_runner_and_paths(&allocation, &paths, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert!(rendered.iter().any(|cmd| {
            cmd == "/usr/sbin/ip netns del axis-00000000-0000-4000-8000-000000000001"
        }));
        assert!(
            !rendered
                .iter()
                .any(|cmd| { cmd == "/usr/sbin/ip link del axh000000000000" })
        );
    }

    #[test]
    fn removed_legacy_helper_create_is_rejected_without_commands() {
        let paths = fixed_test_paths();
        let mut runner = FakeRunner::default();
        let err = run_helper_with_runner(
            &strings(["create", "00000000-0000-4000-8000-000000000001", "3128"]),
            &paths,
            &mut runner,
        )
        .unwrap_err();

        assert!(err.contains("usage: axis-netns-helper"));
        assert!(runner.commands.is_empty());
    }

    #[test]
    fn safe_root_executable_rejects_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("ip");
        std::fs::write(&candidate, b"#!/bin/sh\n").unwrap();
        let mut permissions = std::fs::metadata(&candidate).unwrap().permissions();
        permissions.set_mode(0o777);
        std::fs::set_permissions(&candidate, permissions).unwrap();

        assert!(!safe_root_executable(&candidate));
    }

    #[test]
    fn safe_root_executable_or_trusted_symlink_rejects_user_owned_symlink_chain() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("iptables");
        symlink("/bin/sh", &candidate).unwrap();

        assert!(!safe_root_executable_or_trusted_symlink(&candidate));
    }

    #[test]
    fn safe_root_executable_or_trusted_symlink_accepts_distro_symlink_when_present() {
        for candidate in [
            "/usr/sbin/ip",
            "/sbin/ip",
            "/usr/sbin/iptables",
            "/sbin/iptables",
        ] {
            let path = std::path::Path::new(candidate);
            let Ok(metadata) = std::fs::symlink_metadata(path) else {
                continue;
            };
            if !metadata.file_type().is_symlink() {
                continue;
            }
            let Ok(resolved) = std::fs::canonicalize(path) else {
                continue;
            };
            if safe_root_executable(&resolved) {
                assert!(safe_root_executable_or_trusted_symlink(path));
                return;
            }
        }

        eprintln!("no trusted distro symlinked network command found (test skipped)");
    }

    #[test]
    fn safe_root_owner_and_mode_accepts_only_root_owned_non_writable_paths() {
        assert!(safe_root_owner_and_mode(0, 0o755));
        assert!(safe_root_owner_and_mode(0, 0o500));
        assert!(!safe_root_owner_and_mode(1000, 0o755));
        assert!(!safe_root_owner_and_mode(0, 0o775));
        assert!(!safe_root_owner_and_mode(0, 0o777));
    }

    #[test]
    fn safe_root_metadata_checks_path_kind_and_symlink_state() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("ip");
        let non_executable = dir.path().join("iptables");
        let link = dir.path().join("sysctl");
        std::fs::write(&executable, b"#!/bin/sh\n").unwrap();
        std::fs::write(&non_executable, b"#!/bin/sh\n").unwrap();
        symlink(&executable, &link).unwrap();

        let mut executable_permissions = std::fs::metadata(&executable).unwrap().permissions();
        executable_permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, executable_permissions).unwrap();

        let mut non_executable_permissions =
            std::fs::metadata(&non_executable).unwrap().permissions();
        non_executable_permissions.set_mode(0o644);
        std::fs::set_permissions(&non_executable, non_executable_permissions).unwrap();

        let executable_metadata = std::fs::symlink_metadata(&executable).unwrap();
        let non_executable_metadata = std::fs::symlink_metadata(&non_executable).unwrap();
        let directory_metadata = std::fs::symlink_metadata(dir.path()).unwrap();
        let link_metadata = std::fs::symlink_metadata(&link).unwrap();

        assert!(!safe_root_metadata(
            &directory_metadata,
            SafePathKind::ExecutableFile
        ));
        assert!(!safe_root_metadata(
            &executable_metadata,
            SafePathKind::AncestorDirectory
        ));
        assert!(!safe_root_metadata(
            &non_executable_metadata,
            SafePathKind::ExecutableFile
        ));
        assert!(!safe_root_metadata(
            &link_metadata,
            SafePathKind::ExecutableFile
        ));
    }

    #[test]
    fn create_plan_allows_only_proxy_output_and_has_no_nat_or_forwarding() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);

        let commands = create_command_plan(&allocation);
        let rendered: Vec<String> = commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(rendered.iter().any(|cmd| cmd.contains("ip netns add")));
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains(&allocation.host_cidr))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains(&allocation.sandbox_cidr))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("net.ipv6.conf.all.disable_ipv6=1"))
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("net.ipv6.conf.default.disable_ipv6=1"))
        );
        assert!(rendered.iter().any(|cmd| {
            cmd.contains(&format!(
                "iptables -A OUTPUT -d {} -p tcp --dport 3128 -j ACCEPT",
                allocation.host_addr
            ))
        }));
        let bypass_prefix = crate::linux::bypass_audit::bypass_log_prefix(sandbox_id);
        assert!(rendered.iter().any(|cmd| {
            cmd.contains(&format!(
                "iptables -A OUTPUT -j LOG --log-prefix {bypass_prefix}"
            ))
        }));
        assert!(
            bypass_prefix.len() <= crate::linux::bypass_audit::IPTABLES_LOG_PREFIX_LIMIT,
            "iptables log prefix exceeded kernel limit"
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| cmd.contains("iptables -A OUTPUT -j REJECT"))
        );
        let disable_ipv6_all = rendered
            .iter()
            .position(|cmd| cmd.contains("net.ipv6.conf.all.disable_ipv6=1"))
            .unwrap();
        let disable_ipv6_default = rendered
            .iter()
            .position(|cmd| cmd.contains("net.ipv6.conf.default.disable_ipv6=1"))
            .unwrap();
        let default_route = rendered
            .iter()
            .position(|cmd| cmd.contains("ip route add default"))
            .unwrap();
        let proxy_accept = rendered
            .iter()
            .position(|cmd| cmd.contains("iptables -A OUTPUT -d"))
            .unwrap();
        let bypass_log = rendered
            .iter()
            .position(|cmd| cmd.contains("iptables -A OUTPUT -j LOG"))
            .unwrap();
        let final_reject = rendered
            .iter()
            .position(|cmd| cmd.contains("iptables -A OUTPUT -j REJECT"))
            .unwrap();
        assert!(disable_ipv6_all < default_route);
        assert!(disable_ipv6_default < default_route);
        assert!(default_route < proxy_accept);
        assert!(proxy_accept < bypass_log);
        assert!(bypass_log < final_reject);
        assert!(!rendered.iter().any(|cmd| cmd.contains("MASQUERADE")));
        assert!(!rendered.iter().any(|cmd| cmd.contains("ip_forward")));
    }

    #[test]
    fn create_with_runner_cleans_up_namespace_and_veth_after_failure() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let mut runner = FakeRunner {
            fail_at: Some(3),
            ..Default::default()
        };

        let err = create_with_runner(&allocation, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip netns del {}", allocation.namespace) })
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip link del {}", allocation.veth_host) })
        );
    }

    #[test]
    fn ownership_tracked_create_collision_performs_no_name_based_rollback() {
        let sandbox_id = SandboxId::from_str("10000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let mut runner = FakeRunner {
            fail_at: Some(1),
            failure_message: Some("namespace already exists".into()),
            ..Default::default()
        };

        let error = create_with_runner(&allocation, &mut runner).unwrap_err();

        assert!(error.contains("already exists"));
        assert_eq!(
            runner.commands,
            vec![create_command_plan(&allocation)[0].clone()]
        );
    }

    #[test]
    fn colliding_veth_failure_rolls_back_only_new_namespace() {
        let victim_id = SandboxId::from_str("12345678-90ab-4000-8000-000000000001").unwrap();
        let attacker_id = SandboxId::from_str("12345678-90ab-4fff-8000-000000000002").unwrap();
        let victim = proxy_netns_allocation(victim_id, 3128);
        let attacker = proxy_netns_allocation(attacker_id, 3128);
        assert_eq!(victim.veth_host, attacker.veth_host);
        assert_ne!(victim.namespace, attacker.namespace);
        let mut runner = FakeRunner {
            fail_at: Some(2),
            failure_message: Some("veth already exists".into()),
            ..Default::default()
        };

        let error = create_with_runner(&attacker, &mut runner).unwrap_err();
        let rendered = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect::<Vec<_>>();

        assert!(error.contains("already exists"));
        assert_eq!(rendered.len(), 3);
        assert_eq!(rendered[2], format!("ip netns del {}", attacker.namespace));
        assert!(
            !rendered
                .iter()
                .any(|command| command == &format!("ip link del {}", victim.veth_host))
        );
    }

    #[test]
    fn host_address_collision_fails_closed_and_cleans_up() {
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 3128);
        let host_addr_command_index = create_command_plan(&allocation)
            .iter()
            .position(|command| {
                command.program == "ip"
                    && command.args
                        == vec![
                            "addr".to_string(),
                            "add".to_string(),
                            allocation.host_cidr.clone(),
                            "dev".to_string(),
                            allocation.veth_host.clone(),
                        ]
            })
            .unwrap()
            + 1;
        let mut runner = FakeRunner {
            fail_at: Some(host_addr_command_index),
            ..Default::default()
        };

        let err = create_with_runner(&allocation, &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains(&allocation.host_cidr));
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip netns del {}", allocation.namespace) })
        );
        assert!(
            rendered
                .iter()
                .any(|cmd| { cmd == &format!("ip link del {}", allocation.veth_host) })
        );
    }

    #[test]
    fn destroy_with_runner_reports_cleanup_failures_after_best_effort_cleanup() {
        let mut runner = FakeRunner {
            fail_at: Some(1),
            ..Default::default()
        };

        let err = destroy_with_runner("axis-1234567890abcdef", &mut runner).unwrap_err();
        let rendered: Vec<String> = runner
            .commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect();

        assert!(err.contains("forced failure"));
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0], "ip netns del axis-1234567890abcdef");
        assert_eq!(rendered[1], "ip link del axh1234567890ab");
    }

    #[test]
    fn destroy_with_runner_ignores_host_veth_already_removed_by_namespace_delete() {
        let mut runner = FakeRunner {
            fail_at: Some(2),
            failure_message: Some("Cannot find device \"axh1234567890ab\"".into()),
            ..Default::default()
        };

        destroy_with_runner("axis-1234567890abcdef", &mut runner).unwrap();

        assert_eq!(runner.commands.len(), 2);
    }

    #[test]
    fn gated_real_ip_netns_create_and_destroy_cleans_namespace() {
        if std::env::var("AXIS_REAL_NETNS_TESTS").as_deref() != Ok("1") {
            eprintln!("AXIS_REAL_NETNS_TESTS=1 not set (test skipped)");
            return;
        }

        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-00000000bb05").unwrap();
        let allocation = proxy_netns_allocation(sandbox_id, 43_128);
        let namespace = allocation.namespace.clone();

        let create_result = create_netns(sandbox_id, 43_128);
        if create_result.is_err() {
            let _ = destroy_netns(&namespace);
        }
        create_result.unwrap();

        let verify_result = verify_real_netns_setup(&allocation);
        let cleanup_result = destroy_netns(&namespace);

        assert!(
            cleanup_result.is_ok(),
            "real netns cleanup failed: {cleanup_result:?}"
        );
        assert!(
            !real_netns_exists(&namespace),
            "namespace {namespace} remained after cleanup"
        );
        assert!(
            verify_result.is_ok(),
            "real netns verification failed: {verify_result:?}"
        );
    }

    #[test]
    fn destroy_derives_sandbox_name_from_axis_namespace() {
        let sandbox_name = sandbox_name_from_netns("axis-1234567890");

        assert_eq!(sandbox_name, "1234567890");
        assert_eq!(veth_host_name(sandbox_name), "axh1234567890");
    }

    fn verify_real_netns_setup(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        if !which("python3") {
            return Err("AXIS_REAL_NETNS_TESTS=1 requires python3 on PATH".into());
        }
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "ip",
                "addr",
                "show",
                "dev",
                &allocation.veth_sandbox,
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "ip",
                "route",
                "show",
                "default",
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &allocation.namespace,
                "iptables",
                "-S",
                "OUTPUT",
            ],
        )?;
        verify_real_proxy_port_reachable(allocation)?;
        verify_real_non_proxy_port_denied(allocation)?;
        verify_real_ipv6_denied(allocation)
    }

    fn real_netns_exists(namespace: &str) -> bool {
        Command::new("ip")
            .args(["netns", "list"])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains(namespace))
            .unwrap_or(false)
    }

    fn verify_real_proxy_port_reachable(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let listener = bind_real_host_listener(allocation, allocation.proxy_addr.port())?;

        let status = run_netns_python(
            &allocation.namespace,
            &format!(
                "import socket; s=socket.create_connection(('{}', {}), 2); s.close()",
                allocation.host_addr,
                allocation.proxy_addr.port()
            ),
        )?;

        if !status.success() {
            return Err(format!(
                "sandbox could not reach proxy port {}",
                allocation.proxy_addr.port()
            ));
        }
        if !listener_observed_connection(&listener)? {
            return Err("host listener did not observe proxy-port connection".into());
        }
        Ok(())
    }

    fn verify_real_non_proxy_port_denied(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let denied_port = allocation
            .proxy_addr
            .port()
            .checked_add(1)
            .ok_or_else(|| "proxy port has no adjacent denied port".to_string())?;
        let listener = bind_real_host_listener(allocation, denied_port)?;

        let status = run_netns_python(
            &allocation.namespace,
            &format!(
                "import socket; s=socket.create_connection(('{}', {}), 1); s.close()",
                allocation.host_addr, denied_port
            ),
        )?;

        if status.success() {
            return Err(format!(
                "sandbox reached denied host-veth port {denied_port}"
            ));
        }
        if listener_observed_connection(&listener)? {
            return Err(format!(
                "host listener observed denied port {denied_port} connection"
            ));
        }
        Ok(())
    }

    fn verify_real_ipv6_denied(allocation: &ProxyNetnsAllocation) -> Result<(), String> {
        let status = run_netns_python(
            &allocation.namespace,
            "import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(1); s.connect(('::1', 1)); s.close()",
        )?;
        if status.success() {
            Err("sandbox completed IPv6 connection attempt despite IPv6 disable".into())
        } else {
            Ok(())
        }
    }

    fn bind_real_host_listener(
        allocation: &ProxyNetnsAllocation,
        port: u16,
    ) -> Result<std::net::TcpListener, String> {
        let listener =
            std::net::TcpListener::bind(SocketAddr::new(allocation.host_addr.into(), port))
                .map_err(|e| format!("host listener bind {port}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("host listener nonblocking: {e}"))?;
        Ok(listener)
    }

    fn run_netns_python(namespace: &str, code: &str) -> Result<std::process::ExitStatus, String> {
        Command::new("ip")
            .args(["netns", "exec", namespace, "python3", "-c", code])
            .status()
            .map_err(|e| format!("failed to run python3 in netns: {e}"))
    }

    fn listener_observed_connection(listener: &std::net::TcpListener) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok((_stream, _addr)) => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(false);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(format!("host listener accept: {e}")),
            }
        }
    }

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }

    fn fixed_test_paths() -> NetnsCommandPaths {
        NetnsCommandPaths {
            ip: "/usr/sbin/ip".into(),
            iptables: "/usr/sbin/iptables".into(),
            sysctl: "/usr/sbin/sysctl".into(),
        }
    }

    fn valid_test_token() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()
    }

    fn helper_launch_spec() -> HelperLaunchSpec {
        HelperLaunchSpec {
            launch_kind: HelperLaunchKind::DirectProcess,
            mxc_config_fd: None,
            workspace_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy {
                cpu_rate_percent: 0,
                ..ProcessPolicy::default()
            },
            rlimits: HelperRlimits::default(),
            command: "true".into(),
            args: Vec::new(),
            env: Vec::new(),
            destroy_token: valid_test_token(),
        }
    }

    fn command_boundary_fixture_path(parent_pid: libc::pid_t) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("axis-command-boundary-{parent_pid}"))
    }

    fn command_boundary_fixture_args() -> Vec<String> {
        vec![
            "--ignored".into(),
            "--exact".into(),
            "linux::netns::tests::command_boundary_fixture".into(),
            "--test-threads=1".into(),
        ]
    }

    fn command_namespace_churn_fixture_args() -> Vec<String> {
        vec![
            "--ignored".into(),
            "--exact".into(),
            "linux::netns::tests::command_namespace_churn_fixture".into(),
            "--test-threads=1".into(),
        ]
    }

    fn test_exit_wait_status(exit_code: i32) -> libc::c_int {
        exit_code << 8
    }

    fn test_signal_wait_status(signal: i32) -> libc::c_int {
        signal
    }

    fn wait_for_fixture_records(path: &std::path::Path, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if std::fs::read_to_string(path).is_ok_and(|contents| contents.lines().count() >= count)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not publish {count} records"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_command_boundary_fixture(path: &std::path::Path) -> Vec<(libc::pid_t, i32, i32)> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| {
                let mut fields = line.split_whitespace();
                let record = (
                    fields.next().unwrap().parse().unwrap(),
                    fields.next().unwrap().parse().unwrap(),
                    fields.next().unwrap().parse().unwrap(),
                );
                assert!(fields.next().is_none(), "unexpected fixture record: {line}");
                record
            })
            .collect()
    }

    fn assert_process_disappears(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let probe = unsafe { libc::kill(pid, 0) };
            if probe < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "process {pid} survived lifecycle cleanup"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn spawn_paused_test_process() -> libc::pid_t {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        pid
    }

    fn run_continuous_churn_reap_scenario(signal: i32) -> NamespaceReapResult {
        let (read_fd, write_fd) = test_pipe();
        let reaper = unsafe { libc::fork() };
        assert!(
            reaper >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if reaper == 0 {
            close_fds(&[read_fd]);
            if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
                unsafe { libc::_exit(125) };
            }
            let primary = unsafe { libc::fork() };
            if primary < 0 {
                unsafe { libc::_exit(124) };
            }
            if primary == 0 {
                loop {
                    let worker = unsafe { libc::fork() };
                    if worker < 0 {
                        unsafe { libc::_exit(123) };
                    }
                    if worker == 0 {
                        let orphan = unsafe { libc::fork() };
                        if orphan < 0 {
                            unsafe { libc::_exit(122) };
                        }
                        unsafe { libc::_exit(0) };
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }

            let terminator = unsafe { libc::fork() };
            if terminator < 0 {
                unsafe { libc::_exit(121) };
            }
            if terminator == 0 {
                std::thread::sleep(Duration::from_millis(75));
                unsafe {
                    libc::kill(primary, signal);
                    libc::_exit(0);
                }
            }

            let result = reap_namespace_children_with(primary, false);
            let record = [
                result.exit_code as u64,
                result.reaped_descendants as u64,
                result.reaped_while_primary_alive as u64,
                u64::from(result.drained),
            ];
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&record),
                )
            };
            let _ = super::super::write_all_fd(write_fd, bytes);
            close_fds(&[write_fd]);
            unsafe { libc::_exit(0) };
        }

        close_fds(&[write_fd]);
        let mut record = [0u64; 4];
        read_exact_test_fd(read_fd, unsafe {
            std::slice::from_raw_parts_mut(
                record.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(&record),
            )
        });
        close_fds(&[read_fd]);
        assert_eq!(wait_for_helper_child(reaper), 0);
        NamespaceReapResult {
            exit_code: record[0] as i32,
            reaped_descendants: record[1] as usize,
            reaped_while_primary_alive: record[2] as usize,
            drained: record[3] != 0,
        }
    }

    fn open_test_pidfd(pid: libc::pid_t) -> RawFd {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
        assert!(
            fd >= 0,
            "pidfd_open({pid}) failed: {}",
            std::io::Error::last_os_error()
        );
        fd
    }

    fn clear_test_cloexec(fd: RawFd) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            flags >= 0,
            "F_GETFD failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
    }

    fn test_pipe() -> (RawFd, RawFd) {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe failed: {}", std::io::Error::last_os_error());
        (fds[0], fds[1])
    }

    fn read_exact_test_fd(fd: RawFd, mut buffer: &mut [u8]) {
        while !buffer.is_empty() {
            let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            assert!(read > 0, "read failed: {}", std::io::Error::last_os_error());
            let (_, remaining) = buffer.split_at_mut(read as usize);
            buffer = remaining;
        }
    }
}
