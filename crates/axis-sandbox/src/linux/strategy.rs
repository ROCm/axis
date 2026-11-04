// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux isolation strategy planning.
//!
//! The planner decides which Linux primitives are required before the child is
//! spawned. Later setup code consumes this plan; the important property here is
//! that fallbacks are explicit and unsupported combinations fail before launch.

use super::resources;
use crate::sandbox::SandboxConfig;
use axis_core::policy::{NetworkMode, Policy, ProcessPolicy};
use axis_core::types::SandboxId;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

const CAP_NET_ADMIN_BIT: u32 = 12;
const SECCOMP_GET_ACTION_AVAIL: libc::c_long = 2;
const MIN_LANDLOCK_CONTRACT_ABI: u32 = 3;

/// Complete Linux isolation plan for a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxIsolationPlan {
    pub sandbox_id: SandboxId,
    pub workspace_dir: PathBuf,
    pub filesystem: FilesystemStrategy,
    pub seccomp: SeccompStrategy,
    pub network: NetworkStrategy,
    pub resources: ResourceStrategy,
    pub identity: IdentityStrategy,
    pub proxy: ProxyStrategy,
    pub fallbacks: Vec<PlanFallback>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilesystemStrategy {
    Landlock { abi: u32 },
    Bubblewrap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeccompStrategy {
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkStrategy {
    Proxy {
        setup: ProxyNetworkSetup,
        firewall: Option<FirewallTool>,
        host_addr: Ipv4Addr,
        sandbox_addr: Ipv4Addr,
        proxy_port: u16,
    },
    BlockedBySeccomp,
    BlockedByBubblewrap,
    AllowHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyNetworkSetup {
    IpNetnsWithCapNetAdmin,
    AxisNetnsHelperLaunch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallTool {
    Iptables,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResourceStrategy {
    CgroupsV2 {
        support: CgroupV2Support,
    },
    RlimitFallback {
        memory_limit: bool,
        process_limit: ProcessLimitFallback,
        cpu_limit: CpuLimitFallback,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessLimitFallback {
    RlimitNprocWithDedicatedUser,
    NotRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuLimitFallback {
    NotRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentityStrategy {
    CurrentUser,
    RunAsUser { username: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyStrategy {
    None,
    Required {
        bind_addr: Ipv4Addr,
        sandbox_addr: Ipv4Addr,
        port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanFallback {
    pub area: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrategyError {
    area: &'static str,
    message: String,
}

impl StrategyError {
    fn new(area: &'static str, message: impl Into<String>) -> Self {
        Self {
            area,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StrategyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.area, self.message)
    }
}

impl std::error::Error for StrategyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapabilitySnapshot {
    pub landlock_abi: Option<u32>,
    pub seccomp: bool,
    pub cgroup_v2: CgroupV2Support,
    pub ip: bool,
    pub iptables: bool,
    pub nft: bool,
    pub cap_net_admin: bool,
    pub netns_helper: bool,
    pub unprivileged_userns: bool,
    pub bubblewrap: bool,
}

impl Default for CapabilitySnapshot {
    fn default() -> Self {
        Self {
            landlock_abi: None,
            seccomp: false,
            cgroup_v2: CgroupV2Support::Unavailable,
            ip: false,
            iptables: false,
            nft: false,
            cap_net_admin: false,
            netns_helper: false,
            unprivileged_userns: false,
            bubblewrap: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupV2Support {
    Unavailable,
    AvailableReadOnly,
    Writable,
}

pub(crate) trait CapabilityProbe {
    fn snapshot(&self) -> CapabilitySnapshot;
}

pub(crate) struct DefaultCapabilityProbe;

impl CapabilityProbe for DefaultCapabilityProbe {
    fn snapshot(&self) -> CapabilitySnapshot {
        CapabilitySnapshot {
            landlock_abi: super::landlock::detect_abi_version()
                .ok()
                .and_then(|abi| u32::try_from(abi).ok()),
            seccomp: detect_seccomp(),
            cgroup_v2: detect_cgroup_v2(),
            ip: super::netns::fixed_system_tool_available("ip"),
            iptables: super::netns::fixed_system_tool_available("iptables"),
            nft: super::netns::fixed_system_tool_available("nft"),
            cap_net_admin: detect_cap_net_admin(),
            netns_helper: super::netns::helper_available(),
            unprivileged_userns: detect_unprivileged_userns(),
            bubblewrap: super::bwrap::available(),
        }
    }
}

pub(crate) fn build_isolation_plan(
    config: &SandboxConfig,
) -> Result<LinuxIsolationPlan, StrategyError> {
    let probe = DefaultCapabilityProbe;
    plan_with_probe(
        &config.policy,
        config.id,
        &config.workspace_dir,
        config.proxy_port,
        config.proxy_addr,
        &probe,
    )
}

pub(crate) fn build_resource_strategy(
    policy: &ProcessPolicy,
) -> Result<(ResourceStrategy, Vec<PlanFallback>), StrategyError> {
    let probe = DefaultCapabilityProbe;
    plan_resource_strategy(policy, &probe)
}

pub(crate) fn plan_resource_strategy(
    policy: &ProcessPolicy,
    probe: &dyn CapabilityProbe,
) -> Result<(ResourceStrategy, Vec<PlanFallback>), StrategyError> {
    let caps = probe.snapshot();
    let mut fallbacks = Vec::new();
    let resources = plan_resources(policy, &caps, &mut fallbacks)?;
    Ok((resources, fallbacks))
}

pub(crate) fn build_strict_proxy_strategy(
    policy: &Policy,
    sandbox_id: SandboxId,
    proxy_port: u16,
    proxy_addr: Option<SocketAddr>,
) -> Result<(NetworkStrategy, ProxyStrategy), StrategyError> {
    let probe = DefaultCapabilityProbe;
    plan_strict_proxy_strategy(policy, sandbox_id, proxy_port, proxy_addr, &probe)
}

pub(crate) fn plan_strict_proxy_strategy(
    policy: &Policy,
    sandbox_id: SandboxId,
    proxy_port: u16,
    proxy_addr: Option<SocketAddr>,
    probe: &dyn CapabilityProbe,
) -> Result<(NetworkStrategy, ProxyStrategy), StrategyError> {
    let caps = probe.snapshot();
    let proxy_addr = validate_proxy_bind(sandbox_id, proxy_port, proxy_addr)?;
    plan_strict_proxy_network(policy, sandbox_id, proxy_addr, &caps)
}

pub(crate) fn plan_with_probe(
    policy: &Policy,
    sandbox_id: SandboxId,
    workspace_dir: &Path,
    proxy_port: u16,
    proxy_addr: Option<SocketAddr>,
    probe: &dyn CapabilityProbe,
) -> Result<LinuxIsolationPlan, StrategyError> {
    if !workspace_dir.exists() {
        return Err(StrategyError::new(
            "filesystem",
            format!("workspace does not exist: {}", workspace_dir.display()),
        ));
    }

    let caps = probe.snapshot();
    let mut fallbacks = Vec::new();

    let identity = plan_identity(&policy.process)?;
    let filesystem = plan_filesystem(policy, &caps)?;
    let seccomp = plan_seccomp(&caps)?;
    let (network, proxy) = plan_network(policy, sandbox_id, proxy_port, proxy_addr, &caps)?;
    let resources = plan_resources(&policy.process, &caps, &mut fallbacks)?;

    Ok(LinuxIsolationPlan {
        sandbox_id,
        workspace_dir: workspace_dir.to_path_buf(),
        filesystem,
        seccomp,
        network,
        resources,
        identity,
        proxy,
        fallbacks,
    })
}

fn plan_filesystem(
    policy: &Policy,
    caps: &CapabilitySnapshot,
) -> Result<FilesystemStrategy, StrategyError> {
    let landlock_error = match caps.landlock_abi {
        Some(abi) if abi >= MIN_LANDLOCK_CONTRACT_ABI => {
            return Ok(FilesystemStrategy::Landlock { abi });
        }
        Some(abi) => format!(
            "Landlock ABI {abi} cannot enforce the AXIS filesystem contract; require Landlock ABI >= {MIN_LANDLOCK_CONTRACT_ABI}"
        ),
        None => "Landlock unavailable".into(),
    };

    let uid_dac_error = policy.process.run_as_user.as_ref().map(|username| {
        format!(
            "UID/DAC fallback for run_as_user '{username}' is disabled because DAC cannot prove Landlock default-deny filesystem semantics"
        )
    });

    if caps.bubblewrap {
        if let Some(reason) = uid_dac_error {
            return Err(StrategyError::new(
                "filesystem",
                format!(
                    "{landlock_error}; bubblewrap fallback does not support run_as_user yet; {reason}"
                ),
            ));
        }
        return Ok(FilesystemStrategy::Bubblewrap);
    }

    if let Some(reason) = uid_dac_error {
        return Err(StrategyError::new(
            "filesystem",
            format!("{landlock_error}; {reason}"),
        ));
    }

    Err(StrategyError::new(
        "filesystem",
        format!("{landlock_error} and no valid filesystem fallback is available"),
    ))
}

fn plan_seccomp(caps: &CapabilitySnapshot) -> Result<SeccompStrategy, StrategyError> {
    if caps.seccomp {
        Ok(SeccompStrategy::Native)
    } else {
        Err(StrategyError::new(
            "seccomp",
            "native seccomp filtering is unavailable",
        ))
    }
}

fn plan_network(
    policy: &Policy,
    sandbox_id: SandboxId,
    proxy_port: u16,
    proxy_addr: Option<SocketAddr>,
    caps: &CapabilitySnapshot,
) -> Result<(NetworkStrategy, ProxyStrategy), StrategyError> {
    match policy.network.mode {
        NetworkMode::Block => {
            reject_endpoint_policies_for_non_proxy(policy, "block")?;
            if caps.landlock_abi.is_none() && caps.bubblewrap {
                Ok((NetworkStrategy::BlockedByBubblewrap, ProxyStrategy::None))
            } else {
                Ok((NetworkStrategy::BlockedBySeccomp, ProxyStrategy::None))
            }
        }
        NetworkMode::Allow => {
            reject_endpoint_policies_for_non_proxy(policy, "allow")?;
            Ok((NetworkStrategy::AllowHost, ProxyStrategy::None))
        }
        NetworkMode::Proxy => {
            let proxy_addr = validate_proxy_bind(sandbox_id, proxy_port, proxy_addr)?;

            if caps.landlock_abi.is_none() && caps.bubblewrap {
                return Err(StrategyError::new(
                    "network",
                    "bubblewrap filesystem fallback cannot preserve proxy network semantics",
                ));
            }

            plan_strict_proxy_network(policy, sandbox_id, proxy_addr, caps)
        }
    }
}

fn plan_strict_proxy_network(
    policy: &Policy,
    sandbox_id: SandboxId,
    proxy_addr: SocketAddr,
    caps: &CapabilitySnapshot,
) -> Result<(NetworkStrategy, ProxyStrategy), StrategyError> {
    let firewall = selected_firewall(caps);
    if caps.cap_net_admin && caps.ip && firewall.is_some() {
        return Ok(proxy_plan(
            sandbox_id,
            ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
            firewall,
            proxy_addr,
        ));
    }

    if caps.cap_net_admin && caps.ip && caps.nft {
        return Err(StrategyError::new(
            "network",
            "nft is available but Linux proxy setup currently requires iptables",
        ));
    }

    if caps.netns_helper {
        if policy.process.run_as_user.is_some() {
            return Err(StrategyError::new(
                "network",
                "axis-netns-helper proxy setup with run_as_user is not implemented yet",
            ));
        }
        if super::landlock::policy_uses_tmpdir(&policy.filesystem) {
            return Err(StrategyError::new(
                "network",
                "axis-netns-helper proxy setup with {tmpdir} filesystem policy is not implemented yet",
            ));
        }
        return Ok(proxy_plan(
            sandbox_id,
            ProxyNetworkSetup::AxisNetnsHelperLaunch,
            Some(FirewallTool::Iptables),
            proxy_addr,
        ));
    }

    if caps.unprivileged_userns && caps.ip && firewall.is_some() {
        return Err(StrategyError::new(
            "network",
            "unprivileged user namespace proxy setup is not implemented yet",
        ));
    }

    if caps.bubblewrap {
        return Err(StrategyError::new(
            "network",
            "bubblewrap is available only as a block-mode fallback until proxy reachability is implemented",
        ));
    }

    Err(StrategyError::new(
        "network",
        "proxy mode requires CAP_NET_ADMIN with ip/firewall tooling, axis-netns-helper, or unprivileged user namespace support",
    ))
}

fn validate_proxy_bind(
    sandbox_id: SandboxId,
    proxy_port: u16,
    proxy_addr: Option<SocketAddr>,
) -> Result<SocketAddr, StrategyError> {
    if proxy_port == 0 {
        return Err(StrategyError::new(
            "network",
            "proxy mode requires a non-zero proxy port",
        ));
    }

    let proxy_addr = proxy_addr
        .ok_or_else(|| StrategyError::new("network", "proxy mode requires a proxy bind address"))?;

    if proxy_addr.port() != proxy_port {
        return Err(StrategyError::new(
            "network",
            format!("proxy port {proxy_port} does not match proxy bind address {proxy_addr}"),
        ));
    }

    let expected = super::netns::proxy_bind_addr(sandbox_id, proxy_port);
    if proxy_addr != expected {
        return Err(StrategyError::new(
            "network",
            format!("proxy mode requires proxy bind address {expected}, got {proxy_addr}"),
        ));
    }

    Ok(proxy_addr)
}

fn reject_endpoint_policies_for_non_proxy(
    policy: &Policy,
    mode: &str,
) -> Result<(), StrategyError> {
    if policy.network.policies.is_empty() {
        Ok(())
    } else {
        Err(StrategyError::new(
            "network",
            format!("network endpoint policies are invalid in {mode} mode"),
        ))
    }
}

fn selected_firewall(caps: &CapabilitySnapshot) -> Option<FirewallTool> {
    if caps.iptables {
        Some(FirewallTool::Iptables)
    } else {
        None
    }
}

fn proxy_plan(
    sandbox_id: SandboxId,
    setup: ProxyNetworkSetup,
    firewall: Option<FirewallTool>,
    proxy_addr: SocketAddr,
) -> (NetworkStrategy, ProxyStrategy) {
    let proxy_port = proxy_addr.port();
    let allocation = super::netns::proxy_netns_allocation(sandbox_id, proxy_port);
    (
        NetworkStrategy::Proxy {
            setup,
            firewall,
            host_addr: allocation.host_addr,
            sandbox_addr: allocation.sandbox_addr,
            proxy_port,
        },
        ProxyStrategy::Required {
            bind_addr: allocation.host_addr,
            sandbox_addr: allocation.host_addr,
            port: proxy_port,
        },
    )
}

fn plan_resources(
    policy: &ProcessPolicy,
    caps: &CapabilitySnapshot,
    fallbacks: &mut Vec<PlanFallback>,
) -> Result<ResourceStrategy, StrategyError> {
    let memory_requested = policy.max_memory_mb > 0;
    let process_requested = policy.effective_max_processes() > 0;
    let cpu_requested = policy.cpu_rate_percent > 0;

    if !memory_requested && !process_requested && !cpu_requested {
        return Ok(ResourceStrategy::RlimitFallback {
            memory_limit: false,
            process_limit: ProcessLimitFallback::NotRequested,
            cpu_limit: CpuLimitFallback::NotRequested,
        });
    }

    if matches!(caps.cgroup_v2, CgroupV2Support::Writable) {
        return Ok(ResourceStrategy::CgroupsV2 {
            support: caps.cgroup_v2,
        });
    }

    if cpu_requested {
        return Err(StrategyError::new(
            "resources",
            "CPU rate limits require writable cgroups v2",
        ));
    }

    if process_requested && policy.run_as_user.is_none() {
        return Err(StrategyError::new(
            "resources",
            "process count rlimit fallback requires a dedicated run_as_user",
        ));
    }

    fallbacks.push(PlanFallback {
        area: "resources",
        reason: match caps.cgroup_v2 {
            CgroupV2Support::AvailableReadOnly => {
                "cgroups v2 is read-only; using documented rlimit fallback with limitations"
            }
            CgroupV2Support::Unavailable => {
                "cgroups v2 unavailable; using documented rlimit fallback with limitations"
            }
            CgroupV2Support::Writable => unreachable!("writable cgroups returned earlier"),
        }
        .to_string(),
    });

    Ok(ResourceStrategy::RlimitFallback {
        memory_limit: memory_requested,
        process_limit: if process_requested {
            ProcessLimitFallback::RlimitNprocWithDedicatedUser
        } else {
            ProcessLimitFallback::NotRequested
        },
        cpu_limit: CpuLimitFallback::NotRequested,
    })
}

fn plan_identity(policy: &ProcessPolicy) -> Result<IdentityStrategy, StrategyError> {
    match policy.run_as_user.as_deref() {
        Some("root") => Err(StrategyError::new(
            "identity",
            "run_as_user must not be root",
        )),
        Some(username) if username.trim().is_empty() => Err(StrategyError::new(
            "identity",
            "run_as_user must not be empty",
        )),
        Some(username) => Ok(IdentityStrategy::RunAsUser {
            username: username.to_string(),
        }),
        None => Ok(IdentityStrategy::CurrentUser),
    }
}

fn detect_seccomp() -> bool {
    let mut action = libc::SECCOMP_RET_ALLOW;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0,
            &mut action as *mut u32,
        )
    };
    ret == 0
}

fn detect_cgroup_v2() -> CgroupV2Support {
    let controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers.exists() {
        return CgroupV2Support::Unavailable;
    }

    if resources::find_writable_cgroup_v2_delegation().is_ok() {
        CgroupV2Support::Writable
    } else {
        CgroupV2Support::AvailableReadOnly
    }
}

fn detect_cap_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_cap_eff(&status))
        .map(|cap_eff| cap_eff_contains(cap_eff, CAP_NET_ADMIN_BIT))
        .unwrap_or(false)
}

fn detect_unprivileged_userns() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn parse_cap_eff(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let value = line.strip_prefix("CapEff:")?.trim();
        u64::from_str_radix(value, 16).ok()
    })
}

fn cap_eff_contains(cap_eff: u64, bit: u32) -> bool {
    let Some(mask) = 1u64.checked_shl(bit) else {
        return false;
    };
    cap_eff & mask != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::netns;
    use axis_core::policy::{
        Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkPolicy,
        SshPolicy,
    };
    use std::str::FromStr;

    struct FakeProbe {
        snapshot: CapabilitySnapshot,
    }

    impl CapabilityProbe for FakeProbe {
        fn snapshot(&self) -> CapabilitySnapshot {
            self.snapshot.clone()
        }
    }

    struct PanicProbe;

    impl CapabilityProbe for PanicProbe {
        fn snapshot(&self) -> CapabilitySnapshot {
            panic!("probe should not run")
        }
    }

    fn full_caps() -> CapabilitySnapshot {
        CapabilitySnapshot {
            landlock_abi: Some(7),
            seccomp: true,
            cgroup_v2: CgroupV2Support::Writable,
            ip: true,
            iptables: true,
            nft: false,
            cap_net_admin: true,
            netns_helper: false,
            unprivileged_userns: false,
            bubblewrap: false,
        }
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn plan(policy: &Policy, caps: CapabilitySnapshot, proxy_port: u16) -> LinuxIsolationPlan {
        let workspace = tempfile::tempdir().unwrap();
        let sandbox_id = test_sandbox_id();
        plan_with_probe(
            policy,
            sandbox_id,
            workspace.path(),
            proxy_port,
            proxy_bind(sandbox_id, proxy_port),
            &FakeProbe { snapshot: caps },
        )
        .unwrap()
    }

    fn test_sandbox_id() -> SandboxId {
        SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap()
    }

    fn proxy_bind(sandbox_id: SandboxId, port: u16) -> Option<SocketAddr> {
        if port == 0 {
            None
        } else {
            Some(netns::proxy_bind_addr(sandbox_id, port))
        }
    }

    #[test]
    fn missing_workspace_is_rejected_before_capability_probe() {
        let workspace = tempfile::tempdir().unwrap();
        let missing = workspace.path().join("missing");

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            &missing,
            0,
            None,
            &PanicProbe,
        )
        .unwrap_err();

        assert_eq!(err.area, "filesystem");
        assert!(err.message.contains("workspace does not exist"));
    }

    #[test]
    fn proxy_mode_uses_native_netns_when_capabilities_are_present() {
        let plan = plan(&policy(NetworkMode::Proxy), full_caps(), 3128);
        let allocation = netns::proxy_netns_allocation(plan.sandbox_id, 3128);

        assert_eq!(plan.filesystem, FilesystemStrategy::Landlock { abi: 7 });
        assert_eq!(plan.seccomp, SeccompStrategy::Native);
        assert_eq!(
            plan.network,
            NetworkStrategy::Proxy {
                setup: ProxyNetworkSetup::IpNetnsWithCapNetAdmin,
                firewall: Some(FirewallTool::Iptables),
                host_addr: allocation.host_addr,
                sandbox_addr: allocation.sandbox_addr,
                proxy_port: 3128,
            }
        );
        assert_eq!(
            plan.proxy,
            ProxyStrategy::Required {
                bind_addr: allocation.host_addr,
                sandbox_addr: allocation.host_addr,
                port: 3128,
            }
        );
    }

    #[test]
    fn proxy_mode_rejects_zero_proxy_port() {
        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("non-zero proxy port"));
    }

    #[test]
    fn proxy_mode_rejects_loopback_proxy_bind() {
        let sandbox_id = test_sandbox_id();
        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            Some("127.0.0.1:3128".parse().unwrap()),
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(
            err.message
                .contains(&netns::proxy_bind_addr(sandbox_id, 3128).to_string())
        );
    }

    #[test]
    fn proxy_mode_rejects_mismatched_proxy_port() {
        let sandbox_id = test_sandbox_id();
        let wrong_addr = SocketAddr::new(netns::proxy_bind_addr(sandbox_id, 3128).ip(), 4000);
        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            Some(wrong_addr),
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("does not match"));
    }

    #[test]
    fn proxy_mode_uses_helper_launch_when_available_without_cap_net_admin() {
        let mut caps = full_caps();
        caps.cap_net_admin = false;
        caps.ip = false;
        caps.iptables = false;
        caps.netns_helper = true;
        let sandbox_id = test_sandbox_id();

        let plan = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap();
        let allocation = netns::proxy_netns_allocation(sandbox_id, 3128);

        assert_eq!(
            plan.network,
            NetworkStrategy::Proxy {
                setup: ProxyNetworkSetup::AxisNetnsHelperLaunch,
                firewall: Some(FirewallTool::Iptables),
                host_addr: allocation.host_addr,
                sandbox_addr: allocation.sandbox_addr,
                proxy_port: 3128,
            }
        );
    }

    #[test]
    fn proxy_mode_rejects_helper_launch_with_run_as_user_until_supported() {
        let mut caps = full_caps();
        caps.cap_net_admin = false;
        caps.ip = false;
        caps.iptables = false;
        caps.netns_helper = true;
        let sandbox_id = test_sandbox_id();
        let mut policy = policy(NetworkMode::Proxy);
        policy.process.run_as_user = Some("sandbox-user".into());

        let err = plan_with_probe(
            &policy,
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("run_as_user"));
    }

    #[test]
    fn proxy_mode_rejects_helper_launch_with_tmpdir_until_supported() {
        let mut caps = full_caps();
        caps.cap_net_admin = false;
        caps.ip = false;
        caps.iptables = false;
        caps.netns_helper = true;
        let sandbox_id = test_sandbox_id();
        let mut policy = policy(NetworkMode::Proxy);
        policy.filesystem.read_write.push("{tmpdir}".into());

        let err = plan_with_probe(
            &policy,
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("{tmpdir}"));
    }

    #[test]
    fn proxy_mode_rejects_user_namespace_until_runtime_support_exists() {
        let mut caps = full_caps();
        caps.cap_net_admin = false;
        caps.unprivileged_userns = true;
        let sandbox_id = test_sandbox_id();

        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("not implemented yet"));
    }

    #[test]
    fn proxy_mode_rejects_bubblewrap_only_capability_set() {
        let caps = CapabilitySnapshot {
            landlock_abi: Some(7),
            seccomp: true,
            cgroup_v2: CgroupV2Support::Writable,
            bubblewrap: true,
            ..CapabilitySnapshot::default()
        };
        let sandbox_id = test_sandbox_id();

        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("block-mode fallback"));
    }

    #[test]
    fn proxy_mode_rejects_bubblewrap_filesystem_fallback_even_with_native_proxy_caps() {
        let mut caps = full_caps();
        caps.landlock_abi = None;
        caps.bubblewrap = true;
        let sandbox_id = test_sandbox_id();

        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("cannot preserve proxy"));
    }

    #[test]
    fn proxy_mode_rejects_nft_until_runtime_support_exists() {
        let mut caps = full_caps();
        caps.iptables = false;
        caps.nft = true;
        let sandbox_id = test_sandbox_id();

        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("requires iptables"));
    }

    #[test]
    fn proxy_mode_rejects_missing_firewall_for_native_setup() {
        let mut caps = full_caps();
        caps.iptables = false;
        caps.nft = false;
        let sandbox_id = test_sandbox_id();

        let err = plan_with_probe(
            &policy(NetworkMode::Proxy),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("CAP_NET_ADMIN"));
    }

    #[test]
    fn block_mode_uses_seccomp_socket_filter_without_proxy() {
        let sandbox_id = test_sandbox_id();
        let plan = plan_with_probe(
            &policy(NetworkMode::Block),
            sandbox_id,
            tempfile::tempdir().unwrap().path(),
            3128,
            proxy_bind(sandbox_id, 3128),
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap();

        assert_eq!(plan.network, NetworkStrategy::BlockedBySeccomp);
        assert_eq!(plan.proxy, ProxyStrategy::None);
    }

    #[test]
    fn block_mode_without_global_seccomp_is_seccomp_fatal() {
        let caps = CapabilitySnapshot {
            landlock_abi: Some(7),
            seccomp: false,
            cgroup_v2: CgroupV2Support::Writable,
            bubblewrap: true,
            ..CapabilitySnapshot::default()
        };

        let err = plan_with_probe(
            &policy(NetworkMode::Block),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "seccomp");
    }

    #[test]
    fn allow_mode_uses_host_network_without_proxy() {
        let plan = plan(&policy(NetworkMode::Allow), full_caps(), 0);

        assert_eq!(plan.network, NetworkStrategy::AllowHost);
        assert_eq!(plan.proxy, ProxyStrategy::None);
    }

    #[test]
    fn non_proxy_modes_reject_endpoint_policies() {
        let mut policy = policy(NetworkMode::Allow);
        policy.network.policies.push(EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "github.com".into(),
                port: 443,
                access: Default::default(),
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        });

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("invalid in allow mode"));
    }

    #[test]
    fn block_mode_rejects_endpoint_policies() {
        let mut policy = policy(NetworkMode::Block);
        policy.network.policies.push(EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "github.com".into(),
                port: 443,
                access: Default::default(),
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: Vec::new(),
        });

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "network");
        assert!(err.message.contains("invalid in block mode"));
    }

    #[test]
    fn missing_landlock_uses_bubblewrap_filesystem_fallback() {
        let mut caps = full_caps();
        caps.landlock_abi = None;
        caps.bubblewrap = true;

        let plan = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap();

        assert_eq!(plan.filesystem, FilesystemStrategy::Bubblewrap);
        assert_eq!(plan.network, NetworkStrategy::AllowHost);
    }

    #[test]
    fn missing_landlock_block_mode_uses_bubblewrap_network_fallback() {
        let mut caps = full_caps();
        caps.landlock_abi = None;
        caps.bubblewrap = true;

        let plan = plan_with_probe(
            &policy(NetworkMode::Block),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap();

        assert_eq!(plan.filesystem, FilesystemStrategy::Bubblewrap);
        assert_eq!(plan.network, NetworkStrategy::BlockedByBubblewrap);
    }

    #[test]
    fn landlock_abi_below_contract_uses_bubblewrap_filesystem_fallback() {
        let mut caps = full_caps();
        caps.landlock_abi = Some(2);
        caps.bubblewrap = true;

        let plan = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap();

        assert_eq!(plan.filesystem, FilesystemStrategy::Bubblewrap);
        assert_eq!(plan.network, NetworkStrategy::AllowHost);
    }

    #[test]
    fn landlock_abi_below_contract_without_fallback_is_fatal() {
        let mut caps = full_caps();
        caps.landlock_abi = Some(2);
        caps.bubblewrap = false;

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "filesystem");
        assert!(err.message.contains("Landlock ABI 2"));
        assert!(err.message.contains("require Landlock ABI >= 3"));
    }

    #[test]
    fn missing_landlock_rejects_uid_dac_fallback_even_with_run_as_user() {
        let mut caps = full_caps();
        caps.landlock_abi = None;

        let mut policy = policy(NetworkMode::Allow);
        policy.filesystem.read_only = vec!["/".into()];
        policy.filesystem.read_write = vec!["{workspace}".into(), "{tmpdir}".into()];
        policy.process.run_as_user = Some("sandbox-user".into());

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "filesystem");
        assert!(err.message.contains("UID/DAC fallback"));
        assert!(err.message.contains("disabled"));
    }

    #[test]
    fn missing_landlock_without_fallback_is_fatal() {
        let mut caps = full_caps();
        caps.landlock_abi = None;

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "filesystem");
    }

    #[test]
    fn missing_seccomp_is_fatal_when_no_network_fallback_applies() {
        let mut caps = full_caps();
        caps.seccomp = false;

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "seccomp");
    }

    #[test]
    fn cgroup_read_only_with_requested_cpu_is_fatal() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::AvailableReadOnly;

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "resources");
        assert!(err.message.contains("CPU rate limits"));
    }

    #[test]
    fn cgroup_absence_with_requested_cpu_is_fatal() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let err = plan_with_probe(
            &policy(NetworkMode::Allow),
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "resources");
        assert!(err.message.contains("CPU rate limits"));
    }

    #[test]
    fn cgroup_absence_with_full_cpu_quota_is_fatal() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let mut policy = policy(NetworkMode::Allow);
        policy.process.cpu_rate_percent = 100;
        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "resources");
        assert!(err.message.contains("CPU rate limits"));
    }

    #[test]
    fn no_requested_resource_limits_skip_cgroups_even_when_writable() {
        let caps = full_caps();
        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_processes = 0;
        policy.process.max_memory_mb = 0;
        policy.process.cpu_rate_percent = 0;

        let plan = plan(&policy, caps, 0);

        assert_eq!(
            plan.resources,
            ResourceStrategy::RlimitFallback {
                memory_limit: false,
                process_limit: ProcessLimitFallback::NotRequested,
                cpu_limit: CpuLimitFallback::NotRequested,
            }
        );
        assert!(plan.fallbacks.is_empty());
    }

    #[test]
    fn requested_resource_limits_use_writable_cgroups() {
        let caps = full_caps();
        let mut policy = policy(NetworkMode::Allow);
        policy.process.cpu_rate_percent = 0;
        policy.process.max_processes = 32;
        policy.process.max_memory_mb = 8192;

        let plan = plan(&policy, caps, 0);

        assert_eq!(
            plan.resources,
            ResourceStrategy::CgroupsV2 {
                support: CgroupV2Support::Writable,
            }
        );
    }

    #[test]
    fn cgroup_absence_allows_rlimit_fallback_when_cpu_is_not_requested() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let mut policy = policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("sandbox-user".into());
        policy.process.cpu_rate_percent = 0;

        let plan = plan(&policy, caps, 0);

        assert_eq!(
            plan.resources,
            ResourceStrategy::RlimitFallback {
                memory_limit: true,
                process_limit: ProcessLimitFallback::RlimitNprocWithDedicatedUser,
                cpu_limit: CpuLimitFallback::NotRequested,
            }
        );
        assert!(plan.fallbacks.iter().any(|f| f.area == "resources"));
    }

    #[test]
    fn process_rlimit_without_dedicated_user_is_fatal() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let mut policy = policy(NetworkMode::Allow);
        policy.process.cpu_rate_percent = 0;

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe { snapshot: caps },
        )
        .unwrap_err();

        assert_eq!(err.area, "resources");
        assert!(err.message.contains("dedicated run_as_user"));
    }

    #[test]
    fn cgroup_absence_allows_memory_only_rlimit_fallback_without_run_as_user() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_processes = 0;
        policy.process.cpu_rate_percent = 0;

        let plan = plan(&policy, caps, 0);

        assert_eq!(
            plan.resources,
            ResourceStrategy::RlimitFallback {
                memory_limit: true,
                process_limit: ProcessLimitFallback::NotRequested,
                cpu_limit: CpuLimitFallback::NotRequested,
            }
        );
        assert!(plan.fallbacks.iter().any(|f| f.area == "resources"));
    }

    #[test]
    fn rlimit_process_fallback_uses_dedicated_user_when_configured() {
        let mut caps = full_caps();
        caps.cgroup_v2 = CgroupV2Support::Unavailable;

        let mut policy = policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("sandbox-user".into());
        policy.process.cpu_rate_percent = 0;

        let plan = plan(&policy, caps, 0);

        assert_eq!(
            plan.resources,
            ResourceStrategy::RlimitFallback {
                memory_limit: true,
                process_limit: ProcessLimitFallback::RlimitNprocWithDedicatedUser,
                cpu_limit: CpuLimitFallback::NotRequested,
            }
        );
    }

    #[test]
    fn run_as_root_is_rejected() {
        let mut policy = policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("root".into());

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "identity");
    }

    #[test]
    fn empty_run_as_user_is_rejected() {
        let mut policy = policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("   ".into());

        let err = plan_with_probe(
            &policy,
            SandboxId::new(),
            tempfile::tempdir().unwrap().path(),
            0,
            None,
            &FakeProbe {
                snapshot: full_caps(),
            },
        )
        .unwrap_err();

        assert_eq!(err.area, "identity");
        assert!(err.message.contains("empty"));
    }

    #[test]
    fn cap_eff_parser_detects_cap_net_admin_bit() {
        assert!(cap_eff_contains(0x1000, CAP_NET_ADMIN_BIT));
        assert!(!cap_eff_contains(0, CAP_NET_ADMIN_BIT));
        assert!(!cap_eff_contains(0xffff_ffff_ffff_ffff, 64));
        assert_eq!(
            parse_cap_eff("Name:\ttest\nCapEff:\t0000000000001000\n"),
            Some(0x1000)
        );
        assert_eq!(parse_cap_eff("Name:\ttest\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnot-hex\n"), None);
    }
}
