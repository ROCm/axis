// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Repository-owned backend capability maps.
//!
//! These maps are deliberately conservative. A backend capability is marked
//! exact only when AXIS can rely on the backend or an AXIS-owned layer to
//! preserve the shared isolation contract. Preview and experimental maps keep
//! weaker or unsupported behavior explicit so platform adapters can reject the
//! policy before spawning a workload.

use crate::capability::{
    AuditCapabilities, BackendCapabilities, BackendPlatform, BackendStability, CapabilitySupport,
    CleanupCapabilities, CredentialCapabilities, FilesystemCapabilities, HostDependency,
    InferenceCapabilities, LifecycleCapabilities, NetworkCapabilities, ProcessCapabilities,
    ResourceCapabilities,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod host_dependency {
    pub const AXIS_NETNS_HELPER: &str = "axis.netns_helper";
    pub const AXIS_SECCOMP_LAUNCHER: &str = "axis.seccomp_launcher";
    pub const LINUX_BUBBLEWRAP: &str = "linux.bubblewrap";
    pub const LINUX_CGROUP_V2: &str = "linux.cgroup_v2_delegated";
    pub const LINUX_KVM: &str = "linux.kvm";
    pub const LINUX_LANDLOCK: &str = "linux.landlock_abi_v3";
    pub const LINUX_LXC: &str = "linux.lxc";
    pub const LINUX_NETNS: &str = "linux.network_namespaces";
    pub const LINUX_SECCOMP_BPF: &str = "linux.seccomp_bpf";
    pub const LINUX_SECCOMP_NOTIFY: &str = "linux.seccomp_notify";
    pub const LINUX_STRICT_PROXY: &str = "linux.strict_proxy_boundary";
    pub const LINUX_USERNS: &str = "linux.user_namespaces";
    pub const MACOS_SEATBELT: &str = "macos.seatbelt";
    pub const MACOS_XCODE_CLT: &str = "macos.xcode_command_line_tools";
    pub const MXC_EXECUTOR: &str = "mxc.executor";
    pub const MXC_HYPERLIGHT_RUNTIME: &str = "mxc.hyperlight_runtime";
    pub const MXC_MICROVM_RUNTIME: &str = "mxc.microvm_runtime";
    pub const WINDOWS_HYPERLIGHT_RUNTIME: &str = "windows.hyperlight_runtime";
    pub const WINDOWS_ISOLATION_SESSION: &str = "windows.isolation_session";
    pub const WINDOWS_JOBOBJECT: &str = "windows.job_object";
    pub const WINDOWS_LOW_INTEGRITY: &str = "windows.low_integrity";
    pub const WINDOWS_PROCESS_CONTAINER: &str = "windows.processcontainer";
    pub const WINDOWS_WFP_BROKER: &str = "windows.axis_wfp_broker";
    pub const WINDOWS_SANDBOX: &str = "windows.windows_sandbox";
    pub const WINDOWS_WHP: &str = "windows.whp";
    pub const WINDOWS_WSL2: &str = "windows.wsl2";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendCapabilityMapId {
    AxisNativeLinux,
    MxcLinuxBubblewrap,
    MxcLinuxLxc,
    MxcLinuxMicrovm,
    MxcLinuxHyperlight,
    AxisNativeMacosSeatbelt,
    MxcMacosSeatbelt,
    AxisNativeWindows,
    MxcWindowsProcessContainer,
    MxcWindowsIsolationSession,
    MxcWindowsSandbox,
    MxcWindowsWslc,
    MxcWindowsMicrovm,
    MxcWindowsHyperlight,
}

impl BackendCapabilityMapId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AxisNativeLinux => "axis-native-linux",
            Self::MxcLinuxBubblewrap => "mxc-linux-bubblewrap",
            Self::MxcLinuxLxc => "mxc-linux-lxc",
            Self::MxcLinuxMicrovm => "mxc-linux-microvm",
            Self::MxcLinuxHyperlight => "mxc-linux-hyperlight",
            Self::AxisNativeMacosSeatbelt => "axis-native-macos-seatbelt",
            Self::MxcMacosSeatbelt => "mxc-macos-seatbelt",
            Self::AxisNativeWindows => "axis-native-windows",
            Self::MxcWindowsProcessContainer => "mxc-windows-processcontainer",
            Self::MxcWindowsIsolationSession => "mxc-windows-isolation-session",
            Self::MxcWindowsSandbox => "mxc-windows-sandbox",
            Self::MxcWindowsWslc => "mxc-windows-wslc",
            Self::MxcWindowsMicrovm => "mxc-windows-microvm",
            Self::MxcWindowsHyperlight => "mxc-windows-hyperlight",
        }
    }

    pub fn platform(self) -> BackendPlatform {
        match self {
            Self::AxisNativeLinux
            | Self::MxcLinuxBubblewrap
            | Self::MxcLinuxLxc
            | Self::MxcLinuxMicrovm
            | Self::MxcLinuxHyperlight => BackendPlatform::Linux,
            Self::AxisNativeMacosSeatbelt | Self::MxcMacosSeatbelt => BackendPlatform::Macos,
            Self::AxisNativeWindows
            | Self::MxcWindowsProcessContainer
            | Self::MxcWindowsIsolationSession
            | Self::MxcWindowsSandbox
            | Self::MxcWindowsWslc
            | Self::MxcWindowsMicrovm
            | Self::MxcWindowsHyperlight => BackendPlatform::Windows,
        }
    }
}

pub const BACKEND_CAPABILITY_MAP_IDS: &[BackendCapabilityMapId] = &[
    BackendCapabilityMapId::AxisNativeLinux,
    BackendCapabilityMapId::MxcLinuxBubblewrap,
    BackendCapabilityMapId::MxcLinuxLxc,
    BackendCapabilityMapId::MxcLinuxMicrovm,
    BackendCapabilityMapId::MxcLinuxHyperlight,
    BackendCapabilityMapId::AxisNativeMacosSeatbelt,
    BackendCapabilityMapId::MxcMacosSeatbelt,
    BackendCapabilityMapId::AxisNativeWindows,
    BackendCapabilityMapId::MxcWindowsProcessContainer,
    BackendCapabilityMapId::MxcWindowsIsolationSession,
    BackendCapabilityMapId::MxcWindowsSandbox,
    BackendCapabilityMapId::MxcWindowsWslc,
    BackendCapabilityMapId::MxcWindowsMicrovm,
    BackendCapabilityMapId::MxcWindowsHyperlight,
];

pub fn backend_capability_map(id: BackendCapabilityMapId) -> BackendCapabilities {
    match id {
        BackendCapabilityMapId::AxisNativeLinux => axis_native_linux(),
        BackendCapabilityMapId::MxcLinuxBubblewrap => mxc_linux_bubblewrap(),
        BackendCapabilityMapId::MxcLinuxLxc => mxc_linux_lxc(),
        BackendCapabilityMapId::MxcLinuxMicrovm => mxc_linux_microvm(),
        BackendCapabilityMapId::MxcLinuxHyperlight => mxc_linux_hyperlight(),
        BackendCapabilityMapId::AxisNativeMacosSeatbelt => axis_native_macos_seatbelt(),
        BackendCapabilityMapId::MxcMacosSeatbelt => mxc_macos_seatbelt(),
        BackendCapabilityMapId::AxisNativeWindows => axis_native_windows(),
        BackendCapabilityMapId::MxcWindowsProcessContainer => mxc_windows_processcontainer(),
        BackendCapabilityMapId::MxcWindowsIsolationSession => mxc_windows_isolation_session(),
        BackendCapabilityMapId::MxcWindowsSandbox => mxc_windows_sandbox(),
        BackendCapabilityMapId::MxcWindowsWslc => mxc_windows_wslc(),
        BackendCapabilityMapId::MxcWindowsMicrovm => mxc_windows_microvm(),
        BackendCapabilityMapId::MxcWindowsHyperlight => mxc_windows_hyperlight(),
    }
}

pub fn backend_capability_map_by_name(name: &str) -> Option<BackendCapabilities> {
    BACKEND_CAPABILITY_MAP_IDS
        .iter()
        .copied()
        .find(|id| id.as_str() == name)
        .map(backend_capability_map)
}

pub fn all_backend_capability_maps() -> Vec<BackendCapabilities> {
    BACKEND_CAPABILITY_MAP_IDS
        .iter()
        .copied()
        .map(backend_capability_map)
        .collect()
}

pub fn backend_capability_maps_for_platform(platform: BackendPlatform) -> Vec<BackendCapabilities> {
    BACKEND_CAPABILITY_MAP_IDS
        .iter()
        .copied()
        .filter(|id| id.platform() == platform)
        .map(backend_capability_map)
        .collect()
}

pub fn validate_backend_capability_map(backend: &BackendCapabilities) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if backend.name.trim().is_empty() {
        problems.push("backend name must not be empty".into());
    }

    let mut declared = BTreeSet::new();
    for dependency in &backend.host_dependencies {
        if dependency.name.trim().is_empty() {
            problems.push(format!(
                "{} declares an empty dependency name",
                backend.name
            ));
        }
        if dependency.description.trim().is_empty() {
            problems.push(format!(
                "{} dependency '{}' must describe the host requirement",
                backend.name, dependency.name
            ));
        }
        if !declared.insert(dependency.name.as_str()) {
            problems.push(format!(
                "{} declares duplicate dependency '{}'",
                backend.name, dependency.name
            ));
        }
    }

    validate_support(
        &backend.filesystem.read_only,
        "filesystem.read_only",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.filesystem.read_write,
        "filesystem.read_write",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.filesystem.deny,
        "filesystem.deny",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.filesystem.workspace,
        "filesystem.workspace",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.command,
        "process.command",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.working_dir,
        "process.working_dir",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.environment,
        "process.environment",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.stdio,
        "process.stdio",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.user_identity,
        "process.user_identity",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.isolated_identity,
        "process.isolated_identity",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.syscall_filtering,
        "process.syscall_filtering",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.pty,
        "process.pty",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.process.timeout,
        "process.timeout",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.allow,
        "network.allow",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.block,
        "network.block",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.strict_proxy,
        "network.strict_proxy",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.cooperative_proxy,
        "network.cooperative_proxy",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.endpoint_policy,
        "network.endpoint_policy",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.binary_attribution,
        "network.binary_attribution",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.network.l7_policy,
        "network.l7_policy",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.resources.process_count,
        "resources.process_count",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.resources.memory,
        "resources.memory",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.resources.cpu,
        "resources.cpu",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.resources.timeout,
        "resources.timeout",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.credentials.secret_filtering,
        "credentials.secret_filtering",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.credentials.host_boundary_injection,
        "credentials.host_boundary_injection",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.credentials.placeholder_projection,
        "credentials.placeholder_projection",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.inference.inference_local,
        "inference.local",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.inference.external_provider,
        "inference.external_provider",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.inference.streaming,
        "inference.streaming",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.lifecycle.start,
        "lifecycle.start",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.lifecycle.exec,
        "lifecycle.exec",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.lifecycle.destroy,
        "lifecycle.destroy",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.lifecycle.stateful,
        "lifecycle.stateful",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.cleanup.process_tree,
        "cleanup.process_tree",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.cleanup.resources,
        "cleanup.resources",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.cleanup.temp_state,
        "cleanup.temp_state",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.cleanup.backend_state,
        "cleanup.backend_state",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.audit.denials,
        "audit.denials",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.audit.dependency_reasons,
        "audit.dependency_reasons",
        &declared,
        &mut problems,
    );
    validate_support(
        &backend.audit.bypass_evidence,
        "audit.bypass_evidence",
        &declared,
        &mut problems,
    );

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn validate_support(
    support: &CapabilitySupport,
    field: &str,
    declared: &BTreeSet<&str>,
    problems: &mut Vec<String>,
) {
    match support {
        CapabilitySupport::Exact | CapabilitySupport::AxisOwned => {}
        CapabilitySupport::ExactWithHostDependency { dependencies } => {
            if dependencies.is_empty() {
                problems.push(format!(
                    "{field} uses exact-with-host-dependency without dependencies"
                ));
            }
            for dependency in dependencies {
                if !declared.contains(dependency.as_str()) {
                    problems.push(format!(
                        "{field} references undeclared dependency '{dependency}'"
                    ));
                }
            }
        }
        CapabilitySupport::WeakerOnly { reason } => {
            if reason.trim().is_empty() {
                problems.push(format!("{field} weaker support must include a reason"));
            }
        }
        CapabilitySupport::Unsupported { reason } => {
            if reason.trim().is_empty() {
                problems.push(format!("{field} unsupported support must include a reason"));
            }
        }
    }
}

fn axis_native_linux() -> BackendCapabilities {
    let landlock = dep_support(host_dependency::LINUX_LANDLOCK);
    let seccomp = dep_support(host_dependency::LINUX_SECCOMP_BPF);
    let cgroups = dep_support(host_dependency::LINUX_CGROUP_V2);
    let strict_proxy = deps_support([
        host_dependency::LINUX_NETNS,
        host_dependency::AXIS_NETNS_HELPER,
        host_dependency::LINUX_SECCOMP_NOTIFY,
    ]);

    BackendCapabilities {
        platform: BackendPlatform::Linux,
        name: BackendCapabilityMapId::AxisNativeLinux.as_str().into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::LINUX_LANDLOCK,
            host_dependency::LINUX_SECCOMP_BPF,
            host_dependency::LINUX_SECCOMP_NOTIFY,
            host_dependency::LINUX_NETNS,
            host_dependency::AXIS_NETNS_HELPER,
            host_dependency::LINUX_CGROUP_V2,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: landlock.clone(),
            read_write: landlock.clone(),
            deny: landlock.clone(),
            workspace: landlock,
        },
        process: ProcessCapabilities {
            command: CapabilitySupport::Exact,
            working_dir: CapabilitySupport::Exact,
            environment: CapabilitySupport::Exact,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "run_as_user needs a platform identity adapter before it can be planned generically",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "the native Linux process backend does not create a distinct identity by default",
            ),
            syscall_filtering: seccomp.clone(),
            pty: CapabilitySupport::unsupported(
                "PTY attachment is not part of the current backend contract",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: CapabilitySupport::Exact,
            block: seccomp,
            strict_proxy,
            cooperative_proxy: CapabilitySupport::unsupported(
                "cooperative proxy environment variables are not an AXIS-native network boundary",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: dep_support(host_dependency::LINUX_SECCOMP_NOTIFY),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: cgroups.clone(),
            memory: cgroups.clone(),
            cpu: cgroups.clone(),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: one_shot_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: cgroups,
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: CapabilitySupport::AxisOwned,
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: dep_support(host_dependency::LINUX_SECCOMP_NOTIFY),
        },
    }
}

fn mxc_linux_bubblewrap() -> BackendCapabilities {
    let mxc_bwrap = deps_support([
        host_dependency::MXC_EXECUTOR,
        host_dependency::LINUX_BUBBLEWRAP,
        host_dependency::LINUX_USERNS,
    ]);

    BackendCapabilities {
        platform: BackendPlatform::Linux,
        name: BackendCapabilityMapId::MxcLinuxBubblewrap.as_str().into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::MXC_EXECUTOR,
            host_dependency::LINUX_BUBBLEWRAP,
            host_dependency::LINUX_USERNS,
            host_dependency::AXIS_SECCOMP_LAUNCHER,
            host_dependency::LINUX_SECCOMP_NOTIFY,
            host_dependency::LINUX_NETNS,
            host_dependency::AXIS_NETNS_HELPER,
            host_dependency::LINUX_STRICT_PROXY,
            host_dependency::LINUX_CGROUP_V2,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: mxc_bwrap.clone(),
            read_write: mxc_bwrap.clone(),
            deny: mxc_bwrap.clone(),
            workspace: mxc_bwrap.clone(),
        },
        process: ProcessCapabilities {
            command: dep_support(host_dependency::MXC_EXECUTOR),
            working_dir: dep_support(host_dependency::MXC_EXECUTOR),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::AxisOwned,
            isolated_identity: CapabilitySupport::unsupported(
                "MXC bubblewrap isolated identity semantics are not yet proven",
            ),
            syscall_filtering: dep_support(host_dependency::AXIS_SECCOMP_LAUNCHER),
            pty: CapabilitySupport::unsupported("MXC bubblewrap PTY support is not mapped by AXIS"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: dep_support(host_dependency::MXC_EXECUTOR),
            block: mxc_bwrap,
            strict_proxy: dep_support(host_dependency::LINUX_STRICT_PROXY),
            cooperative_proxy: CapabilitySupport::weaker(
                "MXC cooperative proxy relies on proxy environment variables and cannot stop direct sockets",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: dep_support(host_dependency::LINUX_SECCOMP_NOTIFY),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::AxisOwned,
            memory: CapabilitySupport::AxisOwned,
            cpu: CapabilitySupport::AxisOwned,
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: one_shot_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::AxisOwned,
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: dep_support(host_dependency::MXC_EXECUTOR),
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::AxisOwned,
        },
    }
}

fn mxc_linux_lxc() -> BackendCapabilities {
    let mxc_lxc = deps_support([host_dependency::MXC_EXECUTOR, host_dependency::LINUX_LXC]);
    let cgroups = dep_support(host_dependency::LINUX_CGROUP_V2);

    BackendCapabilities {
        platform: BackendPlatform::Linux,
        name: BackendCapabilityMapId::MxcLinuxLxc.as_str().into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::MXC_EXECUTOR,
            host_dependency::LINUX_LXC,
            host_dependency::LINUX_CGROUP_V2,
            host_dependency::LINUX_NETNS,
            host_dependency::LINUX_SECCOMP_NOTIFY,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: mxc_lxc.clone(),
            read_write: mxc_lxc.clone(),
            deny: mxc_lxc.clone(),
            workspace: mxc_lxc.clone(),
        },
        process: ProcessCapabilities {
            command: mxc_lxc.clone(),
            working_dir: mxc_lxc.clone(),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: mxc_lxc.clone(),
            isolated_identity: mxc_lxc.clone(),
            syscall_filtering: CapabilitySupport::weaker(
                "LXC profile support is host configuration dependent and not yet proven against the AXIS syscall matrix",
            ),
            pty: CapabilitySupport::unsupported("MXC LXC PTY support is not mapped by AXIS"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: mxc_lxc.clone(),
            block: mxc_lxc.clone(),
            strict_proxy: deps_support([
                host_dependency::MXC_EXECUTOR,
                host_dependency::LINUX_LXC,
                host_dependency::LINUX_NETNS,
            ]),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy behavior is not a fail-closed network boundary",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: dep_support(host_dependency::LINUX_SECCOMP_NOTIFY),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: cgroups.clone(),
            memory: cgroups.clone(),
            cpu: cgroups.clone(),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: stateful_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: mxc_lxc.clone(),
            resources: cgroups,
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: mxc_lxc,
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: dep_support(host_dependency::LINUX_SECCOMP_NOTIFY),
        },
    }
}

fn mxc_linux_microvm() -> BackendCapabilities {
    microvm_backend(
        BackendCapabilityMapId::MxcLinuxMicrovm,
        BackendPlatform::Linux,
        BackendStability::Experimental,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::LINUX_KVM,
            host_dependency::MXC_MICROVM_RUNTIME,
        ],
    )
}

fn mxc_linux_hyperlight() -> BackendCapabilities {
    vm_backend(
        BackendCapabilityMapId::MxcLinuxHyperlight,
        BackendPlatform::Linux,
        BackendStability::Experimental,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::LINUX_KVM,
            host_dependency::MXC_HYPERLIGHT_RUNTIME,
        ],
    )
}

fn axis_native_macos_seatbelt() -> BackendCapabilities {
    let seatbelt = dep_support(host_dependency::MACOS_SEATBELT);

    BackendCapabilities {
        platform: BackendPlatform::Macos,
        name: BackendCapabilityMapId::AxisNativeMacosSeatbelt
            .as_str()
            .into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::MACOS_SEATBELT,
            host_dependency::MACOS_XCODE_CLT,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: seatbelt.clone(),
            read_write: seatbelt.clone(),
            deny: seatbelt.clone(),
            workspace: seatbelt.clone(),
        },
        process: ProcessCapabilities {
            command: CapabilitySupport::Exact,
            working_dir: CapabilitySupport::Exact,
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "macOS run_as_user parity is not part of the current AXIS contract",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "Seatbelt does not create a distinct process identity",
            ),
            syscall_filtering: CapabilitySupport::unsupported(
                "Seatbelt profiles do not expose seccomp-style syscall filtering",
            ),
            pty: CapabilitySupport::unsupported("macOS PTY support is not mapped by AXIS"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: CapabilitySupport::Exact,
            block: seatbelt.clone(),
            strict_proxy: CapabilitySupport::weaker(
                "Seatbelt can deny direct network access but AXIS has not mapped a non-bypass proxy route",
            ),
            cooperative_proxy: CapabilitySupport::weaker(
                "proxy environment variables are advisory and can be ignored by clients",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "connect-time executable attribution is not implemented for macOS",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::weaker(
                "macOS rlimits can bound processes but do not provide cgroup-style tree accounting",
            ),
            memory: CapabilitySupport::unsupported(
                "memory enforcement is not mapped for the macOS native backend",
            ),
            cpu: CapabilitySupport::unsupported(
                "CPU quota enforcement is not mapped for the macOS native backend",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: one_shot_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::weaker(
                "resource cleanup is limited to process-tree cleanup without native cgroup state",
            ),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: CapabilitySupport::AxisOwned,
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::unsupported(
                "macOS bypass evidence collection is not mapped",
            ),
        },
    }
}

fn mxc_macos_seatbelt() -> BackendCapabilities {
    let mxc_seatbelt = deps_support([
        host_dependency::MXC_EXECUTOR,
        host_dependency::MACOS_SEATBELT,
    ]);

    BackendCapabilities {
        platform: BackendPlatform::Macos,
        name: BackendCapabilityMapId::MxcMacosSeatbelt.as_str().into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::MXC_EXECUTOR,
            host_dependency::MACOS_SEATBELT,
            host_dependency::MACOS_XCODE_CLT,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: mxc_seatbelt.clone(),
            read_write: mxc_seatbelt.clone(),
            deny: mxc_seatbelt.clone(),
            workspace: mxc_seatbelt.clone(),
        },
        process: ProcessCapabilities {
            command: dep_support(host_dependency::MXC_EXECUTOR),
            working_dir: dep_support(host_dependency::MXC_EXECUTOR),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "MXC Seatbelt run_as_user parity is not mapped by AXIS",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "MXC Seatbelt isolated identity semantics are not mapped",
            ),
            syscall_filtering: CapabilitySupport::unsupported(
                "Seatbelt does not provide AXIS seccomp-style syscall filtering",
            ),
            pty: CapabilitySupport::unsupported("MXC Seatbelt PTY support is not mapped by AXIS"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: mxc_seatbelt.clone(),
            block: mxc_seatbelt.clone(),
            strict_proxy: CapabilitySupport::weaker(
                "MXC Seatbelt proxy support is not proven as a strict AXIS proxy boundary",
            ),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy environment variables cannot prevent direct clients from bypassing policy",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "connect-time executable attribution is not implemented for MXC Seatbelt",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::weaker(
                "MXC Seatbelt process limits are not proven to match AXIS tree accounting",
            ),
            memory: CapabilitySupport::unsupported("MXC Seatbelt memory enforcement is not mapped"),
            cpu: CapabilitySupport::unsupported("MXC Seatbelt CPU quota enforcement is not mapped"),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: one_shot_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::weaker(
                "resource cleanup is limited to process-tree cleanup without backend resource state",
            ),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: dep_support(host_dependency::MXC_EXECUTOR),
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::unsupported(
                "macOS bypass evidence collection is not mapped",
            ),
        },
    }
}

fn axis_native_windows() -> BackendCapabilities {
    let unavailable = CapabilitySupport::unsupported(
        "native Windows containment is disabled until restricted-token, Job Object, filesystem, and network controls are applied to the spawned process",
    );

    BackendCapabilities {
        platform: BackendPlatform::Windows,
        name: BackendCapabilityMapId::AxisNativeWindows.as_str().into(),
        stability: BackendStability::Experimental,
        host_dependencies: deps([
            host_dependency::WINDOWS_JOBOBJECT,
            host_dependency::WINDOWS_LOW_INTEGRITY,
            host_dependency::WINDOWS_PROCESS_CONTAINER,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: unavailable.clone(),
            read_write: unavailable.clone(),
            deny: unavailable.clone(),
            workspace: unavailable.clone(),
        },
        process: ProcessCapabilities {
            command: unavailable.clone(),
            working_dir: unavailable.clone(),
            environment: unavailable.clone(),
            stdio: unavailable.clone(),
            user_identity: unavailable.clone(),
            isolated_identity: unavailable.clone(),
            syscall_filtering: unavailable.clone(),
            pty: unavailable.clone(),
            timeout: unavailable.clone(),
        },
        network: NetworkCapabilities {
            allow: unavailable.clone(),
            block: unavailable.clone(),
            strict_proxy: unavailable.clone(),
            cooperative_proxy: unavailable.clone(),
            endpoint_policy: unavailable.clone(),
            binary_attribution: unavailable.clone(),
            l7_policy: unavailable.clone(),
        },
        resources: ResourceCapabilities {
            process_count: unavailable.clone(),
            memory: unavailable.clone(),
            cpu: unavailable.clone(),
            timeout: unavailable.clone(),
        },
        credentials: CredentialCapabilities {
            secret_filtering: unavailable.clone(),
            host_boundary_injection: unavailable.clone(),
            placeholder_projection: unavailable.clone(),
        },
        inference: InferenceCapabilities {
            inference_local: unavailable.clone(),
            external_provider: unavailable.clone(),
            streaming: unavailable.clone(),
        },
        lifecycle: LifecycleCapabilities {
            start: unavailable.clone(),
            exec: unavailable.clone(),
            destroy: unavailable.clone(),
            stateful: unavailable.clone(),
        },
        cleanup: CleanupCapabilities {
            process_tree: unavailable.clone(),
            resources: unavailable.clone(),
            temp_state: unavailable.clone(),
            backend_state: unavailable.clone(),
        },
        audit: AuditCapabilities {
            denials: unavailable.clone(),
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: unavailable,
        },
    }
}

fn mxc_windows_processcontainer() -> BackendCapabilities {
    let processcontainer = deps_support([
        host_dependency::MXC_EXECUTOR,
        host_dependency::WINDOWS_PROCESS_CONTAINER,
        host_dependency::WINDOWS_JOBOBJECT,
    ]);

    BackendCapabilities {
        platform: BackendPlatform::Windows,
        name: BackendCapabilityMapId::MxcWindowsProcessContainer
            .as_str()
            .into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_PROCESS_CONTAINER,
            host_dependency::WINDOWS_JOBOBJECT,
            host_dependency::WINDOWS_WFP_BROKER,
        ]),
        filesystem: FilesystemCapabilities {
            read_only: processcontainer.clone(),
            read_write: processcontainer.clone(),
            deny: CapabilitySupport::unsupported(
                "MXC ProcessContainer deniedPaths support depends on the selected Windows isolation tier and is not uniformly enforceable",
            ),
            workspace: processcontainer.clone(),
        },
        process: ProcessCapabilities {
            command: dep_support(host_dependency::MXC_EXECUTOR),
            working_dir: dep_support(host_dependency::MXC_EXECUTOR),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "MXC ProcessContainer cannot map a caller-named host account",
            ),
            isolated_identity: processcontainer.clone(),
            syscall_filtering: CapabilitySupport::unsupported(
                "ProcessContainer does not provide AXIS seccomp-style syscall filtering",
            ),
            pty: CapabilitySupport::unsupported(
                "the BaseContainer launch API rejects pseudoconsole handles, and AXIS does not force the older AppContainer/DACL tier to obtain ConPTY support",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: processcontainer.clone(),
            block: processcontainer.clone(),
            strict_proxy: deps_support([
                host_dependency::MXC_EXECUTOR,
                host_dependency::WINDOWS_PROCESS_CONTAINER,
                host_dependency::WINDOWS_WFP_BROKER,
            ]),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy environment variables cannot prevent direct socket bypass",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "SID-scoped WFP filters prove the sandbox boundary but not the initiating image; user-mode PID/tuple lookup is raceable through PID reuse and short-lived connects, so per-binary rules remain fail-closed without ALE process metadata or a callout",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: dep_support(host_dependency::WINDOWS_JOBOBJECT),
            memory: dep_support(host_dependency::WINDOWS_JOBOBJECT),
            cpu: dep_support(host_dependency::WINDOWS_JOBOBJECT),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: one_shot_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: dep_support(host_dependency::WINDOWS_JOBOBJECT),
            resources: dep_support(host_dependency::WINDOWS_JOBOBJECT),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: dep_support(host_dependency::MXC_EXECUTOR),
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: dep_support(host_dependency::WINDOWS_WFP_BROKER),
        },
    }
}

fn mxc_windows_isolation_session() -> BackendCapabilities {
    let mut backend = windows_vm_like_backend(
        BackendCapabilityMapId::MxcWindowsIsolationSession,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_ISOLATION_SESSION,
        ],
        BackendStability::Preview,
    );
    backend.filesystem.deny = CapabilitySupport::unsupported(
        "MXC Isolation Session rejects deniedPaths; only read-only and read-write shares are mapped",
    );
    backend.network.allow = CapabilitySupport::unsupported(
        "MXC Isolation Session rejects allow-mode network policy; only default block is mapped",
    );
    backend.network.strict_proxy = CapabilitySupport::unsupported(
        "MXC Isolation Session does not expose AXIS strict proxy routing",
    );
    backend
}

fn mxc_windows_sandbox() -> BackendCapabilities {
    let mut backend = windows_vm_like_backend(
        BackendCapabilityMapId::MxcWindowsSandbox,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_SANDBOX,
        ],
        BackendStability::Preview,
    );
    backend.filesystem.read_only = CapabilitySupport::unsupported(
        "MXC Windows Sandbox ignores shared filesystem policy sections",
    );
    backend.filesystem.read_write = CapabilitySupport::unsupported(
        "MXC Windows Sandbox ignores shared filesystem policy sections",
    );
    backend.filesystem.deny = CapabilitySupport::unsupported(
        "MXC Windows Sandbox ignores shared filesystem policy sections",
    );
    backend.network.allow = CapabilitySupport::unsupported(
        "MXC Windows Sandbox does not expose allow-mode AXIS network policy; guest firewall lockdown is block-oriented",
    );
    backend.network.strict_proxy = CapabilitySupport::unsupported(
        "MXC Windows Sandbox does not expose AXIS strict proxy routing",
    );
    backend
}

fn mxc_windows_wslc() -> BackendCapabilities {
    let wslc = deps_support([host_dependency::MXC_EXECUTOR, host_dependency::WINDOWS_WSL2]);

    BackendCapabilities {
        platform: BackendPlatform::Windows,
        name: BackendCapabilityMapId::MxcWindowsWslc.as_str().into(),
        stability: BackendStability::Preview,
        host_dependencies: deps([host_dependency::MXC_EXECUTOR, host_dependency::WINDOWS_WSL2]),
        filesystem: FilesystemCapabilities {
            read_only: wslc.clone(),
            read_write: wslc.clone(),
            deny: CapabilitySupport::unsupported(
                "MXC WSLC denied-path enforcement is not mapped exactly for Windows host paths",
            ),
            workspace: wslc.clone(),
        },
        process: ProcessCapabilities {
            command: wslc.clone(),
            working_dir: wslc.clone(),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "WSL identity mapping is not planned as AXIS run_as_user parity",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "WSLC isolated identity semantics are not yet mapped",
            ),
            syscall_filtering: CapabilitySupport::unsupported(
                "MXC WSLC syscall behavior is not mapped to the AXIS seccomp contract",
            ),
            pty: CapabilitySupport::unsupported("MXC WSLC PTY support is not mapped"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: wslc.clone(),
            block: CapabilitySupport::unsupported(
                "MXC WSLC network block is not mapped as an exact AXIS host network boundary",
            ),
            strict_proxy: CapabilitySupport::unsupported(
                "MXC WSLC strict proxy routing is not mapped as a fail-closed AXIS boundary",
            ),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy environment variables cannot prevent direct socket bypass",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "connect-time executable attribution is not implemented for MXC WSLC",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::unsupported(
                "MXC WSLC process limits are not mapped to exact AXIS per-sandbox tree limits",
            ),
            memory: CapabilitySupport::unsupported(
                "MXC WSLC memory limits are VM-scoped rather than exact AXIS per-sandbox policy",
            ),
            cpu: CapabilitySupport::unsupported(
                "MXC WSLC CPU limits are VM-scoped rather than exact AXIS per-sandbox policy",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: stateful_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::unsupported(
                "MXC WSLC resource cleanup is not mapped to exact per-sandbox AXIS resource state",
            ),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: dep_support(host_dependency::MXC_EXECUTOR),
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::unsupported(
                "WSL bypass evidence collection is not mapped",
            ),
        },
    }
}

fn mxc_windows_microvm() -> BackendCapabilities {
    microvm_backend(
        BackendCapabilityMapId::MxcWindowsMicrovm,
        BackendPlatform::Windows,
        BackendStability::Experimental,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_WHP,
            host_dependency::MXC_MICROVM_RUNTIME,
        ],
    )
}

fn mxc_windows_hyperlight() -> BackendCapabilities {
    windows_vm_like_backend(
        BackendCapabilityMapId::MxcWindowsHyperlight,
        [
            host_dependency::MXC_EXECUTOR,
            host_dependency::WINDOWS_WHP,
            host_dependency::WINDOWS_HYPERLIGHT_RUNTIME,
        ],
        BackendStability::Experimental,
    )
}

fn vm_backend<const N: usize>(
    id: BackendCapabilityMapId,
    platform: BackendPlatform,
    stability: BackendStability,
    dependency_names: [&'static str; N],
) -> BackendCapabilities {
    let vm = deps_support(dependency_names);

    BackendCapabilities {
        platform,
        name: id.as_str().into(),
        stability,
        host_dependencies: deps(dependency_names),
        filesystem: FilesystemCapabilities {
            read_only: vm.clone(),
            read_write: vm.clone(),
            deny: vm.clone(),
            workspace: vm.clone(),
        },
        process: ProcessCapabilities {
            command: vm.clone(),
            working_dir: vm.clone(),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "VM identity mapping is not planned as AXIS run_as_user parity",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "VM guest identity is not yet mapped to the portable process identity contract",
            ),
            syscall_filtering: CapabilitySupport::unsupported(
                "VM backends isolate the guest but do not expose the AXIS per-process syscall contract",
            ),
            pty: CapabilitySupport::unsupported("VM backend PTY support is not mapped by AXIS"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: vm.clone(),
            block: vm.clone(),
            strict_proxy: CapabilitySupport::weaker(
                "VM network isolation can be strong, but AXIS strict proxy routing and bypass evidence are not mapped",
            ),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy environment variables cannot prevent direct socket bypass",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "connect-time executable attribution is not implemented for VM backends",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::unsupported(
                "VM process limits are not mapped to exact AXIS per-sandbox process-tree limits",
            ),
            memory: CapabilitySupport::unsupported(
                "VM memory limits are not carried in the AXIS VM execution spec yet",
            ),
            cpu: CapabilitySupport::unsupported(
                "VM CPU limits are not carried in the AXIS VM execution spec yet",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: stateful_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::unsupported(
                "VM resource cleanup is not mapped for per-sandbox AXIS resource limits",
            ),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: vm,
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::unsupported(
                "VM bypass evidence collection is not mapped to AXIS audit records",
            ),
        },
    }
}

fn microvm_backend<const N: usize>(
    id: BackendCapabilityMapId,
    platform: BackendPlatform,
    stability: BackendStability,
    dependency_names: [&'static str; N],
) -> BackendCapabilities {
    let mut backend = vm_backend(id, platform, stability, dependency_names);
    backend.filesystem.deny = CapabilitySupport::unsupported(
        "MXC Nanvix MicroVM rejects deniedPaths; only read-only and read-write staging paths are mapped",
    );
    backend.network.allow = CapabilitySupport::unsupported(
        "MXC Nanvix MicroVM has no network stack and cannot represent allow-mode network policy",
    );
    backend.network.strict_proxy = CapabilitySupport::unsupported(
        "MXC Nanvix MicroVM has no network stack and cannot reach an AXIS strict proxy",
    );
    backend
}

fn windows_vm_like_backend<const N: usize>(
    id: BackendCapabilityMapId,
    dependency_names: [&'static str; N],
    stability: BackendStability,
) -> BackendCapabilities {
    let vm = deps_support(dependency_names);

    BackendCapabilities {
        platform: BackendPlatform::Windows,
        name: id.as_str().into(),
        stability,
        host_dependencies: deps(dependency_names),
        filesystem: FilesystemCapabilities {
            read_only: vm.clone(),
            read_write: vm.clone(),
            deny: vm.clone(),
            workspace: vm.clone(),
        },
        process: ProcessCapabilities {
            command: vm.clone(),
            working_dir: vm.clone(),
            environment: CapabilitySupport::AxisOwned,
            stdio: CapabilitySupport::AxisOwned,
            user_identity: CapabilitySupport::unsupported(
                "Windows VM-style identity mapping is not planned as AXIS run_as_user parity",
            ),
            isolated_identity: CapabilitySupport::unsupported(
                "Windows VM-style guest identity is not mapped to the portable process identity contract",
            ),
            syscall_filtering: CapabilitySupport::unsupported(
                "Windows VM-style backends do not expose AXIS seccomp-style syscall filtering",
            ),
            pty: CapabilitySupport::unsupported("Windows VM-style PTY support is not mapped"),
            timeout: CapabilitySupport::AxisOwned,
        },
        network: NetworkCapabilities {
            allow: vm.clone(),
            block: vm.clone(),
            strict_proxy: CapabilitySupport::weaker(
                "Windows VM-style networking can isolate guests, but AXIS strict proxy routing is not mapped",
            ),
            cooperative_proxy: CapabilitySupport::weaker(
                "cooperative proxy environment variables cannot prevent direct socket bypass",
            ),
            endpoint_policy: CapabilitySupport::AxisOwned,
            binary_attribution: CapabilitySupport::unsupported(
                "connect-time executable attribution is not implemented for Windows VM-style backends",
            ),
            l7_policy: unsupported_l7_policy(),
        },
        resources: ResourceCapabilities {
            process_count: CapabilitySupport::unsupported(
                "Windows VM-style process limits are not mapped to exact AXIS per-sandbox process-tree limits",
            ),
            memory: CapabilitySupport::unsupported(
                "Windows VM-style memory limits are not carried in the AXIS VM execution spec yet",
            ),
            cpu: CapabilitySupport::unsupported(
                "Windows VM-style CPU limits are not carried in the AXIS VM execution spec yet",
            ),
            timeout: CapabilitySupport::AxisOwned,
        },
        credentials: axis_credentials(),
        inference: axis_inference(),
        lifecycle: stateful_lifecycle(),
        cleanup: CleanupCapabilities {
            process_tree: CapabilitySupport::AxisOwned,
            resources: CapabilitySupport::unsupported(
                "Windows VM-style resource cleanup is not mapped for per-sandbox AXIS resource limits",
            ),
            temp_state: CapabilitySupport::AxisOwned,
            backend_state: vm,
        },
        audit: AuditCapabilities {
            denials: CapabilitySupport::AxisOwned,
            dependency_reasons: CapabilitySupport::AxisOwned,
            bypass_evidence: CapabilitySupport::unsupported(
                "Windows VM-style bypass evidence collection is not mapped",
            ),
        },
    }
}

fn axis_credentials() -> CredentialCapabilities {
    CredentialCapabilities {
        secret_filtering: CapabilitySupport::AxisOwned,
        host_boundary_injection: CapabilitySupport::AxisOwned,
        placeholder_projection: CapabilitySupport::AxisOwned,
    }
}

fn unsupported_l7_policy() -> CapabilitySupport {
    CapabilitySupport::unsupported("L7 method/path policy is not enforced")
}

fn axis_inference() -> InferenceCapabilities {
    InferenceCapabilities {
        inference_local: CapabilitySupport::AxisOwned,
        external_provider: CapabilitySupport::AxisOwned,
        streaming: CapabilitySupport::AxisOwned,
    }
}

fn one_shot_lifecycle() -> LifecycleCapabilities {
    LifecycleCapabilities {
        start: CapabilitySupport::Exact,
        exec: CapabilitySupport::unsupported("backend is planned as one-shot execution"),
        destroy: CapabilitySupport::AxisOwned,
        stateful: CapabilitySupport::unsupported(
            "stateful sessions are not mapped for this backend",
        ),
    }
}

fn stateful_lifecycle() -> LifecycleCapabilities {
    LifecycleCapabilities {
        start: CapabilitySupport::Exact,
        exec: CapabilitySupport::Exact,
        destroy: CapabilitySupport::Exact,
        stateful: CapabilitySupport::Exact,
    }
}

fn deps_support<const N: usize>(names: [&'static str; N]) -> CapabilitySupport {
    CapabilitySupport::with_dependencies(names)
}

fn dep_support(name: &'static str) -> CapabilitySupport {
    CapabilitySupport::with_dependency(name)
}

fn deps<const N: usize>(names: [&'static str; N]) -> Vec<HostDependency> {
    names.into_iter().map(host_dependency_for).collect()
}

fn host_dependency_for(name: &'static str) -> HostDependency {
    let description = match name {
        host_dependency::AXIS_NETNS_HELPER => {
            "optional AXIS helper for strict Linux proxy network namespace setup"
        }
        host_dependency::AXIS_SECCOMP_LAUNCHER => {
            "AXIS launcher artifact that applies the generated seccomp filter before exec"
        }
        host_dependency::LINUX_BUBBLEWRAP => "trusted Bubblewrap executable on PATH",
        host_dependency::LINUX_CGROUP_V2 => {
            "delegated cgroup v2 subtree writable by the test or runtime user"
        }
        host_dependency::LINUX_KVM => "readable and writable /dev/kvm for the runtime user",
        host_dependency::LINUX_LANDLOCK => "Linux kernel with Landlock ABI v3 or newer",
        host_dependency::LINUX_LXC => "prepared LXC runtime usable by the current user",
        host_dependency::LINUX_NETNS => "Linux network namespace and veth support",
        host_dependency::LINUX_SECCOMP_BPF => "Linux seccomp-BPF filter support",
        host_dependency::LINUX_SECCOMP_NOTIFY => "Linux seccomp user notification support",
        host_dependency::LINUX_STRICT_PROXY => {
            "AXIS strict proxy boundary selected after network namespace, firewall, and privilege checks"
        }
        host_dependency::LINUX_USERNS => "unprivileged user namespace support",
        host_dependency::MACOS_SEATBELT => "macOS Seatbelt profile execution support",
        host_dependency::MACOS_XCODE_CLT => {
            "Xcode Command Line Tools for profile tooling and platform test builds"
        }
        host_dependency::MXC_EXECUTOR => "packaged MXC executor resolved from a safe install path",
        host_dependency::MXC_HYPERLIGHT_RUNTIME => "MXC Hyperlight runtime artifact",
        host_dependency::MXC_MICROVM_RUNTIME => "MXC microVM runtime artifact",
        host_dependency::WINDOWS_HYPERLIGHT_RUNTIME => "Windows Hyperlight runtime feature",
        host_dependency::WINDOWS_ISOLATION_SESSION => "Windows Isolation Session feature",
        host_dependency::WINDOWS_JOBOBJECT => "Windows Job Object resource enforcement",
        host_dependency::WINDOWS_LOW_INTEGRITY => "Windows low-integrity token support",
        host_dependency::WINDOWS_PROCESS_CONTAINER => "Windows ProcessContainer support",
        host_dependency::WINDOWS_WFP_BROKER => {
            "installed AXIS WFP broker service with a reachable lease pipe"
        }
        host_dependency::WINDOWS_SANDBOX => "Windows Sandbox optional feature",
        host_dependency::WINDOWS_WHP => "Windows Hypervisor Platform feature",
        host_dependency::WINDOWS_WSL2 => "Windows Subsystem for Linux 2 feature",
        _ => panic!("unknown host dependency {name}"),
    };
    HostDependency::new(name, description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        BackendPlanOutcome, DependencyState, PlannerOptions, RuntimeProbeSnapshot,
        plan_backend_policy,
    };
    use crate::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, Policy,
        ProcessPolicy, SshPolicy,
    };

    #[test]
    fn every_backend_map_validates() {
        let maps = all_backend_capability_maps();

        assert_eq!(maps.len(), BACKEND_CAPABILITY_MAP_IDS.len());
        for backend in maps {
            validate_backend_capability_map(&backend)
                .unwrap_or_else(|problems| panic!("{}: {problems:?}", backend.name));
        }
    }

    #[test]
    fn no_backend_advertises_unenforced_l7_policy() {
        for backend in all_backend_capability_maps() {
            assert!(
                matches!(
                    backend.network.l7_policy,
                    CapabilitySupport::Unsupported { .. }
                ),
                "{} advertised L7 policy support",
                backend.name
            );
        }
    }

    #[test]
    fn catalog_covers_required_platform_backends() {
        let names = all_backend_capability_maps()
            .into_iter()
            .map(|backend| backend.name)
            .collect::<BTreeSet<_>>();

        for expected in [
            "axis-native-linux",
            "mxc-linux-bubblewrap",
            "mxc-linux-lxc",
            "mxc-linux-microvm",
            "mxc-linux-hyperlight",
            "axis-native-macos-seatbelt",
            "mxc-macos-seatbelt",
            "axis-native-windows",
            "mxc-windows-processcontainer",
            "mxc-windows-isolation-session",
            "mxc-windows-sandbox",
            "mxc-windows-wslc",
            "mxc-windows-microvm",
            "mxc-windows-hyperlight",
        ] {
            assert!(names.contains(expected), "missing backend map {expected}");
        }
    }

    #[test]
    fn catalog_exposes_required_host_dependencies() {
        let dependencies = all_backend_capability_maps()
            .into_iter()
            .flat_map(|backend| backend.host_dependencies)
            .map(|dependency| dependency.name)
            .collect::<BTreeSet<_>>();

        for expected in [
            host_dependency::WINDOWS_SANDBOX,
            host_dependency::WINDOWS_WSL2,
            host_dependency::WINDOWS_WHP,
            host_dependency::LINUX_KVM,
            host_dependency::LINUX_LXC,
            host_dependency::LINUX_BUBBLEWRAP,
            host_dependency::MACOS_XCODE_CLT,
            host_dependency::LINUX_CGROUP_V2,
            host_dependency::LINUX_STRICT_PROXY,
            host_dependency::LINUX_USERNS,
            host_dependency::MXC_EXECUTOR,
            host_dependency::MXC_HYPERLIGHT_RUNTIME,
            host_dependency::MXC_MICROVM_RUNTIME,
        ] {
            assert!(
                dependencies.contains(expected),
                "missing host dependency {expected}"
            );
        }
    }

    #[test]
    fn maps_round_trip_through_json() {
        let maps = all_backend_capability_maps();
        let json = serde_json::to_string(&maps).unwrap();
        let parsed: Vec<BackendCapabilities> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, maps);
    }

    #[test]
    fn maps_can_be_filtered_by_platform_and_name() {
        let linux = backend_capability_maps_for_platform(BackendPlatform::Linux);

        assert_eq!(linux.len(), 5);
        assert!(
            linux
                .iter()
                .all(|backend| backend.platform == BackendPlatform::Linux)
        );
        assert_eq!(
            backend_capability_map_by_name("mxc-linux-bubblewrap")
                .unwrap()
                .name,
            "mxc-linux-bubblewrap"
        );
        assert!(backend_capability_map_by_name("missing-backend").is_none());
    }

    #[test]
    fn planner_accepts_present_dependencies_from_backend_map() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present);
        let plan = plan_backend_policy(
            &policy(NetworkMode::Block),
            &backend,
            &runtime,
            &PlannerOptions::new(),
        );

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::ExactWithHostDependency { .. }
        ));
        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
    }

    #[test]
    fn native_windows_rejects_launch_until_confinement_is_applied() {
        let backend = backend_capability_map(BackendCapabilityMapId::AxisNativeWindows);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::WINDOWS_JOBOBJECT, DependencyState::Present)
            .with_dependency(
                host_dependency::WINDOWS_LOW_INTEGRITY,
                DependencyState::Present,
            )
            .with_dependency(
                host_dependency::WINDOWS_PROCESS_CONTAINER,
                DependencyState::Present,
            );
        let plan = plan_backend_policy(
            &policy(NetworkMode::Block),
            &backend,
            &runtime,
            &PlannerOptions::new(),
        );

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("native Windows containment is disabled")
        );
    }

    #[test]
    fn planner_reports_missing_dependency_from_backend_map() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present);
        let plan = plan_backend_policy(
            &policy(NetworkMode::Block),
            &backend,
            &runtime,
            &PlannerOptions::new(),
        );

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.block"));
        assert!(error.contains(host_dependency::LINUX_BUBBLEWRAP));
        assert!(error.contains("missing host dependency"));
    }

    #[test]
    fn planner_reports_malformed_dependency_from_fake_probe() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::LINUX_BUBBLEWRAP,
                DependencyState::Malformed,
            );
        let plan = plan_backend_policy(
            &policy(NetworkMode::Block),
            &backend,
            &runtime,
            &PlannerOptions::new(),
        );

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains(host_dependency::LINUX_BUBBLEWRAP));
        assert!(error.contains("malformed"));
    }

    #[test]
    fn planner_reports_permission_denied_dependency_from_fake_probe() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxMicrovm);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::MXC_MICROVM_RUNTIME,
                DependencyState::Present,
            )
            .with_dependency(
                host_dependency::LINUX_KVM,
                DependencyState::PermissionDenied,
            );
        let plan = plan_backend_policy(
            &policy(NetworkMode::Block),
            &backend,
            &runtime,
            &PlannerOptions::new(),
        );

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains(host_dependency::LINUX_KVM));
        assert!(error.contains("permission-denied"));
    }

    #[test]
    fn weaker_capability_requires_explicit_acceptance() {
        let backend = backend_capability_map(BackendCapabilityMapId::AxisNativeMacosSeatbelt);
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);
        let mut policy = policy(NetworkMode::Allow);
        policy.process.max_processes = 32;
        let plan = plan_backend_policy(&policy, &backend, &runtime, &PlannerOptions::new());

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::WeakerOnly {
                accepted: false,
                ..
            }
        ));
        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("backend offers only weaker behavior")
        );
    }

    #[test]
    fn unsupported_capability_fails_before_spawn() {
        let backend = backend_capability_map(BackendCapabilityMapId::AxisNativeMacosSeatbelt);
        let mut policy = policy(NetworkMode::Allow);
        policy.process.blocked_syscalls.push("ptrace".into());
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);
        let plan = plan_backend_policy(&policy, &backend, &runtime, &PlannerOptions::new());

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(!plan.spawn_allowed());
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("process.syscall_filtering")
        );
    }

    #[test]
    fn validation_rejects_undeclared_dependency() {
        let mut backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        backend.network.block = CapabilitySupport::with_dependency("undeclared");

        let problems = validate_backend_capability_map(&backend).unwrap_err();

        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("undeclared dependency 'undeclared'")),
            "{problems:?}"
        );
    }

    #[test]
    fn validation_rejects_empty_reasons() {
        let mut backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        backend.network.strict_proxy = CapabilitySupport::weaker("");
        backend.process.pty = CapabilitySupport::unsupported("");

        let problems = validate_backend_capability_map(&backend).unwrap_err();

        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("weaker support must include a reason")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("unsupported support must include a reason")),
            "{problems:?}"
        );
    }

    #[test]
    fn validation_rejects_duplicate_dependency_declarations() {
        let mut backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);
        backend
            .host_dependencies
            .push(host_dependency_for(host_dependency::MXC_EXECUTOR));

        let problems = validate_backend_capability_map(&backend).unwrap_err();

        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("duplicate dependency")),
            "{problems:?}"
        );
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "map-test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into()],
                read_write: vec!["{workspace}".into()],
                deny: Vec::new(),
                compatibility: Default::default(),
                workspace_read_only: false,
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                run_as_user: None,
                blocked_syscalls: Vec::new(),
                identity: Default::default(),
                child_processes: Default::default(),
                timeout_sec: None,
            },
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
}
