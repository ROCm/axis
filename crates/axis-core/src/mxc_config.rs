// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MXC wire configuration shapes.
//!
//! This module keeps MXC JSON generation platform-neutral where the shared
//! backend planner has already approved the AXIS policy and launch inputs.
//! Platform adapters remain responsible for spawning executors and for any
//! AXIS-owned layers around the MXC process.

use crate::container_backend::{
    ContainerBackendConfigFormat, ContainerBackendExecutionSpec, ContainerBackendNetworkMode,
    ContainerMountAccess, ContainerRootfsSource,
};
use crate::process_backend::{
    ProcessBackendConfigFormat, ProcessBackendExecutionSpec, ProcessBackendNetworkMode,
};
use crate::sandbox_env;
use crate::vm_backend::{
    VmBackendConfigFormat, VmBackendExecutionSpec, VmBackendNetworkMode, VmImageSource,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const MXC_CONFIG_VERSION: &str = "0.6.0-alpha";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MxcConfigError {
    #[error("MXC process command line must not be empty")]
    EmptyCommandLine,

    #[error("MXC process environment entry must be KEY=VALUE with a non-empty key")]
    InvalidEnvironmentEntry,

    #[error("MXC process environment entry is filtered by AXIS sandbox policy: {key}")]
    FilteredEnvironmentEntry { key: String },

    #[error(
        "AXIS strict proxy must be enforced outside MXC before emitting allow-mode MXC network config"
    )]
    StrictProxyRequiresAxisLayer,

    #[error("MXC config cannot represent endpoint policies outside AXIS strict proxy mode")]
    EndpointPolicyRequiresStrictProxy,

    #[error("MXC process config cannot use native AXIS backend '{backend}'")]
    NativeProcessBackendUnsupported { backend: String },

    #[error("MXC process timeout {timeout_ms}ms exceeds the MXC wire limit")]
    ProcessTimeoutOverflow { timeout_ms: u64 },

    #[error(
        "AXIS process resource limits must be enforced outside MXC before emitting process config"
    )]
    ProcessResourceLimitsRequireAxisLayer,

    #[error("MXC LXC config requires a distribution/release rootfs source")]
    LxcRootfsRequired,

    #[error("MXC WSLC config requires a WSL image or image tar rootfs source")]
    WslcImageRequired,

    #[error("MXC WSLC config cannot represent AXIS container bind mounts")]
    WslcBindMountsUnsupported,

    #[error("MXC WSLC config cannot represent AXIS denied paths exactly")]
    WslcDeniedPathsUnsupported,

    #[error("MXC WSLC config cannot represent AXIS network mode '{mode:?}' exactly")]
    WslcNetworkModeUnsupported { mode: ContainerBackendNetworkMode },

    #[error(
        "AXIS container resource limits must be enforced outside MXC before emitting container config"
    )]
    ContainerResourceLimitsRequireAxisLayer,

    #[error(
        "MXC container config cannot represent bind mount aliases: {host_path} -> {container_path}"
    )]
    BindMountAliasUnsupported {
        host_path: String,
        container_path: String,
    },

    #[error(
        "MXC container config bind mount '{host_path}' is not granted by AXIS filesystem policy"
    )]
    BindMountNotGranted { host_path: String },

    #[error("MXC WSLC config cannot represent AXIS per-sandbox resource limits exactly")]
    WslcResourceLimitsUnsupported,

    #[error("MXC VM config cannot represent custom image/config source for backend '{backend}'")]
    VmImageSourceUnsupported { backend: String },

    #[error("MXC VM config cannot represent guest working directory for backend '{backend}'")]
    VmGuestWorkingDirectoryUnsupported { backend: String },

    #[error("MXC VM config cannot represent copy-in/out for backend '{backend}'")]
    VmCopyPathsUnsupported { backend: String },

    #[error("MXC VM config cannot represent backend feature flags for backend '{backend}'")]
    VmFeatureFlagsUnsupported { backend: String },

    #[error("MXC VM config cannot represent persistent VM state for backend '{backend}'")]
    VmPersistentStateUnsupported { backend: String },

    #[error("MXC VM backend '{backend}' cannot represent denied paths exactly")]
    VmDeniedPathsUnsupported { backend: String },

    #[error("MXC VM backend '{backend}' cannot represent AXIS filesystem grants exactly")]
    VmFilesystemUnsupported { backend: String },

    #[error("MXC VM backend '{backend}' cannot represent AXIS network mode '{mode:?}' exactly")]
    VmNetworkModeUnsupported {
        backend: String,
        mode: VmBackendNetworkMode,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcContainerConfigOptions {
    pub container_id: Option<String>,
    pub strict_proxy_enforced_by_axis: bool,
    pub resource_limits_enforced_by_axis: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcProcessConfigOptions {
    pub container_id: Option<String>,
    pub strict_proxy_enforced_by_axis: bool,
    pub cooperative_proxy_configured_by_mxc: bool,
    pub resource_limits_enforced_by_axis: bool,
    pub proxy_url: Option<String>,
    pub axis_wfp: Option<MxcAxisWfpConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MxcVmConfigOptions {
    pub container_id: Option<String>,
    pub strict_proxy_enforced_by_axis: bool,
    pub windows_sandbox: Option<MxcWindowsSandboxConfig>,
    pub isolation_session: Option<MxcIsolationSessionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessConfig {
    #[serde(rename = "commandLine")]
    pub command_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcContainerWireConfig {
    pub version: String,
    #[serde(rename = "containerId", skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub containment: MxcContainment,
    pub platform: MxcPlatform,
    pub process: MxcProcessConfig,
    pub filesystem: MxcFilesystemConfig,
    pub network: MxcNetworkConfig,
    pub lifecycle: MxcLifecycleConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxc: Option<MxcLxcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<MxcExperimentalConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessWireConfig {
    pub version: String,
    #[serde(rename = "containerId", skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub containment: MxcContainment,
    pub platform: MxcPlatform,
    pub process: MxcProcessConfig,
    pub filesystem: MxcFilesystemConfig,
    pub network: MxcNetworkConfig,
    pub lifecycle: MxcLifecycleConfig,
    #[serde(rename = "processContainer", skip_serializing_if = "Option::is_none")]
    pub process_container: Option<MxcProcessContainerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<MxcFallbackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<MxcExperimentalConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcVmWireConfig {
    pub version: String,
    #[serde(rename = "containerId", skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub containment: MxcContainment,
    pub platform: MxcPlatform,
    pub process: MxcProcessConfig,
    pub filesystem: MxcFilesystemConfig,
    pub network: MxcNetworkConfig,
    pub lifecycle: MxcLifecycleConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<MxcExperimentalConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MxcContainment {
    Bubblewrap,
    Lxc,
    #[serde(rename = "processcontainer")]
    ProcessContainer,
    Seatbelt,
    Wslc,
    Microvm,
    Hyperlight,
    WindowsSandbox,
    IsolationSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcPlatform {
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcFilesystemConfig {
    #[serde(rename = "readwritePaths", default)]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths", default)]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths", default)]
    pub denied_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcNetworkConfig {
    #[serde(rename = "defaultPolicy")]
    pub default_policy: MxcNetworkDefaultPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<MxcNetworkProxy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcNetworkProxy {
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcNetworkDefaultPolicy {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcLifecycleConfig {
    #[serde(rename = "destroyOnExit")]
    pub destroy_on_exit: bool,
    #[serde(rename = "preservePolicy")]
    pub preserve_policy: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessContainerConfig {
    #[serde(rename = "leastPrivilege")]
    pub least_privilege: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    pub resources: MxcProcessResourceConfig,
    #[serde(rename = "axisWfp", skip_serializing_if = "Option::is_none")]
    pub axis_wfp: Option<MxcAxisWfpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcAxisWfpConfig {
    #[serde(rename = "pipeName")]
    pub pipe_name: String,
    #[serde(rename = "leaseId")]
    pub lease_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcProcessResourceConfig {
    #[serde(rename = "maxProcesses")]
    pub max_processes: u32,
    #[serde(rename = "maxMemoryMb")]
    pub max_memory_mb: u64,
    #[serde(rename = "cpuRatePercent")]
    pub cpu_rate_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcFallbackConfig {
    #[serde(rename = "allowDaclMutation")]
    pub allow_dacl_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcLxcConfig {
    pub distribution: String,
    pub release: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcExperimentalConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wslc: Option<MxcWslcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seatbelt: Option<MxcSeatbeltConfig>,
    #[serde(rename = "windows_sandbox", skip_serializing_if = "Option::is_none")]
    pub windows_sandbox: Option<MxcWindowsSandboxConfig>,
    #[serde(rename = "isolation_session", skip_serializing_if = "Option::is_none")]
    pub isolation_session: Option<MxcIsolationSessionConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcWslcConfig {
    #[serde(rename = "targetOs")]
    pub target_os: String,
    pub image: String,
    #[serde(rename = "imageTarPath", skip_serializing_if = "Option::is_none")]
    pub image_tar_path: Option<String>,
    #[serde(rename = "storagePath", skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    pub gpu: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcSeatbeltConfig {
    #[serde(rename = "profileOverride", skip_serializing_if = "Option::is_none")]
    pub profile_override: Option<String>,
    #[serde(rename = "guiAccess")]
    pub gui_access: bool,
    #[serde(rename = "launchMethod")]
    pub launch_method: MxcSeatbeltLaunchMethod,
    #[serde(rename = "nestedPty")]
    pub nested_pty: bool,
    #[serde(rename = "keychainAccess")]
    pub keychain_access: bool,
    #[serde(
        rename = "extraMachLookups",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub extra_mach_lookups: Vec<String>,
}

impl Default for MxcSeatbeltConfig {
    fn default() -> Self {
        Self {
            profile_override: None,
            gui_access: false,
            launch_method: MxcSeatbeltLaunchMethod::Exec,
            nested_pty: false,
            keychain_access: false,
            extra_mach_lookups: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcSeatbeltLaunchMethod {
    Exec,
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcWindowsSandboxConfig {
    #[serde(rename = "idleTimeoutMs")]
    pub idle_timeout_ms: u32,
    #[serde(rename = "daemonPipeName")]
    pub daemon_pipe_name: String,
}

impl Default for MxcWindowsSandboxConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 300_000,
            daemon_pipe_name: "wxc-windows-sandbox".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxcIsolationSessionConfig {
    #[serde(rename = "configurationId")]
    pub configuration_id: MxcIsolationSessionConfigurationId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MxcIsolationSessionConfigurationId {
    Small,
    Medium,
    Large,
    #[default]
    Composable,
}

pub fn build_mxc_container_config(
    process: MxcProcessConfig,
    spec: &ContainerBackendExecutionSpec,
    options: MxcContainerConfigOptions,
) -> Result<MxcContainerWireConfig, MxcConfigError> {
    validate_process_config(&process)?;
    validate_container_network(spec, &options)?;
    validate_bind_mounts(spec)?;
    validate_container_backend_semantics(spec)?;
    validate_container_resources(spec, &options)?;

    let filesystem = MxcFilesystemConfig {
        readwrite_paths: spec.filesystem.read_write.clone(),
        readonly_paths: spec.filesystem.read_only.clone(),
        denied_paths: spec.filesystem.deny.clone(),
    };
    let network = MxcNetworkConfig {
        default_policy: mxc_network_policy(spec, &options)?,
        proxy: None,
    };
    let lifecycle = MxcLifecycleConfig {
        destroy_on_exit: spec.destroy_on_exit,
        preserve_policy: false,
    };

    match spec.config_format {
        ContainerBackendConfigFormat::MxcLinuxLxcJson => {
            let (distribution, release) = lxc_distribution_release(spec)?;
            Ok(MxcContainerWireConfig {
                version: MXC_CONFIG_VERSION.into(),
                container_id: options.container_id,
                containment: MxcContainment::Lxc,
                platform: MxcPlatform::Linux,
                process,
                filesystem,
                network,
                lifecycle,
                lxc: Some(MxcLxcConfig {
                    distribution: distribution.into(),
                    release: release.into(),
                }),
                experimental: None,
            })
        }
        ContainerBackendConfigFormat::MxcWindowsWslcJson => {
            let wslc = wslc_config(spec)?;
            Ok(MxcContainerWireConfig {
                version: MXC_CONFIG_VERSION.into(),
                container_id: options.container_id,
                containment: MxcContainment::Wslc,
                platform: MxcPlatform::Windows,
                process,
                filesystem,
                network,
                lifecycle,
                lxc: None,
                experimental: Some(MxcExperimentalConfig {
                    wslc: Some(wslc),
                    ..Default::default()
                }),
            })
        }
    }
}

pub fn build_mxc_process_config(
    command_line: impl Into<String>,
    spec: &ProcessBackendExecutionSpec,
    options: MxcProcessConfigOptions,
) -> Result<MxcProcessWireConfig, MxcConfigError> {
    validate_process_backend_supported(spec)?;
    validate_process_network(spec, &options)?;
    validate_process_resources(spec, &options)?;
    let process = process_config_for_process_spec(command_line.into(), spec)?;
    let filesystem = MxcFilesystemConfig {
        readwrite_paths: spec.filesystem.read_write.clone(),
        readonly_paths: spec.filesystem.read_only.clone(),
        denied_paths: spec.filesystem.deny.clone(),
    };
    let network = MxcNetworkConfig {
        default_policy: mxc_process_network_policy(spec, &options)?,
        proxy: options.proxy_url.clone().map(|url| MxcNetworkProxy { url }),
    };
    let lifecycle = MxcLifecycleConfig {
        destroy_on_exit: true,
        preserve_policy: false,
    };

    match spec.config_format {
        ProcessBackendConfigFormat::MxcLinuxJson => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::Bubblewrap,
            platform: MxcPlatform::Linux,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: None,
            fallback: None,
            experimental: None,
        }),
        ProcessBackendConfigFormat::MxcWindowsProcessContainer => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::ProcessContainer,
            platform: MxcPlatform::Windows,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: Some(MxcProcessContainerConfig {
                least_privilege: true,
                capabilities: Vec::new(),
                resources: MxcProcessResourceConfig {
                    max_processes: spec.resources.max_processes,
                    max_memory_mb: spec.resources.max_memory_mb,
                    cpu_rate_percent: spec.resources.cpu_rate_percent,
                },
                axis_wfp: options.axis_wfp,
            }),
            fallback: Some(MxcFallbackConfig {
                allow_dacl_mutation: false,
            }),
            experimental: None,
        }),
        ProcessBackendConfigFormat::MxcMacosSeatbeltProfile => Ok(MxcProcessWireConfig {
            version: MXC_CONFIG_VERSION.into(),
            container_id: options.container_id,
            containment: MxcContainment::Seatbelt,
            platform: MxcPlatform::Macos,
            process,
            filesystem,
            network,
            lifecycle,
            process_container: None,
            fallback: None,
            experimental: Some(MxcExperimentalConfig {
                seatbelt: Some(MxcSeatbeltConfig::default()),
                ..Default::default()
            }),
        }),
        ProcessBackendConfigFormat::AxisNativeLinux
        | ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile
        | ProcessBackendConfigFormat::AxisNativeWindowsProcess => unreachable!(
            "native AXIS process backends are rejected before MXC process config emission"
        ),
    }
}

pub fn build_mxc_vm_config(
    process: MxcProcessConfig,
    spec: &VmBackendExecutionSpec,
    options: MxcVmConfigOptions,
) -> Result<MxcVmWireConfig, MxcConfigError> {
    validate_process_config(&process)?;
    validate_vm_launch(spec)?;
    validate_vm_filesystem(spec)?;
    validate_vm_network(spec, &options)?;

    let filesystem = MxcFilesystemConfig {
        readwrite_paths: spec.filesystem.read_write.clone(),
        readonly_paths: spec.filesystem.read_only.clone(),
        denied_paths: spec.filesystem.deny.clone(),
    };
    let network = MxcNetworkConfig {
        default_policy: mxc_vm_network_policy(spec, &options)?,
        proxy: None,
    };
    let lifecycle = MxcLifecycleConfig {
        destroy_on_exit: spec.destroy_on_exit,
        preserve_policy: false,
    };

    let (containment, platform, experimental) = match spec.config_format {
        VmBackendConfigFormat::MxcLinuxMicrovmJson => {
            (MxcContainment::Microvm, MxcPlatform::Linux, None)
        }
        VmBackendConfigFormat::MxcLinuxHyperlightJson => {
            (MxcContainment::Hyperlight, MxcPlatform::Linux, None)
        }
        VmBackendConfigFormat::MxcWindowsMicrovmJson => {
            (MxcContainment::Microvm, MxcPlatform::Windows, None)
        }
        VmBackendConfigFormat::MxcWindowsHyperlightJson => {
            (MxcContainment::Hyperlight, MxcPlatform::Windows, None)
        }
        VmBackendConfigFormat::MxcWindowsSandboxJson => (
            MxcContainment::WindowsSandbox,
            MxcPlatform::Windows,
            Some(MxcExperimentalConfig {
                windows_sandbox: Some(options.windows_sandbox.unwrap_or_default()),
                ..Default::default()
            }),
        ),
        VmBackendConfigFormat::MxcWindowsIsolationSessionJson => (
            MxcContainment::IsolationSession,
            MxcPlatform::Windows,
            Some(MxcExperimentalConfig {
                isolation_session: Some(options.isolation_session.unwrap_or_default()),
                ..Default::default()
            }),
        ),
    };

    Ok(MxcVmWireConfig {
        version: MXC_CONFIG_VERSION.into(),
        container_id: options.container_id,
        containment,
        platform,
        process,
        filesystem,
        network,
        lifecycle,
        experimental,
    })
}

fn process_config_for_process_spec(
    command_line: String,
    spec: &ProcessBackendExecutionSpec,
) -> Result<MxcProcessConfig, MxcConfigError> {
    let timeout = match spec.timeout_ms {
        Some(timeout_ms) if timeout_ms > u32::MAX.into() => {
            return Err(MxcConfigError::ProcessTimeoutOverflow { timeout_ms });
        }
        Some(timeout_ms) => Some(timeout_ms as u32),
        None => None,
    };
    let process = MxcProcessConfig {
        command_line,
        cwd: spec.working_dir.clone(),
        env: spec
            .environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        timeout,
    };

    validate_process_config(&process)?;
    Ok(process)
}

fn validate_process_config(process: &MxcProcessConfig) -> Result<(), MxcConfigError> {
    if process.command_line.trim().is_empty() {
        return Err(MxcConfigError::EmptyCommandLine);
    }

    if process.env.iter().any(|entry| {
        let Some((key, _value)) = entry.split_once('=') else {
            return true;
        };
        key.trim().is_empty()
    }) {
        return Err(MxcConfigError::InvalidEnvironmentEntry);
    }

    for entry in &process.env {
        let (key, _value) = entry
            .split_once('=')
            .expect("process env entry shape is validated above");
        if sandbox_env::is_secret_env_key(key) || sandbox_env::is_proxy_env_key(key) {
            return Err(MxcConfigError::FilteredEnvironmentEntry { key: key.into() });
        }
    }

    Ok(())
}

fn validate_process_backend_supported(
    spec: &ProcessBackendExecutionSpec,
) -> Result<(), MxcConfigError> {
    match spec.config_format {
        ProcessBackendConfigFormat::AxisNativeLinux
        | ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile
        | ProcessBackendConfigFormat::AxisNativeWindowsProcess => {
            Err(MxcConfigError::NativeProcessBackendUnsupported {
                backend: spec.backend.clone(),
            })
        }
        ProcessBackendConfigFormat::MxcLinuxJson
        | ProcessBackendConfigFormat::MxcWindowsProcessContainer
        | ProcessBackendConfigFormat::MxcMacosSeatbeltProfile => Ok(()),
    }
}

fn validate_process_resources(
    spec: &ProcessBackendExecutionSpec,
    options: &MxcProcessConfigOptions,
) -> Result<(), MxcConfigError> {
    let emitted_to_windows_processcontainer = matches!(
        spec.config_format,
        ProcessBackendConfigFormat::MxcWindowsProcessContainer
    );
    if process_resources_requested(spec)
        && !emitted_to_windows_processcontainer
        && !options.resource_limits_enforced_by_axis
    {
        return Err(MxcConfigError::ProcessResourceLimitsRequireAxisLayer);
    }
    Ok(())
}

fn process_resources_requested(spec: &ProcessBackendExecutionSpec) -> bool {
    spec.resources.max_processes != 0
        || spec.resources.max_memory_mb != 0
        || spec.resources.cpu_rate_percent != 0
}

fn validate_process_network(
    spec: &ProcessBackendExecutionSpec,
    options: &MxcProcessConfigOptions,
) -> Result<(), MxcConfigError> {
    let has_endpoint_policy =
        !spec.network.endpoint_policy_names.is_empty() || spec.network.binary_attribution_required;
    if has_endpoint_policy && spec.network.mode != ProcessBackendNetworkMode::StrictProxy {
        return Err(MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }
    if spec.network.binary_attribution_required
        && options.cooperative_proxy_configured_by_mxc
        && !options.strict_proxy_enforced_by_axis
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }
    if spec.network.mode == ProcessBackendNetworkMode::StrictProxy
        && !process_proxy_boundary_configured(options)
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }
    Ok(())
}

fn process_proxy_boundary_configured(options: &MxcProcessConfigOptions) -> bool {
    options.strict_proxy_enforced_by_axis || options.cooperative_proxy_configured_by_mxc
}

fn validate_container_network(
    spec: &ContainerBackendExecutionSpec,
    options: &MxcContainerConfigOptions,
) -> Result<(), MxcConfigError> {
    let has_endpoint_policy =
        !spec.network.endpoint_policy_names.is_empty() || spec.network.binary_attribution_required;
    if has_endpoint_policy && spec.network.mode != ContainerBackendNetworkMode::StrictProxy {
        return Err(MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }
    if spec.network.mode == ContainerBackendNetworkMode::StrictProxy
        && !options.strict_proxy_enforced_by_axis
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }
    Ok(())
}

fn validate_vm_launch(spec: &VmBackendExecutionSpec) -> Result<(), MxcConfigError> {
    if !matches!(spec.image, VmImageSource::RuntimeDefault) {
        return Err(MxcConfigError::VmImageSourceUnsupported {
            backend: spec.backend.clone(),
        });
    }
    if spec.guest_working_dir.is_some() {
        return Err(MxcConfigError::VmGuestWorkingDirectoryUnsupported {
            backend: spec.backend.clone(),
        });
    }
    if !spec.copy_in.is_empty() || !spec.copy_out.is_empty() {
        return Err(MxcConfigError::VmCopyPathsUnsupported {
            backend: spec.backend.clone(),
        });
    }
    if !spec.required_features.is_empty() {
        return Err(MxcConfigError::VmFeatureFlagsUnsupported {
            backend: spec.backend.clone(),
        });
    }
    if !spec.destroy_on_exit {
        return Err(MxcConfigError::VmPersistentStateUnsupported {
            backend: spec.backend.clone(),
        });
    }
    Ok(())
}

fn validate_vm_filesystem(spec: &VmBackendExecutionSpec) -> Result<(), MxcConfigError> {
    match spec.config_format {
        VmBackendConfigFormat::MxcLinuxMicrovmJson
        | VmBackendConfigFormat::MxcWindowsMicrovmJson
        | VmBackendConfigFormat::MxcWindowsIsolationSessionJson
            if !spec.filesystem.deny.is_empty() =>
        {
            Err(MxcConfigError::VmDeniedPathsUnsupported {
                backend: spec.backend.clone(),
            })
        }
        VmBackendConfigFormat::MxcWindowsSandboxJson
            if !spec.filesystem.read_only.is_empty()
                || !spec.filesystem.read_write.is_empty()
                || !spec.filesystem.deny.is_empty() =>
        {
            Err(MxcConfigError::VmFilesystemUnsupported {
                backend: spec.backend.clone(),
            })
        }
        _ => Ok(()),
    }
}

fn validate_vm_network(
    spec: &VmBackendExecutionSpec,
    options: &MxcVmConfigOptions,
) -> Result<(), MxcConfigError> {
    let has_endpoint_policy =
        !spec.network.endpoint_policy_names.is_empty() || spec.network.binary_attribution_required;
    if has_endpoint_policy && spec.network.mode != VmBackendNetworkMode::StrictProxy {
        return Err(MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }
    if spec.network.mode == VmBackendNetworkMode::StrictProxy
        && !options.strict_proxy_enforced_by_axis
    {
        return Err(MxcConfigError::StrictProxyRequiresAxisLayer);
    }

    let supported = match spec.config_format {
        VmBackendConfigFormat::MxcLinuxMicrovmJson
        | VmBackendConfigFormat::MxcWindowsMicrovmJson
        | VmBackendConfigFormat::MxcWindowsSandboxJson
        | VmBackendConfigFormat::MxcWindowsIsolationSessionJson => {
            spec.network.mode == VmBackendNetworkMode::Block
        }
        VmBackendConfigFormat::MxcLinuxHyperlightJson
        | VmBackendConfigFormat::MxcWindowsHyperlightJson => {
            matches!(
                spec.network.mode,
                VmBackendNetworkMode::Allow | VmBackendNetworkMode::Block
            ) || (spec.network.mode == VmBackendNetworkMode::StrictProxy
                && options.strict_proxy_enforced_by_axis)
        }
    };

    if !supported {
        return Err(MxcConfigError::VmNetworkModeUnsupported {
            backend: spec.backend.clone(),
            mode: spec.network.mode,
        });
    }

    Ok(())
}

fn validate_bind_mounts(spec: &ContainerBackendExecutionSpec) -> Result<(), MxcConfigError> {
    if spec.config_format == ContainerBackendConfigFormat::MxcWindowsWslcJson
        && !spec.bind_mounts.is_empty()
    {
        return Err(MxcConfigError::WslcBindMountsUnsupported);
    }

    for mount in &spec.bind_mounts {
        if Path::new(&mount.host_path) != Path::new(&mount.container_path) {
            return Err(MxcConfigError::BindMountAliasUnsupported {
                host_path: mount.host_path.clone(),
                container_path: mount.container_path.clone(),
            });
        }

        let granted = match mount.access {
            ContainerMountAccess::ReadOnly => spec
                .filesystem
                .read_only
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
            ContainerMountAccess::ReadWrite => spec
                .filesystem
                .read_write
                .iter()
                .any(|path| Path::new(path) == Path::new(&mount.host_path)),
        };
        if !granted {
            return Err(MxcConfigError::BindMountNotGranted {
                host_path: mount.host_path.clone(),
            });
        }
    }

    Ok(())
}

fn validate_container_backend_semantics(
    spec: &ContainerBackendExecutionSpec,
) -> Result<(), MxcConfigError> {
    if spec.config_format != ContainerBackendConfigFormat::MxcWindowsWslcJson {
        return Ok(());
    }

    if !spec.filesystem.deny.is_empty() {
        return Err(MxcConfigError::WslcDeniedPathsUnsupported);
    }

    if spec.network.mode != ContainerBackendNetworkMode::Allow {
        return Err(MxcConfigError::WslcNetworkModeUnsupported {
            mode: spec.network.mode,
        });
    }

    Ok(())
}

fn validate_container_resources(
    spec: &ContainerBackendExecutionSpec,
    options: &MxcContainerConfigOptions,
) -> Result<(), MxcConfigError> {
    if !container_resources_requested(spec) {
        return Ok(());
    }

    match spec.config_format {
        ContainerBackendConfigFormat::MxcWindowsWslcJson => {
            Err(MxcConfigError::WslcResourceLimitsUnsupported)
        }
        ContainerBackendConfigFormat::MxcLinuxLxcJson
            if !options.resource_limits_enforced_by_axis =>
        {
            Err(MxcConfigError::ContainerResourceLimitsRequireAxisLayer)
        }
        ContainerBackendConfigFormat::MxcLinuxLxcJson => Ok(()),
    }
}

fn container_resources_requested(spec: &ContainerBackendExecutionSpec) -> bool {
    spec.resources.max_processes != 0
        || spec.resources.max_memory_mb != 0
        || spec.resources.cpu_rate_percent != 0
}

fn mxc_process_network_policy(
    spec: &ProcessBackendExecutionSpec,
    options: &MxcProcessConfigOptions,
) -> Result<MxcNetworkDefaultPolicy, MxcConfigError> {
    match spec.network.mode {
        ProcessBackendNetworkMode::Allow => Ok(MxcNetworkDefaultPolicy::Allow),
        ProcessBackendNetworkMode::Block => Ok(MxcNetworkDefaultPolicy::Block),
        ProcessBackendNetworkMode::StrictProxy if process_proxy_boundary_configured(options) => {
            Ok(MxcNetworkDefaultPolicy::Allow)
        }
        ProcessBackendNetworkMode::StrictProxy => Err(MxcConfigError::StrictProxyRequiresAxisLayer),
    }
}

fn mxc_network_policy(
    spec: &ContainerBackendExecutionSpec,
    options: &MxcContainerConfigOptions,
) -> Result<MxcNetworkDefaultPolicy, MxcConfigError> {
    match spec.network.mode {
        ContainerBackendNetworkMode::Allow => Ok(MxcNetworkDefaultPolicy::Allow),
        ContainerBackendNetworkMode::Block => Ok(MxcNetworkDefaultPolicy::Block),
        ContainerBackendNetworkMode::StrictProxy if options.strict_proxy_enforced_by_axis => {
            Ok(MxcNetworkDefaultPolicy::Allow)
        }
        ContainerBackendNetworkMode::StrictProxy => {
            Err(MxcConfigError::StrictProxyRequiresAxisLayer)
        }
    }
}

fn mxc_vm_network_policy(
    spec: &VmBackendExecutionSpec,
    options: &MxcVmConfigOptions,
) -> Result<MxcNetworkDefaultPolicy, MxcConfigError> {
    match spec.network.mode {
        VmBackendNetworkMode::Allow => Ok(MxcNetworkDefaultPolicy::Allow),
        VmBackendNetworkMode::Block => Ok(MxcNetworkDefaultPolicy::Block),
        VmBackendNetworkMode::StrictProxy if options.strict_proxy_enforced_by_axis => {
            Ok(MxcNetworkDefaultPolicy::Allow)
        }
        VmBackendNetworkMode::StrictProxy => Err(MxcConfigError::StrictProxyRequiresAxisLayer),
    }
}

fn lxc_distribution_release(
    spec: &ContainerBackendExecutionSpec,
) -> Result<(&str, &str), MxcConfigError> {
    let ContainerRootfsSource::LxcDistributionRelease {
        distribution,
        release,
    } = &spec.rootfs
    else {
        return Err(MxcConfigError::LxcRootfsRequired);
    };
    Ok((distribution, release))
}

fn wslc_config(spec: &ContainerBackendExecutionSpec) -> Result<MxcWslcConfig, MxcConfigError> {
    if spec.resources.max_processes != 0
        || spec.resources.max_memory_mb != 0
        || spec.resources.cpu_rate_percent != 0
    {
        return Err(MxcConfigError::WslcResourceLimitsUnsupported);
    }

    match &spec.rootfs {
        ContainerRootfsSource::WslImage { image } => Ok(MxcWslcConfig {
            target_os: "linux".into(),
            image: image.clone(),
            image_tar_path: None,
            storage_path: spec.storage_path.clone(),
            gpu: false,
        }),
        ContainerRootfsSource::WslImageTar {
            image,
            image_tar_path,
        } => Ok(MxcWslcConfig {
            target_os: "linux".into(),
            image: image.clone(),
            image_tar_path: Some(image_tar_path.clone()),
            storage_path: spec.storage_path.clone(),
            gpu: false,
        }),
        _ => Err(MxcConfigError::WslcImageRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{DependencyState, PlannerOptions, RuntimeProbeSnapshot};
    use crate::capability_map::{BackendCapabilityMapId, backend_capability_map};
    use crate::container_backend::{
        ContainerBackendNetworkMode, ContainerBackendSpecError, ContainerBindMount,
        ContainerLaunchOptions, ContainerMountAccess, build_container_backend_execution_spec,
    };
    use crate::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkMode, NetworkPolicy, Policy, ProcessPolicy, SshPolicy,
    };
    use crate::process_backend::{
        ProcessBackendSpecError, ProcessLaunchOptions, build_process_backend_execution_spec,
    };
    use crate::vm_backend::{
        VmBackendExecutionSpec, VmBackendFilesystemSpec, VmBackendNetworkMode, VmBackendSpecError,
        VmCopyPath, VmImageSource, VmLaunchOptions, build_vm_backend_execution_spec,
    };
    use std::collections::BTreeMap;

    #[test]
    fn lxc_container_config_serializes_mxc_wire_shape() {
        let spec = lxc_execution_spec(NetworkMode::Block).unwrap();
        let config = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["version"], MXC_CONFIG_VERSION);
        assert_eq!(json["containerId"], "axis-lxc");
        assert_eq!(json["containment"], "lxc");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["process"]["commandLine"], "echo container");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["process"]["env"][0], "PATH=/usr/bin");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert_eq!(json["lxc"]["distribution"], "alpine");
        assert_eq!(json["lxc"]["release"], "3.23");
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn wslc_container_config_serializes_experimental_wslc_shape() {
        let launch = ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImageTar {
                image: "alpine:latest".into(),
                image_tar_path: "C:\\images\\alpine.tar".into(),
            },
            storage_path: Some("C:\\axis\\wslc".into()),
            working_dir: None,
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        };
        let spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            launch,
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let config = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "wslc");
        assert_eq!(json["platform"], "windows");
        assert!(json.get("lxc").is_none());
        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["experimental"]["wslc"]["targetOs"], "linux");
        assert_eq!(json["experimental"]["wslc"]["image"], "alpine:latest");
        assert_eq!(
            json["experimental"]["wslc"]["imageTarPath"],
            "C:\\images\\alpine.tar"
        );
        assert_eq!(
            json["experimental"]["wslc"]["storagePath"],
            "C:\\axis\\wslc"
        );
        assert_eq!(json["experimental"]["wslc"]["gpu"], false);
    }

    #[test]
    fn bubblewrap_process_config_serializes_mxc_wire_shape() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Block,
        )
        .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["version"], MXC_CONFIG_VERSION);
        assert_eq!(json["containerId"], "axis-bwrap");
        assert_eq!(json["containment"], "bubblewrap");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["process"]["commandLine"], "agent --version");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["process"]["env"][0], "AXIS_TEST=1");
        assert_eq!(json["process"]["timeout"], 3000);
        assert_eq!(json["filesystem"]["readonlyPaths"][0], "/usr");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert_eq!(json["filesystem"]["deniedPaths"][0], "/home/user/.ssh");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert_eq!(json["lifecycle"]["preservePolicy"], false);
        assert!(json.get("processContainer").is_none());
        assert!(json.get("fallback").is_none());
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn windows_processcontainer_config_serializes_mxc_wire_shape() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            NetworkMode::Allow,
        )
        .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-windows"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "processcontainer");
        assert_eq!(json["platform"], "windows");
        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["processContainer"]["leastPrivilege"], true);
        assert!(json["processContainer"].get("capabilities").is_none());
        assert_eq!(
            json["processContainer"]["resources"],
            serde_json::json!({
                "maxProcesses": 0,
                "maxMemoryMb": 0,
                "cpuRatePercent": 0
            })
        );
        assert_eq!(json["fallback"]["allowDaclMutation"], false);
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn windows_strict_proxy_serializes_axis_wfp_pre_resume_contract() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            NetworkMode::Proxy,
        )
        .unwrap();
        let config = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-windows-proxy".into()),
                strict_proxy_enforced_by_axis: true,
                proxy_url: Some("http://127.0.0.1:31280".into()),
                axis_wfp: Some(MxcAxisWfpConfig {
                    pipe_name: r"\\.\pipe\axis-wfp-broker-v1".into(),
                    lease_id: "d5406689-f871-42e0-ae5b-eb4b5720ad2a".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let json = serde_json::to_value(config).unwrap();

        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["network"]["proxy"]["url"], "http://127.0.0.1:31280");
        assert_eq!(
            json["processContainer"]["axisWfp"],
            serde_json::json!({
                "pipeName": r"\\.\pipe\axis-wfp-broker-v1",
                "leaseId": "d5406689-f871-42e0-ae5b-eb4b5720ad2a"
            })
        );
    }

    #[test]
    fn macos_seatbelt_config_serializes_experimental_mxc_wire_shape() {
        let spec =
            process_execution_spec(BackendCapabilityMapId::MxcMacosSeatbelt, NetworkMode::Block)
                .unwrap();
        let config =
            build_mxc_process_config("agent --version", &spec, process_options("axis-seatbelt"))
                .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "seatbelt");
        assert_eq!(json["platform"], "macos");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(json.get("processContainer").is_none());
        assert_eq!(json["experimental"]["seatbelt"]["guiAccess"], false);
        assert_eq!(json["experimental"]["seatbelt"]["launchMethod"], "exec");
        assert_eq!(json["experimental"]["seatbelt"]["nestedPty"], false);
        assert_eq!(json["experimental"]["seatbelt"]["keychainAccess"], false);
        assert!(
            json["experimental"]["seatbelt"]
                .get("extraMachLookups")
                .is_none()
        );
    }

    #[test]
    fn linux_microvm_config_serializes_mxc_wire_shape() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxMicrovm,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        let config = build_mxc_vm_config(vm_process(), &spec, vm_options("axis-microvm")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["version"], MXC_CONFIG_VERSION);
        assert_eq!(json["containerId"], "axis-microvm");
        assert_eq!(json["containment"], "microvm");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["process"]["commandLine"], "print('vm')");
        assert_eq!(json["process"]["timeout"], 30000);
        assert_eq!(json["filesystem"]["readonlyPaths"][0], "/opt/axis-ref");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["lifecycle"]["destroyOnExit"], true);
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn linux_hyperlight_config_serializes_mxc_wire_shape() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Allow,
            vm_policy(NetworkMode::Allow),
        )
        .unwrap();
        let config =
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-hyperlight")).unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "hyperlight");
        assert_eq!(json["platform"], "linux");
        assert_eq!(json["network"]["defaultPolicy"], "allow");
        assert_eq!(json["filesystem"]["readwritePaths"][0], "/workspace");
        assert!(json.get("experimental").is_none());
    }

    #[test]
    fn windows_sandbox_config_serializes_experimental_mxc_wire_shape() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcWindowsSandbox,
            NetworkMode::Block,
            vm_empty_filesystem_policy(NetworkMode::Block),
        )
        .unwrap();
        let config = build_mxc_vm_config(
            vm_process(),
            &spec,
            MxcVmConfigOptions {
                container_id: Some("axis-windows-sandbox".into()),
                windows_sandbox: Some(MxcWindowsSandboxConfig {
                    idle_timeout_ms: 60_000,
                    daemon_pipe_name: "axis-windows-sandbox".into(),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "windows_sandbox");
        assert_eq!(json["platform"], "windows");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert!(
            json["filesystem"]["readwritePaths"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            json["experimental"]["windows_sandbox"]["idleTimeoutMs"],
            60_000
        );
        assert_eq!(
            json["experimental"]["windows_sandbox"]["daemonPipeName"],
            "axis-windows-sandbox"
        );
    }

    #[test]
    fn isolation_session_config_serializes_experimental_mxc_wire_shape() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcWindowsIsolationSession,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        let config = build_mxc_vm_config(
            vm_process(),
            &spec,
            MxcVmConfigOptions {
                container_id: Some("axis-isolation-session".into()),
                isolation_session: Some(MxcIsolationSessionConfig {
                    configuration_id: MxcIsolationSessionConfigurationId::Medium,
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let json = serde_json::to_value(&config).unwrap();

        assert_eq!(json["containment"], "isolation_session");
        assert_eq!(json["platform"], "windows");
        assert_eq!(json["network"]["defaultPolicy"], "block");
        assert_eq!(json["filesystem"]["readonlyPaths"][0], "/opt/axis-ref");
        assert_eq!(
            json["experimental"]["isolation_session"]["configurationId"],
            "medium"
        );
    }

    #[test]
    fn native_process_backends_are_rejected_before_mxc_config() {
        let spec =
            process_execution_spec(BackendCapabilityMapId::AxisNativeLinux, NetworkMode::Allow)
                .unwrap();

        let err =
            build_mxc_process_config("agent --version", &spec, MxcProcessConfigOptions::default())
                .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::NativeProcessBackendUnsupported {
                backend: "axis-native-linux".into()
            }
        );
    }

    #[test]
    fn process_strict_proxy_requires_axis_owned_network_layer_before_mxc_config() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Proxy,
        )
        .unwrap();

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();
        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);

        let config = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-bwrap".into()),
                strict_proxy_enforced_by_axis: true,
                resource_limits_enforced_by_axis: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn process_strict_proxy_allows_mxc_configured_cooperative_proxy_boundary() {
        let spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Proxy,
        )
        .unwrap();

        let config = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-bwrap".into()),
                cooperative_proxy_configured_by_mxc: true,
                resource_limits_enforced_by_axis: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn process_cooperative_proxy_rejects_binary_attributed_endpoint_policy() {
        let mut policy = process_policy(NetworkMode::Proxy);
        policy.network.policies.push(endpoint_policy_with_binary());
        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            process_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxBubblewrap),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-bwrap".into()),
                cooperative_proxy_configured_by_mxc: true,
                resource_limits_enforced_by_axis: true,
                ..Default::default()
            },
        )
        .unwrap_err();

        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);
    }

    #[test]
    fn process_endpoint_policies_are_rejected_outside_strict_proxy_mode() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy_with_binary());
        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            process_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxBubblewrap),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(err, MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }

    #[test]
    fn process_inputs_are_validated_before_mxc_process_config() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();

        assert_eq!(
            build_mxc_process_config(" ", &spec, process_options("axis-bwrap")).unwrap_err(),
            MxcConfigError::EmptyCommandLine
        );

        spec.environment.insert(" ".into(), "bad".into());
        assert_eq!(
            build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
                .unwrap_err(),
            MxcConfigError::InvalidEnvironmentEntry
        );
    }

    #[test]
    fn process_config_rejects_secret_and_inherited_proxy_env_before_mxc_json() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();
        spec.environment
            .insert("OPENAI_API_KEY".into(), "super-secret-token".into());

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::FilteredEnvironmentEntry {
                key: "OPENAI_API_KEY".into()
            }
        );
        assert!(!err.to_string().contains("super-secret-token"));

        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();
        spec.environment
            .insert("HTTPS_PROXY".into(), "http://proxy-with-creds".into());

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::FilteredEnvironmentEntry {
                key: "HTTPS_PROXY".into()
            }
        );
        assert!(!err.to_string().contains("proxy-with-creds"));
    }

    #[test]
    fn process_timeout_overflow_is_rejected_before_mxc_process_config() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            NetworkMode::Allow,
        )
        .unwrap();
        spec.timeout_ms = Some(u64::from(u32::MAX) + 1);

        let err = build_mxc_process_config("agent --version", &spec, process_options("axis-bwrap"))
            .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::ProcessTimeoutOverflow {
                timeout_ms: u64::from(u32::MAX) + 1
            }
        );
    }

    #[test]
    fn windows_process_resource_limits_are_emitted_for_mxc_inner_job() {
        let mut spec = process_execution_spec(
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            NetworkMode::Allow,
        )
        .unwrap();
        spec.resources.max_processes = 32;
        spec.resources.max_memory_mb = 1024;
        spec.resources.cpu_rate_percent = 50;

        let config = build_mxc_process_config(
            "agent --version",
            &spec,
            MxcProcessConfigOptions {
                container_id: Some("axis-windows".into()),
                resource_limits_enforced_by_axis: false,
                ..Default::default()
            },
        )
        .unwrap();
        let resources = &config.process_container.unwrap().resources;
        assert_eq!(resources.max_processes, 32);
        assert_eq!(resources.max_memory_mb, 1024);
        assert_eq!(resources.cpu_rate_percent, 50);
    }

    #[test]
    fn strict_proxy_requires_axis_owned_network_layer_before_mxc_config() {
        let spec = lxc_execution_spec(NetworkMode::Proxy).unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();
        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);

        let config = build_mxc_container_config(
            process(),
            &spec,
            MxcContainerConfigOptions {
                container_id: Some("axis-lxc".into()),
                strict_proxy_enforced_by_axis: true,
                resource_limits_enforced_by_axis: true,
            },
        )
        .unwrap();
        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn endpoint_policies_are_rejected_outside_strict_proxy_mode() {
        let mut policy = policy(NetworkMode::Allow);
        policy.network.policies.push(endpoint_policy_with_binary());
        let spec = build_container_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxLxc,
            lxc_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxLxc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(err, MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }

    #[test]
    fn bind_mount_aliases_are_rejected_before_mxc_config() {
        let mut spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        spec.bind_mounts[0].container_path = "/container-workspace".into();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::BindMountAliasUnsupported {
                host_path: "/workspace".into(),
                container_path: "/container-workspace".into()
            }
        );
    }

    #[test]
    fn wslc_bind_mounts_are_rejected_before_mxc_config() {
        let mut launch = wslc_launch_without_bind_mounts();
        launch.bind_mounts.push(ContainerBindMount {
            host_path: "C:\\workspace".into(),
            container_path: "C:\\workspace".into(),
            access: ContainerMountAccess::ReadWrite,
        });
        let spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            launch,
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(err, MxcConfigError::WslcBindMountsUnsupported);
    }

    #[test]
    fn wslc_denied_paths_are_rejected_before_mxc_config() {
        let mut spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            wslc_launch_without_bind_mounts(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();
        spec.filesystem.deny.push("C:\\Users\\agent\\.ssh".into());

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(err, MxcConfigError::WslcDeniedPathsUnsupported);
    }

    #[test]
    fn wslc_block_network_is_rejected_before_mxc_config() {
        let mut spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            wslc_launch_without_bind_mounts(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();
        spec.network.mode = ContainerBackendNetworkMode::Block;

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::WslcNetworkModeUnsupported {
                mode: ContainerBackendNetworkMode::Block
            }
        );
    }

    #[test]
    fn wslc_strict_proxy_is_rejected_even_with_axis_layer_before_mxc_config() {
        let mut spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            wslc_launch_without_bind_mounts(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();
        spec.network.mode = ContainerBackendNetworkMode::StrictProxy;

        let err = build_mxc_container_config(
            process(),
            &spec,
            MxcContainerConfigOptions {
                container_id: Some("axis-wslc".into()),
                strict_proxy_enforced_by_axis: true,
                resource_limits_enforced_by_axis: false,
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::WslcNetworkModeUnsupported {
                mode: ContainerBackendNetworkMode::StrictProxy
            }
        );
    }

    #[test]
    fn bind_mounts_must_be_granted_by_axis_filesystem_policy() {
        let mut spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        spec.filesystem.read_write.clear();

        let err = build_mxc_container_config(process(), &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::BindMountNotGranted {
                host_path: "/workspace".into()
            }
        );
    }

    #[test]
    fn lxc_resource_limits_require_axis_owned_layer_before_mxc_config() {
        let mut spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        spec.resources.max_processes = 64;
        spec.resources.max_memory_mb = 512;
        spec.resources.cpu_rate_percent = 25;

        let err = build_mxc_container_config(
            process(),
            &spec,
            MxcContainerConfigOptions {
                container_id: Some("axis-lxc".into()),
                strict_proxy_enforced_by_axis: false,
                resource_limits_enforced_by_axis: false,
            },
        )
        .unwrap_err();

        assert_eq!(err, MxcConfigError::ContainerResourceLimitsRequireAxisLayer);

        let config = build_mxc_container_config(
            process(),
            &spec,
            MxcContainerConfigOptions {
                container_id: Some("axis-lxc".into()),
                strict_proxy_enforced_by_axis: false,
                resource_limits_enforced_by_axis: true,
            },
        )
        .unwrap();
        assert_eq!(config.containment, MxcContainment::Lxc);
    }

    #[test]
    fn wslc_resource_limits_are_not_emitted_as_exact_axis_limits() {
        let mut spec = build_container_backend_execution_spec(
            &policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcWindowsWslc,
            wslc_launch_without_bind_mounts(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsWslc),
            &PlannerOptions::new(),
        )
        .unwrap();
        spec.resources.max_memory_mb = 1024;

        let err = build_mxc_container_config(process(), &spec, options("axis-wslc")).unwrap_err();

        assert_eq!(err, MxcConfigError::WslcResourceLimitsUnsupported);
    }

    #[test]
    fn process_inputs_are_validated_before_mxc_config() {
        let spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        let mut process_config = process();
        process_config.command_line = " ".into();
        assert_eq!(
            build_mxc_container_config(process_config, &spec, options("axis-lxc")).unwrap_err(),
            MxcConfigError::EmptyCommandLine
        );

        let mut process_config = process();
        process_config.env.push("BAD_ENV".into());
        assert_eq!(
            build_mxc_container_config(process_config, &spec, options("axis-lxc")).unwrap_err(),
            MxcConfigError::InvalidEnvironmentEntry
        );
    }

    #[test]
    fn container_config_rejects_secret_env_before_mxc_json() {
        let spec = lxc_execution_spec(NetworkMode::Allow).unwrap();
        let mut process_config = process();
        process_config
            .env
            .push("ANTHROPIC_API_KEY=super-secret-token".into());

        let err =
            build_mxc_container_config(process_config, &spec, options("axis-lxc")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::FilteredEnvironmentEntry {
                key: "ANTHROPIC_API_KEY".into()
            }
        );
        assert!(!err.to_string().contains("super-secret-token"));
    }

    #[test]
    fn vm_inputs_are_validated_before_mxc_config() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        let mut process_config = vm_process();
        process_config.command_line = " ".into();
        assert_eq!(
            build_mxc_vm_config(process_config, &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::EmptyCommandLine
        );

        let mut process_config = vm_process();
        process_config.env.push("BAD_ENV".into());
        assert_eq!(
            build_mxc_vm_config(process_config, &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::InvalidEnvironmentEntry
        );
    }

    #[test]
    fn vm_config_rejects_inherited_proxy_env_before_mxc_json() {
        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        let mut process_config = vm_process();
        process_config
            .env
            .push("HTTPS_PROXY=http://proxy-with-creds".into());

        let err = build_mxc_vm_config(process_config, &spec, vm_options("axis-vm")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::FilteredEnvironmentEntry {
                key: "HTTPS_PROXY".into()
            }
        );
        assert!(!err.to_string().contains("proxy-with-creds"));
    }

    #[test]
    fn vm_config_rejects_custom_image_sources_before_mxc_config() {
        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxMicrovm,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        spec.image = VmImageSource::MicrovmImage {
            image_path: "/var/lib/axis/microvm.img".into(),
            image_home: Some("/var/lib/axis/images".into()),
        };

        let err = build_mxc_vm_config(vm_process(), &spec, vm_options("axis-microvm")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::VmImageSourceUnsupported {
                backend: "mxc-linux-microvm".into()
            }
        );
    }

    #[test]
    fn vm_config_rejects_unmapped_launch_fields_before_mxc_config() {
        let base = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();

        let mut spec = base.clone();
        spec.guest_working_dir = Some("/workspace".into());
        assert_eq!(
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::VmGuestWorkingDirectoryUnsupported {
                backend: "mxc-linux-hyperlight".into()
            }
        );

        let mut spec = base.clone();
        spec.copy_in = vec![VmCopyPath {
            host_path: "/tmp/in".into(),
            guest_path: "/workspace/in".into(),
        }];
        assert_eq!(
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::VmCopyPathsUnsupported {
                backend: "mxc-linux-hyperlight".into()
            }
        );

        let mut spec = base.clone();
        spec.required_features = vec!["snapshot_restore".into()];
        assert_eq!(
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::VmFeatureFlagsUnsupported {
                backend: "mxc-linux-hyperlight".into()
            }
        );

        let mut spec = base;
        spec.destroy_on_exit = false;
        assert_eq!(
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-vm")).unwrap_err(),
            MxcConfigError::VmPersistentStateUnsupported {
                backend: "mxc-linux-hyperlight".into()
            }
        );
    }

    #[test]
    fn vm_config_rejects_endpoint_policies_outside_strict_proxy_mode() {
        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Allow,
            vm_policy(NetworkMode::Allow),
        )
        .unwrap();
        spec.network.endpoint_policy_names.push("github".into());

        let err =
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-hyperlight")).unwrap_err();

        assert_eq!(err, MxcConfigError::EndpointPolicyRequiresStrictProxy);
    }

    #[test]
    fn vm_config_rejects_strict_proxy_without_axis_owned_network_layer() {
        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxHyperlight,
            NetworkMode::Allow,
            vm_policy(NetworkMode::Allow),
        )
        .unwrap();
        spec.network.mode = VmBackendNetworkMode::StrictProxy;

        let err =
            build_mxc_vm_config(vm_process(), &spec, vm_options("axis-hyperlight")).unwrap_err();
        assert_eq!(err, MxcConfigError::StrictProxyRequiresAxisLayer);

        let config = build_mxc_vm_config(
            vm_process(),
            &spec,
            MxcVmConfigOptions {
                container_id: Some("axis-hyperlight".into()),
                strict_proxy_enforced_by_axis: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            config.network.default_policy,
            MxcNetworkDefaultPolicy::Allow
        );
    }

    #[test]
    fn vm_config_rejects_backend_network_modes_that_mxc_cannot_enforce() {
        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxMicrovm,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        spec.network.mode = VmBackendNetworkMode::Allow;

        let err = build_mxc_vm_config(vm_process(), &spec, vm_options("axis-microvm")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::VmNetworkModeUnsupported {
                backend: "mxc-linux-microvm".into(),
                mode: VmBackendNetworkMode::Allow,
            }
        );

        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcWindowsIsolationSession,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        spec.network.mode = VmBackendNetworkMode::StrictProxy;

        let err = build_mxc_vm_config(
            vm_process(),
            &spec,
            MxcVmConfigOptions {
                strict_proxy_enforced_by_axis: true,
                ..vm_options("axis-isolation-session")
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::VmNetworkModeUnsupported {
                backend: "mxc-windows-isolation-session".into(),
                mode: VmBackendNetworkMode::StrictProxy,
            }
        );
    }

    #[test]
    fn vm_config_rejects_filesystem_modes_that_mxc_cannot_enforce() {
        let mut spec = vm_execution_spec(
            BackendCapabilityMapId::MxcLinuxMicrovm,
            NetworkMode::Block,
            vm_policy(NetworkMode::Block),
        )
        .unwrap();
        spec.filesystem.deny = vec!["/home/user/.ssh".into()];

        let err = build_mxc_vm_config(vm_process(), &spec, vm_options("axis-microvm")).unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::VmDeniedPathsUnsupported {
                backend: "mxc-linux-microvm".into()
            }
        );

        let spec = vm_execution_spec(
            BackendCapabilityMapId::MxcWindowsSandbox,
            NetworkMode::Block,
            vm_empty_filesystem_policy(NetworkMode::Block),
        )
        .unwrap();
        let mut spec = spec;
        spec.filesystem = VmBackendFilesystemSpec {
            read_only: vec!["C:\\reference".into()],
            read_write: vec!["C:\\workspace".into()],
            deny: Vec::new(),
        };

        let err = build_mxc_vm_config(vm_process(), &spec, vm_options("axis-windows-sandbox"))
            .unwrap_err();

        assert_eq!(
            err,
            MxcConfigError::VmFilesystemUnsupported {
                backend: "mxc-windows-sandbox".into()
            }
        );
    }

    fn lxc_execution_spec(
        mode: NetworkMode,
    ) -> Result<ContainerBackendExecutionSpec, ContainerBackendSpecError> {
        let proxy_mode = matches!(mode, NetworkMode::Proxy);
        let mut policy = policy(mode);
        if proxy_mode {
            policy.network.policies.push(endpoint_policy_with_binary());
        }
        build_container_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxLxc,
            lxc_launch(),
            &present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxLxc),
            &PlannerOptions::new(),
        )
    }

    fn process() -> MxcProcessConfig {
        MxcProcessConfig {
            command_line: "echo container".into(),
            cwd: Some("/workspace".into()),
            env: vec!["PATH=/usr/bin".into()],
            timeout: Some(5000),
        }
    }

    fn options(container_id: &str) -> MxcContainerConfigOptions {
        MxcContainerConfigOptions {
            container_id: Some(container_id.into()),
            strict_proxy_enforced_by_axis: false,
            resource_limits_enforced_by_axis: true,
        }
    }

    fn process_options(container_id: &str) -> MxcProcessConfigOptions {
        MxcProcessConfigOptions {
            container_id: Some(container_id.into()),
            resource_limits_enforced_by_axis: true,
            ..Default::default()
        }
    }

    fn vm_options(container_id: &str) -> MxcVmConfigOptions {
        MxcVmConfigOptions {
            container_id: Some(container_id.into()),
            strict_proxy_enforced_by_axis: false,
            windows_sandbox: None,
            isolation_session: None,
        }
    }

    fn vm_process() -> MxcProcessConfig {
        MxcProcessConfig {
            command_line: "print('vm')".into(),
            cwd: None,
            env: vec!["AXIS_VM_TEST=1".into()],
            timeout: Some(30_000),
        }
    }

    fn present_runtime_for_backend(id: BackendCapabilityMapId) -> RuntimeProbeSnapshot {
        backend_capability_map(id).host_dependencies.iter().fold(
            RuntimeProbeSnapshot::new(),
            |runtime, dependency| {
                runtime.with_dependency(&dependency.name, DependencyState::Present)
            },
        )
    }

    fn vm_execution_spec(
        id: BackendCapabilityMapId,
        mode: NetworkMode,
        policy: Policy,
    ) -> Result<VmBackendExecutionSpec, VmBackendSpecError> {
        build_vm_backend_execution_spec(
            &policy,
            id,
            vm_launch(),
            &present_runtime_for_backend(id),
            &PlannerOptions::new(),
        )
        .map(|mut spec| {
            spec.network.mode = match mode {
                NetworkMode::Allow => VmBackendNetworkMode::Allow,
                NetworkMode::Block => VmBackendNetworkMode::Block,
                NetworkMode::Proxy => VmBackendNetworkMode::StrictProxy,
            };
            spec
        })
    }

    fn vm_launch() -> VmLaunchOptions {
        VmLaunchOptions {
            image: VmImageSource::RuntimeDefault,
            architecture: Some("x86_64".into()),
            guest_agent: Some("axis-guest-agent".into()),
            guest_working_dir: None,
            copy_in: Vec::new(),
            copy_out: Vec::new(),
            required_features: Vec::new(),
            destroy_on_exit: true,
        }
    }

    fn lxc_launch() -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::LxcDistributionRelease {
                distribution: "alpine".into(),
                release: "3.23".into(),
            },
            storage_path: None,
            working_dir: Some("/workspace".into()),
            bind_mounts: vec![ContainerBindMount {
                host_path: "/workspace".into(),
                container_path: "/workspace".into(),
                access: ContainerMountAccess::ReadWrite,
            }],
            destroy_on_exit: true,
        }
    }

    fn process_execution_spec(
        id: BackendCapabilityMapId,
        mode: NetworkMode,
    ) -> Result<ProcessBackendExecutionSpec, ProcessBackendSpecError> {
        let mut policy = process_policy(mode);
        if id == BackendCapabilityMapId::MxcWindowsProcessContainer {
            policy.filesystem.deny.clear();
        }
        build_process_backend_execution_spec(
            &policy,
            id,
            process_launch(),
            &present_runtime_for_backend(id),
            &PlannerOptions::new(),
        )
    }

    fn process_launch() -> ProcessLaunchOptions {
        ProcessLaunchOptions {
            command: "agent".into(),
            args: vec!["--version".into()],
            working_dir: Some("/workspace".into()),
            environment: BTreeMap::from([("AXIS_TEST".into(), "1".into())]),
            capture_output: true,
            timeout_sec: Some(3),
        }
    }

    fn process_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "mxc-process-config-test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into()],
                read_write: vec!["/workspace".into()],
                deny: vec!["/home/user/.ssh".into()],
                compatibility: Default::default(),
                workspace_read_only: false,
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..Default::default()
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

    fn wslc_launch_without_bind_mounts() -> ContainerLaunchOptions {
        ContainerLaunchOptions {
            rootfs: ContainerRootfsSource::WslImage {
                image: "alpine:latest".into(),
            },
            storage_path: Some("C:\\axis\\wslc".into()),
            working_dir: Some("/workspace".into()),
            bind_mounts: Vec::new(),
            destroy_on_exit: true,
        }
    }

    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "mxc-container-config-test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy {
                read_only: Vec::new(),
                read_write: vec!["/workspace".into()],
                deny: Vec::new(),
                compatibility: Default::default(),
                workspace_read_only: false,
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..Default::default()
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

    fn vm_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "mxc-vm-config-test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/opt/axis-ref".into()],
                read_write: vec!["/workspace".into()],
                deny: Vec::new(),
                compatibility: Default::default(),
                workspace_read_only: false,
            },
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..Default::default()
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

    fn vm_empty_filesystem_policy(mode: NetworkMode) -> Policy {
        let mut policy = vm_policy(mode);
        policy.filesystem = FilesystemPolicy {
            read_only: Vec::new(),
            read_write: Vec::new(),
            deny: Vec::new(),
            compatibility: Default::default(),
            workspace_read_only: false,
        };
        policy
    }

    fn endpoint_policy_with_binary() -> EndpointPolicy {
        EndpointPolicy {
            name: "github".into(),
            endpoints: vec![Endpoint {
                host: "api.github.com".into(),
                port: 443,
                access: Access::ReadWrite,
                protocol: None,
                rules: Vec::new(),
            }],
            binaries: vec![BinaryMatch {
                path: "/usr/bin/git".into(),
            }],
        }
    }
}
