// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Process-style backend planning.
//!
//! This module keeps process backend selection platform-neutral. Platform
//! adapters consume these descriptors, then translate only planner-approved
//! launches into their local config formats.

use crate::capability::{
    BackendPlatform, BackendPolicyPlan, PlannerOptions, RuntimeProbeSnapshot, plan_backend_policy,
};
use crate::capability_map::{
    BackendCapabilityMapId, backend_capability_map, backend_capability_maps_for_platform,
};
use crate::policy::{NetworkMode, Policy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBackendConfigFormat {
    AxisNativeLinux,
    MxcLinuxJson,
    AxisNativeMacosSeatbeltProfile,
    MxcMacosSeatbeltProfile,
    AxisNativeWindowsProcess,
    MxcWindowsProcessContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendDescriptor {
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub config_format: ProcessBackendConfigFormat,
    pub native_axis_backend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBackendRetentionDecision {
    Retain,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativeProcessBackendRetention {
    pub id: BackendCapabilityMapId,
    pub platform: BackendPlatform,
    pub decision: NativeBackendRetentionDecision,
    pub rationale: &'static str,
    pub advantages: &'static [&'static str],
    pub replacement_requirements: &'static [&'static str],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessBackendSpecError {
    #[error("{0:?} is not a process-style backend")]
    NotProcessBackend(BackendCapabilityMapId),

    #[error("process backend rejected policy before config generation: {0}")]
    RejectedBeforeConfig(String),

    #[error("process command must not be empty")]
    EmptyCommand,

    #[error("process environment key must not be empty")]
    EmptyEnvironmentKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLaunchOptions {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub capture_output: bool,
    #[serde(default)]
    pub timeout_sec: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBackendNetworkMode {
    Allow,
    Block,
    StrictProxy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendFilesystemSpec {
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendNetworkSpec {
    pub mode: ProcessBackendNetworkMode,
    #[serde(default)]
    pub endpoint_policy_names: Vec<String>,
    pub binary_attribution_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendResourceSpec {
    pub max_processes: u32,
    pub max_memory_mb: u64,
    pub cpu_rate_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBackendExecutionSpec {
    pub backend: String,
    pub platform: BackendPlatform,
    pub config_format: ProcessBackendConfigFormat,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub filesystem: ProcessBackendFilesystemSpec,
    pub network: ProcessBackendNetworkSpec,
    pub resources: ProcessBackendResourceSpec,
    #[serde(default)]
    pub capture_output: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessBackendPlan {
    pub descriptor: ProcessBackendDescriptor,
    pub policy_plan: BackendPolicyPlan,
}

impl ProcessBackendPlan {
    pub fn spawn_allowed(&self) -> bool {
        self.policy_plan.spawn_allowed()
    }

    pub fn pre_spawn_error(&self) -> Option<String> {
        self.policy_plan.pre_spawn_error()
    }
}

pub const PROCESS_BACKEND_DESCRIPTORS: &[ProcessBackendDescriptor] = &[
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeLinux,
        platform: BackendPlatform::Linux,
        config_format: ProcessBackendConfigFormat::AxisNativeLinux,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcLinuxBubblewrap,
        platform: BackendPlatform::Linux,
        config_format: ProcessBackendConfigFormat::MxcLinuxJson,
        native_axis_backend: false,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeMacosSeatbelt,
        platform: BackendPlatform::Macos,
        config_format: ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcMacosSeatbelt,
        platform: BackendPlatform::Macos,
        config_format: ProcessBackendConfigFormat::MxcMacosSeatbeltProfile,
        native_axis_backend: false,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::AxisNativeWindows,
        platform: BackendPlatform::Windows,
        config_format: ProcessBackendConfigFormat::AxisNativeWindowsProcess,
        native_axis_backend: true,
    },
    ProcessBackendDescriptor {
        id: BackendCapabilityMapId::MxcWindowsProcessContainer,
        platform: BackendPlatform::Windows,
        config_format: ProcessBackendConfigFormat::MxcWindowsProcessContainer,
        native_axis_backend: false,
    },
];

pub const NATIVE_PROCESS_BACKEND_RETENTION: &[NativeProcessBackendRetention] = &[
    NativeProcessBackendRetention {
        id: BackendCapabilityMapId::AxisNativeLinux,
        platform: BackendPlatform::Linux,
        decision: NativeBackendRetentionDecision::Retain,
        rationale: "Retain the direct Landlock plus seccomp path for the no-container quickstart, direct syscall filtering, and AXIS strict-proxy integration until an MXC process backend proves equivalent semantics and startup behavior.",
        advantages: &[
            "direct seccomp filtering",
            "Landlock filesystem deny semantics",
            "lightweight process startup",
            "strict proxy integration",
            "seccomp-notify binary attribution",
        ],
        replacement_requirements: &[
            "matching AXIS policy semantics",
            "equivalent native backend tests",
            "benchmark evidence for startup, teardown, memory, and density",
        ],
    },
    NativeProcessBackendRetention {
        id: BackendCapabilityMapId::AxisNativeMacosSeatbelt,
        platform: BackendPlatform::Macos,
        decision: NativeBackendRetentionDecision::Retain,
        rationale: "Retain the direct Seatbelt path while it provides the no-extra-runtime macOS process sandbox and until the MXC Seatbelt path proves the same profile, lifecycle, and packaging behavior.",
        advantages: &[
            "direct Seatbelt profile generation",
            "no packaged MXC executor dependency for default process sandboxing",
            "platform-native filesystem and network-deny controls",
        ],
        replacement_requirements: &[
            "matching AXIS policy semantics",
            "equivalent native backend tests",
            "benchmark evidence for startup, teardown, memory, and density",
        ],
    },
    NativeProcessBackendRetention {
        id: BackendCapabilityMapId::AxisNativeWindows,
        platform: BackendPlatform::Windows,
        decision: NativeBackendRetentionDecision::Disabled,
        rationale: "Disable the native Windows launch path until Job Object, restricted-token/AppContainer, ACL, proxy, environment, lifecycle, and cleanup controls are applied before user code executes.",
        advantages: &[
            "Job Object implementation asset",
            "restricted-token and AppContainer implementation assets",
            "NTFS ACL implementation asset",
        ],
        replacement_requirements: &[
            "matching AXIS policy semantics",
            "complete pre-execution native backend tests",
            "benchmark evidence after the containment boundary is enabled",
        ],
    },
];

pub fn process_backend_descriptors() -> &'static [ProcessBackendDescriptor] {
    PROCESS_BACKEND_DESCRIPTORS
}

pub fn native_process_backend_retention_decisions() -> &'static [NativeProcessBackendRetention] {
    NATIVE_PROCESS_BACKEND_RETENTION
}

pub fn native_process_backend_retention(
    id: BackendCapabilityMapId,
) -> Option<&'static NativeProcessBackendRetention> {
    NATIVE_PROCESS_BACKEND_RETENTION
        .iter()
        .find(|retention| retention.id == id)
}

pub fn process_backend_descriptor(
    id: BackendCapabilityMapId,
) -> Option<&'static ProcessBackendDescriptor> {
    PROCESS_BACKEND_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.id == id)
}

pub fn process_backend_descriptors_for_platform(
    platform: BackendPlatform,
) -> Vec<&'static ProcessBackendDescriptor> {
    PROCESS_BACKEND_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.platform == platform)
        .collect()
}

pub fn plan_process_backend_policy(
    policy: &Policy,
    id: BackendCapabilityMapId,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Option<ProcessBackendPlan> {
    let descriptor = *process_backend_descriptor(id)?;
    let backend = backend_capability_map(id);
    let policy_plan = plan_backend_policy(policy, &backend, runtime, options);

    Some(ProcessBackendPlan {
        descriptor,
        policy_plan,
    })
}

pub fn process_backend_maps_for_platform(
    platform: BackendPlatform,
) -> Vec<crate::capability::BackendCapabilities> {
    backend_capability_maps_for_platform(platform)
        .into_iter()
        .filter(|backend| {
            PROCESS_BACKEND_DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.id.as_str() == backend.name)
        })
        .collect()
}

pub fn build_process_backend_execution_spec(
    policy: &Policy,
    id: BackendCapabilityMapId,
    launch: ProcessLaunchOptions,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> Result<ProcessBackendExecutionSpec, ProcessBackendSpecError> {
    validate_process_launch_options(&launch)?;

    let plan = plan_process_backend_policy(policy, id, runtime, options)
        .ok_or(ProcessBackendSpecError::NotProcessBackend(id))?;
    if !plan.spawn_allowed() {
        return Err(ProcessBackendSpecError::RejectedBeforeConfig(
            plan.pre_spawn_error()
                .unwrap_or_else(|| "unknown process backend planning failure".into()),
        ));
    }

    Ok(ProcessBackendExecutionSpec {
        backend: plan.descriptor.id.as_str().into(),
        platform: plan.descriptor.platform,
        config_format: plan.descriptor.config_format,
        command: launch.command,
        args: launch.args,
        working_dir: launch.working_dir,
        environment: launch.environment,
        filesystem: process_filesystem_spec(policy),
        network: process_network_spec(policy),
        resources: ProcessBackendResourceSpec {
            max_processes: policy.process.effective_max_processes(),
            max_memory_mb: policy.process.max_memory_mb,
            cpu_rate_percent: policy.process.cpu_rate_percent,
        },
        capture_output: launch.capture_output,
        timeout_ms: launch
            .timeout_sec
            .or(policy.process.timeout_sec)
            .map(|seconds| seconds.saturating_mul(1000)),
    })
}

fn validate_process_launch_options(
    launch: &ProcessLaunchOptions,
) -> Result<(), ProcessBackendSpecError> {
    if launch.command.trim().is_empty() {
        return Err(ProcessBackendSpecError::EmptyCommand);
    }
    if launch.environment.keys().any(|key| key.trim().is_empty()) {
        return Err(ProcessBackendSpecError::EmptyEnvironmentKey);
    }
    Ok(())
}

fn process_filesystem_spec(policy: &Policy) -> ProcessBackendFilesystemSpec {
    ProcessBackendFilesystemSpec {
        read_only: policy.filesystem.read_only.clone(),
        read_write: policy.filesystem.read_write.clone(),
        deny: policy.filesystem.deny.clone(),
    }
}

fn process_network_spec(policy: &Policy) -> ProcessBackendNetworkSpec {
    ProcessBackendNetworkSpec {
        mode: match policy.network.mode {
            NetworkMode::Allow => ProcessBackendNetworkMode::Allow,
            NetworkMode::Block => ProcessBackendNetworkMode::Block,
            NetworkMode::Proxy => ProcessBackendNetworkMode::StrictProxy,
        },
        endpoint_policy_names: policy
            .network
            .policies
            .iter()
            .map(|policy| policy.name.clone())
            .collect(),
        binary_attribution_required: policy
            .network
            .policies
            .iter()
            .any(|policy| !policy.binaries.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{BackendPlanOutcome, CapabilitySupport, DependencyState};
    use crate::capability_map::{backend_capability_map, host_dependency};
    use crate::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, NetworkMode, NetworkPolicy, Policy, ProcessPolicy, SshPolicy,
    };
    use std::collections::BTreeSet;

    #[test]
    fn process_backend_catalog_covers_required_platform_paths() {
        let ids = process_backend_descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<BTreeSet<_>>();

        for id in [
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            BackendCapabilityMapId::AxisNativeLinux,
            BackendCapabilityMapId::AxisNativeMacosSeatbelt,
            BackendCapabilityMapId::AxisNativeWindows,
        ] {
            assert!(ids.contains(&id), "missing process backend {id:?}");
        }
    }

    #[test]
    fn process_backend_catalog_is_partitioned_by_platform() {
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Linux).len(),
            2
        );
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Macos).len(),
            2
        );
        assert_eq!(
            process_backend_descriptors_for_platform(BackendPlatform::Windows).len(),
            2
        );
        assert!(process_backend_descriptors_for_platform(BackendPlatform::Other).is_empty());
    }

    #[test]
    fn process_backend_maps_are_filterable_by_platform() {
        let linux_maps = process_backend_maps_for_platform(BackendPlatform::Linux);

        assert_eq!(linux_maps.len(), 2);
        assert!(
            linux_maps
                .iter()
                .any(|backend| backend.name == "mxc-linux-bubblewrap")
        );
        assert!(
            linux_maps
                .iter()
                .all(|backend| backend.platform == BackendPlatform::Linux)
        );
    }

    #[test]
    fn process_backend_config_formats_are_explicit() {
        for descriptor in process_backend_descriptors() {
            match descriptor.id {
                BackendCapabilityMapId::AxisNativeLinux => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeLinux
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcLinuxBubblewrap => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcLinuxJson
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::AxisNativeMacosSeatbelt => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeMacosSeatbeltProfile
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcMacosSeatbelt => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcMacosSeatbeltProfile
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::AxisNativeWindows => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::AxisNativeWindowsProcess
                    );
                    assert!(descriptor.native_axis_backend);
                }
                BackendCapabilityMapId::MxcWindowsProcessContainer => {
                    assert_eq!(
                        descriptor.config_format,
                        ProcessBackendConfigFormat::MxcWindowsProcessContainer
                    );
                    assert!(!descriptor.native_axis_backend);
                }
                other => panic!("unexpected process backend descriptor {other:?}"),
            }
        }
    }

    #[test]
    fn native_retention_decisions_cover_every_native_process_backend() {
        let native_ids = process_backend_descriptors()
            .iter()
            .filter(|descriptor| descriptor.native_axis_backend)
            .map(|descriptor| descriptor.id)
            .collect::<BTreeSet<_>>();
        let retention_ids = native_process_backend_retention_decisions()
            .iter()
            .map(|retention| retention.id)
            .collect::<BTreeSet<_>>();

        assert_eq!(native_ids, retention_ids);
    }

    #[test]
    fn native_retention_decisions_are_planner_backed() {
        for retention in native_process_backend_retention_decisions() {
            let descriptor = process_backend_descriptor(retention.id)
                .expect("retained native backend must be a process descriptor");
            let backend = crate::capability_map::backend_capability_map(retention.id);

            assert!(descriptor.native_axis_backend);
            assert_eq!(descriptor.platform, retention.platform);
            assert_eq!(backend.platform, retention.platform);
            if retention.decision == NativeBackendRetentionDecision::Disabled {
                assert!(matches!(
                    backend.process.command,
                    CapabilitySupport::Unsupported { .. }
                ));
            } else {
                assert_eq!(retention.decision, NativeBackendRetentionDecision::Retain);
            }
            assert!(!retention.rationale.trim().is_empty());
            assert!(!retention.advantages.is_empty());
            assert!(!retention.replacement_requirements.is_empty());
            for value in retention
                .advantages
                .iter()
                .chain(retention.replacement_requirements.iter())
            {
                assert!(!value.trim().is_empty());
            }
        }
    }

    #[test]
    fn native_retention_decisions_require_tests_and_benchmarks_before_replacement() {
        for retention in native_process_backend_retention_decisions() {
            assert!(
                retention
                    .replacement_requirements
                    .iter()
                    .any(|requirement| requirement.contains("matching AXIS policy semantics")),
                "{retention:?}"
            );
            assert!(
                retention
                    .replacement_requirements
                    .iter()
                    .any(|requirement| requirement.contains("tests")),
                "{retention:?}"
            );
            assert!(
                retention
                    .replacement_requirements
                    .iter()
                    .any(|requirement| requirement.contains("benchmark evidence")),
                "{retention:?}"
            );
        }
    }

    #[test]
    fn linux_native_retention_identifies_seccomp_and_strict_proxy_advantages() {
        let retention =
            native_process_backend_retention(BackendCapabilityMapId::AxisNativeLinux).unwrap();

        assert!(
            retention
                .advantages
                .iter()
                .any(|advantage| advantage.contains("direct seccomp filtering"))
        );
        assert!(
            retention
                .advantages
                .iter()
                .any(|advantage| advantage.contains("strict proxy integration"))
        );
    }

    #[test]
    fn process_execution_spec_covers_all_process_backend_formats() {
        for descriptor in process_backend_descriptors() {
            let mut policy = process_policy(NetworkMode::Allow);
            if descriptor.id == BackendCapabilityMapId::MxcWindowsProcessContainer {
                policy.filesystem.deny.clear();
            }
            let runtime = present_runtime_for_backend(descriptor.id);
            let result = build_process_backend_execution_spec(
                &policy,
                descriptor.id,
                launch_options(),
                &runtime,
                &PlannerOptions::new(),
            );
            if descriptor.id == BackendCapabilityMapId::AxisNativeWindows {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("native Windows containment is disabled"));
                continue;
            }
            let spec = result.unwrap_or_else(|err| {
                panic!("{} rejected unexpectedly: {err}", descriptor.id.as_str())
            });

            assert_eq!(spec.backend, descriptor.id.as_str());
            assert_eq!(spec.platform, descriptor.platform);
            assert_eq!(spec.config_format, descriptor.config_format);
            assert_eq!(spec.command, "agent");
            assert_eq!(spec.args, ["--version"]);
            assert_eq!(spec.network.mode, ProcessBackendNetworkMode::Allow);
            assert_eq!(spec.filesystem.read_write, ["{workspace}"]);
            assert_eq!(spec.resources.max_processes, 0);
        }
    }

    #[test]
    fn process_execution_spec_rejects_non_process_backend_before_config() {
        let err = build_process_backend_execution_spec(
            &process_policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxLxc,
            launch_options(),
            &RuntimeProbeSnapshot::new(),
            &PlannerOptions::new(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            ProcessBackendSpecError::NotProcessBackend(BackendCapabilityMapId::MxcLinuxLxc)
        );
    }

    #[test]
    fn process_execution_spec_rejects_invalid_launch_options_before_planning() {
        let mut launch = launch_options();
        launch.command = " ".into();
        let err = build_process_backend_execution_spec(
            &process_policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            launch,
            &RuntimeProbeSnapshot::new(),
            &PlannerOptions::new(),
        )
        .unwrap_err();
        assert_eq!(err, ProcessBackendSpecError::EmptyCommand);

        let mut launch = launch_options();
        launch.environment.insert(" ".into(), "bad".into());
        let err = build_process_backend_execution_spec(
            &process_policy(NetworkMode::Allow),
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            launch,
            &RuntimeProbeSnapshot::new(),
            &PlannerOptions::new(),
        )
        .unwrap_err();
        assert_eq!(err, ProcessBackendSpecError::EmptyEnvironmentKey);
    }

    #[test]
    fn process_execution_spec_for_macos_mxc_rejects_syscall_filtering_before_config() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.blocked_syscalls.push("ptrace".into());
        let runtime = present_runtime_for_backend(BackendCapabilityMapId::MxcMacosSeatbelt);

        let err = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            launch_options(),
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ProcessBackendSpecError::RejectedBeforeConfig(_)
        ));
        assert!(err.to_string().contains("process.syscall_filtering"));
    }

    #[test]
    fn process_execution_spec_for_windows_mxc_accepts_proxy_with_wfp_dependencies() {
        let runtime =
            present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsProcessContainer);
        let mut policy = process_policy(NetworkMode::Proxy);
        // BaseContainer deny normalization is owned by the Windows adapter and
        // runs before this platform-neutral execution-spec builder.
        policy.filesystem.deny.clear();

        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            launch_options(),
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert_eq!(spec.network.mode, ProcessBackendNetworkMode::StrictProxy);
    }

    #[test]
    fn process_execution_spec_serializes_fake_executor_boundary() {
        let policy = process_policy(NetworkMode::Block);
        let runtime = present_runtime_for_backend(BackendCapabilityMapId::MxcLinuxBubblewrap);
        let mut launch = launch_options();
        launch.timeout_sec = Some(2);
        launch.environment.insert("AXIS_TEST".into(), "1".into());

        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        let json = serde_json::to_value(&spec).unwrap();

        assert_eq!(json["backend"], "mxc-linux-bubblewrap");
        assert_eq!(json["config_format"], "mxc_linux_json");
        assert_eq!(json["network"]["mode"], "block");
        assert_eq!(json["timeout_ms"], 2000);
        assert_eq!(json["environment"]["AXIS_TEST"], "1");
    }

    #[test]
    fn process_resource_limits_are_planned_or_rejected_by_backend() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.max_processes = 8;
        policy.process.max_memory_mb = 256;
        policy.process.cpu_rate_percent = 50;

        for descriptor in process_backend_descriptors() {
            let runtime = present_runtime_for_backend(descriptor.id);
            let mut backend_policy = policy.clone();
            if descriptor.id == BackendCapabilityMapId::MxcWindowsProcessContainer {
                // BaseContainer deny normalization precedes the portable planner.
                backend_policy.filesystem.deny.clear();
            }
            let plan = plan_process_backend_policy(
                &backend_policy,
                descriptor.id,
                &runtime,
                &PlannerOptions::new(),
            )
            .unwrap_or_else(|| panic!("{} should be a process backend", descriptor.id.as_str()));

            for requirement in [
                "resources.process_count",
                "resources.memory",
                "resources.cpu",
                "cleanup.resources",
            ] {
                assert!(
                    plan.policy_plan
                        .decisions
                        .iter()
                        .any(|decision| decision.requirement == requirement),
                    "{} missing planner decision {requirement}",
                    descriptor.id.as_str()
                );
            }

            match descriptor.id {
                BackendCapabilityMapId::AxisNativeLinux
                | BackendCapabilityMapId::MxcLinuxBubblewrap
                | BackendCapabilityMapId::MxcWindowsProcessContainer => {
                    assert!(
                        plan.spawn_allowed(),
                        "{} should accept resource limits with declared dependencies present: {:?}",
                        descriptor.id.as_str(),
                        plan.pre_spawn_error()
                    );
                }
                BackendCapabilityMapId::AxisNativeMacosSeatbelt
                | BackendCapabilityMapId::MxcMacosSeatbelt => {
                    assert!(
                        !plan.spawn_allowed(),
                        "{} should reject resource limits that do not have exact AXIS semantics",
                        descriptor.id.as_str()
                    );
                    let error = plan.pre_spawn_error().unwrap();
                    assert!(error.contains("resources.memory"), "{error}");
                    assert!(error.contains("resources.cpu"), "{error}");
                }
                BackendCapabilityMapId::AxisNativeWindows => {
                    assert!(!plan.spawn_allowed());
                    assert!(
                        plan.pre_spawn_error()
                            .unwrap()
                            .contains("native Windows containment is disabled")
                    );
                }
                other => panic!("unexpected process backend descriptor {other:?}"),
            }
        }
    }

    #[test]
    fn mxc_windows_resources_require_job_object_dependency() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.filesystem.deny.clear();
        policy.process.max_processes = 8;
        policy.process.max_memory_mb = 256;
        policy.process.cpu_rate_percent = 50;

        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::WINDOWS_PROCESS_CONTAINER,
                DependencyState::Present,
            );
        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("resources.process_count"), "{error}");
        assert!(
            error.contains(host_dependency::WINDOWS_JOBOBJECT),
            "{error}"
        );
    }

    #[test]
    fn mxc_windows_resources_use_inner_job_accounting() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.filesystem.deny.clear();
        policy.process.max_processes = 8;
        policy.process.max_memory_mb = 256;
        policy.process.cpu_rate_percent = 50;
        let runtime =
            present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsProcessContainer);
        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        for requirement in [
            "resources.process_count",
            "resources.memory",
            "resources.cpu",
            "cleanup.resources",
        ] {
            let decision = plan
                .policy_plan
                .decisions
                .iter()
                .find(|decision| decision.requirement == requirement)
                .unwrap();
            assert!(
                !matches!(
                    decision.support,
                    CapabilitySupport::Unsupported { .. } | CapabilitySupport::WeakerOnly { .. }
                ),
                "{decision:?}"
            );
        }
    }

    #[test]
    fn planner_records_process_surfaces_for_mxc_linux() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let mut policy = process_policy(NetworkMode::Block);
        policy.process.timeout_sec = Some(5);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        for requirement in [
            "filesystem.read_only",
            "filesystem.read_write",
            "filesystem.deny",
            "filesystem.workspace",
            "process.command",
            "process.working_dir",
            "process.environment",
            "process.stdio",
            "process.timeout",
            "resources.timeout",
            "network.block",
        ] {
            assert!(
                plan.policy_plan
                    .decisions
                    .iter()
                    .any(|decision| decision.requirement == requirement),
                "missing planner decision {requirement}"
            );
        }
    }

    #[test]
    fn mxc_bubblewrap_cooperative_proxy_is_weaker_only() {
        let backend = backend_capability_map(BackendCapabilityMapId::MxcLinuxBubblewrap);

        let CapabilitySupport::WeakerOnly { reason } = backend.network.cooperative_proxy else {
            panic!("MXC bubblewrap cooperative proxy must not be treated as exact");
        };

        assert!(reason.contains("proxy environment"));
        assert!(reason.contains("direct sockets"));
    }

    #[test]
    fn strict_proxy_requires_selected_axis_boundary_for_mxc_linux_process_backend() {
        let base_runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let policy = process_policy(NetworkMode::Proxy);

        let rejected = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &base_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        assert!(!rejected.spawn_allowed());
        assert!(
            rejected
                .pre_spawn_error()
                .unwrap()
                .contains(host_dependency::LINUX_STRICT_PROXY)
        );

        let runtime = base_runtime.with_dependency(
            host_dependency::LINUX_STRICT_PROXY,
            DependencyState::Present,
        );
        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
        let strict_proxy = plan
            .policy_plan
            .decisions
            .iter()
            .find(|decision| decision.requirement == "network.strict_proxy")
            .unwrap();
        assert_eq!(
            strict_proxy.support,
            CapabilitySupport::with_dependency(host_dependency::LINUX_STRICT_PROXY)
        );
    }

    #[test]
    fn binary_restricted_proxy_requires_attribution_dependency() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let mut policy = process_policy(NetworkMode::Proxy);
        policy.network.policies.push(endpoint_policy_with_binary());

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.binary_attribution"));
        assert!(error.contains(host_dependency::LINUX_SECCOMP_NOTIFY));
    }

    #[test]
    fn macos_seatbelt_rejects_syscall_filtering_before_spawn() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.blocked_syscalls.push("ptrace".into());
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.policy_plan.outcome,
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
    fn windows_processcontainer_requires_wfp_for_proxy_and_bypass_evidence() {
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(
                host_dependency::WINDOWS_PROCESS_CONTAINER,
                DependencyState::Present,
            )
            .with_dependency(host_dependency::WINDOWS_JOBOBJECT, DependencyState::Present);
        let mut policy = process_policy(NetworkMode::Proxy);
        // BaseContainer deny normalization precedes the portable planner.
        policy.filesystem.deny.clear();

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(matches!(
            plan.policy_plan.outcome,
            BackendPlanOutcome::ExactWithHostDependency { .. }
        ));
        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains(host_dependency::WINDOWS_WFP_BROKER));

        let strict_proxy = plan
            .policy_plan
            .decisions
            .iter()
            .find(|decision| decision.requirement == "network.strict_proxy")
            .unwrap();
        assert!(matches!(
            strict_proxy.support,
            CapabilitySupport::ExactWithHostDependency { .. }
        ));

        let runtime = runtime.with_dependency(
            host_dependency::WINDOWS_WFP_BROKER,
            DependencyState::Present,
        );
        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        assert!(plan.spawn_allowed(), "{:?}", plan.pre_spawn_error());
    }

    #[test]
    fn windows_binary_attribution_remains_fail_closed_despite_wfp() {
        let runtime =
            present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsProcessContainer);
        let mut policy = process_policy(NetworkMode::Proxy);
        policy.filesystem.deny.clear();
        policy.network.policies.push(endpoint_policy_with_binary());

        let plan = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.binary_attribution"));
        assert!(error.contains("PID reuse"));
    }

    #[test]
    fn process_identity_is_planned_for_native_and_mxc_paths() {
        let mut policy = process_policy(NetworkMode::Allow);
        policy.process.run_as_user = Some("agent".into());

        let linux_runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_BUBBLEWRAP, DependencyState::Present)
            .with_dependency(host_dependency::LINUX_USERNS, DependencyState::Present)
            .with_dependency(
                host_dependency::AXIS_SECCOMP_LAUNCHER,
                DependencyState::Present,
            );
        let linux = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcLinuxBubblewrap,
            &linux_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();
        assert!(linux.spawn_allowed(), "{:?}", linux.pre_spawn_error());
        assert!(
            linux
                .policy_plan
                .decisions
                .iter()
                .any(|decision| decision.requirement == "process.user_identity")
        );

        let macos_runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);
        let macos = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            &macos_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!macos.spawn_allowed());
        assert!(
            macos
                .pre_spawn_error()
                .unwrap()
                .contains("process.user_identity")
        );

        let windows_runtime =
            present_runtime_for_backend(BackendCapabilityMapId::MxcWindowsProcessContainer);
        let windows = plan_process_backend_policy(
            &policy,
            BackendCapabilityMapId::MxcWindowsProcessContainer,
            &windows_runtime,
            &PlannerOptions::new(),
        )
        .unwrap();

        assert!(!windows.spawn_allowed());
        assert!(
            windows
                .pre_spawn_error()
                .unwrap()
                .contains("process.user_identity")
        );
    }

    #[test]
    fn non_process_backend_is_not_plannable_through_process_facade() {
        let runtime = RuntimeProbeSnapshot::new();
        let policy = process_policy(NetworkMode::Allow);

        assert!(
            plan_process_backend_policy(
                &policy,
                BackendCapabilityMapId::MxcLinuxLxc,
                &runtime,
                &PlannerOptions::new()
            )
            .is_none()
        );
    }

    fn present_runtime_for_backend(id: BackendCapabilityMapId) -> RuntimeProbeSnapshot {
        backend_capability_map(id).host_dependencies.iter().fold(
            RuntimeProbeSnapshot::new(),
            |runtime, dependency| {
                runtime.with_dependency(&dependency.name, DependencyState::Present)
            },
        )
    }

    fn launch_options() -> ProcessLaunchOptions {
        ProcessLaunchOptions {
            command: "agent".into(),
            args: vec!["--version".into()],
            working_dir: Some("{workspace}".into()),
            environment: BTreeMap::new(),
            capture_output: true,
            timeout_sec: None,
        }
    }

    fn process_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "process-backend-test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into()],
                read_write: vec!["{workspace}".into()],
                deny: vec!["~/.ssh".into()],
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
