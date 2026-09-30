// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared backend capability planning.
//!
//! This module is intentionally platform-neutral. Platform adapters provide
//! backend capability maps and side-effect-free runtime dependency snapshots;
//! the planner decides whether an AXIS policy can be enforced without knowing
//! about operating-system primitives.

use crate::policy::{NetworkMode, Policy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendPlatform {
    Linux,
    Macos,
    Windows,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendStability {
    Stable,
    Preview,
    Experimental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySurface {
    Filesystem,
    Process,
    Container,
    Vm,
    Network,
    Resources,
    Credentials,
    Inference,
    Lifecycle,
    Cleanup,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDependency {
    pub name: String,
    pub description: String,
}

impl HostDependency {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub platform: BackendPlatform,
    pub name: String,
    pub stability: BackendStability,
    #[serde(default)]
    pub host_dependencies: Vec<HostDependency>,
    pub filesystem: FilesystemCapabilities,
    pub process: ProcessCapabilities,
    pub network: NetworkCapabilities,
    pub resources: ResourceCapabilities,
    pub credentials: CredentialCapabilities,
    pub inference: InferenceCapabilities,
    pub lifecycle: LifecycleCapabilities,
    pub cleanup: CleanupCapabilities,
    pub audit: AuditCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemCapabilities {
    pub read_only: CapabilitySupport,
    pub read_write: CapabilitySupport,
    pub deny: CapabilitySupport,
    pub workspace: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCapabilities {
    pub command: CapabilitySupport,
    pub working_dir: CapabilitySupport,
    pub environment: CapabilitySupport,
    pub stdio: CapabilitySupport,
    pub user_identity: CapabilitySupport,
    pub isolated_identity: CapabilitySupport,
    pub syscall_filtering: CapabilitySupport,
    pub pty: CapabilitySupport,
    pub timeout: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCapabilities {
    pub allow: CapabilitySupport,
    pub block: CapabilitySupport,
    pub strict_proxy: CapabilitySupport,
    pub cooperative_proxy: CapabilitySupport,
    pub endpoint_policy: CapabilitySupport,
    pub binary_attribution: CapabilitySupport,
    pub l7_policy: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    pub process_count: CapabilitySupport,
    pub memory: CapabilitySupport,
    pub cpu: CapabilitySupport,
    pub timeout: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCapabilities {
    pub secret_filtering: CapabilitySupport,
    pub host_boundary_injection: CapabilitySupport,
    pub placeholder_projection: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceCapabilities {
    pub inference_local: CapabilitySupport,
    pub external_provider: CapabilitySupport,
    pub streaming: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleCapabilities {
    pub start: CapabilitySupport,
    pub exec: CapabilitySupport,
    pub destroy: CapabilitySupport,
    pub stateful: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupCapabilities {
    pub process_tree: CapabilitySupport,
    pub resources: CapabilitySupport,
    pub temp_state: CapabilitySupport,
    pub backend_state: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCapabilities {
    pub denials: CapabilitySupport,
    pub dependency_reasons: CapabilitySupport,
    pub bypass_evidence: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Exact,
    AxisOwned,
    ExactWithHostDependency { dependencies: Vec<String> },
    WeakerOnly { reason: String },
    Unsupported { reason: String },
}

impl CapabilitySupport {
    pub fn exact() -> Self {
        Self::Exact
    }

    pub fn axis_owned() -> Self {
        Self::AxisOwned
    }

    pub fn with_dependency(dependency: impl Into<String>) -> Self {
        Self::ExactWithHostDependency {
            dependencies: vec![dependency.into()],
        }
    }

    pub fn with_dependencies(dependencies: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::ExactWithHostDependency {
            dependencies: dependencies.into_iter().map(Into::into).collect(),
        }
    }

    pub fn weaker(reason: impl Into<String>) -> Self {
        Self::WeakerOnly {
            reason: reason.into(),
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyState {
    Present,
    Missing,
    Malformed,
    PermissionDenied,
}

impl DependencyState {
    fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }

    fn failure_label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::PermissionDenied => "permission-denied",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProbeSnapshot {
    dependencies: BTreeMap<String, DependencyState>,
}

impl RuntimeProbeSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dependency(mut self, name: impl Into<String>, state: DependencyState) -> Self {
        self.dependencies.insert(name.into(), state);
        self
    }

    pub fn dependency_state(&self, name: &str) -> DependencyState {
        self.dependencies
            .get(name)
            .copied()
            .unwrap_or(DependencyState::Missing)
    }
}

/// Runtime probes must only observe host state. They must not install helpers,
/// change capabilities, enable OS features, or mutate firewall/container/VM
/// configuration.
pub trait RuntimeCapabilityProbe {
    fn snapshot(&self, backend: &BackendCapabilities) -> RuntimeProbeSnapshot;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlannerOptions {
    accepted_weaker_surfaces: BTreeSet<PolicySurface>,
}

impl PlannerOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept_weaker_surface(mut self, surface: PolicySurface) -> Self {
        self.accepted_weaker_surfaces.insert(surface);
        self
    }

    fn accepts_weaker(&self, surface: PolicySurface) -> bool {
        self.accepted_weaker_surfaces.contains(&surface)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequirement {
    pub surface: PolicySurface,
    pub name: &'static str,
    pub support: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDecision {
    pub surface: PolicySurface,
    pub requirement: &'static str,
    pub support: CapabilitySupport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanReason {
    pub surface: PolicySurface,
    pub requirement: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDecision {
    pub surface: PolicySurface,
    pub requirement: &'static str,
    pub dependency: String,
    pub present: bool,
    pub state: DependencyState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendPlanOutcome {
    Exact,
    ExactWithHostDependency {
        dependencies: Vec<DependencyDecision>,
    },
    WeakerOnly {
        accepted: bool,
        reasons: Vec<PlanReason>,
    },
    Unsupported {
        reasons: Vec<PlanReason>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendPolicyPlan {
    pub backend_name: String,
    pub platform: BackendPlatform,
    pub stability: BackendStability,
    pub outcome: BackendPlanOutcome,
    pub decisions: Vec<SurfaceDecision>,
}

impl BackendPolicyPlan {
    pub fn spawn_allowed(&self) -> bool {
        match &self.outcome {
            BackendPlanOutcome::Exact => true,
            BackendPlanOutcome::ExactWithHostDependency { dependencies } => {
                dependencies.iter().all(|dependency| dependency.present)
            }
            BackendPlanOutcome::WeakerOnly { accepted, .. } => *accepted,
            BackendPlanOutcome::Unsupported { .. } => false,
        }
    }

    pub fn pre_spawn_error(&self) -> Option<String> {
        match &self.outcome {
            BackendPlanOutcome::Exact => None,
            BackendPlanOutcome::ExactWithHostDependency { dependencies } => {
                let missing = dependencies
                    .iter()
                    .filter(|dependency| !dependency.present)
                    .map(|dependency| {
                        if matches!(dependency.state, DependencyState::Missing) {
                            format!(
                                "{} requires missing host dependency '{}'",
                                dependency.requirement, dependency.dependency
                            )
                        } else {
                            format!(
                                "{} requires host dependency '{}' but probe reported {}",
                                dependency.requirement,
                                dependency.dependency,
                                dependency.state.failure_label()
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                if missing.is_empty() {
                    None
                } else {
                    Some(missing.join("; "))
                }
            }
            BackendPlanOutcome::WeakerOnly { accepted, reasons } => {
                if *accepted {
                    None
                } else {
                    Some(format!(
                        "backend offers only weaker behavior: {}",
                        format_reasons(reasons)
                    ))
                }
            }
            BackendPlanOutcome::Unsupported { reasons } => Some(format!(
                "unsupported policy/backend pair: {}",
                format_reasons(reasons)
            )),
        }
    }
}

pub fn plan_backend_policy(
    policy: &Policy,
    backend: &BackendCapabilities,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> BackendPolicyPlan {
    let requirements = requirements_for_policy(policy, backend);
    plan_backend_requirements(
        backend.name.clone(),
        backend.platform,
        backend.stability,
        requirements,
        runtime,
        options,
    )
}

pub fn plan_backend_requirements(
    backend_name: impl Into<String>,
    platform: BackendPlatform,
    stability: BackendStability,
    requirements: Vec<CapabilityRequirement>,
    runtime: &RuntimeProbeSnapshot,
    options: &PlannerOptions,
) -> BackendPolicyPlan {
    let mut decisions = Vec::with_capacity(requirements.len());
    let mut dependency_decisions = Vec::new();
    let mut weaker_reasons = Vec::new();
    let mut unsupported_reasons = Vec::new();

    for requirement in requirements {
        match &requirement.support {
            CapabilitySupport::Exact | CapabilitySupport::AxisOwned => {}
            CapabilitySupport::ExactWithHostDependency { dependencies } => {
                for dependency in dependencies {
                    let state = runtime.dependency_state(dependency);
                    dependency_decisions.push(DependencyDecision {
                        surface: requirement.surface,
                        requirement: requirement.name,
                        dependency: dependency.clone(),
                        present: state.is_present(),
                        state,
                    });
                }
            }
            CapabilitySupport::WeakerOnly { reason } => {
                weaker_reasons.push(PlanReason {
                    surface: requirement.surface,
                    requirement: requirement.name,
                    reason: reason.clone(),
                });
            }
            CapabilitySupport::Unsupported { reason } => {
                unsupported_reasons.push(PlanReason {
                    surface: requirement.surface,
                    requirement: requirement.name,
                    reason: reason.clone(),
                });
            }
        }

        decisions.push(SurfaceDecision {
            surface: requirement.surface,
            requirement: requirement.name,
            support: requirement.support,
        });
    }

    let outcome = if !unsupported_reasons.is_empty() {
        BackendPlanOutcome::Unsupported {
            reasons: unsupported_reasons,
        }
    } else if !weaker_reasons.is_empty() {
        let accepted = weaker_reasons
            .iter()
            .all(|reason| options.accepts_weaker(reason.surface));
        BackendPlanOutcome::WeakerOnly {
            accepted,
            reasons: weaker_reasons,
        }
    } else if !dependency_decisions.is_empty() {
        BackendPlanOutcome::ExactWithHostDependency {
            dependencies: dependency_decisions,
        }
    } else {
        BackendPlanOutcome::Exact
    };

    BackendPolicyPlan {
        backend_name: backend_name.into(),
        platform,
        stability,
        outcome,
        decisions,
    }
}

pub fn plan_backend_policy_with_probe(
    policy: &Policy,
    backend: &BackendCapabilities,
    probe: &dyn RuntimeCapabilityProbe,
    options: &PlannerOptions,
) -> BackendPolicyPlan {
    let snapshot = probe.snapshot(backend);
    plan_backend_policy(policy, backend, &snapshot, options)
}

fn requirements_for_policy(
    policy: &Policy,
    backend: &BackendCapabilities,
) -> Vec<CapabilityRequirement> {
    let mut requirements = Vec::new();

    push(
        &mut requirements,
        PolicySurface::Filesystem,
        "filesystem.workspace",
        &backend.filesystem.workspace,
    );
    if !policy.filesystem.read_only.is_empty() {
        push(
            &mut requirements,
            PolicySurface::Filesystem,
            "filesystem.read_only",
            &backend.filesystem.read_only,
        );
    }
    if !policy.filesystem.read_write.is_empty() {
        push(
            &mut requirements,
            PolicySurface::Filesystem,
            "filesystem.read_write",
            &backend.filesystem.read_write,
        );
    }
    if !policy.filesystem.deny.is_empty() {
        push(
            &mut requirements,
            PolicySurface::Filesystem,
            "filesystem.deny",
            &backend.filesystem.deny,
        );
    }

    push(
        &mut requirements,
        PolicySurface::Process,
        "process.command",
        &backend.process.command,
    );
    push(
        &mut requirements,
        PolicySurface::Process,
        "process.working_dir",
        &backend.process.working_dir,
    );
    push(
        &mut requirements,
        PolicySurface::Process,
        "process.environment",
        &backend.process.environment,
    );
    push(
        &mut requirements,
        PolicySurface::Process,
        "process.stdio",
        &backend.process.stdio,
    );
    if policy.process.run_as_user.is_some() {
        push(
            &mut requirements,
            PolicySurface::Process,
            "process.user_identity",
            &backend.process.user_identity,
        );
    }
    if matches!(
        policy.process.identity,
        crate::policy::ProcessIdentity::Isolated
    ) {
        push(
            &mut requirements,
            PolicySurface::Process,
            "process.isolated_identity",
            &backend.process.isolated_identity,
        );
    }
    if !policy.process.blocked_syscalls.is_empty() {
        push(
            &mut requirements,
            PolicySurface::Process,
            "process.syscall_filtering",
            &backend.process.syscall_filtering,
        );
    }
    if policy.process.timeout_sec.is_some() {
        push(
            &mut requirements,
            PolicySurface::Process,
            "process.timeout",
            &backend.process.timeout,
        );
    }

    match policy.network.mode {
        NetworkMode::Allow => {
            push(
                &mut requirements,
                PolicySurface::Network,
                "network.allow",
                &backend.network.allow,
            );
        }
        NetworkMode::Block => {
            push(
                &mut requirements,
                PolicySurface::Network,
                "network.block",
                &backend.network.block,
            );
        }
        NetworkMode::Proxy => {
            push(
                &mut requirements,
                PolicySurface::Network,
                "network.strict_proxy",
                &backend.network.strict_proxy,
            );
        }
    }
    if !policy.network.policies.is_empty() {
        push(
            &mut requirements,
            PolicySurface::Network,
            "network.endpoint_policy",
            &backend.network.endpoint_policy,
        );
    }
    if policy
        .network
        .policies
        .iter()
        .any(|network_policy| !network_policy.binaries.is_empty())
    {
        push(
            &mut requirements,
            PolicySurface::Network,
            "network.binary_attribution",
            &backend.network.binary_attribution,
        );
    }
    if policy.network.policies.iter().any(|network_policy| {
        network_policy
            .endpoints
            .iter()
            .any(|endpoint| !endpoint.rules.is_empty())
    }) {
        push(
            &mut requirements,
            PolicySurface::Network,
            "network.l7_policy",
            &backend.network.l7_policy,
        );
    }

    if policy.process.effective_max_processes() > 0 {
        push(
            &mut requirements,
            PolicySurface::Resources,
            "resources.process_count",
            &backend.resources.process_count,
        );
    }
    if policy.process.max_memory_mb > 0 {
        push(
            &mut requirements,
            PolicySurface::Resources,
            "resources.memory",
            &backend.resources.memory,
        );
    }
    if policy.process.cpu_rate_percent > 0 {
        push(
            &mut requirements,
            PolicySurface::Resources,
            "resources.cpu",
            &backend.resources.cpu,
        );
    }
    if policy.process.timeout_sec.is_some() {
        push(
            &mut requirements,
            PolicySurface::Resources,
            "resources.timeout",
            &backend.resources.timeout,
        );
    }

    push(
        &mut requirements,
        PolicySurface::Credentials,
        "credentials.secret_filtering",
        &backend.credentials.secret_filtering,
    );
    if policy
        .inference
        .routes
        .iter()
        .any(|route| route.has_host_boundary_credentials())
    {
        push(
            &mut requirements,
            PolicySurface::Credentials,
            "credentials.host_boundary_injection",
            &backend.credentials.host_boundary_injection,
        );
        push(
            &mut requirements,
            PolicySurface::Credentials,
            "credentials.placeholder_projection",
            &backend.credentials.placeholder_projection,
        );
    }
    if policy
        .inference
        .routes
        .iter()
        .any(|route| route.uses_https_credentials())
    {
        push(
            &mut requirements,
            PolicySurface::Credentials,
            "credentials.https_host_boundary_injection",
            &CapabilitySupport::unsupported(
                "HTTPS credential injection requires a per-sandbox CA trust path",
            ),
        );
    }

    for route in &policy.inference.routes {
        if route
            .endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.contains("inference.local"))
            || route.name == "local"
            || policy.inference.default_provider.as_deref() == Some(route.name.as_str())
        {
            push(
                &mut requirements,
                PolicySurface::Inference,
                "inference.local",
                &backend.inference.inference_local,
            );
        }
        if route.provider.is_some() || route.api_key_env.is_some() {
            push(
                &mut requirements,
                PolicySurface::Inference,
                "inference.external_provider",
                &backend.inference.external_provider,
            );
        }
        if route
            .protocols
            .iter()
            .any(|protocol| protocol.contains("stream"))
        {
            push(
                &mut requirements,
                PolicySurface::Inference,
                "inference.streaming",
                &backend.inference.streaming,
            );
        }
    }

    push(
        &mut requirements,
        PolicySurface::Lifecycle,
        "lifecycle.start",
        &backend.lifecycle.start,
    );
    push(
        &mut requirements,
        PolicySurface::Lifecycle,
        "lifecycle.destroy",
        &backend.lifecycle.destroy,
    );

    push(
        &mut requirements,
        PolicySurface::Cleanup,
        "cleanup.process_tree",
        &backend.cleanup.process_tree,
    );
    push(
        &mut requirements,
        PolicySurface::Cleanup,
        "cleanup.temp_state",
        &backend.cleanup.temp_state,
    );
    push(
        &mut requirements,
        PolicySurface::Cleanup,
        "cleanup.backend_state",
        &backend.cleanup.backend_state,
    );
    if resources_requested(policy) {
        push(
            &mut requirements,
            PolicySurface::Cleanup,
            "cleanup.resources",
            &backend.cleanup.resources,
        );
    }

    push(
        &mut requirements,
        PolicySurface::Audit,
        "audit.denials",
        &backend.audit.denials,
    );
    push(
        &mut requirements,
        PolicySurface::Audit,
        "audit.dependency_reasons",
        &backend.audit.dependency_reasons,
    );
    if matches!(policy.network.mode, NetworkMode::Proxy) {
        push(
            &mut requirements,
            PolicySurface::Audit,
            "audit.bypass_evidence",
            &backend.audit.bypass_evidence,
        );
    }

    requirements
}

fn push(
    requirements: &mut Vec<CapabilityRequirement>,
    surface: PolicySurface,
    name: &'static str,
    support: &CapabilitySupport,
) {
    requirements.push(CapabilityRequirement {
        surface,
        name,
        support: support.clone(),
    });
}

fn resources_requested(policy: &Policy) -> bool {
    policy.process.effective_max_processes() > 0
        || policy.process.max_memory_mb > 0
        || policy.process.cpu_rate_percent > 0
}

fn format_reasons(reasons: &[PlanReason]) -> String {
    reasons
        .iter()
        .map(|reason| {
            format!(
                "{} ({:?}): {}",
                reason.requirement, reason.surface, reason.reason
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        Access, BinaryMatch, Endpoint, EndpointPolicy, FilesystemPolicy, GpuPolicy,
        InferencePolicy, InferenceRoute, L7Allow, L7Rule, NetworkPolicy, ProcessPolicy, SshPolicy,
    };

    struct FakeProbe {
        snapshot: RuntimeProbeSnapshot,
    }

    impl RuntimeCapabilityProbe for FakeProbe {
        fn snapshot(&self, _backend: &BackendCapabilities) -> RuntimeProbeSnapshot {
            self.snapshot.clone()
        }
    }

    fn exact_backend() -> BackendCapabilities {
        BackendCapabilities {
            platform: BackendPlatform::Linux,
            name: "fake-exact".into(),
            stability: BackendStability::Stable,
            host_dependencies: Vec::new(),
            filesystem: FilesystemCapabilities {
                read_only: CapabilitySupport::exact(),
                read_write: CapabilitySupport::exact(),
                deny: CapabilitySupport::exact(),
                workspace: CapabilitySupport::exact(),
            },
            process: ProcessCapabilities {
                command: CapabilitySupport::exact(),
                working_dir: CapabilitySupport::exact(),
                environment: CapabilitySupport::exact(),
                stdio: CapabilitySupport::exact(),
                user_identity: CapabilitySupport::exact(),
                isolated_identity: CapabilitySupport::exact(),
                syscall_filtering: CapabilitySupport::exact(),
                pty: CapabilitySupport::unsupported("pty not implemented"),
                timeout: CapabilitySupport::exact(),
            },
            network: NetworkCapabilities {
                allow: CapabilitySupport::exact(),
                block: CapabilitySupport::exact(),
                strict_proxy: CapabilitySupport::exact(),
                cooperative_proxy: CapabilitySupport::weaker("proxy environment only"),
                endpoint_policy: CapabilitySupport::axis_owned(),
                binary_attribution: CapabilitySupport::axis_owned(),
                l7_policy: CapabilitySupport::axis_owned(),
            },
            resources: ResourceCapabilities {
                process_count: CapabilitySupport::exact(),
                memory: CapabilitySupport::exact(),
                cpu: CapabilitySupport::exact(),
                timeout: CapabilitySupport::exact(),
            },
            credentials: CredentialCapabilities {
                secret_filtering: CapabilitySupport::exact(),
                host_boundary_injection: CapabilitySupport::axis_owned(),
                placeholder_projection: CapabilitySupport::axis_owned(),
            },
            inference: InferenceCapabilities {
                inference_local: CapabilitySupport::axis_owned(),
                external_provider: CapabilitySupport::axis_owned(),
                streaming: CapabilitySupport::axis_owned(),
            },
            lifecycle: LifecycleCapabilities {
                start: CapabilitySupport::exact(),
                exec: CapabilitySupport::unsupported("exec not required"),
                destroy: CapabilitySupport::exact(),
                stateful: CapabilitySupport::unsupported("stateful sessions not required"),
            },
            cleanup: CleanupCapabilities {
                process_tree: CapabilitySupport::exact(),
                resources: CapabilitySupport::exact(),
                temp_state: CapabilitySupport::exact(),
                backend_state: CapabilitySupport::exact(),
            },
            audit: AuditCapabilities {
                denials: CapabilitySupport::axis_owned(),
                dependency_reasons: CapabilitySupport::exact(),
                bypass_evidence: CapabilitySupport::exact(),
            },
        }
    }

    fn minimal_policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
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

    fn plan(policy: &Policy, backend: &BackendCapabilities) -> BackendPolicyPlan {
        plan_backend_policy(
            policy,
            backend,
            &RuntimeProbeSnapshot::new(),
            &PlannerOptions::new(),
        )
    }

    #[test]
    fn exact_backend_returns_exact_outcome() {
        let backend = exact_backend();
        let policy = minimal_policy(NetworkMode::Block);

        let plan = plan(&policy, &backend);

        assert_eq!(plan.outcome, BackendPlanOutcome::Exact);
        assert!(plan.spawn_allowed());
        assert!(plan.pre_spawn_error().is_none());
        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Network && decision.requirement == "network.block"
        }));
    }

    #[test]
    fn present_host_dependency_allows_spawn_but_records_dependency_outcome() {
        let mut backend = exact_backend();
        backend.network.block = CapabilitySupport::with_dependency("network-blocker");
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency("network-blocker", DependencyState::Present);
        let policy = minimal_policy(NetworkMode::Block);

        let plan = plan_backend_policy(&policy, &backend, &runtime, &PlannerOptions::new());

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::ExactWithHostDependency { .. }
        ));
        assert!(plan.spawn_allowed());
        assert!(plan.pre_spawn_error().is_none());
    }

    #[test]
    fn missing_host_dependency_blocks_spawn_with_actionable_error() {
        let mut backend = exact_backend();
        backend.network.block = CapabilitySupport::with_dependency("network-blocker");
        let policy = minimal_policy(NetworkMode::Block);

        let plan = plan(&policy, &backend);

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::ExactWithHostDependency { .. }
        ));
        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.block"));
        assert!(error.contains("network-blocker"));
    }

    #[test]
    fn unsupported_surface_overrides_host_dependency_outcome() {
        let mut backend = exact_backend();
        backend.network.block = CapabilitySupport::with_dependency("network-blocker");
        backend.filesystem.deny = CapabilitySupport::unsupported("deny masking unavailable");
        let mut policy = minimal_policy(NetworkMode::Block);
        policy.filesystem.deny.push("~/.ssh".into());

        let plan = plan(&policy, &backend);

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("filesystem.deny"));
        assert!(error.contains("deny masking unavailable"));
    }

    #[test]
    fn cooperative_proxy_is_weaker_until_explicitly_accepted() {
        let mut backend = exact_backend();
        backend.network.strict_proxy =
            CapabilitySupport::weaker("cooperative proxy environment variables only");
        let policy = minimal_policy(NetworkMode::Proxy);

        let plan = plan(&policy, &backend);

        assert_eq!(
            plan.outcome,
            BackendPlanOutcome::WeakerOnly {
                accepted: false,
                reasons: vec![PlanReason {
                    surface: PolicySurface::Network,
                    requirement: "network.strict_proxy",
                    reason: "cooperative proxy environment variables only".into(),
                }],
            }
        );
        assert!(!plan.spawn_allowed());
        assert!(plan.pre_spawn_error().unwrap().contains("weaker"));

        let accepted = plan_backend_policy(
            &policy,
            &backend,
            &RuntimeProbeSnapshot::new(),
            &PlannerOptions::new().accept_weaker_surface(PolicySurface::Network),
        );
        assert!(matches!(
            accepted.outcome,
            BackendPlanOutcome::WeakerOnly { accepted: true, .. }
        ));
        assert!(accepted.spawn_allowed());
    }

    #[test]
    fn binary_restricted_endpoint_requires_attribution() {
        let mut backend = exact_backend();
        backend.network.binary_attribution =
            CapabilitySupport::unsupported("connect-time identity unavailable");
        let mut policy = minimal_policy(NetworkMode::Proxy);
        policy.network.policies.push(endpoint_policy_with_binary());

        let plan = plan(&policy, &backend);

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("network.binary_attribution"));
        assert!(error.contains("connect-time identity unavailable"));
    }

    #[test]
    fn l7_rules_require_l7_policy_support() {
        let mut backend = exact_backend();
        backend.network.l7_policy = CapabilitySupport::unsupported("L7 inspection unavailable");
        let mut policy = minimal_policy(NetworkMode::Proxy);
        let mut endpoint_policy = endpoint_policy_with_binary();
        endpoint_policy.endpoints[0].rules.push(L7Rule {
            allow: Some(L7Allow {
                method: "GET".into(),
                path: "/repos".into(),
            }),
        });
        policy.network.policies.push(endpoint_policy);

        let plan = plan(&policy, &backend);

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("network.l7_policy")
        );
    }

    #[test]
    fn resources_and_cleanup_are_planned_when_limits_are_requested() {
        let mut backend = exact_backend();
        backend.resources.cpu = CapabilitySupport::unsupported("CPU quota unavailable");
        let mut policy = minimal_policy(NetworkMode::Allow);
        policy.process.cpu_rate_percent = 50;

        let plan = plan(&policy, &backend);

        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Resources && decision.requirement == "resources.cpu"
        }));
        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Cleanup
                && decision.requirement == "cleanup.resources"
        }));
        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
    }

    #[test]
    fn provider_credentials_require_host_boundary_and_placeholders() {
        let mut backend = exact_backend();
        backend.credentials.host_boundary_injection =
            CapabilitySupport::unsupported("host-side injection unavailable");
        let mut policy = minimal_policy(NetworkMode::Proxy);
        policy.inference.routes.push(InferenceRoute {
            name: "cloud".into(),
            endpoint: None,
            provider: Some("anthropic".into()),
            model: Some("claude".into()),
            api_key_env: Some("ANTHROPIC_API_KEY".into()),
            protocols: vec!["messages_streaming".into()],
        });

        let plan = plan(&policy, &backend);

        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Credentials
                && decision.requirement == "credentials.placeholder_projection"
        }));
        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Credentials
                && decision.requirement == "credentials.https_host_boundary_injection"
                && matches!(decision.support, CapabilitySupport::Unsupported { .. })
        }));
        assert!(plan.decisions.iter().any(|decision| {
            decision.surface == PolicySurface::Inference
                && decision.requirement == "inference.streaming"
        }));
        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::Unsupported { .. }
        ));
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("credentials.host_boundary_injection")
        );
        assert!(
            plan.pre_spawn_error()
                .unwrap()
                .contains("credentials.https_host_boundary_injection")
        );
    }

    #[test]
    fn https_query_placeholder_is_an_unsupported_credential_requirement() {
        let backend = exact_backend();
        let mut policy = minimal_policy(NetworkMode::Proxy);
        policy.inference.routes.push(InferenceRoute {
            name: "query-key".into(),
            endpoint: Some("https://api.example.com/v1?key=axis:resolve:env:EXTERNAL_KEY".into()),
            provider: None,
            model: None,
            api_key_env: None,
            protocols: Vec::new(),
        });

        let plan = plan(&policy, &backend);

        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(error.contains("credentials.https_host_boundary_injection"));
        assert!(plan.decisions.iter().any(|decision| {
            decision.requirement == "credentials.host_boundary_injection"
                && matches!(decision.support, CapabilitySupport::AxisOwned)
        }));
    }

    #[test]
    fn fake_runtime_probe_can_drive_planning_without_launching() {
        let mut backend = exact_backend();
        backend.network.allow =
            CapabilitySupport::with_dependencies(["runtime-executor", "profile-runtime"]);
        let probe = FakeProbe {
            snapshot: RuntimeProbeSnapshot::new()
                .with_dependency("runtime-executor", DependencyState::Present)
                .with_dependency("profile-runtime", DependencyState::Missing),
        };
        let policy = minimal_policy(NetworkMode::Allow);

        let plan =
            plan_backend_policy_with_probe(&policy, &backend, &probe, &PlannerOptions::new());

        assert!(matches!(
            plan.outcome,
            BackendPlanOutcome::ExactWithHostDependency { .. }
        ));
        assert!(!plan.spawn_allowed());
        let error = plan.pre_spawn_error().unwrap();
        assert!(!error.contains("runtime-executor"));
        assert!(error.contains("profile-runtime"));
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
