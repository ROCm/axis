// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! YAML policy schema parsing and validation.
//!
//! The policy model defines the AXIS YAML contract. Policies govern filesystem
//! access, process limits, network connectivity, inference routing, and
//! AMD-specific features.

#![deny(missing_docs)]

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::net::IpAddr;
use thiserror::Error;

/// Error returned when a policy cannot be read, parsed or validated.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The policy text is not valid YAML for this schema.
    #[error("failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),

    /// The policy file cannot be read, or the policy fails a validation rule.
    /// The message gives the reason.
    #[error("policy validation failed: {0}")]
    ValidationError(String),

    /// The policy `version` is not `1`. Holds the version that the policy
    /// gives.
    #[error("unsupported policy version: {0}")]
    UnsupportedVersion(u32),
}

/// Top-level AXIS policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Policy schema version. The only supported value is `1`. Other values
    /// fail validation. Required.
    pub version: u32,
    /// Policy name. It must not be empty, `.` or `..`, and it can contain only
    /// ASCII letters, digits, `.`, `_` and `-`. Other names fail validation.
    /// Required.
    pub name: String,

    /// Runtime launch settings. Default: the default of each field in the section.
    #[serde(default)]
    pub runtime: RuntimePolicy,

    /// Filesystem access settings. Default: the default of each field in the section.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    /// Process limit settings. Default: the default of each field in the section.
    #[serde(default)]
    pub process: ProcessPolicy,

    /// Network access settings. Default: the default of each field in the section.
    #[serde(default)]
    pub network: NetworkPolicy,

    /// Inference routing settings. Default: the default of each field in the section.
    #[serde(default)]
    pub inference: InferencePolicy,

    /// GPU access settings. Default: the default of each field in the section.
    #[serde(default)]
    pub gpu: GpuPolicy,

    /// SSH access settings. Default: the default of each field in the section.
    #[serde(default)]
    pub ssh: SshPolicy,

    /// AMD-specific settings. Unset by default.
    #[serde(default)]
    pub amd: Option<AmdPolicy>,
}

impl Policy {
    /// Parse a policy from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Parse a policy from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            PolicyError::ValidationError(format!("cannot read {}: {e}", path.display()))
        })?;
        Self::from_yaml(&contents)
    }

    /// Validate policy constraints.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }
        validate_policy_name_component(&self.name)?;
        self.runtime.validate()?;
        self.process.validate()?;
        self.network.validate()?;
        self.validate_proxy_features()?;
        self.gpu.validate()?;
        Ok(())
    }

    fn validate_proxy_features(&self) -> Result<(), PolicyError> {
        for network_policy in &self.network.policies {
            for endpoint in &network_policy.endpoints {
                if matches!(endpoint.access, Access::ReadOnly) {
                    return Err(PolicyError::ValidationError(format!(
                        "network policy '{}' requests unsupported read-only endpoint access for {}:{}; endpoint policies currently authorize the full host and port",
                        network_policy.name, endpoint.host, endpoint.port
                    )));
                }
                if endpoint.protocol.is_some() {
                    return Err(PolicyError::ValidationError(format!(
                        "network policy '{}' requests unsupported endpoint protocol filtering for {}:{}",
                        network_policy.name, endpoint.host, endpoint.port
                    )));
                }
                if !endpoint.rules.is_empty() {
                    return Err(PolicyError::ValidationError(format!(
                        "network policy '{}' requests unsupported L7 method/path filtering for {}:{}",
                        network_policy.name, endpoint.host, endpoint.port
                    )));
                }
            }
        }

        let mut credential_scopes = Vec::new();
        for route in self
            .inference
            .routes
            .iter()
            .filter(|route| route.has_host_boundary_credentials())
        {
            if let Some(env_name) = route.api_key_env.as_deref() {
                validate_credential_env_name(&route.name, env_name)?;
            }

            if !matches!(self.network.mode, NetworkMode::Proxy) {
                return Err(PolicyError::ValidationError(format!(
                    "inference route '{}' requires network.mode: proxy for host-boundary credential injection",
                    route.name
                )));
            }

            let endpoint = route.credential_endpoint()?;
            let query_pairs = endpoint.query_pairs().collect::<Vec<_>>();
            for (name, value) in &query_pairs {
                if !value.starts_with("axis:resolve:") {
                    continue;
                }
                if name.is_empty() {
                    return Err(PolicyError::ValidationError(format!(
                        "inference route '{}' credential query placeholder must have a name",
                        route.name
                    )));
                }
                let Some(env_name) = value.strip_prefix("axis:resolve:env:") else {
                    return Err(PolicyError::ValidationError(format!(
                        "inference route '{}' contains unsupported credential placeholder '{value}'",
                        route.name
                    )));
                };
                validate_credential_env_name(&route.name, env_name)?;
                let occurrences = query_pairs
                    .iter()
                    .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                    .count();
                if occurrences != 1 {
                    return Err(PolicyError::ValidationError(format!(
                        "inference route '{}' credential query parameter '{}' must have one unambiguous definition",
                        route.name, name
                    )));
                }
            }
            if endpoint.scheme() != "http" {
                return Err(PolicyError::ValidationError(format!(
                    "inference route '{}' requests unsupported HTTPS credential injection; a per-sandbox CA trust path is not available",
                    route.name
                )));
            }
            let host = endpoint.host_str().ok_or_else(|| {
                PolicyError::ValidationError(format!(
                    "inference route '{}' credential endpoint must include a host",
                    route.name
                ))
            })?;
            let host = canonicalize_network_host(host).map_err(|reason| {
                PolicyError::ValidationError(format!(
                    "inference route '{}' has an invalid credential endpoint host: {reason}",
                    route.name
                ))
            })?;
            if host != "inference.local" {
                return Err(PolicyError::ValidationError(format!(
                    "inference route '{}' may inject credentials only through inference.local; localhost and loopback origins are denied by runtime SSRF controls",
                    route.name
                )));
            }
            credential_scopes.push(CredentialScope {
                route: route.name.as_str(),
                host,
                port: endpoint.port_or_known_default().ok_or_else(|| {
                    PolicyError::ValidationError(format!(
                        "inference route '{}' credential endpoint has no effective port",
                        route.name
                    ))
                })?,
                path: canonicalize_credential_path(endpoint.path()).map_err(|reason| {
                    PolicyError::ValidationError(format!(
                        "inference route '{}' has an invalid credential endpoint path: {reason}",
                        route.name
                    ))
                })?,
            });
        }

        for (index, scope) in credential_scopes.iter().enumerate() {
            for other in &credential_scopes[index + 1..] {
                if scope.host == other.host
                    && scope.port == other.port
                    && credential_paths_overlap(&scope.path, &other.path)
                {
                    return Err(PolicyError::ValidationError(format!(
                        "inference credential routes '{}' and '{}' have ambiguous overlapping scopes on http://{}:{} ('{}' and '{}')",
                        scope.route, other.route, scope.host, scope.port, scope.path, other.path
                    )));
                }
            }
        }

        Ok(())
    }
}

struct CredentialScope<'a> {
    route: &'a str,
    host: String,
    port: u16,
    path: String,
}

fn credential_paths_overlap(left: &str, right: &str) -> bool {
    credential_path_contains(left, right) || credential_path_contains(right, left)
}

fn credential_path_contains(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || if prefix.ends_with('/') {
            path.starts_with(prefix)
        } else {
            path.strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        }
}

/// Canonicalize a URL path for credential scope comparison.
///
/// Percent-encoded unreserved bytes are decoded, while all other encoded bytes
/// retain their URL path semantics with uppercase hexadecimal digits.
pub fn canonicalize_credential_path(path: &str) -> Result<String, &'static str> {
    if !path.starts_with('/') {
        return Err("credential path must be absolute");
    }
    if path.as_bytes().contains(&b'\\') {
        return Err("credential path contains a backslash");
    }

    let bytes = path.as_bytes();
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            canonical.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err("credential path contains malformed percent encoding");
        }
        let Some(high) = decode_url_hex(bytes[index + 1]) else {
            return Err("credential path contains malformed percent encoding");
        };
        let Some(low) = decode_url_hex(bytes[index + 2]) else {
            return Err("credential path contains malformed percent encoding");
        };
        let decoded = (high << 4) | low;
        if decoded.is_ascii_control() {
            return Err("credential path contains an encoded control byte");
        }
        if matches!(decoded, b'\\' | b'%') {
            return Err("credential path contains an encoded backslash or nested percent encoding");
        }
        if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
            canonical.push(decoded);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            canonical.push(b'%');
            canonical.push(HEX[usize::from(decoded >> 4)]);
            canonical.push(HEX[usize::from(decoded & 0x0f)]);
        }
        index += 3;
    }

    if canonical
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b"." || segment == b"..")
    {
        return Err("credential path contains a dot segment");
    }
    String::from_utf8(canonical).map_err(|_| "credential path is not valid UTF-8")
}

fn decode_url_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Reject malformed percent triplets before a URL component is decoded.
pub fn validate_url_percent_encoding(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || decode_url_hex(bytes[index + 1]).is_none()
            || decode_url_hex(bytes[index + 2]).is_none()
        {
            return Err("URL text contains malformed percent encoding");
        }
        index += 3;
    }
    Ok(())
}

/// Parse and validate the URL syntax shared by credential policy and runtime.
pub fn parse_credential_endpoint(endpoint: &str) -> Result<url::Url, &'static str> {
    if endpoint.as_bytes().contains(&b'\\') {
        return Err("credential endpoint must not contain a backslash");
    }
    validate_url_percent_encoding(endpoint)?;
    canonicalize_credential_path(raw_endpoint_path(endpoint)?)?;
    let endpoint = url::Url::parse(endpoint).map_err(|_| "credential endpoint is not a URL")?;
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err("credential endpoint must use http:// or https://");
    }
    if endpoint.host_str().is_none() {
        return Err("credential endpoint must include a host");
    }
    if endpoint.fragment().is_some() {
        return Err("credential endpoint must not contain a fragment");
    }
    canonicalize_credential_path(endpoint.path())?;
    Ok(endpoint)
}

/// Detect credential placeholders in structured query data or rejected URL parts.
pub fn credential_endpoint_has_placeholder(endpoint: &str) -> bool {
    endpoint.contains("axis:resolve:")
        || url::Url::parse(endpoint).is_ok_and(|endpoint| {
            endpoint
                .query_pairs()
                .any(|(_, value)| value.starts_with("axis:resolve:"))
        })
}

fn raw_endpoint_path(endpoint: &str) -> Result<&str, &'static str> {
    let (_, after_scheme) = endpoint
        .split_once("://")
        .ok_or("credential endpoint is not an absolute URL")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let path_and_more = &after_scheme[authority_end..];
    if !path_and_more.starts_with('/') {
        return Ok("/");
    }
    let path_end = path_and_more
        .find(['?', '#'])
        .unwrap_or(path_and_more.len());
    Ok(&path_and_more[..path_end])
}

/// Validate a policy name before it is used as a filesystem path component.
pub fn validate_policy_name_component(name: &str) -> Result<(), PolicyError> {
    if name.is_empty() {
        return Err(PolicyError::ValidationError(
            "policy name must not be empty".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(PolicyError::ValidationError(
            "policy name must be a safe path component".into(),
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PolicyError::ValidationError(
            "policy name must contain only ASCII letters, digits, '.', '_' and '-'".into(),
        ));
    }
    Ok(())
}

/// Runtime launch metadata. This selects a sandbox implementation without
/// changing the security policy semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    /// Containment model for the workload. The only value is `process`.
    /// Default: `process`.
    #[serde(default = "default_runtime_containment")]
    pub containment: RuntimeContainment,

    /// Sandbox implementation that runs the workload. One of `auto`, `mxc`,
    /// `axis_native` or `vxn`. The spelling `axis-native` is also accepted.
    /// Default: `auto`.
    #[serde(default = "default_runtime_provider")]
    pub provider: RuntimeProvider,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            containment: default_runtime_containment(),
            provider: default_runtime_provider(),
        }
    }
}

impl RuntimePolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        match self.containment {
            RuntimeContainment::Process => Ok(()),
        }
    }
}

fn default_runtime_containment() -> RuntimeContainment {
    RuntimeContainment::Process
}

/// Containment model, set by `runtime.containment`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeContainment {
    /// Process containment. YAML value: `process`.
    #[default]
    Process,
}

impl RuntimeContainment {
    /// Returns the YAML spelling of this value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
        }
    }
}

fn default_runtime_provider() -> RuntimeProvider {
    RuntimeProvider::Auto
}

/// Sandbox implementation, set by `runtime.provider`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProvider {
    /// The default provider. YAML value: `auto`.
    #[default]
    Auto,
    /// The MXC provider. YAML value: `mxc`.
    Mxc,
    /// The native AXIS provider. YAML value: `axis_native`. The spelling
    /// `axis-native` is also accepted.
    #[serde(alias = "axis-native")]
    AxisNative,
    /// Each sandbox is a Xen DomU (a VM) driven through the vxn CLI /
    /// vxn-oci-runtime. VM-strength isolation tier; Linux/Xen only.
    /// YAML value: `vxn`.
    Vxn,
}

impl RuntimeProvider {
    /// Returns the YAML spelling of this value, using `axis_native` for
    /// [`RuntimeProvider::AxisNative`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Mxc => "mxc",
            Self::AxisNative => "axis_native",
            Self::Vxn => "vxn",
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_mach_service_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !name.is_empty()
        && name.len() <= 256
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_' | b'@'))
}

fn is_exact_sysctl_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_'))
}

/// Filesystem access policy — controls what paths the sandboxed process can read/write.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Paths listed for read-only access. Default: empty.
    #[serde(default)]
    pub read_only: Vec<String>,

    /// Paths listed for read-write access. Default: empty.
    #[serde(default)]
    pub read_write: Vec<String>,

    /// Paths listed as denied. Default: empty.
    #[serde(default)]
    pub deny: Vec<String>,

    /// When true, the sandbox workspace (cwd) is granted READ-ONLY instead of the
    /// default implicit read-write. A nested `{tmpdir}` listed in `read_write`
    /// still works (Landlock unions the more-specific grant), so the agent keeps a
    /// writable scratch under an otherwise read-only workspace. Enables a
    /// read-only lease: the agent can read its code but not modify it.
    /// Default: `false`.
    #[serde(default)]
    pub workspace_read_only: bool,

    /// Windows MXC 1.x only: let the sandbox enumerate every ancestor of a
    /// grant, which path canonicalization (Node's JS `realpath`) needs. MXC
    /// applies enumeration to the whole subtree, so an ancestor such as `C:\`
    /// exposes the names, sizes and times of every file below it that NTFS
    /// does not separately deny. Contents stay unreadable. Off by default.
    #[serde(default)]
    pub windows_enumerate_ancestors: bool,

    /// Filesystem compatibility mode. One of `best_effort` or
    /// `hard_requirement`. Default: `best_effort`.
    #[serde(default = "default_compatibility")]
    pub compatibility: Compatibility,
}

fn default_compatibility() -> Compatibility {
    Compatibility::BestEffort
}

/// Values accepted for `filesystem.compatibility` and `network.bypass_audit`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    /// YAML value: `best_effort`.
    #[default]
    BestEffort,
    /// YAML value: `hard_requirement`.
    HardRequirement,
}

/// Process containment policy — limits on the sandboxed process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    /// Maximum process count. 0 disables process-count enforcement.
    /// Default: `32`.
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,

    /// Maximum memory in MiB. 0 disables memory enforcement.
    /// Default: `8192`.
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u64,

    /// CPU quota percentage. 0 disables CPU quota enforcement; 1..=100
    /// requests the platform CPU quota mechanism.
    /// A value above `100` fails validation. Default: `80`.
    #[serde(default = "default_cpu_rate")]
    pub cpu_rate_percent: u32,

    /// Host user account name. Unset by default.
    #[serde(default)]
    pub run_as_user: Option<String>,

    /// System call names listed as blocked. Default: empty.
    #[serde(default)]
    pub blocked_syscalls: Vec<String>,

    /// Portable identity intent. Unlike `run_as_user`, this does not name a
    /// host account and can map to a BaseContainer/AppContainer identity.
    /// One of `backend_default` or `isolated`. Default: `backend_default`.
    #[serde(default)]
    pub identity: ProcessIdentity,

    /// Portable descendant-process intent. `deny` maps to a child-tree process
    /// limit of one rather than to platform-specific syscall names.
    /// One of `allow` or `deny`. Default: `allow`.
    #[serde(default)]
    pub child_processes: ChildProcessPolicy,

    /// Maximum wall-clock time in seconds before auto-destroy. None = no timeout.
    #[serde(default)]
    pub timeout_sec: Option<u64>,

    /// Windows only: allow Win32k system calls inside the BaseContainer.
    /// USER32 initialization needs them, so PowerShell, Git for Windows,
    /// `whoami` and most GUI-linked console tools fail with
    /// STATUS_DLL_INIT_FAILED without this. Clipboard access and synthetic
    /// input injection stay denied.
    /// Default: `false`.
    #[serde(default)]
    pub windows_win32k: bool,

    /// Replace the blanket Mach and sysctl access with a fixed allowlist.
    /// `false` (the default) keeps `(allow mach*)` and `(allow sysctl-read)`
    /// on the native macOS Seatbelt profile.
    ///
    /// Only the native macOS Seatbelt backend enforces this. Every other
    /// backend refuses a policy that sets it, so the launch fails before user
    /// code runs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub restrict_system_services: bool,

    /// Extra Mach service names allowed when `restrict_system_services` is
    /// set, such as `com.apple.SecurityServer` for the Keychain. macOS only.
    /// Allowing a name lets the workload look the service up; the service may
    /// still need other access to work.
    /// An entry that is not a valid Mach service name fails validation. A
    /// non-empty list fails validation unless `restrict_system_services` is
    /// `true`. Default: empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macos_mach_lookup: Vec<String>,

    /// Extra exact sysctl names allowed when `restrict_system_services` is
    /// set. Prefixes are not accepted. macOS only.
    /// An entry that is not an exact sysctl name fails validation. A non-empty
    /// list fails validation unless `restrict_system_services` is `true`.
    /// Default: empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macos_sysctl_read: Vec<String>,
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            max_processes: default_max_processes(),
            max_memory_mb: default_max_memory_mb(),
            cpu_rate_percent: default_cpu_rate(),
            run_as_user: None,
            blocked_syscalls: Vec::new(),
            identity: ProcessIdentity::default(),
            child_processes: ChildProcessPolicy::default(),
            timeout_sec: None,
            windows_win32k: false,
            restrict_system_services: false,
            macos_mach_lookup: Vec::new(),
            macos_sysctl_read: Vec::new(),
        }
    }
}

impl ProcessPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.cpu_rate_percent > 100 {
            return Err(PolicyError::ValidationError(format!(
                "cpu_rate_percent must be 0..=100, got {}",
                self.cpu_rate_percent
            )));
        }
        if !self.restrict_system_services
            && (!self.macos_mach_lookup.is_empty() || !self.macos_sysctl_read.is_empty())
        {
            return Err(PolicyError::ValidationError(
                "process.macos_mach_lookup and process.macos_sysctl_read require process.restrict_system_services: true"
                    .into(),
            ));
        }
        for name in &self.macos_mach_lookup {
            if !is_mach_service_name(name) {
                return Err(PolicyError::ValidationError(format!(
                    "process.macos_mach_lookup entry '{name}' is not a Mach service name"
                )));
            }
        }
        for name in &self.macos_sysctl_read {
            if !is_exact_sysctl_name(name) {
                return Err(PolicyError::ValidationError(format!(
                    "process.macos_sysctl_read entry '{name}' is not an exact sysctl name"
                )));
            }
        }
        Ok(())
    }

    /// Returns `1` when `child_processes` is `deny`, and `max_processes`
    /// otherwise.
    pub fn effective_max_processes(&self) -> u32 {
        if matches!(self.child_processes, ChildProcessPolicy::Deny) {
            1
        } else {
            self.max_processes
        }
    }
}

/// Identity for the workload, set by `process.identity`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIdentity {
    /// YAML value: `backend_default`.
    #[default]
    BackendDefault,
    /// YAML value: `isolated`.
    Isolated,
}

/// Values accepted for `process.child_processes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChildProcessPolicy {
    /// YAML value: `allow`.
    #[default]
    Allow,
    /// YAML value: `deny`.
    Deny,
}

fn default_max_processes() -> u32 {
    32
}
fn default_max_memory_mb() -> u64 {
    8192
}
fn default_cpu_rate() -> u32 {
    80
}

/// Network connectivity policy — controls how the sandbox reaches the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// How the workload reaches the network. One of `proxy`, `block` or
    /// `allow`. Default: `proxy`.
    #[serde(default = "default_network_mode")]
    pub mode: NetworkMode,

    /// Named groups of endpoint rules. A non-empty list fails validation
    /// unless `mode` is `proxy`. Default: empty.
    #[serde(default)]
    pub policies: Vec<EndpointPolicy>,

    /// Proxy mode on a backend that blocks bypass attempts but cannot record
    /// them (Windows ProcessContainer). `best_effort` launches and warns that
    /// no bypass audit trail is kept; `hard_requirement` refuses to launch.
    /// Backends that record bypass attempts, or cannot block them, are not
    /// affected.
    /// One of `best_effort` or `hard_requirement`. Default: `best_effort`.
    #[serde(default)]
    pub bypass_audit: Compatibility,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: default_network_mode(),
            policies: Vec::new(),
            bypass_audit: Compatibility::default(),
        }
    }
}

impl NetworkPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if !self.policies.is_empty() && !matches!(self.mode, NetworkMode::Proxy) {
            return Err(PolicyError::ValidationError(
                "network endpoint policies require network.mode: proxy".into(),
            ));
        }
        for ep in &self.policies {
            if ep.name.is_empty() {
                return Err(PolicyError::ValidationError(
                    "network policy entries must have a name".into(),
                ));
            }
            if ep.endpoints.is_empty() {
                return Err(PolicyError::ValidationError(format!(
                    "network policy '{}' has no endpoints",
                    ep.name
                )));
            }
            for endpoint in &ep.endpoints {
                canonicalize_network_host(&endpoint.host).map_err(|reason| {
                    PolicyError::ValidationError(format!(
                        "network policy '{}' has an invalid endpoint host '{}': {reason}",
                        ep.name, endpoint.host
                    ))
                })?;
            }
        }
        Ok(())
    }
}

fn default_network_mode() -> NetworkMode {
    NetworkMode::Proxy
}

/// Network mode, set by `network.mode`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Proxy mode. YAML value: `proxy`.
    #[default]
    Proxy,
    /// Block mode. YAML value: `block`.
    Block,
    /// Allow mode. YAML value: `allow`.
    Allow,
}

/// A named group of endpoint rules with optional binary restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicy {
    /// Name of the group. An empty name fails validation. Required.
    pub name: String,
    /// Endpoints in the group. An empty list fails validation. Required.
    pub endpoints: Vec<Endpoint>,

    /// Program path patterns for the group. Default: empty.
    #[serde(default)]
    pub binaries: Vec<BinaryMatch>,
}

/// One network endpoint, given by host and port.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Host name or IP address. A host name must be an ASCII DNS name of at
    /// most 253 bytes; other values are rejected when the policy is parsed.
    /// A trailing `.` and the brackets around an IPv6 address are removed,
    /// and host names are stored in lowercase. Required.
    #[serde(
        deserialize_with = "deserialize_network_host",
        serialize_with = "serialize_network_host"
    )]
    pub host: String,
    /// Port number. Required.
    pub port: u16,

    /// Access level for the endpoint. One of `read-write` or `read-only`. A
    /// policy that requests `read-only` fails validation.
    /// Default: `read-write`.
    #[serde(default = "default_access")]
    pub access: Access,

    /// Protocol name. A policy that sets it fails validation.
    /// Unset by default.
    #[serde(default)]
    pub protocol: Option<String>,

    /// Request rules by method and path. A non-empty list fails validation.
    /// Default: empty.
    #[serde(default)]
    pub rules: Vec<L7Rule>,
}

fn deserialize_network_host<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let host = String::deserialize(deserializer)?;
    canonicalize_network_host(&host).map_err(D::Error::custom)
}

fn serialize_network_host<S>(host: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    canonicalize_network_host(host)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

fn canonicalize_network_host(host: &str) -> Result<String, &'static str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err("network endpoint host must not be empty");
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if !host.is_ascii() || host.len() > 253 {
        return Err("network endpoint host must be an ASCII DNS name of at most 253 bytes");
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    }) {
        return Err("network endpoint host is not a valid DNS name");
    }
    Ok(host.to_ascii_lowercase())
}

fn default_access() -> Access {
    Access::ReadWrite
}

/// Access level for an endpoint, set by `access`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    /// Read and write access. YAML value: `read-write`.
    #[default]
    ReadWrite,
    /// Read-only access. YAML value: `read-only`. A policy that requests it
    /// fails validation.
    ReadOnly,
}

/// A request rule for an endpoint. A policy that sets any rule fails
/// validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Rule {
    /// Request that the rule allows. Unset by default.
    pub allow: Option<L7Allow>,
}

/// Request method and path that a rule allows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Allow {
    /// Request method. Required.
    pub method: String,
    /// Request path. Required.
    pub path: String,
}

/// One program path pattern in `binaries`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryMatch {
    /// Path pattern for the program. Required.
    pub path: String,
}

/// Inference routing policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferencePolicy {
    /// Name of a route in `routes`. Unset by default.
    #[serde(default)]
    pub default_provider: Option<String>,

    /// Inference routes. Default: empty.
    #[serde(default)]
    pub routes: Vec<InferenceRoute>,

    /// Scheduling section. Unset by default.
    #[serde(default)]
    pub scheduling: Option<SchedulingPolicy>,

    /// Token budget section. Unset by default.
    #[serde(default)]
    pub token_budget: Option<TokenBudget>,
}

/// One inference route.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceRoute {
    /// Route name. Required.
    pub name: String,

    /// URL of the inference endpoint. Unset by default.
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Provider name. Unset by default.
    #[serde(default)]
    pub provider: Option<String>,

    /// Model name. Unset by default.
    #[serde(default)]
    pub model: Option<String>,

    /// Name of the environment variable that holds the API key. It must not
    /// be empty and can contain only uppercase ASCII letters, digits and `_`.
    /// When it is set, `network.mode` must be `proxy` and `endpoint` must be
    /// an `http://` URL with host `inference.local`. Otherwise validation
    /// fails. Unset by default.
    #[serde(default)]
    pub api_key_env: Option<String>,

    /// Protocol names. Default: empty.
    #[serde(default)]
    pub protocols: Vec<String>,
}

impl InferenceRoute {
    pub(crate) fn has_host_boundary_credentials(&self) -> bool {
        self.api_key_env.is_some()
            || self
                .endpoint
                .as_deref()
                .is_some_and(credential_endpoint_has_placeholder)
    }

    pub(crate) fn uses_https_credentials(&self) -> bool {
        if !self.has_host_boundary_credentials() {
            return false;
        }
        self.endpoint
            .as_deref()
            .and_then(|endpoint| url::Url::parse(endpoint).ok())
            .is_none_or(|endpoint| endpoint.scheme() != "http")
    }

    fn credential_endpoint(&self) -> Result<url::Url, PolicyError> {
        let endpoint = self.endpoint.as_deref().ok_or_else(|| {
            PolicyError::ValidationError(format!(
                "inference route '{}' with host-boundary credentials requires an explicit http:// endpoint",
                self.name
            ))
        })?;
        parse_credential_endpoint(endpoint).map_err(|reason| {
            PolicyError::ValidationError(format!(
                "inference route '{}' has an invalid credential endpoint: {reason}",
                self.name
            ))
        })
    }
}

fn validate_credential_env_name(route: &str, env_name: &str) -> Result<(), PolicyError> {
    let valid = !env_name.is_empty()
        && env_name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(PolicyError::ValidationError(format!(
            "inference route '{route}' api_key_env must be a non-empty uppercase environment variable name: {env_name}"
        )))
    }
}

/// Contents of `inference.scheduling`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingPolicy {
    /// Number. Default: `1`.
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// One of `interactive`, `background` or `batch`. Default: `background`.
    #[serde(default = "default_priority")]
    pub priority: Priority,

    /// Number. Unset by default.
    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
}

fn default_weight() -> u32 {
    1
}
fn default_priority() -> Priority {
    Priority::Background
}

/// Values accepted for `inference.scheduling.priority`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// YAML value: `interactive`.
    Interactive,
    /// YAML value: `background`.
    #[default]
    Background,
    /// YAML value: `batch`.
    Batch,
}

/// Contents of `inference.token_budget`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBudget {
    /// Token limit per hour. Required.
    pub max_tokens_per_hour: u64,

    /// Token limit per request. Default: `32768`.
    #[serde(default = "default_max_tokens_per_request")]
    pub max_tokens_per_request: u64,

    /// Action on budget exhaustion. YAML values accepted when the policy is
    /// read: `queue`, `reject` and `fallback_cloud`. Default: `reject`.
    #[serde(default = "default_exhaust_action")]
    pub action_on_exhaust: ExhaustAction,

    /// Route name. Unset by default.
    #[serde(default)]
    pub fallback_route: Option<String>,
}

fn default_max_tokens_per_request() -> u64 {
    32768
}

fn default_exhaust_action() -> ExhaustAction {
    ExhaustAction::Reject
}

/// Values accepted for `inference.token_budget.action_on_exhaust` when the
/// policy is read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustAction {
    /// YAML value: `queue`.
    Queue,
    /// YAML value: `reject`.
    #[default]
    Reject,
    /// YAML value: `fallback_cloud`.
    FallbackCloud,
}

/// AMD hardware-specific policy extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmdPolicy {
    /// The sandboxed process drives the host's AMD GPU directly through ROCm.
    /// On Linux the seccomp filter then also allows `sched_setaffinity`, which
    /// the ROCm runtime needs to start. It grants no device nodes or sysfs
    /// paths: those still come from `filesystem`.
    /// Default: `false`.
    #[serde(default)]
    pub gpu_passthrough: bool,

    /// Boolean. Default: `false`.
    #[serde(default)]
    pub npu_policy_offload: bool,

    /// APEX memory section. Unset by default.
    #[serde(default)]
    pub apex_memory_policy: Option<ApexMemoryPolicy>,
}

/// Contents of `amd.apex_memory_policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApexMemoryPolicy {
    /// Boolean. Default: `false`.
    #[serde(default)]
    pub allow_overcommit: bool,

    /// Number. Unset by default.
    #[serde(default)]
    pub max_vram_mb: Option<u64>,
}

/// GPU isolation policy — controls HIP Remote para-virtual GPU access.
///
/// Only `enabled`, `device`, and the TCP transport are implemented. The other
/// fields name controls the HIP Remote worker does not enforce yet; while
/// `enabled` is true, [`GpuPolicy::validate`] rejects a policy that requests
/// any of them instead of launching with the control silently ignored. With
/// `enabled: false` no worker is started and the fields are accepted unused.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPolicy {
    /// Enable GPU access for this sandbox.
    /// Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Physical GPU device ordinal (default: 0).
    #[serde(default)]
    pub device: u32,

    /// Transport for HIP Remote. Only "tcp" (the default) is implemented;
    /// "uds" (Unix domain socket) is rejected while `enabled` is true.
    #[serde(default = "default_gpu_transport")]
    pub transport: GpuTransport,

    /// Maximum GPU memory allocation in MB. Not enforced yet; rejected while
    /// `enabled` is true.
    /// Unset by default.
    #[serde(default)]
    pub vram_limit_mb: Option<u64>,

    /// Maximum wall-clock time per kernel launch in seconds. Not enforced
    /// yet; rejected while `enabled` is true.
    /// Unset by default.
    #[serde(default)]
    pub compute_timeout_sec: Option<u64>,

    /// Allowed HIP API categories. Not enforced yet; must be empty while
    /// `enabled` is true. No HIP API filtering is applied, including for
    /// default categories.
    /// Default: empty.
    #[serde(default)]
    pub allowed_apis: Vec<String>,

    /// Denied HIP API categories. Not enforced yet; must be empty while
    /// `enabled` is true.
    /// Default: empty.
    #[serde(default)]
    pub denied_apis: Vec<String>,
}

impl GpuPolicy {
    /// Reject GPU controls that AXIS cannot enforce yet.
    ///
    /// The HIP Remote worker is passed only a device ordinal and a TCP port,
    /// so accepting any of these fields on an enabled GPU section would report
    /// a restriction that is never applied.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let unenforced = self.unenforced_controls();
        let Some((last, rest)) = unenforced.split_last() else {
            return Ok(());
        };
        let message = if rest.is_empty() {
            format!("{last} is not enforced yet by the HIP Remote GPU worker; remove it")
        } else {
            format!(
                "{}, {last} are not enforced yet by the HIP Remote GPU worker; remove them",
                rest.join(", ")
            )
        };
        Err(PolicyError::ValidationError(message))
    }

    /// Requested GPU controls that AXIS does not enforce yet. Empty when the
    /// GPU is disabled, because no HIP Remote worker is started then.
    ///
    /// Shared by policy validation and the capability planner so both reject
    /// exactly the same fields.
    pub fn unenforced_controls(&self) -> Vec<&'static str> {
        let mut unenforced = Vec::new();
        if !self.enabled {
            return unenforced;
        }
        if matches!(self.transport, GpuTransport::Uds) {
            unenforced.push("gpu.transport: uds");
        }
        if self.vram_limit_mb.is_some() {
            unenforced.push("gpu.vram_limit_mb");
        }
        if self.compute_timeout_sec.is_some() {
            unenforced.push("gpu.compute_timeout_sec");
        }
        if !self.allowed_apis.is_empty() {
            unenforced.push("gpu.allowed_apis");
        }
        if !self.denied_apis.is_empty() {
            unenforced.push("gpu.denied_apis");
        }
        unenforced
    }
}

fn default_gpu_transport() -> GpuTransport {
    GpuTransport::Tcp
}

/// Values accepted for `gpu.transport`: `tcp` or `uds`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuTransport {
    /// YAML value: `uds`.
    Uds,
    /// YAML value: `tcp`.
    #[default]
    Tcp,
}

/// SSH key policy — controls which SSH keys and hosts agents can access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPolicy {
    /// SSH keys the agent is allowed to use.
    /// Default: empty.
    #[serde(default)]
    pub allowed_keys: Vec<SshKeySpec>,

    /// Auto-generate a scoped known_hosts file for the sandbox.
    /// Default: `false`.
    #[serde(default)]
    pub generate_known_hosts: bool,

    /// Auto-generate a restrictive SSH config for the sandbox.
    /// Default: `false`.
    #[serde(default)]
    pub generate_config: bool,
}

/// A specific SSH key with host restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeySpec {
    /// Display name for the key.
    /// Required.
    pub name: String,

    /// Path to the private key file (expanded from ~/).
    /// Required.
    pub private_key: String,

    /// Hosts this key is allowed to connect to. Empty = all hosts.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_POLICY: &str = r#"
version: 1
name: test-sandbox
"#;

    const FULL_POLICY: &str = r#"
version: 1
name: coding-agent-sandbox

runtime:
  containment: process
  provider: auto

filesystem:
  read_only:
    - /usr
    - /lib
    - /etc/ssl/certs
  read_write:
    - "{workspace}"
    - "{tmpdir}"
  deny:
    - "~/.ssh"
    - "~/.gnupg"

process:
  max_processes: 32
  max_memory_mb: 8192
  cpu_rate_percent: 80
  blocked_syscalls:
    - ptrace
    - mount
    - bpf

network:
  mode: proxy
  policies:
    - name: github-api
      endpoints:
        - host: "api.github.com"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/git"
        - path: "/usr/bin/curl"

inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://localhost:8080"
      protocols: [openai_chat_completions]
      model: "llama-4-scout-109b"
    - name: cloud-fallback
      endpoint: "http://inference.local:8081"
      model: "claude-sonnet-4-20250514"
      api_key_env: ANTHROPIC_API_KEY
  token_budget:
    max_tokens_per_hour: 500000
    max_tokens_per_request: 32768
    action_on_exhaust: fallback_cloud
    fallback_route: cloud-fallback

amd:
  gpu_passthrough: true
  npu_policy_offload: false
  apex_memory_policy:
    allow_overcommit: true
    max_vram_mb: 16384
"#;

    #[test]
    fn parse_minimal_policy() {
        let policy = Policy::from_yaml(MINIMAL_POLICY).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.name, "test-sandbox");
        assert_eq!(policy.runtime.containment, RuntimeContainment::Process);
        assert_eq!(policy.runtime.provider, RuntimeProvider::Auto);
        assert_eq!(policy.process.max_processes, 32);
        assert_eq!(policy.process.cpu_rate_percent, 80);
    }

    #[test]
    fn parse_full_policy() {
        let policy = Policy::from_yaml(FULL_POLICY).unwrap();
        assert_eq!(policy.name, "coding-agent-sandbox");
        assert_eq!(policy.runtime.containment, RuntimeContainment::Process);
        assert_eq!(policy.runtime.provider, RuntimeProvider::Auto);
        assert_eq!(policy.filesystem.read_only.len(), 3);
        assert_eq!(policy.filesystem.deny.len(), 2);
        assert_eq!(policy.network.policies.len(), 1);
        assert_eq!(policy.network.policies[0].name, "github-api");
        assert_eq!(policy.inference.routes.len(), 2);

        let budget = policy.inference.token_budget.as_ref().unwrap();
        assert_eq!(budget.max_tokens_per_hour, 500_000);
        assert!(matches!(
            budget.action_on_exhaust,
            ExhaustAction::FallbackCloud
        ));

        let amd = policy.amd.as_ref().unwrap();
        assert!(amd.gpu_passthrough);
        assert!(!amd.npu_policy_offload);
        assert_eq!(
            amd.apex_memory_policy.as_ref().unwrap().max_vram_mb,
            Some(16384)
        );
    }

    #[test]
    fn reject_invalid_version() {
        let yaml = "version: 99\nname: bad\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion(99)));
    }

    #[test]
    fn reject_empty_name() {
        let yaml = "version: 1\nname: \"\"\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }

    #[test]
    fn reject_policy_name_that_is_not_safe_path_component() {
        for name in [
            ".",
            "..",
            "../escape",
            "/absolute",
            "nested/name",
            "nested\\name",
            "bad name",
        ] {
            let yaml = format!("version: 1\nname: {name:?}\n");
            let err = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                matches!(err, PolicyError::ValidationError(_)),
                "expected invalid policy name {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn allow_policy_name_safe_path_component() {
        let yaml = "version: 1\nname: agent.codex_1-test\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.name, "agent.codex_1-test");
    }

    #[test]
    fn parse_runtime_provider_override() {
        let yaml = "\
version: 1
name: test
runtime:
  containment: process
  provider: mxc
";
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.runtime.containment, RuntimeContainment::Process);
        assert_eq!(policy.runtime.provider, RuntimeProvider::Mxc);
        assert_eq!(policy.runtime.containment.as_str(), "process");
        assert_eq!(policy.runtime.provider.as_str(), "mxc");
    }

    #[test]
    fn parse_runtime_axis_native_alias() {
        let yaml = "\
version: 1
name: test
runtime:
  provider: axis-native
";
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.runtime.provider, RuntimeProvider::AxisNative);
        assert_eq!(policy.runtime.provider.as_str(), "axis_native");
    }

    #[test]
    fn allow_zero_cpu_rate_to_disable_cpu_quota() {
        let yaml = "version: 1\nname: test\nprocess:\n  cpu_rate_percent: 0\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.process.cpu_rate_percent, 0);
    }

    #[test]
    fn allow_zero_process_and_memory_limits_to_disable_resource_limits() {
        let yaml = "version: 1\nname: test\nprocess:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n";
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.process.max_processes, 0);
        assert_eq!(policy.process.max_memory_mb, 0);
        assert_eq!(policy.process.cpu_rate_percent, 0);
    }

    #[test]
    fn portable_process_intents_parse_and_derive_effective_limit() {
        let policy = Policy::from_yaml(
            "version: 1\nname: portable-process\nprocess:\n  identity: isolated\n  child_processes: deny\n",
        )
        .unwrap();
        assert_eq!(policy.process.identity, ProcessIdentity::Isolated);
        assert_eq!(policy.process.child_processes, ChildProcessPolicy::Deny);
        assert_eq!(policy.process.effective_max_processes(), 1);
    }

    #[test]
    fn reject_invalid_cpu_rate() {
        let yaml = "version: 1\nname: test\nprocess:\n  cpu_rate_percent: 101\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }

    #[test]
    fn endpoint_access_defaults_to_full_host_port_authorization() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: endpoint-default
network:
  mode: proxy
  policies:
    - name: example
      endpoints:
        - host: example.com
          port: 443
"#,
        )
        .unwrap();

        assert!(matches!(
            policy.network.policies[0].endpoints[0].access,
            Access::ReadWrite
        ));
    }

    #[test]
    fn reject_endpoint_policies_outside_proxy_mode() {
        for mode in ["allow", "block"] {
            let yaml = format!(
                r#"
version: 1
name: endpoint-mode
network:
  mode: {mode}
  policies:
    - name: example
      endpoints:
        - host: example.com
          port: 443
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                err.to_string().contains("require network.mode: proxy"),
                "{err}"
            );
        }
    }

    #[test]
    fn reject_unenforced_endpoint_refinements() {
        let cases = [
            ("access: read-only", "read-only endpoint access"),
            ("protocol: rest", "protocol filtering"),
            (
                "rules:\n            - allow:\n                method: GET\n                path: /v1/models",
                "L7 method/path filtering",
            ),
        ];

        for (refinement, expected) in cases {
            let yaml = format!(
                r#"
version: 1
name: unsupported-endpoint-refinement
network:
  mode: proxy
  policies:
    - name: example
      endpoints:
        - host: example.com
          port: 443
          {refinement}
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn plain_gpu_enablement_is_accepted() {
        for body in [
            "gpu:\n  enabled: true\n",
            "gpu:\n  enabled: true\n  device: 1\n  transport: tcp\n",
        ] {
            let yaml = format!("version: 1\nname: gpu-plain\n{body}");
            let policy = Policy::from_yaml(&yaml).unwrap();
            assert!(policy.gpu.enabled);
            assert!(matches!(policy.gpu.transport, GpuTransport::Tcp));
        }
    }

    #[test]
    fn reject_unenforced_gpu_controls() {
        let cases = [
            ("vram_limit_mb: 8192", "gpu.vram_limit_mb"),
            ("compute_timeout_sec: 300", "gpu.compute_timeout_sec"),
            ("allowed_apis: [memory_alloc]", "gpu.allowed_apis"),
            ("denied_apis: [ipc]", "gpu.denied_apis"),
            ("transport: uds", "gpu.transport: uds"),
        ];

        for (control, field) in cases {
            let yaml =
                format!("version: 1\nname: gpu-unenforced\ngpu:\n  enabled: true\n  {control}\n");
            let err = Policy::from_yaml(&yaml).unwrap_err().to_string();
            assert!(err.contains(field), "{control}: {err}");
            assert!(err.contains("not enforced yet"), "{control}: {err}");
        }
    }

    #[test]
    fn disabled_gpu_section_accepts_unenforced_controls_unused() {
        let yaml = r#"
version: 1
name: gpu-disabled
gpu:
  enabled: false
  transport: uds
  vram_limit_mb: 1
  compute_timeout_sec: 1
  allowed_apis: [memory_alloc]
  denied_apis: [ipc]
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(!policy.gpu.enabled);
        assert!(policy.gpu.unenforced_controls().is_empty());
    }

    #[test]
    fn reject_unenforced_gpu_controls_names_every_field() {
        let yaml = r#"
version: 1
name: gpu-unenforced
gpu:
  enabled: true
  transport: uds
  vram_limit_mb: 1
  compute_timeout_sec: 1
  allowed_apis: [memory_alloc]
  denied_apis: [ipc]
"#;
        let err = Policy::from_yaml(yaml).unwrap_err().to_string();
        assert!(
            err.contains(
                "gpu.transport: uds, gpu.vram_limit_mb, gpu.compute_timeout_sec, \
                 gpu.allowed_apis, gpu.denied_apis are not enforced yet"
            ),
            "{err}"
        );
    }

    #[test]
    fn reject_l7_rules_independent_of_transport_hint() {
        for (port, protocol) in [(80, ""), (443, "          protocol: rest\n")] {
            let yaml = format!(
                r#"
version: 1
name: unsupported-l7
network:
  mode: proxy
  policies:
    - name: example
      endpoints:
        - host: example.com
          port: {port}
{protocol}          rules:
            - allow:
                method: GET
                path: /allowed
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("L7 method/path filtering")
                    || message.contains("protocol filtering"),
                "{message}"
            );
        }
    }

    #[test]
    fn allow_inference_virtual_host_credentials_in_proxy_mode() {
        for endpoint in [
            "http://inference.local:8080/v1",
            "http://INFERENCE.LOCAL.:8080/v1?key=axis:resolve:env:LOCAL_KEY",
        ] {
            let yaml = format!(
                r#"
version: 1
name: local-http-credentials
network:
  mode: proxy
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: LOCAL_KEY
"#
            );
            Policy::from_yaml(&yaml).unwrap();
        }
    }

    #[test]
    fn reject_credentials_without_proxy_mode() {
        for mode in ["allow", "block"] {
            let yaml = format!(
                r#"
version: 1
name: wrong-credential-mode
network:
  mode: {mode}
inference:
  routes:
    - name: local
      endpoint: http://inference.local:8080
      api_key_env: LOCAL_KEY
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            assert!(err.to_string().contains("network.mode: proxy"), "{err}");
        }
    }

    #[test]
    fn reject_https_host_boundary_credentials() {
        let cases = [
            "endpoint: https://example.com/v1\n      api_key_env: EXTERNAL_KEY",
            "provider: openai\n      api_key_env: EXTERNAL_KEY",
            "provider: anthropic\n      api_key_env: EXTERNAL_KEY",
            "endpoint: https://example.com/v1?key=axis:resolve:env:EXTERNAL_KEY",
        ];

        for route in cases {
            let yaml = format!(
                r#"
version: 1
name: unsupported-https-credentials
network:
  mode: proxy
inference:
  routes:
    - name: external
      {route}
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("HTTPS credential injection")
                    || message.contains("explicit http:// endpoint"),
                "{message}"
            );
        }
    }

    #[test]
    fn reject_plaintext_credentials_to_remote_endpoint() {
        let yaml = r#"
version: 1
name: remote-http-credentials
network:
  mode: proxy
inference:
  routes:
    - name: external
      endpoint: http://example.com/v1
      api_key_env: EXTERNAL_KEY
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("only through inference.local"),
            "{err}"
        );
    }

    #[test]
    fn reject_loopback_credential_origins_rejected_by_runtime_ssrf_controls() {
        for endpoint in [
            "http://localhost:8080/v1",
            "http://LOCALHOST.:8080/v1",
            "http://127.0.0.1:8080/v1",
            "http://127.1:8080/v1",
            "http://[::1]:8080/v1",
            "http://[0:0:0:0:0:0:0:1]:8080/v1",
        ] {
            let yaml = format!(
                r#"
version: 1
name: loopback-credential-origin
network:
  mode: proxy
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: LOCAL_KEY
"#
            );
            let error = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                error.to_string().contains("runtime SSRF controls"),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn reject_overlapping_credential_scopes_independent_of_route_order() {
        for routes in [
            r#"
    - name: broad
      endpoint: http://INFERENCE.LOCAL.:8080/v1
      api_key_env: BROAD_KEY
    - name: narrow
      endpoint: http://inference.local:8080/v1/chat
      api_key_env: NARROW_KEY
"#,
            r#"
    - name: narrow
      endpoint: http://inference.local:8080/v1/chat
      api_key_env: NARROW_KEY
    - name: broad
      endpoint: http://INFERENCE.LOCAL.:8080/v1
      api_key_env: BROAD_KEY
"#,
            r#"
    - name: first
      endpoint: http://inference.local:80/v1
      api_key_env: FIRST_KEY
    - name: duplicate
      endpoint: http://INFERENCE.LOCAL./v1
      api_key_env: SECOND_KEY
"#,
            r#"
    - name: encoded
      endpoint: http://inference.local/%76%31
      api_key_env: ENCODED_KEY
    - name: plain
      endpoint: http://inference.local/v1/chat
      api_key_env: PLAIN_KEY
"#,
            r#"
    - name: plain
      endpoint: http://inference.local/v1/chat
      api_key_env: PLAIN_KEY
    - name: encoded
      endpoint: http://inference.local/%76%31
      api_key_env: ENCODED_KEY
"#,
            r#"
    - name: lowercase-encoding
      endpoint: http://inference.local/v1%2fchat
      api_key_env: LOWER_KEY
    - name: uppercase-encoding
      endpoint: http://inference.local/v1%2Fchat
      api_key_env: UPPER_KEY
"#,
            r#"
    - name: lowercase-unreserved
      endpoint: http://inference.local/v1/%7euser
      api_key_env: LOWER_KEY
    - name: uppercase-unreserved
      endpoint: http://inference.local/v1/%7Euser
      api_key_env: UPPER_KEY
"#,
        ] {
            let yaml = format!(
                "version: 1\nname: ambiguous-scopes\nnetwork:\n  mode: proxy\ninference:\n  routes:{routes}"
            );
            let error = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                error.to_string().contains("ambiguous overlapping scopes"),
                "{error}"
            );
        }
    }

    #[test]
    fn allow_disjoint_credential_paths_and_ports() {
        let yaml = r#"
version: 1
name: disjoint-scopes
network:
  mode: proxy
inference:
  routes:
    - name: chat
      endpoint: http://inference.local:8080/v1/chat
      api_key_env: CHAT_KEY
    - name: models
      endpoint: http://inference.local:8080/v1/models
      api_key_env: MODELS_KEY
    - name: alternate-port
      endpoint: http://inference.local:8081/v1/chat
      api_key_env: ALT_KEY
"#;
        Policy::from_yaml(yaml).unwrap();
    }

    #[test]
    fn preserve_encoded_reserved_separator_scope_boundaries() {
        let yaml = r#"
version: 1
name: reserved-path-boundaries
network:
  mode: proxy
inference:
  routes:
    - name: encoded-separator
      endpoint: http://inference.local/v1%2Fchat
      api_key_env: ENCODED_KEY
    - name: path-separator
      endpoint: http://inference.local/v1/chat
      api_key_env: PATH_KEY
"#;
        Policy::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_credential_endpoint_fragments_and_malformed_percent_encoding() {
        for endpoint in [
            "http://inference.local/v1#fragment?key=axis:resolve:env:LOCAL_KEY",
            "http://inference.local/v1?key=axis:resolve:env:LOCAL_KEY#fragment",
            "http://inference.local/v%7?key=axis:resolve:env:LOCAL_KEY",
            "http://inference.local/v1?key=axis%ZZresolve%3Aenv%3ALOCAL_KEY&other=axis:resolve:env:OTHER_KEY",
        ] {
            let yaml = format!(
                r#"
version: 1
name: invalid-credential-endpoint
network:
  mode: proxy
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: LOCAL_KEY
"#
            );
            let error = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                error.to_string().contains("invalid credential endpoint"),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn detect_percent_encoded_query_credential_placeholders_during_validation() {
        let yaml = r#"
version: 1
name: encoded-query-placeholder
network:
  mode: proxy
inference:
  routes:
    - name: remote
      endpoint: "http://example.com/v1?key=axis%3Aresolve%3Aenv%3AREMOTE_KEY"
"#;
        let error = Policy::from_yaml(yaml).unwrap_err();
        assert!(error.to_string().contains("only through inference.local"));
    }

    #[test]
    fn canonicalize_network_policy_dns_and_ip_hosts_before_serialization() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: canonical-hosts
network:
  mode: proxy
  policies:
    - name: endpoints
      endpoints:
        - host: API.EXAMPLE.COM.
          port: 443
        - host: 2001:0db8:0:0::1
          port: 443
"#,
        )
        .unwrap();

        assert_eq!(
            policy.network.policies[0].endpoints[0].host,
            "api.example.com"
        );
        assert_eq!(policy.network.policies[0].endpoints[1].host, "2001:db8::1");
        let data = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            data["network"]["policies"][0]["endpoints"][0]["host"],
            "api.example.com"
        );
        assert_eq!(
            data["network"]["policies"][0]["endpoints"][1]["host"],
            "2001:db8::1"
        );
    }

    #[test]
    fn reject_malformed_network_policy_hosts() {
        for host in [
            "",
            ".",
            "example.com..",
            "-bad.example",
            "bad-.example",
            "bad_host",
        ] {
            let yaml = format!(
                "version: 1\nname: invalid-host\nnetwork:\n  mode: proxy\n  policies:\n    - name: bad\n      endpoints:\n        - host: \"{host}\"\n          port: 443\n"
            );
            let error = Policy::from_yaml(&yaml).unwrap_err();
            assert!(
                error.to_string().contains("network endpoint host"),
                "{host}: {error}"
            );
        }
    }

    #[test]
    fn reject_invalid_credential_environment_names_and_placeholders() {
        let cases = [
            (
                "http://localhost:8080/v1",
                "api_key_env: lower_case",
                "uppercase environment variable",
            ),
            (
                "http://localhost:8080/v1",
                "api_key_env: ''",
                "uppercase environment variable",
            ),
            (
                "http://localhost:8080/v1?key=axis:resolve:file:secret",
                "",
                "unsupported credential placeholder",
            ),
            (
                "http://localhost:8080/v1?key=axis:resolve:env:lower_case",
                "",
                "uppercase environment variable",
            ),
            (
                "http://localhost:8080/v1?=axis:resolve:env:LOCAL_KEY",
                "",
                "placeholder must have a name",
            ),
            (
                "http://localhost:8080/v1?api_key=axis:resolve:env:LOCAL_KEY&api%5Fkey=shadow",
                "",
                "one unambiguous definition",
            ),
        ];

        for (endpoint, route, expected) in cases {
            let yaml = format!(
                r#"
version: 1
name: invalid-credential-reference
network:
  mode: proxy
inference:
  routes:
    - name: local
      endpoint: {endpoint}
      {route}
"#
            );
            let err = Policy::from_yaml(&yaml).unwrap_err();
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    fn assert_unknown_field_rejected(family: &str, yaml: &str, field: &str) {
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, PolicyError::ParseError(_)),
            "{family} unknown field must fail during deserialization: {err}"
        );
        assert!(
            err.to_string()
                .contains(&format!("unknown field `{field}`")),
            "{family} rejected for an unexpected reason: {err}"
        );
    }

    #[test]
    fn reject_unknown_fields_across_policy_mapping_families() {
        let cases = [
            ("policy", "unexpected: true\n", "unexpected"),
            (
                "runtime",
                "runtime:\n  containment: process\n  providre: auto\n",
                "providre",
            ),
            (
                "filesystem",
                "filesystem:\n  read_only: [/usr]\n  compatiblity: best_effort\n",
                "compatiblity",
            ),
            (
                "process",
                "process:\n  max_processes: 4\n  blocked_syscall: [ptrace]\n",
                "blocked_syscall",
            ),
            (
                "network",
                "network:\n  mode: proxy\n  endpoint_policies: []\n",
                "endpoint_policies",
            ),
            (
                "endpoint",
                "network:\n  mode: proxy\n  policies:\n    - name: web\n      endpoints:\n        - host: example.com\n          port: 443\n          protcol: tcp\n",
                "protcol",
            ),
            (
                "L7 rule",
                "network:\n  mode: proxy\n  policies:\n    - name: web\n      endpoints:\n        - host: example.com\n          port: 443\n          rules:\n            - allow: { method: GET, path: / }\n              audit: true\n",
                "audit",
            ),
            (
                "L7 allow",
                "network:\n  mode: proxy\n  policies:\n    - name: web\n      endpoints:\n        - host: example.com\n          port: 443\n          rules:\n            - allow: { method: GET, path: /, query: safe=true }\n",
                "query",
            ),
            (
                "binary match",
                "network:\n  mode: proxy\n  policies:\n    - name: web\n      endpoints: [{ host: example.com, port: 443 }]\n      binaries:\n        - path: /usr/bin/curl\n          sha256: deadbeef\n",
                "sha256",
            ),
            (
                "inference",
                "inference:\n  default_providr: local\n",
                "default_providr",
            ),
            (
                "inference route",
                "inference:\n  routes:\n    - name: local\n      endpoint: http://localhost:8080\n      protcols: [openai]\n",
                "protcols",
            ),
            (
                "scheduling",
                "inference:\n  scheduling:\n    weight: 1\n    max_concurent_requests: 2\n",
                "max_concurent_requests",
            ),
            (
                "token budget",
                "inference:\n  token_budget:\n    max_tokens_per_hour: 1000\n    max_tokens_per_requst: 100\n",
                "max_tokens_per_requst",
            ),
            ("AMD", "amd:\n  gpu_passthrouh: true\n", "gpu_passthrouh"),
            (
                "APEX memory",
                "amd:\n  apex_memory_policy:\n    allow_overcommit: false\n    max_vram_mib: 1024\n",
                "max_vram_mib",
            ),
            (
                "GPU",
                "gpu:\n  enabled: true\n  denied_api: [ipc]\n",
                "denied_api",
            ),
            (
                "SSH",
                "ssh:\n  generate_known_hosts: true\n  generate_confg: true\n",
                "generate_confg",
            ),
            (
                "SSH key",
                "ssh:\n  allowed_keys:\n    - name: deploy\n      private_key: ~/.ssh/id_ed25519\n      allowed_host: [github.com]\n",
                "allowed_host",
            ),
        ];

        for (family, body, field) in cases {
            let yaml = format!("version: 1\nname: unknown-field\n{body}");
            assert_unknown_field_rejected(family, &yaml, field);
        }
    }

    #[test]
    fn endpoint_binary_typo_cannot_broaden_authorization() {
        let yaml = r#"
version: 1
name: endpoint-binary-typo
network:
  mode: proxy
  policies:
    - name: github
      endpoints:
        - host: api.github.com
          port: 443
      binaires:
        - path: /usr/bin/git
"#;

        assert_unknown_field_rejected("endpoint policy", yaml, "binaires");
    }

    #[test]
    fn system_service_lists_require_the_restriction_flag() {
        let yaml =
            "version: 1\nname: test\nprocess:\n  macos_mach_lookup: [com.apple.SecurityServer]\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("restrict_system_services"));

        let yaml = "version: 1\nname: test\nprocess:\n  macos_sysctl_read: [kern.hostname]\n";
        let err = Policy::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("restrict_system_services"));
    }

    #[test]
    fn system_service_names_reject_profile_metacharacters() {
        let quoted = "version: 1\nname: test\nprocess:\n  restrict_system_services: true\n  macos_mach_lookup: ['bad\"name']\n";
        let err = Policy::from_yaml(quoted).unwrap_err();
        assert!(err.to_string().contains("Mach service name"), "{err}");

        let prefix = "version: 1\nname: test\nprocess:\n  restrict_system_services: true\n  macos_sysctl_read: [kern.proc.]\n";
        let err = Policy::from_yaml(prefix).unwrap_err();
        assert!(err.to_string().contains("exact sysctl name"), "{err}");
    }

    #[test]
    fn system_service_restriction_round_trips() {
        let yaml = r#"
version: 1
name: test
process:
  restrict_system_services: true
  macos_mach_lookup:
    - com.apple.SecurityServer
  macos_sysctl_read:
    - kern.hostname
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.process.restrict_system_services);
        assert_eq!(
            policy.process.macos_mach_lookup,
            vec!["com.apple.SecurityServer".to_string()]
        );
        assert_eq!(
            policy.process.macos_sysctl_read,
            vec!["kern.hostname".to_string()]
        );
        let encoded = serde_yaml::to_string(&policy).unwrap();
        assert!(encoded.contains("restrict_system_services: true"));
        assert!(encoded.contains("macos_mach_lookup"));

        let default_encoded =
            serde_yaml::to_string(&Policy::from_yaml("version: 1\nname: test\n").unwrap()).unwrap();
        assert!(!default_encoded.contains("restrict_system_services"));
        assert!(!default_encoded.contains("macos_"));
    }

    #[test]
    fn removed_macos_section_is_rejected() {
        let yaml = "version: 1\nname: test\nmacos:\n  restrict_system_services: true\n";
        assert!(Policy::from_yaml(yaml).is_err());
    }
}
