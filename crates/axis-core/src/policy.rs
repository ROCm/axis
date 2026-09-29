// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! YAML policy schema parsing and validation.
//!
//! The policy model defines the AXIS YAML contract. Policies govern filesystem
//! access, process limits, network connectivity, inference routing, and
//! AMD-specific features.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("policy validation failed: {0}")]
    ValidationError(String),

    #[error("unsupported policy version: {0}")]
    UnsupportedVersion(u32),
}

/// Top-level AXIS policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub name: String,

    #[serde(default)]
    pub runtime: RuntimePolicy,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub process: ProcessPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub inference: InferencePolicy,

    #[serde(default)]
    pub gpu: GpuPolicy,

    #[serde(default)]
    pub ssh: SshPolicy,

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
    #[serde(default = "default_runtime_containment")]
    pub containment: RuntimeContainment,

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeContainment {
    #[default]
    Process,
}

impl RuntimeContainment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
        }
    }
}

fn default_runtime_provider() -> RuntimeProvider {
    RuntimeProvider::Auto
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProvider {
    #[default]
    Auto,
    Mxc,
    #[serde(alias = "axis-native")]
    AxisNative,
    /// Each sandbox is a Xen DomU (a VM) driven through the vxn CLI /
    /// vxn-oci-runtime. VM-strength isolation tier; Linux/Xen only.
    Vxn,
}

impl RuntimeProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Mxc => "mxc",
            Self::AxisNative => "axis_native",
            Self::Vxn => "vxn",
        }
    }
}

/// Filesystem access policy — controls what paths the sandboxed process can read/write.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub read_only: Vec<String>,

    #[serde(default)]
    pub read_write: Vec<String>,

    #[serde(default)]
    pub deny: Vec<String>,

    #[serde(default = "default_compatibility")]
    pub compatibility: Compatibility,
}

fn default_compatibility() -> Compatibility {
    Compatibility::BestEffort
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

/// Process containment policy — limits on the sandboxed process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    /// Maximum process count. 0 disables process-count enforcement.
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,

    /// Maximum memory in MiB. 0 disables memory enforcement.
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u64,

    /// CPU quota percentage. 0 disables CPU quota enforcement; 1..=100
    /// requests the platform CPU quota mechanism.
    #[serde(default = "default_cpu_rate")]
    pub cpu_rate_percent: u32,

    #[serde(default)]
    pub run_as_user: Option<String>,

    #[serde(default)]
    pub blocked_syscalls: Vec<String>,

    /// Portable identity intent. Unlike `run_as_user`, this does not name a
    /// host account and can map to a BaseContainer/AppContainer identity.
    #[serde(default)]
    pub identity: ProcessIdentity,

    /// Portable descendant-process intent. `deny` maps to a child-tree process
    /// limit of one rather than to platform-specific syscall names.
    #[serde(default)]
    pub child_processes: ChildProcessPolicy,

    /// Maximum wall-clock time in seconds before auto-destroy. None = no timeout.
    #[serde(default)]
    pub timeout_sec: Option<u64>,
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
        Ok(())
    }

    pub fn effective_max_processes(&self) -> u32 {
        if matches!(self.child_processes, ChildProcessPolicy::Deny) {
            1
        } else {
            self.max_processes
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIdentity {
    #[default]
    BackendDefault,
    Isolated,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChildProcessPolicy {
    #[default]
    Allow,
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
    #[serde(default = "default_network_mode")]
    pub mode: NetworkMode,

    #[serde(default)]
    pub policies: Vec<EndpointPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: default_network_mode(),
            policies: Vec::new(),
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Proxy,
    Block,
    Allow,
}

/// A named group of endpoint rules with optional binary restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicy {
    pub name: String,
    pub endpoints: Vec<Endpoint>,

    #[serde(default)]
    pub binaries: Vec<BinaryMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[serde(
        deserialize_with = "deserialize_network_host",
        serialize_with = "serialize_network_host"
    )]
    pub host: String,
    pub port: u16,

    #[serde(default = "default_access")]
    pub access: Access,

    #[serde(default)]
    pub protocol: Option<String>,

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    #[default]
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Rule {
    pub allow: Option<L7Allow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Allow {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryMatch {
    pub path: String,
}

/// Inference routing policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferencePolicy {
    #[serde(default)]
    pub default_provider: Option<String>,

    #[serde(default)]
    pub routes: Vec<InferenceRoute>,

    #[serde(default)]
    pub scheduling: Option<SchedulingPolicy>,

    #[serde(default)]
    pub token_budget: Option<TokenBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceRoute {
    pub name: String,

    #[serde(default)]
    pub endpoint: Option<String>,

    #[serde(default)]
    pub provider: Option<String>,

    #[serde(default)]
    pub model: Option<String>,

    #[serde(default)]
    pub api_key_env: Option<String>,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingPolicy {
    #[serde(default = "default_weight")]
    pub weight: u32,

    #[serde(default = "default_priority")]
    pub priority: Priority,

    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
}

fn default_weight() -> u32 {
    1
}
fn default_priority() -> Priority {
    Priority::Background
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Interactive,
    #[default]
    Background,
    Batch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBudget {
    pub max_tokens_per_hour: u64,

    #[serde(default = "default_max_tokens_per_request")]
    pub max_tokens_per_request: u64,

    #[serde(default = "default_exhaust_action")]
    pub action_on_exhaust: ExhaustAction,

    #[serde(default)]
    pub fallback_route: Option<String>,
}

fn default_max_tokens_per_request() -> u64 {
    32768
}

fn default_exhaust_action() -> ExhaustAction {
    ExhaustAction::Reject
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustAction {
    Queue,
    #[default]
    Reject,
    FallbackCloud,
}

/// AMD hardware-specific policy extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmdPolicy {
    #[serde(default)]
    pub gpu_passthrough: bool,

    #[serde(default)]
    pub npu_policy_offload: bool,

    #[serde(default)]
    pub apex_memory_policy: Option<ApexMemoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApexMemoryPolicy {
    #[serde(default)]
    pub allow_overcommit: bool,

    #[serde(default)]
    pub max_vram_mb: Option<u64>,
}

/// GPU isolation policy — controls HIP Remote para-virtual GPU access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPolicy {
    /// Enable GPU access for this sandbox.
    #[serde(default)]
    pub enabled: bool,

    /// Physical GPU device ordinal (default: 0).
    #[serde(default)]
    pub device: u32,

    /// Transport for HIP Remote: "uds" (Unix domain socket) or "tcp".
    #[serde(default = "default_gpu_transport")]
    pub transport: GpuTransport,

    /// Maximum GPU memory allocation in MB. None = unlimited.
    #[serde(default)]
    pub vram_limit_mb: Option<u64>,

    /// Maximum wall-clock time per kernel launch in seconds. None = unlimited.
    #[serde(default)]
    pub compute_timeout_sec: Option<u64>,

    /// Allowed API categories. Empty = default set (all except IPC/context).
    #[serde(default)]
    pub allowed_apis: Vec<String>,

    /// Denied API categories. Explicit denials override allowed.
    #[serde(default)]
    pub denied_apis: Vec<String>,
}

fn default_gpu_transport() -> GpuTransport {
    GpuTransport::Uds
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuTransport {
    #[default]
    Uds,
    Tcp,
}

/// SSH key policy — controls which SSH keys and hosts agents can access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPolicy {
    /// SSH keys the agent is allowed to use.
    #[serde(default)]
    pub allowed_keys: Vec<SshKeySpec>,

    /// Auto-generate a scoped known_hosts file for the sandbox.
    #[serde(default)]
    pub generate_known_hosts: bool,

    /// Auto-generate a restrictive SSH config for the sandbox.
    #[serde(default)]
    pub generate_config: bool,
}

/// A specific SSH key with host restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeySpec {
    /// Display name for the key.
    pub name: String,

    /// Path to the private key file (expanded from ~/).
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
}
