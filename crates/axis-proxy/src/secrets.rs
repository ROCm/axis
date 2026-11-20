// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Credential placeholder resolution and injection.
//!
//! Rewrites HTTP request headers/query parameters to inject real credentials
//! from host-side environment variables or a secure store. The sandbox process
//! never receives the actual credential values.

use axis_core::policy::{
    InferenceRoute, Policy, canonicalize_credential_path, credential_endpoint_has_placeholder,
    parse_credential_endpoint, validate_url_percent_encoding,
};
use hyper::http::{HeaderValue as HttpHeaderValue, Uri, uri::Authority};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("unresolved placeholder: {0}")]
    Unresolved(String),

    #[error("environment variable not found: {0}")]
    EnvNotFound(String),

    #[error("unsupported placeholder: {0}")]
    UnsupportedPlaceholder(String),

    #[error("invalid credential injection route '{route}': {reason}")]
    InvalidRoute { route: String, reason: String },

    #[error("invalid HTTP request for credential injection: {0}")]
    InvalidHttpRequest(String),

    #[error("resolved credential is not a valid value for HTTP header '{0}'")]
    InvalidHeaderValue(String),
}

/// Resolves credential placeholders in HTTP headers.
#[derive(Clone, Default)]
pub struct SecretResolver {
    /// Static secret mappings (name → value).
    secrets: HashMap<String, String>,
}

impl SecretResolver {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Add a static secret.
    pub fn add_secret(&mut self, name: String, value: String) {
        self.secrets.insert(name, value);
    }

    /// Resolve a placeholder string.
    ///
    /// Supported formats:
    /// - `axis:resolve:env:VAR_NAME` — resolve from environment variable
    /// - `axis:resolve:secret:NAME` — resolve from static secret store
    pub fn resolve(&self, placeholder: &str) -> Result<String, SecretError> {
        if let Some(var_name) = placeholder.strip_prefix("axis:resolve:env:") {
            std::env::var(var_name).map_err(|_| SecretError::EnvNotFound(var_name.into()))
        } else if let Some(secret_name) = placeholder.strip_prefix("axis:resolve:secret:") {
            self.secrets
                .get(secret_name)
                .cloned()
                .ok_or_else(|| SecretError::Unresolved(secret_name.into()))
        } else if placeholder.starts_with("axis:resolve:") {
            Err(SecretError::UnsupportedPlaceholder(placeholder.to_string()))
        } else {
            // Not a placeholder — return as-is.
            Ok(placeholder.to_string())
        }
    }

    /// Scan a header value for placeholders and resolve them.
    pub fn resolve_header_value(&self, value: &str) -> Result<String, SecretError> {
        if value.starts_with("axis:resolve:") {
            self.resolve(value)
        } else {
            Ok(value.to_string())
        }
    }
}

#[derive(Clone)]
pub struct CredentialInjector {
    rules: Vec<CredentialRule>,
    resolver: SecretResolver,
}

#[derive(Clone)]
struct CredentialRule {
    route_name: String,
    host: String,
    port: Option<u16>,
    scheme: Option<EndpointScheme>,
    path_prefix: Option<String>,
    requires_inference_pattern: bool,
    header: Option<HeaderInjection>,
    query: Vec<QueryInjection>,
}

#[derive(Clone)]
struct HeaderInjection {
    name: String,
    value: HeaderValue,
}

#[derive(Clone)]
enum HeaderValue {
    BearerEnv { env_name: String },
    RawEnv { env_name: String },
}

#[derive(Clone)]
struct QueryInjection {
    name: String,
    placeholder: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointScheme {
    Http,
    Https,
}

struct ParsedHttpHead {
    method: String,
    uri: String,
    version: String,
    path: String,
    authority: NormalizedAuthority,
    headers: Vec<(String, String)>,
    body_length: usize,
}

pub(crate) struct RewrittenHttpRequestHead {
    pub(crate) head: Option<Vec<u8>>,
    pub(crate) body_length: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedAuthority {
    host: String,
    port: u16,
}

impl CredentialInjector {
    pub fn from_policy(policy: &Policy) -> Result<Self, SecretError> {
        let resolver = SecretResolver::new();
        let mut rules = Vec::new();
        for route in &policy.inference.routes {
            if let Some(rule) = CredentialRule::from_route(route, &resolver)? {
                rules.push(rule);
            }
        }
        for (index, rule) in rules.iter().enumerate() {
            for other in &rules[index + 1..] {
                if rule.overlaps(other) {
                    return Err(SecretError::InvalidRoute {
                        route: format!("{} and {}", rule.route_name, other.route_name),
                        reason: format!(
                            "credential scopes overlap on {}:{} ('{}' and '{}')",
                            rule.host,
                            rule.port.unwrap_or_else(|| {
                                default_port_for_scheme(rule.scheme.unwrap_or(EndpointScheme::Http))
                            }),
                            rule.path_prefix.as_deref().unwrap_or("/"),
                            other.path_prefix.as_deref().unwrap_or("/")
                        ),
                    });
                }
            }
        }
        Ok(Self { rules, resolver })
    }

    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    pub fn connection_requires_injection(&self, host: &str, port: u16, is_tls: bool) -> bool {
        let host = normalize_host(host);
        self.rules
            .iter()
            .any(|rule| rule.matches_connection(&host, port, is_tls))
    }

    pub fn rewrite_http_request_head(
        &self,
        connect_host: &str,
        connect_port: u16,
        is_tls: bool,
        head: &[u8],
    ) -> Result<Option<Vec<u8>>, SecretError> {
        Ok(self
            .rewrite_http_request_head_with_body_length(connect_host, connect_port, is_tls, head)?
            .head)
    }

    pub(crate) fn rewrite_http_request_head_with_body_length(
        &self,
        connect_host: &str,
        connect_port: u16,
        is_tls: bool,
        head: &[u8],
    ) -> Result<RewrittenHttpRequestHead, SecretError> {
        self.rewrite_http_request_head_with_body_length_impl(
            connect_host,
            connect_port,
            is_tls,
            head,
            false,
        )
    }

    pub(crate) fn inspect_http_request_head_with_body_length(
        &self,
        connect_host: &str,
        connect_port: u16,
        is_tls: bool,
        head: &[u8],
    ) -> Result<RewrittenHttpRequestHead, SecretError> {
        self.rewrite_http_request_head_with_body_length_impl(
            connect_host,
            connect_port,
            is_tls,
            head,
            true,
        )
    }

    fn rewrite_http_request_head_with_body_length_impl(
        &self,
        connect_host: &str,
        connect_port: u16,
        is_tls: bool,
        head: &[u8],
        inspect_without_rules: bool,
    ) -> Result<RewrittenHttpRequestHead, SecretError> {
        let host = normalize_host(connect_host);
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.matches_connection(&host, connect_port, is_tls))
            .collect();
        if rules.is_empty() && !inspect_without_rules {
            return Ok(RewrittenHttpRequestHead {
                head: None,
                body_length: 0,
            });
        }
        let scheme = EndpointScheme::from_tls(is_tls);
        let parsed = ParsedHttpHead::parse(head, scheme)?;
        let connect_authority = NormalizedAuthority {
            host: host.clone(),
            port: connect_port,
        };
        if parsed.authority != connect_authority {
            return Err(SecretError::InvalidHttpRequest(
                "Host authority does not match CONNECT destination".into(),
            ));
        }
        if rules.is_empty() {
            return Ok(RewrittenHttpRequestHead {
                head: None,
                body_length: parsed.body_length,
            });
        }
        let Some(rule) = rules
            .into_iter()
            .find(|rule| rule.applies_to(&parsed, &host))
        else {
            return Ok(RewrittenHttpRequestHead {
                head: None,
                body_length: parsed.body_length,
            });
        };

        Ok(RewrittenHttpRequestHead {
            head: Some(rule.rewrite(&parsed, &self.resolver)?),
            body_length: parsed.body_length,
        })
    }
}

impl CredentialRule {
    fn from_route(
        route: &InferenceRoute,
        resolver: &SecretResolver,
    ) -> Result<Option<Self>, SecretError> {
        let raw_endpoint = route.endpoint.as_deref();
        let has_credential_intent = route.api_key_env.is_some()
            || raw_endpoint.is_some_and(credential_endpoint_has_placeholder);
        let endpoint = match raw_endpoint.map(parse_endpoint).transpose() {
            Ok(endpoint) => endpoint,
            Err(reason) if has_credential_intent => {
                return Err(SecretError::InvalidRoute {
                    route: route.name.clone(),
                    reason,
                });
            }
            Err(_) => None,
        };
        let query = endpoint
            .as_ref()
            .map(|endpoint| query_injections(route, endpoint.query.as_deref(), resolver))
            .transpose()?
            .unwrap_or_default();
        let header = route
            .api_key_env
            .as_deref()
            .map(|env_name| header_injection(route, env_name))
            .transpose()?;

        if header.is_none() && query.is_empty() {
            return Ok(None);
        }

        let host = endpoint
            .as_ref()
            .map(|endpoint| endpoint.host.clone())
            .or_else(|| route.provider.as_deref().and_then(provider_host).map(str::to_string))
            .ok_or_else(|| SecretError::InvalidRoute {
                route: route.name.clone(),
                reason: "api_key_env or endpoint placeholders require an endpoint host or known provider".into(),
            })?;
        let host = normalize_host(&host);
        let scheme = endpoint
            .as_ref()
            .map(|endpoint| endpoint.scheme)
            .or_else(|| {
                route
                    .provider
                    .as_deref()
                    .and_then(provider_host)
                    .map(|_| EndpointScheme::Https)
            });
        let port = endpoint
            .as_ref()
            .and_then(|endpoint| endpoint.port)
            .or_else(|| scheme.map(default_port_for_scheme));
        let path_prefix = endpoint
            .as_ref()
            .and_then(|endpoint| non_root_path_prefix(&endpoint.path));
        let requires_inference_pattern =
            requires_inference_pattern(route.provider.as_deref(), &host);

        Ok(Some(Self {
            route_name: route.name.clone(),
            host,
            port,
            scheme,
            path_prefix,
            requires_inference_pattern,
            header,
            query,
        }))
    }

    fn matches_connection(&self, host: &str, port: u16, is_tls: bool) -> bool {
        if self.host != host {
            return false;
        }
        if let Some(rule_port) = self.port
            && rule_port != port
        {
            return false;
        }
        if let Some(scheme) = self.scheme
            && scheme.is_tls() != is_tls
        {
            return false;
        }
        true
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.scheme == other.scheme
            && credential_path_prefixes_overlap(
                self.path_prefix.as_deref(),
                other.path_prefix.as_deref(),
            )
    }

    fn applies_to(&self, request: &ParsedHttpHead, host: &str) -> bool {
        if let Some(prefix) = &self.path_prefix
            && !path_matches_prefix(&request.path, prefix)
        {
            return false;
        }
        if !self.requires_inference_pattern {
            return true;
        }
        crate::l7::inference::detect_inference_pattern(&request.method, &request.path, host)
            .is_some()
    }

    fn rewrite(
        &self,
        request: &ParsedHttpHead,
        resolver: &SecretResolver,
    ) -> Result<Vec<u8>, SecretError> {
        let header = self
            .header
            .as_ref()
            .map(|header| header.resolve(resolver))
            .transpose()?;

        let mut query_values = Vec::new();
        for query in &self.query {
            let value = resolver.resolve(&query.placeholder)?;
            query_values.push((query.name.as_str(), value));
        }

        let uri = rewrite_uri_query(&request.uri, &query_values)?;
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", request.method, uri, request.version).as_bytes(),
        );

        for (name, value) in &request.headers {
            if let Some((inject_name, _)) = &header
                && name.eq_ignore_ascii_case(inject_name)
            {
                continue;
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }

        if let Some((name, value)) = header {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

impl HeaderInjection {
    fn resolve(&self, resolver: &SecretResolver) -> Result<(String, HttpHeaderValue), SecretError> {
        let (prefix, secret) = match &self.value {
            HeaderValue::BearerEnv { env_name } => {
                let secret = resolver.resolve(&format!("axis:resolve:env:{env_name}"))?;
                (b"Bearer ".as_slice(), secret)
            }
            HeaderValue::RawEnv { env_name } => {
                let secret = resolver.resolve(&format!("axis:resolve:env:{env_name}"))?;
                ([].as_slice(), secret)
            }
        };
        if secret.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(SecretError::InvalidHeaderValue(self.name.clone()));
        }

        let mut value = Vec::with_capacity(prefix.len() + secret.len());
        value.extend_from_slice(prefix);
        value.extend_from_slice(secret.as_bytes());
        let value = HttpHeaderValue::from_bytes(&value)
            .map_err(|_| SecretError::InvalidHeaderValue(self.name.clone()))?;
        Ok((self.name.clone(), value))
    }
}

impl ParsedHttpHead {
    fn parse(head: &[u8], scheme: EndpointScheme) -> Result<Self, SecretError> {
        validate_canonical_http_head(head)?;
        let mut parsed_headers = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut parsed_headers);
        let consumed = match request.parse(head).map_err(|_| {
            SecretError::InvalidHttpRequest("malformed HTTP/1.1 request head".into())
        })? {
            httparse::Status::Complete(consumed) => consumed,
            httparse::Status::Partial => {
                return Err(SecretError::InvalidHttpRequest(
                    "incomplete HTTP/1.1 request head".into(),
                ));
            }
        };
        if consumed != head.len() || request.version != Some(1) {
            return Err(SecretError::InvalidHttpRequest(
                "credential injection requires one canonical HTTP/1.1 request head".into(),
            ));
        }
        let method = request
            .method
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing method".into()))?;
        let uri = request
            .path
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing URI".into()))?;
        let version = "HTTP/1.1";

        validate_url_percent_encoding(uri).map_err(|reason| {
            SecretError::InvalidHttpRequest(format!("malformed request target: {reason}"))
        })?;
        let parsed_uri = uri.parse::<Uri>().map_err(|_| {
            SecretError::InvalidHttpRequest("malformed URI in route-scoped request".into())
        })?;
        if let Some(query) = parsed_uri.query() {
            validate_url_percent_encoding(query).map_err(|reason| {
                SecretError::InvalidHttpRequest(format!("malformed request query: {reason}"))
            })?;
        }
        let path = canonicalize_credential_path(parsed_uri.path()).map_err(|reason| {
            SecretError::InvalidHttpRequest(format!("unsafe credential request path: {reason}"))
        })?;
        let mut headers = Vec::new();
        let mut host_authority = None;
        let mut body_length = None;
        for header in request.headers {
            let name = header.name;
            if !valid_header_name(name) || HttpHeaderValue::from_bytes(header.value).is_err() {
                return Err(SecretError::InvalidHttpRequest(
                    "malformed header in route-scoped request".into(),
                ));
            }
            let value = std::str::from_utf8(header.value)
                .map_err(|_| {
                    SecretError::InvalidHttpRequest("request header value is not UTF-8".into())
                })?
                .trim();
            if name.eq_ignore_ascii_case("host") {
                if host_authority.is_some() {
                    return Err(SecretError::InvalidHttpRequest(
                        "duplicate Host header in route-scoped request".into(),
                    ));
                }
                host_authority = Some(NormalizedAuthority::parse(
                    value,
                    default_port_for_scheme(scheme),
                )?);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(SecretError::InvalidHttpRequest(
                    "transfer-encoded request bodies are not supported".into(),
                ));
            }
            if name.eq_ignore_ascii_case("content-length") {
                if body_length.is_some() {
                    return Err(SecretError::InvalidHttpRequest(
                        "duplicate Content-Length headers are not supported".into(),
                    ));
                }
                body_length = Some(
                    crate::http_framing::parse_content_length(value.as_bytes())
                        .and_then(|length| usize::try_from(length).ok())
                        .ok_or_else(|| {
                            SecretError::InvalidHttpRequest("invalid Content-Length".into())
                        })?,
                );
            }
            headers.push((name.to_string(), value.to_string()));
        }
        let authority = host_authority.ok_or_else(|| {
            SecretError::InvalidHttpRequest("missing Host header in route-scoped request".into())
        })?;
        if let Some(target_authority) = request_target_authority(&parsed_uri, scheme)?
            && target_authority != authority
        {
            return Err(SecretError::InvalidHttpRequest(
                "request-target authority does not match Host header".into(),
            ));
        }

        Ok(Self {
            method: method.to_string(),
            uri: uri.to_string(),
            version: version.to_string(),
            path,
            authority,
            headers,
            body_length: body_length.unwrap_or(0),
        })
    }
}

fn validate_canonical_http_head(head: &[u8]) -> Result<(), SecretError> {
    if !head.ends_with(b"\r\n\r\n") {
        return Err(SecretError::InvalidHttpRequest(
            "request head must use canonical CRLF framing".into(),
        ));
    }
    for (index, byte) in head.iter().copied().enumerate() {
        match byte {
            b'\r' if head.get(index + 1) != Some(&b'\n') => {
                return Err(SecretError::InvalidHttpRequest(
                    "request head contains a bare carriage return".into(),
                ));
            }
            b'\n' if index == 0 || head[index - 1] != b'\r' => {
                return Err(SecretError::InvalidHttpRequest(
                    "request head contains a bare line feed".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

impl NormalizedAuthority {
    fn parse(value: &str, default_port: u16) -> Result<Self, SecretError> {
        let authority = value.parse::<Authority>().map_err(|_| {
            SecretError::InvalidHttpRequest(
                "malformed Host authority in route-scoped request".into(),
            )
        })?;
        Self::from_authority(&authority, default_port)
    }

    fn from_authority(authority: &Authority, default_port: u16) -> Result<Self, SecretError> {
        let text = authority.as_str();
        let has_port_delimiter = if text.starts_with('[') {
            text.rfind(']')
                .is_some_and(|end| text[end + 1..].starts_with(':'))
        } else {
            text.contains(':')
        };
        if text.contains('@') || (has_port_delimiter && authority.port_u16().is_none()) {
            return Err(SecretError::InvalidHttpRequest(
                "malformed authority in route-scoped request".into(),
            ));
        }
        Ok(Self {
            host: normalize_host(authority.host()),
            port: authority.port_u16().unwrap_or(default_port),
        })
    }
}

fn request_target_authority(
    uri: &Uri,
    connection_scheme: EndpointScheme,
) -> Result<Option<NormalizedAuthority>, SecretError> {
    let Some(authority) = uri.authority() else {
        return Ok(None);
    };
    let target_scheme = match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => EndpointScheme::Http,
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => EndpointScheme::Https,
        _ => {
            return Err(SecretError::InvalidHttpRequest(
                "unsupported absolute-form request scheme".into(),
            ));
        }
    };
    if target_scheme != connection_scheme {
        return Err(SecretError::InvalidHttpRequest(
            "request-target scheme does not match connection".into(),
        ));
    }
    Ok(Some(NormalizedAuthority::from_authority(
        authority,
        default_port_for_scheme(target_scheme),
    )?))
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

struct EndpointParts {
    scheme: EndpointScheme,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

fn header_injection(
    route: &InferenceRoute,
    env_name: &str,
) -> Result<HeaderInjection, SecretError> {
    validate_env_name(route, env_name)?;
    let provider = route.provider.as_deref().map(str::to_ascii_lowercase);
    if provider.as_deref() == Some("anthropic") {
        Ok(HeaderInjection {
            name: "x-api-key".into(),
            value: HeaderValue::RawEnv {
                env_name: env_name.into(),
            },
        })
    } else {
        Ok(HeaderInjection {
            name: "Authorization".into(),
            value: HeaderValue::BearerEnv {
                env_name: env_name.into(),
            },
        })
    }
}

fn validate_env_name(route: &InferenceRoute, env_name: &str) -> Result<(), SecretError> {
    let valid = !env_name.is_empty()
        && env_name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(SecretError::InvalidRoute {
            route: route.name.clone(),
            reason: format!(
                "api_key_env must be a non-empty uppercase environment variable name: {env_name}"
            ),
        })
    }
}

fn query_injections(
    route: &InferenceRoute,
    query: Option<&str>,
    resolver: &SecretResolver,
) -> Result<Vec<QueryInjection>, SecretError> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    let mut injections = Vec::new();
    for (name, value) in &pairs {
        if value.starts_with("axis:resolve:") {
            if let Some(env_name) = value.strip_prefix("axis:resolve:env:") {
                validate_env_name(route, env_name)?;
            }
            resolver
                .resolve(value)
                .map(|_| ())
                .or_else(|err| match err {
                    SecretError::EnvNotFound(_) | SecretError::Unresolved(_) => Ok(()),
                    other => Err(other),
                })?;
            injections.push(QueryInjection {
                name: name.as_ref().to_string(),
                placeholder: value.as_ref().to_string(),
            });
        }
    }
    if injections.iter().any(|query| query.name.is_empty()) {
        return Err(SecretError::InvalidRoute {
            route: route.name.clone(),
            reason: "query placeholder name must not be empty".into(),
        });
    }
    for injection in &injections {
        let occurrences = pairs
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(&injection.name))
            .count();
        if occurrences != 1 {
            return Err(SecretError::InvalidRoute {
                route: route.name.clone(),
                reason: format!(
                    "credential query parameter '{}' must have one unambiguous definition",
                    injection.name
                ),
            });
        }
    }
    Ok(injections)
}

fn parse_endpoint(endpoint: &str) -> Result<EndpointParts, String> {
    let endpoint = parse_credential_endpoint(endpoint).map_err(str::to_string)?;
    let scheme = match endpoint.scheme() {
        "http" => EndpointScheme::Http,
        "https" => EndpointScheme::Https,
        _ => return Err("credential endpoint must use http:// or https://".into()),
    };
    let host = endpoint
        .host_str()
        .ok_or_else(|| "credential endpoint must include a host".to_string())?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| "credential endpoint has no effective port".to_string())?;
    let path = canonicalize_credential_path(endpoint.path()).map_err(str::to_string)?;

    Ok(EndpointParts {
        scheme,
        host: normalize_host(host),
        port: Some(port),
        path,
        query: endpoint.query().map(str::to_string),
    })
}

fn provider_host(provider: &str) -> Option<&'static str> {
    match provider.to_ascii_lowercase().as_str() {
        "openai" => Some("api.openai.com"),
        "anthropic" => Some("api.anthropic.com"),
        _ => None,
    }
}

fn requires_inference_pattern(provider: Option<&str>, host: &str) -> bool {
    provider
        .map(|provider| {
            matches!(
                provider.to_ascii_lowercase().as_str(),
                "openai" | "anthropic"
            )
        })
        .unwrap_or(false)
        || matches!(
            host,
            "api.openai.com" | "api.anthropic.com" | "inference.local"
        )
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase())
}

impl EndpointScheme {
    fn from_tls(is_tls: bool) -> Self {
        if is_tls { Self::Https } else { Self::Http }
    }

    fn is_tls(self) -> bool {
        matches!(self, Self::Https)
    }
}

fn default_port_for_scheme(scheme: EndpointScheme) -> u16 {
    match scheme {
        EndpointScheme::Http => 80,
        EndpointScheme::Https => 443,
    }
}

fn non_root_path_prefix(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        None
    } else {
        Some(path.to_string())
    }
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

fn credential_path_prefixes_overlap(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (None, _) | (_, None) => true,
        (Some(left), Some(right)) => {
            path_matches_prefix(left, right) || path_matches_prefix(right, left)
        }
    }
}

fn rewrite_uri_query(uri: &str, query_values: &[(&str, String)]) -> Result<String, SecretError> {
    if query_values.is_empty() {
        return Ok(uri.to_string());
    }

    if uri.contains('#') {
        return Err(SecretError::InvalidHttpRequest(
            "request target must not contain a fragment".into(),
        ));
    }
    let (base, query) = uri
        .split_once('?')
        .map(|(base, query)| (base, Some(query)))
        .unwrap_or((uri, None));
    if let Some(query) = query {
        validate_url_percent_encoding(query).map_err(|reason| {
            SecretError::InvalidHttpRequest(format!("malformed request query: {reason}"))
        })?;
    }
    let existing = query
        .map(|query| url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>())
        .unwrap_or_default();
    for (inject_name, _) in query_values {
        let occurrences = existing
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(inject_name))
            .count();
        if occurrences > 1 {
            return Err(SecretError::InvalidHttpRequest(format!(
                "request contains ambiguous duplicate credential query parameter '{inject_name}'"
            )));
        }
    }

    let mut rewritten_pairs = Vec::new();
    for (name, value) in existing {
        if !query_values
            .iter()
            .any(|(inject_name, _)| name.eq_ignore_ascii_case(inject_name))
        {
            rewritten_pairs.push(format!(
                "{}={}",
                percent_encode_query_component(&name),
                percent_encode_query_component(&value)
            ));
        }
    }
    for (name, value) in query_values {
        rewritten_pairs.push(format!(
            "{}={}",
            percent_encode_query_component(name),
            percent_encode_query_component(value)
        ));
    }
    Ok(format!("{base}?{}", rewritten_pairs.join("&")))
}

fn percent_encode_query_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn policy(yaml: &str) -> Policy {
        Policy::from_yaml(yaml).unwrap()
    }

    fn unchecked_policy(yaml: &str) -> Policy {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn resolve_env_placeholder() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Set a test env var.
        unsafe {
            std::env::set_var("AXIS_TEST_KEY", "test-value-12345");
        }
        let resolver = SecretResolver::new();
        let val = resolver.resolve("axis:resolve:env:AXIS_TEST_KEY").unwrap();
        assert_eq!(val, "test-value-12345");
        unsafe {
            std::env::remove_var("AXIS_TEST_KEY");
        }
    }

    #[test]
    fn resolve_static_secret() {
        let mut resolver = SecretResolver::new();
        resolver.add_secret("my-api-key".into(), "secret-value".into());
        let val = resolver.resolve("axis:resolve:secret:my-api-key").unwrap();
        assert_eq!(val, "secret-value");
    }

    #[test]
    fn passthrough_non_placeholder() {
        let resolver = SecretResolver::new();
        let val = resolver.resolve("just-a-normal-value").unwrap();
        assert_eq!(val, "just-a-normal-value");
    }

    #[test]
    fn error_on_missing_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let resolver = SecretResolver::new();
        unsafe {
            std::env::remove_var("NONEXISTENT_VAR_12345");
        }
        let err = resolver
            .resolve("axis:resolve:env:NONEXISTENT_VAR_12345")
            .unwrap_err();
        assert!(matches!(err, SecretError::EnvNotFound(_)));
    }

    #[test]
    fn unsupported_placeholder_fails_closed() {
        let resolver = SecretResolver::new();
        let err = resolver
            .resolve("axis:resolve:file:/tmp/provider-key")
            .unwrap_err();
        assert!(matches!(err, SecretError::UnsupportedPlaceholder(_)));
    }

    #[test]
    fn api_key_env_injects_authorization_for_matching_inference_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_PROVIDER_KEY", "provider-secret");
        }
        let policy = policy(
            r#"
version: 1
name: inject-auth
inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_PROVIDER_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        for request in [
            "POST /v1/chat/completions HTTP/1.1",
            "POST /v1/completions HTTP/1.1",
            "POST /v1/responses HTTP/1.1",
            "POST /v1/embeddings HTTP/1.1",
            "GET /v1/models HTTP/1.1",
        ] {
            let head = format!(
                "{request}\r\nHost: inference.local\r\nAuthorization: Bearer sandbox-placeholder\r\n\r\n"
            );
            let rewritten = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .unwrap()
                .unwrap();
            let rewritten = String::from_utf8(rewritten).unwrap();

            assert!(rewritten.contains("Authorization: Bearer provider-secret\r\n"));
            assert!(!rewritten.contains("sandbox-placeholder"));
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_PROVIDER_KEY");
        }
    }

    #[test]
    fn request_authority_matches_case_and_default_or_explicit_port_forms() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_AUTHORITY_KEY", "authority-secret");
        }
        let policy = policy(
            r#"
version: 1
name: authority-forms
inference:
  routes:
    - name: local
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_AUTHORITY_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        for (connect_host, request_target, host) in [
            ("inference.local", "/v1/models", "inference.local"),
            ("INFERENCE.LOCAL", "/v1/models", "InFeReNcE.LoCaL"),
            ("inference.local", "/v1/models", "inference.local:80"),
            (
                "inference.local",
                "http://INFERENCE.LOCAL:80/v1/models",
                "inference.local",
            ),
        ] {
            let head = format!("GET {request_target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let rewritten = injector
                .rewrite_http_request_head(connect_host, 80, false, head.as_bytes())
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8(rewritten)
                    .unwrap()
                    .contains("Authorization: Bearer authority-secret\r\n"),
                "expected injection for CONNECT {connect_host}:80 and Host {host}"
            );
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_AUTHORITY_KEY");
        }
    }

    #[test]
    fn request_authority_rejects_mismatch_missing_duplicate_and_malformed_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_AUTHORITY_REJECT_KEY", "must-not-leak");
        }
        let policy = policy(
            r#"
version: 1
name: authority-rejections
inference:
  routes:
    - name: local
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_AUTHORITY_REJECT_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();
        let invalid_heads = [
            "GET /v1/models HTTP/1.1\r\nHost: other.local\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost: inference.local:81\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost: inference.local\r\nHost: inference.local\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost:\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost: inference.local:notaport\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost: inference.local:99999\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost : inference.local\r\n\r\n",
            "GET /v1/models HTTP/1.1\r\nHost: user@inference.local\r\n\r\n",
            "GET http://other.local/v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            "GET https://inference.local/v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
        ];

        for head in invalid_heads {
            let err = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .unwrap_err();
            assert!(
                matches!(err, SecretError::InvalidHttpRequest(_)),
                "{head:?}"
            );
            assert!(!err.to_string().contains("must-not-leak"));
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_AUTHORITY_REJECT_KEY");
        }
    }

    #[test]
    fn request_authority_requires_non_default_port_to_be_explicit() {
        let policy = policy(
            r#"
version: 1
name: custom-port-authority
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:9443"
      api_key_env: AXIS_TEST_UNUSED_AUTHORITY_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                9443,
                false,
                b"GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidHttpRequest(_)));

        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                9443,
                false,
                b"GET /v1/models HTTP/1.1\r\nHost: inference.local:9443\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::EnvNotFound(_)));
    }

    #[test]
    fn validated_policy_rejects_loopback_credential_routes() {
        for endpoint in ["http://127.0.0.1", "http://[::1]"] {
            let yaml = format!(
                r#"
version: 1
name: ip-authority
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: AXIS_TEST_IP_AUTHORITY_KEY
"#
            );
            assert!(Policy::from_yaml(&yaml).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn openai_style_api_key_injects_for_supported_local_paths() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_OPENAI_KEY", "openai-secret");
        }
        let policy = policy(
            r#"
version: 1
name: inject-openai
inference:
  routes:
    - name: openai
      provider: openai
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_OPENAI_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        for request in [
            "POST /v1/chat/completions HTTP/1.1",
            "POST /v1/completions HTTP/1.1",
            "POST /v1/responses HTTP/1.1",
            "POST /v1/embeddings HTTP/1.1",
            "GET /v1/models HTTP/1.1",
        ] {
            let head = format!("{request}\r\nHost: inference.local\r\n\r\n");
            let rewritten = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .unwrap()
                .unwrap();
            let rewritten = String::from_utf8(rewritten).unwrap();

            assert!(rewritten.contains("Authorization: Bearer openai-secret\r\n"));
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_OPENAI_KEY");
        }
    }

    #[test]
    fn api_key_env_does_not_inject_for_unmatched_host_or_path() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_OPENAI_KEY", "openai-secret");
        }
        let policy = policy(
            r#"
version: 1
name: inject-only-openai
inference:
  routes:
    - name: openai
      provider: openai
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_OPENAI_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        assert!(
            injector
                .rewrite_http_request_head(
                    "example.com",
                    443,
                    true,
                    b"POST /v1/chat/completions HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    80,
                    false,
                    b"GET /not-an-inference-route HTTP/1.1\r\nHost: inference.local\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    80,
                    false,
                    b"POST /v1/chat/completions-extra HTTP/1.1\r\nHost: inference.local\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"POST /v1/chat/completions/../files HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidHttpRequest(_)));
        unsafe {
            std::env::remove_var("AXIS_TEST_OPENAI_KEY");
        }
    }

    #[test]
    fn unresolved_api_key_env_fails_closed_without_secret_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AXIS_TEST_MISSING_KEY");
        }
        let policy = policy(
            r#"
version: 1
name: missing-key
inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_MISSING_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();

        assert!(
            matches!(err, SecretError::EnvNotFound(ref name) if name == "AXIS_TEST_MISSING_KEY")
        );
        assert!(!err.to_string().contains("provider-secret"));
    }

    #[test]
    fn endpoint_query_placeholder_rewrites_query_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_QUERY_KEY", "query secret+value");
        }
        let policy = policy(
            r#"
version: 1
name: inject-query
inference:
  routes:
    - name: query-provider
      endpoint: "http://inference.local/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_KEY"
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let rewritten = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"GET /v1/models?limit=10&api_key=sandbox-value HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();

        assert!(
            rewritten
                .starts_with("GET /v1/models?limit=10&api_key=query%20secret%2Bvalue HTTP/1.1\r\n")
        );
        assert!(!rewritten.contains("sandbox-value"));
        unsafe {
            std::env::remove_var("AXIS_TEST_QUERY_KEY");
        }
    }

    #[test]
    fn request_query_percent_encoding_is_strict_and_preserves_reserved_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_STRICT_QUERY_KEY", "query-secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: strict-request-query
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/v1?api_key=axis:resolve:env:AXIS_TEST_STRICT_QUERY_KEY"
"#,
        ))
        .unwrap();

        for query in [
            "value=%",
            "value=%GG",
            "valid=%2F&invalid=%G0",
            "valid=%2F%20ok&invalid=trailing%",
        ] {
            let request =
                format!("GET /v1/models?{query} HTTP/1.1\r\nHost: inference.local\r\n\r\n");
            let error = injector
                .rewrite_http_request_head("inference.local", 80, false, request.as_bytes())
                .unwrap_err();
            assert!(matches!(error, SecretError::InvalidHttpRequest(_)));
            assert!(error.to_string().contains("malformed request"));
            assert!(!error.to_string().contains("query-secret"));
        }

        let rewritten = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"GET /v1/models?literal=/root&encoded=%2froot&delimiter=one%26two&percent=%25&api_key=sandbox HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(rewritten.starts_with(
            "GET /v1/models?literal=%2Froot&encoded=%2Froot&delimiter=one%26two&percent=%25&api_key=query-secret HTTP/1.1\r\n"
        ));
        unsafe {
            std::env::remove_var("AXIS_TEST_STRICT_QUERY_KEY");
        }
    }

    #[test]
    fn local_http_injection_respects_scheme_port_and_path_prefix() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_SCOPED_KEY", "scoped-secret");
        }
        let policy = policy(
            r#"
version: 1
name: scoped-route
inference:
  routes:
    - name: scoped
      endpoint: "http://inference.local:9443/v1/chat"
      api_key_env: AXIS_TEST_SCOPED_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    9443,
                    true,
                    b"POST /v1/chat HTTP/1.1\r\nHost: inference.local\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "HTTP route must not inject into TLS traffic"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    443,
                    false,
                    b"POST /v1/chat HTTP/1.1\r\nHost: inference.local\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route must not inject on a different port"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    9443,
                    false,
                    b"POST /v2/chat HTTP/1.1\r\nHost: inference.local:9443\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route must not inject outside endpoint path prefix"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "inference.local",
                    9443,
                    false,
                    b"POST /v1/chatty HTTP/1.1\r\nHost: inference.local:9443\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route prefix must stop at a path segment boundary"
        );
        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                9443,
                false,
                b"POST /v1/chat/../models HTTP/1.1\r\nHost: inference.local:9443\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidHttpRequest(_)));

        let rewritten = injector
            .rewrite_http_request_head(
                "inference.local",
                9443,
                false,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:9443\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(rewritten.contains("Authorization: Bearer scoped-secret\r\n"));
        unsafe {
            std::env::remove_var("AXIS_TEST_SCOPED_KEY");
        }
    }

    #[test]
    fn credential_injection_rejects_ambiguous_and_unsafe_paths() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_PATH_KEY", "path-secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: path-safety
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/v1/models"
      api_key_env: AXIS_TEST_PATH_KEY
"#,
        ))
        .unwrap();

        for target in [
            "/v1/chat/../admin",
            "/v1/chat/./admin",
            "/v1/chat/%2e%2e/admin",
            "/v1/chat/%2E%2E/admin",
            "/v1/chat/.%2e/admin",
            "/v1/chat/%2e./admin",
            "/v1/chat%5c..%5cadmin",
            "/v1/chat\\..\\admin",
            "/v1/chat/%",
            "/v1/chat/%2",
            "/v1/chat/%GG",
            "/v1/chat/%252e%252e/admin",
            "/v1/chat/%00admin",
            "http://inference.local/v1/chat/%2e%2e/admin",
        ] {
            let head = format!("GET {target} HTTP/1.1\r\nHost: inference.local\r\n\r\n");
            let err = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .expect_err(target);
            assert!(
                matches!(err, SecretError::InvalidHttpRequest(_)),
                "unexpected error for {target}: {err}"
            );
            assert!(!err.to_string().contains("path-secret"));
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_PATH_KEY");
        }
    }

    #[test]
    fn encoded_reserved_separators_do_not_cross_credential_scope_boundaries() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_PATH_BOUNDARY_KEY", "boundary-secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: encoded-separator-boundary
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/v1/chat"
      api_key_env: AXIS_TEST_PATH_BOUNDARY_KEY
"#,
        ))
        .unwrap();

        for target in ["/v1/chat%2Fadmin", "/v1/chat%2f..%2fadmin"] {
            let head = format!("GET {target} HTTP/1.1\r\nHost: inference.local\r\n\r\n");
            assert_eq!(
                injector
                    .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                    .unwrap(),
                None,
                "encoded separators must remain within their URL segment: {target}"
            );
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_PATH_BOUNDARY_KEY");
        }
    }

    #[test]
    fn credential_injection_accepts_unambiguous_percent_encoding() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_SAFE_PATH_KEY", "safe-path-secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: safe-path-encoding
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/v1/models"
      api_key_env: AXIS_TEST_SAFE_PATH_KEY
"#,
        ))
        .unwrap();

        for target in [
            "/v1/models/model%20name",
            "/v1/models/file%2Ejson",
            "/v1/models/%7Euser",
            "/v1/models/model?next=%2Fadmin",
        ] {
            let head = format!("GET {target} HTTP/1.1\r\nHost: inference.local\r\n\r\n");
            let rewritten = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8(rewritten)
                    .unwrap()
                    .contains("Authorization: Bearer safe-path-secret\r\n"),
                "expected injection for {target}"
            );
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_SAFE_PATH_KEY");
        }
    }

    #[test]
    fn credential_scope_matching_decodes_percent_encoded_unreserved_bytes() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_CANONICAL_PATH_KEY", "canonical-secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: canonical-path-matching
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/%76%31/models"
      api_key_env: AXIS_TEST_CANONICAL_PATH_KEY
"#,
        ))
        .unwrap();

        for target in ["/v1/models", "/%76%31/models", "/%76%31/models/%7euser"] {
            let head = format!("GET {target} HTTP/1.1\r\nHost: inference.local\r\n\r\n");
            let rewritten = injector
                .rewrite_http_request_head("inference.local", 80, false, head.as_bytes())
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8(rewritten)
                    .unwrap()
                    .contains("Authorization: Bearer canonical-secret\r\n"),
                "expected canonical scope match for {target}"
            );
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_CANONICAL_PATH_KEY");
        }
    }

    #[test]
    fn unsafe_credential_path_prefixes_reject_policy() {
        for endpoint in [
            "http://inference.local/v1/../admin",
            "http://inference.local/v1/%2e%2e/admin",
            "http://inference.local/v1/%",
            "http://inference.local/v1/%252e%252e/admin",
        ] {
            let yaml = format!(
                r#"
version: 1
name: unsafe-prefix
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: AXIS_TEST_UNUSED_PATH_KEY
"#
            );
            let err = match CredentialInjector::from_policy(&unchecked_policy(&yaml)) {
                Ok(_) => panic!("expected unsafe endpoint to reject policy: {endpoint}"),
                Err(err) => err,
            };
            assert!(
                matches!(err, SecretError::InvalidRoute { .. }),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn injected_header_values_reject_ascii_controls() {
        let _lock = ENV_LOCK.lock().unwrap();
        let injections = [
            HeaderInjection {
                name: "Authorization".into(),
                value: HeaderValue::BearerEnv {
                    env_name: "AXIS_TEST_HEADER_VALUE".into(),
                },
            },
            HeaderInjection {
                name: "x-api-key".into(),
                value: HeaderValue::RawEnv {
                    env_name: "AXIS_TEST_HEADER_VALUE".into(),
                },
            },
        ];

        for value in [
            "before\rafter",
            "before\nafter",
            "before\tafter",
            "before\u{1f}after",
            "before\u{7f}after",
        ] {
            unsafe {
                std::env::set_var("AXIS_TEST_HEADER_VALUE", value);
            }
            for injection in &injections {
                let err = injection.resolve(&SecretResolver::new()).unwrap_err();
                assert!(matches!(err, SecretError::InvalidHeaderValue(_)));
                assert!(!err.to_string().contains(value));
            }
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_HEADER_VALUE");
        }
    }

    #[test]
    fn invalid_environment_header_never_reaches_rewritten_bytes() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(
                "AXIS_TEST_INJECTED_HEADER",
                "safe-prefix\r\nX-Injected: attacker-controlled",
            );
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: invalid-header
inference:
  routes:
    - name: local
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_INJECTED_HEADER
"#,
        ))
        .unwrap();

        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidHeaderValue(_)));
        assert!(!err.to_string().contains("attacker-controlled"));
        unsafe {
            std::env::remove_var("AXIS_TEST_INJECTED_HEADER");
        }
    }

    #[test]
    fn noncanonical_http_framing_is_rejected_before_injection() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_LF_KEY", "lf-secret");
        }
        let policy = policy(
            r#"
version: 1
name: lf-route
inference:
  routes:
    - name: lf
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_LF_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        for head in [
            b"POST /v1/chat/completions HTTP/1.1\nHost: inference.local\n\n".as_slice(),
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\rX-Hidden: yes\r\n\r\n"
                .as_slice(),
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\n\r\n".as_slice(),
        ] {
            let err = injector
                .rewrite_http_request_head("inference.local", 80, false, head)
                .unwrap_err();
            assert!(matches!(err, SecretError::InvalidHttpRequest(_)));
            assert!(!err.to_string().contains("lf-secret"));
        }
        unsafe {
            std::env::remove_var("AXIS_TEST_LF_KEY");
        }
    }

    #[test]
    fn strict_http_parser_returns_one_unambiguous_body_length() {
        let parsed = ParsedHttpHead::parse(
            b"POST / HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 12\r\n\r\n",
            EndpointScheme::Http,
        )
        .unwrap();
        assert_eq!(parsed.body_length, 12);

        for head in [
            b"POST / HTTP/1.1\r\nHost: inference.local\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: inference.local\r\nContent-Length: nope\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.0\r\nHost: inference.local\r\n\r\n".as_slice(),
        ] {
            assert!(ParsedHttpHead::parse(head, EndpointScheme::Http).is_err());
        }
    }

    #[test]
    fn strict_http_parser_content_length_table_is_fail_closed() {
        for (value, expected) in [
            ("0", Some(0)),
            ("00012", Some(12)),
            ("12", Some(12)),
            ("", None),
            ("+1", None),
            ("-1", None),
            ("0x10", None),
            ("1, 1", None),
            ("1_0", None),
            ("184467440737095516161844674407370955161", None),
        ] {
            let head = format!(
                "POST / HTTP/1.1\r\nHost: inference.local\r\nContent-Length: {value}\r\n\r\n"
            );
            match expected {
                Some(length) => assert_eq!(
                    ParsedHttpHead::parse(head.as_bytes(), EndpointScheme::Http)
                        .unwrap()
                        .body_length,
                    length,
                    "{value:?}"
                ),
                None => assert!(
                    ParsedHttpHead::parse(head.as_bytes(), EndpointScheme::Http).is_err(),
                    "{value:?}"
                ),
            }
        }
    }

    #[test]
    fn strict_http_parser_rejects_header_overflow_partial_body_and_pipelining() {
        let mut too_many_headers = b"GET / HTTP/1.1\r\nHost: inference.local\r\n".to_vec();
        for index in 0..128 {
            too_many_headers.extend_from_slice(format!("x-{index}: value\r\n").as_bytes());
        }
        too_many_headers.extend_from_slice(b"\r\n");

        for bytes in [
            too_many_headers,
            b"POST / HTTP/1.1\r\nHost: inference.local\r\nContent-Length: 3\r\n\r\na".to_vec(),
            b"GET / HTTP/1.1\r\nHost: inference.local\r\n\r\nGET /second HTTP/1.1\r\nHost: inference.local\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: inference.local\r\n".to_vec(),
        ] {
            assert!(
                ParsedHttpHead::parse(&bytes, EndpointScheme::Http).is_err(),
                "unexpectedly accepted {bytes:?}"
            );
        }
    }

    #[test]
    fn injector_rejects_overlapping_routes_independent_of_policy_order() {
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
    - name: lower
      endpoint: http://inference.local/v1%2fchat
      api_key_env: LOWER_KEY
    - name: upper
      endpoint: http://inference.local/v1%2Fchat
      api_key_env: UPPER_KEY
"#,
            r#"
    - name: lower-unreserved
      endpoint: http://inference.local/v1/%7euser
      api_key_env: LOWER_KEY
    - name: upper-unreserved
      endpoint: http://inference.local/v1/%7Euser
      api_key_env: UPPER_KEY
"#,
        ] {
            let yaml = format!("version: 1\nname: overlap\ninference:\n  routes:{routes}");
            let policy = unchecked_policy(&yaml);
            let error = match CredentialInjector::from_policy(&policy) {
                Ok(_) => panic!("expected overlapping routes to fail"),
                Err(error) => error,
            };
            assert!(matches!(error, SecretError::InvalidRoute { .. }));
            assert!(error.to_string().contains("credential scopes overlap"));
        }
    }

    #[test]
    fn runtime_rejects_fragmented_and_malformed_credential_endpoints() {
        for endpoint in [
            "http://inference.local/v1#fragment?key=axis:resolve:env:LOCAL_KEY",
            "http://inference.local/v1?key=axis:resolve:env:LOCAL_KEY#fragment",
            "http://inference.local/v%7?key=axis:resolve:env:LOCAL_KEY",
            "http://inference.local/v1?key=%GG&other=axis:resolve:env:LOCAL_KEY",
        ] {
            let yaml = format!(
                r#"
version: 1
name: invalid-runtime-endpoint
inference:
  routes:
    - name: local
      endpoint: "{endpoint}"
      api_key_env: LOCAL_KEY
"#
            );
            let error = match CredentialInjector::from_policy(&unchecked_policy(&yaml)) {
                Ok(_) => panic!("expected endpoint to fail: {endpoint}"),
                Err(error) => error,
            };
            assert!(matches!(error, SecretError::InvalidRoute { .. }));
        }
    }

    #[test]
    fn unsupported_endpoint_query_placeholder_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-placeholder
inference:
  routes:
    - name: query-provider
      endpoint: "http://inference.local/v1?api_key=axis:resolve:file:/tmp/key"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unsupported placeholder to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::UnsupportedPlaceholder(_)));
    }

    #[test]
    fn normalized_duplicate_credential_query_names_are_rejected() {
        let policy = unchecked_policy(
            r#"
version: 1
name: ambiguous-query-name
inference:
  routes:
    - name: query-provider
      endpoint: "http://inference.local/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_KEY&api%5Fkey=shadow"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected ambiguous query name to reject policy"),
            Err(err) => err,
        };
        assert!(matches!(err, SecretError::InvalidRoute { .. }));
        assert!(err.to_string().contains("one unambiguous definition"));
    }

    #[test]
    fn normalized_duplicate_request_query_names_fail_closed() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_QUERY_DUPLICATE", "secret");
        }
        let injector = CredentialInjector::from_policy(&policy(
            r#"
version: 1
name: inject-query
inference:
  routes:
    - name: local
      endpoint: "http://inference.local/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_DUPLICATE"
"#,
        ))
        .unwrap();
        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"GET /v1/models?api_key=one&api%5Fkey=two HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();
        assert!(matches!(err, SecretError::InvalidHttpRequest(_)));
        assert!(err.to_string().contains("ambiguous duplicate"));
        unsafe {
            std::env::remove_var("AXIS_TEST_QUERY_DUPLICATE");
        }
    }

    #[test]
    fn unparseable_endpoint_with_placeholder_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-endpoint-placeholder
inference:
  routes:
    - name: query-provider
      endpoint: "provider.example/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_KEY"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unparseable credential endpoint to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn unparseable_endpoint_with_api_key_env_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-api-key-endpoint
inference:
  routes:
    - name: provider
      provider: openai
      endpoint: "ftp://api.openai.com/v1"
      api_key_env: OPENAI_API_KEY
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unparseable credential endpoint to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn malformed_endpoint_port_with_api_key_env_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-api-key-port
inference:
  routes:
    - name: provider
      endpoint: "http://provider.example:notaport/v1"
      api_key_env: OPENAI_API_KEY
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected malformed credential endpoint port to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn invalid_endpoint_query_env_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-query-env
inference:
  routes:
    - name: query-provider
      endpoint: "http://inference.local/v1?api_key=axis:resolve:env:not-valid"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected invalid query env placeholder to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn invalid_api_key_env_rejects_policy() {
        let policy = unchecked_policy(
            r#"
version: 1
name: bad-env
inference:
  routes:
    - name: query-provider
      endpoint: "http://inference.local"
      api_key_env: "not-valid"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected invalid api_key_env to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }
}
