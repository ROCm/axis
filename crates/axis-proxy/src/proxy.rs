// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP proxy with per-connection OPA policy evaluation.
//!
//! Each sandbox gets its own proxy instance. A connection carries either a
//! CONNECT request, which opens a tunnel, or one absolute-form `http://`
//! request, which the proxy forwards (`proxy/forward.rs`). For both:
//! 1. Parse target host:port
//! 2. Resolve calling binary only when required by binary-restricted policy
//! 3. Evaluate OPA network policy → allow or deny
//! 4. If allowed, relay bytes; optionally run leak detection
//! 5. Log decision via OCSF audit

use axis_core::audit::AuditLog;
use axis_core::connect_attribution::{
    ConnectAttributionError, ConnectAttributionRecord, ConnectAttributionStore,
    policy_requires_connect_attribution,
};
use axis_core::opa::PolicyEngine;
use axis_core::policy::{ExhaustAction, Policy, TokenBudget};
use axis_core::types::{NetworkAction, SandboxId};
use axis_safety::leak_detect::LeakDetector;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::net::TcpListener;
#[cfg(target_os = "linux")]
use tokio::net::TcpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::identity::{BinaryFingerprint, IdentityError, TofuStore};
use crate::process_peer::SandboxProcessPeer;
use crate::secrets::CredentialInjector;

mod forward;

const MAX_HTTP_HEAD_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADERS: usize = 100;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
const CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_ATTRIBUTION_WAIT: std::time::Duration = std::time::Duration::from_millis(250);
const CONNECT_ATTRIBUTION_RETRY: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to bind proxy: {0}")]
    BindFailed(String),

    #[error("connection error: {0}")]
    ConnectionError(String),

    /// The peer sent an HTTP head that is not canonical HTTP/1.1 framing. The
    /// proxy answers `400` before it evaluates policy.
    #[error("malformed HTTP head: {0}")]
    MalformedHead(String),

    #[error("policy denied connection to {host}:{port}: {reason}")]
    PolicyDenied {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for an AXIS proxy instance.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub sandbox_id: SandboxId,
    pub bind_addr: SocketAddr,
    pub policy: Policy,
    pub enable_leak_detection: bool,
    /// Local inference server endpoint for `inference.local` virtual host.
    /// When set, CONNECT requests to `inference.local` are routed here
    /// instead of the real internet.
    pub inference_endpoint: Option<SocketAddr>,
    /// Connect-time identity records produced by a platform-specific sandbox
    /// launcher. Policies with binary allowlists require this hard boundary.
    pub connect_attribution: Option<ConnectAttributionStore>,
    /// Opt into best-effort identity diagnostics for policies that do not
    /// require binary identity. Diagnostic identity never feeds OPA decisions.
    pub enable_identity_diagnostics: bool,
    /// Optional benchmark timing channel. Normal runtime paths leave this unset.
    pub timing_tx: Option<mpsc::UnboundedSender<ProxyTimingEvent>>,
    /// Linux only: serve every client of a loopback listener. Tests and
    /// benchmarks set this. Otherwise a loopback listener serves only the
    /// processes of the sandbox registered on `AxisProxy::sandbox_process_peer`.
    pub unauthenticated_loopback: bool,
}

/// Per-connection proxy timing emitted only when `ProxyConfig::timing_tx` is set.
#[derive(Debug, Clone)]
pub struct ProxyTimingEvent {
    pub outcome: ProxyTimingOutcome,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub phases: Vec<ProxyTimingPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTimingOutcome {
    Allowed,
    Denied,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTimingPhase {
    pub phase: &'static str,
    pub duration: Duration,
}

struct ProxyConnectionTimer {
    start: Instant,
    phases: Vec<ProxyTimingPhase>,
}

impl ProxyConnectionTimer {
    fn start() -> Self {
        Self {
            start: Instant::now(),
            phases: Vec::new(),
        }
    }

    fn record(&mut self, phase: &'static str, duration: Duration) {
        self.phases.push(ProxyTimingPhase { phase, duration });
    }

    fn finish(
        mut self,
        outcome: ProxyTimingOutcome,
        target_host: Option<String>,
        target_port: Option<u16>,
        timing_tx: &Option<mpsc::UnboundedSender<ProxyTimingEvent>>,
    ) {
        self.record("total", self.start.elapsed());
        if let Some(tx) = timing_tx {
            let _ = tx.send(ProxyTimingEvent {
                outcome,
                target_host,
                target_port,
                phases: self.phases,
            });
        }
    }
}

/// Shared state for the proxy, protected by a Mutex for thread-safe access.
struct ProxyState {
    policy_engine: PolicyEngine,
    tofu_store: TofuStore,
    audit_log: AuditLog,
    leak_detector: Option<LeakDetector>,
    credential_injector: CredentialInjector,
    connect_attribution: Option<ConnectAttributionStore>,
    identity_mode: ProxyIdentityMode,
    inference_budget: Option<InferenceBudget>,
}

struct InferenceBudget {
    config: TokenBudget,
    reserved_tokens: u64,
    window_start: Instant,
    hosts: HashSet<String>,
}

impl InferenceBudget {
    fn new(config: TokenBudget, hosts: HashSet<String>) -> Result<Self, ProxyError> {
        if !matches!(config.action_on_exhaust, ExhaustAction::Reject) {
            return Err(ProxyError::BindFailed(
                "inference token budgets currently support only action_on_exhaust: reject; queue and fallback require a trusted request scheduler"
                    .into(),
            ));
        }
        if config.max_tokens_per_hour == 0 || config.max_tokens_per_request == 0 {
            return Err(ProxyError::BindFailed(
                "inference token budget limits must be greater than zero".into(),
            ));
        }
        Ok(Self {
            config,
            reserved_tokens: 0,
            window_start: Instant::now(),
            hosts,
        })
    }

    fn applies_to(&self, hostname: &str) -> bool {
        self.hosts.contains(&hostname.to_ascii_lowercase())
    }

    fn reserve(&mut self, request_body: &[u8]) -> Result<u64, String> {
        if self.window_start.elapsed() >= Duration::from_secs(3600) {
            self.reserved_tokens = 0;
            self.window_start = Instant::now();
        }
        let input_upper_bound = request_body.len() as u64;
        let declared_output = declared_output_tokens(request_body)?.ok_or_else(|| {
            "token-budgeted requests must declare max_tokens, max_completion_tokens, or max_output_tokens"
                .to_string()
        })?;
        let requested = input_upper_bound.saturating_add(declared_output);
        if requested > self.config.max_tokens_per_request {
            return Err(format!(
                "request reserves {requested} tokens, exceeding per-request limit {}",
                self.config.max_tokens_per_request
            ));
        }
        if self.reserved_tokens.saturating_add(requested) > self.config.max_tokens_per_hour {
            return Err(format!(
                "hourly token budget exhausted: {} reserved, {requested} requested, {} allowed",
                self.reserved_tokens, self.config.max_tokens_per_hour
            ));
        }
        self.reserved_tokens = self.reserved_tokens.saturating_add(requested);
        Ok(requested)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyIdentityMode {
    /// Host/port-only policy evaluation. Do not spend request-path time on
    /// identity because it cannot influence the decision.
    None,
    /// Binary-restricted policies require kernel-observed connect-time
    /// attribution. Unknown, stale, ambiguous, or reconstructed identity must
    /// fail closed before OPA can allow the request.
    RequiredConnectAttribution,
    /// Best-effort diagnostics for non-binary policy surfaces. This mode must
    /// not feed OPA decisions or wait for attribution records.
    OptionalBestEffort,
}

/// An AXIS HTTP proxy serving a single sandbox.
pub struct AxisProxy {
    config: ProxyConfig,
    listener: Option<TcpListener>,
    state: Arc<Mutex<ProxyState>>,
    process_peer: Option<SandboxProcessPeer>,
}

impl AxisProxy {
    /// Create a new proxy with OPA policy evaluation.
    pub fn new(config: ProxyConfig) -> Result<Self, ProxyError> {
        config
            .policy
            .validate()
            .map_err(|error| ProxyError::BindFailed(format!("invalid policy: {error}")))?;
        // Initialize the OPA policy engine with the sandbox policy.
        let mut policy_engine = PolicyEngine::new()
            .map_err(|e| ProxyError::BindFailed(format!("OPA engine init: {e}")))?;
        policy_engine
            .load_policy(&config.policy)
            .map_err(|e| ProxyError::BindFailed(format!("OPA policy load: {e}")))?;

        // Initialize leak detector if enabled.
        let leak_detector = if config.enable_leak_detection {
            Some(
                LeakDetector::new()
                    .map_err(|e| ProxyError::BindFailed(format!("leak detector: {e}")))?,
            )
        } else {
            None
        };

        let credential_injector = CredentialInjector::from_policy(&config.policy)
            .map_err(|e| ProxyError::BindFailed(format!("credential injection: {e}")))?;
        let identity_mode = proxy_identity_mode(&config.policy, config.enable_identity_diagnostics);
        let inference_hosts = inference_route_hosts(&config.policy);
        let inference_budget = config
            .policy
            .inference
            .token_budget
            .clone()
            .map(|budget| InferenceBudget::new(budget, inference_hosts))
            .transpose()?;

        let state = Arc::new(Mutex::new(ProxyState {
            policy_engine,
            tofu_store: TofuStore::new(),
            audit_log: AuditLog::new(),
            leak_detector,
            credential_injector,
            connect_attribution: config.connect_attribution.clone(),
            identity_mode,
            inference_budget,
        }));

        let process_peer = (cfg!(target_os = "linux")
            && config.bind_addr.ip().is_loopback()
            && !config.unauthenticated_loopback)
            .then(SandboxProcessPeer::default);
        Ok(Self {
            config,
            listener: None,
            state,
            process_peer,
        })
    }

    /// Set when this proxy serves only the processes of one sandbox. The
    /// launcher registers that sandbox here once it has started; until then
    /// every client is refused.
    pub fn sandbox_process_peer(&self) -> Option<SandboxProcessPeer> {
        self.process_peer.clone()
    }

    /// Start listening for proxy connections.
    pub async fn bind(&mut self) -> Result<SocketAddr, ProxyError> {
        let listener = bind_proxy_listener(self.config.bind_addr).await?;

        let addr = listener.local_addr()?;
        strict_proxy_expected_peer(addr)?;
        tracing::info!(
            "proxy for sandbox {} listening on {addr}",
            self.config.sandbox_id,
        );
        self.listener = Some(listener);
        Ok(addr)
    }

    /// Run the proxy accept loop. Blocks until shutdown.
    pub async fn run(&self) -> Result<(), ProxyError> {
        self.run_with_limits(MAX_CONCURRENT_CONNECTIONS, CONNECT_HEADER_TIMEOUT)
            .await
    }

    async fn run_with_limits(
        &self,
        max_concurrent_connections: usize,
        connect_header_timeout: Duration,
    ) -> Result<(), ProxyError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| ProxyError::BindFailed("not bound".into()))?;

        let connection_slots = Arc::new(Semaphore::new(max_concurrent_connections));
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let permit = match reserve_connection(&connection_slots) {
                Some(permit) => permit,
                None => {
                    tracing::warn!(
                        "proxy for sandbox {} reached its concurrent connection limit",
                        self.config.sandbox_id
                    );
                    drop(stream);
                    continue;
                }
            };
            let proxy_addr = stream.local_addr()?;
            let expected_peer_ip = strict_proxy_expected_peer(proxy_addr)?;
            let context = ProxyConnectionContext {
                sandbox_id: self.config.sandbox_id,
                proxy_addr,
                expected_peer_ip,
                process_peer: self.process_peer.clone(),
                state: Arc::clone(&self.state),
                inference_endpoint: self.config.inference_endpoint,
                timing_tx: self.config.timing_tx.clone(),
                connect_header_timeout,
            };

            tokio::spawn(async move {
                let _permit = permit;
                let sandbox_id = context.sandbox_id;
                if let Err(e) = handle_connection(stream, peer_addr, context).await {
                    tracing::warn!("sandbox {sandbox_id}: connection from {peer_addr} failed: {e}");
                }
            });
        }
    }
}

fn reserve_connection(slots: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(slots).try_acquire_owned().ok()
}

struct ProxyConnectionContext {
    sandbox_id: SandboxId,
    proxy_addr: SocketAddr,
    expected_peer_ip: Option<IpAddr>,
    process_peer: Option<SandboxProcessPeer>,
    state: Arc<Mutex<ProxyState>>,
    inference_endpoint: Option<SocketAddr>,
    timing_tx: Option<mpsc::UnboundedSender<ProxyTimingEvent>>,
    connect_header_timeout: Duration,
}

fn proxy_identity_mode(policy: &Policy, enable_identity_diagnostics: bool) -> ProxyIdentityMode {
    if policy_requires_connect_attribution(policy) {
        ProxyIdentityMode::RequiredConnectAttribution
    } else if enable_identity_diagnostics {
        ProxyIdentityMode::OptionalBestEffort
    } else {
        ProxyIdentityMode::None
    }
}

/// Linux strict proxies bind the host endpoint of the allocator's per-sandbox
/// `/30`. The adjacent address is the only source assigned to the sandbox.
/// Loopback listeners carry no source-address claim; they authenticate
/// clients as sandbox processes instead (`AxisProxy::sandbox_process_peer`).
/// Non-Linux callers receive no peer-authentication claim from this transport;
/// their containment layer must establish an independent boundary. Wildcard
/// and arbitrary non-loopback Linux binds fail closed.
fn strict_proxy_expected_peer(proxy_addr: SocketAddr) -> Result<Option<IpAddr>, ProxyError> {
    #[cfg(target_os = "linux")]
    {
        let IpAddr::V4(proxy_ip) = proxy_addr.ip() else {
            if proxy_addr.ip().is_loopback() {
                return Ok(None);
            }
            return Err(ProxyError::BindFailed(
                "strict proxy listeners require the Linux IPv4 netns allocation".into(),
            ));
        };
        if proxy_ip.is_loopback() {
            return Ok(None);
        }

        let host_bits = u32::from(proxy_ip);
        if proxy_ip.octets()[0] != 10 || (host_bits & 0b11) != 1 {
            return Err(ProxyError::BindFailed(format!(
                "strict proxy address {proxy_ip} is not a Linux sandbox host-veth address"
            )));
        }
        Ok(Some(IpAddr::V4(Ipv4Addr::from(host_bits + 1))))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = proxy_addr;
        Ok(None)
    }
}

fn authenticate_proxy_peer(
    expected_peer_ip: Option<IpAddr>,
    peer_addr: SocketAddr,
) -> Result<(), ProxyError> {
    if let Some(expected) = expected_peer_ip
        && peer_addr.ip() != expected
    {
        return Err(ProxyError::ConnectionError(format!(
            "unauthenticated proxy peer {} (expected sandbox source {expected})",
            peer_addr.ip()
        )));
    }
    Ok(())
}

async fn bind_proxy_listener(bind_addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    #[cfg(target_os = "linux")]
    {
        if linux_proxy_bind_requires_freebind(bind_addr) {
            return bind_linux_freebind_listener(bind_addr);
        }
    }

    TcpListener::bind(bind_addr)
        .await
        .map_err(|e| ProxyError::BindFailed(e.to_string()))
}

#[cfg(target_os = "linux")]
fn linux_proxy_bind_requires_freebind(bind_addr: SocketAddr) -> bool {
    match bind_addr.ip() {
        std::net::IpAddr::V4(addr) => !addr.is_loopback() && !addr.is_unspecified(),
        std::net::IpAddr::V6(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn bind_linux_freebind_listener(bind_addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    let socket = match bind_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .set_reuseaddr(true)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    set_ip_freebind(socket.as_raw_fd()).map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .bind(bind_addr)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
    socket
        .listen(1024)
        .map_err(|e| ProxyError::BindFailed(e.to_string()))
}

#[cfg(target_os = "linux")]
fn set_ip_freebind(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let enabled: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_FREEBIND,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Handle a single proxy connection with full policy evaluation.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    context: ProxyConnectionContext,
) -> Result<(), ProxyError> {
    use tokio::io::{AsyncWriteExt, BufReader};

    let ProxyConnectionContext {
        sandbox_id,
        proxy_addr,
        expected_peer_ip,
        process_peer,
        state,
        inference_endpoint,
        timing_tx,
        connect_header_timeout,
    } = context;
    let mut timing = ProxyConnectionTimer::start();
    let mut peer_check = authenticate_proxy_peer(expected_peer_ip, peer_addr);
    if peer_check.is_ok()
        && let Some(process_peer) = process_peer
    {
        peer_check =
            tokio::task::spawn_blocking(move || process_peer.verify(peer_addr, proxy_addr))
                .await
                .unwrap_or_else(|error| Err(error.to_string()))
                .map_err(ProxyError::ConnectionError);
    }
    if let Err(error) = peer_check {
        tracing::warn!("sandbox {sandbox_id}: rejecting proxy peer {peer_addr}: {error}");
        send_forbidden_response(
            &mut stream,
            "AXIS policy denied connection\r\nReason: unauthenticated sandbox peer\r\n",
        )
        .await?;
        timing.finish(ProxyTimingOutcome::Error, None, None, &timing_tx);
        return Ok(());
    }
    let identity_mode = {
        let st = state.lock().unwrap();
        st.identity_mode
    };
    let (binary_path, binary_sha256) = if identity_mode == ProxyIdentityMode::None {
        timing.record("identity_attribution", Duration::ZERO);
        ("unknown".into(), "unknown".into())
    } else {
        let phase_start = Instant::now();
        let binary_identity =
            resolve_policy_binary_identity(sandbox_id, peer_addr, proxy_addr, &state).await;
        timing.record("identity_attribution", phase_start.elapsed());
        match binary_identity {
            Ok(identity) => identity,
            Err(e) => {
                tracing::warn!("sandbox {sandbox_id}: binary identity check failed: {e}");
                send_forbidden_response(
                    &mut stream,
                    "AXIS policy denied connection\r\nReason: binary identity check failed\r\n",
                )
                .await?;
                timing.finish(ProxyTimingOutcome::Error, None, None, &timing_tx);
                return Ok(());
            }
        }
    };

    let mut reader = BufReader::new(stream);

    // 1. Read and validate one canonical request head: a CONNECT, or one
    //    absolute-form http:// request to forward.
    let phase_start = Instant::now();
    let request_head = match read_request_head(&mut reader, connect_header_timeout).await {
        Ok(head) => head,
        Err(ProxyError::MalformedHead(reason)) => {
            // Not canonical framing, so no policy has seen it. Tell the client,
            // unless it has already gone.
            timing.record("request_parse", phase_start.elapsed());
            tracing::info!(
                "sandbox {sandbox_id}: rejected proxy request from {peer_addr}: {reason}"
            );
            let body = format!("AXIS proxy rejected the request\r\nReason: {reason}\r\n");
            let _ = send_error_response(reader.get_mut(), "400 Bad Request", &body).await;
            timing.finish(ProxyTimingOutcome::Error, None, None, &timing_tx);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let (host, port, forward_request) = if is_connect_request_head(&request_head) {
        let (host, port) = parse_connect_request_head(&request_head)?;
        (host, port, None)
    } else {
        match forward::parse_forward_request_head(&request_head) {
            Ok(request) => (request.host.clone(), request.port, Some(request)),
            Err(rejection) => {
                timing.record("request_parse", phase_start.elapsed());
                tracing::info!(
                    "sandbox {sandbox_id}: rejected proxy request from {peer_addr}: {}",
                    rejection.reason
                );
                let body = format!(
                    "AXIS proxy rejected the request\r\nReason: {}\r\n",
                    rejection.reason
                );
                send_error_response(reader.get_mut(), rejection.status, &body).await?;
                timing.finish(ProxyTimingOutcome::Error, None, None, &timing_tx);
                return Ok(());
            }
        }
    };

    let method = forward_request
        .as_ref()
        .map_or("CONNECT", |request| request.method.as_str());
    tracing::debug!("sandbox {sandbox_id}: {method} {host}:{port} from {peer_addr}");
    timing.record("request_parse", phase_start.elapsed());

    // 4. Evaluate OPA network policy.
    let phase_start = Instant::now();
    let decision = {
        let mut st = state.lock().unwrap();

        let action = NetworkAction {
            host: host.clone(),
            port,
            binary_path: binary_path.clone(),
            binary_sha256: binary_sha256.clone(),
            sandbox_id,
        };

        let decision = st.policy_engine.eval_network(&action).unwrap_or_else(|e| {
            tracing::error!("OPA eval failed: {e}, defaulting to deny");
            axis_core::types::PolicyDecision {
                allowed: false,
                matched_policy: None,
                reason: Some(format!("OPA error: {e}")),
            }
        });

        // Audit log the decision.
        st.audit_log
            .network_decision(sandbox_id, &host, port, &decision);

        decision
    };
    timing.record("opa_evaluation", phase_start.elapsed());

    // 5. Enforce the decision.
    if !decision.allowed {
        let reason = decision.reason.as_deref().unwrap_or("policy denied");
        tracing::info!(
            "sandbox {sandbox_id}: DENIED {host}:{port} (binary={binary_path}, reason={reason})"
        );

        // Send HTTP 403 Forbidden.
        let body =
            format!("AXIS policy denied connection to {host}:{port}\r\nReason: {reason}\r\n");
        let phase_start = Instant::now();
        send_forbidden_response(reader.get_mut(), &body).await?;
        timing.record("response_write", phase_start.elapsed());
        timing.finish(
            ProxyTimingOutcome::Denied,
            Some(host),
            Some(port),
            &timing_tx,
        );
        return Ok(());
    }

    let matched = decision.matched_policy.as_deref().unwrap_or("?");
    tracing::info!(
        "sandbox {sandbox_id}: ALLOWED {host}:{port} (policy={matched}, binary={binary_path})"
    );

    // A forwarded request head is plaintext the proxy holds in full, so it is
    // scanned before anything goes upstream and a blocked request gets a status.
    if let Some(request) = &forward_request
        && let Err(error) = scan_sandbox_bytes(sandbox_id, &request.head, &state)
    {
        let body =
            format!("AXIS policy blocked the request to {host}:{port}\r\nReason: {error}\r\n");
        send_forbidden_response(reader.get_mut(), &body).await?;
        timing.finish(
            ProxyTimingOutcome::Denied,
            Some(host),
            Some(port),
            &timing_tx,
        );
        return Ok(());
    }

    // 6. Connect to upstream.
    //    If the target is `inference.local`, route to the local inference server.
    let phase_start = Instant::now();
    let is_inference_local = host == "inference.local";
    let upstream = if is_inference_local {
        if let Some(ep) = inference_endpoint {
            tracing::info!("sandbox {sandbox_id}: routing inference.local -> {ep}");
            connect_to_resolved_addresses(&host, &[ep]).await
        } else {
            // No inference endpoint configured — return 502.
            let body = "AXIS: no local inference server configured\r\n";
            send_error_response(reader.get_mut(), "502 Bad Gateway", body).await?;
            return Ok(());
        }
    } else {
        connect_authorized_upstream(&host, port).await
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(ProxyError::PolicyDenied { reason, .. }) => {
            tracing::warn!(
                "sandbox {sandbox_id}: rejected resolved destination for {host}:{port}: {reason}"
            );
            let body =
                format!("AXIS policy denied connection to {host}:{port}\r\nReason: {reason}\r\n");
            send_forbidden_response(reader.get_mut(), &body).await?;
            timing.record("upstream_connect", phase_start.elapsed());
            timing.finish(
                ProxyTimingOutcome::Denied,
                Some(host),
                Some(port),
                &timing_tx,
            );
            return Ok(());
        }
        Err(error) => {
            if forward_request.is_some() {
                // A forwarded request has an HTTP client waiting for a status.
                let body = format!("AXIS proxy could not connect to {host}:{port}\r\n");
                send_error_response(reader.get_mut(), "502 Bad Gateway", &body).await?;
            }
            return Err(error);
        }
    };
    timing.record("upstream_connect", phase_start.elapsed());

    if let Some(request) = forward_request {
        timing.finish(
            ProxyTimingOutcome::Allowed,
            Some(host.clone()),
            Some(port),
            &timing_tx,
        );
        return forward::forward_http_request(
            sandbox_id, &host, port, request, reader, upstream, state,
        )
        .await;
    }

    // 7. Send 200 Connection Established.
    let phase_start = Instant::now();
    reader
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    timing.record("response_write", phase_start.elapsed());
    timing.finish(
        ProxyTimingOutcome::Allowed,
        Some(host.clone()),
        Some(port),
        &timing_tx,
    );

    // 8. Relay opaque traffic, applying plaintext credential and leak policy when configured.
    let leak_enabled = {
        let st = state.lock().unwrap();
        st.leak_detector.is_some()
    };

    let request_policy_enabled = {
        let st = state.lock().unwrap();
        st.credential_injector.has_rules() || st.inference_budget.is_some()
    };

    if leak_enabled || request_policy_enabled {
        relay_with_leak_detection(sandbox_id, &host, port, false, reader, upstream, state).await
    } else {
        relay_plain(reader, upstream).await
    }
}

async fn connect_authorized_upstream(
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, ProxyError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // An IP literal has already been authorized verbatim by OPA. This is
        // the only explicit opt-in for loopback or otherwise non-public peers.
        return connect_to_resolved_addresses(host, &[SocketAddr::new(ip, port)]).await;
    }

    // Resolve exactly once. The returned socket addresses are vetted as one
    // answer set and passed directly to connect, preventing a second lookup.
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| ProxyError::ConnectionError(format!("DNS lookup for {host}: {error}")))?
        .collect::<Vec<_>>();
    let vetted = vet_resolved_addresses(host, port, resolved)?;
    connect_to_resolved_addresses(host, &vetted).await
}

fn vet_resolved_addresses(
    host: &str,
    port: u16,
    resolved: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, ProxyError> {
    if resolved.is_empty() {
        return Err(ProxyError::ConnectionError(format!(
            "DNS lookup for {host} returned no addresses"
        )));
    }

    let mut vetted = Vec::with_capacity(resolved.len());
    for address in resolved {
        if !is_public_upstream_ip(address.ip()) {
            return Err(ProxyError::PolicyDenied {
                host: host.into(),
                port,
                reason: format!(
                    "DNS lookup returned prohibited address {}; authorize a literal IP to permit it",
                    address.ip()
                ),
            });
        }
        if !vetted.contains(&address) {
            vetted.push(address);
        }
    }
    Ok(vetted)
}

async fn connect_to_resolved_addresses(
    host: &str,
    addresses: &[SocketAddr],
) -> Result<tokio::net::TcpStream, ProxyError> {
    let mut last_error = None;
    for address in addresses {
        match tokio::net::TcpStream::connect(*address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some((*address, error)),
        }
    }

    let detail = last_error.map_or_else(
        || "no vetted addresses".to_string(),
        |(address, error)| format!("{address}: {error}"),
    );
    Err(ProxyError::ConnectionError(format!(
        "upstream {host} failed: {detail}"
    )))
}

fn is_public_upstream_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }

    // Longest-prefix entries from IANA's IPv6 Special-Purpose Address
    // Registry. `true` entries are explicit globally reachable exceptions;
    // transition mechanisms whose reachability is registry-qualified remain
    // denied because they can obscure the effective destination.
    const SPECIAL_PURPOSE: &[(Ipv6Addr, u8, bool)] = &[
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 1), 128, true),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 2), 128, true),
        (Ipv6Addr::new(0x2001, 0x0001, 0, 0, 0, 0, 0, 3), 128, true),
        (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96, true),
        (Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48, false),
        (Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48, false),
        (
            Ipv6Addr::new(0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 0),
            48,
            true,
        ),
        (Ipv6Addr::new(0x0100, 0, 0, 1, 0, 0, 0, 0), 64, false),
        (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64, false),
        (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32, false),
        (Ipv6Addr::new(0x2001, 0x0003, 0, 0, 0, 0, 0, 0), 32, true),
        (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32, false),
        (Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28, false),
        (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28, true),
        (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28, true),
        (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23, false),
        (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16, false),
        (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20, false),
        (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16, false),
        (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7, false),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10, false),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8, false),
    ];

    for (network, prefix_len, globally_reachable) in SPECIAL_PURPOSE {
        if ipv6_in_prefix(ip, *network, *prefix_len) {
            return *globally_reachable;
        }
    }

    ipv6_in_prefix(ip, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    let shift = 128 - u32::from(prefix_len);
    (u128::from(address) >> shift) == (u128::from(network) >> shift)
}

/// Plain bidirectional TCP relay (no inspection).
async fn relay_plain<S>(
    mut stream: S,
    mut upstream: tokio::net::TcpStream,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// Bidirectional relay with leak detection on response data.
async fn relay_with_leak_detection<S>(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
    is_tls: bool,
    stream: S,
    upstream: tokio::net::TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    // Client -> upstream: scan sandbox-origin bytes, then inject host-side
    // provider credentials into each matching HTTP request head.
    let state_c2u = Arc::clone(&state);
    let hostname = hostname.to_string();
    let c2u = async move {
        relay_client_to_upstream_with_policy(
            sandbox_id, &hostname, port, is_tls, &mut cr, &mut uw, state_c2u,
        )
        .await?;
        tokio::io::AsyncWriteExt::shutdown(&mut uw).await?;
        Ok::<_, std::io::Error>(())
    };

    // Upstream → client: pass through (response data is less likely to leak creds).
    let u2c = async move {
        tokio::io::copy(&mut ur, &mut cw).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut cw).await?;
        Ok::<_, std::io::Error>(())
    };

    tokio::try_join!(c2u, u2c).map_err(ProxyError::Io)?;
    Ok(())
}

async fn relay_client_to_upstream_with_policy<R, W>(
    sandbox_id: SandboxId,
    hostname: &str,
    port: u16,
    is_tls: bool,
    client_read: &mut R,
    upstream_write: &mut W,
    state: Arc<Mutex<ProxyState>>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let requires_request_policy = {
        let st = state.lock().unwrap();
        st.credential_injector
            .connection_requires_injection(hostname, port, is_tls)
            || st
                .inference_budget
                .as_ref()
                .is_some_and(|budget| budget.applies_to(hostname))
    };
    if !requires_request_policy {
        return relay_scanned_bytes(sandbox_id, client_read, upstream_write, state).await;
    }

    let mut buf = vec![0u8; 65536];
    let mut pending = Vec::new();
    let mut body_remaining = 0usize;
    loop {
        let n = tokio::io::AsyncReadExt::read(client_read, &mut buf).await?;
        if n == 0 {
            break;
        }

        scan_sandbox_bytes(sandbox_id, &buf[..n], &state)?;
        pending.extend_from_slice(&buf[..n]);

        loop {
            if body_remaining > 0 {
                let take = body_remaining.min(pending.len());
                if take == 0 {
                    break;
                }
                tokio::io::AsyncWriteExt::write_all(upstream_write, &pending[..take]).await?;
                pending.drain(..take);
                body_remaining -= take;
                if body_remaining > 0 {
                    break;
                }
                continue;
            }

            let Some(head_end) = find_http_head_end(&pending) else {
                if pending.len() > MAX_HTTP_HEAD_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "credential injection failed closed for {hostname}: HTTP request head exceeds {MAX_HTTP_HEAD_BYTES} bytes"
                        ),
                    ));
                }
                break;
            };

            let head = pending[..head_end].to_vec();
            let rewritten = {
                let st = state.lock().unwrap();
                st.credential_injector
                    .inspect_http_request_head_with_body_length(hostname, port, is_tls, &head)
                    .map_err(secret_error_to_io)?
            };
            let next_body_len = rewritten.body_length;
            let budgeted = {
                let st = state.lock().unwrap();
                st.inference_budget
                    .as_ref()
                    .is_some_and(|budget| budget.applies_to(hostname))
                    && is_token_generating_inference_request(&head, hostname)
            };
            if budgeted {
                let complete_request_len =
                    head_end.checked_add(next_body_len).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "inference request length overflow",
                        )
                    })?;
                if pending.len() < complete_request_len {
                    break;
                }
                let body = &pending[head_end..complete_request_len];
                let mut st = state.lock().unwrap();
                let result = st
                    .inference_budget
                    .as_mut()
                    .expect("budget presence checked")
                    .reserve(body);
                match result {
                    Ok(reserved) => {
                        tracing::info!("sandbox {sandbox_id}: reserved {reserved} inference tokens")
                    }
                    Err(reason) => {
                        st.audit_log.inference_budget_denied(sandbox_id, &reason);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("inference token budget denied request: {reason}"),
                        ));
                    }
                }
            }
            if let Some(rewritten_head) = rewritten.head {
                tokio::io::AsyncWriteExt::write_all(upstream_write, &rewritten_head).await?;
            } else {
                tokio::io::AsyncWriteExt::write_all(upstream_write, &head).await?;
            }
            pending.drain(..head_end);
            body_remaining = next_body_len;

            if body_remaining == 0 {
                continue;
            }
        }
    }

    if body_remaining != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "credential injection failed closed for {hostname}: request body ended with {body_remaining} bytes remaining"
            ),
        ));
    }
    if !pending.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "credential injection failed closed for {hostname}: incomplete HTTP request head"
            ),
        ));
    }
    Ok(())
}

fn is_token_generating_inference_request(head: &[u8], hostname: &str) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let Some(request_line) = text.lines().next() else {
        return false;
    };
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(path) = parts.next() else {
        return false;
    };
    let path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    let known_path = matches!(
        path,
        "/v1/chat/completions"
            | "/chat/completions"
            | "/v1/completions"
            | "/v1/responses"
            | "/v1/messages"
            | "/messages"
    );
    let _ = hostname;
    method.eq_ignore_ascii_case("POST") && known_path
}

fn declared_output_tokens(body: &[u8]) -> Result<Option<u64>, String> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("inference request body is not valid JSON: {error}"))?;
    for field in ["max_output_tokens", "max_completion_tokens", "max_tokens"] {
        if let Some(value) = value.get(field) {
            return value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("{field} must be a non-negative integer"));
        }
    }
    Ok(None)
}

fn inference_route_hosts(policy: &Policy) -> HashSet<String> {
    let mut hosts = HashSet::from(["inference.local".to_string()]);
    for route in &policy.inference.routes {
        if let Some(endpoint) = route.endpoint.as_deref()
            && let Some(host) = inference_endpoint_host(endpoint)
        {
            hosts.insert(host);
        }
        if let Some(provider) = route.provider.as_deref() {
            match provider.to_ascii_lowercase().as_str() {
                "openai" | "openai-compatible" => {
                    hosts.insert("api.openai.com".into());
                }
                "anthropic" => {
                    hosts.insert("api.anthropic.com".into());
                }
                _ => {}
            }
        }
    }
    hosts
}

fn inference_endpoint_host(endpoint: &str) -> Option<String> {
    let authority = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))?
        .split(['/', '?', '#'])
        .next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host.to_ascii_lowercase());
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

async fn relay_scanned_bytes<R, W>(
    sandbox_id: SandboxId,
    client_read: &mut R,
    upstream_write: &mut W,
    state: Arc<Mutex<ProxyState>>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65536];
    loop {
        let n = tokio::io::AsyncReadExt::read(client_read, &mut buf).await?;
        if n == 0 {
            break;
        }
        scan_sandbox_bytes(sandbox_id, &buf[..n], &state)?;
        tokio::io::AsyncWriteExt::write_all(upstream_write, &buf[..n]).await?;
    }
    Ok(())
}

fn scan_sandbox_bytes(
    sandbox_id: SandboxId,
    bytes: &[u8],
    state: &Arc<Mutex<ProxyState>>,
) -> std::io::Result<()> {
    let st = state.lock().unwrap();
    if let Some(ref detector) = st.leak_detector {
        let findings = detector.scan(bytes);
        for finding in &findings {
            tracing::warn!(
                "sandbox {sandbox_id}: CREDENTIAL LEAK in outgoing data: {} at offset {}",
                finding.pattern_name,
                finding.byte_offset,
            );
            st.audit_log
                .credential_leak_detected(sandbox_id, finding.pattern_name);
        }
        if !findings.is_empty() {
            tracing::warn!(
                "sandbox {sandbox_id}: BLOCKED outgoing data ({} bytes) due to credential leak",
                bytes.len()
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "credential leak detected in outgoing data",
            ));
        }
    }
    Ok(())
}

fn secret_error_to_io(error: crate::secrets::SecretError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("credential injection failed closed: {error}"),
    )
}

fn find_http_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

/// Resolve the policy identity before any sandbox-controlled request bytes are
/// consumed. Binary-restricted policies accept only a kernel-observed
/// connect-time record. Best-effort diagnostics are intentionally not returned
/// here because optional identity must not become an input to OPA decisions.
async fn resolve_policy_binary_identity(
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
    state: &Arc<Mutex<ProxyState>>,
) -> Result<(String, String), IdentityError> {
    let (connect_attribution, identity_mode) = {
        let st = state.lock().unwrap();
        (st.connect_attribution.clone(), st.identity_mode)
    };

    match identity_mode {
        ProxyIdentityMode::None => Ok(("unknown".into(), "unknown".into())),
        ProxyIdentityMode::RequiredConnectAttribution => {
            let Some(store) = connect_attribution else {
                return Err(IdentityError::ResolveFailed {
                    pid: 0,
                    reason: "connect-time attribution is required by binary-restricted policy but is not configured"
                        .into(),
                });
            };
            let record = wait_for_connect_attribution(&store, sandbox_id, peer_addr, proxy_addr)
                .await
                .map_err(connect_attribution_identity_error)?;
            let mut st = state.lock().unwrap();
            verify_binary_identity(&mut st.tofu_store, Some(record.into()))
        }
        ProxyIdentityMode::OptionalBestEffort => {
            record_optional_identity_diagnostic(
                sandbox_id,
                peer_addr,
                proxy_addr,
                state,
                connect_attribution.as_ref(),
            )
            .await;
            Ok(("unknown".into(), "unknown".into()))
        }
    }
}

async fn record_optional_identity_diagnostic(
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
    state: &Arc<Mutex<ProxyState>>,
    connect_attribution: Option<&ConnectAttributionStore>,
) {
    let identity = match connect_attribution {
        Some(store) => match store.consume(sandbox_id, peer_addr, proxy_addr) {
            Ok(record) => Some(record.into()),
            Err(error) => {
                tracing::debug!(
                    "sandbox {sandbox_id}: optional connect-time attribution unavailable for {peer_addr} -> {proxy_addr}: {error}"
                );
                None
            }
        },
        None => None,
    };
    let Some(identity) = identity else {
        return;
    };
    let diagnostic = {
        let mut st = state.lock().unwrap();
        verify_binary_identity(&mut st.tofu_store, Some(identity))
    };
    match diagnostic {
        Ok((path, _)) => {
            tracing::debug!("sandbox {sandbox_id}: optional binary identity diagnostic: {path}");
        }
        Err(error) => {
            tracing::debug!("sandbox {sandbox_id}: optional binary identity rejected: {error}");
        }
    }
}

async fn wait_for_connect_attribution(
    store: &ConnectAttributionStore,
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
) -> Result<ConnectAttributionRecord, ConnectAttributionError> {
    let started = std::time::Instant::now();
    loop {
        match store.consume(sandbox_id, peer_addr, proxy_addr) {
            Err(ConnectAttributionError::Missing { .. })
                if started.elapsed() < CONNECT_ATTRIBUTION_WAIT =>
            {
                tokio::time::sleep(CONNECT_ATTRIBUTION_RETRY).await;
            }
            result => return result,
        }
    }
}

impl From<ConnectAttributionRecord> for BinaryFingerprint {
    fn from(record: ConnectAttributionRecord) -> Self {
        Self {
            path: record.executable_path,
            sha256: record.executable_sha256,
        }
    }
}

fn connect_attribution_identity_error(error: ConnectAttributionError) -> IdentityError {
    IdentityError::ResolveFailed {
        pid: 0,
        reason: format!("connect-time attribution failed: {error}"),
    }
}

fn verify_binary_identity(
    tofu_store: &mut TofuStore,
    identity: Option<BinaryFingerprint>,
) -> Result<(String, String), IdentityError> {
    let Some(identity) = identity else {
        return Ok(("unknown".into(), "unknown".into()));
    };
    tofu_store.verify_fingerprint(&identity)?;
    Ok((
        identity.path.to_string_lossy().into_owned(),
        identity.sha256,
    ))
}

async fn send_forbidden_response(
    stream: &mut tokio::net::TcpStream,
    body: &str,
) -> Result<(), ProxyError> {
    send_error_response(stream, "403 Forbidden", body).await
}

async fn send_error_response<W>(stream: &mut W, status: &str, body: &str) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Parse "CONNECT host:port HTTP/1.1" into (host, port).
#[cfg(test)]
fn parse_connect_target(request_line: &str) -> Result<(String, u16), ProxyError> {
    let line = request_line.strip_suffix("\r\n").ok_or_else(|| {
        ProxyError::ConnectionError("CONNECT request line must use CRLF framing".into())
    })?;
    let parts = line.split(' ').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| part.is_empty())
        || !parts[0].eq_ignore_ascii_case("CONNECT")
        || parts[2] != "HTTP/1.1"
    {
        return Err(ProxyError::ConnectionError(format!(
            "invalid CONNECT request: {request_line}"
        )));
    }

    parse_connect_authority(parts[1])
}

fn parse_connect_authority(target: &str) -> Result<(String, u16), ProxyError> {
    if let Ok(address) = target.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok((ip.to_string(), 443));
    }
    let authority = target
        .parse::<hyper::http::uri::Authority>()
        .map_err(|_| ProxyError::ConnectionError(format!("invalid CONNECT target: {target}")))?;
    if target.contains('@') {
        return Err(ProxyError::ConnectionError(format!(
            "invalid CONNECT target: {target}"
        )));
    }
    let host = canonicalize_connect_host(authority.host())?;
    Ok((host, authority.port_u16().unwrap_or(443)))
}

async fn read_request_head<R>(reader: &mut R, deadline: Duration) -> Result<Vec<u8>, ProxyError>
where
    R: AsyncBufRead + Unpin,
{
    tokio::time::timeout(deadline, read_http_head_bounded(reader))
        .await
        .map_err(|_| ProxyError::ConnectionError("proxy request head deadline exceeded".into()))?
}

/// Read one canonical HTTP/1.1 head, up to and including the empty line, and
/// leave anything after it buffered in `reader`.
async fn read_http_head_bounded<R>(reader: &mut R) -> Result<Vec<u8>, ProxyError>
where
    R: AsyncBufRead + Unpin,
{
    let mut head = Vec::with_capacity(1024);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(ProxyError::ConnectionError(
                "unexpected EOF in HTTP head".into(),
            ));
        }

        let mut consumed = 0;
        let mut complete = false;
        for byte in available.iter().copied() {
            if head.len() == MAX_HTTP_HEAD_BYTES {
                return Err(ProxyError::MalformedHead(
                    "HTTP head exceeds configured limit".into(),
                ));
            }
            if byte == b'\n' && head.last() != Some(&b'\r') {
                return Err(ProxyError::MalformedHead(
                    "HTTP head contains a bare line feed".into(),
                ));
            }
            if head.last() == Some(&b'\r') && byte != b'\n' {
                return Err(ProxyError::MalformedHead(
                    "HTTP head contains a bare carriage return".into(),
                ));
            }
            head.push(byte);
            consumed += 1;
            if head.ends_with(b"\r\n\r\n") {
                complete = true;
                break;
            }
        }
        reader.consume(consumed);
        if complete {
            return Ok(head);
        }
    }
}

fn is_connect_request_head(head: &[u8]) -> bool {
    head.split(|byte| *byte == b' ')
        .next()
        .is_some_and(|method| method.eq_ignore_ascii_case(b"CONNECT"))
}

fn parse_connect_request_head(head: &[u8]) -> Result<(String, u16), ProxyError> {
    if !head.ends_with(b"\r\n\r\n") {
        return Err(ProxyError::ConnectionError(
            "incomplete CONNECT request head".into(),
        ));
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(head).map_err(|error| {
        ProxyError::ConnectionError(format!("malformed CONNECT request head: {error}"))
    })? {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => {
            return Err(ProxyError::ConnectionError(
                "incomplete CONNECT request head".into(),
            ));
        }
    };
    if consumed != head.len()
        || request.version != Some(1)
        || !request
            .method
            .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
    {
        return Err(ProxyError::ConnectionError(
            "CONNECT proxy requires one canonical HTTP/1.1 request head".into(),
        ));
    }

    for header in request.headers {
        header
            .name
            .parse::<hyper::http::HeaderName>()
            .map_err(|_| ProxyError::ConnectionError("invalid CONNECT header name".into()))?;
        hyper::http::HeaderValue::from_bytes(header.value)
            .map_err(|_| ProxyError::ConnectionError("invalid CONNECT header value".into()))?;
    }

    let target = request.path.ok_or_else(|| {
        ProxyError::ConnectionError("CONNECT request is missing a target authority".into())
    })?;
    parse_connect_authority(target)
}

fn canonicalize_connect_host(host: &str) -> Result<String, ProxyError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || !host.is_ascii()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || host.contains(['/', '\\', '@'])
    {
        return Err(ProxyError::ConnectionError(
            "invalid CONNECT hostname".into(),
        ));
    }
    Ok(host
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn parse_connect_host_port() {
        let (host, port) = parse_connect_target("CONNECT api.github.com:443 HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_no_port() {
        let (host, port) = parse_connect_target("CONNECT example.com HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_canonicalizes_dns_names() {
        let (host, port) = parse_connect_target("CONNECT EXAMPLE.COM.:8443 HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_connect_ipv6_literal() {
        let (host, port) = parse_connect_target("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_connect_invalid() {
        assert!(parse_connect_target("GET / HTTP/1.1\r\n").is_err());
        assert!(parse_connect_target("CONNECT example.com HTTP/1.0\r\n").is_err());
        assert!(parse_connect_target("CONNECT  example.com HTTP/1.1\r\n").is_err());
        assert!(parse_connect_target("CONNECT example.com HTTP/1.1\n").is_err());
        assert!(parse_connect_target("CONNECT user@example.com HTTP/1.1\r\n").is_err());
    }

    #[test]
    fn connect_head_parser_rejects_too_many_headers() {
        let mut head = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        for index in 0..=MAX_HTTP_HEADERS {
            head.extend_from_slice(format!("x-test-{index}: value\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");

        let error = parse_connect_request_head(&head).unwrap_err();
        assert!(error.to_string().contains("too many headers"), "{error}");
    }

    #[tokio::test]
    async fn connect_head_reader_preserves_fragmentation_and_tunnel_bytes() {
        let (mut client, server) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            for fragment in [
                b"CON".as_slice(),
                b"NECT example.com:443 HTTP/1.1\r".as_slice(),
                b"\nHost: example.com\r\n\r".as_slice(),
                b"\nearly-tunnel-data".as_slice(),
            ] {
                client.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut reader = BufReader::new(server);

        let head = read_request_head(&mut reader, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            head,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
        assert_eq!(
            parse_connect_request_head(&head).unwrap(),
            ("example.com".into(), 443)
        );
        let mut early_data = vec![0; "early-tunnel-data".len()];
        reader.read_exact(&mut early_data).await.unwrap();
        assert_eq!(early_data, b"early-tunnel-data");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn connect_head_reader_rejects_oversized_unterminated_and_eof_inputs() {
        let cases = [
            vec![b'a'; MAX_HTTP_HEAD_BYTES + 1],
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n".to_vec(),
            Vec::new(),
        ];

        for input in cases {
            let (mut client, server) = tokio::io::duplex(4096);
            let writer = tokio::spawn(async move {
                client.write_all(&input).await.unwrap();
                client.shutdown().await.unwrap();
            });
            let mut reader = BufReader::new(server);
            let error = read_request_head(&mut reader, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("configured limit")
                    || error.to_string().contains("unexpected EOF"),
                "{error}"
            );
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_head_reader_rejects_noncanonical_and_slow_drip_inputs() {
        for input in [
            b"CONNECT example.com:443 HTTP/1.1\n\n".as_slice(),
            b"CONNECT example.com:443 HTTP/1.1\rX: hidden\r\n\r\n".as_slice(),
        ] {
            let mut reader = BufReader::new(input);
            let error = read_request_head(&mut reader, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("bare"), "{error}");
        }

        let (mut client, server) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            client.write_all(b"C").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = client
                .write_all(b"ONNECT example.com:443 HTTP/1.1\r\n\r\n")
                .await;
        });
        let mut reader = BufReader::new(server);
        let error = read_request_head(&mut reader, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"), "{error}");
        writer.abort();
    }

    #[test]
    fn find_http_head_end_accepts_only_crlf_heads() {
        assert_eq!(
            find_http_head_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"),
            Some(37)
        );
        assert_eq!(
            find_http_head_end(b"GET / HTTP/1.1\nHost: example.com\n\nbody"),
            None
        );
    }

    #[test]
    fn proxy_connection_slots_fail_closed_at_the_limit() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = reserve_connection(&slots).expect("first connection must reserve the slot");
        assert!(reserve_connection(&slots).is_none());
        drop(permit);
        assert!(reserve_connection(&slots).is_some());
    }

    #[tokio::test]
    async fn proxy_server_saturation_is_bounded_and_recovers_after_header_deadline() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let _ = upstream.accept().await.unwrap();
        });
        let policy = Policy::from_yaml(&format!(
            r#"
version: 1
name: saturation
network:
  mode: proxy
  policies:
    - name: local
      endpoints:
        - host: "127.0.0.1"
          port: {}
"#,
            upstream_addr.port()
        ))
        .unwrap();
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_leak_detection: false,
            inference_endpoint: None,
            connect_attribution: None,
            enable_identity_diagnostics: false,
            timing_tx: None,
            unauthenticated_loopback: true,
        };
        let mut proxy = AxisProxy::new(config).unwrap();
        let proxy_addr = proxy.bind().await.unwrap();
        let proxy_task = tokio::spawn(async move {
            let _ = proxy
                .run_with_limits(MAX_CONCURRENT_CONNECTIONS, Duration::from_millis(500))
                .await;
        });

        let mut slow_clients = Vec::with_capacity(MAX_CONCURRENT_CONNECTIONS);
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            stream.write_all(b"C").await.unwrap();
            slow_clients.push(stream);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut saturated = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let mut byte = [0u8; 1];
        let rejected =
            tokio::time::timeout(Duration::from_millis(200), saturated.read(&mut byte)).await;
        assert!(
            matches!(rejected, Ok(Ok(0)) | Ok(Err(_))),
            "257th client was not promptly rejected: {rejected:?}"
        );

        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut valid = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let target = format!("127.0.0.1:{}", upstream_addr.port());
        valid
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0u8; 39];
        tokio::time::timeout(Duration::from_secs(1), valid.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        drop(slow_clients);
        upstream_task.await.unwrap();
        proxy_task.abort();
    }

    #[test]
    fn inference_budget_reserves_conservative_input_and_declared_output() {
        let mut budget = InferenceBudget::new(
            TokenBudget {
                max_tokens_per_hour: 1_000,
                max_tokens_per_request: 500,
                action_on_exhaust: ExhaustAction::Reject,
                fallback_route: None,
            },
            HashSet::from(["inference.local".into()]),
        )
        .unwrap();
        let body = br#"{"model":"test","max_tokens":100}"#;
        assert_eq!(budget.reserve(body).unwrap(), body.len() as u64 + 100);
        assert_eq!(budget.reserved_tokens, body.len() as u64 + 100);
    }

    #[test]
    fn inference_budget_fails_closed_for_oversize_and_unsupported_actions() {
        let mut budget = InferenceBudget::new(
            TokenBudget {
                max_tokens_per_hour: 1_000,
                max_tokens_per_request: 100,
                action_on_exhaust: ExhaustAction::Reject,
                fallback_route: None,
            },
            HashSet::new(),
        )
        .unwrap();
        assert!(budget.reserve(br#"{"max_output_tokens":101}"#).is_err());
        assert!(budget.reserve(br#"{"model":"missing-limit"}"#).is_err());

        let error = InferenceBudget::new(
            TokenBudget {
                max_tokens_per_hour: 1_000,
                max_tokens_per_request: 100,
                action_on_exhaust: ExhaustAction::Queue,
                fallback_route: None,
            },
            HashSet::new(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("trusted request scheduler"));
    }

    #[test]
    fn budget_detection_is_limited_to_token_generating_inference_posts() {
        assert!(is_token_generating_inference_request(
            b"POST /v1/chat/completions HTTP/1.1\r\n\r\n",
            "inference.local"
        ));
        assert!(!is_token_generating_inference_request(
            b"GET /v1/models HTTP/1.1\r\n\r\n",
            "inference.local"
        ));
        assert!(!is_token_generating_inference_request(
            b"POST /unrelated HTTP/1.1\r\n\r\n",
            "inference.local"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_freebind_is_used_only_for_nonlocal_ipv4_binds() {
        assert!(linux_proxy_bind_requires_freebind(
            "10.200.0.1:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "127.0.0.1:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "0.0.0.0:3128".parse().unwrap()
        ));
        assert!(!linux_proxy_bind_requires_freebind(
            "[::1]:3128".parse().unwrap()
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_proxy_accepts_only_the_adjacent_sandbox_source() {
        let expected = strict_proxy_expected_peer("10.42.7.5:3128".parse().unwrap()).unwrap();
        assert_eq!(expected, Some("10.42.7.6".parse().unwrap()));

        authenticate_proxy_peer(expected, "10.42.7.6:49152".parse().unwrap()).unwrap();
        let error =
            authenticate_proxy_peer(expected, "127.0.0.1:49152".parse().unwrap()).unwrap_err();
        assert!(error.to_string().contains("unauthenticated proxy peer"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_proxy_rejects_non_allocator_bind_addresses() {
        let error = strict_proxy_expected_peer("10.42.7.10:3128".parse().unwrap()).unwrap_err();
        assert!(error.to_string().contains("host-veth"));

        let error = strict_proxy_expected_peer("0.0.0.0:3128".parse().unwrap()).unwrap_err();
        assert!(error.to_string().contains("host-veth"));

        assert_eq!(
            strict_proxy_expected_peer("127.0.0.1:3128".parse().unwrap()).unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    async fn observed_peer(source: Ipv4Addr) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(source.into(), 0)).unwrap();
        let client = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        drop((client, server));
        peer
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn strict_proxy_accepts_kernel_observed_sandbox_source() {
        let expected_sandbox_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let sandbox_peer = observed_peer(Ipv4Addr::new(127, 0, 0, 2)).await;
        authenticate_proxy_peer(Some(expected_sandbox_ip), sandbox_peer).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn strict_proxy_rejects_kernel_observed_host_source() {
        let expected_sandbox_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let host_peer = observed_peer(Ipv4Addr::LOCALHOST).await;
        let error = authenticate_proxy_peer(Some(expected_sandbox_ip), host_peer).unwrap_err();
        assert!(error.to_string().contains("unauthenticated proxy peer"));
    }

    #[test]
    fn public_dns_answers_are_vetted_and_deduplicated() {
        let addresses = vec![
            "93.184.216.34:443".parse().unwrap(),
            "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        ];
        let vetted = vet_resolved_addresses("example.com", 443, addresses).unwrap();
        assert_eq!(vetted.len(), 2);
    }

    #[test]
    fn mixed_dns_answers_fail_closed_against_rebinding() {
        for prohibited in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.169.254:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
        ] {
            let error = vet_resolved_addresses(
                "allowed.example",
                443,
                vec![
                    "93.184.216.34:443".parse().unwrap(),
                    prohibited.parse().unwrap(),
                ],
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("prohibited address"),
                "{prohibited}: {error}"
            );
        }
    }

    #[test]
    fn documentation_and_internal_address_classes_are_not_public() {
        for address in [
            "0.0.0.0",
            "100.64.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "2001:db8::1",
            "3fff::1",
            "2001:2::1",
            "100::1",
            "64:ff9b:1::1",
            "::ffff:127.0.0.1",
            "2002:7f00:1::1",
            "4000::1",
        ] {
            let ip = address.parse().unwrap();
            assert!(!is_public_upstream_ip(ip), "{address} must be prohibited");
        }
    }

    #[test]
    fn representative_public_ipv4_and_ipv6_addresses_are_allowed() {
        for address in [
            "93.184.216.34",
            "2606:4700:4700::1111",
            "64:ff9b::c000:201",
            "2001:1::1",
            "2001:3::1",
            "2001:20::1",
            "2001:30::1",
        ] {
            let ip = address.parse().unwrap();
            assert!(is_public_upstream_ip(ip), "{address} must be public");
        }
    }

    #[tokio::test]
    async fn authorized_private_ip_literal_connects_without_dns() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream = connect_authorized_upstream("127.0.0.1", address.port())
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
        let (_, peer) = accept.await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn verify_binary_identity_preserves_unsupported_unknown() {
        let mut tofu_store = TofuStore::new();
        let identity = verify_binary_identity(&mut tofu_store, None).unwrap();
        assert_eq!(identity, ("unknown".into(), "unknown".into()));
    }

    #[test]
    fn verify_binary_identity_rejects_tofu_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("binary");
        std::fs::write(&binary, b"content").unwrap();
        let mut tofu_store = TofuStore::new();
        tofu_store
            .verify_fingerprint(&BinaryFingerprint {
                path: binary.clone(),
                sha256: "0".repeat(64),
            })
            .unwrap();

        let err = verify_binary_identity(
            &mut tofu_store,
            Some(BinaryFingerprint {
                path: binary,
                sha256: "1".repeat(64),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::HashMismatch { .. }));
    }

    #[test]
    fn proxy_identity_mode_defaults_to_none_for_host_port_policy() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: host-port-only
network:
  mode: proxy
  policies:
    - name: api
      endpoints:
        - host: "api.example.com"
          port: 443
"#,
        )
        .unwrap();

        assert_eq!(proxy_identity_mode(&policy, false), ProxyIdentityMode::None);
        assert_eq!(
            proxy_identity_mode(&policy, true),
            ProxyIdentityMode::OptionalBestEffort
        );
    }

    #[test]
    fn proxy_identity_mode_requires_attribution_for_binary_policy() {
        let policy = Policy::from_yaml(
            r#"
version: 1
name: binary-restricted
network:
  mode: proxy
  policies:
    - name: api
      endpoints:
        - host: "api.example.com"
          port: 443
      binaries:
        - path: "/usr/bin/curl"
"#,
        )
        .unwrap();

        assert_eq!(
            proxy_identity_mode(&policy, false),
            ProxyIdentityMode::RequiredConnectAttribution
        );
        assert_eq!(
            proxy_identity_mode(&policy, true),
            ProxyIdentityMode::RequiredConnectAttribution
        );
    }

    #[test]
    fn proxy_config_creates_with_policy() {
        let policy = Policy::from_yaml("version: 1\nname: test\n").unwrap();
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_leak_detection: true,
            inference_endpoint: None,
            connect_attribution: None,
            enable_identity_diagnostics: false,
            timing_tx: None,
            unauthenticated_loopback: true,
        };
        let proxy = AxisProxy::new(config);
        assert!(proxy.is_ok(), "proxy creation failed: {:?}", proxy.err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn loopback_listener_serves_only_the_registered_sandbox_process() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let policy =
            Policy::from_yaml("version: 1\nname: test\nnetwork:\n  mode: proxy\n").unwrap();
        let mut proxy = AxisProxy::new(ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_leak_detection: false,
            inference_endpoint: None,
            connect_attribution: None,
            enable_identity_diagnostics: false,
            timing_tx: None,
            unauthenticated_loopback: false,
        })
        .unwrap();
        let peer = proxy.sandbox_process_peer().unwrap();
        let proxy_addr = proxy.bind().await.unwrap();
        let proxy_task = tokio::spawn(async move {
            let _ = proxy.run().await;
        });
        let request = |request: &'static [u8]| async move {
            let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut response = String::new();
            tokio::time::timeout(
                Duration::from_secs(10),
                stream.read_to_string(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            response
        };

        // Another process is the sandbox, so this one is refused before the
        // proxy reads a request.
        let mut other = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        peer.set_root(other.id());
        let refused = request(b"").await;
        other.kill().unwrap();
        other.wait().unwrap();
        assert!(
            refused.contains("unauthenticated sandbox peer"),
            "{refused}"
        );

        // This process is the sandbox: the request reaches policy evaluation.
        peer.set_root(std::process::id());
        let served = request(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").await;
        assert!(served.starts_with("HTTP/1.1 403"), "{served}");
        assert!(!served.contains("unauthenticated sandbox peer"), "{served}");
        proxy_task.abort();
    }

    #[test]
    fn proxy_revalidates_direct_policy_values() {
        let mut policy = Policy::from_yaml("version: 1\nname: direct-policy\n").unwrap();
        policy
            .inference
            .routes
            .push(axis_core::policy::InferenceRoute {
                name: "external".into(),
                endpoint: Some("https://api.example.com/v1".into()),
                provider: None,
                model: None,
                api_key_env: Some("EXTERNAL_KEY".into()),
                protocols: Vec::new(),
            });
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_leak_detection: true,
            inference_endpoint: None,
            connect_attribution: None,
            enable_identity_diagnostics: false,
            timing_tx: None,
            unauthenticated_loopback: true,
        };

        let err = AxisProxy::new(config).err().unwrap();
        assert!(
            err.to_string().contains("HTTPS credential injection"),
            "{err}"
        );
    }

    #[test]
    fn proxy_with_full_policy() {
        let policy_yaml = r#"
version: 1
name: test-proxy-policy
network:
  mode: proxy
  policies:
    - name: allowed-api
      endpoints:
        - host: "api.example.com"
          port: 443
"#;
        let policy = Policy::from_yaml(policy_yaml).unwrap();
        let config = ProxyConfig {
            sandbox_id: SandboxId::new(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            policy,
            enable_leak_detection: false,
            inference_endpoint: None,
            connect_attribution: None,
            enable_identity_diagnostics: false,
            timing_tx: None,
            unauthenticated_loopback: true,
        };
        let proxy = AxisProxy::new(config).unwrap();
        // Verify the proxy state was initialized correctly.
        let st = proxy.state.lock().unwrap();
        let action = NetworkAction {
            host: "api.example.com".into(),
            port: 443,
            binary_path: "unknown".into(),
            binary_sha256: "unknown".into(),
            sandbox_id: SandboxId::new(),
        };
        drop(st);

        // Test policy evaluation through the proxy's engine.
        let mut st = proxy.state.lock().unwrap();
        let decision = st.policy_engine.eval_network(&action).unwrap();
        assert!(decision.allowed, "expected allow, got: {decision:?}");
        assert_eq!(decision.matched_policy.as_deref(), Some("allowed-api"));

        // Test deny for unknown host.
        let deny_action = NetworkAction {
            host: "evil.example.com".into(),
            port: 443,
            binary_path: "unknown".into(),
            binary_sha256: "unknown".into(),
            sandbox_id: SandboxId::new(),
        };
        let deny_decision = st.policy_engine.eval_network(&deny_action).unwrap();
        assert!(
            !deny_decision.allowed,
            "expected deny, got: {deny_decision:?}"
        );
    }
}
