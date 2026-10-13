// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle manager — create, list, destroy sandboxes.
//!
//! Each sandbox gets:
//! 1. A workspace directory
//! 2. A dedicated proxy (AxisProxy) on a dynamic port when policy uses proxy mode
//! 3. An isolated child process with OS-native sandboxing
//! 4. Optionally, a HIP Remote GPU worker (when gpu.enabled)
//!
//! The proxy enforces OPA network policy and leak detection for proxy-mode sandboxes.

use axis_core::audit::{AuditEvent, AuditLog, BroadcastSink, TracingSink};
use axis_core::policy::{NetworkMode, Policy};
use axis_core::types::{SandboxId, SandboxStatus};
use axis_gateway::SandboxBackend;
use axis_gpu::api_filter::GpuPolicy as GpuFilterPolicy;
use axis_gpu::worker_mgr::WorkerManager;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use axis_router::server_mgr::{InferenceServer, ManagedBackend, ServerMode};
use axis_sandbox::{Sandbox, SandboxConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};

/// Base port for dynamic proxy allocation.
const PROXY_PORT_BASE: u16 = 13100;
const EXEC_OUTPUT_DIR: &str = ".axis-exec";
const TIMEOUT_DESTROY_ATTEMPTS: usize = 3;
const TIMEOUT_DESTROY_RETRY_DELAY_MS: u64 = 100;
const LIFECYCLE_REAP_INTERVAL_MS: u64 = 100;
#[cfg(all(target_os = "linux", not(test)))]
const BYPASS_AUDIT_POLL_INTERVAL_MS: u64 = 250;

#[cfg(target_os = "linux")]
type BypassAuditTokens = std::sync::Arc<std::sync::Mutex<HashMap<String, SandboxId>>>;
type SandboxEnv = Vec<(String, String)>;
type ExecContext = (Policy, PathBuf, SandboxEnv);
type OutputSubscription = (Vec<Vec<u8>>, tokio::sync::broadcast::Receiver<Vec<u8>>);
type ProxyStart = (
    Option<SocketAddr>,
    Option<tokio::sync::oneshot::Sender<()>>,
    Option<axis_core::connect_attribution::ConnectAttributionStore>,
);
type DaemonBackendFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Atomic counter for allocating unique proxy ports.
static NEXT_PORT: AtomicU16 = AtomicU16::new(PROXY_PORT_BASE);

/// State for a running sandbox (sandbox process + proxy + optional GPU worker).
struct ManagedSandbox {
    sandbox: Sandbox,
    policy: Policy,
    env: SandboxEnv,
    proxy_addr: Option<SocketAddr>,
    proxy_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    gpu_enabled: bool,
    policy_name: String,
    /// Broadcast channel for streaming sandbox stdout to WebSocket clients.
    output_tx: Option<tokio::sync::broadcast::Sender<Vec<u8>>>,
    /// Buffered output for replay to late-connecting WebSocket clients.
    output_buffer: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Channel for writing input to the sandbox's stdin.
    input_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

pub struct SandboxManager {
    sandboxes: HashMap<SandboxId, ManagedSandbox>,
    gpu_manager: WorkerManager,
    inference_server: Option<InferenceServer>,
    audit: AuditLog,
    sandbox_base_dir: PathBuf,
    #[cfg(target_os = "linux")]
    bypass_audit_tokens: BypassAuditTokens,
}

impl SandboxManager {
    /// Create a SandboxManager with an optional broadcast channel for streaming
    /// audit events to the gateway (GUI/WebSocket clients).
    pub fn with_event_broadcast(
        event_tx: Option<tokio::sync::broadcast::Sender<AuditEvent>>,
    ) -> Self {
        let mut audit = AuditLog::new();
        audit.add_sink(Box::new(TracingSink));
        if let Some(tx) = event_tx.clone() {
            audit.add_sink(Box::new(BroadcastSink::new(tx)));
        }

        let sandbox_base_dir = dirs_base();
        std::fs::create_dir_all(&sandbox_base_dir).ok();

        // Look for hip-worker binary in standard locations.
        let worker_binary = find_hip_worker();
        #[cfg(target_os = "linux")]
        let bypass_audit_tokens = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        #[cfg(all(target_os = "linux", not(test)))]
        spawn_linux_bypass_audit_collector(bypass_audit_tokens.clone(), event_tx);

        Self {
            sandboxes: HashMap::new(),
            gpu_manager: WorkerManager::new(worker_binary),
            inference_server: None,
            audit,
            sandbox_base_dir,
            #[cfg(target_os = "linux")]
            bypass_audit_tokens,
        }
    }

    /// Create and start a new sandbox with its own proxy (and optional GPU worker)
    /// without holding the manager mutex across slow setup operations.
    pub async fn create_from_shared(
        mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
        policy: Policy,
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> Result<SandboxId, String> {
        let id = SandboxId::new();
        let workspace_dir = {
            let manager = mgr.lock().await;
            let workspace_dir = manager.sandbox_base_dir.join(id.to_string());
            std::fs::create_dir_all(&workspace_dir).map_err(|e| e.to_string())?;
            workspace_dir
        };
        let policy_name = policy.name.clone();
        let gpu_enabled = policy.gpu.enabled;
        let timeout_sec = policy.process.timeout_sec;

        // 1. Start inference server if policy has routes with a local endpoint.
        let inference_endpoint = ensure_inference_server_from_shared(mgr.clone(), &policy).await;

        // 2. Start the proxy only for proxy-mode policies.
        let (proxy_addr, proxy_shutdown, connect_attribution) =
            match start_proxy_for_sandbox(id, &policy, inference_endpoint).await {
                Ok(proxy) => proxy,
                Err(e) => {
                    cleanup_failed_create_workspace(&workspace_dir);
                    return Err(e);
                }
            };

        // 3. Optionally start a GPU worker.
        let extra_env =
            spawn_gpu_worker_from_shared(mgr.clone(), id, &policy, &workspace_dir).await;

        #[cfg(target_os = "linux")]
        let bypass_audit_tokens = {
            let manager = mgr.lock().await;
            manager.bypass_audit_tokens.clone()
        };
        #[cfg(target_os = "linux")]
        let register_bypass_audit = policy_uses_proxy(&policy);
        #[cfg(target_os = "linux")]
        if register_bypass_audit {
            register_bypass_audit_token(&bypass_audit_tokens, id);
        }

        // 4. Create and start the sandbox process.
        let managed = match start_managed_sandbox(StartManagedSandboxArgs {
            id,
            policy,
            policy_name: policy_name.clone(),
            gpu_enabled,
            command,
            args,
            env,
            extra_env,
            workspace_dir: workspace_dir.clone(),
            proxy_addr,
            connect_attribution,
            proxy_shutdown,
        }) {
            Ok(managed) => managed,
            Err(e) => {
                #[cfg(target_os = "linux")]
                if register_bypass_audit {
                    unregister_bypass_audit_token(&bypass_audit_tokens, id);
                }
                if gpu_enabled {
                    stop_gpu_worker_from_shared(mgr.clone(), &id).await;
                }
                cleanup_failed_create_workspace(&workspace_dir);
                return Err(e);
            }
        };

        {
            let mut manager = mgr.lock().await;
            manager.audit.sandbox_created(id, &policy_name);
            manager.sandboxes.insert(id, managed);
        }

        spawn_sandbox_lifecycle(mgr, id, timeout_sec);

        Ok(id)
    }

    /// Execute a command inside an existing sandbox's workspace without
    /// holding the manager mutex while the command runs.
    pub async fn exec_in_sandbox_from_shared(
        mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
        id: SandboxId,
        command: String,
        args: Vec<String>,
    ) -> Result<i32, String> {
        let (policy, workspace, env) = {
            let mut manager = mgr.lock().await;
            let _ = manager.reap_exited(&id)?;
            manager.exec_context(&id)?
        };
        #[cfg(target_os = "linux")]
        let bypass_audit_tokens = {
            let manager = mgr.lock().await;
            manager.bypass_audit_tokens.clone()
        };
        let inference_endpoint = ensure_inference_server_from_shared(mgr.clone(), &policy).await;

        run_contained_exec(
            policy,
            workspace,
            env,
            inference_endpoint,
            #[cfg(target_os = "linux")]
            bypass_audit_tokens,
            command,
            args,
        )
        .await
    }

    fn exec_context(&self, id: &SandboxId) -> Result<ExecContext, String> {
        let managed = self
            .sandboxes
            .get(id)
            .ok_or_else(|| format!("sandbox not found: {id}"))?;
        ensure_sandbox_running(id, managed.sandbox.status)?;
        Ok((
            managed.policy.clone(),
            managed.sandbox.workspace_dir.clone(),
            managed.env.clone(),
        ))
    }

    /// Destroy a sandbox, its proxy, and its GPU worker.
    pub fn destroy(&mut self, id: &SandboxId) -> Result<(), String> {
        let managed = self
            .sandboxes
            .get_mut(id)
            .ok_or_else(|| format!("sandbox not found: {id}"))?;

        managed.sandbox.status = SandboxStatus::Stopping;
        #[cfg(target_os = "linux")]
        let unregister_bypass_audit = policy_uses_proxy(&managed.policy);
        let sandbox_cleanup = managed.sandbox.destroy().map_err(|e| e.to_string());
        shutdown_proxy(managed.proxy_shutdown.take());
        #[cfg(target_os = "linux")]
        if unregister_bypass_audit {
            unregister_bypass_audit_token(&self.bypass_audit_tokens, *id);
        }

        if managed.gpu_enabled {
            match self.gpu_manager.stop_worker(id) {
                Ok(()) => managed.gpu_enabled = false,
                Err(e) => tracing::warn!("sandbox {id}: GPU worker cleanup: {e}"),
            }
        }

        if let Err(e) = sandbox_cleanup {
            managed.sandbox.status = SandboxStatus::Failed;
            return Err(e);
        }

        self.audit.sandbox_destroyed(*id);
        self.sandboxes.remove(id);

        tracing::info!("sandbox {id}: destroyed");
        Ok(())
    }

    fn reap_exited(&mut self, id: &SandboxId) -> Result<Option<i32>, String> {
        enum ReapOutcome {
            Running,
            Exited {
                code: i32,
                gpu_enabled: bool,
                proxy_mode: bool,
            },
            Failed {
                error: String,
                gpu_enabled: bool,
                proxy_mode: bool,
            },
        }

        let outcome = {
            let Some(managed) = self.sandboxes.get_mut(id) else {
                return Ok(None);
            };

            match managed.sandbox.try_wait() {
                Ok(Some(code)) => {
                    shutdown_proxy(managed.proxy_shutdown.take());
                    let gpu_enabled = managed.gpu_enabled;
                    let proxy_mode = policy_uses_proxy(&managed.policy);
                    ReapOutcome::Exited {
                        code,
                        gpu_enabled,
                        proxy_mode,
                    }
                }
                Ok(None) => ReapOutcome::Running,
                Err(e) => {
                    managed.sandbox.status = SandboxStatus::Failed;
                    shutdown_proxy(managed.proxy_shutdown.take());
                    let gpu_enabled = managed.gpu_enabled;
                    let proxy_mode = policy_uses_proxy(&managed.policy);
                    ReapOutcome::Failed {
                        error: e.to_string(),
                        gpu_enabled,
                        proxy_mode,
                    }
                }
            }
        };

        match outcome {
            ReapOutcome::Running => Ok(None),
            ReapOutcome::Exited {
                code,
                gpu_enabled,
                proxy_mode,
            } => {
                #[cfg(target_os = "linux")]
                if proxy_mode {
                    unregister_bypass_audit_token(&self.bypass_audit_tokens, *id);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = proxy_mode;
                if gpu_enabled {
                    match self.gpu_manager.stop_worker(id) {
                        Ok(()) => {
                            if let Some(managed) = self.sandboxes.get_mut(id) {
                                managed.gpu_enabled = false;
                            }
                        }
                        Err(e) => tracing::warn!("sandbox {id}: GPU worker cleanup: {e}"),
                    }
                }
                tracing::info!("sandbox {id}: exited with code {code}");
                Ok(Some(code))
            }
            ReapOutcome::Failed {
                error,
                gpu_enabled,
                proxy_mode,
            } => {
                #[cfg(target_os = "linux")]
                if proxy_mode {
                    unregister_bypass_audit_token(&self.bypass_audit_tokens, *id);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = proxy_mode;
                if gpu_enabled {
                    match self.gpu_manager.stop_worker(id) {
                        Ok(()) => {
                            if let Some(managed) = self.sandboxes.get_mut(id) {
                                managed.gpu_enabled = false;
                            }
                        }
                        Err(e) => tracing::warn!("sandbox {id}: GPU worker cleanup: {e}"),
                    }
                }
                Err(error)
            }
        }
    }

    /// List all sandboxes.
    pub fn list(&self) -> Vec<SandboxInfo> {
        self.sandboxes
            .values()
            .map(|m| {
                let gpu_info = if m.gpu_enabled {
                    self.gpu_manager
                        .endpoint(&m.sandbox.id)
                        .map(|e| e.to_string())
                } else {
                    None
                };

                SandboxInfo {
                    id: m.sandbox.id,
                    status: m.sandbox.status,
                    policy_name: m.policy_name.clone(),
                    pid: m.sandbox.pid,
                    workspace: m.sandbox.workspace_dir.clone(),
                    proxy_addr: m
                        .proxy_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    gpu_worker: gpu_info,
                }
            })
            .collect()
    }

    /// Get a sender for writing to a sandbox's stdin.
    pub fn get_input_sender(&self, id: &SandboxId) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        self.sandboxes.get(id).and_then(|m| m.input_tx.clone())
    }

    /// Subscribe to a sandbox's stdout/stderr output stream.
    /// Returns (buffered_output, live_receiver) — caller should send the buffer first,
    /// then stream from the receiver for new data.
    pub fn subscribe_output(&self, id: &SandboxId) -> Option<OutputSubscription> {
        self.sandboxes.get(id).and_then(|m| {
            let rx = m.output_tx.as_ref()?.subscribe();
            let buffer = m.output_buffer.lock().ok()?.clone();
            Some((buffer, rx))
        })
    }
}

async fn ensure_inference_server_from_shared(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    policy: &Policy,
) -> Option<SocketAddr> {
    {
        let manager = mgr.lock().await;
        if let Some(addr) = current_inference_endpoint(&manager) {
            return Some(addr);
        }
    }

    let (server, addr) = start_inference_server_for_policy(policy).await?;

    let mut manager = mgr.lock().await;
    if let Some(existing_addr) = current_inference_endpoint(&manager) {
        return Some(existing_addr);
    }
    manager.inference_server = Some(server);
    Some(addr)
}

fn current_inference_endpoint(manager: &SandboxManager) -> Option<SocketAddr> {
    manager
        .inference_server
        .as_ref()
        .filter(|server| server.healthy)
        .and_then(|server| server.addr())
}

async fn start_inference_server_for_policy(
    policy: &Policy,
) -> Option<(InferenceServer, SocketAddr)> {
    let (model_path, mode) = inference_server_start_plan(policy)?;

    let mut server = InferenceServer::new(mode);
    match server.start(&model_path).await {
        Ok(addr) => {
            tracing::info!(
                "inference: server started on {addr} (model={})",
                model_path.display()
            );
            Some((server, addr))
        }
        Err(e) => {
            tracing::warn!("inference: server start failed: {e}");
            None
        }
    }
}

fn inference_server_start_plan(policy: &Policy) -> Option<(PathBuf, ServerMode)> {
    let local_route = policy.inference.routes.iter().find(|r| {
        r.endpoint.is_some()
            && r.endpoint.as_ref().is_some_and(|e| {
                e.starts_with("http://localhost") || e.starts_with("http://127.0.0.1")
            })
    });

    if local_route.is_none() && policy.inference.routes.is_empty() {
        return None;
    }

    let registry = axis_router::models::ModelRegistry::new();
    let model_path = policy.inference.routes.iter().find_map(|r| {
        r.model.as_ref().and_then(|name| {
            registry
                .get(name)
                .and_then(|entry| entry.local_path.clone())
        })
    });

    let Some(model_path) = model_path else {
        tracing::info!("inference: no local model available, skipping server start");
        return None;
    };

    let mode = if which_exists("llama-server") {
        ServerMode::Managed {
            backend: ManagedBackend::LlamaServer,
            binary: PathBuf::from("llama-server"),
            extra_args: vec![],
        }
    } else {
        ServerMode::Embedded {
            n_gpu_layers: 0,
            context_size: 4096,
        }
    };

    Some((model_path, mode))
}

async fn spawn_gpu_worker_from_shared(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    id: SandboxId,
    policy: &Policy,
    workspace_dir: &Path,
) -> Vec<(String, String)> {
    if !policy.gpu.enabled {
        return Vec::new();
    }

    // The worker enforces none of transport: uds, the VRAM limit, the compute
    // timeout, or API lists. Both production callers of create_from_shared
    // (IPC create and SandboxManagerBackend) load the policy with
    // Policy::from_yaml, which runs axis_core::policy::GpuPolicy::validate and
    // rejects those fields while gpu.enabled is true. A Policy built in code
    // skips that step and reaches this spawn unvalidated, but Sandbox::create
    // validates it afterwards and fails before user code runs.
    let gpu_filter_policy = GpuFilterPolicy {
        enabled: true,
        device: policy.gpu.device,
        transport: match policy.gpu.transport {
            axis_core::policy::GpuTransport::Uds => axis_gpu::api_filter::GpuTransport::Uds,
            axis_core::policy::GpuTransport::Tcp => axis_gpu::api_filter::GpuTransport::Tcp,
        },
        vram_limit_mb: policy.gpu.vram_limit_mb,
        compute_timeout_sec: policy.gpu.compute_timeout_sec,
        allowed_apis: Vec::new(),
        denied_apis: Vec::new(),
    };

    let endpoint_result = {
        let mut manager = mgr.lock().await;
        manager
            .gpu_manager
            .spawn_worker(id, &gpu_filter_policy, workspace_dir)
    };

    match endpoint_result {
        Ok(endpoint) => {
            tracing::info!("sandbox {id}: GPU worker on {endpoint}");
            let mut extra_env = endpoint.to_env_vars();
            if let Some(dir) = find_hip_client_lib() {
                extra_env.push(("LD_LIBRARY_PATH".into(), dir));
            }
            extra_env
        }
        Err(e) => {
            tracing::warn!("sandbox {id}: GPU worker failed: {e} (sandbox will run without GPU)");
            Vec::new()
        }
    }
}

async fn stop_gpu_worker_from_shared(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    id: &SandboxId,
) {
    let mut manager = mgr.lock().await;
    if let Err(e) = manager.gpu_manager.stop_worker(id) {
        tracing::warn!("sandbox {id}: GPU worker cleanup: {e}");
    }
}

struct StartManagedSandboxArgs {
    id: SandboxId,
    policy: Policy,
    policy_name: String,
    gpu_enabled: bool,
    command: String,
    args: Vec<String>,
    env: SandboxEnv,
    extra_env: SandboxEnv,
    workspace_dir: PathBuf,
    proxy_addr: Option<SocketAddr>,
    connect_attribution: Option<axis_core::connect_attribution::ConnectAttributionStore>,
    proxy_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

fn start_managed_sandbox(input: StartManagedSandboxArgs) -> Result<ManagedSandbox, String> {
    let StartManagedSandboxArgs {
        id,
        policy,
        policy_name,
        gpu_enabled,
        command,
        args,
        env,
        extra_env,
        workspace_dir,
        proxy_addr,
        connect_attribution,
        proxy_shutdown,
    } = input;

    let mut all_env = env;
    all_env.extend(extra_env);
    apply_platform_sandbox_env_filter(&mut all_env);

    let timeout_sec = policy.process.timeout_sec;
    tracing::info!("sandbox {id}: spawning: {command} {}", args.join(" "));
    let config = SandboxConfig {
        id,
        policy: policy.clone(),
        command,
        args,
        working_dir: None,
        workspace_dir,
        env: all_env.clone(),
        proxy_port: proxy_addr.map(|addr| addr.port()).unwrap_or(0),
        proxy_addr,
        connect_attribution,
        capture_output: true,
        interactive_terminal: false,
        pty_bridge_helper: None,
        timeout_sec,
        backend_preflight: Default::default(),
        startup_trace: None,
    };

    let mut sandbox = match Sandbox::create(config) {
        Ok(sandbox) => sandbox,
        Err(e) => {
            shutdown_proxy(proxy_shutdown);
            return Err(e.to_string());
        }
    };
    if let Err(e) = sandbox.start() {
        let cleanup_error = sandbox.destroy().err();
        shutdown_proxy(proxy_shutdown);
        if let Some(cleanup_error) = cleanup_error {
            return Err(format!("sandbox start: {e}; cleanup: {cleanup_error}"));
        }
        return Err(format!("sandbox start: {e}"));
    }

    let gpu_label = if gpu_enabled { ", gpu=on" } else { "" };
    let proxy_label = proxy_addr
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "none".into());
    tracing::info!(
        "sandbox {id}: started (pid={}, proxy={proxy_label}, policy='{policy_name}'{gpu_label})",
        sandbox.pid.unwrap_or(0),
    );

    Ok(managed_sandbox_from_started(
        sandbox,
        policy,
        all_env,
        proxy_addr,
        proxy_shutdown,
        gpu_enabled,
        policy_name,
    ))
}

fn managed_sandbox_from_started(
    mut sandbox: Sandbox,
    policy: Policy,
    all_env: Vec<(String, String)>,
    proxy_addr: Option<SocketAddr>,
    proxy_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    gpu_enabled: bool,
    policy_name: String,
) -> ManagedSandbox {
    let id = sandbox.id;
    let (output_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
    let output_buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    tracing::info!(
        "sandbox {id}: stdout={}, stderr={}, stdin={}, pty_read={}",
        sandbox.stdout.is_some(),
        sandbox.stderr.is_some(),
        sandbox.stdin.is_some(),
        sandbox.pty_read.is_some()
    );

    let stdout_log = sandbox.workspace_dir.join("stdout.log");
    if stdout_log.exists() && sandbox.stdout.is_none() {
        let tx = output_tx.clone();
        let buf_clone = output_buffer.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, BufReader};
            let file = match std::fs::File::open(&stdout_log) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("can't open stdout.log: {e}");
                    return;
                }
            };
            let mut reader = BufReader::new(file);
            let mut eof_count = 0;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        eof_count += 1;
                        if eof_count > 600 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Ok(_) => {
                        eof_count = 0;
                        let data = line.into_bytes();
                        if let Ok(mut b) = buf_clone.lock() {
                            b.push(data.clone());
                            if b.len() > 1000 {
                                b.drain(..500);
                            }
                        }
                        if tx.send(data).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    if let Some(pty_read) = sandbox.pty_read.take() {
        let tx = output_tx.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut reader = pty_read;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = tx.send(buf[..n].to_vec());
                    }
                    Err(_) => break,
                }
            }
        });
    } else {
        if let Some(stdout) = sandbox.stdout.take() {
            let tx = output_tx.clone();
            let buf_clone = output_buffer.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut stdout = stdout;
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            if let Ok(mut b) = buf_clone.lock() {
                                b.push(data.clone());
                                if b.len() > 1000 {
                                    b.drain(..500);
                                }
                            }
                            let _ = tx.send(data);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        if let Some(stderr) = sandbox.stderr.take() {
            let tx = output_tx.clone();
            let buf_clone = output_buffer.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let mut stderr = stderr;
                let mut buf = [0u8; 4096];
                loop {
                    match stderr.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = buf[..n].to_vec();
                            if let Ok(mut b) = buf_clone.lock() {
                                b.push(data.clone());
                                if b.len() > 1000 {
                                    b.drain(..500);
                                }
                            }
                            let _ = tx.send(data);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    if let Some(stdin) = sandbox.stdin.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stdin = tokio::process::ChildStdin::from_std(stdin).unwrap();
            while let Some(data) = input_rx.recv().await {
                if stdin.write_all(&data).await.is_err() {
                    break;
                }
                if stdin.flush().await.is_err() {
                    break;
                }
            }
        });
    }

    ManagedSandbox {
        sandbox,
        policy,
        env: all_env,
        proxy_addr,
        proxy_shutdown,
        gpu_enabled,
        policy_name,
        output_tx: Some(output_tx),
        output_buffer,
        input_tx: Some(input_tx),
    }
}

async fn run_contained_exec(
    policy: Policy,
    workspace: PathBuf,
    env: SandboxEnv,
    inference_endpoint: Option<SocketAddr>,
    #[cfg(target_os = "linux")] bypass_audit_tokens: BypassAuditTokens,
    command: String,
    args: Vec<String>,
) -> Result<i32, String> {
    let exec_id = SandboxId::new();
    #[cfg(target_os = "linux")]
    let _bypass_audit_registration = scoped_bypass_audit_token_registration(
        &bypass_audit_tokens,
        exec_id,
        policy_uses_proxy(&policy),
    );
    let (exec_proxy_addr, mut exec_proxy_shutdown, exec_connect_attribution) =
        start_proxy_for_sandbox(exec_id, &policy, inference_endpoint).await?;
    let config = contained_exec_config_from(ContainedExecConfigInput {
        policy: &policy,
        workspace_dir: &workspace,
        env: &env,
        exec_id,
        proxy_addr: exec_proxy_addr,
        connect_attribution: exec_connect_attribution,
        command: command.clone(),
        args: args.clone(),
    });
    let exec_workspace = config.workspace_dir.clone();

    tracing::info!(
        "exec sandbox {exec_id}: '{command}' in {}",
        workspace.display()
    );

    let mut exec_sandbox = match Sandbox::create_for_exec(config) {
        Ok(sandbox) => sandbox,
        Err(e) => {
            shutdown_proxy(exec_proxy_shutdown.take());
            cleanup_contained_exec_workspace(&exec_workspace);
            return Err(format!("exec sandbox create: {e}"));
        }
    };
    if let Err(e) = exec_sandbox.start() {
        let _ = exec_sandbox.destroy();
        shutdown_proxy(exec_proxy_shutdown.take());
        cleanup_contained_exec_workspace(&exec_workspace);
        return Err(format!("exec sandbox start: {e}"));
    }
    let code = match exec_sandbox.wait().await {
        Ok(code) => code,
        Err(e) => {
            let _ = exec_sandbox.destroy();
            shutdown_proxy(exec_proxy_shutdown.take());
            cleanup_contained_exec_workspace(&exec_workspace);
            return Err(format!("exec sandbox wait: {e}"));
        }
    };
    if let Err(e) = exec_sandbox.destroy() {
        shutdown_proxy(exec_proxy_shutdown.take());
        cleanup_contained_exec_workspace(&exec_workspace);
        return Err(format!("exec sandbox cleanup: {e}"));
    }
    shutdown_proxy(exec_proxy_shutdown.take());
    cleanup_contained_exec_workspace(&exec_workspace);

    tracing::info!("exec sandbox {exec_id}: '{command}' exited with code {code}");
    Ok(code)
}

#[derive(Debug, serde::Serialize)]
pub struct SandboxInfo {
    pub id: SandboxId,
    pub status: SandboxStatus,
    pub policy_name: String,
    pub pid: Option<u32>,
    pub workspace: PathBuf,
    pub proxy_addr: String,
    pub gpu_worker: Option<String>,
}

/// Collect essential environment variables for sandbox child processes.
/// Mirrors the logic from axis-cli's env passthrough.
fn collect_sandbox_env() -> Vec<(String, String)> {
    collect_sandbox_env_from(std::env::vars())
}

fn collect_sandbox_env_from<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env = Vec::new();
    for (key, val) in vars {
        let key_cmp = if cfg!(windows) {
            key.to_uppercase()
        } else {
            key.clone()
        };
        // Skip internal session tracking vars. Provider credentials are
        // stripped by the shared sandbox env classifier below.
        if matches!(key_cmp.as_str(), "CLAUDECODE" | "CLAUDE_AGENT_SDK_VERSION") {
            continue;
        }

        if axis_core::sandbox_env::is_collected_sandbox_env_key(&key_cmp) {
            env.push((key, val));
        }
    }
    env
}

fn apply_platform_sandbox_env_filter(env: &mut Vec<(String, String)>) {
    #[cfg(target_os = "linux")]
    axis_core::sandbox_env::retain_linux_sandbox_env(env);

    #[cfg(not(target_os = "linux"))]
    let _ = env;
}

fn allocate_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

fn policy_uses_proxy(policy: &Policy) -> bool {
    matches!(policy.network.mode, NetworkMode::Proxy)
}

fn ensure_sandbox_running(id: &SandboxId, status: SandboxStatus) -> Result<(), String> {
    if matches!(status, SandboxStatus::Running) {
        Ok(())
    } else {
        Err(format!("sandbox is not running: {id} ({status:?})"))
    }
}

async fn start_proxy_for_sandbox(
    id: SandboxId,
    policy: &Policy,
    inference_endpoint: Option<SocketAddr>,
) -> Result<ProxyStart, String> {
    if !policy_uses_proxy(policy) {
        tracing::info!(
            "sandbox {id}: network proxy disabled for {:?} mode",
            policy.network.mode
        );
        return Ok((None, None, None));
    }

    let proxy_port = allocate_port();
    let connect_attribution =
        if axis_core::connect_attribution::policy_requires_connect_attribution(policy) {
            Some(axis_core::connect_attribution::ConnectAttributionStore::default())
        } else {
            None
        };
    let proxy_config = proxy_config_for_sandbox(
        id,
        policy,
        inference_endpoint,
        proxy_port,
        connect_attribution.clone(),
    )
    .expect("proxy config must exist for proxy-mode policy");

    let mut proxy = AxisProxy::new(proxy_config).map_err(|e| format!("proxy init: {e}"))?;
    let proxy_addr = proxy.bind().await.map_err(|e| format!("proxy bind: {e}"))?;

    tracing::info!("sandbox {id}: proxy on {proxy_addr}");

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::select! {
            result = proxy.run() => {
                if let Err(e) = result {
                    tracing::error!("proxy for sandbox exited: {e}");
                }
            }
            _ = &mut shutdown_rx => {
                tracing::info!("proxy shutdown signal received");
            }
        }
    });

    Ok((Some(proxy_addr), Some(shutdown_tx), connect_attribution))
}

fn proxy_config_for_sandbox(
    id: SandboxId,
    policy: &Policy,
    inference_endpoint: Option<SocketAddr>,
    proxy_port: u16,
    connect_attribution: Option<axis_core::connect_attribution::ConnectAttributionStore>,
) -> Option<ProxyConfig> {
    if !policy_uses_proxy(policy) {
        return None;
    }

    Some(ProxyConfig {
        sandbox_id: id,
        bind_addr: proxy_bind_addr_for_sandbox(id, proxy_port, policy),
        policy: policy.clone(),
        enable_leak_detection: true,
        inference_endpoint,
        connect_attribution,
        enable_identity_diagnostics: false,
        timing_tx: None,
    })
}

fn proxy_bind_addr_for_sandbox(id: SandboxId, proxy_port: u16, policy: &Policy) -> SocketAddr {
    #[cfg(target_os = "linux")]
    {
        if policy_uses_proxy(policy) {
            return axis_sandbox::linux::netns::proxy_bind_addr(id, proxy_port);
        }
    }

    let _ = id;
    #[cfg(not(target_os = "linux"))]
    let _ = policy;
    format!("127.0.0.1:{proxy_port}").parse().unwrap()
}

fn shutdown_proxy(tx: Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(tx) = tx {
        let _ = tx.send(());
    }
}

#[cfg(target_os = "linux")]
fn register_bypass_audit_token(tokens: &BypassAuditTokens, id: SandboxId) {
    let token = axis_sandbox::linux::bypass_audit::bypass_log_token(id);
    match tokens.lock() {
        Ok(mut tokens) => {
            tokens.insert(token, id);
        }
        Err(_) => tracing::warn!("sandbox {id}: bypass audit token registry is poisoned"),
    }
}

#[cfg(target_os = "linux")]
fn unregister_bypass_audit_token(tokens: &BypassAuditTokens, id: SandboxId) {
    let token = axis_sandbox::linux::bypass_audit::bypass_log_token(id);
    match tokens.lock() {
        Ok(mut tokens) => {
            tokens.remove(&token);
        }
        Err(_) => tracing::warn!("sandbox {id}: bypass audit token registry is poisoned"),
    }
}

#[cfg(target_os = "linux")]
struct ScopedBypassAuditTokenRegistration {
    tokens: BypassAuditTokens,
    id: SandboxId,
    registered: bool,
}

#[cfg(target_os = "linux")]
fn scoped_bypass_audit_token_registration(
    tokens: &BypassAuditTokens,
    id: SandboxId,
    enabled: bool,
) -> ScopedBypassAuditTokenRegistration {
    if enabled {
        register_bypass_audit_token(tokens, id);
    }
    ScopedBypassAuditTokenRegistration {
        tokens: tokens.clone(),
        id,
        registered: enabled,
    }
}

#[cfg(target_os = "linux")]
impl Drop for ScopedBypassAuditTokenRegistration {
    fn drop(&mut self) {
        if self.registered {
            unregister_bypass_audit_token(&self.tokens, self.id);
            self.registered = false;
        }
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn spawn_linux_bypass_audit_collector(
    tokens: BypassAuditTokens,
    event_tx: Option<tokio::sync::broadcast::Sender<AuditEvent>>,
) {
    if let Err(e) = std::thread::Builder::new()
        .name("axis-bypass-audit".into())
        .spawn(move || run_linux_bypass_audit_collector(tokens, event_tx))
    {
        tracing::warn!("linux bypass audit collector disabled: {e}");
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn run_linux_bypass_audit_collector(
    tokens: BypassAuditTokens,
    event_tx: Option<tokio::sync::broadcast::Sender<AuditEvent>>,
) {
    let mut audit = AuditLog::new();
    audit.add_sink(Box::new(TracingSink));
    if let Some(tx) = event_tx {
        audit.add_sink(Box::new(BroadcastSink::new(tx)));
    }

    let file = match axis_sandbox::linux::bypass_audit::open_kernel_log_source() {
        Ok(file) => file,
        Err(e) => {
            tracing::info!("linux bypass audit collector disabled: cannot read /dev/kmsg: {e}");
            return;
        }
    };
    let mut reader = std::io::BufReader::new(file);

    loop {
        let token_snapshot = match tokens.lock() {
            Ok(tokens) => tokens.clone(),
            Err(_) => {
                tracing::warn!("linux bypass audit collector stopped: token registry is poisoned");
                return;
            }
        };

        if let Err(e) = axis_sandbox::linux::bypass_audit::collect_available_bypass_events(
            &mut reader,
            &token_snapshot,
            &audit,
        ) && e.kind() != std::io::ErrorKind::Interrupted
        {
            tracing::warn!("linux bypass audit collector read failed: {e}");
        }

        std::thread::sleep(std::time::Duration::from_millis(
            BYPASS_AUDIT_POLL_INTERVAL_MS,
        ));
    }
}

fn spawn_sandbox_lifecycle(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    id: SandboxId,
    timeout_sec: Option<u64>,
) -> tokio::task::JoinHandle<()> {
    spawn_sandbox_lifecycle_after(
        mgr,
        id,
        timeout_sec.map(std::time::Duration::from_secs),
        std::time::Duration::from_millis(LIFECYCLE_REAP_INTERVAL_MS),
        std::time::Duration::from_millis(TIMEOUT_DESTROY_RETRY_DELAY_MS),
    )
}

fn spawn_sandbox_lifecycle_after(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    id: SandboxId,
    timeout: Option<std::time::Duration>,
    reap_interval: std::time::Duration,
    retry_delay: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        loop {
            {
                let mut manager = mgr.lock().await;
                match manager.reap_exited(&id) {
                    Ok(Some(_)) => return,
                    Ok(None) if !manager.sandboxes.contains_key(&id) => return,
                    Ok(None)
                        if !manager.sandboxes.get(&id).is_some_and(|managed| {
                            matches!(managed.sandbox.status, SandboxStatus::Running)
                        }) =>
                    {
                        return;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("sandbox {id}: lifecycle reaper failed: {e}");
                        return;
                    }
                }
            }

            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                destroy_sandbox_after_timeout(mgr.clone(), id, timeout, retry_delay).await;
                return;
            }

            tokio::time::sleep(reap_interval).await;
        }
    })
}

async fn destroy_sandbox_after_timeout(
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
    id: SandboxId,
    timeout: Option<std::time::Duration>,
    retry_delay: std::time::Duration,
) {
    destroy_sandbox_after_timeout_with(
        id,
        timeout,
        retry_delay,
        TIMEOUT_DESTROY_ATTEMPTS,
        move |id| {
            let mgr = mgr.clone();
            async move {
                let mut manager = mgr.lock().await;
                manager.destroy(&id)
            }
        },
    )
    .await;
}

async fn destroy_sandbox_after_timeout_with<D, Fut>(
    id: SandboxId,
    timeout: Option<std::time::Duration>,
    retry_delay: std::time::Duration,
    max_attempts: usize,
    mut destroy: D,
) where
    D: FnMut(SandboxId) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    for attempt in 1..=max_attempts {
        let destroy_result = destroy(id).await;
        match destroy_result {
            Ok(()) => {
                if let Some(timeout) = timeout {
                    tracing::warn!(
                        "sandbox {id}: destroyed after {}s timeout",
                        timeout.as_secs()
                    );
                }
                return;
            }
            Err(e) if e.contains("sandbox not found") => return,
            Err(e) if attempt == max_attempts => {
                tracing::warn!("sandbox {id}: timeout cleanup failed: {e}");
            }
            Err(e) => {
                tracing::warn!("sandbox {id}: timeout cleanup attempt {attempt} failed: {e}");
                tokio::time::sleep(retry_delay).await;
            }
        }
    }
}

struct ContainedExecConfigInput<'a> {
    policy: &'a Policy,
    workspace_dir: &'a Path,
    env: &'a [(String, String)],
    exec_id: SandboxId,
    proxy_addr: Option<SocketAddr>,
    connect_attribution: Option<axis_core::connect_attribution::ConnectAttributionStore>,
    command: String,
    args: Vec<String>,
}

fn contained_exec_config_from(input: ContainedExecConfigInput<'_>) -> SandboxConfig {
    let ContainedExecConfigInput {
        policy,
        workspace_dir,
        env,
        exec_id,
        proxy_addr,
        connect_attribution,
        command,
        args,
    } = input;
    let exec_workspace = contained_exec_workspace_dir(workspace_dir, exec_id);
    let mut policy = policy.clone();
    let workspace_policy_path = workspace_dir.to_string_lossy().into_owned();
    if !policy
        .filesystem
        .read_write
        .iter()
        .any(|path| path == &workspace_policy_path)
    {
        policy.filesystem.read_write.push(workspace_policy_path);
    }
    let timeout_sec = policy.process.timeout_sec;

    SandboxConfig {
        id: exec_id,
        policy,
        command,
        args,
        working_dir: Some(workspace_dir.to_path_buf()),
        workspace_dir: exec_workspace,
        env: env.to_vec(),
        proxy_port: proxy_addr.map(|addr| addr.port()).unwrap_or(0),
        proxy_addr,
        connect_attribution,
        capture_output: true,
        interactive_terminal: false,
        pty_bridge_helper: None,
        timeout_sec,
        backend_preflight: Default::default(),
        startup_trace: None,
    }
}

fn contained_exec_workspace_dir(workspace_dir: &Path, exec_id: SandboxId) -> PathBuf {
    workspace_dir
        .join(EXEC_OUTPUT_DIR)
        .join(exec_id.to_string())
}

fn cleanup_contained_exec_workspace(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("failed to remove exec workspace {}: {e}", path.display()),
    }
}

fn cleanup_failed_create_workspace(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            "failed to remove sandbox workspace after create failure {}: {e}",
            path.display()
        ),
    }
}

fn which_exists(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn find_hip_client_lib() -> Option<String> {
    // Find the directory containing the hip-remote client library (libamdhip64.so).
    for candidate in &[
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../hip-remote/build-client"),
        "/usr/local/lib",
        "/usr/lib",
    ] {
        let dir = PathBuf::from(candidate);
        if dir.join("libamdhip64.so").exists() {
            return Some(dir.to_string_lossy().into());
        }
    }
    None
}

fn find_hip_worker() -> PathBuf {
    // Check common locations for the hip-worker binary.
    for candidate in &[
        // AXIS build directory (development)
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hip-remote/build-worker/hip-worker"
        ),
        "/usr/local/bin/hip-worker",
        "/usr/bin/hip-worker",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    // Default: expect it in PATH.
    PathBuf::from("hip-worker")
}

fn dirs_base() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("axis").join("sandboxes")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("axis")
            .join("sandboxes")
    } else {
        PathBuf::from("/tmp/axis/sandboxes")
    }
}

// ── Gateway Backend ─────────────────────────────────────────────────────

/// Wraps `SandboxManager` behind `Arc<Mutex<>>` to implement `SandboxBackend`
/// for the gateway. All methods acquire the mutex for each operation.
pub struct SandboxManagerBackend {
    mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
}

impl SandboxManagerBackend {
    pub fn new(mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>) -> Self {
        Self { mgr }
    }
}

impl SandboxBackend for SandboxManagerBackend {
    fn create_sandbox(
        &self,
        policy_yaml: &str,
        command: String,
        args: Vec<String>,
    ) -> DaemonBackendFuture<'_, Result<String, String>> {
        let policy_yaml = policy_yaml.to_string();
        let mgr_handle = self.mgr.clone();
        // Collect essential env vars for the sandbox (same logic as axis-cli).
        let env = collect_sandbox_env();
        let claude_vars: Vec<_> = env
            .iter()
            .filter(|(k, _)| {
                k.to_uppercase().contains("CLAUDE") || k.to_uppercase().contains("ANTHROPIC")
            })
            .map(|(k, v)| format!("{}={}...", k, &v[..v.len().min(20)]))
            .collect();
        tracing::info!(
            "gateway create_sandbox: {} env vars, auth: {:?}",
            env.len(),
            claude_vars
        );
        Box::pin(async move {
            let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)
                .map_err(|e| format!("invalid policy: {e}"))?;
            let id =
                SandboxManager::create_from_shared(mgr_handle.clone(), policy, command, args, env)
                    .await?;
            Ok(id.to_string())
        })
    }

    fn destroy_sandbox(&self, id: &str) -> DaemonBackendFuture<'_, Result<(), String>> {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id
                .parse()
                .map_err(|_| format!("invalid sandbox id: {id}"))?;
            let mut mgr = self.mgr.lock().await;
            mgr.destroy(&sandbox_id)
        })
    }

    fn list_sandboxes(&self) -> DaemonBackendFuture<'_, Vec<serde_json::Value>> {
        Box::pin(async move {
            let mgr = self.mgr.lock().await;
            mgr.list()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id.to_string(),
                        "status": format!("{:?}", s.status),
                        "policy_name": s.policy_name,
                        "pid": s.pid,
                        "proxy_addr": s.proxy_addr,
                        "gpu_worker": s.gpu_worker,
                    })
                })
                .collect()
        })
    }

    fn subscribe_output(&self, id: &str) -> DaemonBackendFuture<'_, Option<OutputSubscription>> {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id.parse().ok()?;
            let mgr = self.mgr.lock().await;
            mgr.subscribe_output(&sandbox_id)
        })
    }

    fn send_input(&self, id: &str, data: Vec<u8>) -> DaemonBackendFuture<'_, Result<(), String>> {
        let id = id.to_string();
        Box::pin(async move {
            let sandbox_id: axis_core::types::SandboxId = id
                .parse()
                .map_err(|_| format!("invalid sandbox id: {id}"))?;
            let tx = {
                let mgr = self.mgr.lock().await;
                mgr.get_input_sender(&sandbox_id)
                    .ok_or_else(|| "sandbox not found or stdin not available".to_string())?
            };
            tx.send(data).await.map_err(|e| format!("stdin send: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkPolicy, ProcessPolicy, SshPolicy,
    };
    use std::str::FromStr;

    #[test]
    fn block_mode_does_not_use_daemon_proxy() {
        let policy = test_policy(NetworkMode::Block);

        assert!(!policy_uses_proxy(&policy));
    }

    #[test]
    fn allow_mode_does_not_use_daemon_proxy() {
        let policy = test_policy(NetworkMode::Allow);

        assert!(!policy_uses_proxy(&policy));
    }

    #[test]
    fn proxy_mode_uses_daemon_proxy() {
        let policy = test_policy(NetworkMode::Proxy);

        assert!(policy_uses_proxy(&policy));
    }

    #[test]
    fn proxy_config_is_omitted_for_non_proxy_modes() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();

        for mode in [NetworkMode::Block, NetworkMode::Allow] {
            let policy = test_policy(mode);

            assert!(proxy_config_for_sandbox(id, &policy, None, 3128, None).is_none());
        }
    }

    #[test]
    fn proxy_config_uses_netns_bind_addr_for_proxy_mode() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let policy = test_policy(NetworkMode::Proxy);
        let inference_endpoint = Some("127.0.0.1:9000".parse().unwrap());
        let config = proxy_config_for_sandbox(id, &policy, inference_endpoint, 3128, None)
            .expect("proxy mode should plan a proxy config");

        assert_eq!(config.sandbox_id, id);
        assert_eq!(
            config.bind_addr,
            proxy_bind_addr_for_sandbox(id, 3128, &policy)
        );
        assert!(config.enable_leak_detection);
        assert_eq!(config.inference_endpoint, inference_endpoint);
    }

    #[tokio::test]
    async fn start_proxy_for_sandbox_returns_none_for_non_proxy_modes() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();

        for mode in [NetworkMode::Block, NetworkMode::Allow] {
            let policy = test_policy(mode);
            let (proxy_addr, proxy_shutdown, connect_attribution) =
                start_proxy_for_sandbox(id, &policy, None).await.unwrap();

            assert!(proxy_addr.is_none());
            assert!(proxy_shutdown.is_none());
            assert!(connect_attribution.is_none());
        }
    }

    #[test]
    fn proxy_mode_uses_linux_netns_bind_addr() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let policy = test_policy(NetworkMode::Proxy);
        let bind_addr = proxy_bind_addr_for_sandbox(id, 3128, &policy);

        #[cfg(target_os = "linux")]
        assert_eq!(
            bind_addr,
            axis_sandbox::linux::netns::proxy_bind_addr(id, 3128)
        );

        #[cfg(not(target_os = "linux"))]
        assert_eq!(bind_addr, "127.0.0.1:3128".parse().unwrap());
    }

    #[test]
    fn non_proxy_modes_keep_loopback_bind_addr() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();

        for mode in [NetworkMode::Block, NetworkMode::Allow] {
            let policy = test_policy(mode);

            assert_eq!(
                proxy_bind_addr_for_sandbox(id, 3128, &policy),
                "127.0.0.1:3128".parse().unwrap()
            );
        }
    }

    #[test]
    fn daemon_env_collection_omits_provider_secrets_and_proxy_vars() {
        let env = collect_sandbox_env_from(vec![
            ("PATH".into(), "/bin".into()),
            ("ANTHROPIC_API_KEY".into(), "secret".into()),
            ("OPENAI_API_KEY".into(), "secret".into()),
            ("AZURE_STORAGE_CONNECTION_STRING".into(), "secret".into()),
            ("CLAUDE_CODE_OAUTH_TOKEN".into(), "secret".into()),
            ("CLAUDE_CODE_ENTRYPOINT".into(), "entrypoint".into()),
            ("https_proxy".into(), "http://proxy-with-creds".into()),
            ("FTP_PROXY".into(), "http://ftp-proxy-with-creds".into()),
            ("UNRELATED".into(), "value".into()),
        ]);

        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("CLAUDE_CODE_ENTRYPOINT".into(), "entrypoint".into())
            ]
        );
    }

    #[test]
    fn daemon_final_env_filter_is_platform_scoped() {
        let mut env = vec![
            ("PATH".into(), "/bin".into()),
            ("CUSTOM_API_KEY".into(), "secret".into()),
            ("https_proxy".into(), "http://proxy-with-creds".into()),
            ("CUSTOM_CONFIG".into(), "value".into()),
        ];

        apply_platform_sandbox_env_filter(&mut env);

        #[cfg(target_os = "linux")]
        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("CUSTOM_CONFIG".into(), "value".into())
            ]
        );

        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("CUSTOM_API_KEY".into(), "secret".into()),
                ("https_proxy".into(), "http://proxy-with-creds".into()),
                ("CUSTOM_CONFIG".into(), "value".into())
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bypass_audit_token_registry_tracks_active_proxy_sandboxes() {
        let tokens = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let token = axis_sandbox::linux::bypass_audit::bypass_log_token(sandbox_id);

        register_bypass_audit_token(&tokens, sandbox_id);

        assert_eq!(tokens.lock().unwrap().get(&token), Some(&sandbox_id));

        unregister_bypass_audit_token(&tokens, sandbox_id);

        assert!(!tokens.lock().unwrap().contains_key(&token));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scoped_bypass_audit_registration_unregisters_on_drop() {
        let tokens = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000011").unwrap();
        let token = axis_sandbox::linux::bypass_audit::bypass_log_token(sandbox_id);

        {
            let _registration = scoped_bypass_audit_token_registration(&tokens, sandbox_id, true);

            assert_eq!(tokens.lock().unwrap().get(&token), Some(&sandbox_id));
        }

        assert!(!tokens.lock().unwrap().contains_key(&token));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disabled_scoped_bypass_audit_registration_is_noop() {
        let tokens = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let sandbox_id = SandboxId::from_str("00000000-0000-4000-8000-000000000012").unwrap();
        let token = axis_sandbox::linux::bypass_audit::bypass_log_token(sandbox_id);

        let _registration = scoped_bypass_audit_token_registration(&tokens, sandbox_id, false);

        assert!(!tokens.lock().unwrap().contains_key(&token));
    }

    #[test]
    fn contained_exec_config_for_block_mode_omits_proxy_state() {
        let workspace = std::env::temp_dir().join("axis-daemon-block-exec-test");
        let policy = test_policy(NetworkMode::Block);
        let exec_id = SandboxId::from_str("00000000-0000-4000-8000-000000000101").unwrap();

        let env = vec![("PATH".into(), "/bin".into())];
        let config = contained_exec_config_from(ContainedExecConfigInput {
            policy: &policy,
            workspace_dir: &workspace,
            env: &env,
            exec_id,
            proxy_addr: None,
            connect_attribution: None,
            command: "true".into(),
            args: Vec::new(),
        });

        assert_eq!(config.id, exec_id);
        assert!(matches!(config.policy.network.mode, NetworkMode::Block));
        assert_eq!(config.proxy_port, 0);
        assert!(config.proxy_addr.is_none());
        assert_eq!(config.working_dir.as_deref(), Some(workspace.as_path()));
        assert_ne!(config.workspace_dir, workspace);
        assert!(
            config
                .workspace_dir
                .starts_with(workspace.join(EXEC_OUTPUT_DIR))
        );
        assert!(
            config
                .policy
                .filesystem
                .read_write
                .contains(&workspace.to_string_lossy().into_owned())
        );
        assert!(config.capture_output);
    }

    #[test]
    fn contained_exec_config_for_proxy_mode_retains_proxy_state() {
        let workspace = std::env::temp_dir().join("axis-daemon-proxy-exec-test");
        let policy = test_policy(NetworkMode::Proxy);
        let exec_id = SandboxId::from_str("00000000-0000-4000-8000-000000000102").unwrap();
        let proxy_addr = proxy_bind_addr_for_sandbox(exec_id, 3128, &policy);

        let env = vec![("PATH".into(), "/bin".into())];
        let config = contained_exec_config_from(ContainedExecConfigInput {
            policy: &policy,
            workspace_dir: &workspace,
            env: &env,
            exec_id,
            proxy_addr: Some(proxy_addr),
            connect_attribution: None,
            command: "true".into(),
            args: Vec::new(),
        });

        assert_eq!(config.id, exec_id);
        assert!(matches!(config.policy.network.mode, NetworkMode::Proxy));
        assert_eq!(config.proxy_port, 3128);
        assert_eq!(config.proxy_addr, Some(proxy_addr));
        #[cfg(target_os = "linux")]
        assert_eq!(
            config.proxy_addr,
            Some(axis_sandbox::linux::netns::proxy_bind_addr(exec_id, 3128))
        );
        assert_eq!(config.working_dir.as_deref(), Some(workspace.as_path()));
        assert_ne!(config.workspace_dir, workspace);
        assert!(
            config
                .workspace_dir
                .starts_with(workspace.join(EXEC_OUTPUT_DIR))
        );
    }

    #[test]
    fn contained_exec_config_does_not_duplicate_workspace_policy_path() {
        let workspace = std::env::temp_dir().join("axis-daemon-exec-policy-test");
        let workspace_policy_path = workspace.to_string_lossy().into_owned();
        let mut policy = test_policy(NetworkMode::Block);
        policy
            .filesystem
            .read_write
            .push(workspace_policy_path.clone());
        let exec_id = SandboxId::from_str("00000000-0000-4000-8000-000000000103").unwrap();

        let config = contained_exec_config_from(ContainedExecConfigInput {
            policy: &policy,
            workspace_dir: &workspace,
            env: &[],
            exec_id,
            proxy_addr: None,
            connect_attribution: None,
            command: "true".into(),
            args: Vec::new(),
        });

        assert_eq!(
            config
                .policy
                .filesystem
                .read_write
                .iter()
                .filter(|path| *path == &workspace_policy_path)
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timeout_destroy_retries_until_success() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000201").unwrap();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        destroy_sandbox_after_timeout_with(
            id,
            Some(std::time::Duration::from_secs(1)),
            std::time::Duration::from_millis(1),
            3,
            {
                let attempts = attempts.clone();
                move |_| {
                    let attempts = attempts.clone();
                    async move {
                        let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if attempt < 2 {
                            Err("cleanup failed".to_string())
                        } else {
                            Ok(())
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn timeout_destroy_stops_retrying_after_final_failure() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000202").unwrap();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        destroy_sandbox_after_timeout_with(
            id,
            Some(std::time::Duration::from_secs(1)),
            std::time::Duration::from_millis(1),
            3,
            {
                let attempts = attempts.clone();
                move |_| {
                    let attempts = attempts.clone();
                    async move {
                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Err("cleanup failed".to_string())
                    }
                }
            },
        )
        .await;

        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn exec_context_rejects_non_running_parent_status() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000203").unwrap();

        assert!(ensure_sandbox_running(&id, SandboxStatus::Running).is_ok());
        for status in [
            SandboxStatus::Creating,
            SandboxStatus::Stopping,
            SandboxStatus::Stopped,
            SandboxStatus::Failed,
        ] {
            let err = ensure_sandbox_running(&id, status).unwrap_err();

            assert!(err.contains("not running"));
        }
    }

    #[test]
    fn cleanup_contained_exec_workspace_removes_only_exec_workspace() {
        let workspace = std::env::temp_dir().join(format!(
            "axis-daemon-exec-cleanup-test-{}",
            SandboxId::new()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let exec_workspace = contained_exec_workspace_dir(&workspace, SandboxId::new());
        std::fs::create_dir_all(&exec_workspace).unwrap();
        std::fs::write(exec_workspace.join("stdout.log"), b"exec output").unwrap();

        cleanup_contained_exec_workspace(&exec_workspace);

        assert!(workspace.exists());
        assert!(!exec_workspace.exists());
        std::fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn cleanup_failed_create_workspace_removes_sandbox_workspace() {
        let workspace = std::env::temp_dir().join(format!(
            "axis-daemon-create-cleanup-test-{}",
            SandboxId::new()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("stdout.log"), b"partial create output").unwrap();

        cleanup_failed_create_workspace(&workspace);

        assert!(!workspace.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_reaps_exited_sandbox_and_updates_status() {
        if !std::path::Path::new("/bin/true").exists() {
            eprintln!("/bin/true unavailable (test skipped)");
            return;
        }
        let (mgr, base_dir) = runtime_manager("axis-daemon-lifecycle-reap");
        let policy = runtime_policy(NetworkMode::Allow, None);
        let Some(id) =
            create_runtime_sandbox_or_skip(mgr.clone(), policy, "/bin/true".into(), Vec::new())
                .await
        else {
            let _ = std::fs::remove_dir_all(base_dir);
            return;
        };

        assert!(
            wait_for_sandbox_status(mgr.clone(), id, SandboxStatus::Stopped).await,
            "sandbox was not reaped to stopped status"
        );
        mgr.lock().await.destroy(&id).unwrap();
        let _ = std::fs::remove_dir_all(base_dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn lifecycle_timeout_destroys_sandbox_without_caller_wait() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }
        let (mgr, base_dir) = runtime_manager("axis-daemon-lifecycle-timeout");
        let policy = runtime_policy(NetworkMode::Allow, Some(1));
        let Some(id) = create_runtime_sandbox_or_skip(
            mgr.clone(),
            policy,
            "/bin/sh".into(),
            vec!["-c".into(), "sleep 10".into()],
        )
        .await
        else {
            let _ = std::fs::remove_dir_all(base_dir);
            return;
        };

        assert!(
            wait_for_sandbox_absent(mgr.clone(), id).await,
            "timed-out sandbox remained registered"
        );
        let _ = std::fs::remove_dir_all(base_dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn contained_exec_cannot_read_unallowed_host_file() {
        if !std::path::Path::new("/bin/sh").exists() || !std::path::Path::new("/bin/cat").exists() {
            eprintln!("/bin/sh or /bin/cat unavailable (test skipped)");
            return;
        }
        let (mgr, base_dir) = runtime_manager("axis-daemon-exec-fs");
        let denied_path = base_dir.join("host-denied.txt");
        std::fs::write(&denied_path, b"secret").unwrap();
        let mut policy = runtime_policy(NetworkMode::Allow, None);
        policy
            .filesystem
            .deny
            .push(denied_path.to_string_lossy().into_owned());
        let Some(id) = create_runtime_sandbox_or_skip(
            mgr.clone(),
            policy,
            "/bin/sh".into(),
            vec!["-c".into(), "sleep 10".into()],
        )
        .await
        else {
            let _ = std::fs::remove_dir_all(base_dir);
            return;
        };

        let code = SandboxManager::exec_in_sandbox_from_shared(
            mgr.clone(),
            id,
            "/bin/cat".into(),
            vec![denied_path.to_string_lossy().into_owned()],
        )
        .await
        .unwrap();

        assert_ne!(code, 0, "contained exec read an unallowed host file");
        mgr.lock().await.destroy(&id).unwrap();
        let _ = std::fs::remove_dir_all(base_dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn contained_exec_preserves_block_mode_network_denial() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("/bin/sh unavailable (test skipped)");
            return;
        }
        let Some(python) =
            find_on_path("python3").and_then(|path| std::fs::canonicalize(path).ok())
        else {
            eprintln!("python3 unavailable (test skipped)");
            return;
        };
        let (mgr, base_dir) = runtime_manager("axis-daemon-exec-network");
        let mut policy = runtime_policy(NetworkMode::Block, None);
        if let Some(parent) = python.parent() {
            policy
                .filesystem
                .read_only
                .push(parent.to_string_lossy().into_owned());
        }
        let Some(id) = create_runtime_sandbox_or_skip(
            mgr.clone(),
            policy,
            "/bin/sh".into(),
            vec!["-c".into(), "sleep 10".into()],
        )
        .await
        else {
            let _ = std::fs::remove_dir_all(base_dir);
            return;
        };

        let code = SandboxManager::exec_in_sandbox_from_shared(
            mgr.clone(),
            id,
            python.to_string_lossy().into_owned(),
            vec![
                "-c".into(),
                "import socket, sys\ntry:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError:\n    sys.exit(0)\nelse:\n    s.close(); sys.exit(42)\n".into(),
            ],
        )
        .await
        .unwrap();

        assert_eq!(code, 0, "contained exec bypassed block-mode network denial");
        mgr.lock().await.destroy(&id).unwrap();
        let _ = std::fs::remove_dir_all(base_dir);
    }

    fn test_policy(network_mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test-policy".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: network_mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn runtime_policy(network_mode: NetworkMode, timeout_sec: Option<u64>) -> Policy {
        let mut policy = test_policy(network_mode);
        policy.filesystem = FilesystemPolicy {
            read_only: vec![
                "/bin".into(),
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/nix/store".into(),
                "/etc".into(),
            ],
            read_write: Vec::new(),
            ..Default::default()
        };
        policy.process.timeout_sec = timeout_sec;
        policy.process.cpu_rate_percent = 0;
        policy
    }

    #[cfg(target_os = "linux")]
    fn runtime_manager(
        name: &str,
    ) -> (std::sync::Arc<tokio::sync::Mutex<SandboxManager>>, PathBuf) {
        let base_dir = std::env::temp_dir().join(format!("{name}-{}", SandboxId::new()));
        let _ = std::fs::remove_dir_all(&base_dir);
        std::fs::create_dir_all(&base_dir).unwrap();
        let mut manager = SandboxManager::with_event_broadcast(None);
        manager.sandbox_base_dir = base_dir.clone();
        (
            std::sync::Arc::new(tokio::sync::Mutex::new(manager)),
            base_dir,
        )
    }

    #[cfg(target_os = "linux")]
    async fn create_runtime_sandbox_or_skip(
        mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
        policy: Policy,
        command: String,
        args: Vec<String>,
    ) -> Option<SandboxId> {
        match SandboxManager::create_from_shared(
            mgr,
            policy,
            command,
            args,
            vec![("PATH".into(), "/bin:/usr/bin".into())],
        )
        .await
        {
            Ok(id) => Some(id),
            Err(e) if runtime_create_is_capability_gated(&e) => {
                eprintln!("runtime sandbox unavailable (test skipped): {e}");
                None
            }
            Err(e) => panic!("runtime sandbox create failed: {e}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn runtime_create_is_capability_gated(error: &str) -> bool {
        error.contains("process count rlimit fallback requires a dedicated run_as_user")
            || error.contains("CPU rate limits require writable cgroups v2")
            || error.contains("cgroups v2")
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_sandbox_status(
        mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
        id: SandboxId,
        status: SandboxStatus,
    ) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if mgr
                .lock()
                .await
                .list()
                .iter()
                .any(|sandbox| sandbox.id == id && sandbox.status == status)
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_sandbox_absent(
        mgr: std::sync::Arc<tokio::sync::Mutex<SandboxManager>>,
        id: SandboxId,
    ) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !mgr
                .lock()
                .await
                .list()
                .iter()
                .any(|sandbox| sandbox.id == id)
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    #[cfg(target_os = "linux")]
    fn find_on_path(binary: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(binary);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }
}
