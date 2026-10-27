// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Compare phase-rich startup and proxy metrics across named runtime profiles.

use axis_core::connect_attribution::ConnectAttributionStore;
use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig, ProxyTimingEvent, ProxyTimingOutcome};
use axis_sandbox::{SandboxConfig, StartupTrace};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const DEFAULT_STARTUP_SAMPLES: usize = 10;
const DEFAULT_OPA_EVALS: u64 = 50_000;
const DEFAULT_PROXY_BASELINE_CONNS: u32 = 50;
const DEFAULT_PROXY_REQUESTS: u32 = 100;
const STRICT_PROXY_PORT: u16 = 31_280;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = BenchmarkConfig::from_env()?;
    let mut rows = Vec::new();

    for profile in &config.profiles {
        if !config.providers.contains(&profile.provider()) {
            continue;
        }
        rows.push(benchmark_profile(*profile, &config).await?);
    }

    let report = RuntimeMetricsReport {
        profiles: config
            .profiles
            .iter()
            .map(|profile| profile.as_str())
            .collect(),
        providers: config
            .providers
            .iter()
            .map(|provider| provider.as_str())
            .collect(),
        profile_definitions: RuntimeProfileCase::all()
            .iter()
            .map(|profile| profile.definition())
            .collect(),
        startup_samples: config.startup_samples,
        opa_evals: config.opa_evals,
        proxy_baseline_connections: config.proxy_baseline_connections,
        proxy_requests: config.proxy_requests,
        rows,
    };

    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

#[derive(Debug, Clone)]
struct BenchmarkConfig {
    profiles: Vec<RuntimeProfileCase>,
    providers: Vec<RuntimeProviderCase>,
    startup_samples: usize,
    opa_evals: u64,
    proxy_baseline_connections: u32,
    proxy_requests: u32,
}

impl BenchmarkConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let profiles = match std::env::var("AXIS_RUNTIME_METRICS_PROFILES") {
            Ok(value) => parse_profiles(&value)?,
            Err(_) => RuntimeProfileCase::all().to_vec(),
        };
        if profiles.is_empty() {
            return Err("AXIS_RUNTIME_METRICS_PROFILES must not be empty".into());
        }
        let providers = match std::env::var("AXIS_RUNTIME_METRICS_PROVIDERS") {
            Ok(value) => parse_providers(&value)?,
            Err(_) => RuntimeProviderCase::all().to_vec(),
        };
        if providers.is_empty() {
            return Err("AXIS_RUNTIME_METRICS_PROVIDERS must not be empty".into());
        }

        Ok(Self {
            profiles,
            providers,
            startup_samples: env_usize(
                "AXIS_RUNTIME_METRICS_STARTUP_SAMPLES",
                DEFAULT_STARTUP_SAMPLES,
            )?,
            opa_evals: env_u64("AXIS_RUNTIME_METRICS_OPA_EVALS", DEFAULT_OPA_EVALS)?,
            proxy_baseline_connections: env_u32(
                "AXIS_RUNTIME_METRICS_PROXY_BASELINE_CONNS",
                DEFAULT_PROXY_BASELINE_CONNS,
            )?,
            proxy_requests: env_u32(
                "AXIS_RUNTIME_METRICS_PROXY_REQUESTS",
                DEFAULT_PROXY_REQUESTS,
            )?,
        })
    }
}

fn env_usize(key: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

fn env_u64(key: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

fn env_u32(key: &str, default: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{key} must be greater than zero").into());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProviderCase {
    Auto,
    Mxc,
    AxisNative,
}

impl RuntimeProviderCase {
    fn all() -> &'static [Self] {
        &[Self::Auto, Self::Mxc, Self::AxisNative]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Mxc => "mxc",
            Self::AxisNative => "axis_native",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProfileCase {
    MainCompat,
    AxisNative,
    MxcProcess,
    BinaryAttribution,
    Interactive,
}

impl RuntimeProfileCase {
    fn all() -> &'static [Self] {
        &[
            Self::MainCompat,
            Self::AxisNative,
            Self::MxcProcess,
            Self::BinaryAttribution,
            Self::Interactive,
        ]
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::MainCompat => "main_compat",
            Self::AxisNative => "axis_native",
            Self::MxcProcess => "mxc_process",
            Self::BinaryAttribution => "binary_attribution",
            Self::Interactive => "interactive",
        }
    }

    fn provider(self) -> RuntimeProviderCase {
        match self {
            // MXC Bubblewrap relays sandbox connections through slirp4netns
            // and rejects binary-restricted endpoint policies, so connect-time
            // attribution is measured on the native provider.
            Self::MainCompat | Self::AxisNative | Self::BinaryAttribution => {
                RuntimeProviderCase::AxisNative
            }
            Self::MxcProcess | Self::Interactive => RuntimeProviderCase::Mxc,
        }
    }

    fn is_apples_to_apples(self) -> bool {
        matches!(self, Self::MainCompat)
    }

    fn policy_surface(self) -> &'static str {
        match self {
            Self::MainCompat => "success-metrics-compatible minimal process policy",
            Self::AxisNative => "AXIS native Landlock/seccomp process path with limits disabled",
            Self::MxcProcess => {
                "MXC Bubblewrap process path with AXIS policy layers and limits disabled"
            }
            Self::BinaryAttribution => {
                "AXIS native strict proxy policy with binary-restricted endpoint rules and connect-time attribution"
            }
            Self::Interactive => "MXC process path with interactive PTY bridge enabled",
        }
    }

    fn dependency_gate(self) -> &'static str {
        match self {
            Self::MainCompat | Self::AxisNative => {
                "requires native AXIS process isolation support on this platform"
            }
            Self::MxcProcess => "requires a safe MXC process executor",
            Self::BinaryAttribution => {
                "requires strict proxy setup and connect-time attribution support"
            }
            Self::Interactive => "requires a safe MXC process executor and PTY bridge support",
        }
    }

    fn definition(self) -> RuntimeProfileDefinition {
        RuntimeProfileDefinition {
            name: self.as_str(),
            runtime_containment: "process",
            runtime_provider: self.provider().as_str(),
            apples_to_apples_with_success_metrics: self.is_apples_to_apples(),
            policy_surface: self.policy_surface(),
            dependency_gate: self.dependency_gate(),
        }
    }
}

fn parse_providers(value: &str) -> Result<Vec<RuntimeProviderCase>, Box<dyn std::error::Error>> {
    value
        .split(',')
        .map(|raw| match raw.trim() {
            "auto" => Ok(RuntimeProviderCase::Auto),
            "mxc" => Ok(RuntimeProviderCase::Mxc),
            "axis_native" | "axis-native" => Ok(RuntimeProviderCase::AxisNative),
            "" => Err("empty runtime provider in AXIS_RUNTIME_METRICS_PROVIDERS".into()),
            other => Err(format!("unknown runtime provider '{other}'").into()),
        })
        .collect()
}

fn parse_profiles(value: &str) -> Result<Vec<RuntimeProfileCase>, Box<dyn std::error::Error>> {
    value
        .split(',')
        .map(|raw| match raw.trim() {
            "main_compat" | "main-compatible" | "main-compat" => Ok(RuntimeProfileCase::MainCompat),
            "axis_native" | "axis-native" => Ok(RuntimeProfileCase::AxisNative),
            "mxc_process" | "mxc-process" | "mxc" => Ok(RuntimeProfileCase::MxcProcess),
            "binary_attribution" | "binary-attribution" => {
                Ok(RuntimeProfileCase::BinaryAttribution)
            }
            "interactive" => Ok(RuntimeProfileCase::Interactive),
            "" => Err("empty runtime profile in AXIS_RUNTIME_METRICS_PROFILES".into()),
            other => Err(format!("unknown runtime profile '{other}'").into()),
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct RuntimeMetricsReport {
    profiles: Vec<&'static str>,
    providers: Vec<&'static str>,
    profile_definitions: Vec<RuntimeProfileDefinition>,
    startup_samples: usize,
    opa_evals: u64,
    proxy_baseline_connections: u32,
    proxy_requests: u32,
    rows: Vec<RuntimeMetricsRow>,
}

#[derive(Debug, Serialize)]
struct RuntimeProfileDefinition {
    name: &'static str,
    runtime_containment: &'static str,
    runtime_provider: &'static str,
    apples_to_apples_with_success_metrics: bool,
    policy_surface: &'static str,
    dependency_gate: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RuntimeMetricsRow {
    Ok {
        profile: &'static str,
        runtime_containment: &'static str,
        runtime_provider: &'static str,
        apples_to_apples_with_success_metrics: bool,
        policy_surface: &'static str,
        startup: StartupReport,
        cold_proxy_deny: ColdProxyReport,
        synthetic_opa: SyntheticOpaReport,
    },
    Error {
        profile: &'static str,
        runtime_containment: &'static str,
        runtime_provider: &'static str,
        apples_to_apples_with_success_metrics: bool,
        policy_surface: &'static str,
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct RuntimeMetricSet {
    startup: StartupReport,
    cold_proxy_deny: ColdProxyReport,
    synthetic_opa: SyntheticOpaReport,
}

#[derive(Debug, Serialize)]
struct StartupReport {
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    min_ms: f64,
    max_ms: f64,
    samples_ms: Vec<f64>,
    phases: Vec<PhaseReport>,
}

#[derive(Debug, Serialize)]
struct ColdProxyReport {
    latency_ms: f64,
    baseline_ms: f64,
    total_ms: f64,
    phases: Vec<PhaseReport>,
}

#[derive(Debug, Serialize)]
struct SyntheticOpaReport {
    evals_per_sec: f64,
    us_per_eval: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PhaseReport {
    phase: String,
    median_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    min_ms: f64,
    max_ms: f64,
    samples_ms: Vec<f64>,
}

#[derive(Debug)]
struct StartupSample {
    total: Duration,
    phases: Vec<PhaseSample>,
}

#[derive(Debug, Clone)]
struct PhaseSample {
    phase: String,
    duration: Duration,
}

async fn benchmark_profile(
    profile: RuntimeProfileCase,
    config: &BenchmarkConfig,
) -> Result<RuntimeMetricsRow, Box<dyn std::error::Error>> {
    let definition = profile.definition();
    let metrics = match benchmark_profile_metrics(profile, config).await {
        Ok(metrics) => metrics,
        Err(err) => {
            return Ok(RuntimeMetricsRow::Error {
                profile: definition.name,
                runtime_containment: definition.runtime_containment,
                runtime_provider: definition.runtime_provider,
                apples_to_apples_with_success_metrics: definition
                    .apples_to_apples_with_success_metrics,
                policy_surface: definition.policy_surface,
                reason: err.to_string(),
            });
        }
    };

    Ok(RuntimeMetricsRow::Ok {
        profile: definition.name,
        runtime_containment: definition.runtime_containment,
        runtime_provider: definition.runtime_provider,
        apples_to_apples_with_success_metrics: definition.apples_to_apples_with_success_metrics,
        policy_surface: definition.policy_surface,
        startup: metrics.startup,
        cold_proxy_deny: metrics.cold_proxy_deny,
        synthetic_opa: metrics.synthetic_opa,
    })
}

async fn benchmark_profile_metrics(
    profile: RuntimeProfileCase,
    config: &BenchmarkConfig,
) -> Result<RuntimeMetricSet, Box<dyn std::error::Error>> {
    Ok(RuntimeMetricSet {
        startup: benchmark_startup(profile, config.startup_samples).await?,
        cold_proxy_deny: benchmark_cold_proxy_deny(
            profile,
            config.proxy_baseline_connections,
            config.proxy_requests,
        )
        .await?,
        synthetic_opa: benchmark_synthetic_opa(config.opa_evals),
    })
}

async fn benchmark_startup(
    profile: RuntimeProfileCase,
    samples: usize,
) -> Result<StartupReport, String> {
    let mut startup_samples = Vec::with_capacity(samples);
    for sample_index in 0..samples {
        match measure_sandbox_startup(profile).await {
            Ok(sample) => startup_samples.push(sample),
            Err(err) => {
                return Err(format!("startup sample {sample_index}: {err}"));
            }
        }
    }

    let durations = startup_samples
        .iter()
        .map(|sample| sample.total)
        .collect::<Vec<_>>();
    let mut sorted = durations.clone();
    sorted.sort();
    let phase_samples = startup_samples
        .iter()
        .map(|sample| sample.phases.clone())
        .collect::<Vec<_>>();
    Ok(StartupReport {
        median_ms: duration_ms(percentile_sorted(&sorted, 50)),
        p95_ms: duration_ms(percentile_sorted(&sorted, 95)),
        p99_ms: duration_ms(percentile_sorted(&sorted, 99)),
        min_ms: duration_ms(sorted[0]),
        max_ms: duration_ms(sorted[sorted.len() - 1]),
        samples_ms: durations.into_iter().map(duration_ms).collect(),
        phases: summarize_phase_samples(&phase_samples),
    })
}

async fn measure_sandbox_startup(profile: RuntimeProfileCase) -> Result<StartupSample, String> {
    let sandbox_id = SandboxId::new();
    let policy = startup_policy(profile).map_err(|err| err.to_string())?;
    let workspace = tempfile::tempdir().map_err(|err| err.to_string())?;
    let trace = StartupTrace::new();

    let command = if cfg!(target_os = "windows") {
        "cmd.exe".to_string()
    } else {
        "/bin/true".to_string()
    };
    let args = if cfg!(target_os = "windows") {
        vec!["/C".into(), "exit".into(), "0".into()]
    } else {
        Vec::new()
    };

    let (proxy_port, proxy_addr, connect_attribution) =
        startup_proxy_config(profile, sandbox_id, &policy);
    let pty_bridge_helper = startup_pty_bridge_helper(profile)?;
    let config = SandboxConfig {
        id: sandbox_id,
        policy,
        command,
        args,
        working_dir: None,
        workspace_dir: workspace.path().to_path_buf(),
        env: Vec::new(),
        proxy_port,
        proxy_addr,
        connect_attribution,
        capture_output: false,
        interactive_terminal: profile == RuntimeProfileCase::Interactive,
        pty_bridge_helper,
        timeout_sec: None,
        backend_preflight: Default::default(),
        startup_trace: Some(trace.clone()),
    };

    let start = Instant::now();
    let mut sandbox = axis_sandbox::Sandbox::create(config).map_err(|err| err.to_string())?;
    if let Err(err) = sandbox.start() {
        let _ = sandbox.destroy();
        return Err(err.to_string());
    }
    let startup_time = start.elapsed();

    let wait_result = sandbox.wait().await;
    let destroy_result = sandbox.destroy();
    match wait_result {
        Ok(0) => {}
        Ok(code) => return Err(format!("sandbox command exited with status {code}")),
        Err(err) => return Err(err.to_string()),
    }
    if let Err(err) = destroy_result {
        return Err(err.to_string());
    }
    let mut phases = trace
        .phases()
        .into_iter()
        .map(|phase| PhaseSample {
            phase: phase.phase.into(),
            duration: phase.duration,
        })
        .collect::<Vec<_>>();
    phases.push(PhaseSample {
        phase: "startup.total".into(),
        duration: startup_time,
    });
    Ok(StartupSample {
        total: startup_time,
        phases,
    })
}

fn startup_pty_bridge_helper(profile: RuntimeProfileCase) -> Result<Option<PathBuf>, String> {
    if profile != RuntimeProfileCase::Interactive {
        return Ok(None);
    }
    axis_cli_helper_path()
        .map(Some)
        .ok_or_else(|| "interactive profile requires an axis CLI binary beside runtime-metrics; run `cargo build --locked -p axis-cli` before collecting this profile".into())
}

fn axis_cli_helper_path() -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?;
    axis_cli_helper_path_next_to(&current)
}

fn axis_cli_helper_path_next_to(current: &Path) -> Option<PathBuf> {
    let dir = current.parent()?;
    let candidate = dir.join(if cfg!(target_os = "windows") {
        "axis.exe"
    } else {
        "axis"
    });
    candidate.is_file().then_some(candidate)
}

fn startup_policy(profile: RuntimeProfileCase) -> Result<Policy, Box<dyn std::error::Error>> {
    let provider = profile.provider();
    let yaml = match profile {
        RuntimeProfileCase::MainCompat => format!(
            r#"
version: 1
name: bench-main-compat
runtime:
  containment: process
  provider: {}
filesystem:
  read_only:
    - /usr
    - /lib
    - /lib64
    - /bin
    - /sbin
    - /etc
  read_write:
    - "{{workspace}}"
process:
  max_processes: 4
  cpu_rate_percent: 50
network:
  mode: allow
"#,
            provider.as_str()
        ),
        RuntimeProfileCase::BinaryAttribution => format!(
            r#"
version: 1
name: bench-binary-attribution
runtime:
  containment: process
  provider: {}
filesystem:
  read_only:
    - /usr
    - /lib
    - /lib64
    - /bin
    - /sbin
    - /etc
  read_write:
    - "{{workspace}}"
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: proxy
  policies:
    - name: attributed
      endpoints:
        - host: "example.com"
          port: 443
      binaries:
        - path: "/bin/true"
"#,
            provider.as_str()
        ),
        _ if cfg!(target_os = "windows") => format!(
            r#"
version: 1
name: bench
runtime:
  containment: process
  provider: {}
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
"#,
            provider.as_str()
        ),
        _ => format!(
            r#"
version: 1
name: bench
runtime:
  containment: process
  provider: {}
filesystem:
  read_only:
    - /usr
    - /lib
    - /lib64
    - /bin
    - /sbin
    - /etc
  read_write:
    - "{{workspace}}"
process:
  max_processes: 0
  max_memory_mb: 0
  cpu_rate_percent: 0
network:
  mode: allow
"#,
            provider.as_str()
        ),
    };
    Ok(Policy::from_yaml(&yaml)?)
}

fn startup_proxy_config(
    profile: RuntimeProfileCase,
    sandbox_id: SandboxId,
    _policy: &Policy,
) -> (
    u16,
    Option<std::net::SocketAddr>,
    Option<ConnectAttributionStore>,
) {
    if profile == RuntimeProfileCase::BinaryAttribution {
        #[cfg(target_os = "linux")]
        {
            (
                STRICT_PROXY_PORT,
                Some(axis_sandbox::linux::netns::proxy_bind_addr(
                    sandbox_id,
                    STRICT_PROXY_PORT,
                )),
                Some(ConnectAttributionStore::default()),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = sandbox_id;
            (
                STRICT_PROXY_PORT,
                None,
                Some(ConnectAttributionStore::default()),
            )
        }
    } else {
        let _ = sandbox_id;
        (0, None, None)
    }
}

async fn benchmark_cold_proxy_deny(
    profile: RuntimeProfileCase,
    baseline_connections: u32,
    proxy_requests: u32,
) -> Result<ColdProxyReport, Box<dyn std::error::Error>> {
    benchmark_cold_proxy_deny_inner(profile, baseline_connections, proxy_requests).await
}

async fn benchmark_cold_proxy_deny_inner(
    profile: RuntimeProfileCase,
    baseline_connections: u32,
    proxy_requests: u32,
) -> Result<ColdProxyReport, Box<dyn std::error::Error>> {
    let policy = proxy_policy(profile)?;
    let sandbox_id = SandboxId::new();
    let connect_attribution =
        (profile == RuntimeProfileCase::BinaryAttribution).then(ConnectAttributionStore::default);
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut proxy = AxisProxy::new(ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_leak_detection: false,
        inference_endpoint: None,
        connect_attribution: connect_attribution.clone(),
        enable_identity_diagnostics: false,
        timing_tx: Some(timing_tx),
    })?;
    let addr = proxy.bind().await?;
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut baseline_samples = Vec::with_capacity(baseline_connections as usize);
    for _ in 0..baseline_connections {
        let baseline_start = Instant::now();
        let stream = TcpStream::connect(addr).await?;
        drop(stream);
        baseline_samples.push(baseline_start.elapsed());
    }
    let baseline_per_conn = mean_duration(&baseline_samples);

    let mut request_samples = Vec::with_capacity(proxy_requests as usize);
    let mut proxy_phase_samples = Vec::with_capacity(proxy_requests as usize);
    for _ in 0..proxy_requests {
        let request_start = Instant::now();
        let mut stream = if let Some(store) = &connect_attribution {
            let (socket, peer_addr) = bound_tcp_socket()?;
            store.insert(axis_core::connect_attribution::ConnectAttributionRecord {
                sandbox_id,
                peer_addr,
                proxy_addr: addr,
                pid: 42,
                executable_path: "/bin/true".into(),
                executable_sha256: "a".repeat(64),
                source: axis_core::connect_attribution::ConnectAttributionSource::Test,
            })?;
            socket.connect(addr).await?
        } else {
            TcpStream::connect(addr).await?
        };
        stream
            .write_all(
                b"CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com\r\n\r\n",
            )
            .await?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if !line.contains("403") {
            proxy_task.abort();
            return Err(format!("expected 403 response, got {line:?}").into());
        }
        request_samples.push(request_start.elapsed());
        let event = recv_denied_timing_event(&mut timing_rx, "denied.example.com", 443).await?;
        proxy_phase_samples.push(
            event
                .phases
                .into_iter()
                .map(|phase| PhaseSample {
                    phase: phase.phase.into(),
                    duration: phase.duration,
                })
                .collect::<Vec<_>>(),
        );
    }
    proxy_task.abort();

    let total_per_req = mean_duration(&request_samples);
    let latency = total_per_req.saturating_sub(baseline_per_conn);
    let mut phase_reports = Vec::new();
    phase_reports.push(summarize_named_phase(
        "tcp_baseline",
        baseline_samples.as_slice(),
    ));
    phase_reports.push(summarize_named_phase(
        "request_total",
        request_samples.as_slice(),
    ));
    phase_reports.extend(summarize_phase_samples(&proxy_phase_samples));
    Ok(ColdProxyReport {
        latency_ms: duration_ms(latency),
        baseline_ms: duration_ms(baseline_per_conn),
        total_ms: duration_ms(total_per_req),
        phases: phase_reports,
    })
}

async fn recv_denied_timing_event(
    timing_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ProxyTimingEvent>,
    host: &str,
    port: u16,
) -> Result<ProxyTimingEvent, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let event = timing_rx
                .recv()
                .await
                .ok_or("proxy timing channel closed before denied request event")?;
            if event.outcome == ProxyTimingOutcome::Denied
                && event.target_host.as_deref() == Some(host)
                && event.target_port == Some(port)
            {
                return Ok::<ProxyTimingEvent, &'static str>(event);
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for denied proxy timing event")?
    .map_err(Into::into)
}

fn bound_tcp_socket() -> Result<(tokio::net::TcpSocket, std::net::SocketAddr), std::io::Error> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    let peer_addr = socket.local_addr()?;
    Ok((socket, peer_addr))
}

fn proxy_policy(profile: RuntimeProfileCase) -> Result<Policy, Box<dyn std::error::Error>> {
    let provider = profile.provider();
    let yaml = if profile == RuntimeProfileCase::BinaryAttribution {
        format!(
            r#"
version: 1
name: bench-proxy-binary-attribution
runtime:
  containment: process
  provider: {}
network:
  mode: proxy
  policies:
    - name: attributed
      endpoints:
        - host: "example.com"
          port: 443
      binaries:
        - path: "/bin/true"
"#,
            provider.as_str()
        )
    } else {
        format!(
            r#"
version: 1
name: bench-proxy
runtime:
  containment: process
  provider: {}
network:
  mode: proxy
  policies:
    - name: test
      endpoints:
        - host: "example.com"
          port: 443
"#,
            provider.as_str()
        )
    };
    Ok(Policy::from_yaml(&yaml)?)
}

fn benchmark_synthetic_opa(iterations: u64) -> SyntheticOpaReport {
    let (_total_ns, evals_per_sec) = axis_core::bench::bench_network_eval(iterations);
    SyntheticOpaReport {
        evals_per_sec,
        us_per_eval: 1_000_000.0 / evals_per_sec,
    }
}

fn summarize_phase_samples(samples: &[Vec<PhaseSample>]) -> Vec<PhaseReport> {
    let mut by_phase: BTreeMap<String, Vec<Duration>> = BTreeMap::new();
    for sample in samples {
        let mut sample_totals: BTreeMap<String, Duration> = BTreeMap::new();
        for phase in sample {
            *sample_totals.entry(phase.phase.clone()).or_default() += phase.duration;
        }
        for (phase, duration) in sample_totals {
            by_phase.entry(phase).or_default().push(duration);
        }
    }

    by_phase
        .into_iter()
        .map(|(phase, samples)| summarize_named_phase(&phase, &samples))
        .collect()
}

fn summarize_named_phase(phase: &str, samples: &[Duration]) -> PhaseReport {
    let mut sorted = samples.to_vec();
    sorted.sort();
    PhaseReport {
        phase: phase.into(),
        median_ms: duration_ms(percentile_sorted(&sorted, 50)),
        p95_ms: duration_ms(percentile_sorted(&sorted, 95)),
        p99_ms: duration_ms(percentile_sorted(&sorted, 99)),
        min_ms: duration_ms(sorted[0]),
        max_ms: duration_ms(sorted[sorted.len() - 1]),
        samples_ms: samples.iter().copied().map(duration_ms).collect(),
    }
}

fn percentile_sorted(sorted: &[Duration], percentile: usize) -> Duration {
    let index = sorted.len() * percentile / 100;
    sorted[index.min(sorted.len() - 1)]
}

fn mean_duration(samples: &[Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let total_nanos = samples.iter().map(Duration::as_nanos).sum::<u128>() / samples.len() as u128;
    Duration::from_nanos(total_nanos.min(u64::MAX as u128) as u64)
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_attribution_profile_runs_on_the_native_provider() {
        // MXC Bubblewrap rejects binary-restricted endpoint policies, so the
        // attribution profile must not be measured through MXC.
        let providers: Vec<_> = RuntimeProfileCase::all()
            .iter()
            .map(|profile| (profile.as_str(), profile.provider()))
            .collect();
        assert_eq!(
            providers,
            [
                ("main_compat", RuntimeProviderCase::AxisNative),
                ("axis_native", RuntimeProviderCase::AxisNative),
                ("mxc_process", RuntimeProviderCase::Mxc),
                ("binary_attribution", RuntimeProviderCase::AxisNative),
                ("interactive", RuntimeProviderCase::Mxc),
            ]
        );
    }

    #[test]
    fn parse_provider_list_accepts_aliases() {
        assert_eq!(
            parse_providers("auto,mxc,axis-native").unwrap(),
            vec![
                RuntimeProviderCase::Auto,
                RuntimeProviderCase::Mxc,
                RuntimeProviderCase::AxisNative
            ]
        );
    }

    #[test]
    fn parse_provider_list_rejects_unknown() {
        let err = parse_providers("auto,container").unwrap_err();
        assert!(err.to_string().contains("unknown runtime provider"));
    }

    #[test]
    fn parse_profile_list_accepts_aliases() {
        assert_eq!(
            parse_profiles("main-compatible,axis-native,mxc,binary-attribution,interactive")
                .unwrap(),
            vec![
                RuntimeProfileCase::MainCompat,
                RuntimeProfileCase::AxisNative,
                RuntimeProfileCase::MxcProcess,
                RuntimeProfileCase::BinaryAttribution,
                RuntimeProfileCase::Interactive
            ]
        );
    }

    #[test]
    fn parse_profile_list_rejects_unknown() {
        let err = parse_profiles("main_compat,microvm").unwrap_err();
        assert!(err.to_string().contains("unknown runtime profile"));
    }

    #[test]
    fn phase_summary_sums_duplicate_phases_per_sample() {
        let reports = summarize_phase_samples(&[
            vec![
                PhaseSample {
                    phase: "spawn.child".into(),
                    duration: Duration::from_millis(1),
                },
                PhaseSample {
                    phase: "spawn.child".into(),
                    duration: Duration::from_millis(2),
                },
            ],
            vec![PhaseSample {
                phase: "spawn.child".into(),
                duration: Duration::from_millis(5),
            }],
        ]);

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].phase, "spawn.child");
        assert_eq!(reports[0].samples_ms, vec![3.0, 5.0]);
    }

    #[test]
    fn startup_policy_main_compat_matches_success_metrics_limits() {
        let policy = startup_policy(RuntimeProfileCase::MainCompat).unwrap();

        assert_eq!(policy.process.max_processes, 4);
        assert_eq!(policy.process.cpu_rate_percent, 50);
    }

    #[test]
    fn startup_policy_runtime_profiles_disable_all_resource_limits() {
        for profile in [
            RuntimeProfileCase::AxisNative,
            RuntimeProfileCase::MxcProcess,
            RuntimeProfileCase::BinaryAttribution,
            RuntimeProfileCase::Interactive,
        ] {
            let policy = startup_policy(profile).unwrap();
            assert_eq!(policy.process.max_processes, 0);
            assert_eq!(policy.process.max_memory_mb, 0);
            assert_eq!(policy.process.cpu_rate_percent, 0);
        }
    }

    #[test]
    fn axis_cli_helper_path_next_to_current_exe_requires_adjacent_axis_binary() {
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("runtime-metrics");

        assert!(axis_cli_helper_path_next_to(&current).is_none());

        let helper = dir.path().join(if cfg!(target_os = "windows") {
            "axis.exe"
        } else {
            "axis"
        });
        std::fs::write(&helper, "").unwrap();

        assert_eq!(axis_cli_helper_path_next_to(&current), Some(helper));
    }

    #[test]
    fn failed_rows_serialize_without_timing_fields() {
        let row = RuntimeMetricsRow::Error {
            profile: "mxc_process",
            runtime_containment: "process",
            runtime_provider: "mxc",
            apples_to_apples_with_success_metrics: false,
            policy_surface: "MXC process path",
            reason: "injected startup failure".into(),
        };

        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value.get("status").unwrap(), "error");
        assert_eq!(value.get("profile").unwrap(), "mxc_process");
        assert!(value.get("reason").is_some());
        assert!(value.get("startup").is_none());
        assert!(value.get("cold_proxy_deny").is_none());
        assert!(value.get("synthetic_opa").is_none());
        assert!(value.get("median_ms").is_none());
        assert!(value.get("latency_ms").is_none());
    }

    #[test]
    fn ok_rows_serialize_representative_metrics() {
        let row = RuntimeMetricsRow::Ok {
            profile: "main_compat",
            runtime_containment: "process",
            runtime_provider: "axis_native",
            apples_to_apples_with_success_metrics: true,
            policy_surface: "success-metrics-compatible minimal process policy",
            startup: StartupReport {
                median_ms: 1.0,
                p95_ms: 2.0,
                p99_ms: 3.0,
                min_ms: 0.5,
                max_ms: 3.0,
                samples_ms: vec![1.0, 2.0, 3.0],
                phases: vec![PhaseReport {
                    phase: "startup.total".into(),
                    median_ms: 1.0,
                    p95_ms: 2.0,
                    p99_ms: 3.0,
                    min_ms: 0.5,
                    max_ms: 3.0,
                    samples_ms: vec![1.0, 2.0, 3.0],
                }],
            },
            cold_proxy_deny: ColdProxyReport {
                latency_ms: 0.1,
                baseline_ms: 0.2,
                total_ms: 0.3,
                phases: Vec::new(),
            },
            synthetic_opa: SyntheticOpaReport {
                evals_per_sec: 10.0,
                us_per_eval: 100_000.0,
            },
        };

        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value.get("status").unwrap(), "ok");
        assert_eq!(value.get("profile").unwrap(), "main_compat");
        assert_eq!(
            value
                .get("startup")
                .unwrap()
                .get("phases")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            value
                .get("cold_proxy_deny")
                .unwrap()
                .get("latency_ms")
                .unwrap(),
            0.1
        );
        assert_eq!(
            value
                .get("synthetic_opa")
                .unwrap()
                .get("evals_per_sec")
                .unwrap(),
            10.0
        );
    }
}
