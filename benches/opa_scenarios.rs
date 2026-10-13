// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmark OPA-backed proxy policy requests for runnable scenarios.

use axis_core::connect_attribution::{
    ConnectAttributionRecord, ConnectAttributionSource, ConnectAttributionStore,
};
use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_ITERATIONS: u64 = 1_000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::var("AXIS_OPA_SCENARIO_BENCH_ITERS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_ITERATIONS);
    if iterations == 0 {
        return Err("AXIS_OPA_SCENARIO_BENCH_ITERS must be greater than zero".into());
    }

    let repo_root = repo_root()?;
    let scenarios = load_policy_scenarios(&repo_root)?;
    let mut axis_proxy_reports = Vec::with_capacity(scenarios.len());
    for scenario in &scenarios {
        axis_proxy_reports.push(benchmark_axis_proxy_requests(scenario, iterations).await?);
    }

    let mxc_bubblewrap = benchmark_mxc_bubblewrap_proxy_modes(&scenarios, iterations).await?;
    let report = OpaScenarioReport {
        iterations,
        axis_proxy_reports,
        mxc_bubblewrap,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

#[derive(Debug, Serialize)]
struct OpaScenarioReport {
    iterations: u64,
    axis_proxy_reports: Vec<ProxyRequestReport>,
    mxc_bubblewrap: MxcBubblewrapSection,
}

#[derive(Debug, Clone)]
struct PolicyScenario {
    name: &'static str,
    source: &'static str,
    policy: Policy,
    denied_host: &'static str,
    denied_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyRequestReport {
    scenario: String,
    source: String,
    request_host: String,
    request_port: u16,
    transport: &'static str,
    iterations: u64,
    total_ns: u64,
    requests_per_sec: f64,
    ns_per_request: f64,
    denied_responses: u64,
}

#[derive(Debug, Serialize)]
struct MxcBubblewrapSection {
    enabled: bool,
    reason: Option<String>,
    reports: Vec<MxcBubblewrapReport>,
}

#[derive(Debug, Serialize)]
struct MxcBubblewrapReport {
    scenario: String,
    source: String,
    backend: &'static str,
    mxc_network_mode: &'static str,
    policy_engine: &'static str,
    sandbox_wall_ms: u128,
    request_report: ProxyRequestReport,
}

#[derive(Debug, Deserialize)]
struct MxcChildReport {
    iterations: u64,
    request_host: String,
    request_port: u16,
    total_ns: u64,
    requests_per_sec: f64,
    ns_per_request: f64,
    denied_responses: u64,
    failed_requests: u64,
}

fn load_policy_scenarios(
    repo_root: &Path,
) -> Result<Vec<PolicyScenario>, Box<dyn std::error::Error>> {
    Ok(vec![
        PolicyScenario {
            name: "codex-agent-policy",
            source: "policies/agents/codex.yaml",
            policy: Policy::from_file(&repo_root.join("policies/agents/codex.yaml"))?,
            denied_host: "example.invalid",
            denied_port: 443,
        },
        PolicyScenario {
            name: "claude-code-agent-policy",
            source: "policies/agents/claude-code.yaml",
            policy: Policy::from_file(&repo_root.join("policies/agents/claude-code.yaml"))?,
            denied_host: "example.invalid",
            denied_port: 443,
        },
        PolicyScenario {
            name: "local-and-external-inference-policy",
            source: "inline",
            policy: Policy::from_yaml(
                r#"
version: 1
name: opa-scenario-local-and-external-inference
network:
  mode: proxy
  policies:
    - name: local-inference
      endpoints:
        - host: "inference.local"
          port: 443
    - name: anthropic
      endpoints:
        - host: "api.anthropic.com"
          port: 443
inference:
  default_provider: local-rocm
  routes:
    - name: local-rocm
      endpoint: "http://inference.local"
      protocols: [openai_chat_completions, model_discovery]
      model: "llama-4-scout-109b"
    - name: cloud-fallback
      provider: anthropic
      model: "claude-sonnet-4"
      api_key_env: ANTHROPIC_API_KEY
      protocols: [messages_streaming]
"#,
            )?,
            denied_host: "api.openai.com",
            denied_port: 443,
        },
    ])
}

async fn benchmark_axis_proxy_requests(
    scenario: &PolicyScenario,
    iterations: u64,
) -> Result<ProxyRequestReport, Box<dyn std::error::Error>> {
    let sandbox_id = SandboxId::new();
    let connect_attribution = ConnectAttributionStore::default();
    let mut proxy = AxisProxy::new(ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy: scenario.policy.clone(),
        enable_leak_detection: false,
        inference_endpoint: None,
        connect_attribution: Some(connect_attribution.clone()),
        enable_identity_diagnostics: false,
        timing_tx: None,
    })?;
    let proxy_addr = proxy.bind().await?;
    let proxy_task = tokio::spawn(async move { proxy.run().await });

    let result = benchmark_connect_requests(
        proxy_addr,
        scenario.denied_host,
        scenario.denied_port,
        iterations,
        Some(AttributionContext::new(connect_attribution, sandbox_id)?),
    )
    .await;

    proxy_task.abort();
    let report = result?;
    Ok(ProxyRequestReport {
        scenario: scenario.name.into(),
        source: scenario.source.into(),
        request_host: scenario.denied_host.into(),
        request_port: scenario.denied_port,
        transport: "axis_proxy_direct",
        iterations,
        total_ns: report.total_ns,
        requests_per_sec: report.requests_per_sec,
        ns_per_request: report.ns_per_request,
        denied_responses: report.denied_responses,
    })
}

async fn benchmark_mxc_bubblewrap_proxy_modes(
    scenarios: &[PolicyScenario],
    iterations: u64,
) -> Result<MxcBubblewrapSection, Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Ok(MxcBubblewrapSection {
            enabled: false,
            reason: Some("MXC Bubblewrap proxy-mode benchmarks run only on Linux".into()),
            reports: Vec::new(),
        });
    }

    let Some(executor) = find_mxc_executor() else {
        return Ok(MxcBubblewrapSection {
            enabled: false,
            reason: Some(
                "set AXIS_TEST_MXC_EXECUTOR to a safe lxc-exec path, or put lxc-exec on PATH"
                    .into(),
            ),
            reports: Vec::new(),
        });
    };
    if find_on_path("bwrap").is_none() {
        return Ok(MxcBubblewrapSection {
            enabled: false,
            reason: Some("bwrap is not on PATH".into()),
            reports: Vec::new(),
        });
    }
    // MXC 1.x reaches a runtime proxy through a slirp4netns private network
    // namespace; report the section as disabled rather than failing the run.
    #[cfg(target_os = "linux")]
    if !mxc_private_network_available(Path::new("/dev/net/tun"), MXC_EXECUTOR_PATH) {
        return Ok(MxcBubblewrapSection {
            enabled: false,
            reason: Some(
                "MXC proxy routing needs slirp4netns, unshare, nsenter, the iptables tools, and /dev/net/tun"
                    .into(),
            ),
            reports: Vec::new(),
        });
    }

    let mut reports = Vec::new();
    for scenario in scenarios {
        reports.push(
            benchmark_mxc_bubblewrap_external_proxy_mode(&executor, scenario, iterations).await?,
        );
    }

    Ok(MxcBubblewrapSection {
        enabled: true,
        reason: None,
        reports,
    })
}

/// Commands MXC 1.x runs to wire a Bubblewrap sandbox's private network
/// namespace, looked up in the directories AXIS gives the executor.
#[cfg(target_os = "linux")]
const MXC_PRIVATE_NETWORK_TOOLS: &[&str] = &[
    "slirp4netns",
    "unshare",
    "nsenter",
    "iptables",
    "ip6tables",
    "iptables-restore",
    "ip6tables-restore",
];

/// Search path AXIS gives the MXC executor.
const MXC_EXECUTOR_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

#[cfg(target_os = "linux")]
fn mxc_private_network_available(tun_device: &Path, search_path: &str) -> bool {
    tun_device.exists()
        && MXC_PRIVATE_NETWORK_TOOLS.iter().all(|tool| {
            search_path
                .split(':')
                .any(|dir| Path::new(dir).join(tool).is_file())
        })
}

/// MXC 1.0 carries the proxy endpoint in `runtimeConfig.networkProxy`; the
/// retired `network.proxy.localhost` and `network.proxy.builtinTestServer`
/// shapes have no supported equivalent.
const MXC_RUNTIME_PROXY_MODE: &str = "runtimeConfig.networkProxy";

async fn benchmark_mxc_bubblewrap_external_proxy_mode(
    executor: &Path,
    scenario: &PolicyScenario,
    iterations: u64,
) -> Result<MxcBubblewrapReport, Box<dyn std::error::Error>> {
    let external_proxy = StaticDenyProxy::start().await?;

    let result = run_mxc_bubblewrap_child(
        executor,
        &format!("{}-{}", scenario.name, MXC_RUNTIME_PROXY_MODE),
        &format!("http://{}", external_proxy.addr),
        scenario.denied_host,
        scenario.denied_port,
        iterations,
    );

    let (sandbox_wall_ms, child_report) = result?;
    child_report.ensure_success(MXC_RUNTIME_PROXY_MODE)?;
    Ok(MxcBubblewrapReport {
        scenario: scenario.name.into(),
        source: scenario.source.into(),
        backend: "mxc-linux-bubblewrap",
        mxc_network_mode: MXC_RUNTIME_PROXY_MODE,
        policy_engine: "external_static_deny_proxy",
        sandbox_wall_ms,
        request_report: child_report.into_proxy_report(
            scenario.name,
            scenario.source,
            "mxc_bubblewrap_env_proxy",
        ),
    })
}

fn run_mxc_bubblewrap_child(
    executor: &Path,
    scenario_name: &str,
    proxy_url: &str,
    denied_host: &str,
    denied_port: u16,
    iterations: u64,
) -> Result<(u128, MxcChildReport), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let script_path = workspace.path().join("mxc-policy-request-bench.py");
    std::fs::write(&script_path, MXC_POLICY_REQUEST_BENCH_PY)?;

    let config_path = workspace.path().join("mxc-bubblewrap-proxy.json");
    let config = json!({
        "version": "1.0.0",
        "containerId": scenario_name.replace(['.', '_'], "-"),
        "containment": "bubblewrap",
        "process": {
            "commandLine": format!(
                "/usr/bin/python3 {} {} {} {}",
                shell_quote(&script_path.to_string_lossy()),
                iterations,
                shell_quote(denied_host),
                denied_port
            ),
            "env": ["PATH=/usr/bin:/bin"],
            "timeout": 30000
        },
        "filesystem": {
            "readwritePaths": [workspace.path().to_string_lossy()],
            "readonlyPaths": ["/usr", "/lib", "/lib64", "/bin", "/etc"],
            "deniedPaths": []
        },
        // Proxy-only posture: direct egress is denied and the sandbox can
        // reach only the runtime proxy endpoint.
        "network": {
            "egress": { "default": "deny" },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        },
        "runtimeConfig": {
            "networkProxy": proxy_url
        },
        "lifecycle": {
            "destroyOnExit": true,
            "preservePolicy": false
        }
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

    let started = Instant::now();
    let mut command = Command::new(executor);
    command
        .arg("--experimental")
        .arg("--config")
        .arg(&config_path)
        // Same search path AXIS gives the executor: MXC runs the firewall
        // and slirp4netns tools by name, and they live under sbin.
        .env("PATH", MXC_EXECUTOR_PATH)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_with_timeout(&mut command, COMMAND_TIMEOUT)?;
    let sandbox_wall_ms = started.elapsed().as_millis();
    if !output.status.success() {
        return Err(format!(
            "MXC Bubblewrap scenario {scenario_name} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;
    let child_report: MxcChildReport = serde_json::from_str(stdout.trim()).map_err(|err| {
        format!("MXC Bubblewrap scenario {scenario_name} emitted invalid JSON: {err}: {stdout}")
    })?;
    Ok((sandbox_wall_ms, child_report))
}

#[derive(Debug)]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<CommandOutput, Box<dyn std::error::Error>> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut handle) = child.stdout.take() {
                handle.read_to_end(&mut stdout)?;
            }
            if let Some(mut handle) = child.stderr.take() {
                handle.read_to_end(&mut stderr)?;
            }
            return Ok(CommandOutput {
                status,
                stdout,
                stderr,
            });
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            return Err(format!("command timed out after {}s", timeout.as_secs()).into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl MxcChildReport {
    fn ensure_success(&self, mode: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.failed_requests != 0 || self.denied_responses != self.iterations {
            return Err(format!(
                "{mode} reported {} failed requests and {} denied responses for {} iterations",
                self.failed_requests, self.denied_responses, self.iterations
            )
            .into());
        }
        Ok(())
    }

    fn into_proxy_report(
        self,
        scenario: &str,
        source: &str,
        transport: &'static str,
    ) -> ProxyRequestReport {
        ProxyRequestReport {
            scenario: scenario.into(),
            source: source.into(),
            request_host: self.request_host,
            request_port: self.request_port,
            transport,
            iterations: self.iterations,
            total_ns: self.total_ns,
            requests_per_sec: self.requests_per_sec,
            ns_per_request: self.ns_per_request,
            denied_responses: self.denied_responses,
        }
    }
}

struct LocalRequestReport {
    total_ns: u64,
    requests_per_sec: f64,
    ns_per_request: f64,
    denied_responses: u64,
}

async fn benchmark_connect_requests(
    proxy_addr: SocketAddr,
    denied_host: &str,
    denied_port: u16,
    iterations: u64,
    attribution: Option<AttributionContext>,
) -> Result<LocalRequestReport, Box<dyn std::error::Error>> {
    let request = format!(
        "CONNECT {denied_host}:{denied_port} HTTP/1.1\r\nHost: {denied_host}:{denied_port}\r\n\r\n"
    );
    let started = Instant::now();
    let mut denied = 0;
    for _ in 0..iterations {
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(proxy_addr)).await??;
        if let Some(attribution) = &attribution {
            attribution.insert(stream.local_addr()?, proxy_addr)?;
        }
        stream.write_all(request.as_bytes()).await?;
        let mut response = [0_u8; 64];
        let bytes =
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response)).await??;
        let status = std::str::from_utf8(&response[..bytes])?;
        if status.starts_with("HTTP/1.1 403") {
            denied += 1;
        }
    }
    if denied != iterations {
        return Err(format!(
            "expected {iterations} denied responses for {denied_host}:{denied_port}, got {denied}"
        )
        .into());
    }

    let elapsed = started.elapsed();
    let total_ns = elapsed.as_nanos() as u64;
    Ok(LocalRequestReport {
        total_ns,
        requests_per_sec: iterations as f64 / elapsed.as_secs_f64(),
        ns_per_request: total_ns as f64 / iterations as f64,
        denied_responses: denied,
    })
}

#[derive(Clone)]
struct AttributionContext {
    store: ConnectAttributionStore,
    sandbox_id: SandboxId,
    executable_path: PathBuf,
}

impl AttributionContext {
    fn new(
        store: ConnectAttributionStore,
        sandbox_id: SandboxId,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            store,
            sandbox_id,
            executable_path: std::env::current_exe()?,
        })
    }

    fn insert(
        &self,
        peer_addr: SocketAddr,
        proxy_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.store.insert(ConnectAttributionRecord {
            sandbox_id: self.sandbox_id,
            peer_addr,
            proxy_addr,
            pid: std::process::id(),
            executable_path: self.executable_path.clone(),
            executable_sha256: "0".repeat(64),
            source: ConnectAttributionSource::Test,
        })?;
        Ok(())
    }
}

struct StaticDenyProxy {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl StaticDenyProxy {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut request_line = String::new();
                    let _ = reader.read_line(&mut request_line).await;
                    let mut stream = reader.into_inner();
                    let body = b"denied by benchmark proxy\n";
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        });
        Ok(Self { addr, task })
    }
}

impl Drop for StaticDenyProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_mxc_executor() -> Option<PathBuf> {
    std::env::var_os("AXIS_TEST_MXC_EXECUTOR")
        .map(PathBuf::from)
        .or_else(|| find_on_path("lxc-exec"))
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "axis-bench manifest directory must have a repository parent".into())
}

const MXC_POLICY_REQUEST_BENCH_PY: &str = r#"
import json
import os
import socket
import sys
import time
from urllib.parse import urlparse

iterations = int(sys.argv[1])
target_host = sys.argv[2]
target_port = int(sys.argv[3])
proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
if not proxy_url:
    raise SystemExit("HTTP_PROXY was not set")
parsed = urlparse(proxy_url)
proxy_host = parsed.hostname
proxy_port = parsed.port
if not proxy_host or not proxy_port:
    raise SystemExit(f"invalid HTTP_PROXY: {proxy_url}")

denied = 0
failed = 0
request = (
    f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
    f"Host: {target_host}:{target_port}\r\n"
    "\r\n"
).encode("ascii")

start = time.perf_counter_ns()
for _ in range(iterations):
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=2.0) as sock:
            sock.sendall(request)
            data = b""
            while b"\r\n" not in data:
                chunk = sock.recv(1)
                if not chunk:
                    break
                data += chunk
        status = data.split(b"\r\n", 1)[0]
        if b" 403 " in status:
            denied += 1
        else:
            failed += 1
    except Exception:
        failed += 1
end = time.perf_counter_ns()

total_ns = end - start
print(json.dumps({
    "iterations": iterations,
    "request_host": target_host,
    "request_port": target_port,
    "total_ns": total_ns,
    "requests_per_sec": iterations / (total_ns / 1_000_000_000),
    "ns_per_request": total_ns / iterations,
    "denied_responses": denied,
    "failed_requests": failed,
}))
"#;

// The MXC private network, and so its probe, exists only on Linux.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn mxc_section_needs_the_tun_device_and_every_private_network_tool() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let search_path = format!(
            "{}:{}",
            first.path().to_str().unwrap(),
            second.path().to_str().unwrap()
        );
        let tun = Path::new("/dev/null");

        let (last, rest) = MXC_PRIVATE_NETWORK_TOOLS.split_last().unwrap();
        for tool in rest {
            std::fs::write(first.path().join(tool), "").unwrap();
        }
        assert!(!mxc_private_network_available(tun, &search_path));

        std::fs::write(second.path().join(last), "").unwrap();
        assert!(mxc_private_network_available(tun, &search_path));
        assert!(!mxc_private_network_available(
            &first.path().join("missing-tun"),
            &search_path
        ));
    }
}
