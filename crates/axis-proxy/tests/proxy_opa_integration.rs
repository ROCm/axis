// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: proxy with OPA policy evaluation.
//!
//! Starts a real proxy, sends CONNECT requests, verifies that allowed
//! hosts get 200 and denied hosts get 403.

use axis_core::connect_attribution::{
    ConnectAttributionRecord, ConnectAttributionSource, ConnectAttributionStore,
};
use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig, ProxyTimingEvent, ProxyTimingOutcome};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TEST_POLICY: &str = r#"
version: 1
name: proxy-integration-test

network:
  mode: proxy
  policies:
    - name: github
      endpoints:
        - host: "api.github.com"
          port: 443
          access: read-write
    - name: pypi
      endpoints:
        - host: "pypi.org"
          port: 443
          access: read-write
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
"#;

async fn start_proxy() -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_inference(None).await
}

async fn start_proxy_with_inference(
    inference_ep: Option<std::net::SocketAddr>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy(TEST_POLICY, inference_ep).await
}

async fn start_proxy_with_policy(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy_and_attribution(policy_yaml, inference_ep, None).await
}

async fn start_proxy_with_policy_and_attribution(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
    connect_attribution: Option<ConnectAttributionStore>,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_policy_attribution_and_identity_diagnostics(
        policy_yaml,
        inference_ep,
        connect_attribution,
        false,
    )
    .await
}

async fn start_proxy_with_policy_attribution_and_identity_diagnostics(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
    connect_attribution: Option<ConnectAttributionStore>,
    enable_identity_diagnostics: bool,
) -> (SandboxId, std::net::SocketAddr) {
    start_proxy_with_options(
        policy_yaml,
        inference_ep,
        connect_attribution,
        enable_identity_diagnostics,
        true,
    )
    .await
}

async fn start_proxy_with_options(
    policy_yaml: &str,
    inference_ep: Option<std::net::SocketAddr>,
    connect_attribution: Option<ConnectAttributionStore>,
    enable_identity_diagnostics: bool,
    enable_leak_detection: bool,
) -> (SandboxId, std::net::SocketAddr) {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let sandbox_id = SandboxId::new();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_leak_detection,
        inference_endpoint: inference_ep,
        connect_attribution,
        enable_identity_diagnostics,
        timing_tx: None,
        unauthenticated_loopback: true,
    };

    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();

    // Spawn the proxy accept loop in the background.
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    // Give the proxy a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (sandbox_id, addr)
}

#[tokio::test]
async fn denied_connect_emits_phase_timing_event() {
    let policy = Policy::from_yaml(TEST_POLICY).unwrap();
    let sandbox_id = SandboxId::new();
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_leak_detection: false,
        inference_endpoint: None,
        connect_attribution: None,
        enable_identity_diagnostics: false,
        timing_tx: Some(timing_tx),
        unauthenticated_loopback: true,
    };
    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    let status = send_connect(addr, "blocked.example.com:443").await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), timing_rx.recv())
        .await
        .unwrap()
        .expect("proxy should emit timing for denied CONNECT");
    proxy_task.abort();

    assert_eq!(event.outcome, ProxyTimingOutcome::Denied);
    assert_eq!(event.target_host.as_deref(), Some("blocked.example.com"));
    assert_eq!(event.target_port, Some(443));
    let phases = event
        .phases
        .iter()
        .map(|phase| phase.phase)
        .collect::<Vec<_>>();
    assert!(phases.contains(&"identity_attribution"));
    assert!(phases.contains(&"request_parse"));
    assert!(phases.contains(&"opa_evaluation"));
    assert!(phases.contains(&"response_write"));
    assert!(phases.contains(&"total"));
}

#[tokio::test]
async fn host_port_only_denied_connect_skips_identity_attribution() {
    let policy = Policy::from_yaml(TEST_POLICY).unwrap();
    let sandbox_id = SandboxId::new();
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_leak_detection: false,
        inference_endpoint: None,
        connect_attribution: Some(ConnectAttributionStore::new(
            std::time::Duration::from_secs(30),
        )),
        enable_identity_diagnostics: false,
        timing_tx: Some(timing_tx),
        unauthenticated_loopback: true,
    };
    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    let status = send_connect(addr, "blocked.example.com:443").await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), timing_rx.recv())
        .await
        .unwrap()
        .expect("proxy should emit timing for denied CONNECT");
    proxy_task.abort();

    assert_eq!(event.outcome, ProxyTimingOutcome::Denied);
    assert_eq!(
        timing_phase_duration(&event, "identity_attribution"),
        Some(std::time::Duration::ZERO)
    );
}

#[tokio::test]
async fn host_port_only_allowed_connect_skips_identity_attribution() {
    let policy = Policy::from_yaml(TEST_POLICY).unwrap();
    let sandbox_id = SandboxId::new();
    let upstream = start_mock_tcp_server().await;
    let (timing_tx, mut timing_rx) = tokio::sync::mpsc::unbounded_channel();
    let config = ProxyConfig {
        sandbox_id,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy,
        enable_leak_detection: false,
        inference_endpoint: Some(upstream),
        connect_attribution: Some(ConnectAttributionStore::new(
            std::time::Duration::from_secs(30),
        )),
        enable_identity_diagnostics: false,
        timing_tx: Some(timing_tx),
        unauthenticated_loopback: true,
    };
    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    let status = send_connect(addr, "inference.local:443").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let event = tokio::time::timeout(std::time::Duration::from_secs(2), timing_rx.recv())
        .await
        .unwrap()
        .expect("proxy should emit timing for allowed CONNECT");
    proxy_task.abort();

    assert_eq!(event.outcome, ProxyTimingOutcome::Allowed);
    assert_eq!(
        timing_phase_duration(&event, "identity_attribution"),
        Some(std::time::Duration::ZERO)
    );
}

#[tokio::test]
async fn optional_identity_diagnostics_do_not_block_host_port_allow() {
    let store = ConnectAttributionStore::new(std::time::Duration::from_millis(1));
    let upstream = start_mock_tcp_server().await;
    let (sandbox_id, addr) = start_proxy_with_policy_attribution_and_identity_diagnostics(
        TEST_POLICY,
        Some(upstream),
        Some(store.clone()),
        true,
    )
    .await;

    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/diagnostic-only",
            &"d".repeat(64),
        ))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut stream = socket.connect(addr).await.unwrap();

    let response = send_connect_on_stream(&mut stream, "inference.local:443").await;
    assert!(
        response.contains("200"),
        "optional stale identity diagnostics must not block host/port allow: {response}"
    );
}

#[tokio::test]
async fn optional_identity_diagnostics_do_not_override_host_port_deny() {
    let store = ConnectAttributionStore::default();
    let (sandbox_id, addr) = start_proxy_with_policy_attribution_and_identity_diagnostics(
        TEST_POLICY,
        None,
        Some(store.clone()),
        true,
    )
    .await;

    let response = send_connect_with_attribution(
        &store,
        sandbox_id,
        addr,
        "blocked.example.com:443",
        "/usr/bin/diagnostic-only",
        &"d".repeat(64),
    )
    .await;
    assert!(
        response.contains("403"),
        "optional identity diagnostics must not override host/port deny: {response}"
    );
}

fn timing_phase_duration(
    event: &ProxyTimingEvent,
    phase_name: &'static str,
) -> Option<std::time::Duration> {
    event
        .phases
        .iter()
        .find(|phase| phase.phase == phase_name)
        .map(|phase| phase.duration)
}

async fn start_mock_tcp_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    addr
}

async fn start_recording_http_server()
-> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    start_recording_http_server_until("\r\n\r\n").await
}

async fn start_recording_http_server_until(
    stop_pattern: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut received = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                )
                .await;
                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&received).contains(stop_pattern) {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&received).into_owned());
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        }
    });
    (addr, rx)
}

/// Send a CONNECT request and return the response status line.
async fn send_connect(proxy_addr: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    send_connect_on_stream(&mut stream, target).await
}

async fn send_connect_on_stream(stream: &mut TcpStream, target: &str) -> String {
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    read_response_line(stream).await
}

async fn read_pre_request_response(stream: &mut TcpStream) -> String {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read_response_line(stream),
    )
    .await
    .unwrap_or_default()
}

async fn read_response_line(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    while stream.read(&mut buf).await.unwrap_or(0) == 1 {
        response.push(buf[0]);
        if response.ends_with(b"\n") {
            break;
        }
    }
    String::from_utf8(response).unwrap()
}

async fn send_connect_with_attribution(
    store: &ConnectAttributionStore,
    sandbox_id: SandboxId,
    proxy_addr: SocketAddr,
    target: &str,
    executable_path: &str,
    executable_sha256: &str,
) -> String {
    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            proxy_addr,
            executable_path,
            executable_sha256,
        ))
        .unwrap();
    let mut stream = socket.connect(proxy_addr).await.unwrap();
    send_connect_on_stream(&mut stream, target).await
}

fn bound_tcp_socket() -> (tokio::net::TcpSocket, SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer_addr = socket.local_addr().unwrap();
    (socket, peer_addr)
}

fn connect_attribution_record(
    sandbox_id: SandboxId,
    peer_addr: SocketAddr,
    proxy_addr: SocketAddr,
    executable_path: &str,
    executable_sha256: &str,
) -> ConnectAttributionRecord {
    ConnectAttributionRecord {
        sandbox_id,
        peer_addr,
        proxy_addr,
        pid: 42,
        executable_path: executable_path.into(),
        executable_sha256: executable_sha256.into(),
        source: ConnectAttributionSource::Test,
    }
}

#[tokio::test]
async fn allowed_host_gets_200() {
    let (_sandbox_id, addr) = start_proxy().await;

    // api.github.com:443 is in the policy — should get 200.
    // Note: the upstream connection will fail (no real server), but the
    // proxy should attempt it, meaning it passed the OPA check.
    // We test by verifying we DON'T get a 403.
    let response = send_connect(addr, "api.github.com:443").await;

    // The proxy either returns 200 (if upstream connects) or drops
    // the connection (if upstream fails). It should NOT return 403.
    assert!(
        !response.contains("403"),
        "expected allow for api.github.com, got: {response}"
    );
}

#[tokio::test]
async fn authorized_hostname_resolving_to_localhost_is_denied() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let policy = format!(
        r#"
version: 1
name: hostname-localhost-deny
network:
  mode: proxy
  policies:
    - name: local-by-name
      endpoints:
        - host: "localhost"
          port: {}
          access: read-write
"#,
        upstream_addr.port()
    );
    let (_sandbox_id, proxy_addr) = start_proxy_with_policy(&policy, None).await;

    let response = send_connect(proxy_addr, &format!("localhost:{}", upstream_addr.port())).await;
    assert!(
        response.contains("403"),
        "hostname resolution to a local address must fail closed: {response}"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "the proxy must not connect to a prohibited DNS answer"
    );
}

#[tokio::test]
async fn explicitly_authorized_local_ip_literal_connects() {
    let upstream = start_mock_tcp_server().await;
    let policy = format!(
        r#"
version: 1
name: literal-localhost-allow
network:
  mode: proxy
  policies:
    - name: explicit-local-ip
      endpoints:
        - host: "127.0.0.1"
          port: {}
          access: read-write
"#,
        upstream.port()
    );
    let (_sandbox_id, proxy_addr) = start_proxy_with_policy(&policy, None).await;

    let response = send_connect(proxy_addr, &format!("127.0.0.1:{}", upstream.port())).await;
    assert!(
        response.contains("200"),
        "an exact literal-IP policy is the explicit local-address opt-in: {response}"
    );
}

#[tokio::test]
async fn connect_and_initial_tunnel_bytes_in_one_write_reach_upstream_once() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let initial_tunnel_bytes = b"\x16\x03\x01\x00\x08axis-tls".to_vec();
    let expected_len = initial_tunnel_bytes.len();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut received = vec![0; expected_len];
        stream.read_exact(&mut received).await.unwrap();
        let mut extra = [0u8; 1];
        let duplicate = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut extra),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|count| *count > 0)
        .map(|_| extra[0]);
        received_tx.send((received, duplicate)).unwrap();
    });

    let policy = format!(
        r#"
version: 1
name: connect-early-bytes
network:
  mode: proxy
  policies:
    - name: explicit-local-ip
      endpoints:
        - host: "127.0.0.1"
          port: {}
          access: read-write
"#,
        upstream_addr.port()
    );
    let (_sandbox_id, proxy_addr) = start_proxy_with_policy(&policy, None).await;

    let target = format!("127.0.0.1:{}", upstream_addr.port());
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes();
    request.extend_from_slice(&initial_tunnel_bytes);
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&request).await.unwrap();
    let response = read_response_line(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let (received, duplicate) =
        tokio::time::timeout(std::time::Duration::from_secs(2), received_rx)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(received, initial_tunnel_bytes);
    assert_eq!(duplicate, None, "initial tunnel bytes were relayed twice");
}

#[tokio::test]
async fn plain_connect_relay_drains_response_after_client_write_shutdown() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let request = b"request-before-half-close".to_vec();
    let response = vec![b'R'; 128 * 1024];
    let expected_response = response.clone();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received_tx.send(received).unwrap();
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let policy = format!(
        r#"
version: 1
name: plain-half-close
network:
  mode: proxy
  policies:
    - name: local
      endpoints:
        - host: "127.0.0.1"
          port: {}
"#,
        upstream_addr.port()
    );
    let (_sandbox_id, proxy_addr) =
        start_proxy_with_options(&policy, None, None, false, false).await;
    let target = format!("127.0.0.1:{}", upstream_addr.port());
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    client.write_all(&request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received_response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut received_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_response, expected_response);
    assert_eq!(received_rx.await.unwrap(), request);
}

#[tokio::test]
async fn credential_relay_drains_response_after_client_write_shutdown() {
    unsafe {
        std::env::set_var("AXIS_TEST_HALF_CLOSE_KEY", "half-close-secret");
    }
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let response = vec![b'C'; 128 * 1024];
    let expected_response = response.clone();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received_tx.send(received).unwrap();
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let policy = r#"
version: 1
name: credential-half-close
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443/v1"
      api_key_env: AXIS_TEST_HALF_CLOSE_KEY
"#;
    let (_sandbox_id, proxy_addr) =
        start_proxy_with_options(policy, Some(upstream_addr), None, false, false).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
        .await
        .unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    client
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 4\r\n\r\nping",
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut received_response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut received_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_response, expected_response);
    let forwarded = String::from_utf8(received_rx.await.unwrap()).unwrap();
    assert!(forwarded.contains("Authorization: Bearer half-close-secret\r\n"));
    assert!(forwarded.ends_with("\r\nping"));
    unsafe {
        std::env::remove_var("AXIS_TEST_HALF_CLOSE_KEY");
    }
}

#[tokio::test]
async fn plain_connect_relay_keeps_client_writes_after_upstream_write_shutdown() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let request = b"request-after-upstream-half-close".to_vec();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        stream
            .write_all(b"upstream-finished-writing")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received_tx.send(received).unwrap();
    });
    let policy = format!(
        r#"
version: 1
name: upstream-half-close
network:
  mode: proxy
  policies:
    - name: local
      endpoints:
        - host: "127.0.0.1"
          port: {}
"#,
        upstream_addr.port()
    );
    let (_sandbox_id, proxy_addr) =
        start_proxy_with_options(&policy, None, None, false, false).await;
    let target = format!("127.0.0.1:{}", upstream_addr.port());
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    let mut upstream_response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut upstream_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(upstream_response, b"upstream-finished-writing");
    client.write_all(&request).await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(received_rx.await.unwrap(), request);
}

#[tokio::test]
async fn credential_relay_keeps_client_writes_after_upstream_write_shutdown() {
    unsafe {
        std::env::set_var("AXIS_TEST_REVERSE_HALF_CLOSE_KEY", "reverse-secret");
    }
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        stream
            .write_all(b"credential-upstream-finished-writing")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received_tx.send(received).unwrap();
    });
    let policy = r#"
version: 1
name: credential-reverse-half-close
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443/v1"
      api_key_env: AXIS_TEST_REVERSE_HALF_CLOSE_KEY
"#;
    let (_sandbox_id, proxy_addr) =
        start_proxy_with_options(policy, Some(upstream_addr), None, false, false).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
        .await
        .unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    let mut upstream_response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut upstream_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(upstream_response, b"credential-upstream-finished-writing");
    client
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 4\r\n\r\nping",
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let forwarded = String::from_utf8(received_rx.await.unwrap()).unwrap();
    assert!(forwarded.contains("Authorization: Bearer reverse-secret\r\n"));
    assert!(forwarded.ends_with("\r\nping"));
    unsafe {
        std::env::remove_var("AXIS_TEST_REVERSE_HALF_CLOSE_KEY");
    }
}

#[tokio::test]
async fn buffered_post_connect_bytes_are_inspected_once_in_order() {
    unsafe {
        std::env::set_var("AXIS_TEST_BUFFERED_INSPECTION_KEY", "buffered-secret");
    }
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let expected = b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 4\r\nX-Order: first\r\nAuthorization: Bearer buffered-secret\r\n\r\nbody".to_vec();
    let expected_len = expected.len();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut received = vec![0; expected_len];
        stream.read_exact(&mut received).await.unwrap();
        let mut extra = [0u8; 1];
        let duplicate = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut extra),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|count| *count > 0)
        .map(|_| extra[0]);
        received_tx.send((received, duplicate)).unwrap();
    });
    let policy = r#"
version: 1
name: buffered-credential-inspection
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443/v1"
      api_key_env: AXIS_TEST_BUFFERED_INSPECTION_KEY
"#;
    let (_sandbox_id, proxy_addr) =
        start_proxy_with_options(policy, Some(upstream_addr), None, false, false).await;
    let mut combined =
        b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n".to_vec();
    combined.extend_from_slice(
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 4\r\nX-Order: first\r\n\r\nbody",
    );
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&combined).await.unwrap();
    let mut established = [0u8; 39];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

    let (received, duplicate) =
        tokio::time::timeout(std::time::Duration::from_secs(2), received_rx)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(received, expected);
    assert_eq!(
        duplicate, None,
        "buffered inspected bytes were relayed twice"
    );
    unsafe {
        std::env::remove_var("AXIS_TEST_BUFFERED_INSPECTION_KEY");
    }
}

#[tokio::test]
async fn incomplete_inspected_requests_terminate_promptly_on_eof() {
    unsafe {
        std::env::set_var("AXIS_TEST_INCOMPLETE_REQUEST_KEY", "incomplete-secret");
    }
    let cases: [(&str, &[u8], bool); 2] = [
        (
            "head",
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\n",
            false,
        ),
        (
            "body",
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 10\r\n\r\npart",
            true,
        ),
    ];
    for (name, incomplete, forwarded_prefix) in cases {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received_tx.send(received).unwrap();
        });
        let policy = r#"
version: 1
name: incomplete-inspected-request
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443/v1"
      api_key_env: AXIS_TEST_INCOMPLETE_REQUEST_KEY
"#;
        let (_sandbox_id, proxy_addr) =
            start_proxy_with_options(policy, Some(upstream_addr), None, false, false).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
            .await
            .unwrap();
        let mut established = [0u8; 39];
        client.read_exact(&mut established).await.unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        client.write_all(incomplete).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.read_to_end(&mut response),
        )
        .await
        .unwrap_or_else(|_| panic!("{name} EOF did not terminate the client connection"))
        .unwrap();
        assert!(response.is_empty(), "{name}: unexpected proxy response");
        let forwarded = tokio::time::timeout(std::time::Duration::from_millis(500), received_rx)
            .await
            .unwrap_or_else(|_| panic!("{name} EOF did not terminate the upstream connection"))
            .unwrap();
        assert_eq!(
            !forwarded.is_empty(),
            forwarded_prefix,
            "{name}: unexpected forwarding state"
        );
        if forwarded_prefix {
            let forwarded = String::from_utf8(forwarded).unwrap();
            assert!(forwarded.contains("Authorization: Bearer incomplete-secret\r\n"));
            assert!(forwarded.ends_with("\r\npart"));
        }
    }
    unsafe {
        std::env::remove_var("AXIS_TEST_INCOMPLETE_REQUEST_KEY");
    }
}

#[tokio::test]
async fn canonical_dns_policy_matches_uppercase_trailing_dot_connect_target() {
    let upstream = start_mock_tcp_server().await;
    let policy = r#"
version: 1
name: canonical-dns-match
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "INFERENCE.LOCAL."
          port: 443
          access: read-write
"#;
    let (_sandbox_id, proxy_addr) = start_proxy_with_policy(policy, Some(upstream)).await;

    let response = send_connect(proxy_addr, "INFERENCE.LOCAL.:443").await;
    assert!(
        response.contains("200"),
        "canonical policy and CONNECT host forms must match: {response}"
    );
}

#[tokio::test]
async fn denied_host_gets_403() {
    let (_sandbox_id, addr) = start_proxy().await;

    // evil.example.com is NOT in the policy — should get 403.
    let response = send_connect(addr, "evil.example.com:443").await;
    assert!(
        response.contains("403"),
        "expected 403 for evil.example.com, got: {response}"
    );
}

#[tokio::test]
async fn denied_wrong_port_gets_403() {
    let (_sandbox_id, addr) = start_proxy().await;

    // api.github.com on port 80 is NOT in the policy — should get 403.
    let response = send_connect(addr, "api.github.com:80").await;
    assert!(
        response.contains("403"),
        "expected 403 for api.github.com:80, got: {response}"
    );
}

#[tokio::test]
async fn second_allowed_host() {
    let (_sandbox_id, addr) = start_proxy().await;

    // pypi.org:443 is in the policy.
    let response = send_connect(addr, "pypi.org:443").await;
    assert!(
        !response.contains("403"),
        "expected allow for pypi.org, got: {response}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn binary_policy_allows_current_test_binary() {
    let binary_path = std::env::current_exe().unwrap();
    let binary_path = binary_path.to_string_lossy().into_owned();
    let store = ConnectAttributionStore::default();
    let policy = format!(
        r#"
version: 1
name: proxy-binary-allow-test

network:
  mode: proxy
  policies:
    - name: current-test-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "{}"
"#,
        binary_path
    );
    let upstream = start_mock_tcp_server().await;
    let (sandbox_id, addr) =
        start_proxy_with_policy_and_attribution(&policy, Some(upstream), Some(store.clone())).await;

    let response = send_connect_with_attribution(
        &store,
        sandbox_id,
        addr,
        "inference.local:443",
        &binary_path,
        &"a".repeat(64),
    )
    .await;
    assert!(
        response.contains("200"),
        "expected current test binary to match policy, got: {response}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn binary_policy_does_not_fall_back_to_unknown_when_identity_is_available() {
    let policy = r#"
version: 1
name: proxy-binary-no-unknown-fallback-test

network:
  mode: proxy
  policies:
    - name: unknown-fallback
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "unknown"
"#;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, None).await;

    let response = send_connect(addr, "inference.local:443").await;
    assert!(
        response.contains("403"),
        "expected missing connect-time attribution to deny unknown fallback, got: {response}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn binary_policy_diagnostics_flag_still_requires_connect_time_attribution() {
    let policy = r#"
version: 1
name: proxy-binary-diagnostics-still-hard-boundary-test

network:
  mode: proxy
  policies:
    - name: unknown-fallback
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "unknown"
"#;
    let (_sandbox_id, addr) =
        start_proxy_with_policy_attribution_and_identity_diagnostics(policy, None, None, true)
            .await;

    let response = send_connect(addr, "inference.local:443").await;
    assert!(
        response.contains("403"),
        "binary-restricted policies must not use diagnostics or unknown identity for allow: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_wrong_connect_time_binary() {
    let store = ConnectAttributionStore::default();
    let policy = r#"
version: 1
name: proxy-binary-deny-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) =
        start_proxy_with_policy_and_attribution(policy, None, Some(store.clone())).await;

    let response = send_connect_with_attribution(
        &store,
        sandbox_id,
        addr,
        "inference.local:443",
        "/usr/bin/denied",
        &"b".repeat(64),
    )
    .await;
    assert!(
        response.contains("403"),
        "expected denied connect-time binary to fail policy, got: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_stale_connect_time_record() {
    let store = ConnectAttributionStore::new(std::time::Duration::from_millis(1));
    let policy = r#"
version: 1
name: proxy-binary-stale-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) =
        start_proxy_with_policy_and_attribution(policy, None, Some(store.clone())).await;

    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/allowed",
            &"a".repeat(64),
        ))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let mut stream = socket.connect(addr).await.unwrap();

    let response = read_pre_request_response(&mut stream).await;
    assert!(
        response.contains("403"),
        "expected stale connect-time record to deny, got: {response}"
    );
}

#[tokio::test]
async fn binary_policy_denies_ambiguous_connect_time_records() {
    let store = ConnectAttributionStore::default();
    let policy = r#"
version: 1
name: proxy-binary-ambiguous-test

network:
  mode: proxy
  policies:
    - name: allowed-binary
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write
      binaries:
        - path: "/usr/bin/allowed"
"#;
    let (sandbox_id, addr) =
        start_proxy_with_policy_and_attribution(policy, None, Some(store.clone())).await;

    let (socket, peer_addr) = bound_tcp_socket();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/allowed",
            &"a".repeat(64),
        ))
        .unwrap();
    store
        .insert(connect_attribution_record(
            sandbox_id,
            peer_addr,
            addr,
            "/usr/bin/other",
            &"b".repeat(64),
        ))
        .unwrap();
    let mut stream = socket.connect(addr).await.unwrap();

    let response = read_pre_request_response(&mut stream).await;
    assert!(
        response.contains("403"),
        "expected ambiguous connect-time records to deny, got: {response}"
    );
}

#[tokio::test]
async fn provider_credentials_are_injected_at_proxy_boundary() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_PROVIDER_KEY", "provider-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-injection-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_PROVIDER_KEY
"#;
    let (mock_addr, received) = start_recording_http_server().await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: InFeReNcE.LoCaL:443\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();

    let request = received.await.unwrap();
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_PROVIDER_KEY");
    }

    assert!(request.contains("Authorization: Bearer provider-secret\r\n"));
    assert!(!request.contains("AXIS_TEST_PROXY_PROVIDER_KEY"));
}

#[tokio::test]
async fn inference_token_budget_allows_bounded_request_and_rejects_oversize_before_forwarding() {
    let policy = r#"
version: 1
name: proxy-token-budget-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443"
  token_budget:
    max_tokens_per_hour: 1000
    max_tokens_per_request: 100
    action_on_exhaust: reject
"#;

    let (allowed_upstream, allowed_received) =
        start_recording_http_server_until("max_tokens").await;
    let (_sandbox_id, allowed_proxy) =
        start_proxy_with_policy(policy, Some(allowed_upstream)).await;
    let mut allowed = TcpStream::connect(allowed_proxy).await.unwrap();
    allowed
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(allowed);
    let mut response = String::new();
    reader.read_line(&mut response).await.unwrap();
    assert!(response.contains("200"));
    let body = br#"{"max_tokens":10}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    reader
        .into_inner()
        .write_all(request.as_bytes())
        .await
        .unwrap();
    assert!(allowed_received.await.unwrap().contains("max_tokens"));

    let (denied_upstream, denied_received) = start_recording_http_server().await;
    let (_sandbox_id, denied_proxy) = start_proxy_with_policy(policy, Some(denied_upstream)).await;
    let mut denied = TcpStream::connect(denied_proxy).await.unwrap();
    denied
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(denied);
    response.clear();
    reader.read_line(&mut response).await.unwrap();
    assert!(response.contains("200"));
    let body = br#"{"max_tokens":101}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    reader
        .into_inner()
        .write_all(request.as_bytes())
        .await
        .unwrap();
    let denied_request = denied_received.await.unwrap();
    assert!(
        denied_request.is_empty(),
        "oversize inference body reached provider: {denied_request:?}"
    );
}

#[tokio::test]
async fn provider_credentials_fail_closed_for_unbound_or_ambiguous_host() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_AUTHORITY_KEY", "authority-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-authority-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_AUTHORITY_KEY
"#;
    let invalid_requests: &[(&str, &[u8])] = &[
        (
            "mismatched virtual host",
            b"GET /v1/models HTTP/1.1\r\nHost: other.local:443\r\n\r\n",
        ),
        (
            "omitted non-default port",
            b"GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n",
        ),
        (
            "missing Host",
            b"GET /v1/models HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
        ),
        (
            "duplicate Host",
            b"GET /v1/models HTTP/1.1\r\nHost: inference.local:443\r\nHost: inference.local:443\r\n\r\n",
        ),
        (
            "malformed Host",
            b"GET /v1/models HTTP/1.1\r\nHost: inference.local:notaport\r\n\r\n",
        ),
        (
            "conflicting absolute-form authority",
            b"GET http://other.local:443/v1/models HTTP/1.1\r\nHost: inference.local:443\r\n\r\n",
        ),
    ];

    for (case, request) in invalid_requests {
        let (mock_addr, received) = start_recording_http_server().await;
        let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();
        assert!(response_line.contains("200"), "{case}: {response_line}");

        let mut stream = reader.into_inner();
        stream.write_all(request).await.unwrap();

        let forwarded = received.await.unwrap();
        assert!(
            forwarded.is_empty(),
            "{case} must fail closed without forwarding or injecting: {forwarded}"
        );
        assert!(!forwarded.contains("authority-secret"), "{case}");
    }
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_AUTHORITY_KEY");
    }
}

#[tokio::test]
async fn opaque_tls_like_bytes_are_relayed_unchanged() {
    let (mock_addr, received) = start_recording_http_server_until("opaque-payload").await;
    let (_sandbox_id, addr) = start_proxy_with_policy(TEST_POLICY, Some(mock_addr)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(response_line.contains("200"), "{response_line}");

    let mut stream = reader.into_inner();
    let payload = b"\x16\x03\x03opaque-payload";
    stream.write_all(payload).await.unwrap();

    let request = received.await.unwrap().into_bytes();
    assert_eq!(request, payload);
}

#[tokio::test]
async fn provider_credentials_are_injected_for_each_request_on_same_tunnel() {
    unsafe {
        std::env::set_var("AXIS_TEST_PROXY_PIPELINED_KEY", "provider-secret");
    }
    let policy = r#"
version: 1
name: proxy-credential-keepalive-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_PIPELINED_KEY
"#;
    let (mock_addr, received) = start_recording_http_server_until("/v1/models").await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\nContent-Length: 2\r\n\r\n{}GET /v1/models HTTP/1.1\r\nHost: inference.local:443\r\n\r\n",
        )
        .await
        .unwrap();

    let request = received.await.unwrap();
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_PIPELINED_KEY");
    }

    assert_eq!(
        request
            .matches("Authorization: Bearer provider-secret\r\n")
            .count(),
        2,
        "each HTTP request on a credential-bearing tunnel must be rewritten: {request}"
    );
    assert!(!request.contains("AXIS_TEST_PROXY_PIPELINED_KEY"));
}

#[tokio::test]
async fn unresolved_provider_credentials_are_not_forwarded() {
    unsafe {
        std::env::remove_var("AXIS_TEST_PROXY_MISSING_KEY");
    }
    let policy = r#"
version: 1
name: proxy-credential-missing-test

network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
          access: read-write

inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local:443"
      api_key_env: AXIS_TEST_PROXY_MISSING_KEY
"#;
    let (mock_addr, received) = start_recording_http_server().await;
    let (_sandbox_id, addr) = start_proxy_with_policy(policy, Some(mock_addr)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected CONNECT 200 before inner request validation, got: {response_line}"
    );

    let mut stream = reader.into_inner();
    stream
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\n\r\n")
        .await
        .unwrap();

    let request = received.await.unwrap();
    assert!(
        request.is_empty(),
        "missing credential must fail closed without forwarding request, got: {request}"
    );
}

#[tokio::test]
async fn inference_local_without_endpoint_gets_502() {
    // No inference endpoint configured — should get 502 Bad Gateway.
    let (_sandbox_id, addr) = start_proxy_with_inference(None).await;
    let response = send_connect(addr, "inference.local:443").await;
    assert!(
        response.contains("502"),
        "expected 502 for inference.local without endpoint, got: {response}"
    );
}

#[tokio::test]
async fn inference_local_routes_to_endpoint() {
    // Start a mock inference server.
    let mock_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_server.local_addr().unwrap();

    // Accept one connection and send a mock response.
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_server.accept().await {
            // The proxy will establish a raw TCP connection.
            // Read whatever the client sends and respond.
            let mut buf = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"model\":\"test\"}";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        }
    });

    let (_sandbox_id, addr) = start_proxy_with_inference(Some(mock_addr)).await;

    // CONNECT to inference.local — proxy should route to our mock server.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();

    // Should get 200 Connection Established (proxy connected to mock).
    assert!(
        response_line.contains("200"),
        "expected 200 for inference.local with endpoint, got: {response_line}"
    );

    // Now send an HTTP request through the tunnel.
    let inner = reader.into_inner();
    let (mut read_half, mut write_half) = tokio::io::split(inner);
    write_half
        .write_all(b"GET /v1/models HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    // Read the mock server's response through the tunnel.
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut read_half, &mut buf)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&buf[..n]);
    assert!(
        body.contains("\"model\":\"test\""),
        "expected mock inference response, got: {body}"
    );
}

#[tokio::test]
async fn inference_local_relays_streaming_responses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {\"delta\":\"one\"}\n\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stream.write_all(b"data: [DONE]\n\n").await.unwrap();
        }
    });

    let (_sandbox_id, addr) = start_proxy_with_inference(Some(mock_addr)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT inference.local:443 HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "expected 200 for inference.local with endpoint, got: {response_line}"
    );

    let inner = reader.into_inner();
    let (mut read_half, mut write_half) = tokio::io::split(inner);
    write_half
        .write_all(b"POST /v1/responses HTTP/1.1\r\nHost: inference.local\r\n\r\n")
        .await
        .unwrap();

    let received = rx.await.unwrap();
    assert!(
        received.starts_with("POST /v1/responses HTTP/1.1"),
        "expected streaming request to reach mock provider, got: {received}"
    );

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    for _ in 0..4 {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut read_half, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if String::from_utf8_lossy(&response).contains("data: [DONE]") {
            break;
        }
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.contains("data: {\"delta\":\"one\"}") && response.contains("data: [DONE]"),
        "expected streaming chunks to relay through proxy, got: {response}"
    );
}
