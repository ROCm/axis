// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the AXIS gateway API.
// Tests the full HTTP stack (router + handlers) without needing native apps.
//
// Run with: cargo test --locked -p axis-gateway --test api_integration

use axis_gateway::{GatewayConfig, GatewayState, start_gateway};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Start a gateway on a random port and return its address.
async fn spawn_test_gateway() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let (event_tx, _) = broadcast::channel(64);
    let state = Arc::new(GatewayState::new(event_tx, TOKEN.into()));

    // Find a free port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release port for gateway to bind.

    let config = GatewayConfig { bind_addr: addr };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        start_gateway(config, state, shutdown_rx).await.ok();
    });

    // Wait for server to be ready — retry connect.
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    (addr, shutdown_tx)
}

async fn get(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    get_with_token(addr, path, Some(TOKEN)).await
}

async fn get_with_token(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let mut request = reqwest::Client::new().get(&url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let resp = request.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

async fn post(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

async fn delete(addr: SocketAddr, path: &str) -> (u16, serde_json::Value) {
    delete_with_token(addr, path, Some(TOKEN)).await
}

async fn delete_with_token(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    let url = format!("http://{addr}{path}");
    let mut request = reqwest::Client::new().delete(&url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let resp = request.send().await.unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

/// Opens `/ws/v1/events`, offering `protocols`.
async fn connect_events(
    addr: SocketAddr,
    protocols: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = format!("ws://{addr}/ws/v1/events")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", protocols.parse().unwrap());
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

// ── Authentication ──────────────────────────────────────────────────────

#[tokio::test]
async fn requests_without_the_token_are_refused() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    for token in [None, Some(&TOKEN[1..]), Some("f".repeat(64).as_str())] {
        let (status, body) = get_with_token(addr, "/api/v1/sandboxes", token).await;
        assert_eq!(status, 401, "token {token:?} listed sandboxes");
        assert!(body["error"].as_str().unwrap().starts_with("unauthorized"));
        let (status, _) = delete_with_token(addr, "/api/v1/sandboxes/abc-123", token).await;
        assert_eq!(status, 401, "token {token:?} destroyed a sandbox");
    }
    let (status, _) = get_with_token(addr, "/api/v1/health", None).await;
    assert_eq!(status, 200, "health check needs no token");
}

#[tokio::test]
async fn websocket_requires_the_token_subprotocol() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    assert!(connect_events(addr, "axis.v1").await.is_err());
    assert!(
        connect_events(addr, &format!("axis.v1, axis-token.{}", "f".repeat(64)))
            .await
            .is_err()
    );
    let ws = connect_events(addr, &format!("axis.v1, axis-token.{TOKEN}"))
        .await
        .expect("authorized WebSocket handshake failed");
    drop(ws);
}

async fn options(addr: SocketAddr, path: &str) -> reqwest::Response {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    client
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "https://axis.local")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap()
}

// ── Health ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok_with_version() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(!body["version"].as_str().unwrap().is_empty());
}

// ── CORS ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_preflight_returns_204() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let resp = options(addr, "/api/v1/agents").await;
    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    assert!(
        resp.headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("POST")
    );
}

#[tokio::test]
async fn responses_include_cors_headers() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let url = format!("http://{addr}/api/v1/health");
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
}

// ── Sandboxes ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_sandboxes_returns_empty_array() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/sandboxes").await;
    assert_eq!(status, 200);
    assert_eq!(body["sandboxes"], serde_json::json!([]));
}

#[tokio::test]
async fn destroy_sandbox_returns_id() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = delete(addr, "/api/v1/sandboxes/abc-123").await;
    assert_eq!(status, 200);
    assert_eq!(body["destroyed"], "abc-123");
}

// ── Agents ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_agents_returns_array() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/agents").await;
    assert_eq!(status, 200);
    assert!(body["agents"].is_array());
}

#[tokio::test]
async fn run_nonexistent_agent_returns_not_found() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = post(addr, "/api/v1/agents/fake-agent-999/run").await;
    assert_eq!(status, 404);
    assert!(body["error"].as_str().unwrap().contains("not installed"));
}

#[tokio::test]
async fn run_installed_agent_returns_sandbox_id() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    // This test will pass only if agents are installed (e.g., claude-code).
    // On CI without agents, it returns 404 which is also valid.
    let (status, body) = post(addr, "/api/v1/agents/claude-code/run").await;
    if status == 200 {
        assert!(!body["sandbox_id"].as_str().unwrap().is_empty());
        assert_eq!(body["agent"], "claude-code");
    } else {
        assert_eq!(status, 404);
    }
}

// ── 404 ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_path_returns_404() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, body) = get(addr, "/api/v1/nonexistent").await;
    assert_eq!(status, 404);
    assert_eq!(body["error"], "not found");
}

#[tokio::test]
async fn wrong_method_returns_404() {
    let (addr, _shutdown) = spawn_test_gateway().await;
    let (status, _) = delete(addr, "/api/v1/health").await;
    assert_eq!(status, 404);
}
