// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! REST API request handlers.

use crate::GatewayState;
use crate::router::json_response;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes};
use std::sync::Arc;

type BoxBody = Full<Bytes>;

/// GET /api/v1/sandboxes — list running sandboxes.
pub async fn list_sandboxes(state: Arc<GatewayState>) -> Response<BoxBody> {
    if let Some(ref backend) = state.sandbox_backend {
        let sandboxes = backend.list_sandboxes().await;
        json_response(
            StatusCode::OK,
            serde_json::json!({ "sandboxes": sandboxes }),
        )
    } else {
        json_response(StatusCode::OK, serde_json::json!({ "sandboxes": [] }))
    }
}

/// POST /api/v1/sandboxes — create a new sandbox.
pub async fn create_sandbox(
    _req: Request<hyper::body::Incoming>,
    _state: Arc<GatewayState>,
) -> Response<BoxBody> {
    // TODO: Parse body, create sandbox via SandboxManager.
    json_response(
        StatusCode::NOT_IMPLEMENTED,
        serde_json::json!({
            "error": "sandbox creation via gateway not yet wired to daemon"
        }),
    )
}

/// DELETE /api/v1/sandboxes/:id — destroy a sandbox.
pub async fn destroy_sandbox(id: &str, state: Arc<GatewayState>) -> Response<BoxBody> {
    tracing::info!("destroy sandbox requested: {id}");
    if let Some(ref backend) = state.sandbox_backend {
        match backend.destroy_sandbox(id).await {
            Ok(()) => json_response(StatusCode::OK, serde_json::json!({ "destroyed": id })),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": e }),
            ),
        }
    } else {
        json_response(StatusCode::OK, serde_json::json!({ "destroyed": id }))
    }
}

/// GET /api/v1/agents — list installed agents.
pub async fn list_agents(_state: Arc<GatewayState>) -> Response<BoxBody> {
    let agents = discover_installed_agents();
    json_response(StatusCode::OK, serde_json::json!({ "agents": agents }))
}

/// POST /api/v1/agents/:name/run — one-click agent launch.
/// Finds the agent binary, resolves its policy, creates a sandbox, returns sandbox_id.
pub async fn run_agent(name: &str, state: Arc<GatewayState>) -> Response<BoxBody> {
    tracing::info!("run agent requested: {name}");

    // Check if agent is installed.
    let agents = discover_installed_agents();
    let agent = agents.iter().find(|a| a["name"].as_str() == Some(name));

    if agent.is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "error": format!("agent '{name}' is not installed"),
                "hint": format!("Run: axis install {name}")
            }),
        );
    }

    // Find the agent's wrapper script (which contains the real binary path).
    let (binary, policy_path) = match find_agent_binary(name) {
        Some(pair) => pair,
        None => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "error": format!("agent '{name}' is installed but wrapper not found")
                }),
            );
        }
    };

    // Read the policy YAML.
    let policy_yaml = match std::fs::read_to_string(&policy_path) {
        Ok(yaml) => yaml,
        Err(e) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": format!("cannot read policy: {e}") }),
            );
        }
    };

    // Get default flags for this agent (same as wrapper scripts).
    let default_args = agent_default_args(name);

    // Create sandbox via backend if available, otherwise return mock.
    if let Some(ref backend) = state.sandbox_backend {
        match backend
            .create_sandbox(&policy_yaml, binary, default_args)
            .await
        {
            Ok(sandbox_id) => json_response(
                StatusCode::OK,
                serde_json::json!({
                    "sandbox_id": sandbox_id,
                    "agent": name,
                    "status": "running"
                }),
            ),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "error": format!("sandbox creation failed: {e}")
                }),
            ),
        }
    } else {
        // No backend — return mock sandbox_id for UI testing.
        let sandbox_id = uuid::Uuid::new_v4().to_string();
        json_response(
            StatusCode::OK,
            serde_json::json!({
                "sandbox_id": sandbox_id,
                "agent": name,
                "status": "created (mock — no daemon backend)"
            }),
        )
    }
}

/// Find an agent's real binary path and policy path.
/// Parses the wrapper script, resolves symlinks, and skips self-referencing wrappers.
fn find_agent_binary(name: &str) -> Option<(String, String)> {
    let axis_root = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").unwrap_or_default() + "\\axis"
    } else {
        std::env::var("HOME").unwrap_or("/tmp".into()) + "/.axis"
    };

    let bin_dir = std::path::Path::new(&axis_root).join("bin");
    let policies_dir = std::path::Path::new(&axis_root)
        .join("policies")
        .join("agents");

    // Read the .cmd wrapper to extract policy path.
    let wrapper = if cfg!(windows) {
        bin_dir.join(agent_binary_name(name)).with_extension("cmd")
    } else {
        bin_dir.join(agent_binary_name(name))
    };

    let policy = if let Ok(content) = std::fs::read_to_string(&wrapper) {
        extract_quoted_after(&content, "--policy \"")
            .or_else(|| extract_quoted_after(&content, "--policy '"))
    } else {
        None
    };

    // Resolve policy path, falling back to well-known locations.
    let policy_path = policy
        .filter(|p| std::path::Path::new(p).exists())
        .or_else(|| {
            let p = policies_dir.join(format!("{name}.yaml"));
            if p.exists() {
                Some(p.to_string_lossy().to_string())
            } else {
                None
            }
        })?;

    // Find the real agent binary — NOT our own wrappers.
    let binary = resolve_agent_binary(name, &bin_dir)?;

    Some((binary, policy_path))
}

/// Resolve the actual executable for an agent, skipping AXIS wrappers.
fn resolve_agent_binary(name: &str, axis_bin_dir: &std::path::Path) -> Option<String> {
    let bin_name = agent_binary_name(name);

    // Platform-specific search for the real binary.
    if cfg!(windows) {
        // Check well-known install locations first.
        let candidates = [
            // WinGet packages (resolve symlink to real exe)
            format!(
                "{}\\Microsoft\\WinGet\\Links\\{bin_name}.exe",
                std::env::var("LOCALAPPDATA").unwrap_or_default()
            ),
            // npm-installed agents in axis tools dir
            format!(
                "{}\\tools\\{name}\\node_modules\\.bin\\{bin_name}.cmd",
                std::env::var("LOCALAPPDATA").unwrap_or_default() + "\\axis"
            ),
            // Scoop
            format!(
                "{}\\scoop\\shims\\{bin_name}.exe",
                std::env::var("USERPROFILE").unwrap_or_default()
            ),
        ];

        for candidate in &candidates {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                // Resolve symlinks to get the real binary.
                if let Ok(resolved) = std::fs::canonicalize(path) {
                    let mut resolved_str = resolved.to_string_lossy().to_string();
                    // Strip \\?\ prefix that canonicalize adds on Windows —
                    // CreateProcess doesn't accept extended-length paths.
                    if resolved_str.starts_with(r"\\?\") {
                        resolved_str = resolved_str[4..].to_string();
                    }
                    // Skip if it points back to our own wrappers.
                    if !resolved_str.contains(&axis_bin_dir.to_string_lossy().to_string()) {
                        return Some(resolved_str);
                    }
                }
                return Some(candidate.clone());
            }
        }

        // Fallback: try `where.exe` to find it on PATH (skipping our bin dir).
        if let Ok(output) = std::process::Command::new("where.exe")
            .arg(format!("{bin_name}.exe"))
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.contains(&axis_bin_dir.to_string_lossy().to_string()) {
                    if let Ok(resolved) = std::fs::canonicalize(line) {
                        let mut s = resolved.to_string_lossy().to_string();
                        if s.starts_with(r"\\?\") {
                            s = s[4..].to_string();
                        }
                        return Some(s);
                    }
                    return Some(line.to_string());
                }
            }
        }
    } else {
        // Unix: use `which` skipping our bin dir.
        if let Ok(output) = std::process::Command::new("which").arg(bin_name).output() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() && !path.contains(&axis_bin_dir.to_string_lossy().to_string()) {
                if let Ok(resolved) = std::fs::canonicalize(&path) {
                    return Some(resolved.to_string_lossy().to_string());
                }
                return Some(path);
            }
        }
    }

    None
}

/// Default CLI args for each agent when launched from the GUI.
/// Uses non-interactive / streaming modes where available since
/// the gateway captures stdout (no real TTY for TUI rendering).
fn agent_default_args(name: &str) -> Vec<String> {
    match name {
        "claude-code" => vec![
            "--dangerously-skip-permissions".to_string(),
            "--verbose".to_string(),
            "--output-format".to_string(),
            "stream-json".to_string(),
            "-p".to_string(),
            "Hello! You are running inside AXIS sandbox. Introduce yourself and list what you can help with.".to_string(),
        ],
        "codex" => vec!["--dangerously-bypass-approvals-and-sandbox".to_string()],
        _ => vec![],
    }
}

/// Map agent name to its binary name.
fn agent_binary_name(name: &str) -> &str {
    match name {
        "claude-code" => "claude",
        "gemini-cli" => "gemini",
        other => other,
    }
}

/// Extract a quoted string after a marker in text.
fn extract_quoted_after(text: &str, marker: &str) -> Option<String> {
    let idx = text.find(marker)?;
    let start = idx + marker.len();
    let quote = marker.chars().last()?;
    let rest = &text[start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Discover installed agents from the filesystem.
fn discover_installed_agents() -> Vec<serde_json::Value> {
    let axis_root = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Users\\Public".into()) + "\\axis"
    } else {
        std::env::var("HOME").unwrap_or("/tmp".into()) + "/.axis"
    };

    let tools_dir = std::path::Path::new(&axis_root).join("tools");
    let mut agents = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&tools_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                agents.push(serde_json::json!({
                    "name": name,
                    "installed": true,
                }));
            }
        }
    }

    agents
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GatewayState;
    use http_body_util::BodyExt;
    use tokio::sync::broadcast;

    fn test_state() -> Arc<GatewayState> {
        let (tx, _) = broadcast::channel(16);
        Arc::new(GatewayState::new(tx, "test-token".into()))
    }

    async fn body_json(resp: Response<BoxBody>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_list_sandboxes_returns_empty() {
        let resp = list_sandboxes(test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sandboxes"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_list_agents_returns_array() {
        let resp = list_agents(test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["agents"].is_array());
    }

    #[tokio::test]
    async fn test_destroy_sandbox_returns_id() {
        let resp = destroy_sandbox("test-id-123", test_state()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["destroyed"], "test-id-123");
    }

    #[tokio::test]
    async fn test_run_nonexistent_agent_returns_404() {
        let resp = run_agent("nonexistent-agent-xyz", test_state()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_json(resp).await;
        assert!(json["error"].as_str().unwrap().contains("not installed"));
    }
}
