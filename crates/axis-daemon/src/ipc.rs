// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! IPC server for axisd <-> CLI communication.
//! Unix sockets on Linux/macOS, TCP on Windows.

use crate::sandbox_mgr::SandboxManager;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

pub type SharedManager = Arc<Mutex<SandboxManager>>;

/// Socket path for the AXIS daemon.
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("AXIS_SOCKET") {
        return PathBuf::from(path);
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("axis").join("axisd.sock")
    } else {
        PathBuf::from("/tmp/axis-axisd.sock")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcRequest {
    #[serde(rename = "create")]
    Create {
        policy_yaml: String,
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
    #[serde(rename = "exec")]
    Exec {
        sandbox_id: String,
        command: String,
        args: Vec<String>,
    },
    #[serde(rename = "destroy")]
    Destroy { sandbox_id: String },
    #[serde(rename = "list")]
    List,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub success: bool,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Start the IPC server (platform-specific transport). Every request must
/// carry `token`; see [`axis_core::daemon_auth`].
pub async fn serve(socket_path: &PathBuf, mgr: SharedManager, token: Arc<str>) -> Result<()> {
    #[cfg(unix)]
    {
        serve_unix(socket_path, mgr, token).await
    }

    #[cfg(windows)]
    {
        let _ = socket_path;
        serve_tcp(mgr, token).await
    }
}

#[cfg(unix)]
async fn serve_unix(socket_path: &PathBuf, mgr: SharedManager, token: Arc<str>) -> Result<()> {
    use tokio::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("IPC server listening on {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let response = read_and_handle(reader, &mgr, &token).await?;
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
}

#[cfg(windows)]
async fn serve_tcp(mgr: SharedManager, token: Arc<str>) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:18516").await?;
    tracing::info!("IPC server listening on 127.0.0.1:18516");

    loop {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let response = read_and_handle(reader, &mgr, &token).await?;
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
}

async fn read_and_handle<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    mgr: &SharedManager,
    token: &str,
) -> Result<IpcResponse> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(IpcResponse {
            success: false,
            data: serde_json::Value::Null,
            error: Some("empty request".into()),
        });
    }

    let request = match serde_json::from_str::<serde_json::Value>(&line) {
        Ok(request) => request,
        Err(e) => return Ok(invalid_request(e)),
    };
    let presented = request
        .get(axis_core::daemon_auth::IPC_TOKEN_FIELD)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !axis_core::daemon_auth::token_matches(token, presented) {
        return Ok(IpcResponse {
            success: false,
            data: serde_json::Value::Null,
            error: Some(
                "unauthorized: missing or invalid axisd token (sandboxed processes cannot \
                 control axisd)"
                    .into(),
            ),
        });
    }

    Ok(match serde_json::from_value::<IpcRequest>(request) {
        Ok(req) => handle_request(mgr, req).await,
        Err(e) => invalid_request(e),
    })
}

fn invalid_request(e: serde_json::Error) -> IpcResponse {
    IpcResponse {
        success: false,
        data: serde_json::Value::Null,
        error: Some(format!("invalid request: {e}")),
    }
}

async fn handle_request(mgr: &SharedManager, req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Create {
            policy_yaml,
            command,
            args,
            env,
        } => match axis_core::policy::Policy::from_yaml(&policy_yaml) {
            Ok(policy) => {
                let create_result =
                    SandboxManager::create_from_shared(mgr.clone(), policy, command, args, env)
                        .await;
                match create_result {
                    Ok(id) => IpcResponse {
                        success: true,
                        data: serde_json::json!({ "sandbox_id": id.to_string() }),
                        error: None,
                    },
                    Err(e) => IpcResponse {
                        success: false,
                        data: serde_json::Value::Null,
                        error: Some(e),
                    },
                }
            }
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid policy: {e}")),
            },
        },

        IpcRequest::Exec {
            sandbox_id,
            command,
            args,
        } => match uuid::Uuid::parse_str(&sandbox_id) {
            Ok(uuid) => {
                let id = axis_core::types::SandboxId(uuid);
                match SandboxManager::exec_in_sandbox_from_shared(mgr.clone(), id, command, args)
                    .await
                {
                    Ok(exit_code) => IpcResponse {
                        success: true,
                        data: serde_json::json!({ "exit_code": exit_code }),
                        error: None,
                    },
                    Err(e) => IpcResponse {
                        success: false,
                        data: serde_json::Value::Null,
                        error: Some(e),
                    },
                }
            }
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid sandbox_id: {e}")),
            },
        },

        IpcRequest::Destroy { sandbox_id } => match uuid::Uuid::parse_str(&sandbox_id) {
            Ok(uuid) => {
                let id = axis_core::types::SandboxId(uuid);
                let mut mgr = mgr.lock().await;
                match mgr.destroy(&id) {
                    Ok(()) => IpcResponse {
                        success: true,
                        data: serde_json::json!({ "destroyed": sandbox_id }),
                        error: None,
                    },
                    Err(e) => IpcResponse {
                        success: false,
                        data: serde_json::Value::Null,
                        error: Some(e),
                    },
                }
            }
            Err(e) => IpcResponse {
                success: false,
                data: serde_json::Value::Null,
                error: Some(format!("invalid sandbox_id: {e}")),
            },
        },

        IpcRequest::List => {
            let mgr = mgr.lock().await;
            let sandboxes = mgr.list();
            IpcResponse {
                success: true,
                data: serde_json::to_value(sandboxes).unwrap_or_default(),
                error: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn send(line: &str) -> IpcResponse {
        let mgr = Arc::new(Mutex::new(SandboxManager::with_event_broadcast(None)));
        read_and_handle(line.as_bytes(), &mgr, TOKEN).await.unwrap()
    }

    #[tokio::test]
    async fn requests_without_the_token_are_refused() {
        for line in [
            r#"{"type":"list"}"#.to_string(),
            format!(r#"{{"type":"list","token":"{}"}}"#, &TOKEN[1..]),
            format!(r#"{{"type":"list","token":"{}"}}"#, "f".repeat(64)),
            r#"{"type":"list","token":7}"#.to_string(),
            format!(
                r#"{{"type":"destroy","sandbox_id":"{}"}}"#,
                uuid::Uuid::new_v4()
            ),
        ] {
            let response = send(&line).await;
            assert!(!response.success, "accepted {line}");
            assert!(
                response.error.unwrap().starts_with("unauthorized"),
                "{line} refused for another reason"
            );
        }
    }

    #[tokio::test]
    async fn requests_with_the_token_are_handled() {
        let response = send(&format!(r#"{{"type":"list","token":"{TOKEN}"}}"#)).await;
        assert!(response.success, "{response:?}");
    }
}
