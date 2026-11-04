// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Daemon (axisd) — sandbox lifecycle manager.

mod health;
mod ipc;
pub mod policy_watch;
mod sandbox_mgr;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logging: structured JSON, configurable via AXIS_LOG_LEVEL or RUST_LOG.
    // Optional file logging via AXIS_LOG_DIR.
    let log_level = std::env::var("AXIS_LOG_LEVEL").unwrap_or_else(|_| "axis=info".into());
    let filter = EnvFilter::from_default_env().add_directive(
        log_level
            .parse()
            .unwrap_or_else(|_| "axis=info".parse().unwrap()),
    );

    if let Ok(log_dir) = std::env::var("AXIS_LOG_DIR") {
        // File logging: JSON to file + human-readable to stderr.
        let log_dir = std::path::PathBuf::from(log_dir);
        std::fs::create_dir_all(&log_dir).ok();

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join("axisd.log"))
            .expect("cannot open log file");

        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::sync::Mutex::new(file)),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_writer(std::io::stderr),
            )
            .init();

        tracing::info!("logging to {}", log_dir.join("axisd.log").display());
    } else {
        // Default: JSON to stderr.
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    }

    tracing::info!("axisd starting (pid={})", std::process::id());

    // Create broadcast channel for streaming audit events to the gateway.
    let (event_tx, _) = tokio::sync::broadcast::channel::<axis_core::audit::AuditEvent>(1024);

    let mgr = sandbox_mgr::SandboxManager::with_event_broadcast(Some(event_tx.clone()));
    let shared_mgr = std::sync::Arc::new(tokio::sync::Mutex::new(mgr));
    let socket_path = ipc::default_socket_path();
    let token: std::sync::Arc<str> = axis_core::daemon_auth::load_or_create_token()
        .map_err(|e| anyhow::anyhow!("cannot create the axisd client token: {e}"))?
        .into();

    tracing::info!("listening on {}", socket_path.display());

    // Start health check endpoint in background.
    let health_state = health::HealthState::new();
    tokio::spawn(health::serve_health(health_state.clone()));

    // Start HTTP+WebSocket gateway for GUI clients with sandbox backend.
    let gateway_config = axis_gateway::GatewayConfig::default();
    let backend = std::sync::Arc::new(sandbox_mgr::SandboxManagerBackend::new(shared_mgr.clone()));
    let gateway_state = std::sync::Arc::new(axis_gateway::GatewayState::with_backend(
        event_tx,
        backend,
        token.clone(),
    ));
    let (gw_shutdown_tx, gw_shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Err(e) =
            axis_gateway::start_gateway(gateway_config, gateway_state, gw_shutdown_rx).await
        {
            tracing::error!("gateway error: {e}");
        }
    });

    // Run IPC server with graceful shutdown on SIGTERM/SIGINT.
    // If IPC bind fails (port taken), keep running for the gateway.
    tokio::select! {
        result = ipc::serve(&socket_path, shared_mgr.clone(), token) => {
            if let Err(e) = result {
                tracing::warn!("IPC server unavailable: {e}");
                tracing::info!("gateway still running on :18519 — waiting for shutdown signal");
                shutdown_signal().await;
                tracing::info!("shutdown signal received");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        }
    }

    // Shutdown gateway.
    let _ = gw_shutdown_tx.send(());

    // Graceful shutdown: destroy all running sandboxes.
    tracing::info!("shutting down — destroying all sandboxes");

    let mut mgr = shared_mgr.lock().await;
    let sandbox_ids: Vec<axis_core::types::SandboxId> = mgr.list().iter().map(|s| s.id).collect();

    for id in &sandbox_ids {
        if let Err(e) = mgr.destroy(id) {
            tracing::warn!("failed to destroy sandbox {id}: {e}");
        }
    }

    // Clean up socket file.
    let _ = std::fs::remove_file(&socket_path);

    tracing::info!("axisd stopped ({} sandboxes cleaned up)", sandbox_ids.len());
    Ok(())
}

/// Wait for a shutdown signal (SIGTERM, SIGINT, or Ctrl+C).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => { tracing::info!("received SIGTERM"); }
            _ = sigint.recv() => { tracing::info!("received SIGINT"); }
        }
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("received Ctrl+C");
    }
}
