// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! macOS sandbox implementation using Seatbelt (sandbox-exec).
//!
//! Uses Apple's sandbox_init() via Seatbelt profile strings to restrict
//! filesystem access, network, and process capabilities. The profile is
//! generated dynamically from the AXIS policy YAML.

pub mod profile;

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use std::process::Child;

/// macOS sandbox using Seatbelt profiles.
pub(crate) struct MacosSandbox {
    config: SandboxConfig,
    child: Option<Child>,
}

impl MacosSandbox {
    pub fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        std::fs::create_dir_all(&config.workspace_dir)?;
        Ok(Self {
            config: config.clone(),
            child: None,
        })
    }
}

impl SandboxImpl for MacosSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        use std::process::Command;

        let sandbox_id = self.config.id;

        // Generate Seatbelt profile from policy.
        let seatbelt_profile = profile::generate_profile(
            &self.config.policy,
            &self.config.workspace_dir,
            self.config.proxy_port,
        );

        // Write profile to a temp file and use sandbox-exec -f.
        let profile_path = self.config.workspace_dir.join(".axis-sandbox.sb");
        std::fs::write(&profile_path, &seatbelt_profile)
            .map_err(|e| SandboxError::IsolationFailed(format!("write profile: {e}")))?;

        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-f").arg(&profile_path);
        cmd.arg("--");
        cmd.arg(&self.config.command);
        cmd.args(&self.config.args);

        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir(&self.config.workspace_dir);
        }

        // Set environment.
        cmd.env_clear();
        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        // Proxy env vars (only when proxy is active).
        if self.config.proxy_port > 0 {
            let proxy_url = format!("http://127.0.0.1:{}", self.config.proxy_port);
            cmd.env("HTTP_PROXY", &proxy_url);
            cmd.env("HTTPS_PROXY", &proxy_url);
            cmd.env("http_proxy", &proxy_url);
            cmd.env("https_proxy", &proxy_url);
            // NO_PROXY for localhost to avoid proxy loop.
            cmd.env("NO_PROXY", "localhost,127.0.0.1,::1");
            cmd.env("no_proxy", "localhost,127.0.0.1,::1");
        }

        // Capture output in daemon mode.
        if self.config.capture_output {
            let stdout = std::fs::File::create(self.config.workspace_dir.join("stdout.log"))
                .map_err(|e| SandboxError::SpawnFailed(format!("stdout: {e}")))?;
            let stderr = std::fs::File::create(self.config.workspace_dir.join("stderr.log"))
                .map_err(|e| SandboxError::SpawnFailed(format!("stderr: {e}")))?;
            cmd.stdout(std::process::Stdio::from(stdout));
            cmd.stderr(std::process::Stdio::from(stderr));
        }

        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();
        self.child = Some(child);

        tracing::info!("sandbox {sandbox_id} started on macOS (sandbox-exec), pid={pid}");
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| SandboxError::SpawnFailed("no child process".into()))?;
            let status = tokio::task::block_in_place(|| child.wait())?;
            Ok(status.code().unwrap_or(-1))
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let Some(status) = child.try_wait()? else {
            return Ok(None);
        };
        self.child.take();
        Ok(Some(status.code().unwrap_or(-1)))
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        tracing::info!("sandbox {} destroyed", self.config.id);
        Ok(())
    }
}
