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
        for (key, value) in sandbox_env(&self.config.env, self.config.proxy_port) {
            cmd.env(key, value);
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

/// The environment of the sandboxed command.
///
/// In proxy mode AXIS owns the proxy variables: inherited ones are dropped and
/// `HTTP_PROXY`/`HTTPS_PROXY` name the AXIS proxy. `NO_PROXY` is not set, so a
/// request to a loopback address goes through the proxy as well. The profile
/// opens no other loopback port, and the proxy connects to a loopback endpoint
/// only when the policy names it.
fn sandbox_env(env: &[(String, String)], proxy_port: u16) -> Vec<(String, String)> {
    if proxy_port == 0 {
        return env.to_vec();
    }
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    env.iter()
        .filter(|(key, _)| !axis_core::sandbox_env::is_proxy_env_key(key))
        .cloned()
        .chain(
            ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
                .map(|key| (key.to_string(), proxy_url.clone())),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sandbox_env;

    fn value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter()
            .find(|(env_key, _)| env_key == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn proxy_mode_routes_loopback_through_the_proxy() {
        let inherited = [
            ("PATH", "/bin"),
            ("HTTP_PROXY", "http://stale-proxy:1"),
            ("NO_PROXY", "localhost,127.0.0.1,::1"),
            ("no_proxy", "127.0.0.1"),
            ("All_Proxy", "socks5://127.0.0.1:1080"),
        ]
        .map(|(key, value)| (key.to_string(), value.to_string()));

        let env = sandbox_env(&inherited, 3128);

        assert_eq!(value(&env, "PATH"), Some("/bin"));
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(value(&env, key), Some("http://127.0.0.1:3128"), "{key}");
            assert_eq!(
                env.iter().filter(|(env_key, _)| env_key == key).count(),
                1,
                "{key} must not keep a stale inherited value"
            );
        }
        for (key, _) in &env {
            assert!(
                !key.eq_ignore_ascii_case("NO_PROXY") && !key.eq_ignore_ascii_case("ALL_PROXY"),
                "{key} must not be set in proxy mode"
            );
        }
    }

    #[test]
    fn without_a_proxy_the_environment_passes_unchanged() {
        let inherited = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("LANG".to_string(), "C".to_string()),
        ];
        assert_eq!(sandbox_env(&inherited, 0), inherited);
    }
}
