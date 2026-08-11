// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! vxn backend: each AXIS sandbox is a Xen DomU (a VM), driven through the vxn
//! CLI. See meta-virtualization's axis-integration.md for the full model.
//!
//! First cut = VM boundary only (config "a"): the host `vxn` CLI already boots /
//! uses a nested dom0 (qemu-xen backend) and dispatches the container DomU, so
//! this backend just spawns `vxn run ...` as a child process and manages it
//! through the `SandboxImpl` lifecycle. `VXN_BIN` overrides the binary; pointing
//! it at the in-dom0 `vxn` gives config "b" (no code change).
//!
//! IMPORTANT: the AXIS native process primitives (seccomp-BPF, Landlock, netns,
//! cgroups) are kernel-local — they act on whichever kernel the process runs
//! under. In a vxn DomU that is the guest's own kernel, so enforcing the
//! sandbox policy inside the VM is the responsibility of the DomU (applied
//! guest-side by its init), not of this host-side backend. The VM boundary is
//! the outer guarantee, with fine-grained in-guest enforcement layered on top
//! (see axis-integration.md).

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use axis_core::policy::NetworkMode;
use axis_core::types::SandboxId;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Default vxn CLI binary (config a). Override with `VXN_BIN` (e.g. `vxn-x86_64`,
/// an absolute path, or the in-dom0 `vxn` for config b).
const DEFAULT_VXN_BIN: &str = "vxn";
/// Default base image the DomU boots to run the sandboxed command in. AXIS-native
/// runs a command against the host fs; a vxn DomU has its own rootfs, so a base
/// image is required. Override with `VXN_BASE_IMAGE`.
const DEFAULT_BASE_IMAGE: &str = "docker.io/library/alpine:latest";
/// Grace period after SIGTERM before a hard SIGKILL (timeout / destroy).
const KILL_GRACE_SEC: u64 = 5;

/// Standard base64 (RFC 4648, with padding) — matches busybox `base64 -d` in the
/// guest. Inlined to avoid adding a direct dependency (would change Cargo.lock and
/// break `--locked`). Used only to encode short argv elements.
fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b0 = c[0];
        let b1 = *c.get(1).unwrap_or(&0);
        let b2 = *c.get(2).unwrap_or(&0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if c.len() > 1 { T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

pub(crate) struct VxnSandbox {
    id: SandboxId,
    /// Fully-built argv: [vxn_bin, "run", "--rm", <net flag>?, image, cmd, args…]
    argv: Vec<String>,
    capture_output: bool,
    timeout_sec: Option<u64>,
    child: Option<Child>,
    exit_code: Option<i32>,
}

impl VxnSandbox {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        if config.command.is_empty() {
            return Err(SandboxError::CreationFailed(
                "vxn backend: command must not be empty".into(),
            ));
        }

        let vxn_bin = std::env::var("VXN_BIN").unwrap_or_else(|_| DEFAULT_VXN_BIN.to_string());
        let base_image =
            std::env::var("VXN_BASE_IMAGE").unwrap_or_else(|_| DEFAULT_BASE_IMAGE.to_string());

        let mut argv = vec![vxn_bin, "run".to_string(), "--rm".to_string()];

        // AXIS network policy -> the DomU's NIC.
        //   Block -> --no-network (no vif at all; stronger than a netns)
        //   Allow -> default bridge (leave the flag off)
        //   Proxy (the DEFAULT) -> FAIL CLOSED. vxn has no AXIS-proxy path yet,
        //   and silently downgrading strict-proxy to allow would violate the
        //   isolation contract (no silent degradation). Require block/allow.
        match config.policy.network.mode {
            NetworkMode::Block => argv.push("--no-network".to_string()),
            NetworkMode::Allow => {}
            NetworkMode::Proxy => {
                return Err(SandboxError::Unsupported(
                    "vxn backend does not yet enforce 'proxy' network mode; set \
                     network.mode to 'block' or 'allow' (strict-proxy is a TODO)"
                        .into(),
                ));
            }
        }

        // TODO(vxn/axis): filesystem deny/allow -> DomU mount set; rw workspace
        // (#15, two-hop in config a); env transport (#20); nested seccomp/Landlock
        // enforcement inside the DomU (defense-in-depth). First cut = base image +
        // command only.
        argv.push(base_image);

        // Opaque argv (#31): encode [command, args...] as a single sentinel token
        //   __VXNARGV__<base64(arg0)>,<base64(arg1)>,...
        // instead of loose args. It is one space-free, metacharacter-free word
        // starting with '_', so vxn's parser can't eat a container flag (e.g.
        // `--version`) and no shell hop can re-lex quotes/parens/$ in transit. The
        // guest (vxn-init.sh exec_in_container) decodes it back to a vector and
        // exec's it verbatim as positional params -- so an arbitrary agent command
        // (claude, python -c '...', ...) runs exactly as AXIS specified it.
        let mut toks = Vec::with_capacity(1 + config.args.len());
        toks.push(b64(config.command.as_bytes()));
        for a in &config.args {
            toks.push(b64(a.as_bytes()));
        }
        argv.push(format!("__VXNARGV__{}", toks.join(",")));

        Ok(Self {
            id: config.id.clone(),
            argv,
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec,
            child: None,
            exit_code: None,
        })
    }

    /// SIGTERM, brief grace, then SIGKILL the foreground `vxn run` child.
    fn kill_child(child: &mut Child) {
        let pid = child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        for _ in 0..(KILL_GRACE_SEC * 10) {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = child.wait();
    }
}

impl SandboxImpl for VxnSandbox {
    fn start(&mut self) -> Result<u32, SandboxError> {
        if self.child.is_some() {
            return Err(SandboxError::SpawnFailed(
                "vxn sandbox already running".into(),
            ));
        }
        let mut cmd = Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..]);
        if self.capture_output {
            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped());
        }
        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(format!("vxn run spawn failed: {e}")))?;
        let pid = child.id();
        tracing::info!("sandbox {} started as a vxn DomU (pid={pid})", self.id);
        self.child = Some(child);
        Ok(pid)
    }

    fn wait(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, SandboxError>> + Send + '_>>
    {
        Box::pin(async move {
            if let Some(code) = self.exit_code {
                return Ok(code);
            }
            let mut child = self
                .child
                .take()
                .ok_or_else(|| SandboxError::SpawnFailed("no vxn child process".into()))?;
            let pid = child.id() as i32;
            let timeout_sec = self.timeout_sec;

            // std Child::wait blocks; run it on a blocking thread so we can await.
            let mut task = tokio::task::spawn_blocking(move || {
                let status = child.wait();
                (child, status)
            });

            let joined = match timeout_sec {
                None => (&mut task).await,
                Some(secs) => {
                    let sleep = tokio::time::sleep(Duration::from_secs(secs));
                    tokio::pin!(sleep);
                    tokio::select! {
                        j = &mut task => j,
                        _ = &mut sleep => {
                            tracing::warn!(
                                "sandbox {} exceeded timeout {secs}s; terminating DomU",
                                self.id
                            );
                            // SIGTERM unblocks the child.wait() on the blocking
                            // thread; grace, then SIGKILL if still stuck.
                            unsafe { libc::kill(pid, libc::SIGTERM); }
                            match tokio::time::timeout(
                                Duration::from_secs(KILL_GRACE_SEC),
                                &mut task,
                            )
                            .await
                            {
                                Ok(j) => j,
                                Err(_) => {
                                    unsafe { libc::kill(pid, libc::SIGKILL); }
                                    (&mut task).await
                                }
                            }
                        }
                    }
                }
            };

            let (_child, status) = joined
                .map_err(|e| SandboxError::IsolationFailed(format!("vxn wait join: {e}")))?;
            let code = status.map_err(SandboxError::Io)?.code().unwrap_or(-1);
            self.exit_code = Some(code);
            tracing::info!("sandbox {} exited (code={code})", self.id);
            Ok(code)
        })
    }

    fn try_wait(&mut self) -> Result<Option<i32>, SandboxError> {
        if let Some(code) = self.exit_code {
            return Ok(Some(code));
        }
        let status_opt = match self.child.as_mut() {
            Some(child) => child.try_wait()?,
            None => return Err(SandboxError::SpawnFailed("no vxn child process".into())),
        };
        match status_opt {
            Some(status) => {
                self.child = None;
                let code = status.code().unwrap_or(-1);
                self.exit_code = Some(code);
                Ok(Some(code))
            }
            None => Ok(None),
        }
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut().and_then(|c| c.stdout.take())
    }

    fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.as_mut().and_then(|c| c.stderr.take())
    }

    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.as_mut().and_then(|c| c.stdin.take())
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(mut child) = self.child.take() {
            Self::kill_child(&mut child);
            if self.exit_code.is_none() {
                self.exit_code = Some(-1);
            }
        }
        // TODO(vxn/axis): `vxn run --rm` cleans the DomU on normal exit, but on a
        // hard kill the DomU may linger; a best-effort `vxn rm` / `xl destroy` by
        // domain name belongs here once we track it. Idempotent (contract).
        tracing::info!("sandbox {} destroyed (vxn backend)", self.id);
        Ok(())
    }
}
