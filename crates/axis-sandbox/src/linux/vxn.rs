// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! vxn backend: each AXIS sandbox is a Xen DomU (a VM), driven through the vxn
//! CLI. See docs/vxn-integration.md for the full model.
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
//! (see docs/vxn-integration.md).

use crate::sandbox::{SandboxConfig, SandboxError, SandboxImpl};
use axis_core::policy::{Compatibility, NetworkMode};
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
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b0 = c[0];
        let b1 = *c.get(1).unwrap_or(&0);
        let b2 = *c.get(2).unwrap_or(&0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if c.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Append one KEY=VAL record to the newline-delimited env blob, rejecting values
/// that can't survive that transport unambiguously. The guest sources the blob
/// line by line, so a value containing a newline (or a key containing '=' or a
/// newline) would be mis-parsed as additional assignments; base64-ing the whole
/// blob does not resolve that after decode. Fail closed rather than silently
/// injecting unintended variables.
fn push_env_record(buf: &mut String, k: &str, v: &str) -> Result<(), SandboxError> {
    if k.is_empty() || k.contains('=') || k.contains('\n') || v.contains('\n') {
        return Err(SandboxError::Unsupported(format!(
            "vxn backend cannot forward env var {k:?}: the DomU env transport is \
             newline-delimited KEY=VAL, so names must not contain '=' or newlines \
             and values must not contain newlines"
        )));
    }
    buf.push_str(k);
    buf.push('=');
    buf.push_str(v);
    buf.push('\n');
    Ok(())
}

/// True if the path carries an AXIS filesystem placeholder the vxn backend cannot
/// yet map into the DomU. Only the real placeholder tokens count -- a literal
/// path that merely contains braces (e.g. `/opt/data{old}`) is a concrete path
/// and must still be enforced, not dropped.
fn has_fs_placeholder(p: &str) -> bool {
    p.contains("{workspace}") || p.contains("{tmpdir}")
}

pub(crate) struct VxnSandbox {
    id: SandboxId,
    /// Fully-built argv: [vxn_bin, "run", "--rm", "--name", <domain>, …, image, cmd, args…]
    argv: Vec<String>,
    /// vxn binary (argv[0]), retained for the `vxn rm` teardown fallback.
    vxn_bin: String,
    /// `--name` passed to `vxn run` (becomes RUN_CONTAINER_NAME); used for the
    /// `vxn rm` teardown fallback.
    run_name: String,
    /// Xen domain name vxn derives from run_name (HV_DOMNAME = "vxn-<run_name>",
    /// see vcontainer-common.sh build_runner_args). destroy() targets it with
    /// `xl destroy` so the exact DomU is torn down, not orphaned.
    domain: String,
    /// base64(KEY=VAL\n…) of the per-run env, passed to the child via the
    /// VXN_ENV_B64 environment variable (not argv) so secret values are not
    /// exposed on the world-readable process command line.
    env_b64: Option<String>,
    capture_output: bool,
    timeout_sec: Option<u64>,
    child: Option<Child>,
    /// Frontend pid, retained so destroy() can signal it even after wait() has
    /// moved the Child into a blocking task (the interactive SIGTERM path).
    pid: Option<i32>,
    exit_code: Option<i32>,
    /// Set when the frontend was force-terminated (timeout or destroy): the DomU
    /// may have outlived its `--rm` cleanup and must be stopped explicitly.
    force_killed: bool,
}

impl VxnSandbox {
    pub(crate) fn new(config: &SandboxConfig) -> Result<Self, SandboxError> {
        if config.command.is_empty() {
            return Err(SandboxError::CreationFailed(
                "vxn backend: command must not be empty".into(),
            ));
        }

        // Fail closed on explicit process restrictions this backend cannot
        // enforce, rather than launching with image defaults and silently
        // weakening the requested policy. In-guest identity mapping and seccomp
        // are not implemented yet (seccomp is nested-enforcement Phase 3, see
        // the TODO below); an operator who asks for them must get an error, not
        // a weaker sandbox.
        {
            let p = &config.policy.process;
            if p.run_as_user.is_some() {
                return Err(SandboxError::Unsupported(
                    "vxn backend does not enforce process.run_as_user (no in-guest \
                     identity mapping yet); remove it or use a backend that supports it"
                        .into(),
                ));
            }
            if !p.blocked_syscalls.is_empty() {
                return Err(SandboxError::Unsupported(
                    "vxn backend does not enforce process.blocked_syscalls yet \
                     (in-guest seccomp is not implemented; see the nested enforcement \
                     roadmap in docs/vxn-integration.md); remove it rather than run the \
                     workload unprotected"
                        .into(),
                ));
            }
        }

        let vxn_bin = std::env::var("VXN_BIN").unwrap_or_else(|_| DEFAULT_VXN_BIN.to_string());
        // Image: VXN_BASE_IMAGE if set, else derive it from the command name --
        // for vxn the tool IS the image (`axis run -- claude` -> image "claude",
        // which vxn auto-provisions from its recipe on first run). VXN_BASE_IMAGE
        // is the escape hatch for "run a command in a base image"
        // (VXN_BASE_IMAGE=alpine axis run -- echo hi).
        let base_image = std::env::var("VXN_BASE_IMAGE").unwrap_or_else(|_| {
            std::path::Path::new(&config.command)
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_string)
                .unwrap_or_else(|| DEFAULT_BASE_IMAGE.to_string())
        });

        // Deterministic names so destroy() / timeout tears down THIS DomU instead
        // of orphaning it (which would break the fail-closed / timeout contract).
        // vxn maps `--name <run_name>` to the Xen domain "vxn-<run_name>"
        // (vcontainer-common.sh build_runner_args), which destroy() targets with
        // `xl destroy`.
        let run_name = format!("axis-{}", config.id);
        let domain = format!("vxn-{run_name}");
        let mut argv = vec![
            vxn_bin.clone(),
            "run".to_string(),
            "--rm".to_string(),
            "--name".to_string(),
            run_name.clone(),
        ];

        // Interactive terminal (`axis run` under a tty): let vxn allocate an
        // interactive session (-it). vxn routes -it over ssh-tt to dom0's DomU
        // console; AXIS runs the child with the terminal inherited (capture_output
        // is false for `axis run`) and waits without stealing the tty, so the
        // agent's TUI (e.g. claude's login/REPL) drives the real terminal.
        if config.interactive_terminal {
            argv.push("-it".to_string());
        }

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
                     network.mode to 'block' or 'allow' (managed-inference proxy \
                     support is on the roadmap in docs/vxn-integration.md)"
                        .into(),
                ));
            }
        }

        // Per-run env: pass SandboxConfig.env as one opaque base64 blob in the
        // child's VXN_ENV_B64 environment variable (see below; never argv).
        // dom0 stages it on the input disk (off the container cmdline) and the
        // guest sources it before exec -- so secret values (e.g. ANTHROPIC_API_KEY)
        // never ride the DomU kernel cmdline.
        // Env for the DomU = AXIS-collected config.env, PLUS host vars explicitly
        // named in VXN_FORWARD_ENV. The latter is a KNOWING operator opt-in that
        // re-introduces vars AXIS strips from the sandbox (e.g. ANTHROPIC_API_KEY)
        // for the direct-key path: the agent talks to the provider directly rather
        // than via AXIS's managed-inference proxy. Acceptable because the DomU is a
        // VM boundary -- the key stays within this one sandbox, not shared with the
        // host or other sandboxes. Explicit and documented, never silent: nothing
        // is forwarded unless the operator names it in VXN_FORWARD_ENV.
        let mut env_lines = String::new();
        for (k, v) in &config.env {
            push_env_record(&mut env_lines, k, v)?;
        }
        if let Ok(list) = std::env::var("VXN_FORWARD_ENV") {
            for k in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Ok(v) = std::env::var(k) {
                    push_env_record(&mut env_lines, k, &v)?;
                }
            }
        }
        // Credentials/env go to the child's ENVIRONMENT (VXN_ENV_B64), not argv.
        // /proc/<pid>/cmdline is world-readable, so a reversible base64 of e.g.
        // ANTHROPIC_API_KEY on the command line would leak to unrelated local
        // users; /proc/<pid>/environ is owner-only. dom0 reads VXN_ENV_B64 and
        // stages it on the per-run input disk, never on any kernel cmdline. Set
        // on the Command in start(). (config-a relay forwarding: see start()/docs.)
        let env_b64 = if env_lines.is_empty() {
            None
        } else {
            Some(b64(env_lines.as_bytes()))
        };

        // Nested enforcement: carry the enforcement-relevant policy subset into
        // the DomU as one opaque base64 flag (--policy-b64). dom0 stages it on
        // the per-run input disk (.vxn-policy) and vxn-init applies it INSIDE
        // the guest before exec -- defense-in-depth behind the VM boundary. Phases
        // 1-2 below are implemented; the remaining phases (see the TODO after
        // them) are part of the nested-enforcement roadmap item in
        // docs/vxn-integration.md. Phase 1: cgroup v2 resource limits from the
        // process policy. A 0 value means "disabled" upstream, so it is omitted.
        let mut policy_lines = String::new();
        {
            let p = &config.policy.process;
            if p.max_memory_mb > 0 {
                policy_lines.push_str(&format!("MAX_MEMORY_MB={}\n", p.max_memory_mb));
            }
            // effective_max_processes() collapses child_processes:Deny to 1.
            let pids = p.effective_max_processes();
            if pids > 0 {
                policy_lines.push_str(&format!("MAX_PIDS={}\n", pids));
            }
            if p.cpu_rate_percent > 0 {
                policy_lines.push_str(&format!("CPU_RATE_PERCENT={}\n", p.cpu_rate_percent));
            }
        }
        // Phase 2: filesystem policy -> DomU bind-mount view (guest: RO remount
        // read-only, RW carve-out, DENY over-mount). Unresolved placeholders like
        // {workspace} have no vxn-guest path mapping, so skip them.
        {
            let f = &config.policy.filesystem;
            let hard = matches!(f.compatibility, Compatibility::HardRequirement);
            // Skip only paths carrying a placeholder we can't map into the DomU
            // yet ({workspace}/{tmpdir}); a concrete path with literal braces is
            // still emitted. Under hard_requirement an unmappable required rule is
            // rejected rather than silently dropped.
            for (prefix, list) in [
                ("RO", &f.read_only),
                ("RW", &f.read_write),
                ("DENY", &f.deny),
            ] {
                for p in list {
                    if has_fs_placeholder(p) {
                        if hard {
                            return Err(SandboxError::Unsupported(format!(
                                "vxn backend cannot map placeholder path {p:?} into the \
                                 DomU, but filesystem.compatibility is hard_requirement; \
                                 use a concrete path or relax the requirement"
                            )));
                        }
                        continue; // best-effort: skip the unmapped placeholder
                    }
                    policy_lines.push_str(&format!("{prefix}={p}\n"));
                }
            }
        }
        if !policy_lines.is_empty() {
            argv.push(format!("--policy-b64={}", b64(policy_lines.as_bytes())));
        }

        // TODO: seccomp blocked_syscalls + default-deny whitelist
        // (Phase 3, also hardens the Phase 2 mounts by denying mount/umount);
        // network endpoint allowlist (Phase 4). Phases 1-2 (cgroup limits +
        // filesystem bind-mount view) are carried in --policy-b64 above.
        argv.push(base_image);

        // Opaque argv: encode [command, args...] as a single sentinel token
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
            id: config.id,
            argv,
            vxn_bin,
            run_name,
            domain,
            env_b64,
            capture_output: config.capture_output,
            timeout_sec: config.timeout_sec,
            child: None,
            pid: None,
            exit_code: None,
            force_killed: false,
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

    /// SIGTERM, brief grace, then SIGKILL a pid we no longer hold a Child for
    /// (the interactive wait moved the Child into a blocking task). Signalling by
    /// pid still terminates the frontend and unblocks that task's `child.wait()`.
    fn kill_pid(pid: i32) {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        for _ in 0..(KILL_GRACE_SEC * 10) {
            // kill(pid, 0) returns -1 (ESRCH) once the process is gone.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }

    /// Whether `xl list` shows no domain named `self.domain`.
    ///   Ok(true)  listing succeeded and the domain is absent (confirmed gone)
    ///   Ok(false) listing succeeded and the domain is still present
    ///   Err(_)    could not run / parse `xl list` -> the caller must fail closed
    ///
    /// This is an explicit structured check rather than matching `xl destroy`
    /// stderr, so an unrelated failure (e.g. "Runner script not found") is never
    /// mistaken for a successful teardown.
    fn domain_absent(&self) -> Result<bool, SandboxError> {
        let out = Command::new("xl")
            .arg("list")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                SandboxError::IsolationFailed(format!(
                    "could not run `xl list` to confirm teardown of {}: {e}",
                    self.domain
                ))
            })?;
        if !out.status.success() {
            return Err(SandboxError::IsolationFailed(format!(
                "`xl list` failed while confirming teardown of {}: {}",
                self.domain,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // `xl list` rows are: Name  ID  Mem  VCPUs  State  Time(s). The domain
        // name is the first whitespace-delimited field of each row after the
        // header line.
        let present = String::from_utf8_lossy(&out.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next())
            .any(|name| name == self.domain);
        Ok(!present)
    }

    /// Tear the DomU down and confirm it. `vxn run --rm` cleans it on a normal
    /// frontend exit, but a force-kill (timeout/destroy) leaves it running while
    /// its blocked `xl create -c` frontend is killed. `xl destroy` + the
    /// `domain_absent` check is the primary path (dom0 / config-b); `vxn rm` is
    /// the fallback where the host has no xl (config-a). Fail-closed: if teardown
    /// cannot be confirmed, the caller must not treat the VM as destroyed.
    fn stop_domu(&self) -> Result<(), SandboxError> {
        // Best-effort destroy; its exit status/stderr is advisory only. The
        // authoritative result is the explicit `xl list` absence check below.
        let _ = Command::new("xl")
            .args(["destroy", &self.domain])
            .stdin(Stdio::null())
            .output();
        match self.domain_absent() {
            Ok(true) => return Ok(()),
            Ok(false) => {
                return Err(SandboxError::IsolationFailed(format!(
                    "DomU {} is still present after `xl destroy`",
                    self.domain
                )));
            }
            // xl unavailable or unparsable (e.g. an SDK/config-a host with no xl):
            // fall back to tearing down through vxn.
            Err(_) => {}
        }
        match Command::new(&self.vxn_bin)
            .args(["rm", &self.run_name])
            .stdin(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(SandboxError::IsolationFailed(format!(
                "could not confirm DomU teardown: `{} rm {}` failed: {}",
                self.vxn_bin,
                self.run_name,
                String::from_utf8_lossy(&o.stderr).trim()
            ))),
            Err(e) => Err(SandboxError::IsolationFailed(format!(
                "could not tear down DomU {}: no xl, and `{} rm` failed: {e}",
                self.domain, self.vxn_bin
            ))),
        }
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
        // Per-run env/credentials go through the environment, not argv (see
        // new()): dom0 reads VXN_ENV_B64 and stages it off any command line.
        if let Some(ref blob) = self.env_b64 {
            cmd.env("VXN_ENV_B64", blob);
        }
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
        self.pid = Some(pid as i32);
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
                            // The frontend is being force-terminated; the DomU may
                            // outlive its --rm cleanup, so mark it for an explicit
                            // stop in destroy().
                            self.force_killed = true;
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

            let (_child, status) =
                joined.map_err(|e| SandboxError::IsolationFailed(format!("vxn wait join: {e}")))?;
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
        // Skip teardown ONLY on a confirmed clean exit: the frontend exited 0 on
        // its own (where `--rm` has torn the DomU down). Every other state may
        // leave the DomU alive and must run stop_domu(): still holding a Child;
        // force-killed on timeout; no exit observed yet (the interactive wait was
        // cancelled and the Child is in a blocking task); or an abnormal exit
        // code (vxn died unexpectedly while AXIS kept running -- exit_code is
        // Some(nonzero) there, which force_killed does not capture).
        let cleanly_exited =
            self.child.is_none() && !self.force_killed && self.exit_code == Some(0);
        let needs_stop = !cleanly_exited;

        if let Some(mut child) = self.child.take() {
            self.force_killed = true;
            Self::kill_child(&mut child);
        } else if self.exit_code.is_none() {
            // The Child was moved into wait()'s blocking task; signal by the
            // retained pid so the frontend actually stops (and that task's
            // child.wait() returns). Killing the frontend alone is not enough,
            // hence the explicit stop_domu() below.
            if let Some(pid) = self.pid {
                self.force_killed = true;
                Self::kill_pid(pid);
            }
        }
        if self.exit_code.is_none() {
            self.exit_code = Some(-1);
        }

        // Stop the DomU before reporting success. Killing the frontend does not
        // enforce the timeout / fail-closed contract: a lingering VM would be
        // treated as destroyed and the manager would stop cleanup retries.
        if needs_stop {
            self.stop_domu()?;
        }

        tracing::info!("sandbox {} destroyed (vxn backend)", self.id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        ChildProcessPolicy, FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkPolicy, Policy,
        ProcessPolicy, SshPolicy,
    };
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    /// Environment variables `VxnSandbox::new` reads. Every construction in these
    /// tests pins all of them, so a value inherited from the host cannot leak in.
    const VXN_ENV_VARS: [&str; 3] = ["VXN_BIN", "VXN_BASE_IMAGE", "VXN_FORWARD_ENV"];

    /// Run `f` with the given process environment overrides (`None` removes the
    /// variable). Env mutation is serialized with a module-local lock and every
    /// touched variable is restored before the lock is released.
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        struct EnvGuard(Vec<(String, Option<OsString>)>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (name, value) in self.0.drain(..).rev() {
                    // SAFETY: guarded by ENV_LOCK; restores the value captured
                    // before this helper changed it.
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(&name, value),
                            None => std::env::remove_var(&name),
                        }
                    }
                }
            }
        }

        let mut overrides: Vec<(&str, Option<&str>)> =
            VXN_ENV_VARS.iter().map(|name| (*name, None)).collect();
        for (name, value) in vars {
            match overrides.iter_mut().find(|(n, _)| n == name) {
                Some(slot) => slot.1 = *value,
                None => overrides.push((name, *value)),
            }
        }

        let mut env_guard = EnvGuard(Vec::new());
        for (name, value) in overrides {
            env_guard.0.push((name.to_string(), std::env::var_os(name)));
            // SAFETY: guarded by ENV_LOCK; EnvGuard::drop restores the previous value.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        f()
    }

    fn build(config: &SandboxConfig) -> Result<VxnSandbox, SandboxError> {
        build_with_env(config, &[])
    }

    fn build_with_env(
        config: &SandboxConfig,
        vars: &[(&str, Option<&str>)],
    ) -> Result<VxnSandbox, SandboxError> {
        with_env(vars, || VxnSandbox::new(config))
    }

    fn expect_err(result: Result<VxnSandbox, SandboxError>) -> SandboxError {
        match result {
            Ok(sandbox) => panic!("expected an error, got argv {:?}", sandbox.argv),
            Err(err) => err,
        }
    }

    fn unsupported_message(result: Result<VxnSandbox, SandboxError>) -> String {
        match expect_err(result) {
            SandboxError::Unsupported(message) => message,
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// In-repo design doc that the operator-facing rejection messages cite.
    const DOC: &str = "docs/vxn-integration.md";

    fn assert_cites_in_repo_doc(message: &str) {
        assert!(message.contains(DOC), "message must cite {DOC}: {message}");
        let doc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(DOC);
        assert!(doc.is_file(), "cited doc {} must exist", doc.display());
    }

    /// Policy with every optional control off, so each test opts into exactly
    /// the behaviour it exercises.
    fn policy(mode: NetworkMode) -> Policy {
        Policy {
            version: 1,
            name: "test".into(),
            runtime: Default::default(),
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy {
                max_processes: 0,
                max_memory_mb: 0,
                cpu_rate_percent: 0,
                ..ProcessPolicy::default()
            },
            network: NetworkPolicy {
                mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }

    fn config(policy: Policy) -> SandboxConfig {
        SandboxConfig {
            id: SandboxId::new(),
            policy,
            command: "/usr/bin/python3".into(),
            args: vec!["-c".into(), "print('hello world')".into()],
            working_dir: None,
            workspace_dir: std::env::temp_dir().join("axis-vxn-unit-test"),
            env: Vec::new(),
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: true,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: None,
            backend_preflight: Default::default(),
            startup_trace: None,
        }
    }

    /// Independent RFC 4648 decoder used to inspect encoded argv/env payloads.
    fn b64_decode(input: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assert_eq!(input.len() % 4, 0, "unpadded base64: {input:?}");
        let mut out = Vec::new();
        for quad in input.as_bytes().chunks(4) {
            let mut acc = 0u32;
            let mut pad = 0;
            for &c in quad {
                acc <<= 6;
                if c == b'=' {
                    pad += 1;
                } else {
                    assert_eq!(pad, 0, "data after padding in {input:?}");
                    let v = T.iter().position(|&t| t == c).expect("invalid base64 char");
                    acc |= v as u32;
                }
            }
            let bytes = acc.to_be_bytes();
            out.extend_from_slice(&bytes[1..4 - pad]);
        }
        out
    }

    fn decode_utf8(input: &str) -> String {
        String::from_utf8(b64_decode(input)).unwrap()
    }

    /// Decoded `--policy-b64` payload, or `None` when the flag is absent.
    fn policy_payload(sandbox: &VxnSandbox) -> Option<String> {
        let flags: Vec<&String> = sandbox
            .argv
            .iter()
            .filter(|a| a.starts_with("--policy-b64="))
            .collect();
        assert!(flags.len() <= 1, "duplicate policy flags: {flags:?}");
        flags
            .first()
            .map(|flag| decode_utf8(flag.strip_prefix("--policy-b64=").unwrap()))
    }

    // ---- b64 ----

    #[test]
    fn b64_matches_rfc4648_test_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64(input.as_bytes()), expected, "b64({input:?})");
        }
    }

    #[test]
    fn b64_uses_standard_alphabet_and_round_trips_every_byte() {
        // 0xfb 0xff exercises the '+' and '/' alphabet tail (not URL-safe).
        assert_eq!(b64(&[0xfb, 0xff, 0xbf]), "+/+/");
        let all: Vec<u8> = (0..=255).collect();
        for len in 0..=all.len() {
            assert_eq!(b64_decode(&b64(&all[..len])), &all[..len], "len {len}");
        }
    }

    // ---- push_env_record ----

    #[test]
    fn push_env_record_appends_newline_terminated_assignments() {
        let mut buf = String::new();
        push_env_record(&mut buf, "PATH", "/usr/bin:/bin").unwrap();
        push_env_record(&mut buf, "EMPTY", "").unwrap();
        push_env_record(&mut buf, "EQ", "a=b c'$\"").unwrap();
        assert_eq!(buf, "PATH=/usr/bin:/bin\nEMPTY=\nEQ=a=b c'$\"\n");
    }

    #[test]
    fn push_env_record_rejects_records_that_would_split_or_merge() {
        for (key, value) in [
            ("", "value"),
            ("A=B", "value"),
            ("A\nB", "value"),
            ("KEY", "line1\nINJECTED=1"),
            ("KEY", "\n"),
        ] {
            let mut buf = String::from("KEEP=1\n");
            let err = push_env_record(&mut buf, key, value).unwrap_err();
            assert!(
                matches!(err, SandboxError::Unsupported(_)),
                "{key:?}={value:?}: {err:?}"
            );
            assert_eq!(buf, "KEEP=1\n", "rejected record must not be appended");
        }
    }

    // ---- has_fs_placeholder ----

    #[test]
    fn has_fs_placeholder_matches_only_real_placeholder_tokens() {
        for path in [
            "{workspace}",
            "{workspace}/src",
            "{tmpdir}",
            "/data/{tmpdir}/cache",
        ] {
            assert!(has_fs_placeholder(path), "{path:?} should be a placeholder");
        }
        for path in [
            "",
            "/opt/data{old}",
            "/workspace",
            "/tmp/{tmp}",
            "{home}/.ssh",
            "{Workspace}",
            "{workspace",
        ] {
            assert!(!has_fs_placeholder(path), "{path:?} is a literal path");
        }
    }

    // ---- VxnSandbox::new: fail-closed rejections ----

    #[test]
    fn new_rejects_empty_command() {
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.command = String::new();
        let err = expect_err(build(&cfg));
        assert!(matches!(err, SandboxError::CreationFailed(_)), "{err:?}");
    }

    #[test]
    fn new_rejects_run_as_user() {
        let mut p = policy(NetworkMode::Block);
        p.process.run_as_user = Some("nobody".into());
        let err = expect_err(build(&config(p)));
        assert!(
            matches!(&err, SandboxError::Unsupported(msg) if msg.contains("run_as_user")),
            "{err:?}"
        );
    }

    #[test]
    fn blocked_syscalls_fail_closed_and_cite_in_repo_doc() {
        let mut p = policy(NetworkMode::Block);
        p.process.blocked_syscalls = vec!["ptrace".into()];
        let message = unsupported_message(build(&config(p)));
        assert!(message.contains("process.blocked_syscalls"), "{message}");
        assert_cites_in_repo_doc(&message);
    }

    #[test]
    fn proxy_network_mode_fails_closed_and_cites_in_repo_doc() {
        let message = unsupported_message(build(&config(policy(NetworkMode::Proxy))));
        assert!(message.contains("'proxy' network mode"), "{message}");
        assert_cites_in_repo_doc(&message);
    }

    #[test]
    fn new_rejects_placeholder_paths_under_hard_requirement() {
        for list in ["read_only", "read_write", "deny"] {
            let mut p = policy(NetworkMode::Block);
            p.filesystem.compatibility = Compatibility::HardRequirement;
            let path = "{workspace}/src".to_string();
            match list {
                "read_only" => p.filesystem.read_only.push(path),
                "read_write" => p.filesystem.read_write.push(path),
                _ => p.filesystem.deny.push(path),
            }
            let err = expect_err(build(&config(p)));
            assert!(
                matches!(&err, SandboxError::Unsupported(msg) if msg.contains("{workspace}/src")),
                "{list}: {err:?}"
            );
        }
    }

    #[test]
    fn new_rejects_env_values_containing_newlines() {
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.env = vec![("KEY".into(), "a\nINJECTED=1".into())];
        let err = expect_err(build(&cfg));
        assert!(matches!(err, SandboxError::Unsupported(_)), "{err:?}");
    }

    // ---- VxnSandbox::new: argv construction ----

    #[test]
    fn new_builds_named_run_argv_with_image_and_opaque_command() {
        let cfg = config(policy(NetworkMode::Allow));
        let sandbox = build(&cfg).unwrap();
        let run_name = format!("axis-{}", cfg.id);
        let token = format!(
            "__VXNARGV__{},{},{}",
            b64(b"/usr/bin/python3"),
            b64(b"-c"),
            b64(b"print('hello world')")
        );
        assert_eq!(
            sandbox.argv,
            vec![
                DEFAULT_VXN_BIN.to_string(),
                "run".into(),
                "--rm".into(),
                "--name".into(),
                run_name.clone(),
                "python3".into(),
                token,
            ]
        );
        assert_eq!(sandbox.vxn_bin, DEFAULT_VXN_BIN);
        assert_eq!(sandbox.run_name, run_name);
        assert_eq!(sandbox.domain, format!("vxn-{run_name}"));
        assert_eq!(sandbox.id, cfg.id);
        assert!(sandbox.capture_output);
        assert!(sandbox.env_b64.is_none());
        assert!(sandbox.child.is_none() && sandbox.pid.is_none());
    }

    #[test]
    fn new_carries_the_wall_clock_timeout() {
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.timeout_sec = Some(7);
        assert_eq!(build(&cfg).unwrap().timeout_sec, Some(7));
        cfg.timeout_sec = None;
        assert_eq!(build(&cfg).unwrap().timeout_sec, None);
    }

    #[test]
    fn new_names_distinct_sandboxes_distinctly() {
        let a = build(&config(policy(NetworkMode::Allow))).unwrap();
        let b = build(&config(policy(NetworkMode::Allow))).unwrap();
        assert_ne!(a.run_name, b.run_name);
        assert_ne!(a.domain, b.domain);
    }

    #[test]
    fn new_honours_vxn_bin_override() {
        let sandbox = build_with_env(
            &config(policy(NetworkMode::Allow)),
            &[("VXN_BIN", Some("/opt/vxn/bin/vxn-x86_64"))],
        )
        .unwrap();
        assert_eq!(sandbox.argv[0], "/opt/vxn/bin/vxn-x86_64");
        assert_eq!(sandbox.vxn_bin, "/opt/vxn/bin/vxn-x86_64");
    }

    #[test]
    fn new_block_mode_disables_the_guest_nic() {
        let block = build(&config(policy(NetworkMode::Block))).unwrap();
        assert_eq!(
            block
                .argv
                .iter()
                .filter(|a| a.as_str() == "--no-network")
                .count(),
            1
        );
        let allow = build(&config(policy(NetworkMode::Allow))).unwrap();
        assert!(!allow.argv.iter().any(|a| a == "--no-network"));
    }

    #[test]
    fn new_requests_interactive_session_only_for_a_terminal() {
        let mut cfg = config(policy(NetworkMode::Block));
        assert!(!build(&cfg).unwrap().argv.iter().any(|a| a == "-it"));
        cfg.interactive_terminal = true;
        let sandbox = build(&cfg).unwrap();
        let image_at = sandbox.argv.len() - 2;
        let it_at = sandbox.argv.iter().position(|a| a == "-it").unwrap();
        assert!(
            it_at < image_at,
            "-it must be a run option: {:?}",
            sandbox.argv
        );
    }

    #[test]
    fn new_derives_image_from_command_unless_overridden() {
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.command = "claude".into();
        let image = |s: &VxnSandbox| s.argv[s.argv.len() - 2].clone();
        assert_eq!(image(&build(&cfg).unwrap()), "claude");

        cfg.command = "/usr/local/bin/claude".into();
        assert_eq!(image(&build(&cfg).unwrap()), "claude");

        cfg.command = "/".into();
        assert_eq!(image(&build(&cfg).unwrap()), DEFAULT_BASE_IMAGE);

        let overridden = build_with_env(&cfg, &[("VXN_BASE_IMAGE", Some("alpine:3.20"))]).unwrap();
        assert_eq!(image(&overridden), "alpine:3.20");
    }

    #[test]
    fn new_encodes_command_and_args_as_single_opaque_token() {
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.command = "sh".into();
        cfg.args = vec![
            "--version".into(),
            "-c".into(),
            "echo \"$HOME\" && ls 'a b' ; (x)".into(),
            String::new(),
        ];
        let sandbox = build(&cfg).unwrap();
        let token = sandbox.argv.last().unwrap();
        let encoded = token.strip_prefix("__VXNARGV__").expect("sentinel prefix");
        assert!(
            !token.contains(char::is_whitespace),
            "token must be one word: {token:?}"
        );
        let decoded: Vec<String> = encoded.split(',').map(decode_utf8).collect();
        let mut expected = vec![cfg.command.clone()];
        expected.extend(cfg.args.iter().cloned());
        assert_eq!(decoded, expected);
        // No raw argument escapes the token as a loose argv element.
        assert!(!sandbox.argv.iter().any(|a| a == "--version" || a == "-c"));
    }

    // ---- VxnSandbox::new: --policy-b64 ----

    #[test]
    fn new_omits_policy_flag_when_nothing_to_enforce() {
        let sandbox = build(&config(policy(NetworkMode::Block))).unwrap();
        assert_eq!(policy_payload(&sandbox), None);
    }

    #[test]
    fn new_encodes_resource_limits_in_policy_flag() {
        let mut p = policy(NetworkMode::Block);
        p.process.max_memory_mb = 2048;
        p.process.max_processes = 64;
        p.process.cpu_rate_percent = 50;
        let sandbox = build(&config(p)).unwrap();
        assert_eq!(
            policy_payload(&sandbox).unwrap(),
            "MAX_MEMORY_MB=2048\nMAX_PIDS=64\nCPU_RATE_PERCENT=50\n"
        );
        let flag_at = sandbox
            .argv
            .iter()
            .position(|a| a.starts_with("--policy-b64="))
            .unwrap();
        assert!(
            flag_at < sandbox.argv.len() - 2,
            "policy flag must precede the image: {:?}",
            sandbox.argv
        );
    }

    #[test]
    fn new_omits_disabled_limits_and_collapses_child_process_deny() {
        // Deny caps the tree at one process whether or not a process limit is
        // otherwise configured (0 = no limit).
        for max_processes in [64, 0] {
            let mut p = policy(NetworkMode::Block);
            p.process.max_processes = max_processes;
            p.process.child_processes = ChildProcessPolicy::Deny;
            assert_eq!(
                policy_payload(&build(&config(p)).unwrap()).unwrap(),
                "MAX_PIDS=1\n",
                "max_processes = {max_processes}"
            );
        }
    }

    #[test]
    fn new_encodes_filesystem_rules_and_skips_best_effort_placeholders() {
        let mut p = policy(NetworkMode::Block);
        p.filesystem.read_only = vec!["/usr".into(), "{workspace}".into()];
        p.filesystem.read_write = vec!["{tmpdir}/scratch".into(), "/opt/data{old}".into()];
        p.filesystem.deny = vec!["/etc/shadow".into(), "{workspace}/.git".into()];
        assert!(matches!(
            p.filesystem.compatibility,
            Compatibility::BestEffort
        ));
        assert_eq!(
            policy_payload(&build(&config(p)).unwrap()).unwrap(),
            "RO=/usr\nRW=/opt/data{old}\nDENY=/etc/shadow\n"
        );
    }

    #[test]
    fn new_hard_requirement_accepts_concrete_paths() {
        let mut p = policy(NetworkMode::Block);
        p.process.max_memory_mb = 512;
        p.filesystem.compatibility = Compatibility::HardRequirement;
        p.filesystem.read_only = vec!["/usr".into()];
        p.filesystem.read_write = vec!["/opt/data{old}".into()];
        p.filesystem.deny = vec!["/root".into()];
        assert_eq!(
            policy_payload(&build(&config(p)).unwrap()).unwrap(),
            "MAX_MEMORY_MB=512\nRO=/usr\nRW=/opt/data{old}\nDENY=/root\n"
        );
    }

    // ---- VxnSandbox::new: env / secrets ----

    #[test]
    fn new_carries_env_out_of_band_and_never_in_argv() {
        let secret = "configured-secret-value";
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.env = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("API_TOKEN".into(), secret.into()),
        ];
        let sandbox = build(&cfg).unwrap();
        let blob = sandbox.env_b64.as_deref().expect("env must be carried");
        assert_eq!(
            decode_utf8(blob),
            format!("PATH=/usr/bin\nAPI_TOKEN={secret}\n")
        );
        // The env must not reach argv in any encoding: the same config without
        // env builds exactly the same command line.
        let mut no_env = cfg.clone();
        no_env.env.clear();
        assert_eq!(sandbox.argv, build(&no_env).unwrap().argv);
    }

    #[test]
    fn start_hands_env_to_the_vxn_cli_through_its_environment_only() {
        // A stand-in vxn CLI that reports what it received, so the test checks
        // the spawned process rather than VxnSandbox's fields.
        let dir = tempfile::tempdir().unwrap();
        let fake_vxn = dir.path().join("vxn");
        std::fs::write(
            &fake_vxn,
            "#!/bin/sh\nprintf 'ENV:%s\\n' \"$VXN_ENV_B64\"\nprintf 'ARG:%s\\n' \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_vxn, std::fs::Permissions::from_mode(0o700)).unwrap();

        let secret = "configured-secret-value";
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.env = vec![("API_TOKEN".into(), secret.into())];
        let mut sandbox = build_with_env(&cfg, &[("VXN_BIN", fake_vxn.to_str())]).unwrap();
        let blob = sandbox.env_b64.clone().expect("env must be carried");

        // Another test thread forking while the script was open for writing can
        // briefly make it unexecutable (ETXTBSY); that is not what is under test.
        let mut attempts = 0;
        loop {
            match sandbox.start() {
                Ok(_) => break,
                Err(SandboxError::SpawnFailed(msg))
                    if msg.contains("os error 26") && attempts < 10 =>
                {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(err) => panic!("start failed: {err:?}"),
            }
        }
        let output = sandbox.child.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let args: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("ARG:"))
            .collect();
        let expected: Vec<&str> = sandbox.argv[1..].iter().map(String::as_str).collect();
        assert_eq!(args, expected);
        assert!(stdout.contains(&format!("ENV:{blob}\n")), "{stdout}");
        for arg in args {
            assert!(!arg.contains(&blob), "env blob leaked in argv: {arg:?}");
            assert!(!arg.contains(secret), "secret leaked in argv: {arg:?}");
        }
    }

    #[test]
    fn new_forwards_only_named_host_vars_out_of_band() {
        const FORWARDED: &str = "AXIS_VXN_TEST_FORWARDED_SECRET";
        const UNNAMED: &str = "AXIS_VXN_TEST_UNNAMED_SECRET";
        const UNSET: &str = "AXIS_VXN_TEST_UNSET";
        let mut cfg = config(policy(NetworkMode::Block));
        cfg.env = vec![("PATH".into(), "/usr/bin".into())];
        let forward_list = format!(" {FORWARDED} ,,{UNSET}, ");
        let sandbox = build_with_env(
            &cfg,
            &[
                ("VXN_FORWARD_ENV", Some(&forward_list)),
                (FORWARDED, Some("forwarded-secret-value")),
                (UNNAMED, Some("must-not-forward")),
                (UNSET, None),
            ],
        )
        .unwrap();
        let blob = sandbox.env_b64.as_deref().unwrap();
        assert_eq!(
            decode_utf8(blob),
            format!("PATH=/usr/bin\n{FORWARDED}=forwarded-secret-value\n")
        );
        // Forwarding must not change argv in any encoding.
        let mut no_env = cfg.clone();
        no_env.env.clear();
        assert_eq!(sandbox.argv, build(&no_env).unwrap().argv);
    }

    #[test]
    fn new_rejects_forwarded_host_var_containing_newline() {
        const FORWARDED: &str = "AXIS_VXN_TEST_FORWARDED_MULTILINE";
        let err = expect_err(build_with_env(
            &config(policy(NetworkMode::Block)),
            &[
                ("VXN_FORWARD_ENV", Some(FORWARDED)),
                (FORWARDED, Some("a\nINJECTED=1")),
            ],
        ));
        assert!(matches!(err, SandboxError::Unsupported(_)), "{err:?}");
    }
}
