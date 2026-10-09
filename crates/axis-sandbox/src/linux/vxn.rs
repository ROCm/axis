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
        // are not implemented yet (seccomp is #31 Phase 3); an operator who asks
        // for them must get an error, not a weaker sandbox.
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
                     (in-guest seccomp is a TODO, #31 Phase 3); remove it rather than \
                     run the workload unprotected"
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
                     network.mode to 'block' or 'allow' (managed-inference/proxy \
                     support is a TODO -- see axis-integration.md)"
                        .into(),
                ));
            }
        }

        // Per-run env (#20): pass SandboxConfig.env as one opaque base64 flag.
        // dom0 stages it on the input disk (off the container cmdline) and the
        // guest sources it before exec -- so secret values (e.g. ANTHROPIC_API_KEY)
        // never ride the DomU kernel cmdline. Flag goes among the run options,
        // before the image (the image parser ignores `--*` flags).
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

        // Nested enforcement (#31, Approach A): carry the enforcement-relevant
        // policy subset into the DomU as one opaque base64 flag (mirrors
        // --env-b64). dom0 stages it on the per-run input disk (.vxn-policy) and
        // vxn-init applies it INSIDE the guest before exec -- defense-in-depth
        // behind the VM boundary. Phase 1: cgroup v2 resource limits from the
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

        // TODO(vxn/axis, #31): seccomp blocked_syscalls + default-deny whitelist
        // (Phase 3, also hardens the Phase 2 mounts by denying mount/umount);
        // network endpoint allowlist (Phase 4). Phases 1-2 (cgroup limits +
        // filesystem bind-mount view) are carried in --policy-b64 above.
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
