// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS CLI — command-line interface for managing sandboxed agent execution.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(unix)]
mod pty_bridge;

#[derive(Parser)]
#[command(name = "axis", about = "AXIS: Agent eXecution Isolation Substrate")]
#[command(version)]
struct Cli {
    /// Path to axisd Unix socket.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and start a new sandbox.
    Create {
        /// Built-in policy name or path to a policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Command to execute inside the sandbox.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Execute a command in an existing sandbox.
    Exec {
        /// Sandbox ID.
        #[arg(long)]
        sandbox: String,

        /// Command to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Destroy a running sandbox.
    Destroy {
        /// Sandbox ID.
        sandbox: String,
    },

    /// List running sandboxes.
    List,

    /// Policy management subcommands.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Model management subcommands.
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },

    /// Install agent runtimes into contained ~/.axis/tools/ directory.
    Install {
        /// Agents to install (or --all).
        #[arg(trailing_var_arg = true)]
        agents: Vec<String>,

        /// Install all supported agents.
        #[arg(long)]
        all: bool,

        /// List available agents.
        #[arg(long)]
        list: bool,

        /// Wrap system-installed binaries instead of downloading new copies.
        #[arg(long)]
        use_system: bool,
    },

    /// Uninstall agents and clean up AXIS data.
    Uninstall {
        /// Agents to uninstall (or --all).
        #[arg(trailing_var_arg = true)]
        agents: Vec<String>,

        /// Remove all agents, tools, policies, and state.
        #[arg(long)]
        all: bool,
    },

    /// View sandbox logs (stdout/stderr and audit events).
    Logs {
        /// Sandbox ID.
        sandbox: String,

        /// Follow log output (tail -f style).
        #[arg(long, short)]
        follow: bool,

        /// Show only the last N lines.
        #[arg(long, short = 'n', default_value = "50")]
        tail: usize,
    },

    /// Run a command in a new sandbox (auto-starts daemon).
    /// Equivalent to: axis create + attach stdio + destroy on exit.
    Run {
        /// Built-in policy name or path to a policy YAML file.
        #[arg(long, default_value = "minimal")]
        policy: String,

        /// Command to execute inside the sandbox.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    #[command(name = "__axis-pty-bridge", hide = true)]
    PtyBridge {
        #[arg(long)]
        socket: PathBuf,

        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Show inference server status.
    Inference {
        #[command(subcommand)]
        action: InferenceAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy YAML file.
    Validate {
        /// Path to the policy file.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum ModelAction {
    /// List registered models.
    List,
    /// Pull a model from HuggingFace.
    Pull { name: String },
    /// Remove a model.
    Remove { name: String },
}

#[derive(Subcommand)]
enum InferenceAction {
    /// Show live inference server status.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Git-style subcommand extension: if the first arg matches a wrapper
    // in ~/.axis/bin/, execute it directly. This lets `axis claude ...`
    // work as `claude ...` through the AXIS sandbox.
    if let Some(result) = try_agent_subcommand() {
        std::process::exit(result);
    }

    // Suppress logging when stdin is a TTY and we're running an agent
    // (the TUI agent would be confused by JSON log lines on stderr).
    let is_interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let first_arg = std::env::args().nth(1);
    let is_run_cmd = first_arg.as_deref() == Some("run");
    let is_pty_bridge_cmd = first_arg.as_deref() == Some("__axis-pty-bridge");
    let quiet =
        (is_interactive && is_run_cmd && std::env::var("AXIS_LOG").is_err()) || is_pty_bridge_cmd;

    if quiet {
        // Minimal logging — only errors.
        tracing_subscriber::fmt()
            .with_env_filter("axis=error")
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("axis=info".parse()?),
            )
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Uninstall { agents, all } => {
            let bin_dir = axis_bin_dir();
            let axis_root = bin_dir.parent().unwrap_or(&bin_dir).to_path_buf();

            if all {
                eprintln!("Removing all AXIS agent data...");

                // Remove symlinks pointing into .axis first.
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_default();
                if !home.is_empty() {
                    for entry in std::fs::read_dir(&home).into_iter().flatten().flatten() {
                        let path = entry.path();
                        if path.is_symlink()
                            && let Ok(target) = std::fs::read_link(&path)
                            && target.to_string_lossy().contains(".axis")
                        {
                            eprintln!("  Removing symlink: {}", path.display());
                            let _ = std::fs::remove_file(&path);
                            // Restore backup.
                            let backup = PathBuf::from(format!("{}.axis-backup", path.display()));
                            if backup.exists() {
                                let _ = std::fs::rename(&backup, &path);
                                eprintln!("  Restored: {}", path.display());
                            }
                        }
                    }
                }

                // Remove all AXIS directories.
                for dir in &["tools", "bin", "agents", "policies"] {
                    let p = axis_root.join(dir);
                    if p.exists() {
                        eprintln!("  Removing: {}", p.display());
                        let _ = std::fs::remove_dir_all(&p);
                    }
                }

                eprintln!("Done. AXIS agent data removed.");
                eprintln!("Note: the axis binary itself is not removed.");
            } else if agents.is_empty() {
                eprintln!("Usage:");
                eprintln!("  axis uninstall claude-code aider   Remove specific agents");
                eprintln!("  axis uninstall --all               Remove all agents and AXIS data");
                eprintln!();

                // List installed agents.
                if bin_dir.exists() {
                    eprintln!("Installed agents:");
                    for entry in std::fs::read_dir(&bin_dir).into_iter().flatten().flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let name = name
                            .strip_suffix(".cmd")
                            .or(name.strip_suffix(".ps1"))
                            .unwrap_or(&name);
                        eprintln!("  {name}");
                    }
                }
            } else {
                for agent in &agents {
                    let install_name = known_agent(agent).unwrap_or(agent.as_str());
                    let binary_name = agent;

                    eprintln!("Removing {agent}...");

                    // Remove wrapper(s).
                    for ext in &["", ".cmd", ".ps1"] {
                        let wrapper = bin_dir.join(format!("{binary_name}{ext}"));
                        if wrapper.exists() {
                            let _ = std::fs::remove_file(&wrapper);
                            eprintln!("  Removed: {}", wrapper.display());
                        }
                    }

                    // Remove tool directory.
                    let tool_dir = axis_root.join("tools").join(install_name);
                    if tool_dir.exists() {
                        let _ = std::fs::remove_dir_all(&tool_dir);
                        eprintln!("  Removed: {}", tool_dir.display());
                    }

                    // Remove agent state.
                    let state_dir = axis_root
                        .join("agents")
                        .join(format!("agent-{install_name}"));
                    if state_dir.exists() {
                        let _ = std::fs::remove_dir_all(&state_dir);
                        eprintln!("  Removed: {}", state_dir.display());
                    }

                    // Remove symlinks for this agent.
                    let home = std::env::var("HOME")
                        .or_else(|_| std::env::var("USERPROFILE"))
                        .unwrap_or_default();
                    if !home.is_empty() {
                        let agent_state = axis_root
                            .join("agents")
                            .join(format!("agent-{install_name}"));
                        for entry in std::fs::read_dir(&home).into_iter().flatten().flatten() {
                            let path = entry.path();
                            if path.is_symlink()
                                && let Ok(target) = std::fs::read_link(&path)
                                && target.starts_with(&agent_state)
                            {
                                let _ = std::fs::remove_file(&path);
                                eprintln!("  Removed symlink: {}", path.display());
                                let backup =
                                    PathBuf::from(format!("{}.axis-backup", path.display()));
                                if backup.exists() {
                                    let _ = std::fs::rename(&backup, &path);
                                    eprintln!("  Restored: {}", path.display());
                                }
                            }
                        }
                    }
                }
                eprintln!("Done.");
            }
        }

        Commands::Install {
            agents,
            all,
            list,
            use_system,
        } => {
            // Install bundled policies.
            // On Windows: %LOCALAPPDATA%\axis (matches PS1 installer).
            // On Unix: ~/.axis
            let axis_root = if cfg!(windows) {
                PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
                    std::env::var("USERPROFILE").unwrap_or("C:\\Users\\Public".into())
                }))
                .join("axis")
            } else {
                PathBuf::from(std::env::var("HOME").unwrap_or("/tmp".into())).join(".axis")
            };
            let pol_dir = axis_root.join("policies").join("agents");
            std::fs::create_dir_all(&pol_dir)?;
            for (name, content) in [
                (
                    "base-deny.yaml",
                    include_str!("../../../policies/agents/base-deny.yaml"),
                ),
                (
                    "claude-code.yaml",
                    include_str!("../../../policies/agents/claude-code.yaml"),
                ),
                (
                    "claude-code-ssh.yaml",
                    include_str!("../../../policies/agents/claude-code-ssh.yaml"),
                ),
                (
                    "codex.yaml",
                    include_str!("../../../policies/agents/codex.yaml"),
                ),
                (
                    "openclaw.yaml",
                    include_str!("../../../policies/agents/openclaw.yaml"),
                ),
                (
                    "ironclaw.yaml",
                    include_str!("../../../policies/agents/ironclaw.yaml"),
                ),
                (
                    "nanoclaw.yaml",
                    include_str!("../../../policies/agents/nanoclaw.yaml"),
                ),
                (
                    "zeroclaw.yaml",
                    include_str!("../../../policies/agents/zeroclaw.yaml"),
                ),
                (
                    "hermes.yaml",
                    include_str!("../../../policies/agents/hermes.yaml"),
                ),
                (
                    "gemini-cli.yaml",
                    include_str!("../../../policies/agents/gemini-cli.yaml"),
                ),
                (
                    "opencode.yaml",
                    include_str!("../../../policies/agents/opencode.yaml"),
                ),
                (
                    "gemini-cli.yaml",
                    include_str!("../../../policies/agents/gemini-cli.yaml"),
                ),
                (
                    "opencode.yaml",
                    include_str!("../../../policies/agents/opencode.yaml"),
                ),
            ] {
                let _ = std::fs::write(pol_dir.join(name), content);
            }

            #[cfg(unix)]
            {
                let install_script = include_str!("../../../e2e/agents/install_agents.sh");
                let script_path = std::env::temp_dir().join("axis-install-agents.sh");
                std::fs::write(&script_path, install_script)?;

                let mut cmd = std::process::Command::new("bash");
                cmd.arg(&script_path);
                if use_system {
                    cmd.arg("--use-system");
                }
                if list {
                    cmd.arg("--list");
                } else if all {
                    cmd.arg("--all");
                } else if agents.is_empty() {
                    cmd.arg("--help");
                } else {
                    cmd.args(&agents);
                }

                let status = cmd.status()?;
                let _ = std::fs::remove_file(&script_path);
                std::process::exit(status.code().unwrap_or(1));
            }

            #[cfg(windows)]
            {
                let _ = use_system;
                let install_script = include_str!("../../../e2e/agents/install_agents.ps1");
                let script_path = std::env::temp_dir().join("axis-install-agents.ps1");
                std::fs::write(&script_path, install_script)?;

                let mut cmd = std::process::Command::new("powershell");
                cmd.args(["-ExecutionPolicy", "Bypass", "-Command"]);

                // Build the PowerShell command string.
                let mut ps_cmd = format!("& '{}'", script_path.display());
                if list {
                    ps_cmd.push_str(" -List");
                } else if all {
                    ps_cmd.push_str(" -All");
                } else if !agents.is_empty() {
                    ps_cmd.push_str(&format!(" -Agents @('{}')", agents.join("','")));
                }
                cmd.arg(&ps_cmd);

                let status = cmd.status()?;
                let _ = std::fs::remove_file(&script_path);
                std::process::exit(status.code().unwrap_or(1));
            }
        }

        Commands::Create { policy, command } => {
            let policy_yaml = resolve_policy_yaml(&policy)?;

            // Validate policy before sending to daemon.
            let parsed = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
            eprintln!("Policy '{}' validated successfully.", parsed.name);

            let (cmd, args) = command.split_first().expect("command required");

            let request = serde_json::json!({
                "type": "create",
                "policy_yaml": policy_yaml,
                "command": cmd,
                "args": args,
                "env": [],
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                let id = response["data"]["sandbox_id"].as_str().unwrap_or("unknown");
                println!("Sandbox created: {id}");
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::Logs {
            sandbox,
            follow,
            tail,
        } => {
            // Read stdout/stderr logs from the sandbox workspace.
            let request = serde_json::json!({ "type": "list" });
            let response = send_ipc(&cli.socket, &request).await?;

            // Find sandbox workspace from the list.
            let workspace = response["data"]
                .as_array()
                .and_then(|arr| {
                    arr.iter().find(|s| {
                        s["id"]
                            .as_str()
                            .map(|id| id.starts_with(&sandbox))
                            .unwrap_or(false)
                    })
                })
                .and_then(|s| s["workspace"].as_str())
                .map(PathBuf::from);

            let workspace = match workspace {
                Some(ws) => ws,
                None => {
                    // Try the default workspace path.
                    let base = if let Ok(home) = std::env::var("HOME") {
                        PathBuf::from(home).join(".local/share/axis/sandboxes")
                    } else {
                        PathBuf::from("/tmp/axis/sandboxes")
                    };
                    base.join(&sandbox)
                }
            };

            let stdout_path = workspace.join("stdout.log");
            let stderr_path = workspace.join("stderr.log");

            if !stdout_path.exists() && !stderr_path.exists() {
                eprintln!("No logs found for sandbox '{sandbox}'");
                eprintln!("  Checked: {}", workspace.display());
                std::process::exit(1);
            }

            // Read and display logs.
            for (label, path) in [("stdout", &stdout_path), ("stderr", &stderr_path)] {
                if path.exists() {
                    let content = std::fs::read_to_string(path)?;
                    let lines: Vec<&str> = content.lines().collect();
                    let start = lines.len().saturating_sub(tail);
                    if !lines[start..].is_empty() {
                        println!("--- {label} ---");
                        for line in &lines[start..] {
                            println!("{line}");
                        }
                    }
                }
            }

            if follow {
                eprintln!("(following — press Ctrl+C to stop)");
                // Tail the stdout file.
                if stdout_path.exists() {
                    let mut last_size = std::fs::metadata(&stdout_path)?.len();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let meta = std::fs::metadata(&stdout_path)?;
                        if meta.len() > last_size {
                            let file = std::fs::File::open(&stdout_path)?;
                            use std::io::{Read, Seek, SeekFrom};
                            let mut file = file;
                            file.seek(SeekFrom::Start(last_size))?;
                            let mut buf = String::new();
                            file.read_to_string(&mut buf)?;
                            print!("{buf}");
                            last_size = meta.len();
                        }
                    }
                }
            }
        }

        Commands::Exec { sandbox, command } => {
            let (cmd, args) = command.split_first().expect("command required");
            let request = serde_json::json!({
                "type": "exec",
                "sandbox_id": sandbox,
                "command": cmd,
                "args": args,
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                let code = response["data"]["exit_code"].as_i64().unwrap_or(0);
                if code != 0 {
                    eprintln!("Command exited with code {code}");
                }
                std::process::exit(code as i32);
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::Destroy { sandbox } => {
            let request = serde_json::json!({
                "type": "destroy",
                "sandbox_id": sandbox,
            });

            let response = send_ipc(&cli.socket, &request).await?;
            if response["success"].as_bool() == Some(true) {
                println!("Sandbox {sandbox} destroyed.");
            } else {
                let err = response["error"].as_str().unwrap_or("unknown error");
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }

        Commands::List => {
            let request = serde_json::json!({ "type": "list" });
            let response = send_ipc(&cli.socket, &request).await?;

            if response["success"].as_bool() == Some(true) {
                let data = &response["data"];
                if let Some(arr) = data.as_array() {
                    if arr.is_empty() {
                        println!("No running sandboxes.");
                    } else {
                        println!("{:<38} {:<10} {:<8} WORKSPACE", "ID", "STATUS", "PID");
                        for s in arr {
                            println!(
                                "{:<38} {:<10} {:<8} {}",
                                s["id"].as_str().unwrap_or("-"),
                                s["status"].as_str().unwrap_or("-"),
                                s["pid"]
                                    .as_u64()
                                    .map(|p| p.to_string())
                                    .unwrap_or("-".into()),
                                s["workspace"].as_str().unwrap_or("-"),
                            );
                        }
                    }
                }
            }
        }

        Commands::Policy { action } => match action {
            PolicyAction::Validate { path } => {
                let yaml = std::fs::read_to_string(&path)?;
                match axis_core::policy::Policy::from_yaml(&yaml) {
                    Ok(policy) => {
                        println!("Policy '{}' is valid.", policy.name);
                        println!(
                            "  Runtime: {} via {}",
                            policy.runtime.containment.as_str(),
                            policy.runtime.provider.as_str(),
                        );
                        println!(
                            "  Filesystem: {} read-only, {} read-write, {} deny paths",
                            policy.filesystem.read_only.len(),
                            policy.filesystem.read_write.len(),
                            policy.filesystem.deny.len(),
                        );
                        println!(
                            "  Process: max {} processes, {}MB memory, {}% CPU",
                            policy.process.max_processes,
                            policy.process.max_memory_mb,
                            policy.process.cpu_rate_percent,
                        );
                        println!(
                            "  Network: {:?} mode, {} endpoint policies",
                            policy.network.mode,
                            policy.network.policies.len(),
                        );
                        println!("  Inference: {} routes", policy.inference.routes.len());
                        if policy.gpu.enabled {
                            println!(
                                "  GPU: device={}, transport={:?}, vram_limit={}",
                                policy.gpu.device,
                                policy.gpu.transport,
                                policy
                                    .gpu
                                    .vram_limit_mb
                                    .map(|m| format!("{m}MB"))
                                    .unwrap_or("unlimited".into()),
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Policy validation failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Model { action } => match action {
            ModelAction::List => {
                let reg = axis_router::models::ModelRegistry::new();
                let models = reg.list();
                if models.is_empty() {
                    println!("No models registered. Use `axis model pull` to download one.");
                } else {
                    println!("{:<30} {:<12} {:<10} PATH", "NAME", "FORMAT", "VRAM");
                    for m in models {
                        println!(
                            "{:<30} {:<12} {:<10} {}",
                            m.name,
                            format!("{:?}", m.format).to_lowercase(),
                            m.vram_required_mb
                                .map(|v| format!("{v}MB"))
                                .unwrap_or("-".into()),
                            m.local_path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or("-".into()),
                        );
                    }
                }
            }
            ModelAction::Pull { name } => {
                let mut reg = axis_router::models::ModelRegistry::new();
                eprintln!("Pulling model: {name}");
                match reg.pull(&name).await {
                    Ok(path) => {
                        println!("Model downloaded: {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ModelAction::Remove { name } => {
                let mut reg = axis_router::models::ModelRegistry::new();
                if reg.remove(&name) {
                    println!("Model '{name}' removed from registry.");
                } else {
                    eprintln!("Model '{name}' not found in registry.");
                }
            }
        },

        Commands::Run { policy, command } => {
            let policy_yaml = resolve_policy_yaml(std::path::Path::new(&policy))?;

            // Validate.
            let parsed = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
            if !is_interactive {
                eprintln!("AXIS: sandbox '{}' starting...", parsed.name);
            }

            // Try to connect to existing daemon, or start one inline.
            let (cmd, args) = command.split_first().expect("command required");

            let request = serde_json::json!({
                "type": "create",
                "policy_yaml": policy_yaml,
                "command": cmd,
                "args": args,
                "env": [],
            });

            match send_ipc(&cli.socket, &request).await {
                Ok(response) => {
                    if response["success"].as_bool() == Some(true) {
                        let id = response["data"]["sandbox_id"].as_str().unwrap_or("?");
                        eprintln!("AXIS: sandbox {id} running");
                        eprintln!("AXIS: press Ctrl+C to stop");

                        // Wait for Ctrl+C, then destroy.
                        tokio::signal::ctrl_c().await.ok();

                        eprintln!("\nAXIS: shutting down sandbox {id}...");
                        let destroy_req = serde_json::json!({
                            "type": "destroy",
                            "sandbox_id": id,
                        });
                        let _ = send_ipc(&cli.socket, &destroy_req).await;
                        eprintln!("AXIS: done.");
                    } else {
                        let err = response["error"].as_str().unwrap_or("unknown");
                        eprintln!("Error: {err}");
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    // Daemon not running — run sandbox directly (standalone mode).
                    let quiet = std::io::IsTerminal::is_terminal(&std::io::stdin());
                    if !quiet {
                        eprintln!("AXIS: daemon not running, using standalone mode");
                    }

                    let policy = axis_core::policy::Policy::from_yaml(&policy_yaml)?;
                    let sandbox_id = axis_core::types::SandboxId::new();
                    let workspace = std::env::current_dir()?;
                    let connect_attribution =
                        if axis_core::connect_attribution::policy_requires_connect_attribution(
                            &policy,
                        ) {
                            Some(axis_core::connect_attribution::ConnectAttributionStore::default())
                        } else {
                            None
                        };
                    let inference_endpoint = configured_standalone_inference_endpoint()?;

                    // Start an inline proxy if policy uses proxy mode.
                    let proxy_addr = match standalone_proxy_config_for_sandbox(
                        sandbox_id,
                        &policy,
                        inference_endpoint,
                        connect_attribution.clone(),
                    ) {
                        Some(proxy_config) => {
                            let mut proxy = axis_proxy::proxy::AxisProxy::new(proxy_config)
                                .map_err(|e| anyhow::anyhow!("proxy: {e}"))?;
                            let addr = proxy
                                .bind()
                                .await
                                .map_err(|e| anyhow::anyhow!("proxy bind: {e}"))?;
                            if !quiet {
                                eprintln!("AXIS: proxy on {addr}");
                            }
                            tokio::spawn(async move {
                                let _ = proxy.run().await;
                            });
                            Some(addr)
                        }
                        None => None,
                    };
                    let proxy_port = proxy_addr.map(|addr| addr.port()).unwrap_or(0);

                    let mut env = collect_standalone_sandbox_env();

                    // Auto-discover runtime directories (Node.js, Python) and
                    // append them to PATH so npm-installed agents and Python
                    // venvs work without users needing to configure PATH.
                    if cfg!(windows) {
                        let extra_dirs = discover_runtime_dirs();
                        if !extra_dirs.is_empty()
                            && let Some(path_entry) =
                                env.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
                        {
                            for dir in &extra_dirs {
                                if !path_entry.1.to_lowercase().contains(&dir.to_lowercase()) {
                                    path_entry.1.push(';');
                                    path_entry.1.push_str(dir);
                                }
                            }
                        }
                    }

                    let timeout_sec = policy.process.timeout_sec;
                    let config = axis_sandbox::SandboxConfig {
                        id: sandbox_id,
                        policy,
                        command: cmd.to_string(),
                        args: args.to_vec(),
                        working_dir: Some(workspace.clone()),
                        workspace_dir: workspace,
                        env,
                        proxy_port,
                        proxy_addr,
                        connect_attribution,
                        capture_output: false,
                        interactive_terminal: quiet,
                        pty_bridge_helper: None,
                        timeout_sec,
                        backend_preflight: Default::default(),
                        startup_trace: None,
                    };

                    let mut sandbox = axis_sandbox::Sandbox::create(config)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    sandbox.start().map_err(|e| anyhow::anyhow!("{e}"))?;

                    if !quiet {
                        eprintln!(
                            "AXIS: sandbox running (pid={}), Ctrl+C to stop",
                            sandbox.pid.unwrap_or(0)
                        );
                    }

                    if quiet {
                        // Interactive mode: just wait for the child to exit.
                        // Don't install a Ctrl+C handler, because it steals the
                        // TTY from the child process and breaks TUI apps like
                        // Claude Code (setRawMode fails).
                        let code = wait_for_interactive_standalone_sandbox(&mut sandbox).await?;
                        sandbox.destroy().ok();
                        std::process::exit(code);
                    } else {
                        // Non-interactive: wait for process or Ctrl+C.
                        tokio::select! {
                            code = sandbox.wait() => {
                                let code = code.map_err(|e| anyhow::anyhow!("{e}"))?;
                                std::process::exit(code);
                            }
                            _ = tokio::signal::ctrl_c() => {
                                sandbox.destroy().map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                        }
                    }
                }
            }
        }

        Commands::PtyBridge { socket, command } => {
            #[cfg(unix)]
            {
                let code = pty_bridge::run(socket, command)?;
                std::process::exit(code);
            }

            #[cfg(not(unix))]
            {
                let _ = socket;
                let _ = command;
                anyhow::bail!("PTY bridge is not supported on this platform");
            }
        }

        Commands::Inference { action } => match action {
            InferenceAction::Status => {
                println!("Inference status not yet implemented.");
            }
        },
    }

    Ok(())
}

fn resolve_policy_yaml(policy: &std::path::Path) -> anyhow::Result<String> {
    if policy.exists() {
        return Ok(std::fs::read_to_string(policy)?);
    }

    let name = policy
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("policy path is not valid UTF-8: {}", policy.display()))?;
    let yaml = match name {
        "minimal" => include_str!("../../../policies/minimal.yaml"),
        "coding-agent" => include_str!("../../../policies/coding-agent.yaml"),
        "gpu-agent" => include_str!("../../../policies/gpu-agent.yaml"),
        "vxn" => include_str!("../../../policies/vxn.yaml"),
        _ => {
            return Err(anyhow::anyhow!(
                "policy '{name}' not found; use a file path or one of: minimal, coding-agent, gpu-agent, vxn"
            ));
        }
    };
    Ok(yaml.to_string())
}

#[cfg(unix)]
async fn wait_for_interactive_standalone_sandbox(
    sandbox: &mut axis_sandbox::Sandbox,
) -> Result<i32> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        code = sandbox.wait() => Ok(code.map_err(|e| anyhow::anyhow!("{e}"))?),
        _ = terminate.recv() => {
            sandbox.destroy().map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(128 + libc::SIGTERM)
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_interactive_standalone_sandbox(
    sandbox: &mut axis_sandbox::Sandbox,
) -> Result<i32> {
    sandbox.wait().await.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Git-style subcommand extension.
///
/// If `axis claude -p "hello"` is run and "claude" is not a built-in
/// subcommand, check ~/.axis/bin/claude for a wrapper. If found, exec it
/// with the remaining args. This lets `axis <agent> [args]` work for any
/// installed agent.
fn try_agent_subcommand() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();

    // Need at least: axis <subcommand>
    if args.len() < 2 {
        return None;
    }

    let subcmd = &args[1];

    // Skip if it's a built-in command, a flag, or --help/--version.
    if subcmd.starts_with('-') {
        return None;
    }
    let builtins = [
        "create",
        "exec",
        "destroy",
        "list",
        "logs",
        "run",
        "install",
        "policy",
        "model",
        "inference",
        "__axis-pty-bridge",
        "help",
    ];
    if builtins.contains(&subcmd.as_str()) {
        return None;
    }

    // Look for wrapper in the AXIS bin directory.
    let bin_dir = axis_bin_dir();

    // On Unix: ~/.axis/bin/claude (shell script)
    // On Windows: %LOCALAPPDATA%\axis\bin\claude.cmd
    let wrapper = if cfg!(windows) {
        bin_dir.join(format!("{subcmd}.cmd"))
    } else {
        bin_dir.join(subcmd)
    };

    if !wrapper.exists() {
        // Wrapper not found — check if this is a known agent and offer to install.
        return try_prompt_install(subcmd);
    }

    // Found a wrapper — exec it with remaining args.
    let agent_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

    let status = if cfg!(windows) {
        // On Windows, run .cmd via cmd.exe
        std::process::Command::new("cmd")
            .args(["/C", &wrapper.to_string_lossy()])
            .args(&agent_args)
            .env("AXIS_BIN", std::env::current_exe().unwrap_or_default())
            .status()
            .ok()?
    } else {
        std::process::Command::new(&wrapper)
            .args(&agent_args)
            .env("AXIS_BIN", std::env::current_exe().unwrap_or_default())
            .status()
            .ok()?
    };

    Some(status.code().unwrap_or(1))
}

/// Get the AXIS bin directory (platform-specific).
fn axis_bin_dir() -> std::path::PathBuf {
    if cfg!(windows) {
        // Windows: %LOCALAPPDATA%\axis\bin
        std::path::PathBuf::from(
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
                std::env::var("USERPROFILE").unwrap_or("C:\\Users\\Public".into())
            }),
        )
        .join("axis")
        .join("bin")
    } else {
        // Unix: ~/.axis/bin
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or("/tmp".into()))
            .join(".axis")
            .join("bin")
    }
}

/// Known agent binary names → install names.
fn known_agent(binary_name: &str) -> Option<&'static str> {
    match binary_name {
        "claude" => Some("claude-code"),
        "codex" => Some("codex"),
        "openclaw" => Some("openclaw"),
        "ironclaw" => Some("ironclaw"),
        "aider" => Some("aider"),
        "goose" => Some("goose"),
        "gemini" => Some("gemini-cli"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

/// Prompt to install a known but not-yet-installed agent.
fn try_prompt_install(subcmd: &str) -> Option<i32> {
    let install_name = known_agent(subcmd)?;

    eprintln!("'{subcmd}' is not installed. Install it with AXIS sandbox protection?\n");
    eprintln!("  This will:");
    eprintln!("    - Install {subcmd} to ~/.axis/tools/{install_name}/");
    eprintln!("    - Create a sandboxed wrapper at ~/.axis/bin/{subcmd}");
    eprintln!("    - Apply default-deny network + filesystem policy");
    eprintln!();
    eprint!("Install {subcmd}? [Y/n] ");

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Some(1);
    }

    let answer = input.trim().to_lowercase();
    if answer.is_empty() || answer == "y" || answer == "yes" {
        // Run axis install <agent>.
        let axis_bin = std::env::current_exe().unwrap_or_else(|_| "axis".into());
        let status = std::process::Command::new(&axis_bin)
            .args(["install", install_name])
            .status()
            .ok()?;

        if !status.success() {
            return Some(status.code().unwrap_or(1));
        }

        // After install, retry the original command.
        eprintln!(
            "\nRunning: {subcmd} {}",
            std::env::args().skip(2).collect::<Vec<_>>().join(" ")
        );
        let args: Vec<String> = std::env::args().collect();
        let agent_args: Vec<&str> = args[2..].iter().map(|s| s.as_str()).collect();

        let bin_dir = axis_bin_dir();
        let wrapper = if cfg!(windows) {
            bin_dir.join(format!("{subcmd}.cmd"))
        } else {
            bin_dir.join(subcmd)
        };

        if wrapper.exists() {
            let status = if cfg!(windows) {
                std::process::Command::new("cmd")
                    .args(["/C", &wrapper.to_string_lossy()])
                    .args(&agent_args)
                    .env("AXIS_BIN", &axis_bin)
                    .status()
                    .ok()?
            } else {
                std::process::Command::new(&wrapper)
                    .args(&agent_args)
                    .env("AXIS_BIN", &axis_bin)
                    .status()
                    .ok()?
            };
            Some(status.code().unwrap_or(1))
        } else {
            eprintln!(
                "Install succeeded but wrapper not found at {}",
                wrapper.display()
            );
            Some(1)
        }
    } else {
        eprintln!("Not installing. To install manually: axis install {install_name}");
        Some(0)
    }
}

/// Send a JSON request to the axisd daemon via IPC.
/// Uses Unix sockets on Linux/macOS, TCP on Windows.
async fn send_ipc(
    socket_override: &Option<PathBuf>,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut json = serde_json::to_string(request)?;
    json.push('\n');

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        let socket_path = socket_override.clone().unwrap_or_else(|| {
            if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(xdg).join("axis").join("axisd.sock")
            } else {
                PathBuf::from("/tmp/axis-axisd.sock")
            }
        });

        let stream = UnixStream::connect(&socket_path).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axisd at {}: {e}\nIs the daemon running? Start it with: axisd",
                socket_path.display()
            )
        })?;

        let (reader, mut writer) = stream.into_split();
        writer.write_all(json.as_bytes()).await?;

        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(serde_json::from_str(&response)?)
    }

    #[cfg(windows)]
    {
        use tokio::net::TcpStream;

        // On Windows, axisd listens on a TCP port (default 18516).
        let addr = socket_override
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("127.0.0.1:18516");

        let stream = TcpStream::connect(addr).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot connect to axisd at {addr}: {e}\nIs the daemon running? Start it with: axisd"
            )
        })?;

        let (reader, mut writer) = stream.into_split();
        writer.write_all(json.as_bytes()).await?;

        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        Ok(serde_json::from_str(&response)?)
    }
}

fn proxy_bind_addr_for_sandbox(
    id: axis_core::types::SandboxId,
    proxy_port: u16,
    policy: &axis_core::policy::Policy,
) -> std::net::SocketAddr {
    #[cfg(target_os = "linux")]
    {
        if matches!(policy.network.mode, axis_core::policy::NetworkMode::Proxy) {
            return axis_sandbox::linux::netns::proxy_bind_addr(id, proxy_port);
        }
    }

    let _ = id;
    let _ = policy;
    format!("127.0.0.1:{proxy_port}").parse().unwrap()
}

fn standalone_proxy_config_for_sandbox(
    id: axis_core::types::SandboxId,
    policy: &axis_core::policy::Policy,
    inference_endpoint: Option<std::net::SocketAddr>,
    connect_attribution: Option<axis_core::connect_attribution::ConnectAttributionStore>,
) -> Option<axis_proxy::proxy::ProxyConfig> {
    if !matches!(policy.network.mode, axis_core::policy::NetworkMode::Proxy) {
        return None;
    }

    Some(axis_proxy::proxy::ProxyConfig {
        sandbox_id: id,
        bind_addr: proxy_bind_addr_for_sandbox(id, 0, policy),
        policy: policy.clone(),
        enable_leak_detection: true,
        inference_endpoint,
        connect_attribution,
        enable_identity_diagnostics: false,
        timing_tx: None,
    })
}

fn configured_standalone_inference_endpoint() -> anyhow::Result<Option<std::net::SocketAddr>> {
    let Some(value) = std::env::var_os("AXIS_INFERENCE_ENDPOINT") else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("AXIS_INFERENCE_ENDPOINT must be valid Unicode"))?;
    value
        .parse()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("invalid AXIS_INFERENCE_ENDPOINT '{value}': {error}"))
}

fn collect_standalone_sandbox_env() -> Vec<(String, String)> {
    collect_standalone_sandbox_env_from(std::env::vars())
}

fn collect_standalone_sandbox_env_from<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    vars.into_iter()
        .filter(|(key, _)| axis_core::sandbox_env::is_collected_sandbox_env_key(key))
        .collect()
}

/// Discover common runtime directories (Node.js, Python) that may not be
/// in PATH. Returns directories that exist and contain expected binaries.
/// This lets npm-installed agents and Python venvs work out-of-the-box
/// without users needing to configure PATH manually.
#[cfg(windows)]
fn discover_runtime_dirs() -> Vec<String> {
    let mut dirs = Vec::new();

    // Node.js — standard MSI install location
    let node_dir = r"C:\Program Files\nodejs";
    if std::path::Path::new(node_dir).join("node.exe").exists() {
        dirs.push(node_dir.to_string());
    }

    // Node.js — nvm-windows
    if let Ok(nvm_home) = std::env::var("NVM_HOME") {
        if let Ok(nvm_symlink) = std::env::var("NVM_SYMLINK") {
            if std::path::Path::new(&nvm_symlink).join("node.exe").exists() {
                dirs.push(nvm_symlink);
            }
        } else if std::path::Path::new(&nvm_home).join("node.exe").exists() {
            dirs.push(nvm_home);
        }
    }

    // Node.js — Volta
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        let volta_bin = format!(r"{home}\Volta\bin");
        if std::path::Path::new(&volta_bin).join("node.exe").exists() {
            dirs.push(volta_bin);
        }
    }

    // Python — Windows Store / standard install
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let ms_store = format!(r"{local}\Microsoft\WindowsApps");
        if std::path::Path::new(&ms_store).join("python.exe").exists()
            || std::path::Path::new(&ms_store).join("python3.exe").exists()
        {
            dirs.push(ms_store);
        }
    }

    // Git for Windows (often needed for git operations inside agents)
    let git_dir = r"C:\Program Files\Git\bin";
    if std::path::Path::new(git_dir).join("git.exe").exists() {
        dirs.push(git_dir.to_string());
    }

    dirs
}

#[cfg(not(windows))]
fn discover_runtime_dirs() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::policy::{
        FilesystemPolicy, GpuPolicy, InferencePolicy, NetworkMode, NetworkPolicy, Policy,
        ProcessPolicy, RuntimeProvider, SshPolicy,
    };
    use axis_core::types::SandboxId;
    use std::str::FromStr;

    #[test]
    fn policy_resolver_supports_builtins_files_and_missing_names() {
        for name in ["minimal", "coding-agent", "gpu-agent"] {
            let yaml = resolve_policy_yaml(std::path::Path::new(name)).unwrap();
            let parsed = axis_core::policy::Policy::from_yaml(&yaml).unwrap();
            assert!(!parsed.name.is_empty());
        }

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("custom.yaml");
        let custom = "version: 1\nname: custom-policy\nnetwork:\n  mode: block\n";
        std::fs::write(&path, custom).unwrap();
        assert_eq!(resolve_policy_yaml(&path).unwrap(), custom);

        let error = resolve_policy_yaml(std::path::Path::new("missing-policy")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("policy 'missing-policy' not found")
        );
    }

    #[test]
    fn standalone_proxy_planning_covers_backend_and_network_mode_matrix() {
        let id = SandboxId::from_str("00000000-0000-4000-8000-000000000001").unwrap();
        let loopback = "127.0.0.1:0".parse().unwrap();

        for provider in [
            RuntimeProvider::Auto,
            RuntimeProvider::Mxc,
            RuntimeProvider::AxisNative,
        ] {
            for mode in [NetworkMode::Block, NetworkMode::Allow, NetworkMode::Proxy] {
                let policy = test_policy(provider, mode.clone());
                let bind_addr = proxy_bind_addr_for_sandbox(id, 0, &policy);
                let proxy_config = standalone_proxy_config_for_sandbox(id, &policy, None, None);

                if matches!(mode, NetworkMode::Proxy) {
                    #[cfg(target_os = "linux")]
                    {
                        assert_eq!(
                            bind_addr,
                            axis_sandbox::linux::netns::proxy_bind_addr(id, 0),
                            "provider {provider:?} must use strict Linux proxy addressing"
                        );
                        assert_ne!(
                            bind_addr, loopback,
                            "provider {provider:?} must not weaken Linux proxy isolation"
                        );
                    }

                    #[cfg(not(target_os = "linux"))]
                    assert_eq!(
                        bind_addr, loopback,
                        "provider {provider:?} must keep the native platform proxy address"
                    );

                    let config = proxy_config.expect("proxy mode should plan an inline proxy");
                    assert_eq!(config.sandbox_id, id);
                    assert_eq!(config.bind_addr, bind_addr);
                    assert!(config.enable_leak_detection);
                    assert!(config.inference_endpoint.is_none());
                } else {
                    assert_eq!(
                        bind_addr, loopback,
                        "provider {provider:?} mode {mode:?} must keep loopback"
                    );
                    assert!(
                        proxy_config.is_none(),
                        "provider {provider:?} mode {mode:?} must not plan a proxy"
                    );
                }
            }
        }
    }

    #[test]
    fn standalone_proxy_keeps_host_inference_endpoint_out_of_policy_data() {
        let id = SandboxId::new();
        let policy = test_policy(RuntimeProvider::Mxc, NetworkMode::Proxy);
        let endpoint = "127.0.0.1:8080".parse().unwrap();

        let config =
            standalone_proxy_config_for_sandbox(id, &policy, Some(endpoint), None).unwrap();

        assert_eq!(config.inference_endpoint, Some(endpoint));
        assert!(config.policy.inference.routes.is_empty());
    }

    #[test]
    fn standalone_env_collection_omits_provider_secrets_and_proxy_vars() {
        let env = collect_standalone_sandbox_env_from(vec![
            ("PATH".into(), "/bin".into()),
            ("ANTHROPIC_API_KEY".into(), "secret".into()),
            ("OPENAI_API_KEY".into(), "secret".into()),
            ("ANTHROPIC_BASE_URL".into(), "https://api.example".into()),
            ("AXIS_INFERENCE_ENDPOINT".into(), "127.0.0.1:8080".into()),
            ("All_Proxy".into(), "http://proxy-with-creds".into()),
            ("UNRELATED".into(), "value".into()),
        ]);

        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("ANTHROPIC_BASE_URL".into(), "https://api.example".into()),
            ]
        );
    }

    fn test_policy(runtime_provider: RuntimeProvider, network_mode: NetworkMode) -> Policy {
        let runtime = axis_core::policy::RuntimePolicy {
            provider: runtime_provider,
            ..Default::default()
        };

        Policy {
            version: 1,
            name: "test-policy".into(),
            runtime,
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy {
                mode: network_mode,
                policies: Vec::new(),
            },
            inference: InferencePolicy::default(),
            gpu: GpuPolicy::default(),
            ssh: SshPolicy::default(),
            amd: None,
        }
    }
}
