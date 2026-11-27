// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use axis_core::policy::{NetworkMode, Policy};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

struct AgentFixture {
    target: &'static str,
    path: &'static str,
    mode: ExpectedNetworkMode,
    hosts: &'static [&'static str],
}

#[derive(Clone, Copy)]
enum ExpectedNetworkMode {
    Block,
    Proxy,
}

const AGENT_FIXTURES: &[AgentFixture] = &[
    AgentFixture {
        target: "BYO command",
        path: "policies/agents/base-deny.yaml",
        mode: ExpectedNetworkMode::Block,
        hosts: &[],
    },
    AgentFixture {
        target: "Claude Code",
        path: "policies/agents/claude-code.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &["api.anthropic.com", "auth.anthropic.com"],
    },
    AgentFixture {
        target: "Claude Code SSH",
        path: "policies/agents/claude-code-ssh.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &["api.anthropic.com", "auth.anthropic.com", "github.com"],
    },
    AgentFixture {
        target: "Codex",
        path: "policies/agents/codex.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &[
            "api.openai.com",
            "chatgpt.com",
            "api.github.com",
            "github.com",
        ],
    },
    AgentFixture {
        target: "Gemini CLI",
        path: "policies/agents/gemini-cli.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &[
            "generativelanguage.googleapis.com",
            "accounts.google.com",
            "oauth2.googleapis.com",
        ],
    },
    AgentFixture {
        target: "Hermes-style agents",
        path: "policies/agents/hermes.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &[
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
        ],
    },
    AgentFixture {
        target: "Ironclaw",
        path: "policies/agents/ironclaw.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &["api.anthropic.com", "api.openai.com", "api.near.ai"],
    },
    AgentFixture {
        target: "Nanoclaw",
        path: "policies/agents/nanoclaw.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &["api.anthropic.com", "api.openai.com"],
    },
    AgentFixture {
        target: "OpenClaw",
        path: "policies/agents/openclaw.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &["api.anthropic.com", "api.openai.com", "clawhub.ai"],
    },
    AgentFixture {
        target: "OpenCode",
        path: "policies/agents/opencode.yaml",
        mode: ExpectedNetworkMode::Proxy,
        hosts: &[
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
        ],
    },
    AgentFixture {
        target: "ZeroClaw",
        path: "policies/agents/zeroclaw.yaml",
        mode: ExpectedNetworkMode::Block,
        hosts: &[],
    },
];

#[test]
fn bundled_agent_policy_fixtures_parse_and_cover_expected_targets() {
    for fixture in AGENT_FIXTURES {
        let policy = load_policy(fixture.path);

        assert_network_mode(&policy, fixture.mode, fixture.target);
        assert_agent_secret_stores_denied(&policy, fixture.target);
        assert_agent_policy_avoids_cgroup_only_limits(&policy, fixture.target);

        let actual_hosts = endpoint_hosts(&policy);
        for expected_host in fixture.hosts {
            assert!(
                actual_hosts.contains(*expected_host),
                "{} fixture {} must include endpoint host {expected_host}",
                fixture.target,
                fixture.path
            );
        }
    }
}

#[test]
fn bundled_agent_policies_grant_only_their_own_config_directories() {
    for fixture in AGENT_FIXTURES {
        let policy = load_policy(fixture.path);
        let expected_config = format!("~/.axis/agents/{}/xdg-config", policy.name);
        let axis_grants = policy
            .filesystem
            .read_only
            .iter()
            .map(|path| ("read_only", path.as_str()))
            .chain(
                policy
                    .filesystem
                    .read_write
                    .iter()
                    .map(|path| ("read_write", path.as_str())),
            )
            .filter(|(_, path)| *path == "~/.axis" || path.starts_with("~/.axis/"))
            .collect::<Vec<_>>();

        assert_eq!(
            axis_grants,
            [("read_write", expected_config.as_str())],
            "{} fixture {} must grant its separate config directory without exposing legacy config or other agent state",
            fixture.target,
            fixture.path
        );
    }
}

#[test]
fn bundled_policies_do_not_grant_shared_config() {
    for fixture in AGENT_FIXTURES {
        let policy = load_policy(fixture.path);
        assert!(policy.filesystem.deny.contains(&"~/.config".to_string()));
        for grant in policy
            .filesystem
            .read_only
            .iter()
            .chain(&policy.filesystem.read_write)
        {
            assert!(
                grant != "~"
                    && grant != "~/"
                    && grant != "~/.config"
                    && !grant.starts_with("~/.config/"),
                "{} exposes shared config through {grant}",
                fixture.path
            );
        }
    }
    let policy = load_policy("policies/claude-code-macos.yaml");
    assert!(policy.filesystem.deny.contains(&"~/.config".to_string()));
    assert!(
        !policy
            .filesystem
            .read_write
            .contains(&"~/.config".to_string())
    );
    assert!(
        policy
            .filesystem
            .read_write
            .contains(&"~/.axis/agents/claude-code-macos/xdg-config".to_string())
    );
}

#[test]
fn committed_agent_policy_directory_contains_only_tested_fixtures() {
    let policy_dir = repo_root().join("policies/agents");
    let mut actual = std::fs::read_dir(&policy_dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();
            assert_eq!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yaml"),
                "unexpected non-YAML agent fixture {}",
                path.display()
            );
            relative_to_repo(&path)
        })
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = AGENT_FIXTURES
        .iter()
        .map(|fixture| fixture.path.to_string())
        .collect::<Vec<_>>();
    expected.sort();

    assert_eq!(
        actual, expected,
        "new agent policy fixtures need explicit target coverage"
    );
}

#[test]
fn coding_agent_inference_policy_uses_supported_local_route_without_raw_secrets() {
    let policy = load_policy("policies/coding-agent.yaml");
    let local = policy
        .inference
        .routes
        .iter()
        .find(|route| route.name == "local-rocm")
        .expect("coding-agent policy must keep a local inference route");
    assert_eq!(local.endpoint.as_deref(), Some("http://localhost:8080"));
    assert_eq!(
        local.protocols,
        ["openai_chat_completions", "model_discovery"]
    );
    assert!(local.api_key_env.is_none());

    assert!(
        policy
            .inference
            .routes
            .iter()
            .all(|route| route.api_key_env.is_none()),
        "the bundled policy must not advertise unsupported HTTPS credential injection"
    );
    let budget = policy.inference.token_budget.as_ref().unwrap();
    assert!(matches!(
        budget.action_on_exhaust,
        axis_core::policy::ExhaustAction::Reject
    ));
    assert!(budget.fallback_route.is_none());
}

#[test]
fn target_status_document_covers_agents_providers_and_inference_apis() {
    let doc = std::fs::read_to_string(repo_root().join("docs/agent-provider-inference-targets.md"))
        .unwrap();
    for target in [
        "Claude Code",
        "Codex",
        "OpenCode",
        "GitHub Copilot CLI",
        "Gemini CLI",
        "OpenClaw",
        "Hermes-style agents",
        "BYO commands",
        "OpenAI",
        "Anthropic",
        "GitHub",
        "GitLab",
        "Copilot",
        "Google Vertex AI",
        "generic providers",
        "local OpenAI-compatible endpoints",
        "chat completions",
        "completions",
        "responses",
        "embeddings",
        "model discovery",
        "Anthropic messages",
        "streaming",
    ] {
        assert!(
            doc.contains(target),
            "target status document must cover {target}"
        );
    }
}

fn load_policy(relative_path: &str) -> Policy {
    Policy::from_file(&repo_root().join(relative_path))
        .unwrap_or_else(|err| panic!("failed to load {relative_path}: {err}"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must be readable")
}

fn relative_to_repo(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

fn assert_network_mode(policy: &Policy, expected: ExpectedNetworkMode, target: &str) {
    match (expected, &policy.network.mode) {
        (ExpectedNetworkMode::Block, NetworkMode::Block)
        | (ExpectedNetworkMode::Proxy, NetworkMode::Proxy) => {}
        (ExpectedNetworkMode::Block, actual) => {
            panic!("{target} fixture must use block networking, got {actual:?}")
        }
        (ExpectedNetworkMode::Proxy, actual) => {
            panic!("{target} fixture must use proxy networking, got {actual:?}")
        }
    }
}

fn assert_agent_secret_stores_denied(policy: &Policy, target: &str) {
    for denied_path in ["~/.ssh", "~/.gnupg", "~/.aws"] {
        assert!(
            policy
                .filesystem
                .deny
                .iter()
                .any(|path| path == denied_path),
            "{target} fixture must deny {denied_path}"
        );
    }
}

fn assert_agent_policy_avoids_cgroup_only_limits(policy: &Policy, target: &str) {
    assert_eq!(
        policy.process.max_processes, 0,
        "{target} fixture must not require writable cgroups v2 for process-count limits"
    );
    assert_eq!(
        policy.process.cpu_rate_percent, 0,
        "{target} fixture must not require writable cgroups v2 for CPU quota"
    );
    assert!(
        policy.process.max_memory_mb > 0,
        "{target} fixture should keep a memory limit because memory has a no-admin rlimit fallback"
    );
}

fn endpoint_hosts(policy: &Policy) -> BTreeSet<&str> {
    policy
        .network
        .policies
        .iter()
        .flat_map(|endpoint_policy| endpoint_policy.endpoints.iter())
        .map(|endpoint| endpoint.host.as_str())
        .collect()
}
