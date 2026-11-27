# Agent, Provider, And Inference Targets

This document records the AXIS agent, provider, and inference targets that must
remain compatible when any backend substrate is selected. Backend adapters are
responsible for proving exact isolation semantics before launch; this document
only describes workload coverage and the public status of each target.

## Agent Targets

Bundled agent policies are templates intended as convenient starting points.
They may need customization for production use. Review filesystem grants,
network endpoints, and resource limits against your workload and host
requirements before deployment.

| Target | Status | Policy template or contract |
| --- | --- | --- |
| Claude Code | Bundled policy template | `policies/agents/claude-code.yaml` |
| Claude Code with scoped SSH | Bundled policy template | `policies/agents/claude-code-ssh.yaml` |
| Codex | Bundled policy template | `policies/agents/codex.yaml` |
| OpenCode | Bundled policy template | `policies/agents/opencode.yaml` |
| GitHub Copilot CLI | BYO-command only until a dedicated fixture is added | Use an explicit user policy; no bundled first-party fixture currently exists |
| Gemini CLI | Bundled policy template | `policies/agents/gemini-cli.yaml` |
| OpenClaw | Bundled policy template | `policies/agents/openclaw.yaml` |
| Hermes-style agents | Bundled policy template | `policies/agents/hermes.yaml` |
| Ironclaw | Bundled policy template | `policies/agents/ironclaw.yaml` |
| Nanoclaw | Bundled policy template | `policies/agents/nanoclaw.yaml` |
| ZeroClaw | Bundled policy template | `policies/agents/zeroclaw.yaml` |
| BYO commands | Bundled deny-by-default baseline | `policies/agents/base-deny.yaml` and user-provided policies |

Bundled agent templates must keep real credential stores denied, including
`~/.ssh`, `~/.gnupg`, `~/.aws`, and the shared `~/.config`. Agent config uses
a separate `XDG_CONFIG_HOME` under the policy-owned state root; bundled
policies grant that directory without exposing legacy config copies. Scoped SSH
support is mediated by AXIS SSH policy and must not expose the user's real SSH
directory directly.

## Provider Targets

| Provider target | Status | Boundary behavior |
| --- | --- | --- |
| OpenAI | Network endpoint policy supported | HTTPS is relayed opaquely; host-boundary credential injection is not available without a per-sandbox CA trust path |
| Anthropic | Network endpoint policy supported | HTTPS is relayed opaquely; host-boundary credential injection is not available without a per-sandbox CA trust path |
| GitHub | Network endpoint policy supported | Agent fixtures allow GitHub API and repository endpoints where needed; raw tokens are not injected by the inference credential path |
| GitLab | Generic endpoint policy only | Use an explicit endpoint policy or generic provider route; no bundled first-party fixture currently exists |
| Copilot | Generic endpoint policy only | GitHub Copilot CLI is BYO-command only until a dedicated fixture and credential boundary are added |
| Google Vertex AI | Generic endpoint policy only | Gemini CLI fixtures cover Gemini API and auth endpoints; Vertex-specific inference profiles are not bundled yet |
| generic providers | Endpoint-scoped network policy supported | External HTTPS traffic is relayed opaquely and remains subject to host/port policy |
| local OpenAI-compatible endpoints | Supported through `inference.local` or explicit local routes | Explicit local `http://` routes may use host-boundary credential placeholders |

Provider credentials must remain outside sandbox environment variables, backend
configuration JSON, command-line arguments, logs, and child stdio. The proxy
resolves real secrets only for supported local plaintext routes. HTTPS
credential routes fail before launch until authenticated per-sandbox TLS
interception and trust distribution are implemented.

## Inference API Compatibility Targets

The following endpoints describe workloads that AXIS must relay correctly.
They are compatibility targets, not method or path authorization rules. The
current proxy authorizes a complete host and port and relays HTTPS opaquely;
policies that request L7 method or path filtering are rejected before launch.

| API target | Common path | Common method |
| --- | --- | --- |
| OpenAI-compatible chat completions | `/v1/chat/completions` | `POST` |
| OpenAI-compatible completions | `/v1/completions` | `POST` |
| OpenAI-compatible responses | `/v1/responses` | `POST` |
| OpenAI-compatible embeddings | `/v1/embeddings` | `POST` |
| OpenAI-compatible model discovery | `/v1/models` | `GET` |
| Anthropic messages | `/v1/messages` | `POST` |

Streaming uses the same request paths as the corresponding provider API. The
proxy must relay streaming response bodies without requiring real cloud
provider credentials in tests. `inference.local` is the explicit managed local
inference endpoint; external provider hosts remain governed by ordinary network
and provider policy rather than implicit local rewrites.

HIP Remote compatibility remains part of the broader inference story, but this
target matrix does not add new HIP Remote behavior.
