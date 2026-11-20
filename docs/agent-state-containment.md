# Agent State Containment

## Problem

AI agents write persistent state to well-known directories in the user's home,
for example:

```text
~/.claude/          Claude Code sessions, settings, and history
~/.codex/           Codex CLI configuration and cache
~/.openclaw/        OpenClaw workspace, skills, and memory
~/.ironclaw/        Ironclaw configuration, secrets, and routines
```

Without containment, this state can persist after a sandbox exits, mix with
user-managed data, or be reused by a later agent invocation. Shared state also
increases the impact of persistent prompt injection and makes incident review
harder.

## Policy-Owned State Roots

AXIS stores redirected agent state under a directory derived from the policy
name:

```text
~/.axis/
└── agents/
    ├── agent-claude-code/
    │   ├── claude/               # target for ~/.claude
    │   ├── claude-share/         # target for ~/.local/share/claude
    │   └── xdg-config/           # XDG_CONFIG_HOME
    ├── agent-codex/
    │   ├── codex/                # target for ~/.codex
    │   └── xdg-config/
    ├── agent-openclaw/
    │   ├── openclaw/             # target for ~/.openclaw
    │   └── xdg-config/
    └── agent-hermes/
        ├── hermes/               # target for ~/.hermes
        └── xdg-config/
```

Bundled policies grant individual state directories rather than the entire
policy root. For example, Codex receives its own config directory:

```text
~/.axis/agents/agent-codex/xdg-config
```

AXIS sets `XDG_CONFIG_HOME` to this directory when the policy grants that exact
path. The directory starts empty and persists across runs. AXIS does not copy,
move, or replace the user's `~/.config`. A caller's inherited
`XDG_CONFIG_HOME` does not override the policy-owned config directory.

The real `~/.config` remains denied. Agent state aliases receive separate
grants to their contained targets; the shared `~/.axis` tree and whole policy
root are not granted.

For recognized home-directory state paths, AXIS creates aliases such as:

```text
~/.claude -> ~/.axis/agents/agent-claude-code/claude
~/.codex  -> ~/.axis/agents/agent-codex/codex
```

The exact setup differs for backends that use an AXIS-managed home, but the
contained targets remain under the policy-owned state root.

### Lifecycle

1. During sandbox preparation, AXIS creates the policy-owned state directories
   needed for recognized writable home paths and the separate config directory.
2. If a recognized path already exists as a real directory, AXIS copies its
   contents into the contained target, moves the original to an
   `.axis-backup`, and installs the alias.
3. The agent uses its expected home paths while the sandbox grants the
   corresponding contained targets.
4. During cleanup, AXIS removes aliases it created and restores an original
   directory from its backup when one exists.

AXIS does not redirect every arbitrary `~/...` grant. Only supported agent
state paths are mapped; shared `~/.config`, broad user directories, and unknown
paths are not silently moved.

### Benefits

| Benefit | Effect |
|---|---|
| Policy separation | Each policy receives a distinct state root. |
| Auditability | Operators can inspect contained state by policy name. |
| Disposability | Removing one policy root removes that policy's contained state. |
| Backup | The `~/.axis/agents/` tree can be backed up independently of unrelated home-directory data. |
| Forensics | A policy root provides a focused view of state redirected for that policy. |

### Policy Configuration

The policy grants its separate config directory and any supported aliases the
agent needs:

```yaml
version: 1
name: agent-claude-code

filesystem:
  read_write:
    - "{workspace}"
    - "{tmpdir}"
    - "~/.claude"
    - "~/.local/share/claude"
    - "~/.axis/agents/agent-claude-code/xdg-config"
  deny:
    - "~/.config"
```

The config grant must match `~/.axis/agents/<policy-name>/xdg-config` exactly.
Do not grant an ancestor of this directory: older AXIS versions could copy the
user's whole `~/.config` into `<policy-root>/config`. Those legacy copies are
not imported into `xdg-config` and must remain outside the sandbox's grants.
Review legacy copies separately before removing them; they can contain user
data and credentials.

On Linux, paths outside the allow list are inaccessible. On macOS, AXIS permits
reading file contents only for policy paths and required runtime files; path
metadata remains readable to support filesystem traversal. Denying a parent
and allowing a child is not a portable exception mechanism; keep denied real
config paths separate from allowed agent config paths.

## Scoped SSH Keys

### Problem

Some agent workflows use SSH for Git or remote access. Exposing the user's
entire `~/.ssh/` directory would reveal every private key, the user's SSH
configuration, and host history.

### Key Scoping

An `ssh` policy can select individual private keys for AXIS to copy into an
AXIS-managed SSH directory:

```yaml
ssh:
  allowed_keys:
    - name: github
      private_key: "~/.ssh/id_ed25519"
      allowed_hosts:
        - "github.com"
  generate_known_hosts: true
  generate_config: true
```

Only configured keys that exist are copied. The policy should deny the user's
real `~/.ssh`; setup can then expose an AXIS-managed `~/.ssh` path without
exposing the original directory or unselected keys. This is the enforced
key-exposure boundary.

`allowed_hosts`, `generate_config`, and `generate_known_hosts` configure the
sandbox's SSH client defaults:

- Generated SSH config associates copied keys with configured host patterns,
  uses `IdentitiesOnly yes`, and provides a fallback `Host *` entry.
- AXIS attempts to generate `known_hosts` entries for concrete configured hosts
  without copying the user's real `known_hosts`.

These generated files are convenience and defense-in-depth for clients that
use them. They are not a network authorization boundary: a process can invoke
SSH with different config options or use another network client.

### Network Authorization

SSH egress requires an explicit host and port in `network.policies`. AXIS does
not add `ssh.allowed_keys[].allowed_hosts` to the network policy automatically.
For GitHub SSH, the policy must include port 22 directly:

```yaml
network:
  mode: proxy
  policies:
    - name: github-ssh
      endpoints:
        - host: "github.com"
          port: 22
```

The SSH client configuration selects a default key for `github.com`; the
network endpoint rule is what authorizes traffic to `github.com:22`. Omitting
that endpoint means the SSH key policy alone does not authorize the connection.

### Complete Example

```yaml
version: 1
name: agent-claude-code-ssh

filesystem:
  read_write:
    - "{workspace}"
    - "{tmpdir}"
    - "~/.claude"
    - "~/.local/share/claude"
    - "~/.axis/agents/agent-claude-code-ssh/xdg-config"
  deny:
    - "~/.config"
    - "~/.ssh"
    - "~/.gnupg"
    - "~/.aws"

ssh:
  allowed_keys:
    - name: github
      private_key: "~/.ssh/id_ed25519"
      allowed_hosts:
        - "github.com"
  generate_known_hosts: true
  generate_config: true

network:
  mode: proxy
  policies:
    - name: anthropic
      endpoints:
        - host: "api.anthropic.com"
          port: 443
    - name: github-ssh
      endpoints:
        - host: "github.com"
          port: 22
    - name: github-https
      endpoints:
        - host: "github.com"
          port: 443
        - host: "api.github.com"
          port: 443
```

### Security Properties

| Property | Boundary |
|---|---|
| Key scoping | AXIS copies only configured private keys and does not expose the user's SSH directory. |
| SSH client defaults | Generated config selects identities for configured host patterns. |
| Host-key data separation | Generated `known_hosts` does not copy the user's host history. |
| Network authorization | Explicit `network.policies` host and port rules authorize SSH egress. |
| Audit coverage | Depends on the selected backend and network path; scoped SSH does not guarantee an event for every connection. |

Generated SSH config must not be described as an unbypassable host restriction,
and configured SSH hosts must not be described as automatically whitelisted.
AXIS can emit network policy decisions on supported paths, but it does not
provide universal per-SSH-connection auditing across every backend.

### Alternatives

| Approach | Drawback |
|---|---|
| SSH agent forwarding | May expose every key available through the forwarded agent socket. |
| Deploy keys only | Requires separate key management and does not cover every SSH workflow. |
| Full `~/.ssh/` exposure | Reveals unrelated keys, config, and host history. |
| No SSH | Prevents workflows that require SSH transport. |

Scoped key copying plus explicit network rules separates key availability from
network authorization. Both controls are required for the intended boundary.
