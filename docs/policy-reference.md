# AXIS Policy Reference

This page lists every field of an AXIS policy: its key path, type and values,
default, and a short meaning. It is a reference, not a guide. For the shipped
policies, see `policies/`.

This page says what each field is for. It does not say which backends enforce
it: the [AXIS Isolation Contract](axis-isolation-contract.md) states what
backends must do, and its notes on particular backends are not a complete record
of what each enforces, so unless a test shows enforcement, treat a field as not
enforced. `axis policy validate` checks the syntax and the values of a policy,
not whether a backend supports it.

A policy is a YAML document. Every mapping rejects keys that the model does not
define. At the top level, only `version` and `name` are required.

```yaml
version: 1
name: example
runtime:
  provider: auto
filesystem:
  read_only:
    - /usr
network:
  mode: block
```

## How to read this

The page has one section for each top-level key of the model. Each section has
one field table.

The field table lists each field by its full key path. A `[]` in a path stands
for one element of a list of mappings, so
`network.policies[].endpoints[].host` is the `host` key of each endpoint of each
entry in `network.policies`. The columns are:

| Column | Content |
|---|---|
| Field | The key path. |
| Type and values | The YAML type. For a field with fixed values, every value as you write it in YAML. |
| Default | The value of the field when you omit it, written as YAML. `none` means the field has no value. `required` means the field has no default and you must set it. |
| Meaning | What the field is for. |

A test checks this page against the policy model: field paths, defaults, and
enum values. It does not check type descriptions beyond enum values, or meaning
text.

## version

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `version` | integer | `required` | The policy schema version. Any value other than `1` is refused at parse time. |

## name

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `name` | string | `required` | The name of the policy. An empty name, `.`, `..`, or a name with a character other than ASCII letters, digits, `.`, `_`, and `-` is refused at parse time. |

## runtime

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `runtime.containment` | `process` | `"process"` | The containment model of the workload. |
| `runtime.provider` | `auto`, `mxc`, `axis_native`, `vxn` | `"auto"` | Selects the backend. `axis-native` is accepted as an alias of `axis_native`. |

## filesystem

See [Filesystem Semantics](axis-isolation-contract.md#filesystem-semantics).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `filesystem.read_only` | list of strings | `[]` | Paths to grant as read-only. |
| `filesystem.read_write` | list of strings | `[]` | Paths to grant as read-write. |
| `filesystem.deny` | list of strings | `[]` | Paths to deny access to. |
| `filesystem.workspace_read_only` | boolean | `false` | Grants the workspace as read-only instead of read-write. |
| `filesystem.windows_enumerate_ancestors` | boolean | `false` | Windows only. Setting it to `true` widens access: the sandbox can enumerate every ancestor of a grant, which exposes the names, sizes, and times of the files below it that NTFS does not separately deny. |
| `filesystem.compatibility` | `best_effort`, `hard_requirement` | `"best_effort"` | How strictly the filesystem rules must be applied. |

## process

See [Process And Identity Semantics](axis-isolation-contract.md#process-and-identity-semantics)
and [Resource Semantics](axis-isolation-contract.md#resource-semantics).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `process.max_processes` | integer | `32` | The maximum number of processes in the workload's process tree. `0` requests no limit. |
| `process.max_memory_mb` | integer | `8192` | The maximum memory of the workload, in MiB. `0` requests no limit. |
| `process.cpu_rate_percent` | integer | `80` | The CPU quota of the workload, as a percentage. `0` requests no quota. A value above `100` is refused at parse time. |
| `process.run_as_user` | string | `none` | The name of the user account to run the workload as. |
| `process.blocked_syscalls` | list of strings | `[]` | Names of system calls to block. |
| `process.identity` | `backend_default`, `isolated` | `"backend_default"` | Portable identity intent; it does not name a host account. `isolated` asks for an isolated identity that the backend owns. |
| `process.child_processes` | `allow`, `deny` | `"allow"` | Whether the workload may start descendant processes. `deny` means that it may have none. |
| `process.timeout_sec` | integer | `none` | The maximum wall-clock time of the sandbox, in seconds. `none` means no timeout. |
| `process.windows_win32k` | boolean | `false` | Windows only. Setting it to `true` widens access: it allows Win32k system calls. |
| `process.restrict_system_services` | boolean | `false` | Replaces the blanket Mach lookup and `sysctl` read access with an allowlist. See [macOS system services](axis-isolation-contract.md#macos-system-services). |
| `process.macos_mach_lookup` | list of strings | `[]` | Extra Mach service names for the allowlist. A policy that sets this list while `process.restrict_system_services` is `false` is refused at parse time. |
| `process.macos_sysctl_read` | list of strings | `[]` | Extra `sysctl` names for the allowlist. A policy that sets this list while `process.restrict_system_services` is `false` is refused at parse time. |

## network

See [Network Semantics](axis-isolation-contract.md#network-semantics).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `network.mode` | `proxy`, `block`, `allow` | `"proxy"` | How the workload reaches the network. |
| `network.policies` | list of mappings | `[]` | Named groups of endpoints, for `proxy` mode. A policy that sets this list while `network.mode` is not `proxy` is refused at parse time. |
| `network.policies[].name` | string | `required` | The name of the group. |
| `network.policies[].endpoints` | list of mappings | `required` | The endpoints of the group. |
| `network.policies[].endpoints[].host` | string | `required` | A DNS name or an IP address. An invalid host is refused at parse time. |
| `network.policies[].endpoints[].port` | integer | `required` | The TCP port of the endpoint. |
| `network.policies[].endpoints[].access` | `read-write`, `read-only` | `"read-write"` | The access level of the endpoint. `read-only` is refused at parse time. |
| `network.policies[].endpoints[].protocol` | string | `none` | The name of a protocol for the endpoint. A policy that sets it is refused at parse time. |
| `network.policies[].endpoints[].rules` | list of mappings | `[]` | HTTP method and path rules for the endpoint. A policy with a non-empty list is refused at parse time. |
| `network.policies[].endpoints[].rules[].allow` | mapping | `none` | One rule: a pair of HTTP method and path. |
| `network.policies[].endpoints[].rules[].allow.method` | string | `required` | The HTTP method of the rule. |
| `network.policies[].endpoints[].rules[].allow.path` | string | `required` | The path of the rule. |
| `network.policies[].binaries` | list of mappings | `[]` | Programs that may use the group's endpoints, as path globs; an empty list does not restrict by program. See [Strict Proxy Mode](axis-isolation-contract.md#strict-proxy-mode). |
| `network.policies[].binaries[].path` | string | `required` | A glob pattern for the path of a program. |
| `network.bypass_audit` | `best_effort`, `hard_requirement` | `"best_effort"` | Whether `proxy` mode requires a record of bypass attempts on a backend that blocks them but cannot record them. See [Audit And Evidence Semantics](axis-isolation-contract.md#audit-and-evidence-semantics). |

## inference

See [Inference Semantics](axis-isolation-contract.md#inference-semantics) and
[Credential Semantics](axis-isolation-contract.md#credential-semantics).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `inference.default_provider` | string | `none` | The name of the default inference route. |
| `inference.routes` | list of mappings | `[]` | The inference routes of the policy. |
| `inference.routes[].name` | string | `required` | The name of the route. |
| `inference.routes[].endpoint` | string | `none` | The URL of the route. |
| `inference.routes[].provider` | string | `none` | The name of the provider. |
| `inference.routes[].model` | string | `none` | The name of the model that the route serves. |
| `inference.routes[].api_key_env` | string | `none` | The name of the environment variable that holds the provider API key. |
| `inference.routes[].protocols` | list of strings | `[]` | The names of the protocols that the route serves. |
| `inference.scheduling` | mapping | `none` | Scheduling of inference requests. |
| `inference.scheduling.weight` | integer | `1` | The scheduling weight. |
| `inference.scheduling.priority` | `interactive`, `background`, `batch` | `"background"` | The scheduling priority class. |
| `inference.scheduling.max_concurrent_requests` | integer | `none` | A limit on the number of requests in flight at one time. |
| `inference.token_budget` | mapping | `none` | A limit on the tokens of inference requests. |
| `inference.token_budget.max_tokens_per_hour` | integer | `required` | The limit on the tokens in one hour. |
| `inference.token_budget.max_tokens_per_request` | integer | `32768` | The limit on the tokens of one request. |
| `inference.token_budget.action_on_exhaust` | `queue`, `reject`, `fallback_cloud` | `"reject"` | The action for a request after the hourly budget is used. The proxy refuses to start with any value other than `reject`. |
| `inference.token_budget.fallback_route` | string | `none` | The name of a fallback route. |

## gpu

See [Inference Semantics](axis-isolation-contract.md#inference-semantics).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `gpu.enabled` | boolean | `false` | Requests GPU access for the sandbox. |
| `gpu.device` | integer | `0` | The ordinal of the physical GPU. |
| `gpu.transport` | `uds`, `tcp` | `"tcp"` | The transport of HIP Remote. `uds` is refused at parse time while `gpu.enabled` is `true`. |
| `gpu.vram_limit_mb` | integer | `none` | A GPU memory limit, in MB. A policy that sets it while `gpu.enabled` is `true` is refused at parse time. |
| `gpu.compute_timeout_sec` | integer | `none` | A wall-clock time limit for one kernel launch, in seconds. A policy that sets it while `gpu.enabled` is `true` is refused at parse time. |
| `gpu.allowed_apis` | list of strings | `[]` | HIP API categories to allow. A policy that sets it while `gpu.enabled` is `true` is refused at parse time. |
| `gpu.denied_apis` | list of strings | `[]` | HIP API categories to deny. A policy that sets it while `gpu.enabled` is `true` is refused at parse time. |

## ssh

See [Scoped SSH Keys](agent-state-containment.md#scoped-ssh-keys).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `ssh.allowed_keys` | list of mappings | `[]` | Private keys for AXIS to copy into an AXIS-managed SSH directory. |
| `ssh.allowed_keys[].name` | string | `required` | A name for the key. |
| `ssh.allowed_keys[].private_key` | string | `required` | The path of the private key file: absolute, or starting with `~/`. |
| `ssh.allowed_keys[].allowed_hosts` | list of strings | `[]` | Host patterns written to the generated SSH client configuration. An empty list applies the key to every host. See [Scoped SSH Keys](agent-state-containment.md#scoped-ssh-keys). |
| `ssh.generate_known_hosts` | boolean | `false` | Asks for a generated `known_hosts` file for the hosts in `ssh.allowed_keys[].allowed_hosts`. |
| `ssh.generate_config` | boolean | `false` | Asks for a generated SSH client configuration for the keys in `ssh.allowed_keys`. |

## amd

See [Seccomp Syscall Filter](linux-setup.md#seccomp-syscall-filter).

| Field | Type and values | Default | Meaning |
|---|---|---|---|
| `amd` | mapping | `none` | The AMD hardware extensions. |
| `amd.gpu_passthrough` | boolean | `false` | Declares that the workload drives the host's AMD GPU directly through ROCm. It grants no device or sysfs paths; those come from `filesystem`. |
| `amd.npu_policy_offload` | boolean | `false` | Requests policy offload to an NPU. |
| `amd.apex_memory_policy` | mapping | `none` | The APEX memory policy: an overcommit setting and a VRAM limit. |
| `amd.apex_memory_policy.allow_overcommit` | boolean | `false` | Whether overcommit is allowed. |
| `amd.apex_memory_policy.max_vram_mb` | integer | `none` | A VRAM limit, in MB. |
