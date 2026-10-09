# vxn integration architecture

How the `vxn` sandbox backend plugs into AXIS, why it exists, and what it does
and does not enforce. This is the **design/architecture** companion to
[`vxn-backend.md`](vxn-backend.md) (which covers day-to-day usage: prerequisites,
running an agent, env knobs, network modes, config a/b, porting).

## Where vxn fits: the isolation spectrum

AXIS's built-in backends isolate an agent as a **host process** — bubblewrap +
Landlock + seccomp + namespaces + cgroups, all enforced by the **shared host
kernel**. Fast, no-admin, but the agent runs on the same kernel as everything
else.

`vxn` sits at the other end of the same design space: it runs the agent inside a
**Xen PV DomU** — a small VM with its **own kernel** — via the standalone OCI
runtime path from the `meta-virtualization` project.

```
 weaker / faster / no-admin ───────────────────────► stronger / heavier / needs a hypervisor
   seccomp    bwrap+Landlock       userspace-kernel  │  microVM        vxn
   filter     (AXIS native)        (gVisor)          │  (Kata/runx)    (Xen DomU)
                    ▲                                            ▲
              AXIS native                                       vxn
          (shared host kernel)                          (own kernel — real VM boundary)
```

The two are **complementary, not competing**: vxn adds the hardware-isolation /
defense-in-depth tier a process sandbox structurally cannot provide. A
guest-kernel exploit lands in a disposable VM, not on the host. It is the opt-in
high-assurance tier, never the default;  it requires a hypervisor (Xen, or Xen
nested under QEMU/KVM) and so is Linux-only.

## The provider model: how vxn plugs in

AXIS selects a backend through a fixed, cfg-gated match, not a plugin registry —
adding a backend is an in-tree code change:

- `axis-core` `RuntimeProvider` enum — the policy-facing name (`vxn`).
- `axis-sandbox` `PlatformBackendSelection` — the resolved Linux backend
  (`LinuxVxn`).
- `axis-sandbox` `SandboxImpl` — the `pub(crate)` lifecycle trait every backend
  implements.

`SandboxImpl` is deliberately **child-shaped** — `start() -> pid`,
`wait() -> exit`, `try_wait`, `take_stdout/stderr/stdin`, `take_pty_read`,
`destroy()`. It says nothing about *how* the process runs, which is exactly what
makes a VM backend fit behind it transparently: callers above the trait cannot
tell the process is in a VM. The vxn backend lives at
`crates/axis-sandbox/src/linux/vxn.rs` as `VxnSandbox: SandboxImpl`, wired in at
six sites (the `RuntimeProvider` variant, the `PlatformBackendSelection` arm, the
provider→selection mapping, the selection pass-through, the sandbox constructor,
and the `linux` module registration).

## Driving vxn: an OCI runtime, not a container engine

A container **engine** (daemon, images, registry, API — dockerd/podman/
containerd) is a different layer from an OCI **runtime** (a standalone binary
that turns a `config.json` bundle into a running thing: runc, crun,
`vxn-oci-runtime`). AXIS wants the **runtime** layer, not an engine: no daemon,
no registry, no image API in the trusted path.

`VxnSandbox` currently drives the **`vxn` CLI** in a foreground streaming mode
(`vxn run [-it] <image> <argv>`), which maps cleanly onto the child-shaped trait:
`start` spawns the child, stdio/pty are the child's handles, `wait` is the child
exit, `destroy` signals it. The lower-level `vxn-oci-runtime`
(`create/start/state/kill/delete` against a bundle — the runc analog) is the
alternative for a future detached/pooled model. Argument vectors are passed to
the guest opaquely (base64-per-arg) so arbitrary commands survive the transport
without shell re-lexing.

## What the VM boundary enforces (and what it does not)

This is the most important thing to understand about the tier.

**The VM boundary enforces the big-ticket policy directly, by construction:**
- filesystem isolation: the host filesystem is simply **not mounted** in the guest;
- network block: **no vif** exists, so there is no egress at all;
- memory / CPU cap: the DomU's assigned memory and vCPUs;
- a **separate guest kernel**: the agent's syscalls never touch the host kernel.

**The AXIS process primitives do NOT cross the boundary.** seccomp-BPF, Landlock,
netns, and cgroups are *kernel-local*: they configure whichever kernel the
process runs on. The agent runs on the **guest** kernel, so host-side filters do
not apply to it. Fine-grained syscall/path control inside the guest is a
**future layer** ("nested enforcement", below), provisioned by an in-guest
enforcer. The correct framing is *"enforcement relocates into the guest and is
provisioned there,"* never *"seccomp/Landlock still apply."*

## Model differences from the native backend

Worth knowing when writing a policy for the vxn provider:

- **Own rootfs, not the host fs.** The native backend confines a command against
  the host filesystem (Landlock allow/deny). vxn runs the command inside a DomU
  with its **own** rootfs (a base image, or an auto-provisioned one: see
  `vxn-backend.md`). Filesystem `read_only`/`read_write` paths therefore become
  **DomU mounts** rather than host Landlock rules (a workspace-share mechanism is
  on the roadmap; today the guest sees only its image).
- **Network modes** map to the DomU NIC: `block` → no vif; `allow` → bridged;
  `proxy` → **fails closed** today (see roadmap) rather than silently downgrading
  to `allow`, which would violate the isolation contract.
- **config a vs b** — a/nested-dom0 (host `vxn` CLI) vs b/AXIS-in-dom0 (in-dom0
  `vxn`). Same backend, an env flip. Details in `vxn-backend.md`.

## Provisioning vs execution (network-policy honesty)

`network.mode` governs the sandboxed **application**, not image provisioning.
Fetching a base image is environment setup — the vxn analog of "python3 is
already installed" for the native backend. It runs in **dom0, outside the sandbox
boundary** (the sandbox *is* the DomU), so a `block` policy is honored as long as
provisioning finishes before the DomU boots and the DomU genuinely has no vif.
Requiring `allow` just to make a pull work would be a silent policy downgrade and
is treated as a contract violation, not a shortcut. When an image is absent and
cannot be provisioned offline, the backend **fails closed** rather than granting
the network the policy denied.

## What works today

Verified end to end: `axis run --policy vxn -- claude` brings up interactive,
subscription-authenticated Claude Code inside a Xen DomU from a fresh SDK
install: no container engine, no host binary, no manual image build. One command:

```
axis run --policy vxn -- claude
  → VxnSandbox derives the image from the command, adds -it under a tty,
    inherits stdio
  → spawns `vxn run -it claude …`
  → dom0 auto-provisions the rootfs from a shipped recipe (skopeo + chroot),
    caches it, then launches the DomU with the agent's TUI on the real terminal
```

Implemented: the VM-boundary backend behind `RuntimeProvider::Vxn`; faithful
stdio / interactive PTY / exit-code handling through the trait; `-it`; explicit
host-env forwarding (`VXN_FORWARD_ENV`, opt-in, since AXIS strips secrets from the
collected sandbox env); `block`/`allow` network modes; command-name image
derivation; and dom0-side provisioning + image cache so the tier is zero-setup.

## Roadmap

The current backend delivers the VM boundary. The layers that build on it:

- **Nested enforcement** — re-apply AXIS's fine-grained policy (bwrap / Landlock
  / seccomp / cgroups) *inside* the DomU before exec'ing the agent, so the guest
  kernel enforces the same syscall/path rules. Gives parity with the native
  backend as a second layer *behind* the VM boundary (an escape from the in-guest
  filters still lands in a throwaway VM). Requires the guest kernel to carry
  Landlock + an in-guest enforcer in the rootfs.
- **Managed-inference proxy** (`network.mode: proxy`) — route the agent's
  inference through AXIS's egress proxy so the API key is injected host-side and
  **never enters the guest**. The design binds the proxy loopback (config a, via
  an ssh reverse tunnel to the dom0 gateway) or on the dom0 bridge (config b),
  and requires no netns because the DomU *is* the isolation boundary — which also
  makes AXIS's proxy root-free for this provider.
- **rw workspace share** — a read-write host/dom0 workspace into the DomU (9p) so
  coding agents can edit the real project. The gating item for full transparency.
- **Warm-pool / fast boot** — a pool of pre-booted DomUs (and dom0 kept warm) to
  bring per-run latency toward "feels local", via the detached
  `vxn-oci-runtime` lifecycle.
- **GPU via `axis-gpu` HIP Remote** — run the `hip-worker` in dom0 (real AMD GPU)
  and the HIP Remote client in the DomU over the vif: strong VM isolation **and**
  a shared GPU, without heavy/exclusive PCIe passthrough. The natural composition
  for a ROCm deployment.

## See also

- [`vxn-backend.md`](vxn-backend.md) — usage: SDK prerequisite, running agents,
  env knobs, network modes, config a/b, porting.
- [`backend-default-decisions.md`](backend-default-decisions.md) — backend
  selection and defaults.
- meta-virtualization `docs/vxn.md`, `docs/vxn-sdk.md` — the vxn substrate itself
  and building the SDK (<https://git.yoctoproject.org/meta-virtualization/>).
