# MXC Isolation Matrix

`mxc-isolation-matrix` emits a current-host JSON report for MXC backend and
network-mode combinations, plus an AXIS native filesystem-boundary comparison.

```bash
cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

The command does not install local artifacts. If `lxc-exec` is not on `PATH`,
set `AXIS_TEST_MXC_EXECUTOR` to a trusted executor path:

```bash
AXIS_TEST_MXC_EXECUTOR=/path/to/lxc-exec cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

Increase proxy request-loop iterations with:

```bash
AXIS_MXC_MATRIX_ITERS=1000 cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

Run a subset of MXC backends with `AXIS_MXC_MATRIX_BACKENDS`. Values are
comma-separated and accept `bubblewrap`, `lxc`, `microvm`, `hyperlight`, or
`all`:

```bash
AXIS_MXC_MATRIX_BACKENDS=bubblewrap cargo run --locked -p axis-bench --bin mxc-isolation-matrix
```

## Rows

On Linux, the MXC section attempts:

- `mxc-linux-bubblewrap`
- `mxc-linux-lxc`
- `mxc-linux-microvm`
- `mxc-linux-hyperlight`

The suite intentionally reports only the current platform's MXC backends.
It does not emit Windows or macOS rows on a Linux host.

Bubblewrap and LXC rows use the stable MXC `1.0.0` configuration contract.
MicroVM and Hyperlight rows use the `1.1.0-alpha` development contract, the
only MXC contract that includes those backends. Each MXC backend is tried with:

- `network.egress.default.allow`
- `network.egress.default.deny`
- `runtimeConfig.networkProxy`
- `network.enforcementMode.capabilities`
- `network.enforcementMode.firewall`
- `network.enforcementMode.both`
- `network.proxy.localhost`
- `network.proxy.builtinTestServer`

Bubblewrap and LXC rows keep `network.ingress.default` and
`network.ingress.hostLoopback` denied. MicroVM rows use the same action in
every direction, as MXC requires, and Hyperlight rows omit the network
section. `runtimeConfig.networkProxy` configures cooperative proxy routing for
proxy-aware clients with direct egress denied. Hyperlight accepts only
MXC's default-deny network posture, so its non-block rows are reported as
unsupported.

The `network.enforcementMode.*` host-filter rows (which used `allowedHosts`),
`network.proxy.localhost`, and `network.proxy.builtinTestServer` used shapes
from MXC contracts that MXC `1.0` retired. Their rows are kept so reports stay
comparable, and are always reported as unsupported without launching. MXC `1.0` replaced host lists with CIDR egress rules,
which this benchmark does not map yet.

The AXIS native row is not an MXC backend. It launches the native process
sandbox and verifies that a writable workspace remains writable while a
separate denied path cannot be read.

## Result Status

- `passed`: the row executed and emitted the expected marker.
- `failed`: the backend ran but the security expectation was not met.
- `unsupported`: MXC rejected the backend/mode combination, or the suite
  reported a retired or unrepresentable combination without launching it.
- `unavailable`: a host dependency, runtime image, executor feature, or
  privilege prerequisite was missing.

Only `passed` rows include performance metrics. Failed, unsupported, and
unavailable rows include diagnostics but no timing numbers.

## Dependencies

The no-executor case is valid: the MXC section reports the missing executor
gate, and the AXIS native comparison still runs where supported.

Real MXC rows require a safe `lxc-exec`. Individual rows may also require:

- `bwrap` for Bubblewrap;
- `slirp4netns`, `unshare`, `nsenter`, the `iptables`/`ip6tables` tools
  including their `-restore` variants, and `/dev/net/tun` for Bubblewrap rows
  with outbound access or a runtime proxy;
- LXC user namespace and image setup for LXC;
- KVM and runtime artifacts for MicroVM and Hyperlight.

These are runtime prerequisites for the machine running the suite. They are not
normal test requirements and must not be satisfied by root-installing a
checkout-built artifact as part of ordinary tests.
