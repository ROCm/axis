# OPA Proxy Benchmarks

For release-mode synthetic OPA throughput, use `success-metrics`. For
policy-specific proxy request timing, run:

```bash
cargo run --locked -p axis-bench --bin opa-scenarios
```

The command emits JSON and fails instead of reporting timing when a selected
scenario does not return the expected policy denial. It does not enumerate
unsupported backend combinations.

The `axis_proxy_reports` section always runs. It starts an AXIS proxy once per
policy scenario, sends repeated denied `CONNECT` requests through that already
running proxy with test connect-attribution records, and reports only
request-loop timing. Startup and teardown are outside `total_ns`.

The `mxc_bubblewrap` section is optional. On Linux, when a safe MXC executor is
provided through `AXIS_TEST_MXC_EXECUTOR` or `lxc-exec` is on `PATH`, the
benchmark launches MXC Bubblewrap with `runtimeConfig.networkProxy` pointing at
a benchmark-owned external deny proxy and direct egress denied
(`network.egress.default: deny`).

The section is reported as disabled unless `bwrap`, `/dev/net/tun`, and the
MXC private-network tools (`slirp4netns`, `unshare`, `nsenter`, and the
`iptables`/`ip6tables` tools with their `-restore` variants) are available,
because MXC reaches a runtime proxy through a private `slirp4netns` network
namespace. That mode measures MXC's cooperative proxy environment. The rows
prove proxy routing behavior, not AXIS OPA policy evaluation. MXC `1.0`
retired the `network.proxy.localhost` and `network.proxy.builtinTestServer`
shapes that earlier versions of this benchmark also measured.

Increase the request iteration count when collecting stable numbers:

```bash
AXIS_OPA_SCENARIO_BENCH_ITERS=50000 cargo run --locked -p axis-bench --bin opa-scenarios
```
