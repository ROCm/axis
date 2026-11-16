# HTTP Forwarding Through The AXIS Proxy

## Problem

In strict proxy mode the workload reaches the network only through the AXIS
proxy, and the proxy accepted only `CONNECT`. A client that honors `HTTP_PROXY`
does not use `CONNECT` for a plain-HTTP URL. It sends the whole request to the
proxy with an absolute-form target, such as
`POST http://127.0.0.1:8765/mcp HTTP/1.1`. OpenCode 1.19 (Bun's `fetch`),
curl and Python's `urllib` all do this. The proxy closed those connections, so
an `http://` endpoint named in `network.policies` was unreachable for them.

Loopback made it worse. Every backend set `NO_PROXY=localhost,127.0.0.1,::1`,
so clients connected to a loopback endpoint directly instead of through the
proxy:

- On Linux the sandbox has its own loopback, so the direct connection reached
  nothing. A host service on `127.0.0.1` was unreachable.
- On macOS Seatbelt shares the host loopback. The profile used to allow every
  `localhost` port, so the workload reached any local service, unchecked and
  unaudited. Opening only the proxy port closed that, and with it the endpoints
  the policy names.

The case that surfaced this is an MCP server on the host that an agent in the
sandbox reaches at `http://127.0.0.1:<port>/mcp`.

## Options

1. **Allow direct connections to loopback endpoints the policy names (macOS).**
   Seatbelt can allow `localhost:<port>`. The connection bypasses the proxy, so
   nothing checks or audits it, and the same policy entry would mean "direct"
   on macOS and "through the proxy" on Linux. Rejected.
2. **Redirect direct loopback connections to the proxy.** Linux could do this in
   its network namespace. Seatbelt can only allow or deny, so this would work on
   one platform and reintroduce the divergence. Rejected.
3. **Forward absolute-form `http://` requests in the proxy, and stop exempting
   loopback from the proxy environment.** Chosen.

## Decision

### Proxy

A connection carries either a `CONNECT` request or one absolute-form `http://`
request. A forwarded request is authorized exactly like a `CONNECT` target: the
same canonical host and port, OPA evaluation, audit record, binary identity,
DNS vetting with the literal-IP opt-in for non-public addresses, and
`inference.local` routing.

Framing is strict, so the upstream receives one well-formed request and nothing
else:

- HTTP/1.1 only. The target must be an absolute `http://` URI without user
  information or a fragment. `https://` and other schemes use `CONNECT`.
- The request is rewritten to origin-form, and `Host` is set to the authorized
  authority, whatever the client sent.
- Hop-by-hop headers are removed: `Connection` and the headers it names,
  `Keep-Alive`, `Proxy-Connection`, `Proxy-Authorization`, `TE` and `Trailer`.
  The proxy writes `Content-Length` from the parsed value, so a `Connection`
  option cannot remove it.
- Only `Content-Length` bodies are forwarded. `Transfer-Encoding` and `Upgrade`
  are refused with `501`, a duplicate or malformed `Content-Length` with `400`.
  Bytes past the declared length are never sent upstream.
- One request per connection. `Connection: close` goes upstream and back to the
  client.

The response is relayed as it arrives: interim `1xx` responses such as
`100 Continue` first, then the final head with `Connection: close` and without
hop-by-hop headers, then the body until the upstream closes. A server-sent
events stream passes through. An upstream that answers `101` unasked gets the
client a `502`.

Leak detection, credential injection and token budgets apply to a forwarded
request as they do to plain HTTP inside a tunnel. The proxy scans the request
head before anything goes upstream, so a blocked request gets `403` instead of
a reset.

The proxy answers `400`, `501` or `505` before policy evaluation when it cannot
forward a request exactly, `403` for a policy denial or a blocked request, and
`502` when the upstream cannot be reached or sends no valid response.

### Backends

No backend sets `NO_PROXY` in proxy mode any more: native macOS, native Linux
(direct and helper launch) and MXC Linux. Inherited proxy variables are still
dropped. A request to a loopback address therefore goes to the proxy, which
connects to the host's loopback endpoint only when the policy names it with a
literal IP. This does not loop: clients connect to the proxy itself directly,
and the proxy opens its own upstream connection.

The Windows backends set no `NO_PROXY` and are unchanged.

## Consequences

- A loopback endpoint in `network.policies` means the same on macOS and Linux:
  reachable through the proxy, checked and audited. Any other local port is
  refused.
- A client that ignores `HTTP_PROXY` and connects to a loopback address
  directly still fails on both platforms. Seatbelt denies it on macOS, and on
  Linux the sandbox's own loopback has no such service.
- On Linux, an HTTP client that honors `HTTP_PROXY` no longer reaches a server
  the workload starts on its own loopback. The request goes to the proxy, which
  refuses it or, when the policy names that port, connects to the host's port
  instead. A workload that needs its own server sets `NO_PROXY` for that
  client. macOS already denies loopback listeners in proxy mode.
- Plain HTTP through the proxy is visible to leak detection. A request whose
  head or body looks like a credential is refused, as it already was inside a
  `CONNECT` tunnel. That includes `Authorization: Bearer` with a token of 20 or
  more characters, so the MCP server in the motivating case sends its session
  token in a dedicated header.
- Chunked request bodies, protocol upgrades over a forwarded request, HTTP/1.0
  clients, keep-alive and pipelining are not supported. Upgrades and anything
  else that needs a raw stream use `CONNECT`.

## Evidence

Tests:

- `crates/axis-proxy/src/proxy/forward.rs` unit tests cover the rewriting and
  every refusal.
- `crates/axis-proxy/tests/proxy_http_forwarding.rs` runs a real proxy against
  real sockets: origin-form forwarding with bytes past the body withheld,
  policy and DNS denials without upstream contact, refused framing, streaming,
  `100 Continue`, a truncated body, the leak block, both `502` cases, and
  credential injection.
- The macOS, native Linux and MXC environment tests assert that `NO_PROXY` is
  absent and an inherited value is dropped. The Linux and MXC runtime probes
  check the same inside the sandbox.

End to end on macOS (Apple silicon, OpenCode 1.19.0, an MCP server on
`127.0.0.1:18765` named in the policy, a second local service on
`127.0.0.1:8765` that is not):

| Check from inside the sandbox | 0.4.0 | `CONNECT` only, proxy port only | This change |
| --- | --- | --- | --- |
| OpenCode lists the MCP server | connected, direct | failed | connected, through the proxy |
| Python `urllib` MCP session | works, direct | fails | works, through the proxy |
| Direct connection to the server | allowed | denied | denied |
| Request to the port outside the policy | reaches it | denied | `403` from the proxy |

Proxy timing inside `axis run` on the same Mac, release builds, 2000 sequential
requests per case on fresh connections, two alternating rounds. The server
answers the forwarded request itself, and a direct request to it from the host
takes 200 µs median.

| Case | Base commit, median (p95) | This change, median (p95) |
| --- | --- | --- |
| Denied `CONNECT` | 72 µs (83), 75 µs (86) | 75 µs (90), 75 µs (86) |
| Denied forwarded request | connection dropped | 75 µs (86), 75 µs (87) |
| Allowed forwarded request | connection dropped | 285 µs (318), 287 µs (323) |

The `runtime-metrics` profiles need Linux isolation, so their numbers come from
the Linux MXC proof workflow on the pull request.
