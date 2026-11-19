// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Forwarding of absolute-form `http://` requests.
//!
//! A client that honors `HTTP_PROXY` sends a plain-HTTP request to the proxy
//! whole, as `POST http://host:port/path HTTP/1.1`, instead of opening a
//! CONNECT tunnel. The caller authorizes the target and opens the upstream
//! connection exactly as it does for CONNECT. This module frames the one
//! request and its response:
//!
//! - the request is rewritten to origin-form and `Host` is set to the
//!   authorized authority, so the upstream sees the destination the policy
//!   checked, whatever `Host` the client sent;
//! - hop-by-hop headers are dropped. Only `Content-Length` bodies are
//!   forwarded: a transfer coding or a protocol upgrade is refused, and bytes
//!   past the declared length never reach the upstream;
//! - a connection carries one request. `Connection: close` goes both ways, and
//!   the response is relayed as it arrives, so a long-lived stream such as
//!   server-sent events passes through.
//!
//! Leak detection, credential injection and token budgets apply as they do to
//! plaintext HTTP inside a tunnel.

use super::{
    MAX_HTTP_HEADERS, ProxyError, ProxyState, canonicalize_connect_host, read_http_head_bounded,
    relay_client_to_upstream_with_policy, scan_sandbox_bytes, send_error_response,
};
use crate::http_framing::parse_content_length;
use axis_core::types::SandboxId;
use hyper::http::uri::Authority;
use hyper::http::{HeaderName, HeaderValue, Uri};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const DEFAULT_HTTP_PORT: u16 = 80;

/// How long a finished exchange waits for the client to close its side.
/// Closing a socket that still holds unread request bytes resets the
/// connection, which can discard a response the client has not read yet.
const CLIENT_CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Request headers about the client's connection to the proxy. `Host` and
/// `Content-Length` are dropped as well, because the proxy writes them itself.
const HOP_BY_HOP_REQUEST_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Response headers about the upstream's connection to the proxy.
const HOP_BY_HOP_RESPONSE_HEADERS: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "upgrade"];

/// One absolute-form request, rewritten for the upstream.
#[derive(Debug)]
pub(super) struct ForwardRequest {
    pub(super) method: String,
    pub(super) host: String,
    pub(super) port: u16,
    /// The origin-form request head sent upstream, ending with the empty line.
    pub(super) head: Vec<u8>,
    pub(super) body_length: u64,
}

/// A request refused before policy evaluation, and the status to answer with.
#[derive(Debug)]
pub(super) struct ForwardRejection {
    pub(super) status: &'static str,
    pub(super) reason: String,
}

impl ForwardRejection {
    fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            status: "400 Bad Request",
            reason: reason.into(),
        }
    }

    fn not_implemented(reason: impl Into<String>) -> Self {
        Self {
            status: "501 Not Implemented",
            reason: reason.into(),
        }
    }
}

/// Parse one absolute-form request head and rewrite it for the upstream.
pub(super) fn parse_forward_request_head(head: &[u8]) -> Result<ForwardRequest, ForwardRejection> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(consumed)) if consumed == head.len() => {}
        Ok(_) => return Err(ForwardRejection::bad_request("incomplete request head")),
        Err(error) => {
            return Err(ForwardRejection::bad_request(format!(
                "malformed request head: {error}"
            )));
        }
    }
    if request.version != Some(1) {
        return Err(ForwardRejection {
            status: "505 HTTP Version Not Supported",
            reason: "only HTTP/1.1 requests are forwarded".into(),
        });
    }
    let method = request
        .method
        .ok_or_else(|| ForwardRejection::bad_request("missing method"))?;
    let target = request
        .path
        .ok_or_else(|| ForwardRejection::bad_request("missing request target"))?;
    if target.contains('#') {
        return Err(ForwardRejection::bad_request(
            "request target contains a fragment",
        ));
    }
    let uri = target
        .parse::<Uri>()
        .map_err(|_| ForwardRejection::bad_request("invalid request target"))?;
    match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => {}
        Some(_) => {
            return Err(ForwardRejection::bad_request(
                "only http:// URLs are forwarded; use CONNECT for https",
            ));
        }
        None => {
            return Err(ForwardRejection::bad_request(
                "a proxied request needs an absolute http:// URL",
            ));
        }
    }
    let authority = uri
        .authority()
        .ok_or_else(|| ForwardRejection::bad_request("request target has no authority"))?;
    let (host, port) = parse_forward_authority(authority)?;
    let path = match uri.path() {
        "" => "/",
        path => path,
    };
    let origin_form = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };

    let mut content_length = None;
    let mut connection_options = Vec::new();
    for header in request.headers.iter() {
        if HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || HeaderValue::from_bytes(header.value).is_err()
        {
            return Err(ForwardRejection::bad_request("malformed header"));
        }
        let name = header.name;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ForwardRejection::not_implemented(
                "transfer-encoded request bodies are not forwarded; send Content-Length",
            ));
        }
        if name.eq_ignore_ascii_case("upgrade") {
            return Err(ForwardRejection::not_implemented(
                "protocol upgrades are not forwarded; use CONNECT",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ForwardRejection::bad_request("duplicate Content-Length"));
            }
            let length = parse_content_length(header.value)
                .ok_or_else(|| ForwardRejection::bad_request("invalid Content-Length"))?;
            content_length = Some(length);
        }
        if name.eq_ignore_ascii_case("connection") {
            connection_options.extend(header_list(header.value));
        }
    }

    let mut rewritten = format!(
        "{method} {origin_form} HTTP/1.1\r\nHost: {}\r\n",
        host_header(&host, port)
    )
    .into_bytes();
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        if name == "host"
            || name == "content-length"
            || HOP_BY_HOP_REQUEST_HEADERS.contains(&name.as_str())
            || connection_options.contains(&name)
        {
            continue;
        }
        push_header(&mut rewritten, header.name, header.value);
    }
    if let Some(length) = content_length {
        rewritten.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    Ok(ForwardRequest {
        method: method.to_string(),
        host,
        port,
        head: rewritten,
        body_length: content_length.unwrap_or(0),
    })
}

fn parse_forward_authority(authority: &Authority) -> Result<(String, u16), ForwardRejection> {
    let text = authority.as_str();
    if text.contains('@') {
        return Err(ForwardRejection::bad_request(
            "request target contains user information",
        ));
    }
    let host = match authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        Some(literal) => literal
            .parse::<Ipv6Addr>()
            .map_err(|_| ForwardRejection::bad_request("invalid IPv6 address in request target"))?
            .to_string(),
        None => canonicalize_connect_host(authority.host())
            .map_err(|_| ForwardRejection::bad_request("invalid host in request target"))?,
    };
    let has_port = match text.rfind(']') {
        Some(end) => text[end + 1..].starts_with(':'),
        None => text.contains(':'),
    };
    let port = match authority.port_u16() {
        Some(port) => port,
        None if has_port => {
            return Err(ForwardRejection::bad_request(
                "invalid port in request target",
            ));
        }
        None => DEFAULT_HTTP_PORT,
    };
    Ok((host, port))
}

/// The `Host` value for an authorized target, written as a client writes it.
fn host_header(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == DEFAULT_HTTP_PORT {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// The lowercase names in a comma-separated header such as `Connection`.
fn header_list(value: &[u8]) -> Vec<String> {
    value
        .split(|byte| *byte == b',')
        .map(|item| String::from_utf8_lossy(item.trim_ascii()).to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn push_header(head: &mut Vec<u8>, name: &str, value: &[u8]) {
    head.extend_from_slice(name.as_bytes());
    head.extend_from_slice(b": ");
    head.extend_from_slice(value);
    head.extend_from_slice(b"\r\n");
}

/// Rewrite one upstream response head for the client. Returns the status code
/// and the head; a final response tells the client the connection closes.
/// A head whose framing is ambiguous is an error, and the client gets a `502`.
pub(super) fn rewrite_forward_response_head(head: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(consumed)) if consumed == head.len() => {}
        Ok(_) => return Err("incomplete upstream response head".into()),
        Err(error) => return Err(format!("malformed upstream response head: {error}")),
    }
    let code = response
        .code
        .ok_or("upstream response has no status code")?;
    if code == 101 {
        return Err("upstream switched protocols without an upgrade request".into());
    }
    let mut connection_options = Vec::new();
    let mut content_length = None;
    let mut transfer_encoded = false;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("connection") {
            connection_options.extend(header_list(header.value));
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoded = true;
        } else if header.name.eq_ignore_ascii_case("content-length") {
            let length = parse_content_length(header.value)
                .ok_or("upstream response has an invalid Content-Length")?;
            if content_length.is_some_and(|previous| previous != length) {
                return Err("upstream response has conflicting Content-Length values".into());
            }
            content_length = Some(length);
        }
    }
    // The relay passes the body through untouched, so the client would frame
    // it by whichever of the two it trusts. RFC 9112 section 6.3.
    if transfer_encoded && content_length.is_some() {
        return Err("upstream response has both Transfer-Encoding and Content-Length".into());
    }
    let mut rewritten =
        format!("HTTP/1.1 {code} {}\r\n", response.reason.unwrap_or("")).into_bytes();
    let mut wrote_content_length = false;
    for header in response.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let framing = name == "content-length" || name == "transfer-encoding";
        if HOP_BY_HOP_RESPONSE_HEADERS.contains(&name.as_str())
            || (!framing && connection_options.contains(&name))
        {
            continue;
        }
        if name == "content-length" {
            // Repeated equal values mean one length; send it once.
            if std::mem::replace(&mut wrote_content_length, true) {
                continue;
            }
        }
        push_header(&mut rewritten, header.name, header.value);
    }
    if code >= 200 {
        rewritten.extend_from_slice(b"Connection: close\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    Ok((code, rewritten))
}

#[derive(Debug, PartialEq, Eq)]
enum Sent {
    /// The whole request reached the upstream.
    Complete,
    /// The upstream stopped reading first. Its response still goes to the client.
    UpstreamClosed,
}

/// Send one authorized request on `upstream` and relay its response.
pub(super) async fn forward_http_request(
    sandbox_id: SandboxId,
    host: &str,
    port: u16,
    request: ForwardRequest,
    client: BufReader<TcpStream>,
    upstream: TcpStream,
    state: Arc<Mutex<ProxyState>>,
) -> Result<(), ProxyError> {
    let request_policy = {
        let st = state.lock().unwrap();
        st.credential_injector
            .connection_requires_injection(host, port, false)
            || st
                .inference_budget
                .as_ref()
                .is_some_and(|budget| budget.applies_to(host))
    };

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let final_response_started = AtomicBool::new(false);
    let finished = {
        let send = async {
            let sent = if request_policy {
                send_inspected_request(
                    sandbox_id,
                    host,
                    port,
                    request,
                    &mut client_read,
                    &mut upstream_write,
                    Arc::clone(&state),
                )
                .await?
            } else {
                send_request(
                    sandbox_id,
                    request,
                    &mut client_read,
                    &mut upstream_write,
                    &state,
                )
                .await?
            };
            if sent == Sent::Complete {
                // One request per connection: anything else the client sends is
                // read and dropped, never forwarded.
                tokio::io::copy(&mut client_read, &mut tokio::io::sink()).await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let receive = relay_response(upstream_read, &mut client_write, &final_response_started);
        tokio::pin!(send, receive);

        tokio::select! {
            received = &mut receive => {
                let _ = tokio::time::timeout(CLIENT_CLOSE_GRACE, &mut send).await;
                Finished::Done(received)
            }
            sent = &mut send => match sent {
                Ok(()) => Finished::Done(receive.await),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    Finished::Blocked(error)
                }
                Err(error) => Finished::Done(Err(error.into())),
            }
        }
    };

    match finished {
        Finished::Done(result) => result,
        Finished::Blocked(error) => {
            // Leak detection, credential injection or a token budget refused
            // the request after it was authorized. The client is waiting for a
            // status unless the upstream has already started its answer.
            if !final_response_started.load(Ordering::Acquire) {
                let body = format!(
                    "AXIS policy blocked the request to {host}:{port}\r\nReason: {error}\r\n"
                );
                let _ = send_error_response(&mut client_write, "403 Forbidden", &body).await;
                let _ = client_write.shutdown().await;
                // Closing with unread request bytes resets the connection and
                // can discard the status, so let the client finish sending.
                let _ = tokio::time::timeout(
                    CLIENT_CLOSE_GRACE,
                    tokio::io::copy(&mut client_read, &mut tokio::io::sink()),
                )
                .await;
            }
            Err(ProxyError::Io(error))
        }
    }
}

enum Finished {
    Done(Result<(), ProxyError>),
    /// The request was refused by policy while it was being sent.
    Blocked(std::io::Error),
}

/// Send the head and exactly `body_length` body bytes, scanning the body for
/// leaks. The caller has already scanned the head.
async fn send_request<R, W>(
    sandbox_id: SandboxId,
    request: ForwardRequest,
    client: &mut R,
    upstream: &mut W,
    state: &Arc<Mutex<ProxyState>>,
) -> std::io::Result<Sent>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if upstream.write_all(&request.head).await.is_err() {
        return Ok(Sent::UpstreamClosed);
    }
    let mut remaining = request.body_length;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let limit = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = client.read(&mut buf[..limit]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed the connection before the request body ended",
            ));
        }
        scan_sandbox_bytes(sandbox_id, &buf[..read], state)?;
        if upstream.write_all(&buf[..read]).await.is_err() {
            return Ok(Sent::UpstreamClosed);
        }
        remaining -= read as u64;
    }
    if upstream.flush().await.is_err() {
        return Ok(Sent::UpstreamClosed);
    }
    Ok(Sent::Complete)
}

/// Send a request through the plaintext request policy, credential injection
/// and token budgets, with the code that inspects HTTP inside a tunnel.
async fn send_inspected_request<R, W>(
    sandbox_id: SandboxId,
    host: &str,
    port: u16,
    request: ForwardRequest,
    client: &mut R,
    upstream: &mut W,
    state: Arc<Mutex<ProxyState>>,
) -> std::io::Result<Sent>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut body = client.take(request.body_length);
    {
        let mut whole = std::io::Cursor::new(request.head).chain(&mut body);
        relay_client_to_upstream_with_policy(
            sandbox_id, host, port, false, &mut whole, upstream, state,
        )
        .await?;
    }
    if body.limit() != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed the connection before the request body ended",
        ));
    }
    upstream.flush().await?;
    Ok(Sent::Complete)
}

/// Relay interim (1xx) heads, then the final head with `Connection: close`,
/// then the body as it arrives until the upstream closes. `final_response_started`
/// is set before the final head is written.
async fn relay_response<R, W>(
    upstream: R,
    client: &mut W,
    final_response_started: &AtomicBool,
) -> Result<(), ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut upstream = BufReader::new(upstream);
    loop {
        let rewritten = match read_http_head_bounded(&mut upstream).await {
            Ok(head) => rewrite_forward_response_head(&head).map_err(ProxyError::ConnectionError),
            Err(error) => Err(error),
        };
        let (code, head) = match rewritten {
            Ok(rewritten) => rewritten,
            Err(error) => {
                let body = "AXIS proxy received no valid response from the upstream\r\n";
                let _ = send_error_response(&mut *client, "502 Bad Gateway", body).await;
                return Err(error);
            }
        };
        if code >= 200 {
            // From here the client has an answer, so it can no longer be
            // given a different status.
            final_response_started.store(true, Ordering::Release);
        }
        client.write_all(&head).await?;
        if code >= 200 {
            break;
        }
    }
    client.flush().await?;
    tokio::io::copy_buf(&mut upstream, client).await?;
    client.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(head: &str) -> Result<ForwardRequest, ForwardRejection> {
        parse_forward_request_head(head.as_bytes())
    }

    fn rewritten(head: &str) -> String {
        String::from_utf8(parse(head).unwrap().head).unwrap()
    }

    #[test]
    fn absolute_form_request_is_rewritten_for_the_upstream() {
        let request = parse(
            "POST http://127.0.0.1:8765/mcp?session=1 HTTP/1.1\r\n\
             Host: attacker.example\r\n\
             Proxy-Connection: keep-alive\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
             Connection: keep-alive, X-Hop\r\n\
             Keep-Alive: timeout=5\r\n\
             X-Hop: dropped\r\n\
             Accept: application/json, text/event-stream\r\n\
             Content-Length: 4\r\n\
             TE: trailers\r\n\
             Mcp-Session-Id: abc\r\n\
             \r\n",
        )
        .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.host, "127.0.0.1");
        assert_eq!(request.port, 8765);
        assert_eq!(request.body_length, 4);
        assert_eq!(
            String::from_utf8(request.head).unwrap(),
            "POST /mcp?session=1 HTTP/1.1\r\n\
             Host: 127.0.0.1:8765\r\n\
             Accept: application/json, text/event-stream\r\n\
             Mcp-Session-Id: abc\r\n\
             Content-Length: 4\r\n\
             Connection: close\r\n\
             \r\n"
        );
    }

    #[test]
    fn host_and_path_are_canonical_and_the_default_port_is_implicit() {
        let request = parse("GET HTTP://Example.COM. HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((request.host.as_str(), request.port), ("example.com", 80));
        assert_eq!(request.body_length, 0);
        assert_eq!(
            String::from_utf8(request.head).unwrap(),
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn ipv6_literal_target_keeps_brackets_only_in_host() {
        let request = parse("DELETE http://[::1]:8765/mcp HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((request.host.as_str(), request.port), ("::1", 8765));
        assert!(
            String::from_utf8(request.head)
                .unwrap()
                .starts_with("DELETE /mcp HTTP/1.1\r\nHost: [::1]:8765\r\n")
        );
    }

    #[test]
    fn connection_options_cannot_remove_framing_or_host() {
        let head = rewritten(
            "POST http://127.0.0.1:9/ HTTP/1.1\r\n\
             Connection: content-length, host\r\n\
             Content-Length: 2\r\n\
             \r\n",
        );
        assert!(head.contains("Host: 127.0.0.1:9\r\n"), "{head}");
        assert!(head.contains("Content-Length: 2\r\n"), "{head}");
        assert!(head.ends_with("Connection: close\r\n\r\n"), "{head}");
    }

    #[test]
    fn content_length_is_rewritten_from_the_parsed_value() {
        let head = rewritten("PUT http://127.0.0.1:9/ HTTP/1.1\r\nContent-Length: 0004\r\n\r\n");
        assert!(head.contains("\r\nContent-Length: 4\r\n"), "{head}");
    }

    #[test]
    fn requests_that_cannot_be_forwarded_exactly_are_refused() {
        let cases = [
            (
                "origin-form",
                "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\n\r\n",
                "400",
            ),
            ("https", "GET https://example.com/ HTTP/1.1\r\n\r\n", "400"),
            (
                "other scheme",
                "GET ftp://example.com/ HTTP/1.1\r\n\r\n",
                "400",
            ),
            ("asterisk", "OPTIONS * HTTP/1.1\r\n\r\n", "400"),
            (
                "userinfo",
                "GET http://user@127.0.0.1:8765/ HTTP/1.1\r\n\r\n",
                "400",
            ),
            (
                "fragment",
                "GET http://127.0.0.1:8765/#top HTTP/1.1\r\n\r\n",
                "400",
            ),
            (
                "port too large",
                "GET http://127.0.0.1:99999/ HTTP/1.1\r\n\r\n",
                "400",
            ),
            (
                "empty port",
                "GET http://127.0.0.1:/ HTTP/1.1\r\n\r\n",
                "400",
            ),
            (
                "backslash host",
                "GET http://evil\\@127.0.0.1/ HTTP/1.1\r\n\r\n",
                "400",
            ),
            ("bad ipv6", "GET http://[::g]/ HTTP/1.1\r\n\r\n", "400"),
            ("http/1.0", "GET http://127.0.0.1/ HTTP/1.0\r\n\r\n", "505"),
            (
                "chunked",
                "POST http://127.0.0.1/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                "501",
            ),
            (
                "transfer coding with length",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: gzip\r\n\r\n",
                "501",
            ),
            (
                "upgrade",
                "GET http://127.0.0.1/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                "501",
            ),
            (
                "duplicate length",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n",
                "400",
            ),
            (
                "length list",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: 4, 4\r\n\r\n",
                "400",
            ),
            (
                "signed length",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: +4\r\n\r\n",
                "400",
            ),
            (
                "negative length",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                "400",
            ),
            (
                "empty length",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: \r\n\r\n",
                "400",
            ),
            (
                "length overflow",
                "POST http://127.0.0.1/ HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n",
                "400",
            ),
            (
                "folded header",
                "GET http://127.0.0.1/ HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n",
                "400",
            ),
            (
                "space before colon",
                "GET http://127.0.0.1/ HTTP/1.1\r\nContent-Length : 4\r\n\r\n",
                "400",
            ),
            (
                "control in value",
                "GET http://127.0.0.1/ HTTP/1.1\r\nX-A: a\x01b\r\n\r\n",
                "400",
            ),
            (
                "trailing bytes",
                "GET http://127.0.0.1/ HTTP/1.1\r\n\r\nGET",
                "400",
            ),
        ];
        for (name, head, status) in cases {
            let rejection = parse(head).expect_err(name);
            assert!(
                rejection.status.starts_with(status),
                "{name}: expected {status}, got {} ({})",
                rejection.status,
                rejection.reason
            );
        }
    }

    #[test]
    fn final_response_closes_and_loses_only_hop_by_hop_headers() {
        let (code, head) = rewrite_forward_response_head(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: text/event-stream\r\n\
              Connection: keep-alive, X-Upstream-Hop\r\n\
              Keep-Alive: timeout=5\r\n\
              X-Upstream-Hop: dropped\r\n\
              Transfer-Encoding: chunked\r\n\
              Mcp-Session-Id: abc\r\n\
              \r\n",
        )
        .unwrap();
        assert_eq!(code, 200);
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Transfer-Encoding: chunked\r\n\
             Mcp-Session-Id: abc\r\n\
             Connection: close\r\n\
             \r\n"
        );
    }

    #[test]
    fn response_connection_options_cannot_remove_framing() {
        let (_, head) = rewrite_forward_response_head(
            b"HTTP/1.1 200 OK\r\nConnection: content-length, transfer-encoding\r\nContent-Length: 2\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn interim_responses_pass_without_closing_and_101_is_refused() {
        let (code, head) = rewrite_forward_response_head(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_eq!(code, 100);
        assert_eq!(head, b"HTTP/1.1 100 Continue\r\n\r\n");

        let error = rewrite_forward_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap_err();
        assert!(error.contains("switched protocols"), "{error}");
    }

    #[test]
    fn http10_response_is_relayed_as_http11_and_closes() {
        let (code, head) = rewrite_forward_response_head(b"HTTP/1.0 204 \r\n\r\n").unwrap();
        assert_eq!(code, 204);
        assert_eq!(head, b"HTTP/1.1 204 \r\nConnection: close\r\n\r\n");
    }

    #[test]
    fn malformed_response_heads_are_refused() {
        for head in [
            b"HTTP/1.1 abc OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nBad Header\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\ntrailing".as_slice(),
            b"ICY 200 OK\r\n\r\n".as_slice(),
        ] {
            assert!(
                rewrite_forward_response_head(head).is_err(),
                "{}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn response_with_ambiguous_framing_is_refused() {
        let cases = [
            (
                "conflicting lengths",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
                "conflicting Content-Length",
            ),
            (
                "length list",
                "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\n",
                "invalid Content-Length",
            ),
            (
                "signed length",
                "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n",
                "invalid Content-Length",
            ),
            (
                "empty length",
                "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
                "invalid Content-Length",
            ),
            (
                "length overflow",
                "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
                "invalid Content-Length",
            ),
            (
                "transfer coding with length",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n",
                "both Transfer-Encoding and Content-Length",
            ),
            (
                "length then transfer coding",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                "both Transfer-Encoding and Content-Length",
            ),
            (
                "interim response with both",
                "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n",
                "both Transfer-Encoding and Content-Length",
            ),
        ];
        for (name, head, expected) in cases {
            let error = rewrite_forward_response_head(head.as_bytes()).expect_err(name);
            assert!(error.contains(expected), "{name}: {error}");
        }
    }

    #[test]
    fn equal_repeated_response_lengths_are_sent_once() {
        let (_, head) = rewrite_forward_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: 1\r\nContent-Length: 2\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: 1\r\nConnection: close\r\n\r\n"
        );
    }
}
