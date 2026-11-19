// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: absolute-form `http://` requests through a real proxy.
//!
//! A client that honors `HTTP_PROXY` sends a plain-HTTP request to the proxy
//! whole instead of opening a CONNECT tunnel. These tests prove the proxy
//! authorizes the target as it authorizes a CONNECT target, forwards exactly
//! one origin-form request, refuses what it cannot frame exactly, and streams
//! the response back.

use axis_core::policy::Policy;
use axis_core::types::SandboxId;
use axis_proxy::proxy::{AxisProxy, ProxyConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const TIMEOUT: Duration = Duration::from_secs(5);

async fn start_proxy(
    policy_yaml: &str,
    enable_leak_detection: bool,
    inference_endpoint: Option<SocketAddr>,
) -> SocketAddr {
    let config = ProxyConfig {
        sandbox_id: SandboxId::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        policy: Policy::from_yaml(policy_yaml).unwrap(),
        enable_leak_detection,
        inference_endpoint,
        connect_attribution: None,
        enable_identity_diagnostics: false,
        timing_tx: None,
    };
    let mut proxy = AxisProxy::new(config).unwrap();
    let addr = proxy.bind().await.unwrap();
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });
    addr
}

fn policy_for(host: &str, port: u16) -> String {
    format!(
        r#"
version: 1
name: forward-test
network:
  mode: proxy
  policies:
    - name: local
      endpoints:
        - host: "{host}"
          port: {port}
"#
    )
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// Read one request head and its Content-Length body.
async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = find(&received, b"\r\n\r\n")
            && received.len() >= end + 4 + content_length(&received[..end])
        {
            return received;
        }
        let read = stream.read(&mut buf).await.unwrap();
        if read == 0 {
            return received;
        }
        received.extend_from_slice(&buf[..read]);
    }
}

async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received))
        .await
        .expect("connection was not closed")
        .unwrap();
    received
}

/// An upstream that reads one request, answers with `response` and closes its
/// side, then reports the request and every byte that arrived after it.
async fn recording_upstream(
    response: &'static [u8],
) -> (SocketAddr, oneshot::Receiver<(Vec<u8>, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = read_request(&mut stream).await;
        let end = find(&request, b"\r\n\r\n").map_or(request.len(), |end| {
            (end + 4 + content_length(&request[..end])).min(request.len())
        });
        let mut extra = request.split_off(end);
        stream.write_all(response).await.unwrap();
        stream.shutdown().await.unwrap();
        let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut extra)).await;
        let _ = tx.send((request, extra));
    });
    (addr, rx)
}

async fn assert_no_connection(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the proxy connected to the upstream"
    );
}

#[tokio::test]
async fn absolute_form_request_reaches_the_upstream_once_in_origin_form() {
    let (upstream, recorded) = recording_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\nok",
    )
    .await;
    let proxy = start_proxy(&policy_for("127.0.0.1", upstream.port()), false, None).await;
    let target = format!("127.0.0.1:{}", upstream.port());

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{target}/mcp HTTP/1.1\r\n\
                 Host: elsewhere.example\r\n\
                 Proxy-Connection: keep-alive\r\n\
                 Connection: keep-alive\r\n\
                 Content-Length: 4\r\n\
                 \r\n\
                 ping\
                 POST http://{target}/smuggled HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    assert_eq!(
        String::from_utf8(read_to_end(&mut client).await).unwrap(),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    );
    let (request, extra) = tokio::time::timeout(TIMEOUT, recorded)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(request).unwrap(),
        format!(
            "POST /mcp HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping"
        )
    );
    assert!(
        extra.is_empty(),
        "bytes past the declared body reached the upstream: {}",
        String::from_utf8_lossy(&extra)
    );
}

#[tokio::test]
async fn request_outside_the_policy_is_refused_without_contacting_the_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let proxy = start_proxy(&policy_for("127.0.0.1", 1), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://127.0.0.1:{port}/mcp HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(
        response.contains(&format!(
            "AXIS policy denied connection to 127.0.0.1:{port}"
        )),
        "{response}"
    );
    assert_no_connection(&upstream).await;
}

#[tokio::test]
async fn hostname_resolving_to_loopback_is_refused_like_connect() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let proxy = start_proxy(&policy_for("localhost", port), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://localhost:{port}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("prohibited address"), "{response}");
    assert_no_connection(&upstream).await;
}

#[tokio::test]
async fn requests_that_cannot_be_framed_exactly_are_refused_before_policy() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;
    let target = format!("127.0.0.1:{port}");

    let cases = [
        (
            format!(
                "POST http://{target}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n0\r\n\r\n"
            ),
            "HTTP/1.1 501 Not Implemented\r\n",
        ),
        (
            format!(
                "GET http://{target}/ HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ),
            "HTTP/1.1 501 Not Implemented\r\n",
        ),
        (
            format!("GET /mcp HTTP/1.1\r\nHost: {target}\r\n\r\n"),
            "HTTP/1.1 400 Bad Request\r\n",
        ),
        (
            format!("GET https://{target}/ HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 400 Bad Request\r\n",
        ),
        (
            format!(
                "POST http://{target}/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nping"
            ),
            "HTTP/1.1 400 Bad Request\r\n",
        ),
        (
            format!("GET http://{target}/ HTTP/1.0\r\n\r\n"),
            "HTTP/1.1 505 HTTP Version Not Supported\r\n",
        ),
    ];
    for (request, expected) in cases {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
        assert!(response.starts_with(expected), "{request:?}: {response}");
        assert!(
            response.contains("AXIS proxy rejected the request"),
            "{response}"
        );
    }
    assert_no_connection(&upstream).await;
}

#[tokio::test]
async fn response_is_streamed_while_the_upstream_holds_it_open() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: first\n\n")
            .await
            .unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"data: second\n\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://127.0.0.1:{port}/mcp HTTP/1.1\r\nAccept: text/event-stream\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let expected_first: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: first\n\n";
    let mut first = vec![0; expected_first.len()];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut first))
        .await
        .expect("the first event was held back until the stream ended")
        .unwrap();
    assert_eq!(first, expected_first);

    release_tx.send(()).unwrap();
    assert_eq!(read_to_end(&mut client).await, b"data: second\n\n");
}

#[tokio::test]
async fn expect_continue_reaches_the_client_before_it_sends_the_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (head_tx, head_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        let mut body = [0u8; 4];
        stream.read_exact(&mut body).await.unwrap();
        let _ = head_tx.send((head, body));
        stream
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "PUT http://127.0.0.1:{port}/upload HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut interim = [0u8; 25];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut interim))
        .await
        .expect("100 Continue was not relayed")
        .unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");

    client.write_all(b"ping").await.unwrap();
    assert_eq!(
        String::from_utf8(read_to_end(&mut client).await).unwrap(),
        "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (head, body) = head_rx.await.unwrap();
    assert!(
        String::from_utf8(head)
            .unwrap()
            .contains("\r\nExpect: 100-continue\r\n")
    );
    assert_eq!(&body, b"ping");
}

#[tokio::test]
async fn truncated_body_closes_the_upstream_without_a_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (received_tx, received_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let closed = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received))
            .await
            .is_ok();
        let _ = received_tx.send((received, closed));
    });
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\nContent-Length: 10\r\n\r\npart")
                .as_bytes(),
        )
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    assert!(read_to_end(&mut client).await.is_empty());
    let (received, closed) = received_rx.await.unwrap();
    assert!(
        closed,
        "the proxy kept the upstream open after the client left"
    );
    assert!(
        String::from_utf8(received)
            .unwrap()
            .ends_with("\r\n\r\npart")
    );
}

#[tokio::test]
async fn bearer_token_in_a_forwarded_request_is_blocked_by_leak_detection() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let proxy = start_proxy(&policy_for("127.0.0.1", port), true, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://127.0.0.1:{port}/mcp HTTP/1.1\r\n\
                 Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("credential leak detected"), "{response}");
    assert_no_connection(&upstream).await;
}

const LEAKING_BODY: &str = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";

#[tokio::test]
async fn credential_in_a_forwarded_body_is_refused_with_403() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut received = Vec::new();
        let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received)).await;
        let _ = seen_tx.send(received);
    });
    let proxy = start_proxy(&policy_for("127.0.0.1", port), true, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://127.0.0.1:{port}/mcp HTTP/1.1\r\nContent-Length: {}\r\n\r\n{LEAKING_BODY}",
                LEAKING_BODY.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(response.contains("credential leak detected"), "{response}");
    let seen = seen_rx.await.unwrap();
    assert!(
        !String::from_utf8_lossy(&seen).contains("abcdefghijklmnop"),
        "the credential reached the upstream"
    );
}

#[tokio::test]
async fn credential_in_a_body_after_100_continue_is_refused_with_403() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut rest)).await;
    });
    let proxy = start_proxy(&policy_for("127.0.0.1", port), true, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "PUT http://127.0.0.1:{port}/upload HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
                LEAKING_BODY.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut interim = [0u8; 25];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut interim))
        .await
        .expect("100 Continue was not relayed")
        .unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");

    client.write_all(LEAKING_BODY.as_bytes()).await.unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "an interim response must not stop the status: {response}"
    );
    assert!(response.contains("credential leak detected"), "{response}");
}

#[tokio::test]
async fn heads_with_bare_line_endings_get_400() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = upstream.local_addr().unwrap().port();
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;

    for request in [
        format!("GET http://127.0.0.1:{port}/ HTTP/1.1\nHost: 127.0.0.1\n\n"),
        format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1\n\r\n"),
        format!("GET http://127.0.0.1:{port}/ HTTP/1.1\rX: hidden\r\n\r\n"),
        format!("CONNECT 127.0.0.1:{port} HTTP/1.1\n\n"),
    ] {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{request:?}: {response}"
        );
        assert!(response.contains("bare"), "{response}");
    }
    assert_no_connection(&upstream).await;
}

#[tokio::test]
async fn upstream_response_with_ambiguous_framing_gets_502() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok!".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nok!",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    ] {
        let (upstream, _recorded) = recording_upstream(response).await;
        let proxy = start_proxy(&policy_for("127.0.0.1", upstream.port()), false, None).await;

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!("GET http://127.0.0.1:{}/ HTTP/1.1\r\n\r\n", upstream.port()).as_bytes(),
            )
            .await
            .unwrap();
        let reply = String::from_utf8(read_to_end(&mut client).await).unwrap();
        assert!(
            reply.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{reply}"
        );
        assert!(!reply.contains("ok"), "{reply}");
    }
}

#[tokio::test]
async fn unreachable_upstream_gets_502() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let proxy = start_proxy(&policy_for("127.0.0.1", port), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{response}"
    );
}

#[tokio::test]
async fn upstream_that_switches_protocols_unasked_gets_502() {
    let (upstream, _recorded) = recording_upstream(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\nraw-bytes",
    )
    .await;
    let proxy = start_proxy(&policy_for("127.0.0.1", upstream.port()), false, None).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("GET http://127.0.0.1:{}/ HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{response}"
    );
    assert!(!response.contains("raw-bytes"), "{response}");
}

#[tokio::test]
async fn provider_credentials_are_injected_into_forwarded_requests() {
    unsafe {
        std::env::set_var("AXIS_TEST_FORWARD_KEY", "forward-secret");
    }
    let (upstream, recorded) =
        recording_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await;
    let policy = r#"
version: 1
name: forward-credentials
network:
  mode: proxy
  policies:
    - name: inference
      endpoints:
        - host: "inference.local"
          port: 443
inference:
  routes:
    - name: local
      endpoint: "http://inference.local:443/v1"
      api_key_env: AXIS_TEST_FORWARD_KEY
"#;
    let proxy = start_proxy(policy, false, Some(upstream)).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"POST http://inference.local:443/v1/chat/completions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_to_end(&mut client).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let (request, _) = tokio::time::timeout(TIMEOUT, recorded)
        .await
        .unwrap()
        .unwrap();
    let request = String::from_utf8(request).unwrap();
    assert!(
        request.starts_with("POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local:443\r\n"),
        "{request}"
    );
    assert!(
        request.contains("Authorization: Bearer forward-secret\r\n"),
        "{request}"
    );
    assert!(request.ends_with("\r\n\r\n{}"), "{request}");
    unsafe {
        std::env::remove_var("AXIS_TEST_FORWARD_KEY");
    }
}
