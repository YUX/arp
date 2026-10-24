//! Comprehensive smoke test for a running arps relay server.
//! Connects via WebSocket, performs admission handshake, routes messages, etc.
//!
//! Usage: cargo run --example smoke_test -- ws://127.0.0.1:8181

use arp_common::Pubkey;
use arp_common::crypto;
use arp_common::frame::Frame;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rng;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

struct SmokeClient {
    ws_tx: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    ws_rx: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    pubkey: Pubkey,
}

impl SmokeClient {
    async fn connect(url: &str, keypair: &SigningKey) -> Self {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
        );
        let (ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .expect("WS connect failed");
        let (mut ws_tx, mut ws_rx) = ws.split();

        let challenge_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(challenge_data) = challenge_msg else {
            panic!("expected binary challenge frame");
        };
        let frame = Frame::parse(&challenge_data).unwrap();
        let Frame::Challenge { challenge, .. } = frame else {
            panic!("expected challenge frame, got {frame:?}");
        };

        let timestamp = crypto::unix_now().expect("clock error");
        let signature = crypto::sign_admission(keypair, &challenge, timestamp);
        let pubkey: Pubkey = keypair.verifying_key().to_bytes();
        let response = Frame::response(&pubkey, timestamp, &signature);
        ws_tx
            .send(Message::Binary(response.serialize().into()))
            .await
            .unwrap();

        let admit_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(admit_data) = admit_msg else {
            panic!("expected binary admission frame");
        };
        let admit = Frame::parse(&admit_data).unwrap();
        assert!(
            matches!(admit, Frame::Admitted),
            "expected Admitted, got {admit:?}"
        );

        Self {
            ws_tx,
            ws_rx,
            pubkey,
        }
    }

    async fn send_route(&mut self, dest: &Pubkey, payload: &[u8]) {
        let route = Frame::route(dest, payload);
        self.ws_tx
            .send(Message::Binary(route.serialize().into()))
            .await
            .unwrap();
    }

    async fn send_ping(&mut self, payload: &[u8]) {
        let ping = Frame::ping(payload);
        self.ws_tx
            .send(Message::Binary(ping.serialize().into()))
            .await
            .unwrap();
    }

    async fn recv_frame(&mut self) -> Frame {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), self.ws_rx.next())
                .await
                .expect("timeout waiting for frame")
                .unwrap()
                .unwrap();
            match msg {
                Message::Binary(data) => return Frame::parse(&data).unwrap(),
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("expected binary frame, got {other:?}"),
            }
        }
    }

    /// Receive the next Deliver frame, skipping any Status frames (delivery acknowledgments).
    async fn recv_deliver(&mut self) -> Frame {
        loop {
            let frame = self.recv_frame().await;
            if matches!(frame, Frame::Status { .. }) {
                continue;
            }
            return frame;
        }
    }

    #[allow(dead_code)]
    async fn recv_frame_timeout(&mut self, timeout: Duration) -> Option<Frame> {
        tokio::time::timeout(timeout, self.recv_frame()).await.ok()
    }

    async fn close(mut self) {
        let _ = self.ws_tx.send(Message::Close(None)).await;
    }
}

fn pass(name: &str) {
    eprintln!("  \x1b[32m✓\x1b[0m {name}");
}

fn fail(name: &str, msg: &str) -> ! {
    eprintln!("  \x1b[31m✗\x1b[0m {name}: {msg}");
    std::process::exit(1);
}

async fn fetch_metrics(addr: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect to metrics endpoint");
    let request = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:8181".to_string());
    eprintln!("\n\x1b[1m=== ARP Smoke Test ===\x1b[0m");
    eprintln!("Target: {url}\n");

    // ── Test 1: Admission handshake ──
    eprintln!("\x1b[1m[1/6] Admission Handshake\x1b[0m");
    let keypair_a = SigningKey::generate(&mut rng());
    let mut client_a = SmokeClient::connect(&url, &keypair_a).await;
    pass("Agent A admitted");

    let keypair_b = SigningKey::generate(&mut rng());
    let mut client_b = SmokeClient::connect(&url, &keypair_b).await;
    pass("Agent B admitted");

    // ── Test 2: Route A → B ──
    eprintln!("\x1b[1m[2/6] Message Routing (A → B)\x1b[0m");
    let payload = b"hello from A";
    client_a.send_route(&client_b.pubkey, payload).await;

    let frame = client_b.recv_frame().await;
    match &frame {
        Frame::Deliver { src, payload: p } => {
            assert_eq!(src, &client_a.pubkey, "src mismatch");
            assert_eq!(p.as_slice(), payload, "payload mismatch");
            pass("B received Deliver with correct src/payload");
        }
        other => fail("Route A→B", &format!("expected Deliver, got {other:?}")),
    }

    let payload2 = b"reply from B";
    client_b.send_route(&client_a.pubkey, payload2).await;
    let frame2 = client_a.recv_deliver().await;
    match &frame2 {
        Frame::Deliver { src, payload: p } => {
            assert_eq!(src, &client_b.pubkey);
            assert_eq!(p.as_slice(), payload2);
            pass("A received Deliver from B (bidirectional routing works)");
        }
        other => fail("Route B→A", &format!("expected Deliver, got {other:?}")),
    }

    // ── Test 3: Send to offline agent → Status(offline) ──
    eprintln!("\x1b[1m[3/6] Offline Agent Status\x1b[0m");
    let fake_pubkey: Pubkey = [0xFFu8; 32];
    client_a.send_route(&fake_pubkey, b"to nobody").await;
    let status_frame = client_a.recv_frame().await;
    match &status_frame {
        Frame::Status { code, .. } => {
            assert_eq!(
                *code, 0x01,
                "expected offline status code 0x01, got {code:#x}"
            );
            pass("Received Status 0x01 (offline) for nonexistent agent");
        }
        other => fail("Offline status", &format!("expected Status, got {other:?}")),
    }

    // ── Test 4: Ping/Pong ──
    eprintln!("\x1b[1m[4/6] Ping/Pong\x1b[0m");
    let ping_payload = b"smoke-ping";
    client_a.send_ping(ping_payload).await;
    let pong_frame = client_a.recv_frame().await;
    match &pong_frame {
        Frame::Pong { payload: data } => {
            assert_eq!(data.as_slice(), ping_payload);
            pass("Received Pong with matching payload");
        }
        other => fail("Ping/Pong", &format!("expected Pong, got {other:?}")),
    }

    // ── Test 5: Metrics endpoint ──
    let metrics_addr = std::env::args().nth(2);
    if let Some(ref addr) = metrics_addr {
        eprintln!("\x1b[1m[5/6] Prometheus Metrics\x1b[0m");
        let body = fetch_metrics(addr).await;
        for metric_name in [
            "arp_messages_relayed_total",
            "arp_connections_active",
            "arp_admissions_total",
        ] {
            if body.contains(metric_name) {
                pass(&format!("Metrics contains {metric_name}"));
            } else {
                fail(
                    "Metrics",
                    &format!("{metric_name} not found in metrics output"),
                );
            }
        }
    } else {
        eprintln!("\x1b[1m[5/6] Prometheus Metrics\x1b[0m");
        pass("Skipped (pass metrics addr as 2nd arg for local testing)");
    }

    // ── Test 6: Multiple messages in rapid succession ──
    eprintln!("\x1b[1m[6/6] Rapid Fire (10 messages A→B)\x1b[0m");
    for i in 0u8..10 {
        client_a.send_route(&client_b.pubkey, &[i]).await;
    }
    for i in 0u8..10 {
        // Use recv_deliver to skip any Status frames (delivery acknowledgments)
        let frame = tokio::time::timeout(Duration::from_secs(5), client_b.recv_deliver()).await;
        match frame {
            Ok(Frame::Deliver { payload, .. }) => {
                assert_eq!(payload, vec![i], "payload mismatch on message {i}");
            }
            Ok(other) => fail(
                "Rapid fire",
                &format!("message {i}: expected Deliver, got {other:?}"),
            ),
            Err(_) => fail(
                "Rapid fire",
                &format!("message {i}: timeout waiting for delivery"),
            ),
        }
    }
    pass("All 10 rapid-fire messages delivered in order");

    client_a.close().await;
    client_b.close().await;

    eprintln!("\n\x1b[1;32m=== All smoke tests passed! ===\x1b[0m\n");
}
