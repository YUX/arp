mod common;

use arp_common::Pubkey;
use arp_common::crypto;
use arp_common::frame::Frame;
use arp_common::types::status_code;
use arps::router::Router;
use arps::server::ServerState;
use common::*;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[tokio::test]
async fn two_agents_exchange_messages() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    client_a
        .send_message(&client_b.pubkey, b"hello from A")
        .await;

    let frame = client_b.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_a.pubkey);
            assert_eq!(payload, b"hello from A");
        }
        other => panic!("expected Deliver, got {other:?}"),
    }

    client_b
        .send_message(&client_a.pubkey, b"hello from B")
        .await;

    let frame = client_a.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_b.pubkey);
            assert_eq!(payload, b"hello from B");
        }
        other => panic!("expected Deliver, got {other:?}"),
    }
}

#[tokio::test]
async fn send_to_offline_agent_returns_status() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let offline_pubkey: Pubkey = [0xFFu8; 32];

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    client_a.send_message(&offline_pubkey, b"hello?").await;

    let frame = client_a.recv_frame().await;
    match frame {
        Frame::Status { ref_pubkey, code } => {
            assert_eq!(ref_pubkey, offline_pubkey);
            assert_eq!(code, 0x01);
        }
        other => panic!("expected Status offline, got {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_pubkey_replaces_old_connection() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_old = TestClient::connect(&addr, &keypair).await;
    let mut client_new = TestClient::connect(&addr, &keypair).await;

    let mut client_b = TestClient::connect(&addr, &keypair_b).await;
    client_b
        .send_message(&client_new.pubkey, b"to new connection")
        .await;

    let frame = client_new.recv_frame().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_b.pubkey);
            assert_eq!(payload, b"to new connection");
        }
        other => panic!("expected Deliver on new connection, got {other:?}"),
    }

    let timeout_result = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(msg) = client_old.ws_rx.next().await {
            match msg {
                Ok(Message::Binary(data)) => return Some(data),
                Ok(Message::Close(_)) | Err(_) => return None,
                _ => {}
            }
        }
        None
    })
    .await;
    match timeout_result {
        // timeout = old connection got nothing, expected
        // connection closed or stream ended, also acceptable
        Err(_) | Ok(None) => {}
        Ok(Some(data)) => {
            let frame = Frame::parse(&data).unwrap();
            panic!("old connection should not receive messages, got {frame:?}");
        }
    }
}

#[tokio::test]
async fn oversized_payload_returns_status() {
    let (addr, _state) = start_server_with_max_payload(512).await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let _client_b = TestClient::connect(&addr, &keypair_b).await;

    let oversized = vec![0u8; 1024];
    client_a
        .send_message(&keypair_b.verifying_key().to_bytes(), &oversized)
        .await;

    let frame = client_a.recv_frame().await;
    match frame {
        Frame::Status { code, .. } => {
            assert_eq!(code, 0x03);
        }
        other => panic!("expected Status oversize, got {other:?}"),
    }
}

#[tokio::test]
async fn concurrent_agents_exchange_messages() {
    let (addr, _state) = start_server().await;

    let agent_count = 10;
    let mut keypairs = Vec::new();
    for _ in 0..agent_count {
        keypairs.push(SigningKey::generate(&mut rng()));
    }

    let mut clients = Vec::new();
    for kp in &keypairs {
        clients.push(TestClient::connect(&addr, kp).await);
    }

    let pubkeys: Vec<Pubkey> = keypairs
        .iter()
        .map(|kp| kp.verifying_key().to_bytes())
        .collect();

    for (i, client) in clients.iter_mut().enumerate() {
        let dest_idx = (i + 1) % agent_count;
        let payload = format!("msg from agent {i}");
        client
            .send_message(&pubkeys[dest_idx], payload.as_bytes())
            .await;
    }

    for (i, client) in clients.iter_mut().enumerate() {
        let src_idx = if i == 0 { agent_count - 1 } else { i - 1 };
        let expected_payload = format!("msg from agent {src_idx}");

        let frame = client.recv_deliver().await;
        match frame {
            Frame::Deliver { src, payload } => {
                assert_eq!(src, pubkeys[src_idx]);
                assert_eq!(payload, expected_payload.as_bytes());
            }
            other => panic!("agent {i} expected Deliver, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_rate_limiting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_keypair = SigningKey::generate(&mut rng());
    let config = test_config_with_params(addr, 1000, 5, 5);
    let router = Router::new(config.max_conns);
    let state = Arc::new(ServerState {
        router,
        server_keypair,
        config,
        ip_connections: dashmap::DashMap::new(),
        active_connections: std::sync::atomic::AtomicUsize::new(0),
        pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let keypair = SigningKey::generate(&mut rng());
    let mut client = TestClient::connect(&addr, &keypair).await;

    let dest_pubkey: Pubkey = [0xFFu8; 32];

    for _ in 0..10 {
        client.send_message(&dest_pubkey, b"test").await;
    }

    let mut found_rate_limited = false;
    for _ in 0..10 {
        match client.recv_frame_timeout(Duration::from_millis(500)).await {
            Some(Frame::Status { code, .. }) if code == status_code::RATE_LIMITED => {
                found_rate_limited = true;
                break;
            }
            Some(Frame::Status { code: 0x01, .. }) => {}
            Some(other) => panic!("unexpected frame: {other:?}"),
            None => break,
        }
    }

    assert!(found_rate_limited, "expected rate limited status");
}

#[tokio::test]
async fn test_invalid_admission_signature() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let url = format!("ws://{addr}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
    );
    req.headers_mut()
        .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let challenge_msg = ws_rx.next().await.unwrap().unwrap();
    let Message::Binary(challenge_data) = challenge_msg else {
        panic!("expected binary challenge frame");
    };
    let frame = Frame::parse(&challenge_data).unwrap();
    let Frame::Challenge { .. } = frame else {
        panic!("expected challenge frame");
    };

    let timestamp = crypto::unix_now().expect("clock error");
    let invalid_signature = [0xFFu8; 64];
    let pubkey: Pubkey = keypair.verifying_key().to_bytes();
    let response = Frame::response(&pubkey, timestamp, &invalid_signature);
    ws_tx
        .send(Message::Binary(response.serialize().into()))
        .await
        .unwrap();

    let response_msg = tokio::time::timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .expect("timeout waiting for response")
        .unwrap()
        .unwrap();

    let Message::Binary(data) = response_msg else {
        panic!("expected binary frame");
    };
    let frame = Frame::parse(&data).unwrap();
    match frame {
        Frame::Rejected { .. } => {}
        other => panic!("expected Rejected frame, got {other:?}"),
    }
}

#[tokio::test]
async fn test_admission_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_keypair = SigningKey::generate(&mut rng());
    let config = test_config_with_params(addr, 1000, 120, 1);
    let router = Router::new(config.max_conns);
    let state = Arc::new(ServerState {
        router,
        server_keypair,
        config,
        ip_connections: dashmap::DashMap::new(),
        active_connections: std::sync::atomic::AtomicUsize::new(0),
        pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("ws://{addr}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
    );
    req.headers_mut()
        .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (_ws_tx, mut ws_rx) = ws.split();

    let challenge_msg = ws_rx.next().await.unwrap().unwrap();
    let Message::Binary(_) = challenge_msg else {
        panic!("expected binary challenge frame");
    };

    let result = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if let Ok(frame) = Frame::parse(&data)
                        && matches!(frame, Frame::Rejected { .. })
                    {
                        return true;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => return true,
                _ => {}
            }
        }
        false
    })
    .await;

    assert!(
        result.unwrap_or(false),
        "expected connection to close with rejection"
    );
}

#[tokio::test]
async fn test_ping_pong() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let mut client = TestClient::connect(&addr, &keypair).await;

    let ping_payload = b"test ping";
    client.send_ping(ping_payload).await;

    let frame = client.recv_frame().await;
    match frame {
        Frame::Pong { payload } => {
            assert_eq!(payload, ping_payload);
        }
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[tokio::test]
async fn test_max_connections_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_keypair = SigningKey::generate(&mut rng());
    let config = test_config_with_params(addr, 2, 120, 5);
    let router = Router::new(config.max_conns);
    let state = Arc::new(ServerState {
        router,
        server_keypair,
        config,
        ip_connections: dashmap::DashMap::new(),
        active_connections: std::sync::atomic::AtomicUsize::new(0),
        pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
    });

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let keypair1 = SigningKey::generate(&mut rng());
    let keypair2 = SigningKey::generate(&mut rng());

    let mut _client1 = TestClient::connect(&addr, &keypair1).await;
    let mut _client2 = TestClient::connect(&addr, &keypair2).await;

    let url = format!("ws://{addr}");
    let req = {
        let mut r = url.into_client_request().unwrap();
        r.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
        );
        r.headers_mut()
            .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
        r
    };
    let connection_result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_tungstenite::connect_async(req),
    )
    .await;
    if let Ok(Ok((ws, _))) = connection_result {
        let (_, mut ws_rx) = ws.split();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(msg) = ws_rx.next().await {
                match msg {
                    Ok(Message::Close(_)) | Err(_) => return true,
                    _ => {}
                }
            }
            false
        })
        .await;
        assert!(result.unwrap_or(false), "expected 3rd connection to fail");
    }
}

/// Test that admission succeeds with proof-of-work enabled (difficulty 8).
/// Difficulty 8 requires ~256 hash attempts — fast enough for a test.
#[tokio::test]
async fn test_admission_with_pow() {
    let (addr, _state) = start_server_with_pow(8).await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    // Both clients solve PoW and get admitted
    let mut client_a = TestClient::connect_with_pow(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect_with_pow(&addr, &keypair_b).await;

    // Verify the connection actually works — send a message through
    client_a.send_message(&client_b.pubkey, b"pow works").await;

    let frame = client_b.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_a.pubkey);
            assert_eq!(payload, b"pow works");
        }
        other => panic!("expected Deliver, got {other:?}"),
    }
}

/// Test that a client sending a response WITHOUT a PoW nonce gets rejected
/// when the server requires PoW.
#[tokio::test]
async fn test_pow_required_rejects_no_nonce() {
    let (addr, _state) = start_server_with_pow(8).await;

    let url = format!("ws://{addr}");
    let req = {
        let mut r = url.into_client_request().unwrap();
        r.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
        );
        r.headers_mut()
            .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
        r
    };
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Read challenge
    let challenge_msg = ws_rx.next().await.unwrap().unwrap();
    let Message::Binary(challenge_data) = challenge_msg else {
        panic!("expected binary");
    };
    let frame = Frame::parse(&challenge_data).unwrap();
    let Frame::Challenge { challenge, .. } = frame else {
        panic!("expected challenge");
    };

    // Send response WITHOUT PoW nonce
    let keypair = SigningKey::generate(&mut rng());
    let timestamp = arp_common::crypto::unix_now().expect("clock");
    let signature = arp_common::crypto::sign_admission(&keypair, &challenge, timestamp);
    let pubkey: Pubkey = keypair.verifying_key().to_bytes();
    let response = Frame::response(&pubkey, timestamp, &signature); // no PoW!
    ws_tx
        .send(Message::Binary(response.serialize().into()))
        .await
        .unwrap();

    // Should get rejected (or connection closed)
    let result = tokio::time::timeout(Duration::from_secs(3), ws_rx.next()).await;
    if let Ok(Some(Ok(Message::Binary(data)))) = result {
        let frame = Frame::parse(&data).unwrap();
        assert!(
            matches!(frame, Frame::Rejected { .. }),
            "expected Rejected, got {frame:?}"
        );
    }
    // Connection closed or rejected — both are acceptable
}

/// SEC-01: A direct connection without CF-Connecting-IP is accepted using peer_addr.
#[tokio::test]
async fn test_direct_connection_uses_peer_addr() {
    let (addr, _state) = start_server().await;

    let url = format!("ws://{addr}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
    );
    // No CF-Connecting-IP header — server should use peer_addr.ip() directly
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (_, mut ws_rx) = ws.split();

    // Server should proceed to admission (send Challenge, not reject)
    let msg = tokio::time::timeout(Duration::from_secs(2), ws_rx.next()).await;
    match msg {
        Ok(Some(Ok(Message::Binary(data)))) => {
            let frame = Frame::parse(&data).unwrap();
            assert!(
                matches!(frame, Frame::Challenge { .. }),
                "expected Challenge frame, got {frame:?}"
            );
        }
        other => panic!("expected Challenge frame, got {other:?}"),
    }
}

#[tokio::test]
async fn test_disconnect_during_admission() {
    let (addr, state) = start_server().await;

    // Connect WebSocket but drop before completing admission
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!("ws://{addr}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
    );
    req.headers_mut()
        .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let (mut _ws_tx, mut ws_rx) = ws.split();

    // Receive the challenge but don't respond — just drop the connection
    let _challenge = ws_rx.next().await;
    drop(ws_rx);
    drop(_ws_tx);

    // Small delay for cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Server should still be functional — verify by connecting normally
    let keypair = SigningKey::generate(&mut rng());
    let _client = TestClient::connect(&addr, &keypair).await;
    assert_eq!(
        state
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_rapid_connect_disconnect_cycle() {
    let (addr, _state) = start_server().await;

    // Rapidly connect and disconnect 10 clients
    for _ in 0..10 {
        let keypair = SigningKey::generate(&mut rng());
        let client = TestClient::connect(&addr, &keypair).await;
        drop(client);
    }

    // Small delay for cleanup
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Server should still accept connections after rapid cycling
    let keypair = SigningKey::generate(&mut rng());
    let _client = TestClient::connect(&addr, &keypair).await;
}

#[tokio::test]
async fn test_rate_limiter_boundary_exact_limit() {
    let msg_rate = 5u32;
    let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listen.local_addr().unwrap();
    let config = test_config_with_params(addr, 1000, msg_rate, 5);
    let state = Arc::new(ServerState {
        router: Router::new(config.max_conns),
        server_keypair: SigningKey::generate(&mut rng()),
        config,
        ip_connections: dashmap::DashMap::new(),
        active_connections: std::sync::atomic::AtomicUsize::new(0),
        pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
    });
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listen, state_clone).await {
            eprintln!("server error: {e}");
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());
    let mut sender = TestClient::connect(&addr, &keypair_a).await;
    let mut receiver = TestClient::connect(&addr, &keypair_b).await;

    // Send exactly msg_rate messages — all should succeed
    for i in 0..msg_rate {
        sender
            .send_message(&receiver.pubkey, format!("msg-{i}").as_bytes())
            .await;
    }

    // All messages should be delivered
    for _ in 0..msg_rate {
        let frame = receiver.recv_frame().await;
        assert!(matches!(frame, Frame::Deliver { .. }), "expected delivery");
    }

    // The next message should trigger rate limiting
    sender.send_message(&receiver.pubkey, b"over-limit").await;
    // Sender should receive a status frame indicating rate limit
    let status = sender.recv_frame().await;
    assert!(
        matches!(status, Frame::Status { .. }),
        "expected rate limit status"
    );
}
