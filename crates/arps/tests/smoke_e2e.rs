//! Comprehensive end-to-end smoke tests for ARP protocol
//!
//! These tests simulate real-world user workflows including:
//! - Authentication and admission handshake
//! - Message routing between agents
//! - Error scenarios and edge cases
//! - Rate limiting behavior
//! - Connection lifecycle management

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
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Test Suite 1: Basic Connection and Admission
#[tokio::test]
async fn smoke_test_01_basic_admission() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let _client = TestClient::connect(&addr, &keypair).await;

    println!("✓ Test 1: Basic admission works");
}

/// Test Suite 2: Bidirectional Message Routing
#[tokio::test]
async fn smoke_test_02_bidirectional_routing() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    client_a
        .send_message(&client_b.pubkey, b"Hello from Agent A")
        .await;

    let frame = client_b.recv_frame().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_a.pubkey, "Source pubkey mismatch");
            assert_eq!(payload, b"Hello from Agent A", "Payload mismatch");
        }
        other => panic!("Expected Deliver, got {:?}", other),
    }

    client_b
        .send_message(&client_a.pubkey, b"Reply from Agent B")
        .await;

    let frame = client_a.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_b.pubkey, "Source pubkey mismatch");
            assert_eq!(payload, b"Reply from Agent B", "Payload mismatch");
        }
        other => panic!("Expected Deliver, got {:?}", other),
    }

    println!("✓ Test 2: Bidirectional routing works");
}

/// Test Suite 3: Offline Agent Detection
#[tokio::test]
async fn smoke_test_03_offline_agent() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let offline_pubkey: Pubkey = [0xFFu8; 32];

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    client_a.send_message(&offline_pubkey, b"to nobody").await;

    let frame = client_a.recv_frame().await;
    match frame {
        Frame::Status { ref_pubkey, code } => {
            assert_eq!(ref_pubkey, offline_pubkey, "Status pubkey mismatch");
            assert_eq!(code, status_code::OFFLINE, "Expected OFFLINE status");
        }
        other => panic!("Expected Status(offline), got {:?}", other),
    }

    println!("✓ Test 3: Offline agent detection works");
}

/// Test Suite 4: Rate Limiting Enforcement
#[tokio::test]
async fn smoke_test_04_rate_limiting() {
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
            eprintln!("server error in test: {}", e);
        }
    });

    sleep(Duration::from_millis(50)).await;

    let keypair = SigningKey::generate(&mut rng());
    let mut client = TestClient::connect(&addr, &keypair).await;

    let dest_pubkey: Pubkey = [0xFFu8; 32];

    for _ in 0..10 {
        client.send_message(&dest_pubkey, b"test").await;
    }

    let mut found_rate_limited = false;
    let mut _offline_count = 0;

    for _ in 0..10 {
        match client.recv_frame_timeout(Duration::from_millis(500)).await {
            Some(Frame::Status { code, .. }) if code == status_code::RATE_LIMITED => {
                found_rate_limited = true;
            }
            Some(Frame::Status { code: 0x01, .. }) => {
                _offline_count += 1;
            }
            Some(_) => {}
            None => break,
        }
    }

    assert!(
        found_rate_limited,
        "Expected at least one rate-limited response"
    );

    println!("✓ Test 4: Rate limiting enforced");
}

/// Test Suite 5: Payload Size Limits
#[tokio::test]
async fn smoke_test_05_payload_size_limits() {
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
            assert_eq!(code, status_code::OVERSIZE, "Expected OVERSIZE status");
        }
        other => panic!("Expected Status(oversize), got {:?}", other),
    }

    println!("✓ Test 5: Payload size limits enforced");
}

/// Test Suite 6: Connection Replacement
#[tokio::test]
async fn smoke_test_06_connection_replacement() {
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
        other => panic!("Expected Deliver on new connection, got {:?}", other),
    }

    let timeout_result = timeout(Duration::from_millis(500), async {
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
        Err(_) | Ok(None) => {}
        Ok(Some(_)) => panic!("Old connection should not receive messages"),
    }

    println!("✓ Test 6: Connection replacement works correctly");
}

/// Test Suite 7: Concurrent Message Exchange
#[tokio::test]
async fn smoke_test_07_concurrent_agents() {
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
        let payload = format!("msg from agent {}", i);
        client
            .send_message(&pubkeys[dest_idx], payload.as_bytes())
            .await;
    }

    for (i, client) in clients.iter_mut().enumerate() {
        let src_idx = if i == 0 { agent_count - 1 } else { i - 1 };
        let expected_payload = format!("msg from agent {}", src_idx);

        let frame = client.recv_deliver().await;
        match frame {
            Frame::Deliver { src, payload } => {
                assert_eq!(src, pubkeys[src_idx], "Agent {}: Source mismatch", i);
                assert_eq!(
                    payload,
                    expected_payload.as_bytes(),
                    "Agent {}: Payload mismatch",
                    i
                );
            }
            other => panic!("Agent {}: Expected Deliver, got {:?}", i, other),
        }
    }

    println!(
        "✓ Test 7: Concurrent {}-agent message exchange works",
        agent_count
    );
}

/// Test Suite 8: Rapid Fire Message Delivery
#[tokio::test]
async fn smoke_test_08_rapid_fire() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    let message_count = 50;

    for i in 0u8..message_count {
        client_a.send_message(&client_b.pubkey, &[i]).await;
    }

    for i in 0u8..message_count {
        match timeout(Duration::from_secs(5), client_b.recv_frame()).await {
            Ok(Frame::Deliver { payload, .. }) => {
                assert_eq!(payload, vec![i], "Message {}: payload mismatch", i);
            }
            Ok(other) => panic!("Message {}: expected Deliver, got {:?}", i, other),
            Err(_) => panic!("Message {}: timeout waiting for delivery", i),
        }
    }

    println!(
        "✓ Test 8: Rapid fire {} messages delivered in order",
        message_count
    );
}

/// Test Suite 9: Admission Rejection
#[tokio::test]
async fn smoke_test_09_invalid_signature_rejection() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let url = format!("ws://{}", addr);
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

    let response_msg = timeout(Duration::from_secs(2), ws_rx.next())
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
        other => panic!("expected Rejected frame, got {:?}", other),
    }

    println!("✓ Test 9: Invalid signatures are properly rejected");
}

/// Test Suite 10: Ping/Pong Keepalive
#[tokio::test]
async fn smoke_test_10_ping_pong() {
    let (addr, _state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let mut client = TestClient::connect(&addr, &keypair).await;

    let ping_payload = b"keepalive test";
    client.send_ping(ping_payload).await;

    let frame = client.recv_frame().await;
    match frame {
        Frame::Pong { payload } => {
            assert_eq!(payload, ping_payload, "Pong payload mismatch");
        }
        other => panic!("Expected Pong, got {:?}", other),
    }

    println!("✓ Test 10: Ping/pong keepalive works");
}

/// Test Suite 11: Large Payload Handling
#[tokio::test]
async fn smoke_test_11_large_payload() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    let large_payload = vec![0xABu8; 32 * 1024];
    client_a
        .send_message(&client_b.pubkey, &large_payload)
        .await;

    let frame = client_b.recv_frame().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_a.pubkey);
            assert_eq!(payload.len(), large_payload.len());
            assert_eq!(payload, large_payload);
        }
        other => panic!("Expected Deliver, got {:?}", other),
    }

    println!("✓ Test 11: Large payload (32KB) handled correctly");
}

/// Test Suite 12: Empty Payload Handling
#[tokio::test]
async fn smoke_test_12_empty_payload() {
    let (addr, _state) = start_server().await;

    let keypair_a = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let mut client_a = TestClient::connect(&addr, &keypair_a).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    client_a.send_message(&client_b.pubkey, b"").await;

    let frame = client_b.recv_frame().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, client_a.pubkey);
            assert!(payload.is_empty(), "Expected empty payload");
        }
        other => panic!("Expected Deliver, got {:?}", other),
    }

    println!("✓ Test 12: Empty payload handled correctly");
}

/// Test Suite 13: Connection Cleanup
#[tokio::test]
async fn smoke_test_13_connection_cleanup() {
    let (addr, state) = start_server().await;

    let keypair = SigningKey::generate(&mut rng());
    let keypair_b = SigningKey::generate(&mut rng());

    let client_a = TestClient::connect(&addr, &keypair).await;
    let mut client_b = TestClient::connect(&addr, &keypair_b).await;

    assert_eq!(state.router.len(), 2, "Expected 2 connections in router");

    drop(client_a);

    sleep(Duration::from_millis(100)).await;

    client_b
        .send_message(&keypair.verifying_key().to_bytes(), b"to offline agent")
        .await;

    let frame = client_b.recv_frame().await;
    match frame {
        Frame::Status { code, .. } => {
            assert_eq!(code, status_code::OFFLINE);
        }
        other => panic!("Expected Status(offline), got {:?}", other),
    }

    println!("✓ Test 13: Connection cleanup works correctly");
}

/// Test Suite 14: HPKE Encryption Simulation (binary payload integrity)
///
/// Verifies the relay correctly forwards opaque binary payloads that simulate
/// the HPKE Auth mode encryption flow between two agents. The relay is payload-agnostic;
/// this test ensures multi-step, variable-size binary exchanges arrive intact.
#[tokio::test]
async fn smoke_test_14_noise_handshake_simulation() {
    let (addr, _state) = start_server().await;

    let keypair_alice = SigningKey::generate(&mut rng());
    let keypair_bob = SigningKey::generate(&mut rng());

    let mut alice = TestClient::connect(&addr, &keypair_alice).await;
    let mut bob = TestClient::connect(&addr, &keypair_bob).await;

    // Step 1: Alice sends a simulated HPKE Auth mode encrypted message (prefix 0x04)
    // HPKE Auth mode: encapped_key (32 bytes) + ciphertext + tag (16 bytes)
    let mut hs_init = vec![0x04u8]; // HPKE auth encrypted prefix
    hs_init.extend_from_slice(&[0xAA; 95]); // 96 bytes total
    alice.send_message(&bob.pubkey, &hs_init).await;

    let frame = bob.recv_frame().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, alice.pubkey, "HS init: source mismatch");
            assert_eq!(payload.len(), 96, "HS init: length mismatch");
            assert_eq!(payload[0], 0x04, "HPKE init: prefix mismatch");
            assert_eq!(payload, hs_init, "HS init: payload corrupted");
        }
        other => panic!("Expected Deliver for HS init, got {:?}", other),
    }

    // Step 2: Bob sends back a simulated HPKE response (prefix 0x04)
    // HPKE Auth mode response uses the same prefix (stateless per-message)
    let mut hpke_resp = vec![0x04u8]; // HPKE auth encrypted prefix
    hpke_resp.extend_from_slice(&[0xBB; 47]); // 48 bytes total
    bob.send_message(&alice.pubkey, &hpke_resp).await;

    let frame = alice.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, bob.pubkey, "HPKE resp: source mismatch");
            assert_eq!(payload.len(), 48, "HPKE resp: length mismatch");
            assert_eq!(payload[0], 0x04, "HPKE resp: prefix mismatch");
            assert_eq!(payload, hpke_resp, "HPKE resp: payload corrupted");
        }
        other => panic!("Expected Deliver for HPKE resp, got {:?}", other),
    }

    // Step 3: Alice sends a simulated encrypted transport message (prefix 0x04)
    let mut enc_msg_a = vec![0x04u8]; // HPKE auth encrypted prefix
    enc_msg_a.extend_from_slice(&[0xCC; 127]); // 128 bytes total
    alice.send_message(&bob.pubkey, &enc_msg_a).await;

    let frame = bob.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, alice.pubkey, "Enc A->B: source mismatch");
            assert_eq!(payload.len(), 128, "Enc A->B: length mismatch");
            assert_eq!(payload[0], 0x04, "Enc A->B: prefix mismatch");
            assert_eq!(payload, enc_msg_a, "Enc A->B: payload corrupted");
        }
        other => panic!("Expected Deliver for encrypted msg A->B, got {:?}", other),
    }

    // Step 4: Bob sends an encrypted reply back (prefix 0x04)
    let mut enc_msg_b = vec![0x04u8];
    enc_msg_b.extend_from_slice(&[0xDD; 255]); // 256 bytes total
    bob.send_message(&alice.pubkey, &enc_msg_b).await;

    let frame = alice.recv_deliver().await;
    match frame {
        Frame::Deliver { src, payload } => {
            assert_eq!(src, bob.pubkey, "Enc B->A: source mismatch");
            assert_eq!(payload.len(), 256, "Enc B->A: length mismatch");
            assert_eq!(payload[0], 0x04, "Enc B->A: prefix mismatch");
            assert_eq!(payload, enc_msg_b, "Enc B->A: payload corrupted");
        }
        other => panic!("Expected Deliver for encrypted msg B->A, got {:?}", other),
    }

    // Step 5: Rapid encrypted exchange — verify ordering and integrity
    for i in 0u8..10 {
        let mut msg = vec![0x04, i];
        msg.extend_from_slice(&[i; 64]);
        alice.send_message(&bob.pubkey, &msg).await;
    }

    for i in 0u8..10 {
        let frame = bob.recv_deliver().await;
        match frame {
            Frame::Deliver { src, payload } => {
                assert_eq!(src, alice.pubkey, "Rapid msg {i}: source mismatch");
                assert_eq!(payload[0], 0x04, "Rapid msg {i}: prefix mismatch");
                assert_eq!(payload[1], i, "Rapid msg {i}: sequence mismatch");
                assert_eq!(payload.len(), 66, "Rapid msg {i}: length mismatch");
            }
            other => panic!("Rapid msg {i}: expected Deliver, got {other:?}"),
        }
    }

    println!("\u{2713} Test 14: HPKE encryption simulation — binary payload integrity verified");
}
