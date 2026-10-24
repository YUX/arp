//! OpenClaw gateway bridge — injects inbound ARP messages into an agent session.
//!
//! Connects to the OpenClaw gateway via WebSocket protocol v3, performs a
//! challenge-response handshake with device auth, then forwards each
//! [`InboundMsg`] as a `chat.send` request.
//! One-way only: ARP → session. The agent uses `arpc send` for outbound.

use crate::backoff::ExponentialBackoff;
use crate::config::BridgeConfig;
use crate::contacts::ContactStore;
use crate::relay::InboundMsg;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use rand::RngExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, trace, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

fn rand_id() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_message(contacts: &ContactStore, msg: &InboundMsg) -> String {
    let from_b58 = arp_common::base58::encode(&msg.from);
    let display_name = contacts
        .lookup_by_pubkey(&from_b58)
        .map_or_else(|| from_b58.clone(), |c| c.name);
    let body = String::from_utf8_lossy(&msg.payload);
    format!("[ARP from {display_name}]: {body}")
}

// --- Device identity for gateway auth ---

struct DeviceIdentity {
    device_id: String,
    public_key_raw: [u8; 32],
    signing_key: SigningKey,
}

/// Load OpenClaw device identity from `~/.openclaw/identity/device.json`.
fn load_device_identity() -> Option<DeviceIdentity> {
    let path = dirs::home_dir()?.join(".openclaw/identity/device.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    let device_id = json["deviceId"].as_str()?.to_string();
    let private_pem = json["privateKeyPem"].as_str()?;
    let public_pem = json["publicKeyPem"].as_str()?;

    let private_der = pem_to_der(private_pem)?;
    let public_der = pem_to_der(public_pem)?;

    // PKCS8 Ed25519: 16-byte prefix + 32-byte raw key
    if private_der.len() < 48 {
        return None;
    }
    let private_raw: [u8; 32] = private_der[16..48].try_into().ok()?;

    // SPKI Ed25519: 12-byte prefix + 32-byte raw key
    if public_der.len() < 44 {
        return None;
    }
    let public_key_raw: [u8; 32] = public_der[12..44].try_into().ok()?;

    let signing_key = SigningKey::from_bytes(&private_raw);

    // Verify device_id matches SHA-256(raw public key)
    let expected_id = sha256_hex(&public_key_raw);
    if expected_id != device_id {
        warn!(
            expected = %expected_id,
            actual = %device_id,
            "device identity mismatch, skipping device auth"
        );
        return None;
    }

    Some(DeviceIdentity {
        device_id,
        public_key_raw,
        signing_key,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(b64).ok()
}

fn build_connect_frame(token: &str, device: Option<&DeviceIdentity>, nonce: &str) -> Value {
    let signed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let scopes = ["operator.read", "operator.write"];

    let device_json = device.map(|id| {
        let payload = format!(
            "v2|{}|gateway-client|backend|operator|{}|{}|{}|{}",
            id.device_id,
            scopes.join(","),
            signed_at_ms,
            token,
            nonce
        );
        let signature = id.signing_key.sign(payload.as_bytes());

        json!({
            "id": id.device_id,
            "publicKey": URL_SAFE_NO_PAD.encode(id.public_key_raw),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "signedAt": signed_at_ms,
            "nonce": nonce
        })
    });

    let mut params = json!({
        "minProtocol": 3,
        "maxProtocol": 3,
        "client": {
            "id": "gateway-client",
            "version": env!("CARGO_PKG_VERSION"),
            "platform": "rust",
            "mode": "backend"
        },
        "role": "operator",
        "scopes": scopes,
        "auth": {
            "token": token
        }
    });

    if let Some(dev) = device_json {
        params["device"] = dev;
    }

    json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": params
    })
}

fn chat_send_frame(session_key: &str, message: &str) -> Value {
    json!({
        "type": "req",
        "id": rand_id(),
        "method": "chat.send",
        "params": {
            "sessionKey": session_key,
            "message": message,
            "idempotencyKey": rand_id()
        }
    })
}

/// Top-level bridge loop with automatic reconnection and backoff.
///
/// Subscribes to the daemon's `inbox_tx` broadcast channel and, for each
/// inbound message, sends `chat.send` to the OpenClaw gateway.
pub async fn run_bridge(
    config: BridgeConfig,
    mut inbox_rx: broadcast::Receiver<InboundMsg>,
    contacts: Arc<ContactStore>,
) {
    info!(
        gateway = %config.gateway_url,
        session_key = "<REDACTED>",
        "bridge starting"
    );

    let device = load_device_identity();
    if device.is_some() {
        info!("bridge loaded device identity for gateway auth");
    } else {
        warn!("bridge has no device identity, scopes will be limited");
    }

    let mut backoff =
        ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(30), 2.0);

    loop {
        match bridge_session(&config, &mut inbox_rx, &contacts, device.as_ref()).await {
            Ok(()) => {
                info!("bridge session ended cleanly");
                break;
            }
            Err(BridgeError::Fatal(e)) => {
                error!(error = %e, "fatal bridge error, not retrying");
                break;
            }
            Err(BridgeError::Transient(e)) => {
                warn!(error = %e, "bridge connection lost");
            }
        }

        let delay = backoff.next_delay();
        info!(delay_ms = delay.as_millis() as u64, "bridge reconnecting");
        tokio::time::sleep(delay).await;
    }
}

#[derive(Debug)]
enum BridgeError {
    Fatal(anyhow::Error),
    Transient(anyhow::Error),
}

async fn bridge_session(
    config: &BridgeConfig,
    inbox_rx: &mut broadcast::Receiver<InboundMsg>,
    contacts: &ContactStore,
    device: Option<&DeviceIdentity>,
) -> Result<(), BridgeError> {
    // --- Connect ---
    let (ws, _) = tokio_tungstenite::connect_async(&config.gateway_url)
        .await
        .map_err(|e| BridgeError::Transient(e.into()))?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    info!("bridge connected to gateway");

    // --- Wait for connect.challenge ---
    let challenge = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_rx.next())
        .await
        .map_err(|_| BridgeError::Transient(anyhow::anyhow!("challenge timeout")))?
        .ok_or_else(|| {
            BridgeError::Transient(anyhow::anyhow!("connection closed before challenge"))
        })?
        .map_err(|e| BridgeError::Transient(e.into()))?;

    let challenge_text = match challenge {
        Message::Text(t) => t,
        other => {
            return Err(BridgeError::Transient(anyhow::anyhow!(
                "expected text challenge, got: {other:?}"
            )));
        }
    };

    let challenge_json: Value = serde_json::from_str(&challenge_text)
        .map_err(|e| BridgeError::Transient(anyhow::anyhow!("challenge parse error: {e}")))?;

    if challenge_json.get("type").and_then(|v| v.as_str()) != Some("event")
        || challenge_json.get("event").and_then(|v| v.as_str()) != Some("connect.challenge")
    {
        return Err(BridgeError::Transient(anyhow::anyhow!(
            "expected connect.challenge event, got: {challenge_json}"
        )));
    }

    let nonce = challenge_json
        .pointer("/payload/nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    debug!("received connect.challenge from gateway");

    // --- Send connect request with device auth ---
    let hs = build_connect_frame(&config.gateway_token, device, nonce);
    ws_tx
        .send(Message::Text(hs.to_string().into()))
        .await
        .map_err(|e| BridgeError::Transient(e.into()))?;

    // --- Wait for connect response (skip interleaved events) ---
    let hs_json = loop {
        let hs_resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_rx.next())
            .await
            .map_err(|_| BridgeError::Transient(anyhow::anyhow!("handshake timeout")))?
            .ok_or_else(|| {
                BridgeError::Transient(anyhow::anyhow!("connection closed during handshake"))
            })?
            .map_err(|e| BridgeError::Transient(e.into()))?;

        let hs_text = match hs_resp {
            Message::Text(t) => t,
            Message::Ping(_) | Message::Pong(_) => continue,
            other => {
                return Err(BridgeError::Transient(anyhow::anyhow!(
                    "expected text handshake response, got: {other:?}"
                )));
            }
        };

        let json: Value = serde_json::from_str(&hs_text)
            .map_err(|e| BridgeError::Transient(anyhow::anyhow!("handshake parse error: {e}")))?;

        // Skip gateway events (e.g. tick) while waiting for connect response
        if json.get("type").and_then(|v| v.as_str()) == Some("event") {
            debug!(event = %hs_text, "skipping gateway event during handshake");
            continue;
        }

        break json;
    };

    if hs_json.get("type").and_then(|v| v.as_str()) != Some("res") {
        return Err(BridgeError::Transient(anyhow::anyhow!(
            "unexpected handshake frame type: {hs_json}"
        )));
    }
    if hs_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err_msg = hs_json
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(BridgeError::Fatal(anyhow::anyhow!(
            "handshake rejected: {err_msg}"
        )));
    }

    info!("bridge handshake succeeded");

    // --- Message forwarding loop ---
    loop {
        tokio::select! {
            msg = inbox_rx.recv() => {
                match msg {
                    Ok(inbound) => {
                        let text = format_message(contacts, &inbound);
                        let frame = chat_send_frame(&config.session_key, &text);

                        trace!(message = %text, "bridge injecting message");

                        ws_tx
                            .send(Message::Text(frame.to_string().into()))
                            .await
                            .map_err(|e| BridgeError::Transient(e.into()))?;

                        // Response may be interleaved with gateway events; non-blocking check
                        match tokio::time::timeout(SEND_TIMEOUT, ws_rx.next()).await {
                            Ok(Some(Ok(Message::Text(resp_text)))) => {
                                if let Ok(resp) = serde_json::from_str::<Value>(&resp_text) {
                                    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                                        debug!("chat.send succeeded");
                                    } else {
                                        let err = resp
                                            .pointer("/error/message")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown");
                                        warn!(error = %err, "chat.send failed");
                                    }
                                }
                            }
                            Ok(Some(Ok(Message::Close(_)))) => {
                                return Err(BridgeError::Transient(
                                    anyhow::anyhow!("gateway closed connection"),
                                ));
                            }
                            Ok(Some(Err(e))) => {
                                return Err(BridgeError::Transient(e.into()));
                            }
                            Ok(None) => {
                                return Err(BridgeError::Transient(
                                    anyhow::anyhow!("gateway connection closed"),
                                ));
                            }
                            Err(_) => {
                                warn!("chat.send response timeout (message may still have been delivered)");
                            }
                            _ => { tracing::trace!("ignoring unexpected chat.send response"); }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "bridge lagged behind inbox, some messages dropped");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbox channel closed, bridge shutting down");
                        return Ok(());
                    }
                }
            }

            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Ping(data))) => {
                        ws_tx.send(Message::Pong(data)).await
                            .map_err(|e| BridgeError::Transient(e.into()))?;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(BridgeError::Transient(
                            anyhow::anyhow!("gateway closed connection"),
                        ));
                    }
                    Some(Ok(Message::Text(text))) => {
                        debug!(frame = %text, "bridge ignoring gateway event");
                    }
                    Some(Err(e)) => {
                        return Err(BridgeError::Transient(e.into()));
                    }
                    _ => { tracing::trace!("ignoring non-binary gateway message"); }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::InboundMsg;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_contacts_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join("arpc_bridge_tests");
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir.join(format!("{name}_{unique}.toml"))
    }

    fn inbound(from: [u8; 32], payload: Vec<u8>) -> InboundMsg {
        InboundMsg {
            from,
            payload,
            received_at: Utc::now(),
        }
    }

    #[test]
    fn format_message_uses_contact_name_for_known_sender() {
        let path = temp_contacts_path("known_sender");
        let contacts = ContactStore::load(path.clone()).expect("load contact store");

        let from = [0x11u8; 32];
        let from_b58 = arp_common::base58::encode(&from);
        contacts
            .add("Alice", &from_b58, "")
            .expect("add contact should succeed");

        let msg = inbound(from, b"hello".to_vec());
        let formatted = format_message(&contacts, &msg);

        assert_eq!(formatted, "[ARP from Alice]: hello");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn format_message_uses_base58_for_unknown_sender() {
        let path = temp_contacts_path("unknown_sender");
        let contacts = ContactStore::load(path.clone()).expect("load contact store");

        let from = [0x22u8; 32];
        let from_b58 = arp_common::base58::encode(&from);
        let msg = inbound(from, b"hello".to_vec());

        let formatted = format_message(&contacts, &msg);

        assert_eq!(formatted, format!("[ARP from {from_b58}]: hello"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn format_message_uses_lossy_utf8_for_payload() {
        let path = temp_contacts_path("lossy_payload");
        let contacts = ContactStore::load(path.clone()).expect("load contact store");

        let from = [0x33u8; 32];
        let payload = vec![0x66, 0x6f, 0x80, 0x6f];
        let msg = inbound(from, payload.clone());
        let from_b58 = arp_common::base58::encode(&from);
        let lossy = String::from_utf8_lossy(&payload);

        let formatted = format_message(&contacts, &msg);

        assert_eq!(formatted, format!("[ARP from {from_b58}]: {lossy}"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn build_connect_frame_without_device_has_required_fields() {
        let frame = build_connect_frame("token-123", None, "nonce-xyz");

        assert_eq!(frame["type"], "req");
        assert_eq!(frame["method"], "connect");
        assert_eq!(frame["id"], "connect-1");
        assert_eq!(frame["params"]["minProtocol"], 3);
        assert_eq!(frame["params"]["maxProtocol"], 3);
        assert_eq!(frame["params"]["client"]["id"], "gateway-client");
        assert_eq!(frame["params"]["client"]["platform"], "rust");
        assert_eq!(frame["params"]["client"]["mode"], "backend");
        assert_eq!(frame["params"]["role"], "operator");
        assert_eq!(frame["params"]["auth"]["token"], "token-123");
        assert_eq!(
            frame["params"]["scopes"],
            json!(["operator.read", "operator.write"])
        );
        assert!(frame["params"].get("device").is_none());
    }

    #[test]
    fn chat_send_frame_has_expected_shape() {
        let frame = chat_send_frame("session:abc", "hi there");

        assert_eq!(frame["type"], "req");
        assert_eq!(frame["method"], "chat.send");
        assert_eq!(frame["params"]["sessionKey"], "session:abc");
        assert_eq!(frame["params"]["message"], "hi there");

        let id = frame["id"].as_str().expect("id is string");
        let idempotency = frame["params"]["idempotencyKey"]
            .as_str()
            .expect("idempotencyKey is string");
        assert_eq!(id.len(), 32);
        assert_eq!(idempotency.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(idempotency.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pem_to_der_valid_pem_decodes_bytes() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAQIDBA==\n-----END PUBLIC KEY-----";

        let der = pem_to_der(pem).expect("valid pem should decode");
        assert_eq!(der, vec![1, 2, 3, 4]);
    }

    #[test]
    fn pem_to_der_invalid_base64_returns_none() {
        let pem = "-----BEGIN PUBLIC KEY-----\n%%%not-base64%%%\n-----END PUBLIC KEY-----";

        assert!(pem_to_der(pem).is_none());
    }

    #[test]
    fn pem_to_der_empty_input_is_empty_or_none() {
        let result = pem_to_der("");
        assert!(match result {
            None => true,
            Some(bytes) => bytes.is_empty(),
        });
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
