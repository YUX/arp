use crate::admission::admit;
use crate::error::ArpsError;
use crate::message_loop::{WsRecv, WsSink, run_message_loop};
use crate::metrics::{counters, gauges};
use crate::router::ConnHandle;
use crate::server::ServerState;
use arp_common::Pubkey;
use arp_common::frame::Frame;
use futures_util::{SinkExt, StreamExt};
use rand::RngExt;
use rand::rng;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

struct IpGuard {
    state: Arc<ServerState>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut remove = false;
        if let Some(mut entry) = self.state.ip_connections.get_mut(&self.ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                remove = true;
            }
        }
        if remove {
            self.state
                .ip_connections
                .remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}

/// Send a challenge frame, wait for a valid admission response, and return
/// the authenticated client's public key.
async fn perform_admission(
    ws_tx: &mut WsSink,
    ws_rx: &mut WsRecv,
    state: &ServerState,
) -> Result<Pubkey, ArpsError> {
    let mut challenge = [0u8; 32];
    rng().fill(&mut challenge);

    let server_pubkey = state.server_keypair.verifying_key().to_bytes();

    let challenge_frame = Frame::challenge(&challenge, &server_pubkey, state.config.pow_difficulty);
    ws_tx
        .send(Message::Binary(challenge_frame.serialize().into()))
        .await
        .map_err(ArpsError::WebSocket)?;

    match timeout(
        Duration::from_secs(state.config.admit_timeout),
        admit(ws_rx, &challenge, state.config.pow_difficulty),
    )
    .await
    {
        Ok(Ok(pk)) => {
            counters::admissions_total("admitted");
            let admitted_frame = Frame::admitted();
            ws_tx
                .send(Message::Binary(admitted_frame.serialize().into()))
                .await
                .map_err(ArpsError::WebSocket)?;
            Ok(pk)
        }
        Ok(Err(e)) => {
            counters::admissions_total("rejected");
            let reason = match &e {
                ArpsError::TimestampExpired => {
                    arp_common::types::rejection_reason::TIMESTAMP_EXPIRED
                }
                ArpsError::InvalidPoW => arp_common::types::rejection_reason::INVALID_POW,
                ArpsError::SignatureError(_) => arp_common::types::rejection_reason::BAD_SIG,
                _ => arp_common::types::rejection_reason::BAD_SIG,
            };
            let rejected_frame = Frame::rejected(reason);
            match ws_tx
                .send(Message::Binary(rejected_frame.serialize().into()))
                .await
            {
                Ok(()) => tracing::debug!(reason = reason, "sent rejection frame to client"),
                Err(send_err) => {
                    tracing::debug!(reason = reason, error = %send_err, "failed to send rejection frame")
                }
            }
            Err(e)
        }
        Err(_) => {
            counters::admissions_total("timeout");
            let rejected_frame = Frame::rejected(0x02);
            match ws_tx
                .send(Message::Binary(rejected_frame.serialize().into()))
                .await
            {
                Ok(()) => tracing::debug!("sent timeout rejection to client"),
                Err(send_err) => {
                    tracing::debug!(error = %send_err, "failed to send timeout rejection")
                }
            }
            Err(ArpsError::InvalidAdmission)
        }
    }
}

pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<(), ArpsError> {
    // Acquire pre-auth semaphore to limit unauthenticated connections
    // This prevents DoS by exhausting file descriptors before authentication
    let _permit = state.pre_auth_semaphore.acquire().await.map_err(|_| {
        tracing::debug!("pre-auth semaphore closed");
        ArpsError::ConnectionClosed
    })?;

    stream.set_nodelay(true).map_err(ArpsError::Io)?;

    // Detect plain HTTP requests (e.g., browser visits) and respond with a landing
    // page or configured redirect. The relay only speaks WebSocket; without this,
    // browsers would see a connection error.
    {
        let mut peek_buf = [0u8; 4096];
        if let Ok(n) = stream.peek(&mut peek_buf).await
            && let Ok(preview) = std::str::from_utf8(&peek_buf[..n])
        {
            let is_http = preview.starts_with("GET ")
                || preview.starts_with("HEAD ")
                || preview.starts_with("POST ");
            if is_http && !preview.to_ascii_lowercase().contains("upgrade: websocket") {
                if let Some(ref url) = state.config.redirect_url {
                    let resp = format!(
                        "HTTP/1.1 301 Moved Permanently\r\n\
                             Location: {url}\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\
                             \r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    let body = "<html><head><title>ARP Relay</title></head>\
                            <body><h1>ARP Relay</h1>\
                            <p>This is an Agent Relay Protocol (ARP) WebSocket endpoint.</p>\
                            <p>Connect with an ARP client to start communicating.</p>\
                            </body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/html\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
                return Ok(());
            }
        }
    }

    // WebSocketConfig is #[non_exhaustive] in tungstenite 0.30, so start from
    // defaults and override the size limits.
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(33 + 65535);
    ws_config.max_frame_size = Some(33 + 65535);

    let client_ip = Arc::new(std::sync::OnceLock::new());
    let client_proto = Arc::new(std::sync::OnceLock::new());
    let ip_cell = client_ip.clone();
    let proto_cell = client_proto.clone();
    #[allow(clippy::result_large_err)] // Error type dictated by tungstenite callback API
    let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        move |req: &Request<()>, mut resp: tokio_tungstenite::tungstenite::http::Response<()>| {
            // Extract real client IP from Cloudflare headers.
            // CF Tunnel uses X-Forwarded-For; CF proxy uses CF-Connecting-IP.
            //
            // AUDIT NET-01: Self-hosters deploying without Cloudflare must configure
            // their reverse proxy to set a trusted X-Forwarded-For or CF-Connecting-IP
            // header. Without a trusted proxy, these headers can be spoofed by clients,
            // undermining per-IP rate limiting and connection limits.
            let ip = req
                .headers()
                .get("cf-connecting-ip")
                .or_else(|| req.headers().get("x-forwarded-for"))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok());
            if let Some(ip) = ip {
                let _ = ip_cell.set(ip);
            }
            if let Some(protocols) = req.headers().get("sec-websocket-protocol")
                && let Ok(proto_str) = protocols.to_str()
            {
                for p in proto_str.split(',').map(str::trim) {
                    if p == arp_common::types::PROTOCOL_VERSION {
                        let _ = proto_cell.set(p.to_string());
                        resp.headers_mut().insert(
                            "sec-websocket-protocol",
                            tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                                arp_common::types::PROTOCOL_VERSION,
                            ),
                        );
                        break;
                    }
                }
                // If no match found, store the first offered protocol for error reporting
                if proto_cell.get().is_none()
                    && let Some(first) = proto_str.split(',').next().map(str::trim)
                {
                    let _ = proto_cell.set(first.to_string());
                }
            }
            Ok(resp)
        },
        Some(ws_config),
    )
    .await
    .map_err(ArpsError::WebSocket)?;

    // SEC-01: Default to TCP peer address. Only trust forwarded headers
    // (CF-Connecting-IP / X-Forwarded-For) when the peer is in a configured
    // trusted proxy CIDR range.
    let client_ip = if let Some(forwarded_ip) = client_ip.get().copied() {
        if state
            .config
            .trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(&peer_addr.ip()))
        {
            forwarded_ip
        } else {
            tracing::debug!(
                peer = %peer_addr.ip(),
                forwarded = %forwarded_ip,
                "ignoring forwarded IP from untrusted peer"
            );
            peer_addr.ip()
        }
    } else {
        peer_addr.ip()
    };

    // Atomic check-and-increment for per-IP connection limiting
    // Uses DashMap entry API to prevent race conditions between check and increment
    let mut should_reject = false;

    // Use entry API to atomically check and update
    match state.ip_connections.entry(client_ip) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let count = *entry.get();
            if count >= state.config.max_conns_ip {
                should_reject = true;
            } else {
                *entry.get_mut() += 1;
            }
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(1);
        }
    }

    if should_reject {
        tracing::debug!(ip = %client_ip, limit = state.config.max_conns_ip, "per-IP connection limit exceeded");
        return Err(ArpsError::ConnectionClosed);
    }

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip: client_ip,
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Reject clients with outdated protocol version
    let required = arp_common::types::PROTOCOL_VERSION;
    let client_version = client_proto.get().map(String::as_str).unwrap_or("");
    if client_version != required {
        tracing::debug!(
            client_proto = client_version,
            required = required,
            "rejecting outdated client"
        );
        let rejected = Frame::rejected(arp_common::types::rejection_reason::OUTDATED_CLIENT);
        let _ = ws_tx
            .send(Message::Binary(rejected.serialize().into()))
            .await;
        return Err(ArpsError::ConnectionClosed);
    }

    let pubkey = perform_admission(&mut ws_tx, &mut ws_rx, &state).await?;

    let (deliver_tx, mut deliver_rx) = mpsc::channel::<Vec<u8>>(256);

    let admitted_at = Instant::now();
    let conn_handle = ConnHandle {
        tx: deliver_tx,
        pubkey,
        admitted_at,
    };

    if let Some(old_handle) = state.router.insert(pubkey, conn_handle.clone()) {
        drop(old_handle);
    }

    state.active_connections.fetch_add(1, Ordering::Relaxed);
    gauges::inc_connections_active();
    tracing::info!(
        client_ip = %client_ip,
        pubkey = %arp_common::base58::encode(&pubkey),
        "agent admitted"
    );
    let result = run_message_loop(
        &mut ws_tx,
        &mut ws_rx,
        &mut deliver_rx,
        &state,
        &conn_handle,
    )
    .await;
    state.router.remove_if(&pubkey, admitted_at);
    state.active_connections.fetch_sub(1, Ordering::Relaxed);
    gauges::dec_connections_active();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn ip_guard_decrements_on_drop() {
        use crate::config::ServerConfig;
        use crate::router::Router;

        let config = ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            max_conns: 100,
            max_conns_ip: 10,
            msg_rate: 120,
            bw_rate: 1_048_576,
            max_payload: 65535,
            admit_timeout: 5,
            ping_interval: 30,
            idle_timeout: 120,
            pow_difficulty: 0,
            trusted_proxy_cidrs: vec![],
            redirect_url: None,
            pre_auth_limit: 1000,
        };
        let state = Arc::new(ServerState {
            config,
            router: Router::new(100_000),
            server_keypair: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            ip_connections: dashmap::DashMap::new(),
            active_connections: std::sync::atomic::AtomicUsize::new(0),
            pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
        });

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.ip_connections.insert(ip, 2);

        {
            let _guard = IpGuard {
                state: state.clone(),
                ip,
            };
        } // guard drops here

        assert_eq!(*state.ip_connections.get(&ip).unwrap(), 1);
    }

    #[test]
    fn ip_guard_removes_entry_at_zero() {
        use crate::config::ServerConfig;
        use crate::router::Router;

        let config = ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            max_conns: 100,
            max_conns_ip: 10,
            msg_rate: 120,
            bw_rate: 1_048_576,
            max_payload: 65535,
            admit_timeout: 5,
            ping_interval: 30,
            idle_timeout: 120,
            pow_difficulty: 0,
            trusted_proxy_cidrs: vec![],
            redirect_url: None,
            pre_auth_limit: 1000,
        };
        let state = Arc::new(ServerState {
            config,
            router: Router::new(100_000),
            server_keypair: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            ip_connections: dashmap::DashMap::new(),
            active_connections: std::sync::atomic::AtomicUsize::new(0),
            pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
        });

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.ip_connections.insert(ip, 1);

        {
            let _guard = IpGuard {
                state: state.clone(),
                ip,
            };
        }

        assert!(state.ip_connections.get(&ip).is_none());
    }
}
