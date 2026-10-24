use crate::backoff::ExponentialBackoff;
use crate::config::{ClientConfig, RelayConfig, SendStrategy};
use crate::contacts::ContactStore;
use crate::dedup::Deduplicator;
use crate::webhook::WebhookClient;
use arp_common::Pubkey;
use arp_common::crypto;
use arp_common::frame::Frame;
use chrono::Utc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tracing::{debug, error, info, warn};

/// Internal error status code for seal/encrypt failures.
/// Not a protocol-level STATUS code; only used inside arpc.
const INTERNAL_ERROR: u8 = 0xFF;

// ── Public types ────────────────────────────────────────────────────

/// Runtime statistics for the daemon, shared across relay workers and local API.
pub struct DaemonStats {
    /// When the daemon started.
    pub started_at: Instant,
    /// Total messages sent (counted once per outbound message, not per relay).
    pub messages_sent: AtomicU64,
    /// Total messages received (after deduplication).
    pub messages_received: AtomicU64,
}

impl DaemonStats {
    /// Creates a new `DaemonStats` with the current time as start.
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
        }
    }

    /// Returns the number of seconds since the daemon started.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl Default for DaemonStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection status of the relay WebSocket link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnStatus {
    /// Not connected to the relay.
    Disconnected,
    /// TCP/TLS connection in progress or admission handshake pending.
    Connecting,
    /// Admitted and ready to route messages.
    Connected,
}

/// A message received from a remote peer via the relay.
#[derive(Debug, Clone)]
pub struct InboundMsg {
    /// Sender's Ed25519 public key.
    pub from: Pubkey,
    /// Decrypted (or plaintext) message payload.
    pub payload: Vec<u8>,
    /// Local timestamp when the message was received.
    pub received_at: chrono::DateTime<Utc>,
}

/// A message to send to a remote peer via the relay.
#[derive(Debug)]
pub struct OutboundMsg {
    /// Recipient's Ed25519 public key.
    pub dest: Pubkey,
    /// Raw payload bytes (will be encrypted if encryption is enabled).
    pub payload: Vec<u8>,
    /// Optional channel to receive the aggregated relay status code for this send.
    pub ack_tx: Option<oneshot::Sender<u8>>,
}

/// Per-relay status for API response.
#[derive(Debug, Clone, Serialize)]
pub struct RelayInfo {
    /// WebSocket URL of this relay.
    pub url: String,
    /// Current connection status.
    pub status: String,
}

// ── Relay Pool ──────────────────────────────────────────────────────

/// Handle to the running relay pool (coordinator + N workers).
pub struct RelayPool {
    /// Coordinator task handle.
    pub coordinator_handle: JoinHandle<()>,
    /// Per-relay worker task handles.
    pub worker_handles: Vec<JoinHandle<()>>,
    /// Per-relay connection status receivers (for per-relay status reporting).
    worker_status_rxs: Vec<watch::Receiver<ConnStatus>>,
    /// Per-relay URLs (for status reporting).
    relay_urls: Vec<String>,
}

impl RelayPool {
    /// Returns per-relay status information for the API.
    pub fn relay_infos(&self) -> Vec<RelayInfo> {
        self.relay_urls
            .iter()
            .zip(self.worker_status_rxs.iter())
            .map(|(url, rx)| {
                let status = match *rx.borrow() {
                    ConnStatus::Disconnected => "disconnected",
                    ConnStatus::Connecting => "connecting",
                    ConnStatus::Connected => "connected",
                };
                RelayInfo {
                    url: url.clone(),
                    status: status.to_string(),
                }
            })
            .collect()
    }

    /// Returns per-relay connection status receivers for passing to local API.
    pub fn relay_status_receivers(&self) -> Vec<(String, watch::Receiver<ConnStatus>)> {
        self.relay_urls
            .iter()
            .zip(self.worker_status_rxs.iter())
            .map(|(url, rx)| (url.clone(), rx.clone()))
            .collect()
    }
}

/// Spawn the relay pool: one coordinator task + N independent relay worker tasks.
///
/// The coordinator handles outbound messages (seal once, fan out, collect STATUS).
/// Each worker manages its own WebSocket connection with independent backoff.
/// Inbound messages are deduplicated across workers before delivery.
pub fn spawn_relay_pool(
    config: Arc<ClientConfig>,
    keypair: ed25519_dalek::SigningKey,
    outbox_rx: mpsc::Receiver<OutboundMsg>,
    inbox_tx: broadcast::Sender<InboundMsg>,
    status_tx: watch::Sender<ConnStatus>,
    contacts: Arc<ContactStore>,
    stats: Arc<DaemonStats>,
) -> RelayPool {
    let relays = config.normalized_relays();
    let n = relays.len();
    let dedup = Arc::new(Mutex::new(Deduplicator::default()));

    let mut relay_txs = Vec::with_capacity(n);
    let mut worker_status_rxs = Vec::with_capacity(n);
    let mut relay_urls = Vec::with_capacity(n);
    let mut worker_handles = Vec::with_capacity(n);

    // Shared STATUS report channel (workers → coordinator)
    let (status_report_tx, status_report_rx) = mpsc::channel::<StatusReport>(n.max(1) * 64);
    // Shared webhook client (single semaphore across all workers)
    let shared_webhook = WebhookClient::new(&config.webhook);

    for (i, relay_config) in relays.into_iter().enumerate() {
        let (relay_tx, relay_rx) = mpsc::channel::<RelayCommand>(64);
        let (worker_status_tx, worker_status_rx) = watch::channel(ConnStatus::Disconnected);

        relay_txs.push(relay_tx);
        worker_status_rxs.push(worker_status_rx);
        relay_urls.push(relay_config.url.clone());

        let handle = tokio::spawn(relay_worker(
            i,
            relay_config,
            keypair.clone(),
            config.reconnect.clone(),
            config.keepalive.clone(),
            config.encryption.enabled,
            relay_rx,
            status_report_tx.clone(),
            worker_status_tx,
            inbox_tx.clone(),
            dedup.clone(),
            contacts.clone(),
            stats.clone(),
            shared_webhook.clone(),
        ));

        worker_handles.push(handle);
    }

    // Drop coordinator's clone so rx closes when all workers drop theirs
    drop(status_report_tx);

    let coordinator_handle = tokio::spawn(relay_coordinator(
        outbox_rx,
        relay_txs,
        status_report_rx,
        worker_status_rxs.clone(),
        status_tx,
        keypair,
        config.send_strategy.clone(),
        config.encryption.enabled,
        stats,
    ));

    RelayPool {
        coordinator_handle,
        worker_handles,
        worker_status_rxs,
        relay_urls,
    }
}

// ── Internal types ──────────────────────────────────────────────────

#[derive(Debug)]
enum RelayError {
    Fatal(anyhow::Error),
    Transient(anyhow::Error),
}

/// Command from coordinator to a relay worker.
#[derive(Debug)]
enum RelayCommand {
    /// Send a pre-built ROUTE frame to this relay.
    Send {
        /// Monotonic ID for correlating STATUS responses.
        send_id: u64,
        /// Destination pubkey (for STATUS matching in worker).
        dest: Pubkey,
        /// Serialized ROUTE frame bytes.
        data: Vec<u8>,
    },
}

/// STATUS report from a relay worker back to the coordinator.
#[derive(Debug)]
struct StatusReport {
    /// Which send operation this STATUS corresponds to.
    send_id: u64,
    /// Which relay worker sent this report (for sequential mode correlation and debugging).
    #[allow(dead_code)]
    relay_idx: usize,
    /// Relay status code (DELIVERED, OFFLINE, RATE_LIMITED, OVERSIZE).
    code: u8,
}

/// Pending ack being collected by the coordinator across relays.
struct PendingAck {
    /// Channel to send the final aggregated status to the caller.
    ack_tx: oneshot::Sender<u8>,
    /// Best status code received so far (highest precedence wins).
    best_code: Option<u8>,
    /// Number of relays that haven't responded yet (fan-out mode).
    remaining: usize,
    /// Absolute deadline for STATUS collection.
    deadline: Instant,
    /// Sequential mode state (None for fan-out).
    sequential: Option<SequentialState>,
}

/// State for sequential send strategy.
struct SequentialState {
    /// Pre-built ROUTE frame bytes for retrying on next relay.
    route_data: Vec<u8>,
    /// Destination pubkey.
    dest: Pubkey,
    /// Index of next relay to try.
    next_relay_idx: usize,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Helper: deliver an inbound message to subscribers and webhook.
fn deliver_inbound(
    inbox_tx: &broadcast::Sender<InboundMsg>,
    webhook: Option<&WebhookClient>,
    contacts: &ContactStore,
    stats: &DaemonStats,
    from: Pubkey,
    payload: Vec<u8>,
) {
    if !contacts.should_deliver(&from) {
        return;
    }
    stats.messages_received.fetch_add(1, Ordering::Relaxed);
    if let Some(wh) = webhook {
        wh.fire(&from, &payload);
    }
    if inbox_tx
        .send(InboundMsg {
            from,
            payload,
            received_at: Utc::now(),
        })
        .is_err()
    {
        debug!("inbound message dropped: no active subscribers");
    }
}

/// STATUS precedence: higher is better. DELIVERED wins everything.
fn status_precedence(code: u8) -> u8 {
    use arp_common::types::status_code;
    match code {
        status_code::DELIVERED => 4,
        status_code::RATE_LIMITED => 3,
        status_code::OVERSIZE => 2,
        status_code::OFFLINE | status_code::REJECTED_BY_DEST => 1,
        _ => 0,
    }
}

/// Aggregate connection status from multiple relay workers.
/// Connected if ANY relay connected. Connecting if any connecting.
/// Disconnected only if ALL disconnected.
fn aggregate_conn_status(statuses: &[ConnStatus]) -> ConnStatus {
    if statuses.contains(&ConnStatus::Connected) {
        ConnStatus::Connected
    } else if statuses.contains(&ConnStatus::Connecting) {
        ConnStatus::Connecting
    } else {
        ConnStatus::Disconnected
    }
}

/// Seal the outbound payload (encrypt if enabled, pass through otherwise).
#[allow(unused_variables)]
fn seal_payload(
    keypair: &ed25519_dalek::SigningKey,
    dest: &Pubkey,
    payload: &[u8],
    encryption_enabled: bool,
) -> Result<Vec<u8>, anyhow::Error> {
    #[cfg(feature = "encryption")]
    if encryption_enabled {
        return crate::hpke_seal::seal(keypair, dest, payload)
            .map_err(|e| anyhow::anyhow!("hpke seal failed: {e}"));
    }
    #[cfg(not(feature = "encryption"))]
    if encryption_enabled {
        return Err(anyhow::anyhow!(
            "encryption.enabled = true but arpc was built without the 'encryption' feature"
        ));
    }
    Ok(payload.to_vec())
}

// ── Coordinator ─────────────────────────────────────────────────────

/// Coordinator task: receives outbound messages, seals once, fans out to
/// relay workers, collects STATUS responses with timeout, and aggregates
/// worker connection statuses into the global status channel.
#[allow(clippy::too_many_arguments)]
async fn relay_coordinator(
    mut outbox_rx: mpsc::Receiver<OutboundMsg>,
    relay_txs: Vec<mpsc::Sender<RelayCommand>>,
    mut status_report_rx: mpsc::Receiver<StatusReport>,
    worker_status_rxs: Vec<watch::Receiver<ConnStatus>>,
    global_status_tx: watch::Sender<ConnStatus>,
    keypair: ed25519_dalek::SigningKey,
    send_strategy: SendStrategy,
    encryption_enabled: bool,
    stats: Arc<DaemonStats>,
) {
    let mut next_send_id: u64 = 0;
    let mut pending_acks: HashMap<u64, PendingAck> = HashMap::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            // ── Outbound message from local API ──
            msg = outbox_rx.recv() => {
                let Some(msg) = msg else { break };
                let send_id = next_send_id;
                next_send_id = next_send_id.wrapping_add(1);

                // 1. Seal ONCE (HPKE uses fresh ephemeral key per seal)
                let wire_payload = match seal_payload(
                    &keypair, &msg.dest, &msg.payload, encryption_enabled,
                ) {
                    Ok(wp) => wp,
                    Err(e) => {
                        error!(error = %e, "seal failed, dropping outbound message");
                        if let Some(ack_tx) = msg.ack_tx {
                            let _ = ack_tx.send(INTERNAL_ERROR);
                        }
                        continue;
                    }
                };

                // 2. Build ROUTE frame bytes (reused across relays)
                let route_bytes = Frame::route(&msg.dest, &wire_payload).serialize();

                // 3. Send strategy
                match &send_strategy {
                    SendStrategy::FanOut => {
                        // Non-blocking fan-out: try_send to all relays
                        let mut sent_count = 0;
                        for (idx, tx) in relay_txs.iter().enumerate() {
                            // Skip disconnected workers to avoid phantom buffering
                            if *worker_status_rxs[idx].borrow() == ConnStatus::Disconnected {
                                continue;
                            }
                            if tx.try_send(RelayCommand::Send {
                                send_id,
                                dest: msg.dest,
                                data: route_bytes.clone(),
                            }).is_ok() {
                                sent_count += 1;
                            } else {
                                warn!(worker = idx, "relay worker channel full, dropping message for this relay");
                            }
                        }
                        if sent_count > 0 {
                            stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }

                        if let Some(ack_tx) = msg.ack_tx {
                            if sent_count > 0 {
                                pending_acks.insert(send_id, PendingAck {
                                    ack_tx,
                                    best_code: None,
                                    remaining: sent_count,
                                    deadline: Instant::now() + Duration::from_secs(4),
                                    sequential: None,
                                });
                            } else {
                                // No relay accepted the message
                                let _ = ack_tx.send(arp_common::types::status_code::OFFLINE);
                            }
                        }
                    }
                    SendStrategy::Sequential => {
                        // Try first available relay; on non-DELIVERED status,
                        // the report handler tries the next relay.
                        let mut sent = false;
                        let mut first_relay_idx = 0;
                        for (idx, tx) in relay_txs.iter().enumerate() {
                            // Skip disconnected workers
                            if *worker_status_rxs[idx].borrow() == ConnStatus::Disconnected {
                                continue;
                            }
                            if tx.try_send(RelayCommand::Send {
                                send_id,
                                dest: msg.dest,
                                data: route_bytes.clone(),
                            }).is_ok() {
                                first_relay_idx = idx + 1;
                                sent = true;
                                break;
                            } else {
                                warn!(worker = idx, "relay worker channel full, dropping message for this relay");
                            }
                        }
                        stats.messages_sent.fetch_add(1, Ordering::Relaxed);

                        if let Some(ack_tx) = msg.ack_tx {
                            if sent {
                                pending_acks.insert(send_id, PendingAck {
                                    ack_tx,
                                    best_code: None,
                                    remaining: 0, // not used for sequential
                                    deadline: Instant::now() + Duration::from_secs(4),
                                    sequential: Some(SequentialState {
                                        route_data: route_bytes,
                                        dest: msg.dest,
                                        next_relay_idx: first_relay_idx,
                                    }),
                                });
                            } else {
                                let _ = ack_tx.send(arp_common::types::status_code::OFFLINE);
                            }
                        }
                    }
                }
            }

            // ── STATUS report from relay worker ──
            report = status_report_rx.recv() => {
                let Some(report) = report else { break };

                let should_resolve = {
                    let Some(pending) = pending_acks.get_mut(&report.send_id) else {
                        continue; // stale or unknown send_id
                    };

                    // Update best status (higher precedence wins)
                    let is_better = pending
                        .best_code
                        .is_none_or(|old| status_precedence(report.code) > status_precedence(old));
                    if is_better {
                        pending.best_code = Some(report.code);
                    }

                    if report.code == arp_common::types::status_code::DELIVERED {
                        // DELIVERED = best possible, resolve immediately
                        true
                    } else if let Some(ref mut seq) = pending.sequential {
                        // Sequential: try next relay
                        let mut sent_next = false;
                        while seq.next_relay_idx < relay_txs.len() {
                            let idx = seq.next_relay_idx;
                            seq.next_relay_idx += 1;
                            // Skip disconnected workers
                            if *worker_status_rxs[idx].borrow() == ConnStatus::Disconnected {
                                continue;
                            }
                            if relay_txs[idx].try_send(RelayCommand::Send {
                                send_id: report.send_id,
                                dest: seq.dest,
                                data: seq.route_data.clone(),
                            }).is_ok() {
                                sent_next = true;
                                break;
                            } else {
                                warn!(worker = idx, "relay worker channel full, dropping message for this relay");
                            }
                        }
                        // Resolve if no more relays to try
                        !sent_next
                    } else {
                        // Fan-out: decrement remaining
                        pending.remaining = pending.remaining.saturating_sub(1);
                        pending.remaining == 0
                    }
                };

                if should_resolve
                    && let Some(ack) = pending_acks.remove(&report.send_id) {
                        let code = ack.best_code
                            .unwrap_or(arp_common::types::status_code::OFFLINE);
                        let _ = ack.ack_tx.send(code);
                    }
            }

            // ── Periodic cleanup + status aggregation ──
            _ = cleanup_interval.tick() => {
                // Expire timed-out pending acks
                let now = Instant::now();
                let expired: Vec<u64> = pending_acks.iter()
                    .filter(|(_, ack)| now >= ack.deadline)
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    if let Some(ack) = pending_acks.remove(&id) {
                        let code = ack.best_code
                            .unwrap_or(arp_common::types::status_code::OFFLINE);
                        let _ = ack.ack_tx.send(code);
                    }
                }

                // Aggregate worker connection statuses
                let statuses: Vec<ConnStatus> = worker_status_rxs.iter()
                    .map(|rx| rx.borrow().clone())
                    .collect();
                global_status_tx.send_replace(aggregate_conn_status(&statuses));
            }
        }
    }
}

// ── Relay Worker ────────────────────────────────────────────────────

/// Per-relay worker task: manages a single WebSocket connection with
/// independent reconnection backoff, keepalive, and dedup.
#[allow(clippy::too_many_arguments)]
async fn relay_worker(
    worker_id: usize,
    relay_config: RelayConfig,
    keypair: ed25519_dalek::SigningKey,
    reconnect_config: crate::config::ReconnectConfig,
    keepalive_config: crate::config::KeepaliveConfig,
    encryption_enabled: bool,
    mut relay_rx: mpsc::Receiver<RelayCommand>,
    status_report_tx: mpsc::Sender<StatusReport>,
    worker_status_tx: watch::Sender<ConnStatus>,
    inbox_tx: broadcast::Sender<InboundMsg>,
    dedup: Arc<Mutex<Deduplicator>>,
    contacts: Arc<ContactStore>,
    stats: Arc<DaemonStats>,
    webhook: Option<WebhookClient>,
) {
    let mut backoff = ExponentialBackoff::new(
        Duration::from_millis(reconnect_config.initial_delay_ms),
        Duration::from_millis(reconnect_config.max_delay_ms),
        reconnect_config.backoff_factor,
    );

    loop {
        worker_status_tx.send_replace(ConnStatus::Connecting);

        match relay_worker_connection(
            worker_id,
            &relay_config,
            &keypair,
            &keepalive_config,
            encryption_enabled,
            &mut relay_rx,
            &status_report_tx,
            &worker_status_tx,
            &inbox_tx,
            &dedup,
            &contacts,
            &stats,
            webhook.as_ref(),
        )
        .await
        {
            Ok(()) => {
                info!(worker = worker_id, relay = %relay_config.url, "relay connection closed cleanly");
                worker_status_tx.send_replace(ConnStatus::Disconnected);
                break;
            }
            Err(RelayError::Fatal(e)) => {
                error!(worker = worker_id, relay = %relay_config.url, error = %e, "fatal relay error, not retrying");
                worker_status_tx.send_replace(ConnStatus::Disconnected);
                break;
            }
            Err(RelayError::Transient(e)) => {
                let was_connected = *worker_status_tx.borrow() == ConnStatus::Connected;
                warn!(worker = worker_id, relay = %relay_config.url, error = %e, "relay connection lost");
                worker_status_tx.send_replace(ConnStatus::Disconnected);
                if was_connected {
                    // Was fully admitted — reset backoff so the first reconnect
                    // attempt is fast (the relay likely just bounced).
                    backoff.reset();
                } else {
                    // Never reached Connected state (DNS failure, handshake
                    // timeout, TLS error, etc.).  Cap the backoff at a moderate
                    // ceiling so the client doesn't sleep 30 s when the relay
                    // comes back up — but still back off enough to avoid
                    // hammering a down relay.
                    let cap = Duration::from_secs(5);
                    if backoff.peek() > cap {
                        backoff.reset();
                    }
                }
                // Drain stale commands buffered while disconnected — report OFFLINE
                // to prevent phantom store-and-forward on reconnect
                while let Ok(cmd) = relay_rx.try_recv() {
                    match cmd {
                        RelayCommand::Send { send_id, .. } => {
                            if status_report_tx
                                .try_send(StatusReport {
                                    send_id,
                                    relay_idx: worker_id,
                                    code: arp_common::types::status_code::OFFLINE,
                                })
                                .is_err()
                            {
                                debug!(
                                    worker = worker_id,
                                    send_id, "status report channel full during drain"
                                );
                            }
                        }
                    }
                }
            }
        }

        let delay = backoff.next_delay();
        info!(
            worker = worker_id,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "reconnecting"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Build a TLS connector that forces HTTP/1.1 ALPN.
/// Without this, rustls advertises h2 which causes Cloudflare (and other
/// HTTP/2-capable reverse proxies) to negotiate HTTP/2 — breaking the
/// HTTP/1.1 WebSocket upgrade handshake.
fn build_ws_connector() -> Result<tokio_tungstenite::Connector, RelayError> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("failed to load native certs") {
        root_store.add(cert).ok();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Explicitly request HTTP/1.1 only — WebSocket upgrade requires HTTP/1.1.
    // Without this, servers behind HTTP/2-capable proxies (Cloudflare, etc.)
    // may negotiate h2 and reject the HTTP/1.1 Upgrade handshake.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
}

/// Single connection attempt for a relay worker. Connects, completes the
/// admission handshake, then enters the message loop: receives DELIVER (with
/// dedup), forwards STATUS to coordinator, sends pre-built ROUTE commands.
#[allow(clippy::too_many_arguments, unused_variables)]
async fn relay_worker_connection(
    worker_id: usize,
    relay_config: &RelayConfig,
    keypair: &ed25519_dalek::SigningKey,
    keepalive_config: &crate::config::KeepaliveConfig,
    encryption_enabled: bool,
    relay_rx: &mut mpsc::Receiver<RelayCommand>,
    status_report_tx: &mpsc::Sender<StatusReport>,
    worker_status_tx: &watch::Sender<ConnStatus>,
    inbox_tx: &broadcast::Sender<InboundMsg>,
    dedup: &Arc<Mutex<Deduplicator>>,
    contacts: &ContactStore,
    stats: &DaemonStats,
    webhook: Option<&WebhookClient>,
) -> Result<(), RelayError> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = relay_config
        .url
        .as_str()
        .into_client_request()
        .map_err(|e| RelayError::Transient(e.into()))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
            arp_common::types::PROTOCOL_VERSION,
        ),
    );
    let connector = build_ws_connector()?;
    let (ws, _) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| RelayError::Transient(e.into()))?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let relay_pubkey = relay_config
        .pubkey
        .as_ref()
        .and_then(|pk_str| arp_common::base58::decode_pubkey(pk_str).ok());
    perform_relay_handshake(&mut ws_tx, &mut ws_rx, keypair, relay_pubkey.as_ref()).await?;

    worker_status_tx.send_replace(ConnStatus::Connected);
    info!(worker = worker_id, relay = %relay_config.url, "admitted to relay");

    // STATUS frames are correlated to ROUTE sends by destination pubkey using FIFO ordering.
    // This is safe because: (1) WebSocket guarantees in-order delivery per connection,
    // (2) the relay server processes ROUTE frames sequentially per connection,
    // so STATUS responses arrive in the same order as ROUTE frames were sent.
    let mut pending_sends: HashMap<Pubkey, VecDeque<u64>> = HashMap::new();
    let mut ping_interval = tokio::time::interval(Duration::from_secs(keepalive_config.interval_s));

    loop {
        tokio::select! {
            // ── Inbound from relay WebSocket ──
            msg = ws_rx.next() => {
                let msg = msg
                    .ok_or_else(|| RelayError::Transient(anyhow::anyhow!("connection closed")))
                    .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
                match msg {
                    Message::Binary(data) => {
                        let frame = match Frame::parse(&data) {
                            Ok(f) => f,
                            Err(e) => {
                                debug!(error = %e, "ignoring unparseable frame");
                                continue;
                            }
                        };
                        match frame {
                            Frame::Deliver { src, payload } => {
                                // 1. Check dedup BEFORE decryption (fast path)
                                let dedup_key = Deduplicator::key(&src, &payload);
                                {
                                    let guard = dedup.lock().unwrap_or_else(|e| e.into_inner());
                                    if guard.is_duplicate(&dedup_key) {
                                        debug!(worker = worker_id, "dropping duplicate message");
                                        continue;
                                    }
                                }

                                // 2. Decrypt if encryption enabled
                                #[cfg(feature = "encryption")]
                                if encryption_enabled {
                                    // Check contact filter BEFORE expensive HPKE decrypt (CPU DoS mitigation)
                                    if !contacts.should_deliver(&src) {
                                        debug!(
                                            worker = worker_id,
                                            from = %arp_common::base58::encode(&src),
                                            "dropping message from non-contact (pre-decrypt)"
                                        );
                                        continue;
                                    }
                                    match crate::hpke_seal::open(keypair, &src, &payload) {
                                        Ok(decrypted) => {
                                            // 3. Atomic check-and-insert AFTER successful decrypt
                                            // (prevents race where two workers both pass pre-decrypt check)
                                            {
                                                let mut guard = dedup.lock().unwrap_or_else(|e| e.into_inner());
                                                if guard.is_duplicate(&dedup_key) {
                                                    debug!(worker = worker_id, "dropping duplicate (post-decrypt race)");
                                                    continue;
                                                }
                                                guard.mark_seen(dedup_key);
                                            }
                                            deliver_inbound(inbox_tx, webhook, contacts, stats, src, decrypted);
                                        }
                                        Err(e) => {
                                            // AUDIT CRIT-01: Never accept plaintext fallback when encryption
                                            // is enabled. Do NOT mark as seen — failed decrypt doesn't prove
                                            // this is the "real" message.
                                            warn!(error = %e, from = %arp_common::base58::encode(&src), "hpke: dropping undecryptable message");
                                        }
                                    }
                                    continue;
                                }

                                #[cfg(not(feature = "encryption"))]
                                if encryption_enabled {
                                    warn!(
                                        worker = worker_id,
                                        "dropping message: encryption enabled but feature not compiled"
                                    );
                                    continue;
                                }

                                // Non-encrypted: atomic check-and-insert (prevents race)
                                let should_deliver = contacts.should_deliver(&src);
                                {
                                    let mut guard = dedup.lock().unwrap_or_else(|e| e.into_inner());
                                    if guard.is_duplicate(&dedup_key) {
                                        debug!(worker = worker_id, "dropping duplicate (post-check race)");
                                        continue;
                                    }
                                    if should_deliver {
                                        guard.mark_seen(dedup_key);
                                    }
                                }
                                if should_deliver {
                                    deliver_inbound(inbox_tx, webhook, contacts, stats, src, payload);
                                }
                            }
                            Frame::Status { ref_pubkey, code } => {
                                debug!(
                                    worker = worker_id,
                                    pubkey = %arp_common::base58::encode(&ref_pubkey),
                                    code = code,
                                    "status frame received"
                                );
                                // Match STATUS to the oldest pending send for this pubkey (FIFO).
                                if let Some(queue) = pending_sends.get_mut(&ref_pubkey) {
                                    if let Some(send_id) = queue.pop_front()
                                        && status_report_tx
                                            .try_send(StatusReport {
                                                send_id,
                                                relay_idx: worker_id,
                                                code,
                                            })
                                            .is_err()
                                        {
                                            warn!(worker = worker_id, send_id, "status report channel full, coordinator may timeout");
                                        }
                                    if queue.is_empty() {
                                        pending_sends.remove(&ref_pubkey);
                                    }
                                }
                            }
                            Frame::Pong { .. } => {
                                debug!("pong received");
                            }
                            _ => {
                                debug!(frame_type = frame.frame_type(), "unexpected frame type");
                            }
                        }
                    }
                    Message::Ping(data) => {
                        tokio::time::timeout(Duration::from_secs(10), ws_tx.send(Message::Pong(data)))
                            .await
                            .map_err(|_| RelayError::Transient(anyhow::anyhow!("WebSocket write timed out")))?
                            .map_err(|e| RelayError::Transient(e.into()))?;
                    }
                    Message::Close(_) => {
                        return Err(RelayError::Transient(anyhow::anyhow!("relay sent WebSocket close frame")));
                    }
                    _ => { tracing::trace!("ignoring non-binary WebSocket message"); }
                }
            }

            // ── Outbound command from coordinator ──
            cmd = relay_rx.recv() => {
                let Some(cmd) = cmd else { break }; // coordinator dropped
                match cmd {
                    RelayCommand::Send { send_id, dest, data } => {
                        // Check in-flight depth BEFORE sending.
                        {
                            let queue = pending_sends.entry(dest).or_default();
                            if queue.len() >= 16 {
                                warn!(
                                    worker = worker_id,
                                    dest = %arp_common::base58::encode(&dest),
                                    "too many in-flight sends for destination, synthesizing OFFLINE"
                                );
                                if status_report_tx
                                    .try_send(StatusReport {
                                        send_id,
                                        relay_idx: worker_id,
                                        code: arp_common::types::status_code::OFFLINE,
                                    })
                                    .is_err()
                                {
                                    debug!(
                                        worker = worker_id,
                                        send_id,
                                        "status report channel full during backpressure"
                                    );
                                }
                                continue;
                            }
                        }

                        tokio::time::timeout(
                            Duration::from_secs(10),
                            ws_tx.send(Message::Binary(data.into())),
                        )
                        .await
                        .map_err(|_| RelayError::Transient(anyhow::anyhow!("WebSocket write timed out")))?
                        .map_err(|e| RelayError::Transient(e.into()))?;

                        // Track pending STATUS for this send
                        let queue = pending_sends.entry(dest).or_default();
                        queue.push_back(send_id);

                        if pending_sends.len() > 256 {
                            warn!(count = pending_sends.len(), "pending_sends high watermark, cleaning empty queues");
                            pending_sends.retain(|_, q| !q.is_empty());
                        }
                    }
                }
            }

            // ── Keepalive ping ──
            _ = ping_interval.tick() => {
                tokio::time::timeout(Duration::from_secs(10), ws_tx.send(Message::Ping(Bytes::new())))
                    .await
                    .map_err(|_| RelayError::Transient(anyhow::anyhow!("WebSocket write timed out")))?
                    .map_err(|e| RelayError::Transient(e.into()))?;
            }
        }
    }

    Ok(())
}

// ── Handshake ───────────────────────────────────────────────────────

async fn perform_relay_handshake<S>(
    ws_tx: &mut SplitSink<WebSocketStream<S>, Message>,
    ws_rx: &mut SplitStream<WebSocketStream<S>>,
    keypair: &ed25519_dalek::SigningKey,
    expected_relay_pubkey: Option<&Pubkey>,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge_frame = tokio::time::timeout(Duration::from_secs(10), ws_rx.next())
        .await
        .map_err(|_| RelayError::Transient(anyhow::anyhow!("handshake read timed out")))?
        .ok_or_else(|| RelayError::Transient(anyhow::anyhow!("connection closed before challenge")))
        .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
    let Message::Binary(challenge_data) = challenge_frame else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected binary challenge frame"
        )));
    };

    let frame = Frame::parse(&challenge_data)
        .map_err(|e| RelayError::Transient(anyhow::anyhow!("challenge parse error: {e}")))?;
    let Frame::Challenge {
        challenge,
        difficulty,
        server_pubkey,
    } = frame
    else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected challenge frame"
        )));
    };

    // AUDIT SPEC-01: Verify relay server identity if pinned
    if let Some(expected) = expected_relay_pubkey {
        if server_pubkey != *expected {
            return Err(RelayError::Fatal(anyhow::anyhow!(
                "relay server pubkey mismatch: expected {}, got {}",
                arp_common::base58::encode(expected),
                arp_common::base58::encode(&server_pubkey)
            )));
        }
        info!(
            pubkey = %arp_common::base58::encode(&server_pubkey),
            "relay server identity verified"
        );
    }
    let timestamp = crypto::unix_now()
        .map_err(|e| RelayError::Fatal(anyhow::anyhow!("system clock error: {e}")))?;
    let signature = crypto::sign_admission(keypair, &challenge, timestamp);
    let pubkey: Pubkey = keypair.verifying_key().to_bytes();
    let response = if difficulty > 0 {
        tracing::debug!(difficulty, "solving proof-of-work");
        let nonce = crypto::pow_solve(&challenge, &pubkey, timestamp, difficulty)
            .map_err(|e| RelayError::Fatal(anyhow::anyhow!("PoW solver failed: {e}")))?;
        Frame::response_with_pow(&pubkey, timestamp, &signature, nonce)
    } else {
        Frame::response(&pubkey, timestamp, &signature)
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        ws_tx.send(Message::Binary(response.serialize().into())),
    )
    .await
    .map_err(|_| RelayError::Transient(anyhow::anyhow!("handshake write timed out")))?
    .map_err(|e| RelayError::Transient(e.into()))?;

    let admit_frame = tokio::time::timeout(Duration::from_secs(10), ws_rx.next())
        .await
        .map_err(|_| RelayError::Transient(anyhow::anyhow!("handshake read timed out")))?
        .ok_or_else(|| {
            RelayError::Transient(anyhow::anyhow!(
                "connection closed before admission response"
            ))
        })
        .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
    let Message::Binary(admit_data) = admit_frame else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected binary admission frame"
        )));
    };

    let admit = Frame::parse(&admit_data)
        .map_err(|e| RelayError::Transient(anyhow::anyhow!("admission parse error: {e}")))?;
    match admit {
        Frame::Admitted => Ok(()),
        Frame::Rejected { reason } => {
            if reason == arp_common::types::rejection_reason::OUTDATED_CLIENT {
                error!("arpc is outdated and incompatible with the relay server");
                eprintln!();
                eprintln!("arpc is outdated. Run 'arpc update' to update.");
                eprintln!();
            }
            Err(RelayError::Fatal(anyhow::anyhow!(
                "admission rejected with reason: 0x{reason:02x}"
            )))
        }
        _ => Err(RelayError::Fatal(anyhow::anyhow!(
            "unexpected frame during admission"
        ))),
    }
}
