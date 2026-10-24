use crate::contacts::ContactStore;
use crate::relay::{ConnStatus, DaemonStats, InboundMsg, OutboundMsg, RelayInfo};
use arp_common::Pubkey;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{debug, info, warn};

/// Maximum command line length (1 MB). Prevents unbounded memory allocation
/// from a malicious or misbehaving local process sending an enormous line.
const MAX_CMD_LEN: usize = 1_048_576;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd")]
enum ApiCommand {
    #[serde(rename = "send")]
    Send { to: String, payload: String },
    #[serde(rename = "recv")]
    Recv { timeout_ms: Option<u64> },
    #[serde(rename = "identity")]
    Identity,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "contact_add")]
    ContactAdd {
        name: String,
        pubkey: String,
        #[serde(default)]
        notes: String,
    },
    #[serde(rename = "contact_remove")]
    ContactRemove {
        name: Option<String>,
        pubkey: Option<String>,
    },
    #[serde(rename = "contact_list")]
    ContactList,
    #[serde(rename = "contact_lookup")]
    ContactLookup {
        name: Option<String>,
        pubkey: Option<String>,
    },
    #[serde(rename = "filter_mode")]
    FilterMode { mode: Option<String> },
}

#[derive(Debug, Clone, Serialize)]
struct SendResponse {
    status: String,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RecvResponse {
    from: String,
    payload: String,
    received_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct IdentityResponse {
    identity: String,
    connected: bool,
}

#[derive(Debug, Clone, Serialize)]
struct StatusResponse {
    status: String,
    uptime_secs: u64,
    messages_sent: u64,
    messages_received: u64,
    relays: Vec<RelayInfo>,
}

/// # Errors
///
/// Returns an error if binding the local API listener fails.
#[allow(clippy::too_many_arguments)]
pub async fn start_local_api(
    listen: &str,
    outbox_tx: mpsc::Sender<OutboundMsg>,
    inbox_tx: broadcast::Sender<InboundMsg>,
    status_rx: watch::Receiver<ConnStatus>,
    pubkey: Pubkey,
    contacts: Arc<ContactStore>,
    stats: Arc<DaemonStats>,
    relay_statuses: Vec<(String, watch::Receiver<ConnStatus>)>,
) -> anyhow::Result<()> {
    if let Some(_path) = listen.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            let path = _path;
            // bind() applies process-umask defaults first; tighten to 0o600 immediately after.
            let listener = tokio::net::UnixListener::bind(path)?;

            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

            info!("Local API listening on unix socket: {}", path);

            loop {
                let (stream, _) = listener.accept().await?;
                let outbox_tx = outbox_tx.clone();
                let inbox_tx = inbox_tx.clone();
                let status_rx = status_rx.clone();
                let contacts = contacts.clone();
                let stats = stats.clone();
                let relay_statuses = relay_statuses.clone();
                let (reader, writer) = stream.into_split();

                tokio::spawn(async move {
                    if let Err(e) = handle_local_client(
                        reader,
                        writer,
                        outbox_tx,
                        inbox_tx,
                        status_rx,
                        pubkey,
                        &contacts,
                        &stats,
                        &relay_statuses,
                    )
                    .await
                    {
                        debug!("Client handler error: {}", e);
                    }
                });
            }
        }
        #[cfg(not(unix))]
        anyhow::bail!("unix:// sockets are not supported on this platform");
    } else if let Some(addr) = listen.strip_prefix("tcp://") {
        let listener = TcpListener::bind(addr).await?;
        info!("Local API listening on TCP: {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let outbox_tx = outbox_tx.clone();
            let inbox_tx = inbox_tx.clone();
            let status_rx = status_rx.clone();
            let contacts = contacts.clone();
            let stats = stats.clone();
            let relay_statuses = relay_statuses.clone();
            let (reader, writer) = stream.into_split();

            tokio::spawn(async move {
                if let Err(e) = handle_local_client(
                    reader,
                    writer,
                    outbox_tx,
                    inbox_tx,
                    status_rx,
                    pubkey,
                    &contacts,
                    &stats,
                    &relay_statuses,
                )
                .await
                {
                    debug!("Client handler error: {}", e);
                }
            });
        }
    } else {
        anyhow::bail!(
            "Invalid listen address format: {listen}. Use unix://path or tcp://addr:port"
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_local_client<R, W>(
    reader: R,
    mut writer: W,
    outbox_tx: mpsc::Sender<OutboundMsg>,
    inbox_tx: broadcast::Sender<InboundMsg>,
    status_rx: watch::Receiver<ConnStatus>,
    pubkey: Pubkey,
    contacts: &ContactStore,
    stats: &DaemonStats,
    relay_statuses: &[(String, watch::Receiver<ConnStatus>)],
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let mut limited = (&mut reader).take(MAX_CMD_LEN as u64 + 1);
        match tokio::io::AsyncBufReadExt::read_line(&mut limited, &mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }
        if line.len() > MAX_CMD_LEN {
            let error = serde_json::to_string(&serde_json::json!({
                "error": format!("command exceeds maximum length ({MAX_CMD_LEN} bytes)")
            }))? + "\n";
            writer.write_all(error.as_bytes()).await?;
            continue;
        }

        let cmd: ApiCommand = match serde_json::from_str(&line) {
            Ok(cmd) => cmd,
            Err(e) => {
                let error =
                    serde_json::to_string(&serde_json::json!({"error": e.to_string()}))? + "\n";
                writer.write_all(error.as_bytes()).await?;
                line.clear();
                continue;
            }
        };

        let response = match cmd {
            ApiCommand::Send { to, payload } => match handle_send(to, payload, &outbox_tx).await {
                Ok(json) => json,
                Err(e) => {
                    serde_json::to_string(
                        &serde_json::json!({"status": "error", "error": e.to_string()}),
                    )? + "\n"
                }
            },
            ApiCommand::Recv { timeout_ms } => {
                match handle_recv(inbox_tx.subscribe(), timeout_ms).await {
                    Ok(json) => json,
                    Err(e) => {
                        serde_json::to_string(&serde_json::json!({"error": e.to_string()}))? + "\n"
                    }
                }
            }
            ApiCommand::Identity => {
                let connected = *status_rx.borrow() == ConnStatus::Connected;
                let resp = IdentityResponse {
                    identity: arp_common::base58::encode(&pubkey),
                    connected,
                };
                serde_json::to_string(&resp)? + "\n"
            }
            ApiCommand::Status => {
                let status = match *status_rx.borrow() {
                    ConnStatus::Disconnected => "disconnected",
                    ConnStatus::Connecting => "connecting",
                    ConnStatus::Connected => "connected",
                };
                let relays: Vec<RelayInfo> = relay_statuses
                    .iter()
                    .map(|(url, rx)| {
                        let st = match *rx.borrow() {
                            ConnStatus::Disconnected => "disconnected",
                            ConnStatus::Connecting => "connecting",
                            ConnStatus::Connected => "connected",
                        };
                        RelayInfo {
                            url: url.clone(),
                            status: st.to_string(),
                        }
                    })
                    .collect();
                let resp = StatusResponse {
                    status: status.to_string(),
                    uptime_secs: stats.uptime_secs(),
                    messages_sent: stats.messages_sent.load(Ordering::Relaxed),
                    messages_received: stats.messages_received.load(Ordering::Relaxed),
                    relays,
                };
                serde_json::to_string(&resp)? + "\n"
            }
            ApiCommand::Subscribe => {
                handle_subscribe(inbox_tx.subscribe(), &mut writer).await?;
                return Ok(());
            }
            ApiCommand::ContactAdd {
                name,
                pubkey: pk,
                notes,
            } => match contacts.add(&name, &pk, &notes) {
                Ok(()) => {
                    serde_json::to_string(&serde_json::json!({
                        "status": "added", "name": name, "pubkey": pk
                    }))? + "\n"
                }
                Err(e) => serde_json::to_string(&serde_json::json!({"error": e}))? + "\n",
            },
            ApiCommand::ContactRemove { name, pubkey: pk } => {
                let result = if let Some(n) = name {
                    contacts.remove_by_name(&n)
                } else if let Some(p) = pk {
                    contacts.remove_by_pubkey(&p)
                } else {
                    Err("must provide name or pubkey".to_string())
                };
                match result {
                    Ok(c) => {
                        serde_json::to_string(&serde_json::json!({
                            "status": "removed", "name": c.name, "pubkey": c.pubkey
                        }))? + "\n"
                    }
                    Err(e) => serde_json::to_string(&serde_json::json!({"error": e}))? + "\n",
                }
            }
            ApiCommand::ContactList => {
                let list = contacts.list();
                let mode = contacts.filter_mode();
                let mode_str = match mode {
                    crate::contacts::FilterMode::ContactsOnly => "contacts_only",
                    crate::contacts::FilterMode::AcceptAll => "accept_all",
                };
                serde_json::to_string(&serde_json::json!({
                    "contacts": list, "filter_mode": mode_str
                }))? + "\n"
            }
            ApiCommand::ContactLookup { name, pubkey: pk } => {
                let contact = if let Some(n) = name {
                    contacts.lookup_by_name(&n)
                } else if let Some(p) = pk {
                    contacts.lookup_by_pubkey(&p)
                } else {
                    None
                };
                match contact {
                    Some(c) => serde_json::to_string(&c)? + "\n",
                    None => {
                        serde_json::to_string(&serde_json::json!({"error": "not found"}))? + "\n"
                    }
                }
            }
            ApiCommand::FilterMode { mode } => {
                if let Some(m) = mode {
                    match m.as_str() {
                        "contacts_only" => {
                            contacts.set_filter_mode(crate::contacts::FilterMode::ContactsOnly)
                        }
                        "accept_all" => {
                            contacts.set_filter_mode(crate::contacts::FilterMode::AcceptAll)
                        }
                        _ => {
                            let resp = serde_json::to_string(&serde_json::json!({
                                "error": format!("unknown filter mode: {m}")
                            }))? + "\n";
                            writer.write_all(resp.as_bytes()).await?;
                            line.clear();
                            continue;
                        }
                    }
                }
                let current = match contacts.filter_mode() {
                    crate::contacts::FilterMode::ContactsOnly => "contacts_only",
                    crate::contacts::FilterMode::AcceptAll => "accept_all",
                };
                serde_json::to_string(&serde_json::json!({"filter_mode": current}))? + "\n"
            }
        };

        writer.write_all(response.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

async fn handle_send(
    to: String,
    payload: String,
    outbox_tx: &mpsc::Sender<OutboundMsg>,
) -> anyhow::Result<String> {
    let dest = arp_common::base58::decode_pubkey(&to)
        .map_err(|e| anyhow::anyhow!("invalid pubkey: {e}"))?;
    let payload_bytes = BASE64
        .decode(&payload)
        .map_err(|e| anyhow::anyhow!("Invalid base64 payload: {e}"))?;
    let (ack_tx, ack_rx) = oneshot::channel();
    let msg = OutboundMsg {
        dest,
        payload: payload_bytes,
        ack_tx: Some(ack_tx),
    };
    outbox_tx
        .send(msg)
        .await
        .map_err(|_| anyhow::anyhow!("Outbox channel closed"))?;
    // Wait for relay acknowledgment with timeout
    let (status, error) = match tokio::time::timeout(Duration::from_secs(5), ack_rx).await {
        Ok(Ok(code)) => {
            use arp_common::types::status_code;
            match code {
                status_code::DELIVERED => ("sent".to_string(), None),
                status_code::OFFLINE => (
                    "error".to_string(),
                    Some("recipient is offline".to_string()),
                ),
                status_code::RATE_LIMITED => (
                    "error".to_string(),
                    Some("rate limited by relay".to_string()),
                ),
                status_code::OVERSIZE => {
                    ("error".to_string(), Some("payload too large".to_string()))
                }
                _ => (
                    "error".to_string(),
                    Some(format!("relay status: 0x{code:02x}")),
                ),
            }
        }
        Ok(Err(_)) => {
            // oneshot dropped = relay connection lost during send
            (
                "error".to_string(),
                Some("relay connection lost".to_string()),
            )
        }
        Err(_) => (
            "timeout".to_string(),
            Some("relay acknowledgment timed out".to_string()),
        ),
    };

    let resp = SendResponse { status, error };
    Ok(serde_json::to_string(&resp)? + "\n")
}

async fn handle_recv(
    mut inbox: broadcast::Receiver<InboundMsg>,
    timeout_ms: Option<u64>,
) -> anyhow::Result<String> {
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(5000));

    let msg = tokio::time::timeout(timeout, async {
        loop {
            match inbox.recv().await {
                Ok(msg) => return Ok(msg),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(dropped = n, "inbox lagged, messages dropped");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(anyhow::anyhow!("Inbox channel closed"));
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timeout waiting for message"))??;

    let resp = RecvResponse {
        from: arp_common::base58::encode(&msg.from),
        payload: BASE64.encode(&msg.payload),
        received_at: msg.received_at.to_rfc3339(),
    };

    Ok(serde_json::to_string(&resp)? + "\n")
}

async fn handle_subscribe<W>(
    mut inbox: broadcast::Receiver<InboundMsg>,
    writer: &mut W,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        match inbox.recv().await {
            Ok(msg) => {
                let resp = RecvResponse {
                    from: arp_common::base58::encode(&msg.from),
                    payload: BASE64.encode(&msg.payload),
                    received_at: msg.received_at.to_rfc3339(),
                };

                if let Ok(json) = serde_json::to_string(&resp)
                    && writer.write_all((json + "\n").as_bytes()).await.is_err()
                {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(dropped = n, "subscribe stream lagged, messages dropped");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::ContactStore;
    use crate::relay::{ConnStatus, DaemonStats, InboundMsg, OutboundMsg};
    use tokio::io::AsyncBufReadExt;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::sync::{broadcast, mpsc, watch};

    fn test_contacts() -> ContactStore {
        let path = std::env::temp_dir()
            .join("arpc_local_api_test")
            .join(format!("contacts_{}.toml", std::process::id()));
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_file(&path);
        let store = ContactStore::load(path).unwrap();
        store.set_filter_mode(crate::contacts::FilterMode::AcceptAll);
        store
    }

    fn setup_test_channels() -> (
        mpsc::Sender<OutboundMsg>,
        broadcast::Sender<InboundMsg>,
        watch::Receiver<ConnStatus>,
        Pubkey,
        Arc<DaemonStats>,
    ) {
        let (outbox_tx, mut outbox_rx) = mpsc::channel::<OutboundMsg>(256);
        let (inbox_tx, inbox_rx) = broadcast::channel::<InboundMsg>(1024);
        let (status_tx, status_rx) = watch::channel(ConnStatus::Connected);
        let pubkey = [0x42u8; 32];
        let stats = Arc::new(DaemonStats::new());

        tokio::spawn(async move {
            while let Some(msg) = outbox_rx.recv().await {
                if let Some(ack_tx) = msg.ack_tx {
                    let _ = ack_tx.send(arp_common::types::status_code::DELIVERED);
                }
            }
        });

        drop(inbox_rx);
        drop(status_tx);

        (outbox_tx, inbox_tx, status_rx, pubkey, stats)
    }

    async fn send_command_and_get_response(
        client_writer: &mut (impl AsyncWrite + Unpin),
        client_reader: &mut (impl AsyncRead + Unpin),
        command: &str,
    ) -> String {
        client_writer.write_all(command.as_bytes()).await.unwrap();
        client_writer.shutdown().await.unwrap();

        let mut response = String::new();
        let mut buf_reader = BufReader::new(client_reader);
        buf_reader.read_line(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn send_command_produces_valid_response() {
        let (outbox_tx, inbox_tx, status_rx, pubkey, stats) = setup_test_channels();
        let (mut client_reader, server_writer) = duplex(4096);
        let (mut client_writer, server_reader) = duplex(4096);

        let valid_pubkey = arp_common::base58::encode(&[0x01u8; 32]);
        let command = format!(r#"{{"cmd":"send","to":"{valid_pubkey}","payload":"aGVsbG8="}}"#);

        tokio::spawn(async move {
            handle_local_client(
                server_reader,
                server_writer,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                &test_contacts(),
                &stats,
                &[],
            )
            .await
            .unwrap();
        });

        let response = send_command_and_get_response(
            &mut client_writer,
            &mut client_reader,
            &format!("{command}\n"),
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["status"], "sent");
    }

    #[tokio::test]
    async fn identity_command_returns_pubkey() {
        let (outbox_tx, inbox_tx, status_rx, pubkey, stats) = setup_test_channels();
        let (mut client_reader, server_writer) = duplex(4096);
        let (mut client_writer, server_reader) = duplex(4096);

        tokio::spawn(async move {
            handle_local_client(
                server_reader,
                server_writer,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                &test_contacts(),
                &stats,
                &[],
            )
            .await
            .unwrap();
        });

        let response = send_command_and_get_response(
            &mut client_writer,
            &mut client_reader,
            "{\"cmd\":\"identity\"}\n",
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(json["identity"].is_string());
        assert_eq!(json["identity"], arp_common::base58::encode(&[0x42u8; 32]));
    }

    #[tokio::test]
    async fn status_command_returns_status() {
        let (outbox_tx, inbox_tx, status_rx, pubkey, stats) = setup_test_channels();
        let (mut client_reader, server_writer) = duplex(4096);
        let (mut client_writer, server_reader) = duplex(4096);

        tokio::spawn(async move {
            handle_local_client(
                server_reader,
                server_writer,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                &test_contacts(),
                &stats,
                &[],
            )
            .await
            .unwrap();
        });

        let response = send_command_and_get_response(
            &mut client_writer,
            &mut client_reader,
            "{\"cmd\":\"status\"}\n",
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(json["status"].is_string());
    }

    #[tokio::test]
    async fn invalid_json_returns_error() {
        let (outbox_tx, inbox_tx, status_rx, pubkey, stats) = setup_test_channels();
        let (mut client_reader, server_writer) = duplex(4096);
        let (mut client_writer, server_reader) = duplex(4096);

        tokio::spawn(async move {
            handle_local_client(
                server_reader,
                server_writer,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                &test_contacts(),
                &stats,
                &[],
            )
            .await
            .unwrap();
        });

        let response =
            send_command_and_get_response(&mut client_writer, &mut client_reader, "not json\n")
                .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn unknown_command_returns_error() {
        let (outbox_tx, inbox_tx, status_rx, pubkey, stats) = setup_test_channels();
        let (mut client_reader, server_writer) = duplex(4096);
        let (mut client_writer, server_reader) = duplex(4096);

        tokio::spawn(async move {
            handle_local_client(
                server_reader,
                server_writer,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                &test_contacts(),
                &stats,
                &[],
            )
            .await
            .unwrap();
        });

        let response = send_command_and_get_response(
            &mut client_writer,
            &mut client_reader,
            "{\"cmd\":\"unknown\"}\n",
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(json["error"].is_string());
    }
}
