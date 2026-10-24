#![forbid(unsafe_code)]

use arpc::config::{Cli, Commands, ContactAction, load_config};
use arpc::contacts::ContactStore;
use arpc::keypair;
use arpc::local_api;
use arpc::relay::{ConnStatus, DaemonStats, InboundMsg, OutboundMsg, spawn_relay_pool};

use arp_common::base58;
use base64::Engine;
use clap::Parser;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use arp_common::style::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

fn tty() -> bool {
    std::io::stdout().is_terminal()
}

// ── Shared helpers ──────────────────────────────────────────────────

fn daemon_addr(cli: &Cli) -> String {
    let listen = cli
        .listen
        .clone()
        .or_else(|| load_config(cli.config.as_deref()).ok().map(|c| c.listen))
        .unwrap_or_else(|| "tcp://127.0.0.1:7700".to_string());
    if let Some(path) = listen.strip_prefix("unix://") {
        return path.to_string();
    }
    listen.strip_prefix("tcp://").unwrap_or(&listen).to_string()
}

/// Resolve path for arpc data files (key, contacts.toml, etc.).
/// Checks platform-native config dir first, then falls back to ~/.config/arpc/.
fn resolve_data_path(filename: &str) -> PathBuf {
    let native = dirs::config_dir().map(|d| d.join("arpc").join(filename));
    let xdg = dirs::home_dir().map(|d| d.join(".config").join("arpc").join(filename));

    if let Some(p) = native.as_ref().filter(|p| p.exists()) {
        return p.clone();
    }
    if let Some(p) = xdg.as_ref().filter(|p| p.exists()) {
        return p.clone();
    }
    native.unwrap_or_else(|| PathBuf::from(filename))
}

fn init_tracing(cli: &Cli) -> anyhow::Result<()> {
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        let directive = match cli.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };
        EnvFilter::new(directive)
    };

    if let Some(ref path) = cli.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("failed to open log file {path:?}: {e}"))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    Ok(())
}

// ── Daemon ──────────────────────────────────────────────────────────

async fn run_daemon(cli: &Cli) -> anyhow::Result<()> {
    let mut config = load_config(cli.config.as_deref())?;

    if let Some(ref relay) = cli.relay {
        config.relay = relay.clone();
    }
    if let Some(ref listen) = cli.listen {
        config.listen = listen.clone();
    }
    if let Some(ref relay_pubkey) = cli.relay_pubkey
        && config.relays.is_empty()
    {
        config.relay_pubkey = Some(relay_pubkey.clone());
    }

    if cli.relay.is_some() && !config.relays.is_empty() {
        warn!("--relay flag ignored: config file has [[relays]] entries which take precedence");
    }
    if cli.relay_pubkey.is_some() && !config.relays.is_empty() {
        warn!(
            "--relay-pubkey flag ignored: config file has [[relays]] entries which take precedence"
        );
    }

    config
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid configuration: {e}"))?;

    let key_path = resolve_data_path("key");
    let keypair = keypair::load_or_generate_keypair(&key_path)?;
    let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();

    let contacts_path = resolve_data_path("contacts.toml");
    let contacts = Arc::new(ContactStore::load(contacts_path)?);

    // Startup banner
    if std::io::stderr().is_terminal() {
        let v = env!("CARGO_PKG_VERSION");
        eprintln!();
        eprintln!("  {BOLD}◈ ARP Client{RESET} {DIM}v{v}{RESET}");
        eprintln!(
            "  {DIM}Identity{RESET}   {CYAN}{}{RESET}",
            base58::encode(&pubkey)
        );
        let relays = config.normalized_relays();
        if relays.len() == 1 {
            eprintln!("  {DIM}Relay{RESET}      {}", relays[0].url);
        } else {
            for (i, r) in relays.iter().enumerate() {
                if i == 0 {
                    eprintln!("  {DIM}Relays{RESET}     {}", r.url);
                } else {
                    eprintln!("             {}", r.url);
                }
            }
        }
        eprintln!("  {DIM}Listen{RESET}     {}", config.listen);
        if config.webhook.enabled {
            eprintln!(
                "  {DIM}Webhook{RESET}    {GREEN}●{RESET} {} (channel: {})",
                config.webhook.url, config.webhook.channel
            );
        }
        if config.bridge.enabled {
            eprintln!(
                "  {DIM}Bridge{RESET}     {GREEN}●{RESET} {}",
                config.bridge.session_key
            );
        }
        if config.webhook.enabled && config.bridge.enabled {
            eprintln!();
            eprintln!("  {YELLOW}⚠ Both webhook and bridge are enabled — inbound messages will be");
            eprintln!("    delivered twice. Consider disabling one.{RESET}");
        }
        eprintln!();
    }

    info!(
        "Starting arpc daemon with identity {}",
        base58::encode(&pubkey)
    );

    if config.webhook.enabled && config.bridge.enabled {
        warn!("both webhook and bridge are enabled — inbound messages will be delivered twice");
    }

    // Non-blocking background version check
    tokio::spawn(async {
        match arp_common::update::check_for_update_quiet("arpc", env!("CARGO_PKG_VERSION")).await {
            Ok(Some(latest)) => {
                warn!(
                    "arpc update available: {} (current: v{})",
                    latest,
                    env!("CARGO_PKG_VERSION")
                );
            }
            Ok(None) => {}
            Err(e) => {
                debug!("background version check failed: {e}");
            }
        }
    });

    let config = Arc::new(config);

    let (outbox_tx, outbox_rx) = mpsc::channel::<OutboundMsg>(256);
    let (inbox_tx, _inbox_rx) = broadcast::channel::<InboundMsg>(config.broadcast_capacity);
    let (status_tx, status_rx) = watch::channel(ConnStatus::Disconnected);
    let stats = Arc::new(DaemonStats::new());

    let pool = spawn_relay_pool(
        config.clone(),
        keypair,
        outbox_rx,
        inbox_tx.clone(),
        status_tx.clone(),
        contacts.clone(),
        stats.clone(),
    );

    let api_handle = tokio::spawn({
        let listen = config.listen.clone();
        let outbox_tx = outbox_tx.clone();
        let inbox_tx = inbox_tx.clone();
        let status_rx = status_rx.clone();
        let contacts = contacts.clone();
        let stats = stats.clone();
        let relay_statuses = pool.relay_status_receivers();
        async move {
            if let Err(e) = local_api::start_local_api(
                &listen,
                outbox_tx,
                inbox_tx,
                status_rx,
                pubkey,
                contacts,
                stats,
                relay_statuses,
            )
            .await
            {
                error!("Local API error: {}", e);
            }
        }
    });

    let bridge_handle = if config.bridge.enabled {
        let bridge_config = config.bridge.clone();
        let inbox_rx = inbox_tx.subscribe();
        let contacts = contacts.clone();
        Some(tokio::spawn(async move {
            arpc::bridge::run_bridge(bridge_config, inbox_rx, contacts).await;
            info!("Bridge exited");
        }))
    } else {
        None
    };
    tokio::select! {
        _ = pool.coordinator_handle => {
            info!("Relay coordinator exited");
        }
        _ = api_handle => {
            info!("Local API server exited");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    // Cancel bridge if still running (non-fatal — it doesn't participate in select)
    if let Some(h) = bridge_handle {
        h.abort();
    }

    Ok(())
}

// ── Daemon IPC ──────────────────────────────────────────────────────

async fn daemon_cmd(endpoint: &str, cmd: &str) -> anyhow::Result<String> {
    #[cfg(unix)]
    if endpoint.starts_with('/') || endpoint.contains(".sock") {
        return daemon_cmd_stream(tokio::net::UnixStream::connect(endpoint).await, cmd).await;
    }

    daemon_cmd_stream(TcpStream::connect(endpoint).await, cmd).await
}

async fn daemon_cmd_stream<S>(result: std::io::Result<S>, cmd: &str) -> anyhow::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    match result {
        Ok(stream) => {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = tokio::io::BufReader::new(reader);

            writer.write_all(cmd.as_bytes()).await?;
            writer.write_all(b"\n").await?;

            let mut line = String::new();
            reader.read_line(&mut line).await?;

            Ok(line)
        }
        Err(e) => {
            if tty() {
                eprintln!();
                eprintln!("  {RED}✗{RESET} Could not connect to daemon");
                eprintln!("    {DIM}{e}{RESET}");
                eprintln!();
                eprintln!("    Is arpc running? Try: {BOLD}arpc start{RESET}");
                eprintln!();
            } else {
                eprintln!("Failed to connect to daemon: {e}");
            }
            std::process::exit(1);
        }
    }
}

// ── Pretty formatters ───────────────────────────────────────────────

fn fmt_status(json: &serde_json::Value, cli: &Cli) {
    let status = json["status"].as_str().unwrap_or("unknown");

    let (dot, label) = match status {
        "connected" => (format!("{GREEN}●{RESET}"), "connected"),
        "connecting" => (format!("{YELLOW}●{RESET}"), "connecting"),
        _ => (format!("{RED}●{RESET}"), "disconnected"),
    };

    let v = env!("CARGO_PKG_VERSION");

    // Load local config + identity for context
    let config = load_config(cli.config.as_deref()).ok();
    let key_path = resolve_data_path("key");
    let identity = keypair::load_or_generate_keypair(&key_path)
        .ok()
        .map(|kp| base58::encode(&kp.verifying_key().to_bytes()));

    println!();
    println!("  {BOLD}◈ ARP Client{RESET} {DIM}v{v}{RESET}");
    println!();
    println!("  {DIM}Status{RESET}     {dot} {label}");

    if let Some(id) = identity {
        println!("  {DIM}Identity{RESET}   {CYAN}{id}{RESET}");
    }

    // Show per-relay status from daemon response (live connection status)
    if let Some(relays) = json["relays"].as_array() {
        if relays.len() == 1 {
            let r = &relays[0];
            let url = r["url"].as_str().unwrap_or("?");
            let st = r["status"].as_str().unwrap_or("unknown");
            let rdot = match st {
                "connected" => format!("{GREEN}●{RESET}"),
                "connecting" => format!("{YELLOW}●{RESET}"),
                _ => format!("{RED}●{RESET}"),
            };
            println!("  {DIM}Relay{RESET}      {rdot} {url}");
        } else {
            for (i, r) in relays.iter().enumerate() {
                let url = r["url"].as_str().unwrap_or("?");
                let st = r["status"].as_str().unwrap_or("unknown");
                let rdot = match st {
                    "connected" => format!("{GREEN}●{RESET}"),
                    "connecting" => format!("{YELLOW}●{RESET}"),
                    _ => format!("{RED}●{RESET}"),
                };
                if i == 0 {
                    println!("  {DIM}Relays{RESET}     {rdot} {url}");
                } else {
                    println!("             {rdot} {url}");
                }
            }
        }
    } else if let Some(ref cfg) = config {
        // Fallback: show relay URLs from config without live status
        let relays = cfg.normalized_relays();
        if relays.len() == 1 {
            println!("  {DIM}Relay{RESET}      {}", relays[0].url);
        } else {
            for (i, r) in relays.iter().enumerate() {
                if i == 0 {
                    println!("  {DIM}Relays{RESET}     {}", r.url);
                } else {
                    println!("             {}", r.url);
                }
            }
        }
    }

    if let Some(ref cfg) = config {
        println!("  {DIM}Listen{RESET}     {}", cfg.listen);

        if cfg.bridge.enabled {
            let sk = &cfg.bridge.session_key;
            println!("  {DIM}Bridge{RESET}     {GREEN}●{RESET} {sk}");
        }
    }

    // Uptime + message stats (only available when daemon is running)
    if let Some(uptime) = json["uptime_secs"].as_u64() {
        let (h, m, s) = (uptime / 3600, (uptime % 3600) / 60, uptime % 60);
        let uptime_str = if h > 0 {
            format!("{h}h {m}m {s}s")
        } else if m > 0 {
            format!("{m}m {s}s")
        } else {
            format!("{s}s")
        };
        println!("  {DIM}Uptime{RESET}     {uptime_str}");
    }
    let sent = json["messages_sent"].as_u64().unwrap_or(0);
    let recv = json["messages_received"].as_u64().unwrap_or(0);
    if sent > 0 || recv > 0 {
        println!("  {DIM}Messages{RESET}   {sent} sent, {recv} received");
    }

    println!();
}

fn fmt_send(json: &serde_json::Value) {
    let status = json["status"].as_str().unwrap_or("error");
    let error = json["error"].as_str();

    match (status, error) {
        ("sent", _) => println!("  {GREEN}✓{RESET} Sent"),
        (_, Some(msg)) => println!("  {RED}✗{RESET} {msg}"),
        _ => println!("  {RED}✗{RESET} Send failed"),
    }
}

fn fmt_contact_list(json: &serde_json::Value) {
    let contacts = json["contacts"].as_array();
    let filter = json["filter_mode"].as_str().unwrap_or("unknown");

    let filter_label = match filter {
        "contacts_only" => "contacts only",
        "accept_all" => "accept all",
        other => other,
    };

    println!();

    match contacts {
        Some(list) if list.is_empty() => {
            println!("  {DIM}No contacts{RESET}");
        }
        Some(list) => {
            // Compute column width from longest name (min 4 for header)
            let name_w = list
                .iter()
                .filter_map(|c| c["name"].as_str())
                .map(|n| n.len())
                .max()
                .unwrap_or(4)
                .max(4);

            // Header
            println!(
                "  {BOLD}{:<w$}{RESET}   {BOLD}PUBLIC KEY{RESET}",
                "NAME",
                w = name_w
            );

            for c in list {
                let name = c["name"].as_str().unwrap_or("");
                let pk = c["pubkey"].as_str().unwrap_or("");
                let notes = c["notes"].as_str().unwrap_or("");

                if notes.is_empty() {
                    println!("  {:<w$}   {CYAN}{pk}{RESET}", name, w = name_w);
                } else {
                    println!(
                        "  {:<w$}   {CYAN}{pk}{RESET}   {DIM}{notes}{RESET}",
                        name,
                        w = name_w
                    );
                }
            }

            println!();
            println!(
                "  {DIM}{} contacts │ filter: {filter_label}{RESET}",
                list.len()
            );
        }
        None => {
            println!("  {RED}✗{RESET} Could not read contacts");
        }
    }

    println!();
}

fn fmt_contact_add(json: &serde_json::Value) {
    if let Some(err) = json["error"].as_str() {
        println!("  {RED}✗{RESET} {err}");
    } else {
        let name = json["name"].as_str().unwrap_or("?");
        let pk = json["pubkey"].as_str().unwrap_or("?");
        println!("  {GREEN}✓{RESET} Added {BOLD}\"{name}\"{RESET} {DIM}({pk}){RESET}");
    }
}

fn fmt_contact_remove(json: &serde_json::Value) {
    if let Some(err) = json["error"].as_str() {
        println!("  {RED}✗{RESET} {err}");
    } else {
        let name = json["name"].as_str().unwrap_or("?");
        let pk = json["pubkey"].as_str().unwrap_or("?");
        println!("  {GREEN}✓{RESET} Removed {BOLD}\"{name}\"{RESET} {DIM}({pk}){RESET}");
    }
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!(
            "Failed to install rustls crypto provider - may already be installed or unsupported platform"
        );
    }

    let cli = Cli::parse();

    init_tracing(&cli)?;

    match &cli.command {
        Commands::Start => run_daemon(&cli).await?,

        Commands::Identity => {
            let key_path = resolve_data_path("key");
            let keypair = keypair::load_or_generate_keypair(&key_path)?;
            let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();
            println!("{}", base58::encode(&pubkey));
        }

        Commands::Keygen => {
            let keypair = keypair::generate_keypair();
            let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();
            println!("{}", base58::encode(&pubkey));
        }

        Commands::Status => {
            let addr = daemon_addr(&cli);
            let resp = daemon_cmd(&addr, r#"{"cmd": "status"}"#).await?;

            if tty() {
                let json: serde_json::Value = serde_json::from_str(resp.trim())?;
                fmt_status(&json, &cli);
            } else {
                print!("{resp}");
            }
        }

        Commands::Send { pubkey, message } => {
            let addr = daemon_addr(&cli);

            // Resolve: if it's a valid base58 pubkey, use as-is; otherwise lookup by contact name
            let resolved_pubkey = if base58::decode_pubkey(pubkey).is_ok() {
                pubkey.clone()
            } else {
                let lookup_cmd = serde_json::json!({
                    "cmd": "contact_lookup",
                    "name": pubkey
                });
                let lookup_resp = daemon_cmd(&addr, &serde_json::to_string(&lookup_cmd)?).await?;
                let lookup_json: serde_json::Value = serde_json::from_str(lookup_resp.trim())?;
                match lookup_json["pubkey"].as_str() {
                    Some(pk) => pk.to_string(),
                    None => {
                        if tty() {
                            println!(
                                "  {RED}\u{2717}{RESET} Unknown contact {BOLD}\"{pubkey}\"{RESET}"
                            );
                        } else {
                            let err = serde_json::json!({"status": "error", "error": format!("unknown contact or invalid pubkey: {pubkey}")});
                            print!("{}", serde_json::to_string(&err)?);
                        }
                        std::process::exit(1);
                    }
                }
            };

            let payload = base64::engine::general_purpose::STANDARD.encode(message.as_bytes());
            let cmd = serde_json::json!({
                "cmd": "send",
                "to": resolved_pubkey,
                "payload": payload
            });
            let resp = daemon_cmd(&addr, &serde_json::to_string(&cmd)?).await?;

            if tty() {
                let json: serde_json::Value = serde_json::from_str(resp.trim())?;
                fmt_send(&json);
            } else {
                print!("{resp}");
            }
        }

        Commands::Contact { action } => {
            let addr = daemon_addr(&cli);

            match action {
                ContactAction::Add {
                    name,
                    pubkey,
                    notes,
                } => {
                    // Validate contact name: 1-32 chars, alphanumeric only
                    if name.is_empty() || name.len() > 32 {
                        if tty() {
                            println!("  {RED}\u{2717}{RESET} Name must be 1\u{2013}32 characters");
                        } else {
                            let err = serde_json::json!({"error": "name must be 1-32 characters"});
                            print!("{}", serde_json::to_string(&err)?);
                        }
                        std::process::exit(1);
                    }
                    if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
                        if tty() {
                            println!(
                                "  {RED}\u{2717}{RESET} Name must contain only letters and digits"
                            );
                        } else {
                            let err = serde_json::json!({"error": "name must contain only letters and digits"});
                            print!("{}", serde_json::to_string(&err)?);
                        }
                        std::process::exit(1);
                    }
                    if base58::decode_pubkey(name).is_ok() {
                        if tty() {
                            println!("  {RED}\u{2717}{RESET} Name must not be a public key");
                        } else {
                            let err = serde_json::json!({"error": "name must not be a public key"});
                            print!("{}", serde_json::to_string(&err)?);
                        }
                        std::process::exit(1);
                    }

                    // Validate pubkey before sending to daemon
                    if let Err(e) = base58::decode_pubkey(pubkey) {
                        if tty() {
                            println!("  {RED}\u{2717}{RESET} Invalid public key: {DIM}{e}{RESET}");
                        } else {
                            let err = serde_json::json!({"error": format!("invalid pubkey: {e}")});
                            print!("{}", serde_json::to_string(&err)?);
                        }
                        std::process::exit(1);
                    }

                    let cmd = serde_json::json!({
                        "cmd": "contact_add",
                        "name": name,
                        "pubkey": pubkey,
                        "notes": notes,
                    });
                    let resp = daemon_cmd(&addr, &serde_json::to_string(&cmd)?).await?;

                    if tty() {
                        let json: serde_json::Value = serde_json::from_str(resp.trim())?;
                        fmt_contact_add(&json);
                    } else {
                        print!("{resp}");
                    }
                }

                ContactAction::Remove { name_or_pubkey } => {
                    let cmd = if base58::decode_pubkey(name_or_pubkey).is_ok() {
                        serde_json::json!({
                            "cmd": "contact_remove",
                            "pubkey": name_or_pubkey,
                        })
                    } else {
                        serde_json::json!({
                            "cmd": "contact_remove",
                            "name": name_or_pubkey,
                        })
                    };
                    let resp = daemon_cmd(&addr, &serde_json::to_string(&cmd)?).await?;

                    if tty() {
                        let json: serde_json::Value = serde_json::from_str(resp.trim())?;
                        fmt_contact_remove(&json);
                    } else {
                        print!("{resp}");
                    }
                }

                ContactAction::List => {
                    let resp = daemon_cmd(&addr, r#"{"cmd": "contact_list"}"#).await?;

                    if tty() {
                        let json: serde_json::Value = serde_json::from_str(resp.trim())?;
                        fmt_contact_list(&json);
                    } else {
                        print!("{resp}");
                    }
                }
            }
        }

        Commands::Update { check } => {
            if *check {
                arp_common::update::check_for_update("arpc", env!("CARGO_PKG_VERSION")).await?;
            } else {
                arp_common::update::perform_update("arpc", env!("CARGO_PKG_VERSION")).await?;
            }
        }

        Commands::Doctor => {
            let mut ok = true;
            let v = env!("CARGO_PKG_VERSION");

            if tty() {
                println!();
                println!("  {BOLD}\u{25c8} ARP Doctor{RESET} {DIM}v{v}{RESET}");
                println!();
            }

            // 1. Config file
            match load_config(cli.config.as_deref()) {
                Ok(cfg) => {
                    if tty() {
                        println!("  {GREEN}\u{2713}{RESET} Config loaded");
                    } else {
                        println!("config: ok");
                    }

                    // Validate config
                    match cfg.validate() {
                        Ok(()) => {
                            if tty() {
                                println!("  {GREEN}\u{2713}{RESET} Config valid");
                            } else {
                                println!("config_valid: ok");
                            }
                        }
                        Err(e) => {
                            ok = false;
                            if tty() {
                                println!("  {RED}\u{2717}{RESET} Config invalid: {DIM}{e}{RESET}");
                            } else {
                                println!("config_valid: error: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    ok = false;
                    if tty() {
                        println!("  {RED}\u{2717}{RESET} Config: {DIM}{e}{RESET}");
                    } else {
                        println!("config: error: {e}");
                    }
                }
            }

            // 2. Key file
            let key_path = resolve_data_path("key");
            if key_path.exists() {
                if tty() {
                    println!(
                        "  {GREEN}\u{2713}{RESET} Key file exists {DIM}({}){RESET}",
                        key_path.display()
                    );
                } else {
                    println!("key: ok: {}", key_path.display());
                }

                // Check permissions on unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&key_path) {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode == 0o600 {
                            if tty() {
                                println!(
                                    "  {GREEN}\u{2713}{RESET} Key permissions correct {DIM}(600){RESET}"
                                );
                            } else {
                                println!("key_perms: ok");
                            }
                        } else {
                            ok = false;
                            if tty() {
                                println!(
                                    "  {RED}\u{2717}{RESET} Key permissions: {DIM}{mode:o} (should be 600){RESET}"
                                );
                            } else {
                                println!("key_perms: warn: {mode:o}");
                            }
                        }
                    }
                }

                // Load and display identity
                match keypair::load_or_generate_keypair(&key_path) {
                    Ok(kp) => {
                        let id = base58::encode(&kp.verifying_key().to_bytes());
                        if tty() {
                            println!("  {GREEN}\u{2713}{RESET} Identity: {CYAN}{id}{RESET}");
                        } else {
                            println!("identity: {id}");
                        }
                    }
                    Err(e) => {
                        ok = false;
                        if tty() {
                            println!("  {RED}\u{2717}{RESET} Key load failed: {DIM}{e}{RESET}");
                        } else {
                            println!("key_load: error: {e}");
                        }
                    }
                }
            } else {
                ok = false;
                if tty() {
                    println!(
                        "  {RED}\u{2717}{RESET} Key file not found {DIM}({}){RESET}",
                        key_path.display()
                    );
                } else {
                    println!("key: missing: {}", key_path.display());
                }
            }

            // 3. Daemon reachable
            let addr = daemon_addr(&cli);
            let connect_result = if addr.starts_with('/') || addr.contains(".sock") {
                #[cfg(unix)]
                {
                    tokio::net::UnixStream::connect(&addr).await.map(|_| ())
                }
                #[cfg(not(unix))]
                {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "unix sockets not supported on this platform",
                    ))
                }
            } else {
                tokio::net::TcpStream::connect(addr.as_str())
                    .await
                    .map(|_| ())
            };
            match connect_result {
                Ok(()) => {
                    if tty() {
                        println!("  {GREEN}\u{2713}{RESET} Daemon reachable {DIM}({addr}){RESET}");
                    } else {
                        println!("daemon: ok: {addr}");
                    }

                    // 4. Relay connection status
                    if let Ok(resp) = daemon_cmd(&addr, r#"{"cmd": "status"}"#).await
                        && let Ok(json) = serde_json::from_str::<serde_json::Value>(resp.trim())
                    {
                        let status = json["status"].as_str().unwrap_or("unknown");
                        let (icon, color) = match status {
                            "connected" => ("\u{2713}", GREEN),
                            "connecting" => ("\u{25cf}", YELLOW),
                            _ => ("\u{2717}", RED),
                        };
                        if tty() {
                            println!("  {color}{icon}{RESET} Relay: {status}");
                        } else {
                            println!("relay: {status}");
                        }
                        if status != "connected" {
                            ok = false;
                        }
                    }
                }
                Err(_) => {
                    ok = false;
                    if tty() {
                        println!(
                            "  {RED}\u{2717}{RESET} Daemon not reachable {DIM}({addr}){RESET}"
                        );
                        println!("    {DIM}Is arpc running? Try: {BOLD}arpc start{RESET}");
                    } else {
                        println!("daemon: unreachable: {addr}");
                    }
                }
            }

            // 5. Bridge config (if enabled)
            if let Ok(cfg) = load_config(cli.config.as_deref())
                && cfg.bridge.enabled
            {
                if !cfg.bridge.gateway_token.is_empty() && !cfg.bridge.session_key.is_empty() {
                    if tty() {
                        println!(
                            "  {GREEN}\u{2713}{RESET} Bridge configured {DIM}({}){RESET}",
                            cfg.bridge.session_key
                        );
                    } else {
                        println!("bridge: configured: {}", cfg.bridge.session_key);
                    }
                } else {
                    ok = false;
                    if tty() {
                        println!(
                            "  {RED}\u{2717}{RESET} Bridge enabled but missing token or session_key"
                        );
                    } else {
                        println!("bridge: misconfigured");
                    }
                }
            }

            // 6. Update check
            match arp_common::update::check_for_update_quiet("arpc", v).await {
                Ok(None) => {
                    if tty() {
                        println!("  {GREEN}\u{2713}{RESET} Up to date {DIM}(v{v}){RESET}");
                    } else {
                        println!("version: current: v{v}");
                    }
                }
                Ok(Some(latest)) => {
                    if tty() {
                        println!(
                            "  {YELLOW}\u{25cf}{RESET} Update available: {BOLD}{latest}{RESET} {DIM}(current: v{v}){RESET}"
                        );
                    } else {
                        println!("version: outdated: v{v} -> {latest}");
                    }
                }
                Err(_) => {
                    if tty() {
                        println!("  {DIM}- Version check skipped (network){RESET}");
                    } else {
                        println!("version: check_failed");
                    }
                }
            }

            // Summary
            if tty() {
                println!();
                if ok {
                    println!("  {GREEN}All checks passed.{RESET}");
                } else {
                    println!("  {RED}Some checks failed.{RESET}");
                }
                println!();
            }

            if !ok {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
