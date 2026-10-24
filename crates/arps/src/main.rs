#![forbid(unsafe_code)]

use anyhow::Result;
use arp_common::base58;
use arps::config::{Args, ServerConfig};
use arps::metrics::{HealthState, start_metrics_server};
use arps::router::Router;
use arps::server::ServerState;
use arps::server::run_with_shutdown;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rng;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use arp_common::style::{BOLD, CYAN, DIM, GREEN, RESET};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Handle update commands before server startup
    if args.check_update {
        arp_common::update::check_for_update("arps", env!("CARGO_PKG_VERSION")).await?;
        return Ok(());
    }
    if args.update {
        arp_common::update::perform_update("arps", env!("CARGO_PKG_VERSION")).await?;
        return Ok(());
    }

    let config: ServerConfig = args.clone().into();

    // Validate configuration before starting
    if let Err(e) = config.validate() {
        anyhow::bail!("configuration error: {}", e);
    }

    let server_keypair = if let Some(ref path) = args.keypair {
        load_keypair(path)?
    } else {
        generate_keypair()
    };

    let pubkey = server_keypair.verifying_key().to_bytes();

    // Startup banner
    if std::io::stderr().is_terminal() {
        let v = env!("CARGO_PKG_VERSION");
        let bw = if config.bw_rate >= 1_048_576 {
            format!("{} MB/min", config.bw_rate / 1_048_576)
        } else {
            format!("{} KB/min", config.bw_rate / 1024)
        };
        eprintln!();
        eprintln!("  {BOLD}◈ ARP Relay{RESET} {DIM}v{v}{RESET}");
        eprintln!(
            "  {DIM}Identity{RESET}   {CYAN}{}{RESET}",
            base58::encode(&pubkey)
        );
        eprintln!("  {DIM}Listen{RESET}     {}", config.listen);
        eprintln!("  {DIM}Metrics{RESET}    {}", config.metrics_addr);
        eprintln!(
            "  {DIM}PoW{RESET}        difficulty {}",
            config.pow_difficulty
        );
        eprintln!(
            "  {DIM}Limits{RESET}     {}/IP │ {} msg/min │ {bw}",
            config.max_conns_ip, config.msg_rate
        );
        eprintln!();
    }

    info!("server public key: {}", base58::encode(&pubkey));

    let router = Router::new(config.max_conns);
    let state = Arc::new(ServerState {
        router,
        server_keypair,
        config: config.clone(),
        ip_connections: dashmap::DashMap::new(),
        active_connections: AtomicUsize::new(0),
        pre_auth_semaphore: Semaphore::new(config.pre_auth_limit),
    });

    let listener = TcpListener::bind(config.listen).await?;
    if std::io::stderr().is_terminal() {
        eprintln!(
            "  {GREEN}●{RESET} Listening on {BOLD}{}{RESET}",
            config.listen
        );
        eprintln!();
    }
    info!("bound to {}", config.listen);

    let health_state = HealthState::new();

    tokio::spawn({
        let health_state = health_state.clone();
        async move {
            if let Err(e) = start_metrics_server(config.metrics_addr, health_state).await {
                warn!("metrics server error: {}", e);
            }
        }
    });

    let (shutdown_tx, _) = tokio::sync::watch::channel(());

    // Spawn a task that sends shutdown on ctrl_c
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("received shutdown signal");
        drop(shutdown_tx_clone);
    });

    if let Err(e) = run_with_shutdown(listener, state, shutdown_tx).await {
        tracing::error!("server error: {}", e);
    }

    Ok(())
}

fn load_keypair(path: &Path) -> Result<SigningKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "keypair file permissions too open: {:o}. Expected 0600",
                mode
            );
        }
    }

    let data = std::fs::read(path)?;
    if data.len() < 32 {
        anyhow::bail!("keypair file too short, expected at least 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    info!("loaded keypair from {}", path.display());
    Ok(signing_key)
}

fn generate_keypair() -> SigningKey {
    let signing_key = SigningKey::generate(&mut rng());
    warn!("using ephemeral keypair (not persisted)");
    signing_key
}
