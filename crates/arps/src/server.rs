use crate::config::ServerConfig;
use crate::connection::handle_connection;
use crate::error::ArpsError;
use crate::router::Router;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

/// Shared state for the relay server.
pub struct ServerState {
    /// Message router for dispatching frames between connected agents.
    pub router: Router,
    /// Ed25519 signing key used for server-side authentication.
    pub server_keypair: ed25519_dalek::SigningKey,
    /// Runtime server configuration.
    pub config: ServerConfig,
    /// Per-IP connection counter for enforcing connection limits.
    pub ip_connections: DashMap<IpAddr, usize>,
    /// Atomic counter for active admitted connections (TOCTOU-safe).
    pub active_connections: AtomicUsize,
    /// Semaphore to limit unauthenticated (pre-admission) connections.
    pub pre_auth_semaphore: Semaphore,
}

/// # Errors
///
/// Returns an error if the accept loop encounters an I/O failure.
pub async fn run(listener: TcpListener, state: Arc<ServerState>) -> Result<(), ArpsError> {
    let (shutdown_tx, _) = tokio::sync::watch::channel(());
    run_with_shutdown(listener, state, shutdown_tx).await
}

/// Run the server accept loop with an externally-controlled shutdown signal.
///
/// When the `shutdown_tx` sender is dropped, the accept loop stops accepting
/// new connections and waits for in-flight connections to finish.
///
/// # Errors
///
/// Returns an error if the accept loop encounters an I/O failure.
pub async fn run_with_shutdown(
    listener: TcpListener,
    state: Arc<ServerState>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
) -> Result<(), ArpsError> {
    let local_addr = listener.local_addr().map_err(ArpsError::Io)?;
    info!("server listening on {}", local_addr);
    let mut shutdown_rx = shutdown_tx.subscribe();
    let task_tracker = Arc::new(tokio::sync::Notify::new());
    let mut active_tasks: usize = 0;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        if state.active_connections.load(Ordering::Relaxed) >= state.config.max_conns {
                            warn!("max connections reached, rejecting {}", addr);
                            drop(stream);
                            continue;
                        }
                let state = Arc::clone(&state);
                        let tracker = task_tracker.clone();
                        active_tasks += 1;
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, addr, state).await {
                                tracing::debug!("connection from {} closed: {}", addr, e);
                            }
                            tracker.notify_one();
                        });
                    }
                    Err(e) => {
                        error!("failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("shutdown signal received, draining {} connections", active_tasks);
                break;
            }
        }
    }

    // Wait for in-flight connections to finish (with timeout)
    let drain_timeout = std::time::Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + drain_timeout;
    while active_tasks > 0 {
        if tokio::time::timeout_at(deadline, task_tracker.notified())
            .await
            .is_err()
        {
            warn!(
                "drain timeout reached with {} connections still active",
                active_tasks
            );
            break;
        }
        active_tasks = active_tasks.saturating_sub(1);
    }

    info!("server shut down gracefully");
    Ok(())
}
