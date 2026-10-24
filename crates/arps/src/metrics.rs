use axum::{Router, http::StatusCode, response::Json, routing::get};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Readiness check response.
#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    ready: bool,
}

/// Shared readiness state.
#[derive(Clone, Default)]
pub struct HealthState {
    ready: Arc<AtomicBool>,
}

impl HealthState {
    /// Create a new health state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Mark the service as ready.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    /// Check if the service is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}

/// # Errors
///
/// Returns an error if binding the metrics HTTP server fails.
pub async fn start_metrics_server(
    addr: SocketAddr,
    health_state: HealthState,
) -> anyhow::Result<()> {
    let handle = PrometheusBuilder::new().install_recorder()?;

    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let h = handle.clone();
                async move { h.render() }
            }),
        )
        .route("/health", get(health_handler))
        .route("/ready", get(move || ready_handler(health_state.clone())));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("metrics server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Health check handler - returns 200 if server is running.
async fn health_handler() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { status: "healthy" }))
}

/// Readiness check handler - returns 200 if ready, 503 if not.
async fn ready_handler(state: HealthState) -> (StatusCode, Json<ReadyResponse>) {
    if state.is_ready() {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                ready: true,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not ready",
                ready: false,
            }),
        )
    }
}

/// Connection count gauges.
pub mod gauges {
    /// Increment the active connections gauge.
    pub fn inc_connections_active() {
        metrics::gauge!("arp_connections_active").increment(1.0);
    }

    /// Decrement the active connections gauge.
    pub fn dec_connections_active() {
        metrics::gauge!("arp_connections_active").decrement(1.0);
    }
}

/// Event counters.
pub mod counters {
    /// Record an admission attempt with the given status label.
    pub fn admissions_total(status: &'static str) {
        metrics::counter!("arp_admissions_total", "status" => status).increment(1);
    }

    /// Increment the relayed-messages counter.
    pub fn messages_relayed_total() {
        metrics::counter!("arp_messages_relayed_total").increment(1);
    }

    /// Increment the dropped-messages counter with the given reason label.
    pub fn messages_dropped_total(reason: &'static str) {
        metrics::counter!("arp_messages_dropped_total", "reason" => reason).increment(1);
    }

    /// Record bytes relayed in the given direction.
    pub fn payload_bytes_total(direction: &'static str, bytes: u64) {
        metrics::counter!("arp_payload_bytes_total", "direction" => direction).increment(bytes);
    }
}

/// Latency histograms.
pub mod histograms {
    /// Record a relay latency observation in seconds.
    pub fn relay_latency_seconds(value: f64) {
        metrics::histogram!("arp_relay_latency_seconds").record(value);
    }
}
