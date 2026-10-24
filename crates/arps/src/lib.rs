//! ARP relay server — stateless WebSocket message router.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod admission;
/// CLI argument parsing and server configuration.
pub mod config;
mod connection;
/// Error types for relay server operations.
pub mod error;
mod message_loop;
/// Prometheus metrics collection and HTTP endpoint.
pub mod metrics;
mod ratelimit;
/// Pubkey-based routing table for connected agents.
pub mod router;
/// Accept loop and shared server state.
pub mod server;

pub use server::{ServerState, run, run_with_shutdown};
