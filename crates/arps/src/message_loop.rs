//! Message relay select loop and frame processing for admitted connections.

use crate::error::ArpsError;
use crate::metrics::{counters, histograms};
use crate::ratelimit::RateLimiter;
use crate::router::ConnHandle;
use crate::server::ServerState;
use arp_common::frame::Frame;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Bytes, Message};

pub(crate) type WsSink = SplitSink<WebSocketStream<TcpStream>, Message>;
pub(crate) type WsRecv = SplitStream<WebSocketStream<TcpStream>>;

/// Drive the main message-relay select loop for an admitted connection.
pub(crate) async fn run_message_loop(
    ws_tx: &mut WsSink,
    ws_rx: &mut WsRecv,
    deliver_rx: &mut mpsc::Receiver<Vec<u8>>,
    state: &ServerState,
    conn_handle: &ConnHandle,
) -> Result<(), ArpsError> {
    let mut rate_limiter = RateLimiter::new();
    let mut ping_interval = interval(Duration::from_secs(state.config.ping_interval));
    let idle_timeout = Duration::from_secs(state.config.idle_timeout);
    let mut last_activity = Instant::now();

    loop {
        tokio::select! {
            msg = ws_rx.next() => {
                last_activity = Instant::now();
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        let start = Instant::now();
                        match process_frame(
                            &data,
                            state,
                            ws_tx,
                            &mut rate_limiter,
                            conn_handle,
                        )
                        .await
                        {
                            Ok(()) => {
                                histograms::relay_latency_seconds(start.elapsed().as_secs_f64());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if let Err(e) = ws_tx.send(Message::Pong(data)).await {
                            tracing::debug!("failed to send pong: {}", e);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(e)) => return Err(ArpsError::WebSocket(e)),
                    _ => {
                        tracing::trace!("ignoring non-binary WebSocket message");
                    }
                }
            }
            Some(data) = deliver_rx.recv() => {
                last_activity = Instant::now();
                counters::payload_bytes_total("out", data.len() as u64);
                ws_tx.send(Message::Binary(data.into())).await.map_err(ArpsError::WebSocket)?;
            }
            _ = ping_interval.tick() => {
                if last_activity.elapsed() >= idle_timeout {
                    tracing::debug!("idle timeout reached, closing connection");
                    return Ok(());
                }
                if let Err(e) = ws_tx.send(Message::Ping(Bytes::new())).await {
                    tracing::debug!("failed to send ping: {}", e);
                }
            }
        }
    }
}

async fn process_frame<T>(
    data: &[u8],
    state: &ServerState,
    ws_tx: &mut T,
    rate_limiter: &mut RateLimiter,
    conn_handle: &ConnHandle,
) -> Result<(), ArpsError>
where
    T: futures_util::Sink<Message> + Unpin,
    T::Error: std::fmt::Debug,
{
    let frame = Frame::parse(data).map_err(ArpsError::Frame)?;

    match frame {
        Frame::Route { dest, payload } => {
            if payload.len() > state.config.max_payload {
                counters::messages_dropped_total("oversize");
                let status = Frame::status(&dest, 0x03);
                ws_tx
                    .send(Message::Binary(status.serialize().into()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
                return Ok(());
            }

            if let Some(_reason) = rate_limiter.check_and_record(
                state.config.msg_rate,
                state.config.bw_rate,
                payload.len(),
            ) {
                counters::messages_dropped_total("rate_limit");
                let status = Frame::status(&dest, 0x02);
                ws_tx
                    .send(Message::Binary(status.serialize().into()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
                return Ok(());
            }

            if let Some(dest_handle) = state.router.get(&dest) {
                let deliver_bytes = Frame::serialize_deliver(&conn_handle.pubkey, &payload);

                match dest_handle.tx.try_send(deliver_bytes) {
                    Ok(()) => {
                        counters::messages_relayed_total();
                        counters::payload_bytes_total("in", payload.len() as u64);
                        let status =
                            Frame::status(&dest, arp_common::types::status_code::DELIVERED);
                        ws_tx
                            .send(Message::Binary(status.serialize().into()))
                            .await
                            .map_err(|_| ArpsError::ConnectionClosed)?;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        counters::messages_dropped_total("rate_limit");
                        let status = Frame::status(&dest, 0x02);
                        ws_tx
                            .send(Message::Binary(status.serialize().into()))
                            .await
                            .map_err(|_| ArpsError::ConnectionClosed)?;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        counters::messages_dropped_total("offline");
                        let status = Frame::status(&dest, 0x01);
                        ws_tx
                            .send(Message::Binary(status.serialize().into()))
                            .await
                            .map_err(|_| ArpsError::ConnectionClosed)?;
                        state.router.remove_if(&dest, dest_handle.admitted_at);
                    }
                }
            } else {
                counters::messages_dropped_total("offline");
                let status = Frame::status(&dest, 0x01);
                ws_tx
                    .send(Message::Binary(status.serialize().into()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
            }
        }
        Frame::Ping { payload } => {
            let pong_frame = Frame::pong(&payload);
            ws_tx
                .send(Message::Binary(pong_frame.serialize().into()))
                .await
                .map_err(|_| ArpsError::ConnectionClosed)?;
        }
        other => {
            tracing::debug!(
                frame_type = other.frame_type(),
                "ignoring unexpected frame type post-admission"
            );
        }
    }

    Ok(())
}
