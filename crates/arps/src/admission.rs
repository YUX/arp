use crate::error::ArpsError;
use arp_common::Pubkey;
use arp_common::crypto;
use arp_common::frame::Frame;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tungstenite::Message;

const TIMESTAMP_TOLERANCE: u64 = 30;

pub async fn admit<T>(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocketStream<T>>,
    challenge: &[u8; 32],
    difficulty: u8,
) -> Result<Pubkey, ArpsError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let msg = ws_rx
        .next()
        .await
        .ok_or(ArpsError::ConnectionClosed)?
        .map_err(ArpsError::WebSocket)?;

    let Message::Binary(data) = msg else {
        return Err(ArpsError::InvalidAdmission);
    };

    let frame = Frame::parse(&data).map_err(ArpsError::Frame)?;

    match frame {
        Frame::Response {
            pubkey,
            timestamp,
            signature,
            pow_nonce,
        } => {
            let now = crypto::unix_now().map_err(|_| ArpsError::ClockError)?;

            if now.abs_diff(timestamp) > TIMESTAMP_TOLERANCE {
                return Err(ArpsError::TimestampExpired);
            }

            let verifying_key = VerifyingKey::from_bytes(&pubkey)?;

            let valid = crypto::verify_admission(&verifying_key, challenge, timestamp, &signature);

            if !valid {
                return Err(ArpsError::InvalidAdmission);
            }

            // Verify proof-of-work when difficulty > 0
            if difficulty > 0 {
                let nonce = pow_nonce.ok_or(ArpsError::InvalidPoW)?;
                if !crypto::pow_verify(challenge, &pubkey, timestamp, &nonce, difficulty) {
                    return Err(ArpsError::InvalidPoW);
                }
            }
            Ok(pubkey)
        }
        _ => Err(ArpsError::InvalidAdmission),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_within_tolerance_is_valid() {
        let now = crypto::unix_now().unwrap();
        assert!(now.abs_diff(now) <= TIMESTAMP_TOLERANCE);
        assert!(now.abs_diff(now + 29) <= TIMESTAMP_TOLERANCE);
        assert!(now.abs_diff(now - 29) <= TIMESTAMP_TOLERANCE);
    }

    #[test]
    fn timestamp_outside_tolerance_is_invalid() {
        let now = crypto::unix_now().unwrap();
        assert!(now.abs_diff(now + 31) > TIMESTAMP_TOLERANCE);
        assert!(now.abs_diff(now.saturating_sub(31)) > TIMESTAMP_TOLERANCE);
    }

    #[test]
    fn timestamp_at_boundary_is_valid() {
        let now = crypto::unix_now().unwrap();
        assert!(now.abs_diff(now + 30) <= TIMESTAMP_TOLERANCE);
        assert!(now.abs_diff(now - 30) <= TIMESTAMP_TOLERANCE);
    }

    #[test]
    fn timestamp_zero_is_rejected() {
        let now = crypto::unix_now().unwrap();
        assert!(now.abs_diff(0) > TIMESTAMP_TOLERANCE);
    }

    #[test]
    fn timestamp_far_future_is_rejected() {
        let now = crypto::unix_now().unwrap();
        assert!(now.abs_diff(u64::MAX) > TIMESTAMP_TOLERANCE);
    }
}
