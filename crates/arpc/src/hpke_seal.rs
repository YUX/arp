//! Stateless per-message HPKE Auth mode encryption (RFC 9180).
//!
//! Every message is independently sealed/opened — no sessions, no handshakes,
//! no state. The sender authenticates themselves via their Ed25519 keypair
//! converted to X25519 for the HPKE Auth operation mode.
//!
//! Ciphersuite: X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20Poly1305

use arp_common::Pubkey;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use thiserror::Error;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;

/// Size of the encapsulated key for X25519 (32 bytes).
const ENCAPPED_KEY_LEN: usize = 32;

/// Info string bound to this protocol version.
/// NOTE: This is intentionally separate from the wire protocol version ("arp.v2"
/// in types.rs). The HPKE info string versions the encryption scheme, which can
/// evolve independently from the wire framing version.
const INFO: &[u8] = b"arp-v1";

/// Empty AAD — all context is in the info string and key authentication.
const AAD: &[u8] = b"";

/// Wire format prefix bytes to distinguish message types.
pub mod prefix {
    /// Plaintext message (encryption disabled).
    pub const PLAINTEXT: u8 = 0x00;
    /// HPKE Auth mode encrypted message.
    pub const HPKE_AUTH: u8 = 0x04;
}

/// Errors from HPKE seal/open operations.
#[derive(Debug, Error)]
pub enum SealError {
    /// HPKE operation failed.
    #[error("hpke: {0}")]
    Hpke(#[from] hpke::HpkeError),
    /// The Ed25519 public key is not a valid curve point.
    #[error("invalid ed25519 key: {0}")]
    InvalidKey(#[from] ed25519_dalek::SignatureError),
    /// Wire payload too short or has wrong prefix.
    #[error("malformed payload: {0}")]
    Malformed(&'static str),
}

/// Convert an Ed25519 `SigningKey` into an HPKE X25519 keypair.
fn ed25519_to_hpke_keypair(
    sk: &ed25519_dalek::SigningKey,
) -> Result<(<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey), SealError> {
    let x_priv_bytes = Zeroizing::new(sk.to_scalar_bytes());
    let x_pub_bytes = sk.verifying_key().to_montgomery().to_bytes();
    let priv_key = <Kem as KemTrait>::PrivateKey::from_bytes(x_priv_bytes.as_ref())?;
    let pub_key = <Kem as KemTrait>::PublicKey::from_bytes(&x_pub_bytes)?;
    Ok((priv_key, pub_key))
}

/// Convert an Ed25519 public key (32 bytes) into an HPKE X25519 public key.
fn ed25519_pub_to_hpke(pub_bytes: &[u8; 32]) -> Result<<Kem as KemTrait>::PublicKey, SealError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pub_bytes)?;
    let x_pub = vk.to_montgomery().to_bytes();
    Ok(<Kem as KemTrait>::PublicKey::from_bytes(&x_pub)?)
}

/// Encrypt a message for `recipient` using HPKE Auth mode.
///
/// Returns wire bytes: `[HPKE_AUTH (1B) | encapped_key (32B) | ciphertext+tag]`.
///
/// Each call is fully stateless — no sessions, no counters.
///
/// # Errors
///
/// Returns [`SealError`] if key conversion or encryption fails.
pub fn seal(
    sender_sk: &ed25519_dalek::SigningKey,
    recipient_pub: &Pubkey,
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let (sender_priv, sender_pub) = ed25519_to_hpke_keypair(sender_sk)?;
    let recipient_pk = ed25519_pub_to_hpke(recipient_pub)?;

    // single_shot_seal draws encapsulation randomness from the OS via getrandom;
    // it panics only if the system RNG fails, which is unrecoverable anyway.
    let (encapped_key, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &hpke::OpModeS::Auth((sender_priv, sender_pub)),
        &recipient_pk,
        INFO,
        plaintext,
        AAD,
    )?;

    let enc_bytes = encapped_key.to_bytes();
    let mut wire = Vec::with_capacity(1 + enc_bytes.len() + ciphertext.len());
    wire.push(prefix::HPKE_AUTH);
    wire.extend_from_slice(&enc_bytes);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

/// Decrypt a message from `sender` using HPKE Auth mode.
///
/// Expects wire bytes: `[HPKE_AUTH (1B) | encapped_key (32B) | ciphertext+tag]`.
///
/// # Errors
///
/// Returns [`SealError`] if the prefix is wrong, the payload is malformed,
/// or decryption/authentication fails.
pub fn open(
    recipient_sk: &ed25519_dalek::SigningKey,
    sender_pub: &Pubkey,
    wire_data: &[u8],
) -> Result<Vec<u8>, SealError> {
    if wire_data.is_empty() {
        return Err(SealError::Malformed("empty payload"));
    }
    if wire_data[0] != prefix::HPKE_AUTH {
        return Err(SealError::Malformed("unexpected prefix byte"));
    }
    let rest = &wire_data[1..];
    if rest.len() < ENCAPPED_KEY_LEN + 16 {
        return Err(SealError::Malformed("payload too short"));
    }

    let enc_bytes = &rest[..ENCAPPED_KEY_LEN];
    let ciphertext = &rest[ENCAPPED_KEY_LEN..];

    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes)?;
    let (recipient_priv, _recipient_pub) = ed25519_to_hpke_keypair(recipient_sk)?;
    let sender_pk = ed25519_pub_to_hpke(sender_pub)?;

    let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &hpke::OpModeR::Auth(sender_pk),
        &recipient_priv,
        &encapped_key,
        INFO,
        ciphertext,
        AAD,
    )?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rng;

    fn gen_key() -> SigningKey {
        SigningKey::generate(&mut rng())
    }

    #[test]
    fn seal_open_roundtrip() {
        let alice = gen_key();
        let bob = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        let plaintext = b"hello from alice to bob";
        let wire = seal(&alice, &bob_pub, plaintext).unwrap();

        // Verify prefix
        assert_eq!(wire[0], prefix::HPKE_AUTH);

        let decrypted = open(&bob, &alice_pub, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn open_wrong_sender_fails() {
        let alice = gen_key();
        let bob = gen_key();
        let charlie = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let charlie_pub = charlie.verifying_key().to_bytes();

        let wire = seal(&alice, &bob_pub, b"secret").unwrap();

        // Bob tries to open but thinks charlie sent it
        let result = open(&bob, &charlie_pub, &wire);
        assert!(result.is_err(), "should fail with wrong sender key");
    }

    #[test]
    fn open_wrong_recipient_fails() {
        let alice = gen_key();
        let bob = gen_key();
        let charlie = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        let wire = seal(&alice, &bob_pub, b"secret").unwrap();

        // Charlie tries to open (not the intended recipient)
        let result = open(&charlie, &alice_pub, &wire);
        assert!(result.is_err(), "should fail with wrong recipient key");
    }

    #[test]
    fn open_tampered_ciphertext_fails() {
        let alice = gen_key();
        let bob = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        let mut wire = seal(&alice, &bob_pub, b"secret").unwrap();

        // Flip a byte in the ciphertext portion
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;

        let result = open(&bob, &alice_pub, &wire);
        assert!(result.is_err(), "should fail with tampered ciphertext");
    }

    #[test]
    fn multiple_messages_no_state() {
        let alice = gen_key();
        let bob = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        for i in 0..10 {
            let msg = format!("message number {i}");
            let wire = seal(&alice, &bob_pub, msg.as_bytes()).unwrap();
            let decrypted = open(&bob, &alice_pub, &wire).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
    }

    #[test]
    fn cross_pair_independent() {
        let alice = gen_key();
        let bob = gen_key();
        let charlie = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();
        let charlie_pub = charlie.verifying_key().to_bytes();

        // A → B
        let wire_ab = seal(&alice, &bob_pub, b"from alice").unwrap();
        // C → B
        let wire_cb = seal(&charlie, &bob_pub, b"from charlie").unwrap();

        let dec_ab = open(&bob, &alice_pub, &wire_ab).unwrap();
        let dec_cb = open(&bob, &charlie_pub, &wire_cb).unwrap();

        assert_eq!(dec_ab, b"from alice");
        assert_eq!(dec_cb, b"from charlie");
    }

    #[test]
    fn bidirectional_works() {
        let alice = gen_key();
        let bob = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        // Alice → Bob
        let wire1 = seal(&alice, &bob_pub, b"hello bob").unwrap();
        assert_eq!(open(&bob, &alice_pub, &wire1).unwrap(), b"hello bob");

        // Bob → Alice
        let wire2 = seal(&bob, &alice_pub, b"hello alice").unwrap();
        assert_eq!(open(&alice, &bob_pub, &wire2).unwrap(), b"hello alice");
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let alice = gen_key();
        let bob = gen_key();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_pub = alice.verifying_key().to_bytes();

        let wire = seal(&alice, &bob_pub, b"").unwrap();
        let decrypted = open(&bob, &alice_pub, &wire).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn open_empty_payload_fails() {
        let bob = gen_key();
        let alice = gen_key();
        let alice_pub = alice.verifying_key().to_bytes();

        let result = open(&bob, &alice_pub, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn open_wrong_prefix_fails() {
        let bob = gen_key();
        let alice = gen_key();
        let alice_pub = alice.verifying_key().to_bytes();

        let result = open(&bob, &alice_pub, &[0x03, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn open_truncated_payload_fails() {
        let bob = gen_key();
        let alice = gen_key();
        let alice_pub = alice.verifying_key().to_bytes();

        // prefix + only 10 bytes (need at least 32 for encapped key + 1 for ciphertext)
        let short = vec![prefix::HPKE_AUTH; 11];
        let result = open(&bob, &alice_pub, &short);
        assert!(result.is_err());
    }
}
