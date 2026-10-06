//! X-Wing (ML-KEM-768 + X25519) hybrid keypair management.
//!
//! Each user holds a long-lived E2E keypair. The public key is uploaded to the
//! server (plaintext — it's public); the private key is stored encrypted with
//! the user's Bitwarden user symmetric key.

use hpke::{kem::XWing, Deserializable, Kem, Serializable};
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

/// A user's E2E X-Wing hybrid keypair. Keys are opaque byte blobs — never
/// hardcode sizes, so a future KEM change doesn't ripple through callers.
#[derive(Clone, ZeroizeOnDrop)]
pub struct UserE2EKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl std::fmt::Debug for UserE2EKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log key material.
        f.debug_struct("UserE2EKey")
            .field("public_len", &self.public.len())
            .field("private_len", &self.private.len())
            .finish()
    }
}

impl UserE2EKey {
    /// Generate a fresh X-Wing hybrid keypair.
    pub fn generate() -> Self {
        let (sk, pk) = XWing::gen_keypair();
        Self {
            public: pk.to_bytes().to_vec(),
            private: sk.to_bytes().to_vec(),
        }
    }

    /// Reconstruct from raw byte blobs (e.g. after decrypting the stored
    /// private key).
    pub fn from_bytes(public: Vec<u8>, private: Vec<u8>) -> Result<Self> {
        // Validate both halves parse before accepting them.
        <XWing as Kem>::PublicKey::from_bytes(&public)
            .map_err(|e| Error::Crypto(format!("invalid public key: {e}")))?;
        <XWing as Kem>::PrivateKey::from_bytes(&private)
            .map_err(|e| Error::Crypto(format!("invalid private key: {e}")))?;
        Ok(Self { public, private })
    }

    /// Base64-encoded public key (for upload / display).
    pub fn public_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.public)
    }
}

/// The deterministic X-Wing keypair derived from a Group Key (crypto doc §2.2).
/// Every member holding the GK derives the identical keypair, which acts as the
/// HPKE recipient for per-message MDKs. Uses hpke's native RFC 9180-style
/// `derive_keypair` (verified in the hpke 0.14.1 spike).
/// Returns `(private, public)` as raw bytes.
pub fn gk_xwing_keypair(gk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = XWing::derive_keypair(gk);
    (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_keypair() {
        let k = UserE2EKey::generate();
        assert_eq!(k.public.len(), 1216); // X-Wing encapsulation key size
        assert_eq!(k.private.len(), 32); // X-Wing decapsulation key (seed form)
        assert!(UserE2EKey::from_bytes(k.public.clone(), k.private.clone()).is_ok());
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(UserE2EKey::from_bytes(vec![0u8; 10], vec![0u8; 10]).is_err());
    }

    #[test]
    fn gk_keypair_is_deterministic() {
        let gk = [42u8; 32];
        let (sk1, pk1) = gk_xwing_keypair(&gk);
        let (sk2, pk2) = gk_xwing_keypair(&gk);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1.len(), 1216);
        assert_eq!(sk1.len(), 32);
    }

    #[test]
    fn different_gk_yields_different_keypair() {
        let (_, pk1) = gk_xwing_keypair(&[1u8; 32]);
        let (_, pk2) = gk_xwing_keypair(&[2u8; 32]);
        assert_ne!(pk1, pk2);
    }
}
