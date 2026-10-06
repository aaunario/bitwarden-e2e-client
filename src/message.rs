//! Message content encryption (AES-256-GCM) — crypto doc §3.
//!
//! Each message gets a fresh 32-byte MDK. The stored format in
//! `secure_group_messages.data` is `{ "v": 1, "nonce": <b64>, "ct": <b64> }`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};

use crate::error::{Error, Result};

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Crypto(format!("invalid base64: {e}")))
}

/// AAD binding the ciphertext to its context: `messageId || groupUuid || keyVersion`.
fn content_aad(message_id: &str, group_uuid: &str, key_version: i32) -> Vec<u8> {
    format!("{message_id}\0{group_uuid}\0{key_version}").into_bytes()
}

/// Encrypt a message body with the MDK. Returns the JSON envelope stored as
/// `secure_group_messages.data`.
pub fn encrypt_message(
    mdk: &[u8; 32],
    plaintext: &[u8],
    message_id: &str,
    group_uuid: &str,
    key_version: i32,
) -> Result<Value> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = aes_gcm::Aes256Gcm::new_from_slice(mdk)
        .map_err(|e| Error::Crypto(format!("aes key init: {e}")))?;
    let ct = cipher
        .encrypt(
            &nonce_bytes.into(),
            Payload {
                msg: plaintext,
                aad: &content_aad(message_id, group_uuid, key_version),
            },
        )
        .map_err(|_| Error::Crypto("message encryption failed".into()))?;

    Ok(json!({
        "v": 1,
        "nonce": b64_encode(&nonce_bytes),
        "ct": b64_encode(&ct),
    }))
}

/// Decrypt a message body. `data` is the JSON envelope from the server.
pub fn decrypt_message(
    mdk: &[u8; 32],
    data: &Value,
    message_id: &str,
    group_uuid: &str,
    key_version: i32,
) -> Result<Vec<u8>> {
    let v = data
        .get("v")
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::Crypto("missing envelope version".into()))?;
    if v != 1 {
        return Err(Error::Crypto(format!("unsupported envelope version {v}")));
    }
    let nonce_b64 = data
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Crypto("missing nonce".into()))?;
    let ct_b64 = data
        .get("ct")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Crypto("missing ciphertext".into()))?;

    let nonce_bytes: [u8; 12] = b64_decode(nonce_b64)?
        .try_into()
        .map_err(|_| Error::Crypto("nonce must be 12 bytes".into()))?;
    let ct = b64_decode(ct_b64)?;

    let cipher = aes_gcm::Aes256Gcm::new_from_slice(mdk)
        .map_err(|e| Error::Crypto(format!("aes key init: {e}")))?;
    cipher
        .decrypt(
            &nonce_bytes.into(),
            Payload {
                msg: &ct,
                aad: &content_aad(message_id, group_uuid, key_version),
            },
        )
        .map_err(|_| Error::Crypto("message decryption failed (wrong key or tampered data)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let mdk = [3u8; 32];
        let pt = b"the launch code is 1234";
        let env = encrypt_message(&mdk, pt, "msg-1", "group-1", 1).unwrap();
        assert_eq!(env["v"], 1);
        let dec = decrypt_message(&mdk, &env, "msg-1", "group-1", 1).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mdk = [3u8; 32];
        let mut env = encrypt_message(&mdk, b"secret", "msg-1", "group-1", 1).unwrap();
        // Flip a byte in the ciphertext.
        let mut ct = b64_decode(env["ct"].as_str().unwrap()).unwrap();
        ct[0] ^= 0xFF;
        env["ct"] = Value::String(b64_encode(&ct));
        assert!(decrypt_message(&mdk, &env, "msg-1", "group-1", 1).is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let mdk = [3u8; 32];
        let env = encrypt_message(&mdk, b"secret", "msg-1", "group-1", 1).unwrap();
        assert!(decrypt_message(&mdk, &env, "msg-OTHER", "group-1", 1).is_err());
        assert!(decrypt_message(&mdk, &env, "msg-1", "group-2", 1).is_err());
        assert!(decrypt_message(&mdk, &env, "msg-1", "group-1", 2).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let env = encrypt_message(&[3u8; 32], b"secret", "msg-1", "group-1", 1).unwrap();
        assert!(decrypt_message(&[4u8; 32], &env, "msg-1", "group-1", 1).is_err());
    }

    #[test]
    fn unique_nonces_per_message() {
        let mdk = [3u8; 32];
        let e1 = encrypt_message(&mdk, b"a", "msg-1", "g", 1).unwrap();
        let e2 = encrypt_message(&mdk, b"a", "msg-2", "g", 1).unwrap();
        assert_ne!(e1["nonce"], e2["nonce"]);
    }
}
