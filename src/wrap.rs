//! HPKE key wrapping (RFC 9180, Base mode, X-Wing KEM).
//!
//! Two wrapping paths (crypto doc §2):
//! - GK → member's E2E public key (`wrap_gk` / `unwrap_gk`)
//! - MDK → GK-derived X-Wing keypair (`wrap_mdk` / `unwrap_mdk`)
//!
//! All blobs are base64(`enc || ct`) — a single opaque string per wrapped key.

use base64::Engine;
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::XWing, Deserializable, Kem, OpModeR, OpModeS,
    Serializable,
};

use crate::error::{Error, Result};
use crate::keys::gk_xwing_keypair;

fn b64_encode(parts: &[&[u8]]) -> String {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Crypto(format!("invalid base64: {e}")))
}

/// `info` for GK wrapping: binds the wrap to the group + key version.
fn gk_info(group_uuid: &str, key_version: i32) -> Vec<u8> {
    format!("e2e-group-gk-v{key_version}\0{group_uuid}").into_bytes()
}

/// AAD for GK wrapping: `groupUuid || keyVersion`.
fn gk_aad(group_uuid: &str, key_version: i32) -> Vec<u8> {
    format!("{group_uuid}\0{key_version}").into_bytes()
}

/// `info` for MDK wrapping.
fn mdk_info(group_uuid: &str) -> Vec<u8> {
    format!("e2e-group-mdk\0{group_uuid}").into_bytes()
}

/// AAD for MDK wrapping: `messageId || groupUuid || keyVersion`.
fn mdk_aad(message_id: &str, group_uuid: &str, key_version: i32) -> Vec<u8> {
    format!("{message_id}\0{group_uuid}\0{key_version}").into_bytes()
}

/// Wrap the Group Key to a member's E2E public key (crypto doc §2.1).
pub fn wrap_gk(gk: &[u8; 32], recipient_pub_b64: &str, group_uuid: &str, key_version: i32) -> Result<String> {
    let pk = <XWing as Kem>::PublicKey::from_bytes(&b64_decode(recipient_pub_b64)?)
        .map_err(|e| Error::Crypto(format!("bad recipient pubkey: {e}")))?;
    let info = gk_info(group_uuid, key_version);
    let aad = gk_aad(group_uuid, key_version);

    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, XWing>(
        &OpModeS::Base, &pk, &info,
    )
    .map_err(|e| Error::Crypto(format!("hpke setup_sender: {e}")))?;
    let ct = ctx
        .seal(gk, &aad)
        .map_err(|e| Error::Crypto(format!("hpke seal: {e}")))?;

    Ok(b64_encode(&[&enc.to_bytes(), &ct]))
}

/// Unwrap the Group Key with the member's E2E private key (crypto doc §2.1).
pub fn unwrap_gk(wrapped_b64: &str, recipient_priv_b64: &str, group_uuid: &str, key_version: i32) -> Result<[u8; 32]> {
    let blob = b64_decode(wrapped_b64)?;
    // X-Wing encapped key is 1120 bytes; the rest is AES-GCM ciphertext+tag.
    if blob.len() <= 1120 {
        return Err(Error::Crypto("wrapped GK blob too short".into()));
    }
    let (enc_bytes, ct) = blob.split_at(1120);
    let enc = <XWing as Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| Error::Crypto(format!("bad encapped key: {e}")))?;
    let sk = <XWing as Kem>::PrivateKey::from_bytes(&b64_decode(recipient_priv_b64)?)
        .map_err(|e| Error::Crypto(format!("bad private key: {e}")))?;

    let info = gk_info(group_uuid, key_version);
    let aad = gk_aad(group_uuid, key_version);
    let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base, &sk, &enc, &info,
    )
    .map_err(|e| Error::Crypto(format!("hpke setup_receiver: {e}")))?;
    let pt = ctx
        .open(ct, &aad)
        .map_err(|_| Error::Crypto("GK unwrap failed (wrong key or tampered AAD)".into()))?;

    pt.try_into()
        .map_err(|_| Error::Crypto("unwrapped GK has wrong length".into()))
}

/// Wrap a Message Data Key to the GK-derived X-Wing keypair (crypto doc §2.2).
pub fn wrap_mdk(
    mdk: &[u8; 32],
    gk: &[u8; 32],
    message_id: &str,
    group_uuid: &str,
    key_version: i32,
) -> Result<String> {
    let (_gk_priv, gk_pub) = gk_xwing_keypair(gk);
    let pk = <XWing as Kem>::PublicKey::from_bytes(&gk_pub)
        .map_err(|e| Error::Crypto(format!("derived gk pubkey invalid: {e}")))?;
    let info = mdk_info(group_uuid);
    let aad = mdk_aad(message_id, group_uuid, key_version);

    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, XWing>(
        &OpModeS::Base, &pk, &info,
    )
    .map_err(|e| Error::Crypto(format!("hpke setup_sender: {e}")))?;
    let ct = ctx
        .seal(mdk, &aad)
        .map_err(|e| Error::Crypto(format!("hpke seal: {e}")))?;

    Ok(b64_encode(&[&enc.to_bytes(), &ct]))
}

/// Unwrap a Message Data Key with the GK-derived private key (crypto doc §2.2).
pub fn unwrap_mdk(
    wrapped_b64: &str,
    gk: &[u8; 32],
    message_id: &str,
    group_uuid: &str,
    key_version: i32,
) -> Result<[u8; 32]> {
    let (gk_priv, _gk_pub) = gk_xwing_keypair(gk);
    let blob = b64_decode(wrapped_b64)?;
    if blob.len() <= 1120 {
        return Err(Error::Crypto("wrapped MDK blob too short".into()));
    }
    let (enc_bytes, ct) = blob.split_at(1120);
    let enc = <XWing as Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| Error::Crypto(format!("bad encapped key: {e}")))?;
    let sk = <XWing as Kem>::PrivateKey::from_bytes(&gk_priv)
        .map_err(|e| Error::Crypto(format!("derived gk privkey invalid: {e}")))?;

    let info = mdk_info(group_uuid);
    let aad = mdk_aad(message_id, group_uuid, key_version);
    let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base, &sk, &enc, &info,
    )
    .map_err(|e| Error::Crypto(format!("hpke setup_receiver: {e}")))?;
    let pt = ctx
        .open(ct, &aad)
        .map_err(|_| Error::Crypto("MDK unwrap failed (wrong key or tampered AAD)".into()))?;

    pt.try_into()
        .map_err(|_| Error::Crypto("unwrapped MDK has wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::UserE2EKey;

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn gk_wrap_unwrap_round_trip() {
        let alice = UserE2EKey::generate();
        let gk = [7u8; 32];
        let wrapped = wrap_gk(&gk, &b64(&alice.public), "group-1", 1).unwrap();
        let unwrapped = unwrap_gk(&wrapped, &b64(&alice.private), "group-1", 1).unwrap();
        assert_eq!(unwrapped, gk);
    }

    #[test]
    fn gk_unwrap_wrong_key_fails() {
        let alice = UserE2EKey::generate();
        let mallory = UserE2EKey::generate();
        let gk = [7u8; 32];
        let wrapped = wrap_gk(&gk, &b64(&alice.public), "group-1", 1).unwrap();
        assert!(unwrap_gk(&wrapped, &b64(&mallory.private), "group-1", 1).is_err());
    }

    #[test]
    fn gk_unwrap_tampered_aad_fails() {
        let alice = UserE2EKey::generate();
        let gk = [7u8; 32];
        let wrapped = wrap_gk(&gk, &b64(&alice.public), "group-1", 1).unwrap();
        // Different key version in AAD → must fail.
        assert!(unwrap_gk(&wrapped, &b64(&alice.private), "group-1", 2).is_err());
        // Different group uuid in AAD → must fail.
        assert!(unwrap_gk(&wrapped, &b64(&alice.private), "group-2", 1).is_err());
    }

    #[test]
    fn mdk_wrap_unwrap_round_trip() {
        let gk = [9u8; 32];
        let mdk = [11u8; 32];
        let wrapped = wrap_mdk(&mdk, &gk, "msg-1", "group-1", 1).unwrap();
        let unwrapped = unwrap_mdk(&wrapped, &gk, "msg-1", "group-1", 1).unwrap();
        assert_eq!(unwrapped, mdk);
    }

    #[test]
    fn mdk_unwrap_tampered_message_id_fails() {
        let gk = [9u8; 32];
        let mdk = [11u8; 32];
        let wrapped = wrap_mdk(&mdk, &gk, "msg-1", "group-1", 1).unwrap();
        assert!(unwrap_mdk(&wrapped, &gk, "msg-OTHER", "group-1", 1).is_err());
    }

    #[test]
    fn mdk_wrap_fails_without_gk_access() {
        // A non-member without the GK cannot derive the keypair → cannot wrap.
        // (Structural guarantee: wrap_mdk requires the GK itself.)
        let gk = [9u8; 32];
        let mdk = [11u8; 32];
        let wrapped = wrap_mdk(&mdk, &gk, "msg-1", "group-1", 1).unwrap();
        let wrong_gk = [10u8; 32];
        assert!(unwrap_mdk(&wrapped, &wrong_gk, "msg-1", "group-1", 1).is_err());
    }
}
