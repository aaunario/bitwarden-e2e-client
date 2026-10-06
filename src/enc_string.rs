//! Bitwarden "enc-string" codec: `<type>.<iv_b64>|<ct_b64>|<mac_b64>`.
//!
//! This is *interop* code — it decodes/encrypts Bitwarden's existing key
//! material format (used by the CLI's throwaway auth module to unlock the user
//! symmetric key). It implements no new cryptographic scheme.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Crypto(format!("invalid base64 in enc-string: {e}")))
}

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// The encryption type byte of an enc-string. Variant names mirror
/// Bitwarden's spec (hence the non-camel-case names).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncType {
    AesCbc256_HmacSha256_B64 = 0,
    AesCbc128_HmacSha256_B64 = 1,
    AesCbc256_HmacSha256_B64_Keys = 2,
    AesCbc256_HmacSha256_B64_Keys2 = 3,
    AesCbc256_HmacSha256_B64_Keys3 = 4,
    Rsa2048_OaepSha256_B64 = 5,
    Rsa2048_OaepSha1_B64 = 6,
    Rsa2048_OaepSha256_HmacSha256_B64 = 7,
    AesCbc256_B64 = 8,
    AesCbc128_HmacSha256_B64_Keys = 9,
    Aes256Cbc_HmacSha256_B64 = 10,
}

/// A parsed Bitwarden enc-string.
#[derive(Debug, Clone)]
pub struct EncString {
    pub enc_type: u8,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl EncString {
    /// Parse `<type>.<iv>|<ct>|<mac>` (types 0/2) or `<type>.<iv>|<ct>` (type 8).
    pub fn parse(s: &str) -> Result<Self> {
        let (type_part, rest) = s
            .split_once('.')
            .ok_or_else(|| Error::Crypto("enc-string missing type prefix".into()))?;
        let enc_type: u8 = type_part
            .parse()
            .map_err(|_| Error::Crypto(format!("unknown enc-string type {type_part}")))?;

        let parts: Vec<&str> = rest.split('|').collect();
        match (enc_type, parts.len()) {
            // AES-CBC + HMAC: iv|ct|mac
            (0 | 2, 3) => Ok(Self {
                enc_type,
                iv: b64_decode(parts[0])?,
                ct: b64_decode(parts[1])?,
                mac: Some(b64_decode(parts[2])?),
            }),
            // AES-CBC without MAC: iv|ct
            (8, 2) => Ok(Self {
                enc_type,
                iv: b64_decode(parts[0])?,
                ct: b64_decode(parts[1])?,
                mac: None,
            }),
            _ => Err(Error::Crypto(format!(
                "enc-string type {enc_type} with {} parts not supported",
                parts.len()
            ))),
        }
    }

    /// Encrypt with AES-256-CBC + HMAC-SHA256 (enc type 0) — the format used
    /// for the user symmetric key and our `e2e_private_key` at rest.
    ///
    /// `key` is 64 bytes: [enc_key(32) || mac_key(32)].
    pub fn encrypt_aes256_hmac(plaintext: &[u8], key: &[u8; 64]) -> Result<Self> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use rand::RngCore;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        if key.len() != 64 {
            return Err(Error::Crypto("enc key must be 64 bytes (enc||mac)".into()));
        }
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        // PKCS7 padding via cbc crate's encrypt_padded_vec_mut.
        let ct = Aes256CbcEnc::new((&key[..32]).into(), &iv.into())
            .encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(plaintext);

        let mut mac_input = Vec::with_capacity(iv.len() + ct.len());
        mac_input.extend_from_slice(&iv);
        mac_input.extend_from_slice(&ct);
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key[32..])
            .map_err(|e| Error::Crypto(format!("hmac init: {e}")))?;
        mac.update(&mac_input);
        let mac_bytes = mac.finalize().into_bytes().to_vec();

        Ok(Self {
            enc_type: 0,
            iv: iv.to_vec(),
            ct,
            mac: Some(mac_bytes),
        })
    }

    /// Decrypt AES-256-CBC + HMAC-SHA256 (enc type 0/2). MAC is verified in
    /// constant time before any decryption.
    ///
    /// `key` is 64 bytes: [enc_key(32) || mac_key(32)].
    pub fn decrypt_aes256_hmac(&self, key: &[u8; 64]) -> Result<Vec<u8>> {
        use aes::cipher::{BlockDecryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use subtle::ConstantTimeEq;
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        let Some(mac_expected) = &self.mac else {
            return Err(Error::Crypto("enc-string has no MAC".into()));
        };
        if self.iv.len() != 16 {
            return Err(Error::Crypto("IV must be 16 bytes".into()));
        }

        // Verify MAC first (constant time).
        let mut mac_input = Vec::with_capacity(self.iv.len() + self.ct.len());
        mac_input.extend_from_slice(&self.iv);
        mac_input.extend_from_slice(&self.ct);
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key[32..])
            .map_err(|e| Error::Crypto(format!("hmac init: {e}")))?;
        mac.update(&mac_input);
        let mac_actual = mac.finalize().into_bytes();
        if mac_actual.ct_eq(mac_expected).unwrap_u8() != 1 {
            return Err(Error::Crypto("MAC verification failed (wrong key?)".into()));
        }

        Aes256CbcDec::new((&key[..32]).into(), self.iv.as_slice().into())
            .decrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(&self.ct)
            .map_err(|e| Error::Crypto(format!("cbc decrypt: {e}")))
    }
}

impl std::fmt::Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.", self.enc_type)?;
        write!(f, "{}|{}", b64_encode(&self.iv), b64_encode(&self.ct))?;
        if let Some(mac) = &self.mac {
            write!(f, "|{}", b64_encode(mac))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 64] {
        let mut k = [0u8; 64];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        k
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let pt = b"user symmetric key material";
        let enc = EncString::encrypt_aes256_hmac(pt, &key).unwrap();
        assert_eq!(enc.enc_type, 0);
        let dec = enc.decrypt_aes256_hmac(&key).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn parse_round_trip() {
        let key = test_key();
        let enc = EncString::encrypt_aes256_hmac(b"data", &key).unwrap();
        let s = enc.to_string();
        let parsed = EncString::parse(&s).unwrap();
        assert_eq!(parsed.decrypt_aes256_hmac(&key).unwrap(), b"data");
    }

    #[test]
    fn parse_known_format() {
        // Type 2 with a real 16-byte IV ("0123456789abcdef").
        let s = "2.MDEyMzQ1Njc4OWFiY2RlZg==|Y2lwaGVydGV4dA==|bWFj";
        let e = EncString::parse(s).unwrap();
        assert_eq!(e.enc_type, 2);
        assert_eq!(e.iv.len(), 16);
        assert!(e.mac.is_some());
    }

    #[test]
    fn wrong_key_mac_fails() {
        let enc = EncString::encrypt_aes256_hmac(b"secret", &test_key()).unwrap();
        let mut bad = test_key();
        bad[0] ^= 1;
        assert!(enc.decrypt_aes256_hmac(&bad).is_err());
    }

    #[test]
    fn tampered_ciphertext_mac_fails() {
        let key = test_key();
        let mut enc = EncString::encrypt_aes256_hmac(b"secret", &key).unwrap();
        enc.ct[0] ^= 0xFF;
        assert!(enc.decrypt_aes256_hmac(&key).is_err());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(EncString::parse("not-an-enc-string").is_err());
        assert!(EncString::parse("0.onlyonepart").is_err());
        assert!(EncString::parse("99.a|b|c").is_err());
    }
}
