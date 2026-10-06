//! THROWAWAY auth module — CLI-only.
//!
//! Implements Bitwarden's login handshake + user-key unlock so the CLI can
//! produce the two things the lib requires: an authenticated transport and the
//! decrypted E2E keypair. The lib itself knows nothing about passwords.
//!
//! Handshake (docs/e2e-groups/04-client-design.md §3.1):
//!   1. POST /identity/accounts/prelogin → kdfType + iterations
//!   2. masterKey = PBKDF2/Argon2id(password, lowercase(email))
//!   3. authHash  = b64(PBKDF2-SHA256(masterKey, password, 1))
//!   4. POST /identity/connect/token → access_token
//!   5. stretchKey(masterKey) → 64B; fetch /sync → protected user symmetric key
//!   6. decrypt user symmetric key (enc-string, AES-256-CBC+HMAC)
//!
//! ~185 lines, isolated here so it can be deleted when the desktop host takes
//! over key unlocking.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde_json::{json, Value};

use crate::enc_string::EncString;


/// KDF params from prelogin.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub kdf_type: i64,
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

/// Everything the CLI needs after login.
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub user_email: String,
    /// 64-byte user symmetric key: [enc_key(32) || mac_key(32)].
    pub user_sym_key: [u8; 64],
}

/// Step 1: prelogin → KDF params.
pub async fn prelogin(http: &reqwest::Client, base: &str, email: &str) -> Result<KdfParams> {
    let resp: Value = http
        .post(format!("{base}/identity/accounts/prelogin"))
        .json(&json!({ "email": email }))
        .send()
        .await?
        .error_for_status()
        .context("prelogin failed")?
        .json()
        .await?;
    Ok(KdfParams {
        kdf_type: resp.get("kdfType").and_then(Value::as_i64).unwrap_or(0),
        iterations: resp.get("kdfIterations").and_then(Value::as_u64).unwrap_or(600_000) as u32,
        memory_kib: resp.get("kdfMemory").and_then(Value::as_u64).unwrap_or(64) as u32,
        parallelism: resp.get("kdfParallelism").and_then(Value::as_u64).unwrap_or(4) as u32,
    })
}

/// Steps 2–3: derive masterKey + authHash.
pub fn derive_master_key(password: &str, email: &str, kdf: &KdfParams) -> Result<Vec<u8>> {
    let salt = email.trim().to_lowercase();
    match kdf.kdf_type {
        0 => {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt.as_bytes(), kdf.iterations, &mut out);
            Ok(out.to_vec())
        }
        1 => {
            use argon2::Algorithm;
            let params = argon2::Params::new(
                kdf.memory_kib,
                kdf.iterations, // Argon2 "time cost" reuses the iterations field
                kdf.parallelism,
                Some(32),
            )
            .map_err(|e| anyhow!("argon2 params: {e}"))?;
            let a2 = argon2::Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut out = vec![0u8; 32];
            a2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
                .map_err(|e| anyhow!("argon2: {e}"))?;
            Ok(out)
        }
        t => Err(anyhow!("unsupported kdfType {t}")),
    }
}

fn auth_hash(master_key: &[u8], password: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(master_key, password.as_bytes(), 1, &mut out);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// Step 4: token exchange.
pub async fn login_token(
    http: &reqwest::Client,
    base: &str,
    email: &str,
    master_key: &[u8],
    password: &str,
) -> Result<(String, String)> {
    let form = [
        ("grant_type", "password"),
        ("username", email),
        ("password", &auth_hash(master_key, password)),
        ("client_id", "cli"),
        ("scope", "api offline_access"),
        ("device_identifier", &uuid_v4()),
        ("device_name", "e2e-cli"),
        ("device_type", "14"),
    ];
    let resp: Value = http
        .post(format!("{base}/identity/connect/token"))
        .form(&form)
        .send()
        .await?
        .error_for_status()
        .map_err(|e| {
            // Include the server's error body if present.
            anyhow!("login failed: {e}")
        })?
        .json()
        .await?;
    let access = resp
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no access_token in response"))?
        .to_string();
    let refresh = resp
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok((access, refresh))
}

/// Steps 5–6: stretchKey + unlock the user symmetric key from /sync.
pub async fn unlock_user_key(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    master_key: &[u8],
) -> Result<(String, String, [u8; 64])> {
    // stretchKey: HKDF-SHA256 expand to 64 bytes with Bitwarden's fixed info.
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(master_key)
        .map_err(|e| anyhow!("stretchKey from_prk: {e}"))?;
    let mut stretched = [0u8; 64];
    hk.expand(b"enc", &mut stretched)
        .map_err(|e| anyhow!("stretchKey: {e}"))?;

    let resp: Value = http
        .get(format!("{base}/api/sync"))
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()
        .context("sync failed")?
        .json()
        .await?;

    let profile = resp
        .get("profile")
        .ok_or_else(|| anyhow!("no profile in sync"))?;
    let user_id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no user id"))?
        .to_string();
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // The user's protected symmetric key lives on the profile as "key"
    // (enc-string, encrypted with the stretched master key).
    let key_enc = profile
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no protected user key in sync"))?;
    let enc = EncString::parse(key_enc)?;
    let pt = enc.decrypt_aes256_hmac(&stretched)?;

    // User symmetric key layout: [enc(32) || mac(32) || enc(32) || mac(32)] —
    // we need the first 64 bytes (encryption + mac keys).
    if pt.len() < 64 {
        return Err(anyhow!("user key too short: {} bytes", pt.len()));
    }
    let mut sym = [0u8; 64];
    sym.copy_from_slice(&pt[..64]);
    Ok((user_id, email, sym))
}

/// Full login flow: returns everything the CLI needs.
pub async fn login(base: &str, email: &str, password: &str, accept_invalid_certs: bool) -> Result<Session> {
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .build()?;
    let kdf = prelogin(&http, base, email).await?;
    let master_key = derive_master_key(password, email, &kdf)?;
    let (access, refresh) = login_token(&http, base, email, &master_key, password).await?;
    let (user_id, user_email, user_sym_key) = unlock_user_key(&http, base, &access, &master_key).await?;
    Ok(Session {
        access_token: access,
        refresh_token: refresh,
        user_id,
        user_email,
        user_sym_key,
    })
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]
    )
}
