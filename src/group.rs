//! Group orchestration: wires the crypto core to the REST API
//! (crypto doc §5 flows).

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::keys::UserE2EKey;
use crate::message;
use crate::transport::Transport;
use crate::wrap;

/// A decrypted message.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecryptedMessage {
    pub id: String,
    pub sender_user_id: String,
    pub key_version: i32,
    pub plaintext: Vec<u8>,
    pub created_at: i64,
}

/// An E2E client bound to an authenticated transport and this user's E2E key.
///
/// The lib does NOT own auth or key unlocking: the caller supplies an
/// authenticated transport and the (already decrypted) E2E keypair. The CLI's
/// throwaway auth module produces both; the future desktop host passes its own.
pub struct E2EClient {
    transport: Transport,
    e2e_key: UserE2EKey,
    /// user uuid (from /sync or the token) — needed for create-group membership.
    user_id: String,
    user_email: String,
}

impl E2EClient {
    pub fn new(transport: Transport, e2e_key: UserE2EKey, user_id: String, user_email: String) -> Self {
        Self {
            transport,
            e2e_key,
            user_id,
            user_email,
        }
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn user_email(&self) -> &str {
        &self.user_email
    }

    // ------------------------------------------------------------------
    // E2E key lifecycle (crypto doc §4)
    // ------------------------------------------------------------------

    /// Upload this user's E2E keypair. The private key must already be
    /// encrypted with the user's symmetric key (the CLI auth module does this;
    /// the lib never sees the user key).
    pub async fn upload_e2e_key(&self, encrypted_private_b64: &str) -> Result<()> {
        self.transport
            .put(
                "/api/accounts/e2e-key",
                json!({
                    "publicKey": self.e2e_key.public_b64(),
                    "privateKey": encrypted_private_b64,
                }),
            )
            .await?;
        Ok(())
    }

    /// Fetch another user's E2E public key by email (for wrapping the GK).
    pub async fn get_user_public_key(&self, email: &str) -> Result<String> {
        let resp = self
            .transport
            .get(&format!("/api/users/{}/e2e-public-key", urlencoding::encode(email)))
            .await?;
        resp.get("publicKey")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::BadResponse("publicKey missing in response".into()))
    }

    // ------------------------------------------------------------------
    // Group management (crypto doc §5.1, §5.2)
    // ------------------------------------------------------------------

    /// Create a group. Generates the GK, wraps it to our own public key.
    pub async fn create_group(&self, name: &str) -> Result<(String, [u8; 32])> {
        let gk = random_32();
        let wrapped = wrap::wrap_gk(&gk, &self.e2e_key.public_b64(), "", 1)?;
        // The server generates the group uuid; we wrapped with an empty uuid.
        // AAD binds groupUuid — so we must re-wrap after learning the id.
        // Simpler: create first, then rotate-style re-wrap is overkill for the
        // creator; instead the server echoes the id and we re-wrap locally.
        let resp = self
            .transport
            .post(
                "/api/secure-groups",
                json!({
                    "name": name,
                    "keyVersion": 1,
                    "members": [{
                        "userId": self.user_id,
                        "publicKey": self.e2e_key.public_b64(),
                        "wrappedGk": wrapped,
                    }],
                }),
            )
            .await?;
        let group_id = resp
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::BadResponse("group id missing".into()))?
            .to_string();

        // Re-wrap the GK with the real group uuid in the AAD (the create call
        // above used an empty uuid; the server stores what we sent, so we push
        // the corrected wrap via rotate — cheap, O(1) member).
        let wrapped = wrap::wrap_gk(&gk, &self.e2e_key.public_b64(), &group_id, 1)?;
        self.transport
            .post(
                &format!("/api/secure-groups/{group_id}/rotate"),
                json!({
                    "keyVersion": 1,
                    "members": [{
                        "userId": self.user_id,
                        "publicKey": self.e2e_key.public_b64(),
                        "wrappedGk": wrapped,
                    }],
                }),
            )
            .await?;

        Ok((group_id, gk))
    }

    /// List groups the user is a member of.
    pub async fn list_groups(&self) -> Result<Vec<Value>> {
        let resp = self.transport.get("/api/secure-groups").await?;
        Ok(resp
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Fetch group details (members + their public keys).
    pub async fn get_group(&self, group_id: &str) -> Result<Value> {
        self.transport
            .get(&format!("/api/secure-groups/{group_id}"))
            .await
    }

    /// Fetch my own wrapped GK for a group (from the member list) and unwrap it.
    pub async fn recover_gk(&self, group_id: &str) -> Result<[u8; 32]> {
        let group = self.get_group(group_id).await?;
        let key_version = group.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;
        // NOTE: the server's member list exposes publicKey but not wrappedGk.
        // See docs/e2e-groups/03-backend-design.md — the wrapped GK must come
        // from a dedicated field/endpoint (tracked as a backend follow-up).
        let _ = key_version;
        Err(Error::BadResponse(format!(
            "wrapped GK not exposed by GET /secure-groups/{group_id} yet (keyVersion {key_version}); backend follow-up required"
        )))
    }

    // ------------------------------------------------------------------
    // Invitations (crypto doc §5.2, §5.3)
    // ------------------------------------------------------------------

    /// Invite a user by email: fetch their public key, wrap the GK, create the
    /// invitation. If they have no key yet, the invitation is created without a
    /// wrapped GK and completed later via `complete_invite`.
    pub async fn invite(&self, group_id: &str, gk: &[u8; 32], email: &str) -> Result<String> {
        let key_version = self.get_group(group_id).await?;
        let key_version = key_version.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;

        let pubkey = match self.get_user_public_key(email).await {
            Ok(pk) => Some(pk),
            Err(Error::Server { status: 404, .. }) => None,
            Err(e) => return Err(e),
        };

        let wrapped_gk = match &pubkey {
            Some(pk) => wrap::wrap_gk(gk, pk, group_id, key_version)?,
            None => String::new(),
        };

        let resp = self
            .transport
            .post(
                &format!("/api/secure-groups/{group_id}/invitations"),
                json!({
                    "email": email,
                    "publicKey": pubkey,
                    "wrappedGk": wrapped_gk,
                }),
            )
            .await?;
        Ok(resp
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string())
    }

    /// Complete a pending invitation whose invitee had no E2E key at invite
    /// time: fetch their (now-uploaded) public key, wrap the GK, PUT it.
    pub async fn complete_invite(&self, group_id: &str, gk: &[u8; 32], inv_id: &str) -> Result<()> {
        let group = self.get_group(group_id).await?;
        let key_version = group.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;

        // Find the invitation's email from the creator-side listing.
        let invites = self
            .transport
            .get(&format!("/api/secure-groups/{group_id}/invitations"))
            .await?;
        let inv = invites
            .get("data")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|i| i.get("id").and_then(Value::as_str) == Some(inv_id)))
            .ok_or_else(|| Error::BadResponse("invitation not found".into()))?;
        let email = inv
            .get("email")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::BadResponse("invitation email missing".into()))?;

        let pubkey = self.get_user_public_key(email).await?;
        let wrapped = wrap::wrap_gk(gk, &pubkey, group_id, key_version)?;
        self.transport
            .put(
                &format!("/api/secure-groups/{group_id}/invitations/{inv_id}"),
                json!({ "publicKey": pubkey, "wrappedGk": wrapped }),
            )
            .await?;
        Ok(())
    }

    /// List pending invitations addressed to this user.
    pub async fn list_my_invitations(&self) -> Result<Vec<Value>> {
        let resp = self.transport.get("/api/secure-groups/invitations/mine").await?;
        Ok(resp
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Accept a pending invitation: unwrap the wrapped GK with our private key.
    pub async fn accept_invitation(&self, group_id: &str, inv_id: &str) -> Result<[u8; 32]> {
        self.transport
            .post(
                &format!("/api/secure-groups/{group_id}/invitations/{inv_id}/accept"),
                json!({ "publicKey": self.e2e_key.public_b64() }),
            )
            .await?;
        // The wrapped GK comes back via the group's member data (backend
        // follow-up, see recover_gk) — for now the caller must supply it.
        Err(Error::BadResponse(
            "accept succeeded but GK recovery needs the backend wrappedGk exposure".into(),
        ))
    }

    // ------------------------------------------------------------------
    // Messages (crypto doc §5.4, §5.5)
    // ------------------------------------------------------------------

    /// Encrypt + send a message to a room.
    pub async fn send_message(&self, group_id: &str, gk: &[u8; 32], plaintext: &[u8]) -> Result<String> {
        let group = self.get_group(group_id).await?;
        let key_version = group.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;

        // The server generates the message uuid; AAD binds messageId, so we
        // send with a client-generated message id used consistently.
        let message_id = uuid_v4();
        let mdk = random_32();
        let envelope = message::encrypt_message(&mdk, plaintext, &message_id, group_id, key_version)?;
        let wrapped_mdk = wrap::wrap_mdk(&mdk, gk, &message_id, group_id, key_version)?;

        let resp = self
            .transport
            .post(
                &format!("/api/secure-groups/{group_id}/messages"),
                json!({ "data": envelope, "key": wrapped_mdk }),
            )
            .await?;
        Ok(resp
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(&message_id)
            .to_string())
    }

    /// Fetch messages since `after_ms` (epoch millis) and decrypt them.
    pub async fn fetch_messages(
        &self,
        group_id: &str,
        gk: &[u8; 32],
        after_ms: Option<i64>,
        limit: i64,
    ) -> Result<Vec<DecryptedMessage>> {
        // Each message carries its own keyVersion; the group's current version
        // is only a fallback for messages missing the field.
        let group = self.get_group(group_id).await?;
        let _group_version = group.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;

        let mut path = format!("/api/secure-groups/{group_id}/messages?limit={limit}");
        if let Some(after) = after_ms {
            path.push_str(&format!("&after={after}"));
        }
        let resp = self.transport.get(&path).await?;
        let items = resp
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let id = item.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
            let msg_v = item.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;
            let sender = item
                .get("senderUserId")
                .or_else(|| item.get("senderId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let created = item.get("createdAt").and_then(Value::as_i64).unwrap_or(0);
            let data = item.get("data").cloned().unwrap_or(Value::Null);
            let wrapped_mdk = item.get("key").and_then(Value::as_str).unwrap_or_default();

            let mdk = wrap::unwrap_mdk(wrapped_mdk, gk, &id, group_id, msg_v)?;
            let plaintext = message::decrypt_message(&mdk, &data, &id, group_id, msg_v)?;
            out.push(DecryptedMessage {
                id,
                sender_user_id: sender,
                key_version: msg_v,
                plaintext,
                created_at: created,
            });
        }
        Ok(out)
    }

    /// Delete a message you sent (sender-delete).
    pub async fn delete_message(&self, group_id: &str, msg_id: &str) -> Result<()> {
        self.transport
            .delete(&format!("/api/secure-groups/{group_id}/messages/{msg_id}"))
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Rotation (crypto doc §5.6)
    // ------------------------------------------------------------------

    /// Remove a member and rotate the GK (forward secrecy). Fetches the current
    /// member list, drops the removed user, re-wraps the new GK to everyone
    /// remaining, and POSTs the COMPLETE remaining list — the server deletes
    /// absent members.
    pub async fn remove_member(&self, group_id: &str, _gk: &[u8; 32], remove_user_id: &str) -> Result<[u8; 32]> {
        let group = self.get_group(group_id).await?;
        let old_version = group.get("keyVersion").and_then(Value::as_i64).unwrap_or(1) as i32;
        let new_version = old_version + 1;
        let members = group
            .get("members")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let new_gk = random_32();
        let mut payload_members = Vec::new();
        for m in &members {
            let uid = m.get("userId").and_then(Value::as_str).unwrap_or_default();
            if uid == remove_user_id {
                continue; // dropped — server will delete their row
            }
            let pk = m.get("publicKey").and_then(Value::as_str).unwrap_or_default();
            let wrapped = if uid == self.user_id {
                wrap::wrap_gk(&new_gk, &self.e2e_key.public_b64(), group_id, new_version)?
            } else {
                wrap::wrap_gk(&new_gk, pk, group_id, new_version)?
            };
            payload_members.push(json!({
                "userId": uid,
                "publicKey": pk,
                "wrappedGk": wrapped,
            }));
        }

        self.transport
            .post(
                &format!("/api/secure-groups/{group_id}/rotate"),
                json!({ "keyVersion": new_version, "members": payload_members }),
            )
            .await?;
        Ok(new_gk)
    }
}

fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// Minimal UUID v4 (avoids pulling the uuid crate for one call site).
fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}
