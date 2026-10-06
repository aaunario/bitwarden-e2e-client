//! e2e-cli — test driver for the E2E secure-group flow.
//!
//! This is a test harness, not a product: it exists to exercise
//! encrypt → store ciphertext → decrypt end-to-end without a frontend.

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use bitwarden_e2e_client::enc_string::EncString;
use bitwarden_e2e_client::group::E2EClient;
use bitwarden_e2e_client::keys::UserE2EKey;
use bitwarden_e2e_client::transport::Transport;

#[derive(Parser)]
#[command(name = "e2e-cli", about = "E2E secure-group test driver")]
struct Cli {
    /// Server base URL.
    #[arg(long, default_value = "https://localhost:8000")]
    server: String,
    /// Accept self-signed certs (local dev only).
    #[arg(long)]
    insecure: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in and cache the session.
    Login {
        #[arg(long)]
        email: String,
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
    },
    /// Show cached session info.
    Whoami,
    /// Ensure this user has an E2E keypair (generate + upload if missing).
    EnsureKey,
    /// Group operations.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Message operations.
    Message {
        #[command(subcommand)]
        cmd: MessageCmd,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create a group.
    Create { name: String },
    /// List my groups.
    List,
    /// Invite a user by email.
    Invite { group_id: String, email: String },
    /// Complete a pending invitation (invitee had no key at invite time).
    Complete { group_id: String, invitation_id: String },
    /// List invitations addressed to me.
    Invitations,
    /// Accept an invitation addressed to me.
    Accept { group_id: String, invitation_id: String },
    /// Remove a member (rotates the GK).
    Remove { group_id: String, user_id: String },
}

#[derive(Subcommand)]
enum MessageCmd {
    /// Send a message.
    Send { group_id: String, text: String },
    /// Fetch + decrypt messages.
    List {
        group_id: String,
        #[arg(long, default_value_t = 100)]
        limit: i64,
    },
}

/// Cached session: access token + user info + encrypted E2E private key.
/// The user symmetric key is NOT persisted — only the E2E private key
/// (encrypted with it) is. 0600 perms.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredSession {
    server: String,
    access_token: String,
    refresh_token: String,
    user_id: String,
    user_email: String,
    /// E2E public key, base64.
    e2e_public: String,
    /// E2E private key encrypted with the user symmetric key (enc-string).
    e2e_private_enc: String,
}

fn session_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".e2e-cli")
        .join("session.json")
}

fn save_session(s: &StoredSession) -> Result<()> {
    let path = session_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.parent().unwrap(), std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(s)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_session() -> Result<StoredSession> {
    let data = std::fs::read_to_string(session_path())
        .with_context(|| format!("no session at {} — run `login` first", session_path().display()))?;
    Ok(serde_json::from_str(&data)?)
}

/// Build a lib client from the stored session. Decrypts the E2E private key
/// using the user symmetric key, which requires the master password (re-prompted).
fn make_client(server: &str, insecure: bool, password: &str) -> Result<E2EClient> {
    let stored = load_session()?;
    // Re-derive the user symmetric key from the password (cheap, no network
    // beyond nothing — we cache nothing sensitive at rest).
    let rt = tokio::runtime::Runtime::new()?;
    let session = rt.block_on(async {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .build()?;
        let kdf = bitwarden_e2e_client::cli::auth::prelogin(&http, server, &stored.user_email).await?;
        let master_key = bitwarden_e2e_client::cli::auth::derive_master_key(password, &stored.user_email, &kdf)?;
        bitwarden_e2e_client::cli::auth::unlock_user_key(&http, server, &stored.access_token, &master_key).await
    })?;

    let transport = Transport::new(server, stored.access_token.clone(), insecure)?;
    let e2e_key = UserE2EKey::from_bytes(
        base64::engine::general_purpose::STANDARD.decode(&stored.e2e_public)?,
        {
            let enc = EncString::parse(&stored.e2e_private_enc)?;
            enc.decrypt_aes256_hmac(&session.2)?
        },
    )?;
    Ok(E2EClient::new(transport, e2e_key, stored.user_id, stored.user_email))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let insecure = cli.insecure;

    match cli.command {
        Command::Login { email, password } => {
            let password = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Master password: ")?,
            };
            let session = bitwarden_e2e_client::cli::auth::login(&cli.server, &email, &password, insecure).await?;
            println!("logged in as {} ({})", session.user_email, session.user_id);

            // Ensure an E2E keypair exists; generate + upload if not.
            let transport = Transport::new(&cli.server, session.access_token.clone(), insecure)?;
            let existing = transport.get("/api/accounts/e2e-key").await.is_ok();
            let (e2e_key, private_enc) = match transport.get("/api/accounts/e2e-key").await {
                Ok(resp) => {
                    let pub_b64 = resp
                        .get("publicKey")
                        .and_then(serde_json::Value::as_str)
                        .context("existing E2E key missing publicKey")?;
                    let priv_enc = resp
                        .get("privateKey")
                        .and_then(serde_json::Value::as_str)
                        .context("existing E2E key missing privateKey")?
                        .to_string();
                    // We can't decrypt the stored private key without the user
                    // sym key — we have it in this scope via session.
                    let enc = EncString::parse(&priv_enc)?;
                    let pt = enc.decrypt_aes256_hmac(&session.user_sym_key)?;
                    (
                        UserE2EKey::from_bytes(
                            base64::engine::general_purpose::STANDARD.decode(pub_b64)?,
                            pt,
                        )?,
                        priv_enc,
                    )
                }
                Err(_) => {
                    println!("no E2E key on server; generating…");
                    let key = UserE2EKey::generate();
                    let enc = EncString::encrypt_aes256_hmac(&key.private, &session.user_sym_key)?;
                    (key, enc.to_string())
                }
            };

            // Upload if we generated a new one.
            if !existing {
                let client = E2EClient::new(
                    transport,
                    e2e_key.clone(),
                    session.user_id.clone(),
                    session.user_email.clone(),
                );
                client.upload_e2e_key(&private_enc).await?;
                println!("E2E keypair generated + uploaded");
            }

            save_session(&StoredSession {
                server: cli.server.clone(),
                access_token: session.access_token,
                refresh_token: session.refresh_token,
                user_id: session.user_id,
                user_email: session.user_email,
                e2e_public: e2e_key.public_b64(),
                e2e_private_enc: private_enc,
            })?;
            println!("session saved to {}", session_path().display());
        }
        Command::Whoami => {
            let s = load_session()?;
            println!("{} @ {} ({})", s.user_email, s.server, s.user_id);
        }
        Command::EnsureKey => {
            let s = load_session()?;
            let password = rpassword::prompt_password("Master password: ")?;
            let _client = make_client(&s.server, insecure, &password)?;
            println!("E2E keypair loaded OK");
        }
        Command::Group { cmd } => run_group(cli.server.clone(), insecure, cmd).await?,
        Command::Message { cmd } => run_message(cli.server.clone(), insecure, cmd).await?,
    }
    Ok(())
}

async fn run_group(server: String, insecure: bool, cmd: GroupCmd) -> Result<()> {
    let password = rpassword::prompt_password("Master password: ")?;
    let client = make_client(&server, insecure, &password)?;

    match cmd {
        GroupCmd::Create { name } => {
            // create_group needs the GK; we generate it here and keep it in the
            // session file (encrypted) so later commands can recover it.
            let (group_id, _gk) = client.create_group(&name).await?;
            println!("created group {group_id}");
            // NOTE: GK persistence per group is a follow-up (session store
            // keyed by group id). For the MVP the GK is recovered via
            // recover_gk() once the backend exposes wrappedGk.
        }
        GroupCmd::List => {
            for g in client.list_groups().await? {
                println!(
                    "{}  {}  v{}",
                    g.get("id").and_then(serde_json::Value::as_str).unwrap_or("?"),
                    g.get("name").and_then(serde_json::Value::as_str).unwrap_or("?"),
                    g.get("keyVersion").and_then(serde_json::Value::as_i64).unwrap_or(0),
                );
            }
        }
        GroupCmd::Invite { group_id, email } => {
            let gk = client.recover_gk(&group_id).await?;
            let inv = client.invite(&group_id, &gk, &email).await?;
            println!("invitation {inv} created for {email}");
        }
        GroupCmd::Complete { group_id, invitation_id } => {
            let gk = client.recover_gk(&group_id).await?;
            client.complete_invite(&group_id, &gk, &invitation_id).await?;
            println!("invitation {invitation_id} completed");
        }
        GroupCmd::Invitations => {
            for inv in client.list_my_invitations().await? {
                println!(
                    "{}  group={}  status={}",
                    inv.get("id").and_then(serde_json::Value::as_str).unwrap_or("?"),
                    inv.get("groupId").and_then(serde_json::Value::as_str).unwrap_or("?"),
                    inv.get("status").and_then(serde_json::Value::as_i64).unwrap_or(0),
                );
            }
        }
        GroupCmd::Accept { group_id, invitation_id } => {
            let _gk = client.accept_invitation(&group_id, &invitation_id).await?;
            println!("accepted invitation {invitation_id}");
        }
        GroupCmd::Remove { group_id, user_id } => {
            let gk = client.recover_gk(&group_id).await?;
            let new_gk = client.remove_member(&group_id, &gk, &user_id).await?;
            println!("member {user_id} removed; GK rotated (new version)");
            let _ = new_gk; // persisted via recover_gk on next use
        }
    }
    Ok(())
}

async fn run_message(server: String, insecure: bool, cmd: MessageCmd) -> Result<()> {
    let password = rpassword::prompt_password("Master password: ")?;
    let client = make_client(&server, insecure, &password)?;

    match cmd {
        MessageCmd::Send { group_id, text } => {
            let gk = client.recover_gk(&group_id).await?;
            let id = client.send_message(&group_id, &gk, text.as_bytes()).await?;
            println!("sent message {id}");
        }
        MessageCmd::List { group_id, limit } => {
            let gk = client.recover_gk(&group_id).await?;
            let msgs = client.fetch_messages(&group_id, &gk, None, limit).await?;
            for m in msgs {
                println!(
                    "[{}] {}: {}",
                    m.created_at,
                    &m.sender_user_id[..8.min(m.sender_user_id.len())],
                    String::from_utf8_lossy(&m.plaintext),
                );
            }
        }
    }
    Ok(())
}
