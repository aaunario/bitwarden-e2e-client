//! Error types for the E2E client library.

use thiserror::Error;

/// Library error type. The lib never panics on crypto failures — everything
/// surfaces as a typed error so callers (CLI, WASM host) can handle it.
#[derive(Debug, Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },

    #[error("not a member of group {0}")]
    NotMember(String),

    #[error("no E2E keypair for this user; call ensure_e2e_key first")]
    NoE2EKey,

    #[error("invalid response from server: {0}")]
    BadResponse(String),

    #[error("key version mismatch: message is v{message_v} but group is v{group_v}")]
    KeyVersionMismatch { message_v: i32, group_v: i32 },
}

pub type Result<T> = std::result::Result<T, Error>;
