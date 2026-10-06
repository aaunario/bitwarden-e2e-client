//! # bitwarden-e2e-client
//!
//! E2E encrypted secure-group communication for Vaultwarden.
//!
//! All crypto runs client-side: the server stores opaque ciphertext blobs and
//! enforces membership only. See `vaultwarden/docs/e2e-groups/` for the design.
//!
//! ## Architecture
//!
//! The lib does **not** own auth or key unlocking. The caller supplies:
//! - an authenticated [`Transport`] (access token), and
//! - this user's decrypted [`keys::UserE2EKey`].
//!
//! The CLI's throwaway auth module produces both; the future desktop host
//! passes its own through WASM. This keeps the lib client-agnostic.
//!
//! ```no_run
//! # async fn f() -> bitwarden_e2e_client::Result<()> {
//! use bitwarden_e2e_client::{transport::Transport, keys::UserE2EKey, group::E2EClient};
//!
//! let transport = Transport::new("https://localhost:8000", "token".into(), true)?;
//! let e2e_key = UserE2EKey::generate();
//! let client = E2EClient::new(transport, e2e_key, "user-uuid".into(), "a@x.com".into());
//! # Ok(())
//! # }
//! ```

pub mod cli {
    //! CLI-only support (throwaway auth module). Not part of the lib's public
    //! crypto API; exists so the e2e-cli binary can reuse it.
    pub mod auth;
}

pub mod enc_string;
pub mod error;
pub mod group;
pub mod keys;
pub mod message;
pub mod transport;
pub mod wrap;

pub use error::{Error, Result};
