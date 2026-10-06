//! Thin authenticated HTTP transport to the vaultwarden fork.
//!
//! The lib is transport-agnostic in spirit but ships this default REST client.
//! The caller supplies the base URL and access token (obtained by the CLI's
//! auth module or, later, by the desktop host).

use serde_json::Value;

use crate::error::{Error, Result};

/// REST client bound to a server + access token.
#[derive(Clone)]
pub struct Transport {
    http: reqwest::Client,
    base_url: String,
    access_token: std::sync::Arc<std::sync::RwLock<String>>,
}

impl Transport {
    /// Build a transport. `danger_accept_invalid_certs` is for local dev with
    /// the fork's self-signed cert — never enable in production.
    pub fn new(base_url: &str, access_token: String, accept_invalid_certs: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .map_err(|e| Error::Transport(format!("client build: {e}")))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: std::sync::Arc::new(std::sync::RwLock::new(access_token)),
        })
    }

    /// Update the access token (e.g. after a refresh).
    pub fn set_token(&self, token: String) {
        *self.access_token.write().unwrap() = token;
    }

    pub fn token(&self) -> String {
        self.access_token.read().unwrap().clone()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self
            .http
            .request(method, self.url(path))
            .bearer_auth(self.token())
            .header("Content-Type", "application/json");
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Transport(format!("request {path}: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Transport(format!("reading {path}: {e}")))?;
        let json: Value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .map_err(|e| Error::BadResponse(format!("{path}: {e} in: {text:.200}")))?
        };

        if !status.is_success() {
            let message = json
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or(&text)
                .to_string();
            return Err(Error::Server {
                status: status.as_u16(),
                message,
            });
        }
        Ok(json)
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.request(reqwest::Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    pub async fn put(&self, path: &str, body: Value) -> Result<Value> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.request(reqwest::Method::DELETE, path, None).await
    }
}
