# bitwarden-e2e-client

Rust client crypto library for **E2E-encrypted secure groups on Vaultwarden/Bitwarden** — the client half of a system where the server stores only opaque ciphertext and never decrypts.

- Server side: [`vaultwarden-e2e-backend`](https://github.com/aaunario/vaultwarden-e2e-backend) — additive-only Vaultwarden fork, server side complete
- Protocol design docs: [`docs/e2e-groups/`](https://github.com/aaunario/vaultwarden-e2e-backend/tree/main/docs/e2e-groups) in that repo (architecture, crypto protocol, backend/client design)

## What it does

Client-side cryptography for host-confidential group messaging:

- **Two-level key hierarchy** — each group has a Group Key (GK); every message is encrypted under a fresh Message Data Key (MDK), which is HPKE-wrapped to the GK. Compromising one message key reveals nothing else.
- **Post-quantum** — group keys are X-Wing keypairs (ML-KEM-768 + X25519 hybrid KEM) via the [`hpke`](https://crates.io/crates/hpke) crate. Every wrap/unwrap and message is AAD-bound (group id + key version), so ciphertexts can't be replayed across groups or key versions.
- **Forward secrecy on membership changes** — rotation re-wraps the GK to the remaining members only; the server deletes absent members, so ex-members can't read post-rotation traffic.
- **Bitwarden interop** — enc-string codec (types 0/2/8; AES-256-CBC+HMAC with constant-time MAC verify) so the library slots into the full Bitwarden key chain (prelogin → PBKDF2/Argon2id master key → stretchKey → user symmetric key).

**Design constraint:** the library does *not* own auth or key unlocking. `E2EClient::new(transport, e2e_key, user_id, user_email)` — callers supply an authenticated transport and a decrypted user E2E key. This keeps the crypto core host-agnostic: CLI test driver today, desktop app via WASM later.

## Status

Crypto core complete and tested — 22 tests (round-trips, tamper cases, enc-string interop), clippy clean.

| Module | State |
|---|---|
| `keys.rs` | ✅ X-Wing keypair generation (deterministic from the GK via `XWing::derive_keypair`) |
| `wrap.rs` | ✅ GK→member + MDK→GK HPKE wrapping, AAD-bound, tamper-tested |
| `message.rs` | ✅ AES-256-GCM content encryption, `{v, nonce, ct}` envelope |
| `enc_string.rs` | ✅ Bitwarden enc-string codec (types 0/2/8), constant-time MAC verify |
| `transport.rs` | ✅ reqwest REST client, Bearer auth |
| `group.rs` | ⚠️ orchestration written; `recover_gk()` pending a small backend addition (`myWrappedGk` on `GET /secure-groups/{id}`) |
| `bin/e2e-cli.rs` | ✅ CLI test driver wired; end-to-end smoke test next |

## Implementation notes (`hpke` 0.14)

- KEM: `hpke::kem::XWing` · KDF: `HkdfSha256` · AEAD: `AesGcm256`
- Sizes: public key 1216 B, seed 32 B, encapped key 1120 B
- `XWing::gen_keypair()` takes no RNG argument; `XWing::derive_keypair(ikm)` yields deterministic keypairs — same GK → same keypair on every member

## Roadmap

1. Backend: expose the caller's own `wrappedGk` on group fetch → implement `recover_gk()` for real
2. Two-user live smoke test (create → invite → accept → send → receive; assert an ex-member can't decrypt post-rotation messages)
3. WASM target (`cdylib` + `wasm-bindgen`) so a desktop host can drive the library
4. Desktop integration; retire the CLI's throwaway auth module

## Development

```bash
cargo test      # 22 tests: crypto round-trips, tamper cases, enc-string
cargo clippy    # clean
cargo run --bin e2e-cli -- --help
```

Detailed status, spike notes, and the full plan: [PLAN.md](PLAN.md).
