# bitwarden-e2e-client — Status & Plan

> Handoff notes, 2026-10-06. Companion to the design docs in
> `../vaultwarden/docs/e2e-groups/` (read `README.md` there first).

## What this repo is

E2E encrypted secure-group client for the `vaultwarden-secure-groups` fork:

- **`src/lib.rs`** — the crypto library (the real deliverable). Compiles as
  `rlib` (CLI/tests) today; `cdylib`/WASM target is planned but not wired.
- **`src/bin/e2e-cli.rs`** — CLI test driver (not a product).
- **`src/cli/auth.rs`** — THROWAWAY auth module (CLI-only). Implements
  Bitwarden's login handshake + user-key unlock. Delete when the desktop host
  takes over key unlocking via WASM.

## Architecture decisions (settled — do not relitigate)

1. **The lib does NOT own auth or key unlocking.** `E2EClient::new(transport,
   e2e_key, user_id, user_email)` — callers supply an authenticated transport
   and a decrypted `UserE2EKey`. The CLI's auth module produces both; the
   future desktop host passes its own through WASM. This is the key design
   constraint that makes the CLI auth throwaway.
2. **Separate client, not a bitwarden-clients fork.** Fast iteration on
   protocol validation; desktop integration is Phase 3.
3. **Polling, not WebSocket, for the MVP CLI.** `GET .../messages?after=` is
   the source of truth; the server's WS hub (SignalR/MessagePack, already
   broadcasting group events 30–32) is a latency optimization for later.
4. **Full Bitwarden key chain in the CLI** (not masterKey-derived shortcut):
   prelogin → PBKDF2/Argon2id masterKey → stretchKey (HKDF-SHA256, info
   `b"enc"`, 64B) → `/sync` profile.key enc-string → AES-256-CBC+HMAC decrypt
   → user symmetric key `[enc(32)||mac(32)]`.
5. **Sibling repo** (this one), path-dependency from the server's dev-deps when
   integration tests come.

## Current state (all compiles, 22 tests pass, clippy clean)

| Module | State |
|---|---|
| `keys.rs` | ✅ X-Wing keypair gen, `gk_xwing_keypair(gk)` (deterministic, via hpke's native `XWing::derive_keypair`) |
| `wrap.rs` | ✅ GK→member + MDK→GK HPKE wrapping, AAD-bound, round-trip + tamper tests |
| `message.rs` | ✅ AES-256-GCM content encryption, `{v,nonce,ct}` envelope, AAD-bound |
| `enc_string.rs` | ✅ Bitwarden enc-string codec (types 0/2/8), AES-256-CBC+HMAC with constant-time MAC verify |
| `transport.rs` | ✅ reqwest REST client, Bearer auth, `--insecure` for self-signed dev certs |
| `group.rs` | ⚠️ orchestration written but **blocked on backend gap** (below) |
| `cli/auth.rs` | ✅ full handshake; **untested against a live server** |
| `bin/e2e-cli.rs` | ✅ all subcommands wired; untested end-to-end |

## hpke 0.14.1 API facts (spike-verified — saves you an hour)

- KEM type: `hpke::kem::XWing` (NOT `MlKem768X25519`)
- KDF: `hpke::kdf::HkdfSha256`; AEAD: `hpke::aead::AesGcm256` (needs `aes` feature)
- Key/enc sizes: pk = 1216 B, sk = 32 B, encapped key = 1120 B
- `XWing::gen_keypair()` takes NO rng arg
- `from_bytes`/`to_bytes` come from `Deserializable`/`Serializable` traits — import them
- Key/enc types are associated types: `<XWing as Kem>::PublicKey` etc.
- **`XWing::derive_keypair(ikm)` exists natively** — the crypto doc's old
  hand-rolled HKDF-seed derivation (§2.2) was replaced with this; docs already
  updated. Same GK → same keypair on every member.

## ⚠️ BLOCKER: backend must expose the member's own wrappedGk

`GET /api/secure-groups/{id}` returns members as `{userId, publicKey}` only —
**no `wrappedGk`**. Without it, a member cannot recover the GK and nothing
works end-to-end (`recover_gk()` in `group.rs` is a stub that returns an error
explaining exactly this).

**Fix (small, in `../vaultwarden`):** in `SecureGroup::to_json_with_members`
(`src/db/models/secure_group.rs`), include the *calling user's* `wrappedGk` in
the response (only their own — never other members'). Suggested shape:

```jsonc
// GET /api/secure-groups/{id}
{ "id": "...", "keyVersion": 1,
  "members": [ { "userId": "...", "publicKey": "..." } ],
  "myWrappedGk": "<b64>",        // ← add: caller's own wrapped GK
  "object": "secureGroup" }
```

Then implement `recover_gk()` in `group.rs`: fetch group → take `myWrappedGk`
→ `wrap::unwrap_gk(wrapped, my_priv_b64, group_id, key_version)`.

Related backend notes (already implemented in the fork):
- `POST /rotate` treats `members` as the COMPLETE remaining list; absent
  members are deleted server-side (forward secrecy).
- `GET /api/secure-groups/invitations/mine` — invitee discovers invites.
- `GET /api/users/{email}/e2e-public-key` — inviter fetches invitee pubkey.
- `PUT /api/secure-groups/{id}/invitations/{inv}` — complete a late-key invite.
- Accept fails with `No wrapped key` if the invitation has no wrappedGk yet.

## Known design wart: create_group double-wrap

`create_group()` wraps the GK with an empty group uuid (the server assigns the
id), then immediately re-wraps via a `rotate` call with the real uuid in the
AAD. Works, but ugly. Cleaner fix: server accepts a client-generated group
uuid on create, OR the AAD drops the group uuid for v1 keys. Decide when
touching the backend next.

## Next steps (in order)

1. **Backend:** add `myWrappedGk` to `GET /secure-groups/{id}` (see above) +
   unit test. Run `cargo check --features sqlite && cargo test secure_group`.
2. **Client:** implement `recover_gk()` for real.
3. **Live smoke test:** start the fork (`cargo run --features sqlite`), then:
   `e2e-cli login --email alice@…` → `group create` → `group invite` →
   (bob) `login` → `group invitations` → `group accept` → (alice)
   `message send` → (bob) `message list`. Expect breakage in details (field
   casing, response shapes) — fix as found.
4. **GK persistence:** the CLI currently recovers the GK from the server every
   command (fine), but `create_group` returns it and drops it — after #2 this
   is moot since recovery works.
5. **Integration script:** extend `../vaultwarden/scripts/test-secure-groups.sh`
   or write `scripts/test-full-stack.sh` here (two users, assert ex-member
   can't decrypt post-rotation messages).
6. **WASM target:** add `wasm-bindgen`, `crate-type = ["cdylib","rlib"]`,
   `wasm-pack test --node` for the crypto round-trips.
7. **Phase 3 (out of scope here):** desktop/Electron integration via WASM;
   delete `src/cli/auth.rs` when that lands.

## Commands

```bash
cargo test          # 22 tests (crypto round-trips, tamper cases, enc-string)
cargo clippy        # clean
cargo run --bin e2e-cli -- --help
# against the fork (self-signed cert):
cargo run --bin e2e-cli -- --insecure login --email alice@x.com
```

## Repo map

```
src/
├── lib.rs            # public API + module docs
├── keys.rs           # UserE2EKey, gk_xwing_keypair
├── wrap.rs           # HPKE wrap/unwrap (GK, MDK)
├── message.rs        # AES-256-GCM content encryption
├── enc_string.rs     # Bitwarden enc-string codec (interop)
├── transport.rs      # REST client
├── error.rs          # Error enum
├── group.rs          # E2EClient orchestration ← recover_gk() stub here
├── cli/auth.rs       # THROWAWAY login handshake (CLI-only)
└── bin/e2e-cli.rs    # CLI driver
```
