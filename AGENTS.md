# Agent Guidelines for avault

Operating manual for coding agents working in this repository. `CLAUDE.md` is a symlink to
this file. The authoritative design is [`docs/DESIGN.md`](docs/DESIGN.md) — read it before
changing crypto, the interface, or the trust model.

## 1. What this is

`avault` is the **Rust key-custody core** for [Avibe](https://github.com/avibe-bot/avibe)
Vaults. It is the **only** component that holds key material or performs cryptography. Its
whole reason to exist is to keep keys and plaintext out of the Python agent runtime.

**The invariant — never break it:**

> Plaintext and key material flow **into** avault only. avault returns **ciphertext,
> delivery results, exit codes, or signatures** — never plaintext, never keys. There is no
> `decrypt → plaintext` verb.

## 2. Architecture

A Cargo workspace, three crates, sharp boundaries:

- `crates/avault-core` — **pure crypto**, no I/O, no platform deps, no logging of secrets.
  Envelope encryption (AES-256-GCM + AAD), per-record DEK wrap, HPKE blind-box open,
  secp256k1 signing; everything zeroized, constant-time where it matters.
- `crates/avault-store` — the **master/VMK key store**. macOS Keychain when
  available, then the `file+mlock` baseline; Secure Enclave / TPM / KMS backends
  are selected by host capability once implemented. The X25519 keypair is
  ephemeral (in-memory), so only the master key needs durable storage.
- `crates/avault-cli` — the **`avault` binary**: one-shot CLI (P1) + resident agent (P2).

What avault owns vs. what Avibe owns: avault owns key material + crypto + its own store.
Avibe (Python) owns the `vault_secrets` DB (ciphertext + metadata), orchestration, REST/UI,
IM approval, audit. **avault never touches Avibe's SQLite**; the daemon passes it ciphertext
and gets back ciphertext/results.

## 3. Security model (the parts you must preserve)

- **Two trust roots, per secret:** *standard* (machine-rooted: hardware keystore or
  `file+mlock`; headless OK) and *protected* (human-rooted: VMK wrapped by passkey/password,
  unlockable only in the browser; no headless use). See DESIGN §4.
- **Blind box:** anything crossing the machine boundary is HPKE-sealed (RFC 9180,
  DHKEM-X25519-HKDF-SHA256 / AES-256-GCM) to avault's X25519 public key; only avault opens it.
- **Memory hygiene (the reason this is Rust):** `zeroize` on deterministic `Drop`,
  `subtle` constant-time compare, `mlock(2)` + `prctl(PR_SET_DUMPABLE,0)` + `madvise(MADV_DONTDUMP)`
  on key pages. Hold keys for the minimum window.
- **Never** log, print, or include secret/key bytes in errors. Errors describe *what failed*,
  not *what the value was*.

## 4. Interface & transport

Narrow verb set: `pubkey`, `seal`, `deliver` (run/fetch/inject), `sign`, `key export|import`,
and `agent` (resident: adds `grant`/`release` DEK-cache). Full contract in DESIGN Appendix C.

- **CLI (P1):** control via argv/JSON; bulk blobs (blind boxes, ciphertext) via **stdin**
  (keep them out of argv so they don't show in `ps`); results via **stdout** JSON.
- **Agent (P2):** unix socket `~/.avibe/run/avault.sock` (0600); length-prefixed JSON frames;
  authorize with `SO_PEERCRED` / `LOCAL_PEERCRED` (peer uid check) — **no shared token**.

## 5. Build, test, lint

```sh
cargo build
cargo test
cargo clippy --all-targets --all-features
cargo fmt
```

- Keep `avault-core` dependency-light and test-heavy: it's the auditable heart. Prefer
  table-driven tests + known-answer vectors; add a vector whenever you touch the wire format.
- Cross-language interop matters: the protected-tier wire format must match the browser
  implementation in Avibe (`ui/src/lib/vaultCrypto.ts`). When you change the format, update
  both and keep a shared test vector.

## 6. Coding standards

- Rust 2021, `rustfmt` defaults, no `clippy` warnings on changed code.
- `#![forbid(unsafe_code)]` in `avault-core`; `unsafe` is allowed only in `avault-store`
  (mlock/prctl/FFI) and must be commented with the invariant it upholds.
- Public functions are documented; secret-bearing types use `Zeroizing` / `#[derive(Zeroize)]`.
- Crypto primitives come from the pinned workspace deps (`aes-gcm`, `hkdf`, `zeroize`,
  `subtle`, …). Do not hand-roll primitives; do not add a second AEAD/KDF without a reason in
  DESIGN.

## 7. Workflow

- Use the `pr-delivery-loop` skill for every implementation task, including the
  reply-then-resolve review loop and exact-head close-out gate.
- Branch from `master`; small, focused commits; `type(scope): summary` messages.
- Open a PR for review; keep `docs/DESIGN.md` in sync when the design changes materially.
- This repo is consumed by Avibe — coordinate wire-format / interface changes with the
  Avibe-side integration (`avibe/docs/plans/avault-custody-core.md`).

## 8. Security & git hygiene

- Never commit keys, secrets, or test material that is actually sensitive.
- `*.key` / `*.pem` are git-ignored; keep it that way.
- Treat every change to the crypto core, the interface, or the trust boundary as
  security-sensitive: explain the threat-model impact in the PR.
