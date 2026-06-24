# avault

A small, hardened **Rust key-custody core** for [Avibe](https://github.com/avibe-bot/avibe) Vaults — the one component that ever holds a key or performs cryptography, so the agent (and Python) never do.

> **Status: early.** This repo is a scaffold + the authoritative design. The crypto is not implemented yet — see [`docs/DESIGN.md`](docs/DESIGN.md) and the roadmap below.

## Why

Avibe is a local-first agent OS: autonomous agents run on your machine and need secrets — API keys, DB passwords, signing keys. But the moment a secret value enters an LLM's context it leaks into transcripts, model context, and logs, and you can't get it back.

avault makes the split real:

> **The agent handles secret _names_; the platform handles secret _values_.** An agent can *use* a key (run a command, call an API, sign a tx) without ever *seeing* it.

## What it guarantees

- **Python never holds keys, never decrypts, never keeps reusable secret state.** It relays only ciphertext or **blind boxes** (sealed to avault). avault is the sole opener, and **plaintext only flows in — never back out**.
- **No `decrypt → plaintext` verb.** A value can only be *delivered* (into a child env / file / HTTP egress) or *signed*; it is never returned to the caller.
- **Two trust roots, chosen per secret:**
  - **Standard (machine-rooted):** master key in a hardware keystore (Keychain / Secure Enclave / TPM) or `file+mlock`. Headless use OK. For API keys.
  - **Protected (human-rooted):** the root (VMK) is wrapped by a passkey/password and only the browser can unlock it; the machine alone cannot decrypt. No headless use. For signing keys & crown jewels.
- **Rust memory hygiene** Python structurally can't do: `zeroize` on `Drop`, constant-time compare (`subtle`), `mlock` / no-coredump on key pages.

## Interface (deliberately narrow)

`pubkey` · `seal` · `deliver` (run/fetch/inject) · `sign` · `key export|import` — plus `agent` (resident, for grant DEK-cache + signing). Full table in [`docs/DESIGN.md`](docs/DESIGN.md) (Appendix C).

## How Avibe talks to it

Like the `askill` dependency: ensured by `vibe runtime prepare`, resolved on `PATH`, shown in Settings · Dependencies. Two transports:

- **CLI subprocess** (P1) — argv/JSON in, blobs via stdin, results via stdout.
- **Resident agent** (P2) — unix socket at `~/.avibe/run/avault.sock` (0600), length-prefixed JSON, authorized by `SO_PEERCRED` / `LOCAL_PEERCRED` (no shared token).

## Layout

```
crates/
  avault-core/    pure crypto: AEAD+AAD, DEK wrap, blind-box open, sign — no I/O, zeroized
  avault-store/   cross-platform master/VMK store: file+mlock → keychain/SE/TPM/KMS
  avault-cli/     the `avault` binary: one-shot CLI + resident agent
docs/
  DESIGN.md       the full custody-core design (authoritative)
```

## Build

```sh
cargo build
cargo test
cargo clippy --all-targets
```

## Roadmap

- **P1** — `avault-core` + CLI + `file+mlock` store; Rust takes the standard-tier seal/open; blind-box create. Closes the Python memory-hygiene gap.
- **P2** — resident agent + `SO_PEERCRED` + scope-grant DEK cache + secp256k1 signer; hardware-store backends.
- **P3** — multi-factor (passkey-PRF, TPM, KMS); external signer (hardware wallet / WalletConnect).

## License

MIT © The Vibe Remote Authors. See [`LICENSE`](LICENSE).
