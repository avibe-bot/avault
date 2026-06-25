# avault

A small, hardened **Rust key-custody core** for [Avibe](https://github.com/avibe-bot/avibe) Vaults — the one component that ever holds a key or performs cryptography, so the agent (and Python) never do.

> **Status: P1.1 standard-tier core.** The standard-tier Rust crypto core,
> `file+mlock` master-key store, and one-shot CLI delivery surface are implemented.
> The resident agent, pubkey/blind-box receiver, signer, protected tier, and
> hardware stores remain P2+.

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

P1.1 implements:

```sh
avault seal --name OPENAI_API_KEY < value.txt
avault deliver run --name OPENAI_API_KEY --env OPENAI_API_KEY -- env
avault deliver run --name OPENAI_API_KEY --env OPENAI_API_KEY --envelope-file envelope.json -- env
avault deliver run -- env < run-secrets.json
avault deliver fetch < fetch-request.json
avault deliver inject < inject-request.json
avault key export < passphrase.txt
avault key import [--force] < import-request.json
```

`seal` reads the value from stdin and writes envelope JSON on stdout:
`{ciphertext, nonce, wrap_meta}`. `wrap_meta` matches P0 Python's
`{"v":1,"scheme":"machine-aesgcm-v1","wrapped_dek":...,"dek_nonce":...}` shape.
New P1 writes authenticate the value with AAD bytes
`name || "machine-aesgcm-v1" || 0x01`; the shared KAT lives at
`crates/avault-core/tests/fixtures/p1_aad_vector.json`. Legacy P0 no-AAD rows are
read-compatible only.

The P1 file store uses `$AVAULT_HOME/machine.key` when `AVAULT_HOME` is set, or
`$HOME/.avibe/state/vault/machine.key` by default, matching the P0 Python basename.

`deliver run` reads envelope JSON from stdin by default, opens it with the local
master key, injects the value into the requested env var for the child command,
inherits stdout/stderr, and exits with the child's exit code. Because stdin is used
for the envelope in that mode, the child gets null stdin; use `--envelope-file` when
the child must inherit avault's stdin. There is no plaintext-printing `open` command.

The canonical P1.1 `deliver run` form accepts multiple secrets on stdin and spawns
one child with all env vars:

```json
[
  {
    "name": "OPENAI_API_KEY",
    "env": "OPENAI_API_KEY",
    "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." }
  }
]
```

`deliver fetch` performs brokered HTTP egress itself. Stdin is:

```json
{
  "name": "GITHUB_TOKEN",
  "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." },
  "request": {
    "method": "GET",
    "url": "https://api.github.com/user",
    "headers": { "Accept": "application/json" },
    "body": null,
    "inject": { "type": "bearer" }
  }
}
```

`inject` defaults to bearer auth; custom forms are
`{"type":"header","name":"X-Api-Key"}` and `{"type":"query","name":"api_key"}`.
Output is response JSON `{status, headers, body}`. `https` is required except
for loopback `http`, unsafe echo methods are rejected before decrypting, transport
errors are sanitized, and the response body is capped.

`deliver inject` accepts:

```json
{
  "path": "/path/to/secrets.env",
  "format": "dotenv",
  "secrets": [
    {
      "name": "OPENAI_API_KEY",
      "key": "OPENAI_API_KEY",
      "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." }
    }
  ]
}
```

P1.1 implements `dotenv` and `json` files with atomic 0600 writes; `yaml` and
`toml` remain deferred.

`key export` reads a passphrase from stdin and emits the P0-compatible
`machine-key-export-v1` JSON blob. `key import` reads JSON from stdin:

```json
{
  "passphrase": "same passphrase",
  "blob": { "scheme": "machine-key-export-v1", "...": "..." }
}
```

P2 stubs: `pubkey`, `sign`, and `agent`.

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

- **P1** — `avault-core` + CLI + `file+mlock` store; Rust takes the standard-tier seal/open. Closes the Python memory-hygiene gap.
- **P1.1** — complete standard-tier delivery: multi-secret run, brokered fetch, and atomic dotenv/json inject.
- **P2** — resident agent + `SO_PEERCRED` + scope-grant DEK cache + secp256k1 signer; hardware-store backends.
- **P3** — multi-factor (passkey-PRF, TPM, KMS); external signer (hardware wallet / WalletConnect).

## License

MIT © The Vibe Remote Authors. See [`LICENSE`](LICENSE).
