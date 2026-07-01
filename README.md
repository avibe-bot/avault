# avault

A small, hardened **Rust key-custody core** for [Avibe](https://github.com/avibe-bot/avibe) Vaults — the one component that ever holds a key or performs cryptography, so the agent (and Python) never do.

> **Status: P2 core.** The standard-tier Rust crypto core, macOS Keychain
> master-key store, Linux TPM2 sealed store, cross-platform file fallback,
> opt-in passphrase-wrapped file store, one-shot delivery surface, blind-box
> create path, secp256k1 signing verbs, and resident grant agent are
> implemented. Secure Enclave remains future work.

## Why

Avibe is a local-first agent OS: autonomous agents run on your machine and need secrets — API keys, DB passwords, signing keys. But the moment a secret value enters an LLM's context it leaks into transcripts, model context, and logs, and you can't get it back.

avault makes the split real:

> **The agent handles secret _names_; the platform handles secret _values_.** An agent can *use* a key (run a command, call an API, sign a tx) without ever *seeing* it.

## What it guarantees

- **Python never holds keys, never decrypts, never keeps reusable secret state.** It relays only ciphertext or **blind boxes** (sealed to avault). avault is the sole opener, and **plaintext only flows in — never back out**.
- **No `decrypt → plaintext` verb.** A value can only be *delivered* (into a child env / file / HTTP egress) or *signed*; it is never returned to the caller.
- **Two trust roots, chosen per secret:**
  - **Standard (machine-rooted):** master key in macOS Keychain when available, otherwise a hardware keystore / TPM where implemented, or the cross-platform file store fallback. Headless use OK. For API keys.
  - **Protected (human-rooted):** the root (VMK) is wrapped by a passkey/password and only the browser can unlock it; the machine alone cannot decrypt. No headless use. For signing keys & crown jewels.
- **Rust memory hygiene** Python structurally can't do: `zeroize` on `Drop`, constant-time compare (`subtle`), `mlock` / `VirtualLock` / no-coredump on key pages.

## Interface (deliberately narrow)

Implemented CLI surface:

```sh
avault seal --name OPENAI_API_KEY < value.txt
avault deliver run --name OPENAI_API_KEY --env OPENAI_API_KEY -- env
avault deliver run --name OPENAI_API_KEY --env OPENAI_API_KEY --envelope-file envelope.json -- env
avault deliver run -- env < run-secrets.json
avault deliver fetch < fetch-request.json
avault deliver inject < inject-request.json
avault key export < passphrase.txt
avault key import [--force] < import-request.json
avault pubkey
avault seal --name OPENAI_API_KEY --blind-box < blind-box.json
avault sign < sign-request.json
```

`seal` reads the value from stdin and writes envelope JSON on stdout:
`{ciphertext, nonce, wrap_meta}`. `wrap_meta` matches P0 Python's
`{"v":1,"scheme":"machine-aesgcm-v1","wrapped_dek":...,"dek_nonce":...}` shape.
New P1 writes authenticate the value with AAD bytes
`name || "machine-aesgcm-v1" || 0x01`; the shared KAT lives at
`crates/avault-core/tests/fixtures/p1_aad_vector.json`. Legacy P0 no-AAD rows are
read-compatible only.

The default standard-tier store is `auto`: macOS prefers a Keychain
generic-password item (`bot.avibe.avault` / `standard-master-key`), Linux uses a
TPM2 sealed blob when TPM2 is available, and other hosts use the file-store
fallback. When upgrading an existing macOS or Linux install that already has
`machine.key`, `auto` first loads that file key and mirrors it into the stronger
store instead of minting a replacement master key. If the stronger store is
unavailable, `auto` only uses the file fallback when an existing file key is
already present, or on first use when no stronger store exists. If both stores
exist but disagree, `auto` refuses to choose silently.

The Keychain item intentionally has no user-presence / biometry access-control
flag, so it stays suitable for headless standard-tier use after the OS session is
unlocked. macOS may still ask once to allow a newly installed `avault` binary to
access its Keychain item; that is the normal Keychain application-access prompt,
not a per-use Touch ID / passcode policy. Select `--store file` (or
`AVAULT_STORE=file`) to force the file store.

On Linux, the TPM backend stores `$AVAULT_HOME/machine.tpm.json` (or
`$HOME/.avibe/state/vault/machine.tpm.json`) containing only TPM2 public/private
sealed-object blobs. The plaintext master key is sealed and unsealed in-process
through TSS/ESAPI; it is not passed to `tpm2-tools` or another subprocess. This
requires a TPM 2.0 device reachable through the system TCTI configuration
(`TCTI` / `TPM2TOOLS_TCTI`, defaulting to `/dev/tpmrm0` then `/dev/tpm0`). It
does not attach PCR, password, PIN, or user-presence policy, so standard-tier use
remains headless while the OS user has TPM access. Select `--store tpm` (or
`AVAULT_STORE=tpm`) to require this backend explicitly; `auto` falls back to the
file store when TPM is unavailable.

The file store uses `$AVAULT_HOME/machine.key` when `AVAULT_HOME` is set, or
`$HOME/.avibe/state/vault/machine.key` by default, matching the P0 Python
basename. On Unix it requires a 0700 parent directory and a 0600 key file. On
Windows it sets and validates a protected owner-only DACL for the key directory
and key file (existing broad ACLs are rejected rather than silently rewritten).

For stronger at-rest protection on no-hardware hosts, select the opt-in
passphrase-wrapped store with `avault --store file-passphrase ...` or
`AVAULT_STORE=file-passphrase`. It stores
`$AVAULT_HOME/machine.passphrase.json` (or the default vault state path) containing
only a scrypt + AES-GCM wrapped master key. One-shot commands read the store
unlock passphrase from the first stdin line, then read the command's normal stdin
payload from the remaining bytes. The resident agent uses:

```sh
printf '%s\n' "$AVAULT_STORE_PASSPHRASE" | avault agent --store file-passphrase --unlock
```

This defends stolen disks/backups and same-uid file reads at rest; after unlock,
the plaintext master is intentionally resident in avault's locked memory until the
one-shot command exits or the agent restarts.

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
    "allowed_hosts": ["api.github.com"],
    "headers": { "Accept": "application/json" },
    "body": null,
    "inject": { "type": "bearer" }
  }
}
```

`inject` defaults to bearer auth; custom forms are
`{"type":"header","name":"X-Api-Key"}` and `{"type":"query","name":"api_key"}`.
`allowed_hosts` is required and must include the URL host before avault opens the
envelope; loopback hosts are not implicit. Output is response JSON
`{status, headers, body}`. `https` is required except for loopback `http`,
unsafe echo methods are rejected before decrypting, conflicting injected
header/query fields are rejected, transport errors are sanitized, and the
response body is capped. avault also best-effort redacts verbatim appearances of
the credential from the returned response body; encoded or transformed echoes are
outside that substring scrub, so `allowed_hosts` remains the authority boundary.

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

P1.1 implements `dotenv` and `json` files with atomic owner-only writes: 0600 on
Unix and a protected owner-only DACL on Windows. `yaml` and `toml` remain deferred.

`key export` reads a passphrase from stdin and emits the P0-compatible
`machine-key-export-v1` JSON blob. `key import` reads JSON from stdin:

```json
{
  "passphrase": "same passphrase",
  "blob": { "scheme": "machine-key-export-v1", "...": "..." }
}
```

`pubkey` emits `{public_key, fingerprint}` for HPKE blind boxes. `seal --blind-box`
reads `{"scheme":"hpke-x25519-hkdfsha256-aes256gcm-v1","enc":"...","ct":"..."}`
from stdin and returns the normal `{ciphertext, nonce, wrap_meta}` envelope.
Blind boxes are authenticated with operation-bound HPKE AAD (`purpose`, `name`,
scheme/version, optional scope, approval nonce/expiry, and a hash of the approved
operation), as pinned in `docs/DESIGN.md` and `tests/vectors/p2_core_crypto.json`.
Protected DEK blind boxes are accepted only by the resident agent, whose receiver
keypair is fresh in memory for that agent lifetime. Agent grant DEKs must include
an `approval` object `{nonce, expires_at_unix}`; grant approval nonces are
single-use until their approval expiry.
The one-shot CLI derives the receiver keypair from the local master key so `pubkey`
and `seal --blind-box` work across processes without persisting a new private key;
that master-derived key is for blind-box create only, not protected DEK release.

`sign` reads:

```json
{
  "name": "ETH_SIGNING_KEY",
  "key_envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." },
  "digest": "<hex 32-byte digest>",
  "scheme": "ecdsa-secp256k1-recoverable"
}
```

Supported schemes are `ecdsa-secp256k1-recoverable`, `ecdsa-secp256k1-der`, and
`schnorr-secp256k1-bip340`. Output is `{"signature":"<hex>","recovery_id":0|null}`.
avault signs exactly the caller-provided digest; chain-specific sighash construction
stays outside avault. One-shot `sign` is standard-tier only and rejects
`dek_blindbox` / `approval`; protected signing goes through the resident agent.
Protected DEK opens are AAD-only; the P0 empty-AAD read fallback applies only to
legacy standard-tier rows.

## How Avibe talks to it

Like the `askill` dependency: ensured by `vibe runtime prepare`, resolved on `PATH`, shown in Settings · Dependencies. Two transports:

- **CLI subprocess** — argv/JSON in, blobs via stdin, results via stdout.
- **Resident agent** — unix socket at `~/.avibe/run/avault.sock` (0600), length-prefixed JSON, authorized by `SO_PEERCRED` / `LOCAL_PEERCRED` (no shared token).

## Layout

```
crates/
  avault-core/    pure crypto: AEAD+AAD, DEK wrap, blind-box open, sign — no I/O, zeroized
  avault-store/   master/VMK store: macOS Keychain, file+mlock, file+passphrase → SE/TPM/KMS
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

- **P1** — `avault-core` + CLI + cross-platform file store; Rust takes the standard-tier seal/open. Closes the Python memory-hygiene gap.
- **P1.1** — complete standard-tier delivery: multi-secret run, brokered fetch, and atomic dotenv/json inject.
- **P2 Phase A** — blind-box create, secp256k1 digest signing, and pinned JSON contracts.
- **P2 Phase B/C** — resident agent + `SO_PEERCRED` + scope-grant DEK cache, protected deliver/sign, and opt-in file+passphrase store.
- **Future** — Secure Enclave and external signer providers behind the existing seams.

## License

MIT © The Vibe Remote Authors. See [`LICENSE`](LICENSE).
