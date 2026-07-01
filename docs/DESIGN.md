# avault — a Rust custody core for Avibe Vaults

**Status:** Approved · v1 design — this repo is the authoritative home of the design and its implementation.
**Owners:** Vaults workstream · **Upstream consumer:** [Avibe](https://github.com/avibe-bot/avibe) (Vaults)
**Related (in Avibe):** #631 (Vaults P0), #632 (the "base avibe on vt" proposal that prompted this), `avibe/docs/plans/avault-custody-core.md` (the Avibe-side integration notes).

> This document is the full custody-core design. The interactive walk-through lives on the Avibe Show Page; the Avibe-side integration plan (how the Python daemon calls into avault) is tracked in the Avibe repo.

---

## 0. TL;DR

Build **`avault`** — a small, hardened **Rust** key-custody core under the `avibe-bot` org — and make it the only component in Avibe that ever holds key material or performs cryptography. We write it fresh (we do **not** fork `vt`), but we borrow `vt`'s proven ideas: a pure crypto core (`derive_dek` / AEAD-with-AAD / `Zeroizing`) and the "agent-as-DEK-broker" release protocol.

Avibe (Python) keeps only **metadata and orchestration**. It never holds the master key, never decrypts, and never holds reusable secret state. The wire between Python and `avault` carries only **ciphertext** or **blobs sealed to `avault`** ("blind boxes") — never plaintext, never key material.

`avault` integrates the same way `askill` does: a dependency that `vibe runtime prepare` ensures, resolved on `PATH`, surfaced in Settings · Dependencies.

Two **trust roots**, chosen per secret:

- **Standard tier (machine-rooted):** the root key lives on the machine (hardware keystore where available, cross-platform file-store fallback). Headless use is allowed. Protects at-rest/disk-theft and keeps values out of the LLM, but does **not** survive a compromised machine.
- **Protected tier (human-rooted):** the root (VMK) is wrapped by a factor only the user can supply in the browser (passkey-PRF or password). The machine alone cannot decrypt. **No headless use.** Survives a compromised machine.

---

## 1. Background & motivation

### 1.1 Where Vaults P0 (#631) stands

P0 ships the **standard tier** in Python:

- Envelope encryption in `storage/vault_crypto.py`: a random per-secret DEK encrypts the value (AES-256-GCM); the DEK is wrapped under a 32-byte **machine key** at `~/.avibe/state/vault/machine.key` (mode 0600).
- Short-lived CLI processes (`vibe vault set/list/run/fetch/request/export/inject/key`) do direct-DB + direct-crypto; no daemon.
- Delivery modes: `run` (child env) and `fetch` (brokered HTTP); `export`/`inject` are help-only.
- The core invariant: **the model handles secret _names_; the platform handles secret _values_.** `$<NAME>` dynamic-ask wakes the agent with a name only; `vault_secrets` is denylisted in `data query`.

P0 is correct for what it is, and it should ship as-is. This document is about **P1+**.

### 1.2 The gaps P0 leaves open

1. **In-memory key hygiene (Python).** The machine key is an immutable `bytes`: it cannot be zeroized, it is copied into OpenSSL (a copy we do not control), and it is exposed to swap / coredump / ptrace with no `mlock` / `PR_SET_DUMPABLE` guard. This is a structural limit of Python's object model (immutability + GC + interning), not a patchable code smell.
2. **The protected tier needs a factor not on the machine.** P0 leans on a browser passkey, which is unavailable in headless / native / IM-only contexts.
3. **The signing oracle must stay outside Python.** Keypair signing (ETH/BTC secp256k1) belongs in `avault` behind the `SignerProvider` seam so Avibe can request signatures without ever receiving private keys.

### 1.3 Why a Rust custody core

For classic memory safety (no UAF/overflow) Python is already fine. The decisive difference is **secret-in-memory hygiene**: deterministic destruction, controlled copies, zeroization, page-locking, constant-time comparison. Python's object model structurally cannot deliver these; Rust can (`zeroize`, `subtle`, `mlock`).

The danger of weak hygiene scales with **how long a secret lives × how often it is reused × whether it is a key**:

- A **long-lived master key** held in Python is catastrophic — one key, alive for the whole daemon lifetime, unlocking every secret, un-zeroizable, GC-copied, swappable.
- A **transient single value** crossing one request handler is a different magnitude — bounded, single-secret, single-request.

The fix is therefore **not** "make sure no byte ever touches Python" (an absolutist claim that is impossible to fully honor and not the real issue). The fix is: **Python is never the component that holds keys, performs decryption, or keeps reusable secret state.** That is fully achievable, and it is what `avault` guarantees.

### 1.4 Why a fresh project, not a fork of `vt`

`vt` (≈6.7k LOC Rust) is an excellent reference and validates our design, but it is built for a different principal:

- Its **principal is a human at a Mac**; ours is an **autonomous agent**.
- Its **custody surface is macOS-only** (`server_macos/` is ≈54% of the codebase: Keychain, Secure Enclave/Touch ID, the 1.8k-LOC SSH-agent that also embeds its `AuthCache`, FIDO2). Only the ≈1.1k-LOC pure core (`derive_dek`, AEAD+AAD, the v2 envelope, `Zeroizing`) is cross-platform and directly reusable.
- Its trust anchor is **Touch ID**; ours must be **browser passkey/password + a cross-platform machine store**.
- Its signer is **SSH-agent (Ed25519/RSA/ECDSA)**; we need **secp256k1 (ETH)**.

Forking it means inheriting the macOS shell we would rip out, while still rebuilding the cross-platform custody we actually need. Writing fresh lets us own a clean core shaped to our model and borrow `vt`'s ≈1.1k-LOC of proven crypto ideas directly. (See Appendix A.)

---

## 2. Goals & non-goals

**Goals**

- One hardened Rust component is the sole holder of key material and sole crypto engine.
- Python never holds keys, never decrypts, never holds reusable secret state.
- Cross-platform (macOS / Linux / headless), local-first.
- Two explicit trust roots selectable per secret.
- Integrate as a `vibe runtime prepare` dependency, mirroring `askill`.
- An ETH-first signer with a path to hardware/external signers.

**Non-goals (now)**

- Replacing the P0 Python standard-tier path before P1 lands. P0 ships first.
- Third-party custody (MPC providers, WalletConnect, 1Password import) — deferred.
- A general multi-backend custody abstraction. We commit to one core (`avault`) behind the seam Vaults already designed; we do not build a plugin framework.

---

## 3. The fundamental law

> **Headless autonomous use ⟺ the decryption capability lives on the machine.**

If a secret must be usable by an unattended agent, the machine must be able to decrypt it without a human present — which means the key (or a path to it) is on the machine. You cannot have both "no human needed" and "key not on the machine." There is **no perfectly safe place** for a key that must support headless use; the honest answer is to **tier secrets by value** and pick the trust root per secret.

(Moving the root to a remote KMS/HSM only relocates the problem: the machine still holds a bootstrap credential to call it, and it breaks local-first. Noted as an escape hatch, not the default.)

---

## 4. The two trust roots (tiers)

### 4.1 Standard tier — machine-rooted

- **Where the key lives:** the strongest implemented OS store where available — macOS Keychain today, later Secure Enclave / Linux TPM — with the file-store floor as the headless fallback (0600 + `mlock` on Unix; protected owner-only DACL + `VirtualLock` on Windows).
- **How it decrypts:** `avault` asks the selected store to release/use the master key. The current macOS Keychain backend stores a regular generic-password item without user-presence / biometry access control, so standard-tier use stays headless after normal OS/keychain access is available. macOS may still ask once to allow a newly installed `avault` binary to access the Keychain item; that is not a per-use Touch ID / passcode policy. Future Secure Enclave / TPM backends can make the wrapping key non-extractable while still avoiding per-use human authentication.
- **Headless:** yes. This is the point of the tier.
- **What it protects:** at-rest encryption (a stolen disk/backup is useless); other processes (with a hardware store + ACL); swap/coredump; and values never enter the LLM, transcript, or Python's persistent state.
- **What it does _not_ protect:** a machine compromised under your own UID. An attacker running as you can, while you are present/unlocked, coerce a decryption. Hardware keystores make the key **non-extractable**, but **use can still be coerced while unlocked.** The real boundary here is the OS account + the hardware element, not cryptography.
- **Use it for:** API keys an agent uses headlessly.

### 4.2 Protected tier — human-rooted

- **Where the key lives:** the machine stores only the **wrapped VMK** (`wrapped_vmk`). The machine alone cannot unwrap it.
- **How it decrypts:** only in the browser, with the user's factor.
  - **Password:** `scrypt(password, salt)` → KEK → unwrap VMK locally (WebCrypto).
  - **Passkey:** WebAuthn **PRF extension** → the authenticator (Touch ID / security key) returns a stable per-credential secret → unwrap VMK. Without the physical authenticator + the user gesture, the VMK cannot be derived.
- **Headless:** no. Each use requires a live browser unlock ceremony.
- **What it protects:** disk/backup theft, **and a compromised machine** (the attacker cannot produce the passkey gesture).
- **Cost:** no unattended use.
- **Use it for:** signing keys and crown-jewel secrets.

| | Standard (machine-rooted) | Protected (human-rooted) |
|---|---|---|
| Root key at rest | master key in hardware keystore / cross-platform file store | only `wrapped_vmk`; machine can't open it |
| Unlock factor | none (OS account + hardware element) | passkey-PRF or password, **in browser** |
| Headless use | ✅ yes | ❌ no |
| Survives stolen disk | ✅ | ✅ |
| Survives compromised machine | ❌ | ✅ |
| Plaintext ever in Python | transient on create (acceptable) — or 0 with blind box | **never** |
| Typical secret | API keys | signing keys, crown jewels |

---

## 5. The blind-box boundary

`avault` holds a keypair; its **public key** is known to the browser. The rule:

> `avault` holds an **X25519** keypair; its public key is published to the browser via the daemon. Any sensitive datum that must cross the machine boundary is **sealed to that public key with HPKE** (RFC 9180 — DHKEM-X25519-HKDF-SHA256 / AES-256-GCM), producing an opaque envelope `{enc, ct‖tag}`. Python only ever relays a **blob it cannot open**. `avault` is the sole opener — and **plaintext only goes _into_ `avault`; it never comes back _out_ to Python.** `avault` returns only ciphertext, delivery side-effects, exit codes, or signatures. (Protected-tier callers must **pin / attest** `avault`'s public key — see §11.4.)

This makes "does a byte touch Python?" the wrong question. Python carries only blind boxes and ciphertext; the **keys** (machine key, VMK, DEKs, `avault`'s private key) are never in Python; and `avault`'s API is shaped so cleartext can never flow back to its caller.

### 5.1 What Python holds on each path

| Path | Source does | Python holds | `avault` does |
|---|---|---|---|
| Standard create | seals the value to `avault`'s pubkey | a blind box | open → re-wrap under machine key → returns **ciphertext** to store |
| Protected create | encrypts under VMK in the browser | ciphertext | not involved |
| Standard deliver | — | the DB ciphertext | unwrap with machine key → inject → returns **exit code** |
| Protected deliver | passkey unlock → releases the per-record **DEK**, sealed to `avault` | a blind box | open → decrypt DB ciphertext → deliver → returns **result** |

In every row Python holds only ciphertext or a blind box. (The standard-create row can instead accept a transient plaintext POST; see §11.3.)

---

## 6. Components & responsibilities

```
┌────────────┐   blind box / signature   ┌──────────────────────┐
│  Browser   │ ───────────────────────►  │  Avibe daemon (Py)    │
│ (factor,   │ ◄───────────────────────  │  metadata + relay     │
│  unlock,   │   avault pubkey, ciphertext└──────────┬───────────┘
│  signing)  │                                       │ blind box / ciphertext
└────────────┘                                       │ (never plaintext/keys)
                                                      ▼
                              ┌────────────────────────────────────┐
                              │  avault (Rust)                      │
                              │  • avault-core: AEAD+AAD, derive/   │
                              │    wrap DEK, Zeroizing              │
                              │  • avault-store: master/VMK store   │
                              │  • CLI (one-shot) + agent (resident)│
                              └───────┬───────────────┬─────────────┘
                                      │               │
                              master/VMK store     child process
                              (keychain/SE/TPM/      (env / file / HTTP egress)
                               file+mlock)
```

| | `avault` (Rust) | Avibe daemon (Python) |
|---|---|---|
| Key material | machine key / VMK / DEKs / its own keypair | **never holds any** |
| Crypto | seal, open, sign, release-DEK | **never performs any** |
| Storage | cross-platform master/VMK store | `vault_secrets` DB: ciphertext columns + all metadata |
| Metadata / orchestration | none | groups, tags, links, audit, requests, REST/UI, `$<NAME>`, IM approval cards, scope-grant bookkeeping |
| Delivery | run (child env) / fetch (HTTP egress) / inject (file) | initiates only; never touches plaintext |

The DB (`vault_secrets` and friends) stays Python-owned and is the source of truth for **metadata**. `avault` never touches SQLite; Python passes it ciphertext blobs and gets back ciphertext or results.

---

## 7. End-to-end flows

Running example: secret **`OPENAI_API_KEY`** (standard tier); task: over Slack you tell the agent "run `sync.py`," which needs the key.

Through-line legend: 🔓 plaintext · 📦 blind box (sealed to `avault`) · 🔒 ciphertext · 🗝️ key material.

### 7.1 Create

**Standard tier (blind-box variant, recommended):**

1. Browser collects name + value; 🔓 plaintext is in the browser only.
2. Browser **seals the value to `avault`'s pubkey** → 📦; `POST /api/vault/secrets` carries the blind box.
3. Daemon relays 📦 to `avault` (it cannot open it).
4. `avault`: open 📦 → read/unlock master key from the selected store → fresh DEK → AES-256-GCM encrypt (random nonce, **AAD = `name + scheme + version`**) → wrap DEK under master key → zeroize plaintext + DEK → return 🔒 `{ciphertext, nonce, wrap_meta}`.
5. Daemon writes the row to `vault_secrets` (ciphertext, wrap_meta, preview `…last4`, `protection=standard`, audit `created`). 🔒 only; no plaintext, no key persists in Python.

**Protected tier:** step 2 is the **browser encrypting under the VMK** (it unlocks the VMK with the passkey/password first, or uses an existing VMK session) and the POST body is already 🔒. Python never sees plaintext at all.

### 7.2 Authorize

The agent (a child process of the daemon) knows it needs the **name** `OPENAI_API_KEY`, not the value.

1. Agent invokes the use, e.g. `vibe vault run --env OPENAI_API_KEY -- python sync.py` — it passes the **name**.
2. Daemon checks for an active **grant** covering this secret / session / not expired.
   - **Hit (within TTL):** skip approval, go to §7.3.
   - **Miss:** the daemon pushes an **ApprovalCard** to the current session surface (Web chat card / IM interactive message):

     ```
     🔐 Agent wants to use a secret
     Session: #sync-task  (Claude Code)
     Secret:  OPENAI_API_KEY        ← name only, never the value
     For:     python sync.py        ← the exact command
     Egress:  local child process (no network)
     [✅ Approve once] [⏱️ 15 min · this session] [📦 group · 15 min] [🚫 Deny]
     ```
3. **Only the user, in the browser/IM, can approve.** Neither the agent nor the daemon can self-grant.
4. On approval the daemon records a **grant** `{scope_type, scope_ref, session_id, expires_at}`. Within the TTL the same session reusing the same scope is not re-prompted; a different session / secret / expiry re-prompts.

Honest boundary: this protects the value from entering the LLM context / transcript / Python, and lets the user **see the exact command** the agent will run. It is not a defense against a fully compromised agent the user blindly approves; the human-reviewed command is that line of defense.

### 7.3 Decrypt & deliver

**Standard tier:**

1. Grant active. Daemon reads the row's 🔒 ciphertext + wrap_meta from the DB and hands them to `avault` with "deliver via run, command = `python sync.py`."
2. `avault`: read master key → unwrap DEK → AES-GCM decrypt + verify AAD → 🔓 plaintext in a `Zeroizing` buffer.
3. `avault` **forks `python sync.py`** with `OPENAI_API_KEY=<plaintext>` in the child's environment, waits, then zeroizes plaintext + DEK.
4. Daemon receives only the **exit code** and writes a value-free `delivered` audit row.

🔓 plaintext lived only in `avault`'s memory (wiped) and in `sync.py`'s environment. It never entered Python, the LLM context, or Slack.

**`fetch` variant:** `avault` makes the HTTP request itself, attaching the secret at egress (header/bearer/query), and returns only the response body. The value never reaches a child env or Python.

**Protected tier (DEK blind-box):** see §8.2 — the browser releases the per-record **DEK** sealed to `avault`; `avault` decrypts the DB ciphertext and delivers; the value materializes only inside `avault` for that one approved use.

---

## 8. Signing & the protected tier specifics

The pivotal distinction:

> A secret **value** (API key) is itself secret and must reach a machine-side consumer. A **signature** is public — so you never need to move the private key. **Sign where the key is unlocked.**

### 8.1 What the browser produces — a key, not a value

On a protected unlock the browser releases the **per-record DEK** (scoped to the grant), **not** the plaintext value and **not** the VMK:

- Browser pipeline: factor → KEK → unwrap **VMK** → unwrap the secret's `wrapped_dek` → **DEK (32 bytes)**. It never needs the bulk ciphertext.
- Releasing the per-record DEK (least privilege) — not the VMK — means `avault` can decrypt exactly the approved secret(s), not everything.
- Keeping the value out of the browser JS heap is deliberate; the value should materialize in `avault`, not in the browser.

### 8.2 Delivering a protected value

Browser seals the DEK to `avault`'s pubkey → 📦 → daemon relays → `avault` opens, decrypts the DB ciphertext with the DEK, and delivers. For a scope grant, the browser releases the scope's DEK-set; `avault` caches it for the TTL (resident agent, §12). The value materializes only inside `avault`.

### 8.3 secp256k1 signing — sign a digest, not a transaction

`avault` is chain-agnostic: callers compute the exact 32-byte digest/sighash and
choose a named secp256k1 output scheme. Phase A implements:

- `ecdsa-secp256k1-recoverable` for ETH-style signatures (`r || s` plus recovery id).
- `ecdsa-secp256k1-der` for BTC legacy/SegWit DER signatures.
- `schnorr-secp256k1-bip340` for BTC Taproot.

Standard-tier signing unwraps a signing-key envelope with the machine master key.
Protected-tier signing opens a browser-released DEK blind box, uses that DEK to
open the signing-key envelope, signs the digest, and wipes the private key. In all
cases the private key never leaves `avault`; the output signature is public.

Honest constraints:

- **secp256k1 is not supported by Secure Enclave / passkeys (all P-256).** A local
  secp256k1 key is therefore software key material once its envelope is opened.
  Hardware-wallet / WalletConnect support belongs behind the deferred `external`
  `SignerProvider` seam.
- Protected-tier local signing still materializes the private key inside `avault`
  for one operation. The protected boundary is that Python never receives the key
  or plaintext and the machine cannot open the key envelope until the browser
  releases the per-record DEK blind box.

### 8.4 If you want unattended signing

Set the signing key to the **standard tier** and have **`avault` sign** with a
machine-rooted key. Weaker (the machine can sign while you are away) but enables
automation. Choose the tier by the signing key's value.

This maps onto the `SignerProvider` ladder: **local** (`avault` opens the signing
key envelope and signs) → **external** (hardware wallet, strongest, deferred) →
**mpc** (deferred). Ed25519-class chains are a direct local extension later; they
are out of scope for Phase A.

Unifying principle:

> **Value → browser releases the DEK; `avault` decrypts & delivers (value materializes in `avault`).**
> **Signature → sign at the unlock point (browser); return only the signature (the private key never moves).**

---

## 9. Authorization & grants

- **ApprovalCard** (§7.2) is rendered on the current session's surface (Web chat / IM). It shows the agent/session, the secret **name**, the exact command/host, the requested scope, and TTL options. It never shows the value.
- **Scope-typed grants:** `{scope_type ∈ {secret, group, …}, scope_ref, session_id, expires_at}`. Recorded by the daemon; suppress re-prompts within the TTL.
- **DEK cache (resident agent, P2):** after the first release, `avault` caches the unwrapped DEK-set for the grant TTL. Repeated uses in the window don't re-hit the store or re-prompt. The daemon proves it is the authorized caller via `SO_PEERCRED` (peer credential on the socket) — not a shared token. On expiry the cache is cleared and zeroized.

Generalized from `vt`'s `AuthCache` rigor: strict TTL with **no** sliding refresh, idempotent grants, PID-reuse defense, lock-clears-the-cache — but re-keyed from `{TTY/app}` to `{scope_type, scope_ref, session_id}` and fed by the UI/IM approval path alongside (or instead of) a biometric one.

---

## 10. Envelope & crypto

- **Keep the P0 `wrap_meta` column shape** (`{scheme, wrapped_dek, dek_nonce}`): storing `wrapped_dek` gives **cheap master rotation** (re-wrap DEKs without touching ciphertext) and does not break the P0 DB. We do **not** adopt `vt`'s pure-derive model (`derive_dek(master, salt)` with nothing stored), which forces a full re-encrypt on every master rotation. The hygiene win comes from Rust owning the key + crypto, which is orthogonal to the envelope shape.
- **Borrow from `vt`:** AES-256-GCM with **AAD binding `name + scheme + version`** (so ciphertext can't be transplanted between records), HKDF-based DEK derivation where applicable, decrypt results in `Zeroizing`, constant-time compare (`subtle`).
- **Protected tier:** VMK wrapped by N factor-copies (password via scrypt; passkey-PRF copies added browser-side), each secret's DEK wrapped by the VMK — the format already prototyped in `storage/vault_protected.py` and `ui/src/lib/vaultCrypto.ts`, now produced/consumed across the browser ↔ `avault` boundary.

---

## 11. Memory hygiene — why Rust, and the honest residuals

### 11.1 Why Python can't

- `bytes`/`str` are **immutable** → no in-place overwrite; you wait for GC and can't verify erasure.
- GC may **move/copy** objects; small strings may be **interned**.
- Passing into the crypto lib makes an **OpenSSL C-side copy** Python doesn't manage.
- No `mlock` → pages can **swap** to disk; no `PR_SET_DUMPABLE=0` → **coredump/ptrace** can read it.

For a **long-lived master key** every one of these is exposed for the whole daemon lifetime. That is the structural problem.

### 11.2 Why Rust can

`Zeroizing<…>` buffers wiped on deterministic `Drop`; constant-time comparison (`subtle`); `mlock` + `PR_SET_DUMPABLE(0)` on the key pages; tight control over copies. `avault` holds keys for the minimum window and wipes them.

### 11.3 The honest residual on standard-create

If standard-create takes a **plaintext POST** (no blind box), the value exists as one transient `bytes` in one Python request — un-zeroizable, briefly swappable. It is bounded (single value, single request, not reused) and the daemon is **in-boundary for the standard tier anyway** (it can ask `avault` to decrypt any standard secret). So it is an acceptable, minimized residual — or eliminated entirely by the **blind-box create** (§7.1), which is the recommended default.

### 11.4 The other honest caveat — pubkey integrity

The blind box assumes the browser gets `avault`'s **genuine** public key. A fully compromised daemon could substitute its own key when relaying. For the **standard tier** the daemon is in-boundary (not in the threat model). For the **protected tier** (where a compromised daemon _is_ in scope), `avault`'s pubkey must be **pinned / attested** (TOFU + pin, or shown to the user) — an explicit control, called out, not buried.

---

## 12. Integration model — like `askill`

`askill` is the precedent: a required local dependency that `vibe runtime prepare` ensures (`ensure_askill_installed`), resolved via `resolve_cli_path("askill")`, reported by `askill_status()`, surfaced in **Settings · Dependencies**, with a managed auto-reconcile loop.

`avault` mirrors the **touchpoints** exactly:

- `vibe runtime prepare` → `ensure_avault_installed` (idempotent; skipped under `--offline`).
- `resolve_cli_path("avault")` on `PATH`; config `agents.avault.cli_path`.
- `avault_status()` → installed / version / path, shown as a Settings · Dependencies card.

**Distribution — decided: a real manifest-pinned release pipeline (not `askill`'s `curl | sh`).** A custody binary is version-sensitive (client/agent must match), so it ships like Show Runtime: per-platform prebuilt `avault` binaries attached to the avibe release, **version-pinned by a manifest**; `vibe runtime prepare` downloads the right platform asset, verifies its checksum, and installs it. Build the full delivery path **stub-first** (wire avibe → download → `PATH` → Settings card against the current stub binary), then implement the crypto behind it — no throwaway dev installer. Targets: `macos-arm64` + `linux-x64` first; **macOS code-signing / notarization is an explicit pipeline sub-task**. The avault repo owns building/releasing the binaries; avibe pins the compatible version.

**Two run modes (same binary) — and which is safer:**

1. **CLI one-shot (P1):** the daemon spawns `avault seal/open/...`; it reads the master key, uses it, wipes it on `Drop`, exits. **This is the more conservative transport** — no listening endpoint to defend, and the key is in memory only for the op (a tiny window).
2. **Resident agent (P2):** `avault agent` listens on a unix socket, holds the grant DEK-set for its TTL, and is the signing oracle. It is **strictly more exposed** (a long-lived key in memory + a socket to defend), so it is used only where cross-call state is required (grant DEK-cache, signing). Harden it: short **idle-timeout zeroize**, cache **DEKs not the master 24/7** (read the master transiently to unwrap, then wipe), `mlock` + no-coredump, and `SO_PEERCRED` / `LOCAL_PEERCRED` peer-uid auth (no shared token).

Peer-cred gates *other users* and remote, not a same-uid process — which is correct, because the standard tier's boundary is the OS account anyway (§4.1). Same-uid misuse is bounded by the narrow interface (no `decrypt → plaintext`), full audit, hardware non-extractability, and — for high-value secrets — the protected tier (cryptographic enforcement, not caller-auth).

**Ingest without Python reading plaintext:** for the CLI `set` path, pass stdin's **file descriptor** straight to the `avault` subprocess (Python never `read()`s the bytes). For the web path, the browser uses the blind box (§7.1).

---

## 13. Cross-platform key stores

`avault-store` selects the strongest local store available. Order (strongest first):

- **Hardware / OS / cloud (strongest roots):** macOS **Keychain** is implemented as the default `auto` backend. Secure Enclave wrapping, Linux **TPM 2.0** (seal/unseal, optional PCR/auth binding), and cloud **KMS** KEK remain backend extensions. Hardware wrapping keys can be non-extractable and still avoid per-use human authentication, which is what standard-tier auto-restart needs.
- **`file + passphrase` (P2 — the cloud/no-hardware sweet spot):** wrap the master key under a KEK derived from an operator passphrase (`scrypt` today, matching `key export`); store only `wrapped_master`, so **the plaintext master never touches disk**. Select it explicitly with `--store file-passphrase` (or `AVAULT_STORE=file-passphrase`). One-shot CLI commands read the store unlock passphrase from the **first stdin line**, then read the command's existing stdin payload from the remaining bytes. The resident agent uses `avault agent --store file-passphrase --unlock`, reads the passphrase once at startup, unlocks into `mlock`'d memory, and holds that master for the agent lifetime. Same "wrap the root under a factor-KEK" idea as the protected-tier VMK, applied to the standard master. *Honest limits:* it defends **at-rest** (stolen disk / leaked backup / same-uid file read are useless without the passphrase) but **not the running machine** (after unlock the master is in memory); and it needs a human passphrase **per restart**, trading fully-unattended auto-restart for at-rest safety.
- **File store + memory lock — P1 baseline / floor:** works headless on Linux, macOS, and Windows. Unix uses a 0700 parent directory, 0600 key file, `mlock`, and no-coredump hardening. Windows uses a protected owner-only DACL on the key directory/key file plus best-effort `VirtualLock` and crash-dump hardening. Existing broad modes/ACLs are rejected rather than silently tightened. At-rest the key file is **plaintext** (protected only by the OS account + page-lock/no-coredump hardening), so it is the floor, not a strong at-rest guarantee.

This is an internal store selection inside `avault`, not an Avibe-level plugin layer.

---

## 14. Project shape

- **Repo:** `avibe-bot/avault` (name settled — see §16).
- **Cargo workspace:**

  ```
  avault/
  ├─ crates/
  │  ├─ avault-core/    # pure crypto: AEAD+AAD, derive/wrap DEK, envelope, Zeroizing. No I/O, no platform deps. Unit-tested, auditable.
  │  ├─ avault-store/   # cross-platform master/VMK store: file+mlock / Windows DACL (P1) → keychain/SE/TPM/KMS
  │  └─ avault-cli/     # the `avault` binary: one-shot ops + the resident agent
  └─ ...
  ```

- `avault-core` is the auditable heart; it borrows `vt`'s proven crypto shapes and has no platform or I/O dependencies.

---

## 15. Roadmap

| Phase | Scope | State |
|---|---|---|
| **P0** | Python standard tier: DB + envelope + delivery + `$<NAME>` (#631) | superseded by P1 |
| **P1 / P1.1** | `avault-core` + CLI + cross-platform file store; Rust takes standard-tier seal/open + `deliver run`/`fetch`/`inject`; `vibe runtime prepare` ensure + Dependencies card. Closes the memory-hygiene gap. | done |
| **P2 — the final trust model, in one shot (no P3)** | Delivered as one reviewed avault re-submission after the unreviewed Phase A/B merges were reverted; nothing ships as a half-released transition state. | in review |
| · **Phase A** | HPKE blind-box `open` / `open_with_dek`, `pubkey`, `seal --blind-box`, secp256k1 digest signing (`ecdsa-secp256k1-recoverable` = ETH, `ecdsa-secp256k1-der` = BTC legacy/SegWit, `schnorr-secp256k1-bip340` = BTC Taproot), `SignerProvider` seam, pinned JSON contracts (Appendix C). | in review |
| · **Phase B** | Resident agent: unix socket + `SO_PEERCRED` / `LOCAL_PEERCRED`, fresh in-memory receiver keypair, scope-typed grant DEK-cache (strict TTL + idle-zeroize), signing oracle; protected-tier `deliver` (browser-released DEK blind box). | in review |
| · **Phase C** | `file + passphrase` master store (passphrase-wrapped master, unlock once at startup). | in review |
| · **avibe + browser** | Same one-shot P2, separate tracks. Python: protected create/resolve, blind-box create relay, scope-typed grants, approval / secure-input cards, signing relay. Browser: HPKE seal, VMK/DEK with passkey-PRF + password, browser ETH/BTC signing. | in progress |
| **Plugin seams** (not a phase) | Additional hardware stores (Secure Enclave / TPM / KMS), external signers (hardware wallet / WalletConnect), MPC, and other curves (e.g. ed25519) — drop in behind the `KeyStore` / `SignerProvider` traits when the need or hardware is real. Adding one is a plugin, never a migration or a released transition. | as needed |

**P2 is the entire final Vaults trust model, built in one shot — there is no separate P3
and no half-released transition state.** It lands as reviewable sub-phases (avault A/B/C
plus the avibe Python and browser tracks) that compose into the final design. The
standard-create transient-plaintext-in-Python residual (§11.3) is eliminated by the
blind-box create path (Phase A). Curves this round are **secp256k1** (ETH + BTC); ed25519
is a direct local add when a chain needs it, not a plugin. The one-shot CLI derives its
blind-box receiver key from the master (HKDF, domain-separated); the resident agent uses a
fresh in-memory receiver keypair that the browser pins/attests (§11.4).

---

## 16. Decisions (settled 2026-06-25)

1. **Name → `avault`.** Short, ownable; already the repo / binary / crate prefix. Not published to crates.io, so no registry-name collision concern.
2. **Envelope → wrapped_dek (Scheme A).** Random per-record DEK, wrapped under the root (master / VMK); store `wrapped_dek`. Cheap rotation (re-wrap, never re-encrypt), no DB break, and it unifies the standard + protected envelopes. The protected tier extends it with **N `wrapped_vmk` factor-copies** (password via `scrypt`, passkey via WebAuthn-PRF, second device, recovery code) — **any one factor unlocks the same random VMK**, and add / remove / change-password is a re-wrap of the VMK, not a re-encrypt of data. The only "derive" is *factor → KEK*; the DEK and VMK are random and wrapped. (Rejected: `vt`'s pure-derive — forces full re-encrypt on rotation and a second envelope format.)
3. **Distribution → a real manifest-pinned release pipeline**, version-locked to the avibe release (Show-Runtime model); build the full path **stub-first**; current required targets are `macos-arm64`, `macos-x64`, `linux-x64`, `linux-arm64`, and `windows-x64`, with `windows-arm64` best-effort. macOS signing/notarization is an explicit sub-task. (Rejected: `curl | sh` and any throwaway dev installer.)
4. **P1 scope → standard-tier CLI core.** In: `avault-core` seal/open (AES-256-GCM + wrapped_dek + AAD), `avault-store` cross-platform file store, `avault-cli` (`seal` via stdin, `deliver run`, `key export/import`), the stub-first delivery pipeline, and the avibe-side wiring (route `vault_crypto.py`'s standard value path through avault; `vault_secrets` stays the metadata source of truth). P1.1 pulls the remaining standard-tier delivery modes (`deliver fetch`, `deliver inject`) forward so Avibe can remove the Python open path all at once. Out → P2: resident agent, scope grants + approval-card UX, signing, the protected tier, hardware/passphrase stores. The standard-create transient-plaintext-in-Python residual stays in P1 (§11.3); the blind box eliminates it in P2.
5. **Protected-tier pubkey trust → deferred to P2** (the protected tier itself is P2). Lean **attest** (sign the ephemeral X25519 pubkey with an identity key the browser already trusts) — it pairs with the ephemeral-keypair choice and defeats first-use MITM; interim **pin** (TOFU) is acceptable. Not on the P1 path.
6. **Transport safety → CLI is the conservative default (P1); the resident agent (P2) is a deliberate, hardened tradeoff.** CLI has no listening surface and a tiny key-in-memory window. The agent (for grant-cache + signing only) is more exposed → idle-timeout zeroize, cache DEKs not the master 24/7, `mlock` + no-coredump, peer-cred auth. See §12.
7. **Master-key store on no-hardware hosts → add `file + passphrase`** (passphrase-wrapped master, unlock once at startup; plaintext never on disk). The cloud/no-TPM sweet spot; defends at-rest, not the running machine; P2, pairs with the agent or the Linux kernel keyring. See §13.

---

## 17. Honest residuals (collected)

- **Standard-create transient plaintext** in Python if not using the blind box — bounded, acceptable, or eliminated by blind-box create (§11.3).
- **`avault` pubkey distribution integrity** — in-boundary for standard; needs pin/attest for protected (§11.4).
- **Standard tier ≠ machine-compromise resistance** — it is at-rest + use-gating + no-LLM-exposure, not "safe if the box is owned" (§4.1).
- **Browser JS hygiene** is best-effort (wipeable typed arrays, non-extractable WebCrypto keys), not a secure enclave; exposure is one operation while the user is present (§8.3).
- **secp256k1 is not hardware-backed** on Apple SE / passkeys — software key + hardware unlock factor; true hardware custody needs an external wallet (§8.3).
- **`file + passphrase` defends at-rest, not the running machine** — after the startup unlock the master is in memory; and it needs a passphrase per restart (trades unattended auto-restart for at-rest safety). For fully-unattended servers use TPM/KMS (§13).
- **The resident agent (P2) widens exposure** vs the one-shot CLI (long-lived key in memory + a socket); mitigated by idle-timeout zeroize, DEK-not-master residency, mlock/no-dump, peer-cred auth (§12).

---

## Appendix A — relationship to `vt`

**Borrow (the ≈1.1k-LOC pure core ideas):** `AesGcmCrypto`, `derive_dek` (HKDF), the AEAD-with-AAD discipline, the v2 envelope + **DEK-release** protocol, `AuthCache`'s rigor (as our grant cache), and the zeroize discipline throughout.

**Don't inherit (the ≈3.6k-LOC macOS shell):** the Keychain-only store, the SSH-agent user surface, FIDO2 enrollment, TOTP, the remote-sudo PAM path, the `VT_AUTH` shared-token channel, and the legacy `vt://mac` format.

**Build fresh for us:** cross-platform store (file-store floor → keychain/SE/TPM/KMS), per-record standard/protected policy, `SO_PEERCRED` daemon authorization, scope-typed grants fed by UI/IM approval, the `name+scheme+version` AAD aligned to our columns, a secp256k1 signer, and the `SignerProvider` seam for later external signers.

Net: `vt` proves the model and donates the crypto shapes; `avault` is the clean, cross-platform, agent-shaped custody core those shapes belong in.

---

## Appendix B — cryptographic primitives (review reference)

Concrete, implementation-ready values for every step.

| Step | Primitive / parameters |
|---|---|
| Symmetric AEAD | AES-256-GCM · 96-bit nonce · 128-bit tag |
| DEK / master / VMK | 256-bit, CSPRNG |
| DEK wrap | AES-256-GCM key-wrap (under master key or VMK) |
| AAD binding | `name ‖ scheme ‖ version` |
| Blind-box sealing | HPKE (RFC 9180) · DHKEM-X25519-HKDF-SHA256 · AES-256-GCM → `{enc, ct‖tag}` |
| Password KDF | scrypt `N=2^15, r=8, p=1` → 256-bit KEK |
| Passkey factor | WebAuthn PRF extension (CTAP2 `hmac-secret`) → 32 B → KEK |
| Signing | ECDSA / secp256k1 · EIP-155 / EIP-1559 · keccak256 digest |
| Browser libs | `@noble/curves`, `@noble/hashes`, WebCrypto |
| Rust libs | `aes-gcm`, `hkdf`, `hpke`, `x25519-dalek`, `k256`, `zeroize`, `subtle` |
| Resident-agent auth | `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) on the unix socket |
| Memory hardening | `mlock(2)` · `prctl(PR_SET_DUMPABLE, 0)` · `madvise(MADV_DONTDUMP)` |
| At-rest storage | SQLite, base64 text columns (`ciphertext` / `nonce` / `wrap_meta`) |

These are starting recommendations, not frozen choices — items #2 (envelope) and #5 (pubkey trust) in §16 may still move them.

---

## Appendix C — avault interface & transport

### Minimal interface

`avault` exposes a deliberately narrow verb set. The defining property: **there is no `decrypt → plaintext` verb.** Plaintext only goes _in_ (sealed); it can only be *delivered* or *signed*, never returned to the caller.

| Verb | Input | Output | Purpose |
|---|---|---|---|
| `pubkey` | — | X25519 public key + fingerprint | one-shot `pubkey` supports blind-box create; protected DEK release uses the resident agent's ephemeral `pubkey` frame |
| `seal` | blind box (the value) + name/scheme | envelope `{ciphertext, nonce, wrap_meta}` | standard-tier create: open box → wrap DEK under master → return ciphertext (never plaintext). The CLI plaintext-stdin path remains for local `set` / fd passthrough. |
| `deliver` | envelope + mode (`run` / `fetch` / `inject`) | exit code / response body / written file | one-shot standard-tier delivery uses the master key; protected delivery uses resident-agent grants, never inline DEK boxes |
| `sign` | key envelope + name + 32-byte digest + scheme | signature (public) | one-shot standard-tier signing; protected signing uses resident-agent grants. The private key never leaves `avault` |
| `key export` / `key import` | passphrase (stdin; if `--store file-passphrase`, first stdin line unlocks the store) | encrypted backup / ok | back up, migrate, restore the master key |

Phase A implements the core blind-box opener and secp256k1 signer plus one-shot CLI
verbs. Phase B adds the resident agent transport plus `grant` / `release`: cache a
scope's DEK-set for a TTL so repeated uses in-window skip re-unlock. Signing is
chain-agnostic: callers provide the exact 32-byte digest/sighash and select the
signature encoding.

### Phase A blind-box and signing schemas

Byte strings in this section are encoded as standard base64 unless explicitly
marked hex. The HPKE blind-box ciphersuite is RFC 9180 Base mode with
DHKEM-X25519-HKDF-SHA256, HKDF-SHA256, and AES-256-GCM. The JSON scheme identifier
is `hpke-x25519-hkdfsha256-aes256gcm-v1`. HPKE `info` is the UTF-8 bytes
`avault:blind-box:v1`.

Every blind box is authenticated with operation-bound HPKE AAD; a box approved
for one operation must not open for another name, scope, or signing digest. The
AAD is:

```text
"avault:blind-box:aad:v1"
  || field(purpose)
  || field(name)
  || field("machine-aesgcm-v1")
  || field(0x01)
  || field(scope_type or "")
  || field(scope_ref or "")
  || field(sign_scheme or "")
  || field(digest or "")
  || field(approval_nonce or "")
  || field(approval_expires_at_unix_be or "")
  || field(operation_hash or "")
```

`field(x)` is `uint32_be(len(x)) || x`. Strings are UTF-8 bytes; `digest` is the
raw 32-byte signing digest, not hex text. `approval_expires_at_unix_be` is an
8-byte unsigned big-endian Unix timestamp. `operation_hash` is the 32-byte
SHA-256 digest of the approved operation fields encoded the same way:
`SHA256(field(part0) || field(part1) || ...)`.

Protected agent-grant DEK blind boxes require approval metadata:

```json
{ "nonce": "<base64 16..128 random bytes>", "expires_at_unix": 4102444800 }
```

The approval nonce/expiry are authenticated in the HPKE AAD. The resident agent
rejects expired approvals and replayed grant nonces until their approval expiry.
Protected DEK blind boxes are accepted only by the resident agent, whose receiver
keypair is fresh in memory for that agent lifetime. The one-shot CLI rejects
`dek_blindbox` / `approval` fields because its `pubkey` compatibility path is
master-derived and therefore not ephemeral. Current `purpose` and
`operation_hash` values:

| Operation | `purpose` | Required AAD context | `operation_hash` fields |
|---|---|---|---|
| `seal --blind-box` | `seal` | `name` | empty |
| agent delivery grant | `agent-deliver` | `scope_type`, `scope_ref`, `name`, approval, `ttl_secs` | `"agent-deliver"`, name, `ttl_secs_u64_be` |
| agent signing grant | `agent-sign` | `scope_type`, `scope_ref`, `name`, `sign_scheme`, `digest`, approval, `ttl_secs` | `"agent-sign"`, scheme, raw 32-byte digest, `ttl_secs_u64_be` |

These values and example AAD bytes are pinned in
`tests/vectors/p2_core_crypto.json`.

`pubkey` emits:

```json
{
  "public_key": "<base64 raw 32-byte X25519 public key>",
  "fingerprint": "<lowercase hex SHA-256 of the raw public key>"
}
```

The resident agent uses a fresh in-memory X25519 receiver keypair for its process
lifetime and never writes the private key to disk. The one-shot CLI cannot keep a
random private key across separate `pubkey` and `seal` processes, so its
compatibility path derives the receiver keypair from the local master key with
HKDF and drops it after each operation. The derived private key is still never
written or returned; the public key is stable for that master key and is only for
the blind-box create path. Protected-tier DEK releases must use the resident
agent's ephemeral `pubkey` frame.

`seal --name NAME --blind-box` reads a blind box from stdin:

```json
{
  "scheme": "hpke-x25519-hkdfsha256-aes256gcm-v1",
  "enc": "<base64 HPKE encapsulated key>",
  "ct": "<base64 HPKE ciphertext || tag>"
}
```

It opens the blind box inside `avault`, then writes the normal persisted envelope:

```json
{
  "ciphertext": "<base64 AES-GCM ciphertext || tag>",
  "nonce": "<base64 12-byte value nonce>",
  "wrap_meta": "{\"v\":1,\"scheme\":\"machine-aesgcm-v1\",\"wrapped_dek\":\"...\",\"dek_nonce\":\"...\"}"
}
```

The legacy/local CLI path `seal --name NAME < value` remains available for direct
file-descriptor passthrough from Avibe's local `set` path. In both paths, new
envelopes authenticate value ciphertext with AAD
`name || "machine-aesgcm-v1" || 0x01`.

`sign` reads one JSON object from stdin:

```json
{
  "name": "ETH_SIGNING_KEY",
  "key_envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." },
  "digest": "<lowercase or uppercase hex 32-byte digest>",
  "scheme": "ecdsa-secp256k1-recoverable"
}
```

`name` is required because it is the AAD name for `key_envelope`; omitting it would
remove the envelope transplant protection. One-shot `sign` is standard-tier only:
it unwraps the key envelope with the machine master key and rejects
`dek_blindbox` / `approval` fields. Protected signing uses the resident agent's
`grant` + `sign` frames; protected DEK opens require the normal
`name || "machine-aesgcm-v1" || 0x01` envelope AAD and never take the P0
empty-AAD read-compatibility fallback.

Supported `scheme` values:

| Scheme | Digest input | Signature output | `recovery_id` |
|---|---|---|---|
| `ecdsa-secp256k1-recoverable` | exactly 32 bytes, caller-computed | hex 64-byte `r || s`, low-S normalized | integer `0..3` |
| `ecdsa-secp256k1-der` | exactly 32 bytes, caller-computed | hex DER-encoded ECDSA signature | `null` |
| `schnorr-secp256k1-bip340` | exactly 32 bytes, caller-computed | hex 64-byte BIP340 Schnorr signature | `null` |

Output:

```json
{
  "signature": "<hex signature bytes>",
  "recovery_id": 0
}
```

Known-answer fixtures for HPKE open and all three signing schemes live in
`tests/vectors/p2_core_crypto.json`; browser `@noble/curves` tests should assert
the same vectors. Production Schnorr signing uses fresh auxiliary randomness;
the fixture records `schnorr_aux_rand_hex` only to make the cross-implementation
test deterministic.

### P1.1 CLI delivery schemas

All P1.1 delivery inputs are JSON on stdin. The `envelope` object is the persisted
`{ciphertext, nonce, wrap_meta}` shape. The `name` field is the secret name used for
AAD. Values never appear in argv. One-shot delivery is standard-tier only and
rejects `dek_blindbox` / `approval` fields. Protected delivery uses the resident
agent's `grant` + `deliver` frames; the protected DEK path is AAD-only, and the
P0 empty-AAD fallback is only for old standard-tier master-key rows.

`deliver run` accepts a JSON array and spawns exactly one child:

```json
[
  {
    "name": "OPENAI_API_KEY",
    "env": "OPENAI_API_KEY",
    "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." }
  }
]
```

The legacy single-secret form remains available:
`avault deliver run --name NAME --env VAR [--envelope-file PATH] -- COMMAND`.

`deliver fetch` accepts one secret plus a request spec:

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

`inject` defaults to `{"type":"bearer"}` and sets `Authorization: Bearer <secret>`.
Custom header and query forms are `{"type":"header","name":"X-Api-Key"}` and
`{"type":"query","name":"api_key"}`. `allowed_hosts` is required and must contain
the URL host (case-insensitive); loopback hosts are only allowed when explicitly
listed. The URL is validated before decrypting: `https` is required except for
loopback `http`, and `TRACE` / `TRACK` / `CONNECT` are rejected because they can
echo credentials. Conflicting injected headers/query parameters are rejected
before the secret is opened. Header credentials trim one trailing CR or LF, then
reject remaining HTTP control bytes before ureq receives a header copy. Output is
JSON: `{"status":200,"headers":{...},"body":"..."}`. Fetch uses bounded connect,
read, write, and overall timeouts; transport errors are sanitized so injected
credentials cannot appear in stderr, and the response body is capped. Before
returning the body, avault performs a best-effort verbatim byte redaction of the
credential. This only covers direct substring echoes; encoded/transformed echoes
are intentionally left to the `allowed_hosts` policy boundary.

`deliver inject` accepts a target file, a format, and a secret array:

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

`key` names the rendered entry, and `env` is accepted as an alias. P1.1 implements
`dotenv` and `json`; `yaml` and `toml` remain deferred. Files are written
atomically through an owner-only temporary file, fsync, rename, and
parent-directory fsync. Unix uses 0600; Windows uses a protected owner-only DACL.
Protected inject uses the agent grant path and rejects inline one-shot DEK boxes.

### Transport

Two modes, the same integration touchpoints as `askill`. **Both channels carry only names, blind boxes, ciphertext, and results — never plaintext or keys.**

- **P1 — CLI subprocess (askill-shaped).** Avibe spawns the `avault` binary. Control args via argv/JSON; **bulk blobs (blind boxes, ciphertext) via stdin** (kept out of argv so they don't show in `ps`); results via **stdout JSON**. The `run` child inherits stdio. One-shot: use the key, zeroize, exit.
- **P2 — resident agent (unix socket).** `avault agent` listens on `~/.avibe/run/avault.sock` (0600) and exchanges **length-prefixed JSON frames**. Authorization is **`SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS)**: `avault` reads the connecting peer's uid/pid to confirm it is the same-user Avibe daemon — **no shared token**, so no decrypt-authorizing secret is re-introduced into Python. The agent is resident so it can hold the grant DEK-cache and act as the signing oracle (keys held across calls).

Each agent frame is a 4-byte unsigned big-endian JSON byte length followed by
that many UTF-8 JSON bytes. Frames are processed sequentially on a connection;
there is no request-id multiplexing in Phase B. Every response is one frame:

```json
{ "ok": true, "result": { "...": "..." } }
```

or:

```json
{ "ok": false, "error": "what failed, never secret bytes" }
```

`pubkey` publishes the agent's fresh in-memory receiver keypair:

```json
{ "type": "pubkey" }
```

Response `result` is the same object as the CLI `pubkey` output:

```json
{
  "public_key": "<base64 raw 32-byte X25519 public key>",
  "fingerprint": "<lowercase hex SHA-256 of the raw public key>"
}
```

This key is generated at agent start, never written to disk, and changes on
restart. Protected-tier callers must re-pin / re-attest it per agent lifetime
(§11.4).

`grant` opens browser-sealed DEKs to the agent's current pubkey and caches them by
scope until the fixed TTL expires. The TTL is strict and does not slide; idle
timeout or process restart also clears the cache. DEKs are stored in the same
dedicated locked 32-byte pages as master keys. Delivery DEKs are keyed by
`{scope_type, scope_ref, name}`. Signing DEKs are keyed by
`{scope_type, scope_ref, name, scheme, digest}` so one approved signing blind box
cannot be replayed for a new digest.

```json
{
  "type": "grant",
  "scope_type": "session",
  "scope_ref": "ses_123",
  "ttl_secs": 300,
  "deks": [
    {
      "name": "OPENAI_API_KEY",
      "purpose": "deliver",
      "dek_blindbox": {
        "scheme": "hpke-x25519-hkdfsha256-aes256gcm-v1",
        "enc": "...",
        "ct": "..."
      },
      "approval": {
        "nonce": "<base64 16..128 random bytes>",
        "expires_at_unix": 4102444800
      }
    },
    {
      "name": "ETH_SIGNING_KEY",
      "purpose": "sign",
      "scheme": "ecdsa-secp256k1-recoverable",
      "digest": "<hex 32-byte digest>",
      "dek_blindbox": {
        "scheme": "hpke-x25519-hkdfsha256-aes256gcm-v1",
        "enc": "...",
        "ct": "..."
      },
      "approval": {
        "nonce": "<base64 16..128 random bytes>",
        "expires_at_unix": 4102444800
      }
    }
  ]
}
```

Response:

```json
{ "ok": true, "result": { "granted": 2, "ttl_secs": 300 } }
```

`purpose` defaults to `deliver` for delivery grants. A delivery grant must not
include `scheme` or `digest`; a signing grant must include both. `digest` is hex
on the JSON wire, but the blind-box AAD authenticates the decoded 32-byte digest.
`scope_type` and `scope_ref` must be non-empty. `ttl_secs` defaults to 300, must
be positive, and is capped at 86400. The same normalized `ttl_secs` value is
authenticated in each grant DEK blind box as an 8-byte unsigned big-endian field
inside `operation_hash`, so a daemon cannot replay a shorter approved release
into a longer agent grant. The effective grant expiry is the earlier of
`ttl_secs` and the approval expiry; TTLs never slide.

`release` and `revoke` are aliases. They drop and zeroize the grant if present:

```json
{ "type": "release", "scope_type": "session", "scope_ref": "ses_123" }
```

Response:

```json
{ "ok": true, "result": { "released": true } }
```

Agent `deliver` uses a cached DEK selected by `{scope_type, scope_ref, name}`. It
never accepts a `dek_blindbox` on deliver frames; the DEK must already be covered
by a grant.

`deliver` run:

```json
{
  "type": "deliver",
  "scope_type": "session",
  "scope_ref": "ses_123",
  "mode": "run",
  "command": ["/usr/bin/env", "python3", "sync.py"],
  "secrets": [
    {
      "name": "OPENAI_API_KEY",
      "env": "OPENAI_API_KEY",
      "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." }
    }
  ]
}
```

Response:

```json
{ "ok": true, "result": { "exit_code": 0 } }
```

`deliver` fetch:

```json
{
  "type": "deliver",
  "scope_type": "session",
  "scope_ref": "ses_123",
  "mode": "fetch",
  "name": "GITHUB_TOKEN",
  "envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." },
  "request": {
    "method": "GET",
    "url": "https://api.github.com/user",
    "allowed_hosts": ["api.github.com"],
    "inject": { "type": "bearer" }
  }
}
```

Response `result` is the normal fetch output:

```json
{ "status": 200, "headers": { "...": "..." }, "body": "..." }
```

`deliver` inject:

```json
{
  "type": "deliver",
  "scope_type": "session",
  "scope_ref": "ses_123",
  "mode": "inject",
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

Response:

```json
{ "ok": true, "result": { "ok": true } }
```

Agent `sign` uses the cached signing DEK selected by
`{scope_type, scope_ref, name, scheme, digest}` to open the signing-key envelope,
signs the caller-provided digest, and wipes the private key immediately.

```json
{
  "type": "sign",
  "scope_type": "session",
  "scope_ref": "ses_123",
  "name": "ETH_SIGNING_KEY",
  "key_envelope": { "ciphertext": "...", "nonce": "...", "wrap_meta": "..." },
  "digest": "<hex 32-byte digest>",
  "scheme": "ecdsa-secp256k1-recoverable"
}
```

Response `result` is the normal signature output:

```json
{ "signature": "<hex signature bytes>", "recovery_id": 0 }
```

### Where avault's own keys live (esp. Linux without a Keychain)

- **The X25519 receiver keypair is ephemeral and in-memory.** It is only used to open blind boxes, so it is generated at agent start (or per CLI invocation) and **never written to disk**. The public key is published on demand; the protected tier pins/attests the *current* public key (re-pin on agent restart). This leaves **only the master key** needing durable secure storage.
- **Master-key store on macOS:** default `auto` uses Keychain generic-password storage for the standard-tier master key. It deliberately does not attach Touch ID / user-presence access-control flags because standard-tier secrets must be usable by unattended agents. A first-run Keychain application-access prompt may still appear for a newly installed binary.
- **Master-key store on Linux (strongest available wins, once implemented):**
  - **TPM 2.0** (present on most Linux hosts) — seal the master key to the TPM; the wrapping key never leaves the chip, optionally bound to PCRs/policy. This is the Linux analog of Keychain/Secure Enclave.
  - **systemd-creds / kernel keyring** — unseal at service start (via TPM or a host key) into non-swappable kernel memory; good for headless services.
  - **`file (0600) + mlock` / Windows protected DACL + `VirtualLock`** (the no-hardware floor) — owned by the service user, kept out of swap and coredumps where the OS allows it.
- **Honest floor:** with no hardware root and no operator factor, the master key's at-rest protection reduces to the **OS user account** (the fundamental law again). The file store is plaintext-at-rest: it resists other users / remote / a stolen disk (with full-disk encryption), but not an attacker already running as your uid. Optional hardening: wrap the master key under a **boot-time passphrase KEK** or a **cloud KMS KEK** (stronger at rest, at the cost of headless start or a network + bootstrap credential). And note: the **protected tier stores nothing decryptable on the box at all** — for high-value secrets, that side-steps the Linux at-rest question entirely.

### Authentication — who may call avault

- **Other users / remote: refused.** The socket is `0600`, owned by the service user; `avault` checks the kernel-supplied peer **uid** (`SO_PEERCRED`/`LOCAL_PEERCRED`, unforgeable) and accepts only its own uid. There is no network listener. The P1 CLI is `fork`/`exec`-ed directly by the daemon, so there is no "someone else connects" surface at all.
- **Another program running as the *same* user: can call avault — by design.** The standard tier's boundary *is* the OS account: an attacker already running as your uid can read the file-store master key, `ptrace` the daemon, etc. — so refusing same-uid callers would be security theater.
- **Why same-uid is still acceptable — three backstops + one root answer:**
  1. **Narrow interface** — even a same-uid caller can only `deliver`/`sign` (results); there is no `decrypt → plaintext`.
  2. **Full audit** — every call is recorded.
  3. **Hardware non-extractability** — with TPM/SE the key can't be exfiltrated; an attacker can at most *coerce a use* (which is audited), not steal the key.
  4. **Root answer = the protected tier** — `avault` has no VMK and cannot decrypt without a browser-released DEK, so for high-value secrets "who can call avault" stops mattering; the cryptography enforces it.
