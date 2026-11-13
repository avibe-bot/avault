# Independent public HD Bitcoin fixtures

**PUBLIC TEST DATA — NEVER FUND THESE IDENTITIES.** All entropy, words,
passphrases, seeds and test keys here are deliberately public. This is a test
oracle, not production cryptography or a wallet. Production still accepts only
64 seed bytes and contains no BIP39/word-list dependency.

## Coverage and provenance

`../vectors/hd_bitcoin_address_types.json` contains seven cases: two random-once,
fixed public 12/24-word mnemonics, each with empty, ASCII, and NFKD-sensitive
Unicode passphrases, plus the published `abandon` ×11 + `about` reference. All 20
indices are covered: 700 public keys, 140 tweaked output keys, and 420 addresses.

| Field | Fixed path / representation |
| --- | --- |
| `evm` | `m/44'/60'/0'/0/i`, compressed SEC1 |
| `bitcoin_p2pkh` | `m/44'/0'/0'/0/i`, compressed SEC1 |
| `bitcoin_p2wpkh` | `m/84'/0'/0'/0/i`, compressed SEC1 |
| `bitcoin` | `m/86'/0'/0'/0/i`, **untweaked** compressed SEC1 |
| `bitcoin_output_key` | even-Y lift plus empty-tree TapTweak, x-only |
| `solana` | `m/44'/501'/i'/0'`, SLIP-0010 raw Ed25519 public key |

Here `i=0..19` is the product index, not hardened Bitcoin account-i. This does not
claim Phantom account-i parity. P2PKH/P2WPKH addresses use their own purpose keys,
not re-encodings of the BIP86 key. Mainnet fixture encodings are **never funded**.

`generate_fixtures.py` independently implements the derivation/address rules in
standard-library Python, checks all 560 secp256k1 public keys with OpenSSL, and
uses OpenSSL for all 140 Ed25519 public keys. `crosscheck_scure.mjs` separately
matches all 700 keys, 140 output keys, and 420 addresses against installed,
lock-pinned scure/noble libraries. It also decodes all 420 addresses and rejects
280 wrong-purpose re-encodings. Internal Taproot parity covers 65 odd / 75 even
keys. Both Unicode cases test NFKD equivalence; unnormalized UTF-8 seeds differ.

Official anchors: 24 BIP39 English vectors; 17 BIP32 key pairs (vectors 1–4);
all three BIP84 and BIP86 examples; SLIP-0132 BIP44/BIP84 account-xpub/address
pairs; and 12 each SLIP-0010 secp256k1/Ed25519 nodes. BIP44 defines the hierarchy;
its numeric anchor comes from SLIP-0132. `../vectors/hd_bitcoin_official.json`
contains extracted public references. Change-path reference vectors test the
oracle, not an exposed product path selector.

`sources-manifest.json` pins 12 primary-source URLs by upstream commit and exact
SHA-256. The fetcher requires this frozen manifest; it never refreshes from HEAD.
`public-entropy.json` holds the two original CSPRNG draws. Do not replace them.
Original Python and JS verification reports record tool versions, counts, fixture
hash, and JS package/lock/code-tree provenance. No claim is made that installed
JS packages were reconstituted from their registry tarballs during that check.

## Reproduce in caller-owned scratch

Run from the repository root. Python needs SHA-256/SHA-512/PBKDF2/RIPEMD-160 and
OpenSSL needs secp256k1/Ed25519. The generator rejects optimized Python so its
assertions cannot disappear. No production dependencies are installed or changed.

```sh
set -eu
REPO=$(pwd)
TOOLS="$REPO/tests/hd-bitcoin-fixtures"
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/hd-bitcoin-fixtures.XXXXXX")
cp "$TOOLS/generate_fixtures.py" "$TOOLS/fetch_sources.py" \
   "$TOOLS/sources-manifest.json" "$TOOLS/public-entropy.json" "$SCRATCH/"
cp "$REPO/tests/vectors/hd_bitcoin_address_types.json" "$SCRATCH/hd-public-fixtures.json"
cp "$REPO/tests/vectors/hd_bitcoin_official.json" "$SCRATCH/official-public-vectors.json"
cd "$SCRATCH"
PYTHONDONTWRITEBYTECODE=1 python3 fetch_sources.py
PYTHONDONTWRITEBYTECODE=1 python3 generate_fixtures.py --check
```

Expected fixture SHA-256:
`d5c2fcbdfe3c4949b4d715dd77276569a3601dab7903b79ded3a32589b526109`.
After fetching, `--check` is offline and read-only. Do not commit `sources/` or
regeneration outputs. Never rerun entropy initialization for these fixtures.

Optional independent JS pass, using an explicitly supplied absolute path to an
existing installed/locked external project (no sibling-repository fallback):

```sh
cp "$TOOLS/crosscheck_scure.mjs" "$SCRATCH/"
HD_FIXTURE_JS_PROJECT=/absolute/path/to/existing/js-project \
  node "$SCRATCH/crosscheck_scure.mjs"
```

Required top-level versions: `@scure/bip32` 1.7.0, `@scure/bip39` 1.6.0,
`@scure/base` 1.2.6, `@noble/curves` and `@noble/hashes` 2.2.0. Nested locked
versions and integrity are recorded in `js-verification.json`. The JS check
writes its evidence only beside the copied script. Remove caller-owned scratch
when done. Do not use either oracle with real private material.

## v0.1.11 downgrade and continuity

`../hd-bitcoin-compatibility.py` takes separately built old and new binaries,
freezes executable copies, and runs serial black-box checks in disposable file
stores. It never selects Keychain/TPM or reads live user state. Its Python EC
arithmetic verifies **public signatures only**, not private HD derivation.

```sh
python3 tests/hd-bitcoin-compatibility.py \
  --old /absolute/path/to/v0.1.11/avault \
  --new /absolute/path/to/current/avault \
  --artifacts /absolute/path/to/new-scratch-directory
```

The artifact directory must not exist. Expected: 798 invocations, 208 fail-closed
refusals, all20 identities/signatures across old/default-new/extended-new imports,
191 BIP86 + 254 ECDSA + 4 raw BIP340 public verifications, and 132 deterministic
signature equality pairs. Schnorr bytes are randomized: continuity means the same
independently tweaked key verifies both, not equal signatures. It checks exact
wire schemas, old refusal of every new selector/profile/verb, immutable envelope
and store state, corruption/substitution, and missing-master no-create behavior.
Disposable master stores are deleted even on failure; retain public evidence only.

BIP143's published native-P2WPKH preimage/digest/DER signature is pinned in the Rust
CLI test. Transaction builders, backfill CAS, and disposable-testnet receive/spend
acceptance remain caller/integration responsibilities; these fixtures do not
replace them.
