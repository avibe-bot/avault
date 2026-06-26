#![forbid(unsafe_code)]

//! avault-core — the pure crypto heart of avault.
//!
//! No I/O, no platform dependencies, no logging of secret material. This crate owns the
//! standard-tier value path: envelope encryption (AES-256-GCM with AAD), per-record DEK
//! wrapping, and passphrase-wrapped master-key export. Storage, transport, policy, and
//! the resident agent live in sibling crates.
//!
//! Design: see `docs/DESIGN.md` (§10 envelope, §11 memory hygiene, Appendix B).
//!
//! Invariant: plaintext only flows *in*; this crate returns ciphertext, signatures, or
//! `Zeroizing` buffers that the caller delivers — it never hands plaintext back to Python.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod blind_box;
mod signing;

pub use blind_box::{
    derive_blind_box_keypair_from_master, generate_blind_box_keypair, BlindBox, BlindBoxKeypair,
    BLIND_BOX_HPKE_INFO, BLIND_BOX_SCHEME,
};
pub use signing::{
    LocalSignerProvider, SignatureResult, SignatureScheme, SignerProvider,
    SIGN_SCHEME_ECDSA_SECP256K1_DER, SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE,
    SIGN_SCHEME_SCHNORR_SECP256K1_BIP340,
};

/// Wrap-meta scheme tag used by the P0 Python standard-tier envelope.
pub const WRAP_SCHEME: &str = "machine-aesgcm-v1";
/// P1 envelope version stored in `wrap_meta.v`.
pub const WRAP_META_VERSION: u8 = 1;
/// AES-256 key length.
pub const KEY_BYTES: usize = 32;
/// AES-GCM nonce length.
pub const NONCE_BYTES: usize = 12;
/// Passphrase-wrapped master-key export scheme used by P0 Python.
pub const EXPORT_SCHEME: &str = "machine-key-export-v1";
/// scrypt N parameter used by P0 Python exports.
pub const SCRYPT_N: u32 = 1 << 15;
/// scrypt r parameter used by P0 Python exports.
pub const SCRYPT_R: u32 = 8;
/// scrypt p parameter used by P0 Python exports.
pub const SCRYPT_P: u32 = 1;

/// An envelope-encrypted value, ready to persist as `vault_secrets` columns.
///
/// The fields are base64/JSON text to match the P0 Python `vault_crypto.py`
/// dataclass and SQLite columns exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub ciphertext: String,
    pub nonce: String,
    pub wrap_meta: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WrapMeta {
    #[serde(default = "default_wrap_meta_version")]
    v: u8,
    scheme: String,
    wrapped_dek: String,
    dek_nonce: String,
}

/// Passphrase-wrapped machine-key export blob.
///
/// This shape is intentionally the same as P0 Python's
/// `export_machine_key()` output so existing exports can import here and vice versa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBlob {
    pub scheme: String,
    pub kdf: String,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Seal `value` under a fresh random DEK, wrapping the DEK with `master_key`.
///
/// AAD binds `name + scheme + version` so a ciphertext cannot be transplanted
/// between records. `value` is borrowed because CLI stdin and browser blind-box
/// opens own the plaintext; callers should hold it in a zeroizing buffer.
pub fn seal(master_key: &[u8; KEY_BYTES], name: &str, value: &[u8]) -> anyhow::Result<Sealed> {
    let mut dek = Zeroizing::new([0u8; KEY_BYTES]);
    OsRng.fill_bytes(dek.as_mut());

    let mut value_nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut value_nonce);
    let ciphertext = encrypt_with_key(&dek, &value_nonce, value, &aad(name))?;

    let mut dek_nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut dek_nonce);
    let wrapped_dek = encrypt_with_key(master_key, &dek_nonce, dek.as_ref(), &[])?;

    let wrap_meta = WrapMeta {
        v: WRAP_META_VERSION,
        scheme: WRAP_SCHEME.to_string(),
        wrapped_dek: b64(&wrapped_dek),
        dek_nonce: b64(&dek_nonce),
    };

    Ok(Sealed {
        ciphertext: b64(&ciphertext),
        nonce: b64(&value_nonce),
        wrap_meta: serde_json::to_string(&wrap_meta).context("failed to encode wrap_meta")?,
    })
}

/// Reverse [`seal`]. Returns plaintext in a zeroizing buffer; the caller must
/// deliver it (child env / file / HTTP) and never return it to Python.
///
/// New P1 envelopes must authenticate with AAD. To avoid breaking P0 standard-tier
/// rows already written before AAD existed, `open` retries value decryption with
/// empty AAD only after the P1 AAD check fails. New writes never use that fallback.
pub fn open(
    master_key: &[u8; KEY_BYTES],
    name: &str,
    sealed: &Sealed,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let meta: WrapMeta =
        serde_json::from_str(&sealed.wrap_meta).context("wrap_meta is not valid JSON")?;
    if meta.scheme != WRAP_SCHEME {
        bail!("unsupported wrap scheme");
    }
    if meta.v != WRAP_META_VERSION {
        bail!("unsupported wrap_meta version");
    }

    let dek_nonce = decode_nonce(&meta.dek_nonce, "dek_nonce")?;
    let wrapped_dek = unb64(&meta.wrapped_dek, "wrapped_dek")?;
    let dek = Zeroizing::new(
        decrypt_with_key(master_key, &dek_nonce, &wrapped_dek, &[]).context("DEK unwrap failed")?,
    );
    if dek.len() != KEY_BYTES {
        bail!("DEK unwrap produced invalid length");
    }

    open_value_with_dek(slice_to_key(dek.as_slice())?, name, sealed)
}

/// Open an envelope when the per-record DEK was released through a blind box.
///
/// This is the protected-tier companion to [`open`]: the master key is not used,
/// but the value ciphertext is still authenticated with the same name/scheme/version AAD.
pub fn open_with_dek(
    dek: &[u8; KEY_BYTES],
    name: &str,
    sealed: &Sealed,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let meta: WrapMeta =
        serde_json::from_str(&sealed.wrap_meta).context("wrap_meta is not valid JSON")?;
    if meta.scheme != WRAP_SCHEME {
        bail!("unsupported wrap scheme");
    }
    if meta.v != WRAP_META_VERSION {
        bail!("unsupported wrap_meta version");
    }
    open_value_with_dek(dek, name, sealed)
}

/// Export an existing master key as a P0-compatible scrypt + AES-256-GCM blob.
pub fn export_master_key(
    master_key: &[u8; KEY_BYTES],
    passphrase: &[u8],
) -> anyhow::Result<ExportBlob> {
    if passphrase.is_empty() {
        bail!("a non-empty passphrase is required");
    }

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek_scrypt(passphrase, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)?;

    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt_with_key(&kek, &nonce, master_key, &[])?;

    Ok(ExportBlob {
        scheme: EXPORT_SCHEME.to_string(),
        kdf: "scrypt".to_string(),
        n: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: b64(&salt),
        nonce: b64(&nonce),
        ciphertext: b64(&ciphertext),
    })
}

/// Import a P0-compatible scrypt + AES-256-GCM master-key export blob.
pub fn import_master_key(
    blob: &ExportBlob,
    passphrase: &[u8],
) -> anyhow::Result<Zeroizing<[u8; KEY_BYTES]>> {
    if passphrase.is_empty() {
        bail!("a non-empty passphrase is required");
    }
    if blob.scheme != EXPORT_SCHEME || blob.kdf != "scrypt" {
        bail!("unrecognized machine-key export blob");
    }
    validate_scrypt_params(blob.n, blob.r, blob.p)?;

    let salt = unb64(&blob.salt, "salt")?;
    let nonce = decode_nonce(&blob.nonce, "nonce")?;
    let ciphertext = unb64(&blob.ciphertext, "ciphertext")?;
    let kek = derive_kek_scrypt(passphrase, &salt, blob.n, blob.r, blob.p)?;
    let key = Zeroizing::new(
        decrypt_with_key(&kek, &nonce, &ciphertext, &[])
            .context("import failed (wrong passphrase or corrupt export)")?,
    );
    if key.len() != KEY_BYTES {
        bail!("imported key has invalid length");
    }

    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    out.as_mut().copy_from_slice(&key);
    Ok(out)
}

fn encrypt_with_key(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))
}

fn decrypt_with_key(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("authentication failed"))
}

fn open_value_with_dek(
    dek: &[u8; KEY_BYTES],
    name: &str,
    sealed: &Sealed,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let value_nonce = decode_nonce(&sealed.nonce, "nonce")?;
    let ciphertext = unb64(&sealed.ciphertext, "ciphertext")?;
    match decrypt_with_key(dek, &value_nonce, &ciphertext, &aad(name)) {
        Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
        Err(p1_err) => decrypt_with_key(dek, &value_nonce, &ciphertext, &[])
            .map(Zeroizing::new)
            .map_err(|_| p1_err)
            .context("value decrypt failed"),
    }
}

fn derive_kek_scrypt(
    passphrase: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
) -> anyhow::Result<Zeroizing<[u8; KEY_BYTES]>> {
    validate_scrypt_params(n, r, p)?;
    let log_n = n
        .checked_ilog2()
        .ok_or_else(|| anyhow!("invalid scrypt N"))?;
    let params =
        scrypt::Params::new(log_n as u8, r, p, KEY_BYTES).context("invalid scrypt parameters")?;
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    scrypt::scrypt(passphrase, salt, &params, out.as_mut()).context("scrypt derivation failed")?;
    Ok(out)
}

fn validate_scrypt_params(n: u32, r: u32, p: u32) -> anyhow::Result<()> {
    if n < 2 || !n.is_power_of_two() || n > (1 << 17) {
        bail!("scrypt N out of bounds");
    }
    if !(1..=16).contains(&r) {
        bail!("scrypt r out of bounds");
    }
    if !(1..=16).contains(&p) {
        bail!("scrypt p out of bounds");
    }
    Ok(())
}

fn aad(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + WRAP_SCHEME.len() + 1);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(WRAP_SCHEME.as_bytes());
    out.push(WRAP_META_VERSION);
    out
}

fn b64(raw: &[u8]) -> String {
    B64.encode(raw)
}

fn unb64(text: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    B64.decode(text.as_bytes())
        .with_context(|| format!("{field} is not valid base64"))
}

fn decode_nonce(text: &str, field: &str) -> anyhow::Result<[u8; NONCE_BYTES]> {
    let raw = unb64(text, field)?;
    if raw.len() != NONCE_BYTES {
        bail!("{field} has invalid length");
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&raw);
    Ok(nonce)
}

fn slice_to_key(key: &[u8]) -> anyhow::Result<&[u8; KEY_BYTES]> {
    key.try_into().map_err(|_| anyhow!("invalid key length"))
}

fn default_wrap_meta_version() -> u8 {
    WRAP_META_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MASTER_KEY: [u8; KEY_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn constants_match_p0_wire_format() {
        assert_eq!(KEY_BYTES, 32);
        assert_eq!(NONCE_BYTES, 12);
        assert_eq!(WRAP_SCHEME, "machine-aesgcm-v1");
        assert_eq!(EXPORT_SCHEME, "machine-key-export-v1");
    }

    #[test]
    fn roundtrip() {
        let sealed = seal(&MASTER_KEY, "OPENAI_API_KEY", b"sk-test").unwrap();
        let opened = open(&MASTER_KEY, "OPENAI_API_KEY", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"sk-test");

        let meta: serde_json::Value = serde_json::from_str(&sealed.wrap_meta).unwrap();
        assert_eq!(meta["v"], 1);
        assert_eq!(meta["scheme"], WRAP_SCHEME);
        assert!(meta["wrapped_dek"].as_str().unwrap().len() > 32);
        assert!(meta["dek_nonce"].as_str().unwrap().len() > 8);
    }

    #[test]
    fn wrong_master_fails() {
        let sealed = seal(&MASTER_KEY, "OPENAI_API_KEY", b"sk-test").unwrap();
        let wrong = [7u8; KEY_BYTES];
        assert!(open(&wrong, "OPENAI_API_KEY", &sealed).is_err());
    }

    #[test]
    fn aad_name_mismatch_fails_for_p1_envelope() {
        let sealed = seal(&MASTER_KEY, "OPENAI_API_KEY", b"sk-test").unwrap();
        assert!(open(&MASTER_KEY, "ANTHROPIC_API_KEY", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(&MASTER_KEY, "OPENAI_API_KEY", b"sk-test").unwrap();
        let mut ct = unb64(&sealed.ciphertext, "ciphertext").unwrap();
        ct[0] ^= 0x80;
        sealed.ciphertext = b64(&ct);
        assert!(open(&MASTER_KEY, "OPENAI_API_KEY", &sealed).is_err());
    }

    #[test]
    fn opens_known_answer_p1_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/p1_aad_vector.json")).unwrap();
        assert_eq!(
            vector["aad_b64"],
            b64(&aad(vector["name"].as_str().unwrap()))
        );
        let master = unb64(vector["master_key_b64"].as_str().unwrap(), "master_key").unwrap();
        let master: [u8; KEY_BYTES] = master.try_into().unwrap();
        let sealed: Sealed = serde_json::from_value(vector["sealed"].clone()).unwrap();
        let opened = open(&master, vector["name"].as_str().unwrap(), &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"sk-known-answer");
    }

    #[test]
    fn opens_p0_python_no_aad_vector_for_read_compatibility() {
        let sealed = Sealed {
            ciphertext: "gbSQ4CgEA//jJu56fOvXZE0hKkc9LktZoM+58v2Dsw==".to_string(),
            nonce: "MDEyMzQ1Njc4OTo7".to_string(),
            wrap_meta: json!({
                "v": 1,
                "scheme": WRAP_SCHEME,
                "wrapped_dek": "suj8cHJp0VSVnU1txzlNBBmnMD/TUGlEHy4kjvt+g7RlXgPlB6d7YQpDbhPKDEg7",
                "dek_nonce": "QEFCQ0RFRkdISUpL"
            })
            .to_string(),
        };
        let opened = open(&MASTER_KEY, "OPENAI_API_KEY", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"p0-python-value");
    }

    #[test]
    fn opens_with_released_dek_and_preserves_aad_rejection() {
        let dek = [0x99u8; KEY_BYTES];
        let value_nonce = [0x11u8; NONCE_BYTES];
        let ciphertext =
            encrypt_with_key(&dek, &value_nonce, b"protected-key", &aad("PROTECTED_KEY")).unwrap();
        let sealed = Sealed {
            ciphertext: b64(&ciphertext),
            nonce: b64(&value_nonce),
            wrap_meta: json!({
                "v": 1,
                "scheme": WRAP_SCHEME,
                "wrapped_dek": "",
                "dek_nonce": ""
            })
            .to_string(),
        };

        let opened = open_with_dek(&dek, "PROTECTED_KEY", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"protected-key");
        assert!(open_with_dek(&dek, "OTHER_KEY", &sealed).is_err());
    }

    #[test]
    fn opens_documented_p0_wrap_meta_without_version() {
        let sealed = Sealed {
            ciphertext: "gbSQ4CgEA//jJu56fOvXZE0hKkc9LktZoM+58v2Dsw==".to_string(),
            nonce: "MDEyMzQ1Njc4OTo7".to_string(),
            wrap_meta: json!({
                "scheme": WRAP_SCHEME,
                "wrapped_dek": "suj8cHJp0VSVnU1txzlNBBmnMD/TUGlEHy4kjvt+g7RlXgPlB6d7YQpDbhPKDEg7",
                "dek_nonce": "QEFCQ0RFRkdISUpL"
            })
            .to_string(),
        };
        let opened = open(&MASTER_KEY, "OPENAI_API_KEY", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"p0-python-value");
    }

    #[test]
    fn export_import_roundtrip() {
        let blob = export_master_key(&MASTER_KEY, b"correct horse battery staple").unwrap();
        let imported = import_master_key(&blob, b"correct horse battery staple").unwrap();
        assert_eq!(imported.as_ref(), &MASTER_KEY);
        assert!(import_master_key(&blob, b"wrong").is_err());
    }

    #[test]
    fn imports_p0_python_export_vector() {
        let blob = ExportBlob {
            scheme: EXPORT_SCHEME.to_string(),
            kdf: "scrypt".to_string(),
            n: SCRYPT_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            salt: "c2FsdHlzYWx0eXNhbHQh".to_string(),
            nonce: "KCkqKywtLi8wMTIz".to_string(),
            ciphertext: "tPZK1A2HjfEGQHGTIaLP0fexWVdzlWPip9Ze0b909RrXyIjE/1sj0YZFTYnOxflB"
                .to_string(),
        };
        let imported = import_master_key(&blob, b"p0-passphrase").unwrap();
        assert_eq!(imported.as_ref(), &MASTER_KEY);
    }
}
