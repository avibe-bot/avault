//! avault-core — the pure crypto heart of avault.
//!
//! No I/O, no platform dependencies, no logging of secret material. This crate owns the
//! value path only: envelope encryption (AES-256-GCM with AAD), per-record DEK wrapping,
//! opening HPKE blind boxes, and signing — all with `zeroize` discipline and constant-time
//! comparison. Storage, transport, policy, and the resident agent live in sibling crates.
//!
//! Design: see `docs/DESIGN.md` (§5 blind box, §10 envelope, §11 memory hygiene, Appendix B).
//!
//! Invariant: plaintext only flows *in*; this crate returns ciphertext, signatures, or
//! `Zeroizing` buffers that the caller delivers — it never hands plaintext back to Python.

use zeroize::Zeroizing;

/// Wrap-meta scheme tag stored alongside each envelope.
pub const WRAP_SCHEME: &str = "avault-aesgcm-v1";
/// AES-256 key length.
pub const KEY_BYTES: usize = 32;
/// AES-GCM nonce length.
pub const NONCE_BYTES: usize = 12;

/// An envelope-encrypted value, ready to persist. `wrap_meta` is JSON
/// `{ scheme, wrapped_dek, dek_nonce }`; the caller base64-encodes for the DB columns.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub wrap_meta: String,
}

/// Seal `value` under a fresh random DEK, wrapping the DEK with `master_key`.
/// AAD binds `name + scheme + version` so a ciphertext can't be transplanted between records.
///
/// TODO(P1): random 256-bit DEK -> AES-256-GCM(value, nonce, aad) -> wrap DEK under master.
pub fn seal(_master_key: &[u8; KEY_BYTES], _name: &str, _value: &[u8]) -> anyhow::Result<Sealed> {
    todo!("P1: implement envelope seal")
}

/// Reverse [`seal`]. Returns plaintext in a zeroizing buffer; the caller delivers it
/// (child env / file / HTTP) and never returns it to Python.
///
/// TODO(P1): unwrap DEK with master -> AES-256-GCM decrypt + verify AAD.
pub fn open(_master_key: &[u8; KEY_BYTES], _name: &str, _sealed: &Sealed) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!("P1: implement envelope open")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_sane() {
        assert_eq!(KEY_BYTES, 32);
        assert_eq!(NONCE_BYTES, 12);
        assert_eq!(WRAP_SCHEME, "avault-aesgcm-v1");
    }
}
