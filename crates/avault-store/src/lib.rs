//! avault-store — where avault's own key material lives.
//!
//! Holds the standard-tier **master key** and avault's **X25519 private key**. Picks the
//! strongest backend available on the host; the X25519 keypair is ephemeral (in-memory),
//! so only the master key needs durable secure storage.
//!
//! Backends, strongest first (see `docs/DESIGN.md` §13 and Appendix C):
//!   - `tpm`       — Linux TPM 2.0 seal/unseal (key never leaves the chip)
//!   - `keychain`  — macOS Keychain / Secure Enclave (non-extractable)
//!   - `file`      — 0600 file + `mlock` + no-coredump (the no-hardware floor)
//!   - (optional)  — passphrase-KEK / cloud-KMS wrap on top of `file`
//!
//! Honest floor: with no hardware root and no operator factor, the master key's at-rest
//! protection reduces to the OS user account. This crate's job is to use the best available
//! backend and harden the in-memory handling regardless.

use zeroize::Zeroizing;

/// Selected master-key storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Tpm,
    Keychain,
    File,
}

/// Load the 32-byte master key, or create it on first use.
///
/// TODO(P1): implement the `file + mlock` backend; add tpm/keychain behind capability checks.
pub fn load_or_create_master_key(_backend: Backend) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    todo!("P1: file+mlock master-key store")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_distinct() {
        assert_ne!(Backend::Tpm, Backend::File);
    }
}
