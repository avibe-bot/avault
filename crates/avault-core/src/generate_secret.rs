//! Generation of random standard-tier static secrets.
//!
//! Plaintext is generated and sealed in this crate. The public production API returns only
//! the existing [`Sealed`] envelope; the zeroizing plaintext helper is private and exists
//! only for format tests in this module.

use crate::{seal, Sealed, KEY_BYTES};
use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

const PASSWORD_LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PASSWORD_DIGITS: &[u8] = b"0123456789";
const PASSWORD_SYMBOLS: &[u8] = b"!#$%&*+-.:=?@^_~";
const LOOKALIKE_BYTES: &[u8] = b"0O1lI";

/// Recipe for an avault Standard static-secret generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretGeneration {
    /// Generate an ASCII password. Letters are always enabled; the other classes are optional.
    Password {
        /// Number of generated characters, inclusive range 12..=128.
        length: usize,
        /// Include decimal digits.
        digits: bool,
        /// Include the fixed symbol set `!#$%&*+-.:=?@^_~`.
        symbols: bool,
        /// Remove `0 O 1 l I` from every enabled class.
        no_lookalikes: bool,
    },
    /// Generate lowercase hexadecimal for this many random bytes, inclusive range 16..=64.
    Hex { bytes: usize },
    /// Generate standard padded Base64, without line wrapping, for this many random bytes,
    /// inclusive range 16..=64.
    Base64 { bytes: usize },
}

/// Generate a static secret from the OS CSPRNG and seal it as the existing Standard record.
///
/// The only returned value is the [`Sealed`] envelope. The generated plaintext is held in
/// zeroizing memory for the duration of generation and sealing and never crosses this API.
pub fn generate_sealed_secret(
    master_key: &[u8; KEY_BYTES],
    name: &str,
    recipe: SecretGeneration,
) -> anyhow::Result<Sealed> {
    validate_recipe(recipe)?;
    let mut rng = OsRng;
    let plaintext = generate_plaintext_with_rng(recipe, &mut rng)?;
    seal(master_key, name, plaintext.as_slice())
}

fn validate_recipe(recipe: SecretGeneration) -> anyhow::Result<()> {
    match recipe {
        SecretGeneration::Password { length, .. } if !(12..=128).contains(&length) => {
            bail!("password length must be between 12 and 128")
        }
        SecretGeneration::Hex { bytes } | SecretGeneration::Base64 { bytes }
            if !(16..=64).contains(&bytes) =>
        {
            bail!("hex/base64 byte count must be between 16 and 64")
        }
        _ => Ok(()),
    }
}

fn generate_plaintext_with_rng<R: RngCore>(
    recipe: SecretGeneration,
    rng: &mut R,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    validate_recipe(recipe)?;
    match recipe {
        SecretGeneration::Password {
            length,
            digits,
            symbols,
            no_lookalikes,
        } => generate_password(length, digits, symbols, no_lookalikes, rng),
        SecretGeneration::Hex { bytes } => {
            let mut raw = Zeroizing::new(vec![0u8; bytes]);
            rng.fill_bytes(raw.as_mut_slice());
            let mut encoded = Zeroizing::new(vec![0u8; bytes * 2]);
            hex::encode_to_slice(raw.as_slice(), encoded.as_mut_slice())
                .map_err(|_| anyhow::anyhow!("hex encoding failed"))?;
            Ok(encoded)
        }
        SecretGeneration::Base64 { bytes } => {
            let mut raw = Zeroizing::new(vec![0u8; bytes]);
            rng.fill_bytes(raw.as_mut_slice());
            let mut encoded = Zeroizing::new(vec![0u8; bytes.div_ceil(3) * 4]);
            let written = B64
                .encode_slice(raw.as_slice(), encoded.as_mut_slice())
                .context("base64 encoding failed")?;
            debug_assert_eq!(written, encoded.len());
            Ok(encoded)
        }
    }
}

fn generate_password<R: RngCore>(
    length: usize,
    digits: bool,
    symbols: bool,
    no_lookalikes: bool,
    rng: &mut R,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let enabled_classes: Vec<Vec<u8>> = [
        Some(PASSWORD_LETTERS),
        digits.then_some(PASSWORD_DIGITS),
        symbols.then_some(PASSWORD_SYMBOLS),
    ]
    .into_iter()
    .flatten()
    .map(|class| {
        class
            .iter()
            .copied()
            .filter(|byte| !no_lookalikes || !LOOKALIKE_BYTES.contains(byte))
            .collect()
    })
    .collect();

    let mut alphabet = Vec::new();
    for class in &enabled_classes {
        alphabet.extend_from_slice(class);
    }
    if alphabet.is_empty() {
        bail!("password alphabet is empty");
    }

    loop {
        let mut candidate = Zeroizing::new(Vec::with_capacity(length));
        for _ in 0..length {
            let index = sample_index(rng, alphabet.len())?;
            candidate.push(alphabet[index]);
        }
        if enabled_classes
            .iter()
            .all(|class| candidate.iter().any(|byte| class.contains(byte)))
        {
            return Ok(candidate);
        }
    }
}

/// Choose a uniformly distributed alphabet index using byte rejection sampling.
///
/// Bytes at or above the largest multiple of `alphabet_len` below 256 are discarded before
/// modulo reduction, so the modulo operation itself cannot introduce bias.
fn sample_index<R: RngCore>(rng: &mut R, alphabet_len: usize) -> anyhow::Result<usize> {
    if alphabet_len == 0 || alphabet_len > 256 {
        bail!("alphabet length must be between 1 and 256");
    }
    let limit = 256 - (256 % alphabet_len);
    loop {
        let mut byte = [0u8; 1];
        rng.fill_bytes(&mut byte);
        let value = byte[0] as usize;
        if value < limit {
            return Ok(value % alphabet_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{CryptoRng, Error};

    struct ByteRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl ByteRng {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl RngCore for ByteRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.offset + dest.len();
            assert!(end <= self.bytes.len(), "fake RNG exhausted");
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ByteRng {}

    #[test]
    fn production_api_uses_os_csprng_and_returns_distinct_valid_plaintexts() {
        let master = [0x42; KEY_BYTES];
        let first_password = generate_sealed_secret(
            &master,
            "GENERATED",
            SecretGeneration::Password {
                length: 24,
                digits: true,
                symbols: true,
                no_lookalikes: true,
            },
        )
        .unwrap();
        let second_password = generate_sealed_secret(
            &master,
            "GENERATED",
            SecretGeneration::Password {
                length: 24,
                digits: true,
                symbols: true,
                no_lookalikes: true,
            },
        )
        .unwrap();
        let first_password = crate::open(&master, "GENERATED", &first_password).unwrap();
        let second_password = crate::open(&master, "GENERATED", &second_password).unwrap();
        assert_eq!(first_password.len(), 24);
        assert!(first_password.as_slice() != second_password.as_slice());
        assert!(first_password.iter().all(|byte| {
            PASSWORD_LETTERS.contains(byte)
                || PASSWORD_DIGITS.contains(byte)
                || PASSWORD_SYMBOLS.contains(byte)
        }));
        assert!(first_password
            .iter()
            .all(|byte| !LOOKALIKE_BYTES.contains(byte)));
        assert!(first_password
            .iter()
            .any(|byte| PASSWORD_LETTERS.contains(byte)));
        assert!(first_password
            .iter()
            .any(|byte| PASSWORD_DIGITS.contains(byte)));
        assert!(first_password
            .iter()
            .any(|byte| PASSWORD_SYMBOLS.contains(byte)));

        let hex_envelope =
            generate_sealed_secret(&master, "GENERATED", SecretGeneration::Hex { bytes: 16 })
                .unwrap();
        let hex_plaintext = crate::open(&master, "GENERATED", &hex_envelope).unwrap();
        assert_eq!(hex_plaintext.len(), 32);
        assert!(hex_plaintext
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        let decoded_hex = hex::decode(hex_plaintext.as_slice()).unwrap();
        assert_eq!(decoded_hex.len(), 16);

        let base64_envelope =
            generate_sealed_secret(&master, "GENERATED", SecretGeneration::Base64 { bytes: 16 })
                .unwrap();
        let base64_plaintext = crate::open(&master, "GENERATED", &base64_envelope).unwrap();
        assert_eq!(base64_plaintext.len(), 24);
        assert!(base64_plaintext.ends_with(b"=="));
        assert!(!base64_plaintext
            .iter()
            .any(|byte| *byte == b'\n' || *byte == b'\r'));
        let decoded_base64 = B64.decode(base64_plaintext.as_slice()).unwrap();
        assert_eq!(decoded_base64.len(), 16);
    }

    #[test]
    fn deterministic_hex_and_base64_vectors_match_standard_encodings() {
        let input: Vec<u8> = (0..16).collect();
        let mut hex_rng = ByteRng::new(input.clone());
        let hex =
            generate_plaintext_with_rng(SecretGeneration::Hex { bytes: 16 }, &mut hex_rng).unwrap();
        assert_eq!(hex.as_slice(), b"000102030405060708090a0b0c0d0e0f");

        let mut base64_rng = ByteRng::new(input);
        let base64 =
            generate_plaintext_with_rng(SecretGeneration::Base64 { bytes: 16 }, &mut base64_rng)
                .unwrap();
        assert_eq!(base64.as_slice(), b"AAECAwQFBgcICQoLDA0ODw==");
    }

    #[test]
    fn password_regenerates_whole_string_until_all_enabled_classes_are_present() {
        // First candidate is all letters. The second candidate contains a letter, digit, and
        // symbol; no individual position is patched after the class check fails.
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(&[0, 52, 62]);
        bytes.extend_from_slice(&[0; 9]);
        let mut rng = ByteRng::new(bytes);
        let password = generate_plaintext_with_rng(
            SecretGeneration::Password {
                length: 12,
                digits: true,
                symbols: true,
                no_lookalikes: false,
            },
            &mut rng,
        )
        .unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.iter().any(|byte| PASSWORD_LETTERS.contains(byte)));
        assert!(password.iter().any(|byte| PASSWORD_DIGITS.contains(byte)));
        assert!(password.iter().any(|byte| PASSWORD_SYMBOLS.contains(byte)));
        assert_eq!(password[0], b'a');
        assert_eq!(password[1], b'0');
        assert_eq!(password[2], b'!');
    }

    #[test]
    fn no_lookalikes_removes_the_five_forbidden_characters() {
        let mut rng = ByteRng::new(vec![52, 40, 53, 11, 34, 62, 0, 1, 2, 3, 4, 5]);
        let password = generate_plaintext_with_rng(
            SecretGeneration::Password {
                length: 12,
                digits: true,
                symbols: true,
                no_lookalikes: true,
            },
            &mut rng,
        )
        .unwrap();
        assert!(password.iter().all(|byte| !LOOKALIKE_BYTES.contains(byte)));
        assert!(password.iter().any(|byte| PASSWORD_LETTERS.contains(byte)));
        assert!(password.iter().any(|byte| PASSWORD_DIGITS.contains(byte)));
        assert!(password.iter().any(|byte| PASSWORD_SYMBOLS.contains(byte)));
    }

    #[test]
    fn rejection_sampling_discards_tail_and_maps_accepted_bytes_uniformly() {
        let mut bytes = vec![255];
        bytes.extend(0..=254);
        let mut rng = ByteRng::new(bytes);
        let mut counts = [0usize; 3];
        for _ in 0..255 {
            counts[sample_index(&mut rng, 3).unwrap()] += 1;
        }
        assert_eq!(counts, [85, 85, 85]);
    }

    #[test]
    fn recipe_bounds_are_rejected_before_randomness_or_sealing() {
        let mut rng = ByteRng::new(Vec::new());
        assert!(generate_plaintext_with_rng(
            SecretGeneration::Password {
                length: 11,
                digits: true,
                symbols: true,
                no_lookalikes: false,
            },
            &mut rng
        )
        .is_err());
        assert!(
            generate_plaintext_with_rng(SecretGeneration::Hex { bytes: 65 }, &mut rng).is_err()
        );
        assert!(
            generate_plaintext_with_rng(SecretGeneration::Base64 { bytes: 15 }, &mut rng).is_err()
        );
    }
}
