use anyhow::{anyhow, bail};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Ed25519 seed length in bytes.
pub const ED25519_SEED_BYTES: usize = 32;
/// Ed25519 public-key length in bytes.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Solana's concatenated secret-key export length in bytes.
pub const SOLANA_SECRET_KEY_BYTES: usize = 64;
/// Maximum raw message accepted by the v1 signing boundary.
pub const MAX_ED25519_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum user-facing base58 length for a 64-byte Solana secret key.
pub const MAX_SOLANA_SECRET_BASE58_BYTES: usize = 88;
/// Maximum JSON framing accepted for a 64-byte Solana CLI keypair.
pub const MAX_SOLANA_CLI_JSON_BYTES: usize = 4096;

/// An Ed25519 keypair whose seed is wiped when the value is dropped.
///
/// The public key is safe to expose; the seed is only available by consuming the
/// keypair, which keeps accidental copies out of the public metadata path.
pub struct Ed25519Keypair {
    seed: Zeroizing<[u8; ED25519_SEED_BYTES]>,
    public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl Ed25519Keypair {
    /// Return the canonical 32-byte public key.
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        self.public_key
    }

    /// Return the Solana base58 address for the public key.
    pub fn address(&self) -> String {
        solana_address(&self.public_key)
    }

    /// Consume the keypair and return its seed for immediate envelope sealing.
    pub fn into_seed(self) -> Zeroizing<[u8; ED25519_SEED_BYTES]> {
        self.seed
    }
}

/// Generate a fresh Ed25519 keypair using the operating system CSPRNG.
pub fn generate_ed25519_keypair() -> Ed25519Keypair {
    let mut seed = Zeroizing::new([0u8; ED25519_SEED_BYTES]);
    OsRng.fill_bytes(seed.as_mut());
    keypair_from_seed(seed)
}

/// Import a Solana CLI/base58 64-byte secret key.
///
/// The first 32 bytes are the Ed25519 seed and the final 32 bytes must equal
/// the public key derived from that seed. The input is copied into a zeroizing
/// buffer and is never included in an error.
pub fn import_solana_secret_key(secret_key: &[u8]) -> anyhow::Result<Ed25519Keypair> {
    if secret_key.len() != SOLANA_SECRET_KEY_BYTES {
        bail!("Solana secret key must be exactly 64 bytes");
    }
    let mut seed = Zeroizing::new([0u8; ED25519_SEED_BYTES]);
    seed.copy_from_slice(&secret_key[..ED25519_SEED_BYTES]);
    let keypair = keypair_from_seed(seed);
    if keypair.public_key.as_slice() != &secret_key[ED25519_SEED_BYTES..] {
        bail!("Solana secret key public key does not match its seed");
    }
    Ok(keypair)
}

/// Import the Solana CLI JSON keypair format: exactly 64 integers in `0..=255`.
pub fn import_solana_cli_json(input: &[u8]) -> anyhow::Result<Ed25519Keypair> {
    if input.len() > MAX_SOLANA_CLI_JSON_BYTES {
        bail!("Solana CLI keypair JSON exceeds the supported size limit");
    }
    let values = decode_solana_cli_json(input)?;
    import_solana_secret_key(values.as_ref())
}

fn decode_solana_cli_json(
    input: &[u8],
) -> anyhow::Result<Zeroizing<[u8; SOLANA_SECRET_KEY_BYTES]>> {
    // Parse the narrow byte-array grammar from borrowed slices. A generic Vec
    // deserializer can free partial secrets on errors or reallocation before a
    // Zeroizing wrapper ever owns them; even JSON string errors can copy input.
    let invalid = || anyhow!("Solana CLI keypair JSON is invalid");
    let text = std::str::from_utf8(input).map_err(|_| invalid())?;
    let body = text
        .trim_matches([' ', '\t', '\r', '\n'])
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .ok_or_else(invalid)?;
    let mut tokens = body.split(',');
    let mut values = Zeroizing::new([0u8; SOLANA_SECRET_KEY_BYTES]);
    for value in values.iter_mut() {
        let token = tokens
            .next()
            .ok_or_else(invalid)?
            .trim_matches([' ', '\t', '\r', '\n']);
        if token.is_empty()
            || token.len() > 3
            || !token.bytes().all(|byte| byte.is_ascii_digit())
            || (token.len() > 1 && token.starts_with('0'))
        {
            return Err(invalid());
        }
        *value = token.parse::<u8>().map_err(|_| invalid())?;
    }
    if tokens.next().is_some() {
        return Err(invalid());
    }
    Ok(values)
}

/// Import a base58-encoded Solana 64-byte secret key.
pub fn import_solana_base58(input: &str) -> anyhow::Result<Ed25519Keypair> {
    let input = input.trim();
    if input.len() > MAX_SOLANA_SECRET_BASE58_BYTES {
        bail!("Solana secret key base58 input is too long");
    }
    // The decoder writes directly into guarded storage, including partial
    // output on invalid characters or overflow; no ordinary Vec holds a key.
    let mut decoded = Zeroizing::new([0u8; SOLANA_SECRET_KEY_BYTES]);
    let len = bs58::decode(input)
        .onto(decoded.as_mut())
        .map_err(|_| anyhow!("Solana secret key is not valid 64-byte base58"))?;
    import_solana_secret_key(&decoded[..len])
}

/// Encode a canonical Ed25519 public key as a Solana address.
pub fn solana_address(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> String {
    bs58::encode(public_key).into_string()
}

/// Derive the canonical public key from a 32-byte Ed25519 seed.
pub fn ed25519_public_key(seed: &[u8; ED25519_SEED_BYTES]) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign exact serialized message bytes with Ed25519.
pub fn sign_ed25519(
    seed: &Zeroizing<[u8; ED25519_SEED_BYTES]>,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if message.len() > MAX_ED25519_MESSAGE_BYTES {
        bail!("ed25519 message exceeds the 1 MiB limit");
    }
    let signing_key = SigningKey::from_bytes(seed);
    Ok(signing_key.sign(message).to_bytes().to_vec())
}

fn keypair_from_seed(seed: Zeroizing<[u8; ED25519_SEED_BYTES]>) -> Ed25519Keypair {
    let public_key = ed25519_public_key(&seed);
    Ed25519Keypair { seed, public_key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn rfc8032_empty_message_vector() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let expected_signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
            5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        let seed = Zeroizing::new(seed);
        let public_key = ed25519_public_key(&seed);
        assert_eq!(hex::encode(public_key), expected_public);
        let signature = sign_ed25519(&seed, b"").unwrap();
        assert_eq!(
            hex::encode(&signature),
            expected_signature.replace(['\n', ' '], "")
        );
        VerifyingKey::from_bytes(&public_key)
            .unwrap()
            .verify(b"", &Signature::from_slice(&signature).unwrap())
            .unwrap();
    }

    #[test]
    fn imports_and_derives_solana_address() {
        let seed: [u8; 32] = [7u8; 32];
        let public_key = ed25519_public_key(&seed);
        let mut secret = Vec::from(seed);
        secret.extend_from_slice(&public_key);
        let keypair = import_solana_secret_key(&secret).unwrap();
        assert_eq!(keypair.public_key(), public_key);
        assert_eq!(keypair.address(), solana_address(&public_key));
        assert_eq!(keypair.into_seed().as_ref(), &seed);
    }

    #[test]
    fn base58_secret_roundtrips() {
        let seed = [11u8; 32];
        let public_key = ed25519_public_key(&seed);
        let mut secret = Vec::from(seed);
        secret.extend_from_slice(&public_key);
        let encoded = bs58::encode(secret).into_string();
        let keypair = import_solana_base58(&encoded).unwrap();
        assert_eq!(keypair.public_key(), public_key);
    }
    #[test]
    fn rejects_mismatched_or_wrong_length_secret_keys() {
        assert!(import_solana_secret_key(&[0u8; 32]).is_err());
        let mut secret = vec![0u8; 64];
        secret[63] = 1;
        assert!(import_solana_secret_key(&secret).is_err());
        assert!(import_solana_base58(&"z".repeat(MAX_SOLANA_SECRET_BASE58_BYTES + 1)).is_err());
    }

    #[test]
    fn import_errors_do_not_echo_secret_input() {
        let secret = "solana-secret-material";
        let input = format!("[\"{secret}\"]");
        let error = match import_solana_cli_json(input.as_bytes()) {
            Ok(_) => panic!("secret string should not parse as a byte array"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(secret));
    }
    #[test]
    fn json_byte_array_grammar_and_partial_failures() {
        for start in [0u8, 64, 128, 192] {
            let bytes: Vec<u8> = (0..64).map(|offset| start + offset).collect();
            for input in [
                serde_json::to_string(&bytes).unwrap(),
                format!(" \r\n{}\t", serde_json::to_string_pretty(&bytes).unwrap()),
            ] {
                assert_eq!(
                    decode_solana_cli_json(input.as_bytes()).unwrap().as_ref(),
                    &bytes
                );
            }
        }
        for token in [
            "",
            "-1",
            "+1",
            "01",
            "256",
            "1.0",
            "1e0",
            "null",
            "true",
            "[1]",
            "{}",
            "\"secret\\nmaterial\"",
            "\u{a0}1",
            "1\u{b}",
        ] {
            for index in [0, 31, 63] {
                let mut tokens = vec!["7"; 64];
                tokens[index] = token;
                let input = format!("[{}]", tokens.join(","));
                let error = decode_solana_cli_json(input.as_bytes()).unwrap_err();
                assert_eq!(error.to_string(), "Solana CLI keypair JSON is invalid");
            }
        }
        for input in ["[]", "[1,2]", "\"secret\"", "{}", "[1,]", "[1][2]"] {
            assert!(decode_solana_cli_json(input.as_bytes()).is_err());
        }
        let input = serde_json::to_vec(&vec![7u8; 65]).unwrap();
        assert!(decode_solana_cli_json(&input).is_err());
        assert!(decode_solana_cli_json(&[0xff]).is_err());
        assert!(import_solana_cli_json(&vec![b' '; MAX_SOLANA_CLI_JSON_BYTES + 1]).is_err());
    }

    #[test]
    fn imports_json_and_base58_with_leading_zero_seed_bytes() {
        for seed in [[0u8; 32], [7; 32], [255; 32]] {
            let public = ed25519_public_key(&seed);
            let mut secret = Vec::from(seed);
            secret.extend_from_slice(&public);
            let json = serde_json::to_vec(&secret).unwrap();
            let base58 = bs58::encode(&secret).into_string();
            assert_eq!(import_solana_cli_json(&json).unwrap().public_key(), public);
            assert_eq!(import_solana_base58(&base58).unwrap().public_key(), public);
            assert!(import_solana_base58(&format!("{}0", &base58[..base58.len() - 1])).is_err());
        }
        // Within the text cap, but too many decoded bytes for the fixed buffer.
        assert!(import_solana_base58(&"1".repeat(65)).is_err());
    }

    #[test]
    fn accepts_longer_than_digest_messages() {
        let seed = Zeroizing::new([3u8; 32]);
        let message = vec![0xabu8; 128];
        let signature = sign_ed25519(&seed, &message).unwrap();
        assert_eq!(signature.len(), 64);
    }
}
