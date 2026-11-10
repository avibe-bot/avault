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
    let values: Zeroizing<Vec<u8>> =
        serde_json::from_slice(input).map_err(|_| anyhow!("Solana CLI keypair JSON is invalid"))?;
    import_solana_secret_key(values.as_slice())
}

/// Import a base58-encoded Solana 64-byte secret key.
pub fn import_solana_base58(input: &str) -> anyhow::Result<Ed25519Keypair> {
    let decoded = bs58::decode(input.trim())
        .into_vec()
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("Solana secret key is not valid base58"))?;
    import_solana_secret_key(decoded.as_slice())
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
    fn accepts_longer_than_digest_messages() {
        let seed = Zeroizing::new([3u8; 32]);
        let message = vec![0xabu8; 128];
        let signature = sign_ed25519(&seed, &message).unwrap();
        assert_eq!(signature.len(), 64);
    }
}
