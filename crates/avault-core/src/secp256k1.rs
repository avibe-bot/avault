//! Standard-tier secp256k1 generation: only ciphertext and a public key leave this path.

use crate::{seal, Sealed, KEY_BYTES};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Generate a secp256k1 key with the OS CSPRNG and immediately seal its raw
/// 32-byte big-endian scalar under the existing master/name-bound envelope.
/// Returns only that envelope and the 33-byte compressed SEC1 public key.
/// No caller-supplied scalar or deterministic RNG is accepted by this API.
pub fn generate_sealed_secp256k1_keypair(
    master_key: &[u8; KEY_BYTES],
    name: &str,
) -> anyhow::Result<(Sealed, [u8; 33])> {
    seal_keypair(master_key, name, SecretKey::random(&mut OsRng))
}

fn seal_keypair(
    master_key: &[u8; KEY_BYTES],
    name: &str,
    secret: SecretKey,
) -> anyhow::Result<(Sealed, [u8; 33])> {
    let encoded_public = secret.public_key().to_encoded_point(true);
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(encoded_public.as_bytes());
    // SecretKey wipes its scalar on Drop. Guard its one serialized copy before
    // sealing, including the seal error path; neither is Debug/JSON output.
    let private_bytes = Zeroizing::new(secret.to_bytes());
    drop(secret);
    let envelope = seal(master_key, name, private_bytes.as_ref())?;
    drop(private_bytes);
    Ok((envelope, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        open, verify_ecdsa_secp256k1_der, LocalSignerProvider, SignatureScheme, SignerProvider,
    };

    const MASTER: [u8; KEY_BYTES] = [0x42; KEY_BYTES];
    const NAME: &str = "TEST_CHANNEL_KEY";

    #[test]
    fn sealed_secp256k1_matches_published_key_and_signature_fixtures() {
        // Reuse fixtures published before this generation path: the shared
        // synthetic signing key and the RFC6979 private-key-one vector. Expected
        // public keys/signatures are fixture bytes, never computed here.
        let signing: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json"))
                .unwrap();
        let verification: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/verify_ecdsa_secp256k1_der.json"
        ))
        .unwrap();
        for (case_name, scalar_hex) in [
            (
                "shared-signing-vector-compressed-key",
                signing["signing"]["private_key_hex"].as_str().unwrap(),
            ),
            (
                "rfc6979-private-key-one",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
        ] {
            let case = verification["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == case_name)
                .unwrap();
            let scalar = Zeroizing::new(hex::decode(scalar_hex).unwrap());
            let secret = SecretKey::from_slice(&scalar).unwrap();
            let (envelope, public_key) = seal_keypair(&MASTER, NAME, secret).unwrap();
            assert_eq!(hex::encode(public_key), case["public_key_hex"]);
            let opened = open(&MASTER, NAME, &envelope).unwrap();
            assert_eq!(opened.as_slice(), scalar.as_slice());
            let mut key = Zeroizing::new([0u8; KEY_BYTES]);
            key.copy_from_slice(&opened);
            drop(opened);
            let digest: [u8; KEY_BYTES] = hex::decode(case["digest_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let signature = LocalSignerProvider
                .sign_digest(SignatureScheme::EcdsaSecp256k1Der, &key, &digest)
                .unwrap();
            assert_eq!(hex::encode(&signature.signature), case["signature_hex"]);
            assert_eq!(signature.recovery_id, None);
            assert!(
                verify_ecdsa_secp256k1_der(&public_key, &digest, &signature.signature).unwrap()
            );
            assert!(open(&MASTER, "OTHER_RECORD", &envelope).is_err());
            assert!(open(&[0x43; KEY_BYTES], NAME, &envelope).is_err());
        }
    }

    #[test]
    fn generated_secp256k1_keys_are_distinct_and_sign_with_the_returned_public_key() {
        let mut previous = None;
        for _ in 0..2 {
            let (envelope, public_key) = generate_sealed_secp256k1_keypair(&MASTER, NAME).unwrap();
            assert_ne!(previous, Some(public_key));
            previous = Some(public_key);
            assert!(matches!(public_key[0], 2 | 3));
            let opened = open(&MASTER, NAME, &envelope).unwrap();
            assert_eq!(opened.len(), KEY_BYTES);
            let mut key = Zeroizing::new([0u8; KEY_BYTES]);
            key.copy_from_slice(&opened);
            drop(opened);
            let digest = [0x24; KEY_BYTES];
            let signature = LocalSignerProvider
                .sign_digest(SignatureScheme::EcdsaSecp256k1Der, &key, &digest)
                .unwrap();
            assert!(
                verify_ecdsa_secp256k1_der(&public_key, &digest, &signature.signature).unwrap()
            );
            assert!(open(&MASTER, "OTHER_RECORD", &envelope).is_err());
        }
    }
}
