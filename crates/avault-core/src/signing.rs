use crate::KEY_BYTES;
use anyhow::{anyhow, bail};
use k256::ecdsa::{DerSignature, SigningKey as EcdsaSigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub const SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE: &str = "ecdsa-secp256k1-recoverable";
pub const SIGN_SCHEME_ECDSA_SECP256K1_DER: &str = "ecdsa-secp256k1-der";
pub const SIGN_SCHEME_SCHNORR_SECP256K1_BIP340: &str = "schnorr-secp256k1-bip340";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256k1Recoverable,
    EcdsaSecp256k1Der,
    SchnorrSecp256k1Bip340,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1Recoverable => SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE,
            Self::EcdsaSecp256k1Der => SIGN_SCHEME_ECDSA_SECP256K1_DER,
            Self::SchnorrSecp256k1Bip340 => SIGN_SCHEME_SCHNORR_SECP256K1_BIP340,
        }
    }
}

impl FromStr for SignatureScheme {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE => Ok(Self::EcdsaSecp256k1Recoverable),
            SIGN_SCHEME_ECDSA_SECP256K1_DER => Ok(Self::EcdsaSecp256k1Der),
            SIGN_SCHEME_SCHNORR_SECP256K1_BIP340 => Ok(Self::SchnorrSecp256k1Bip340),
            _ => bail!("unsupported signing scheme"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureResult {
    pub signature: Vec<u8>,
    pub recovery_id: Option<u8>,
}

pub trait SignerProvider {
    fn sign_digest(
        &self,
        scheme: SignatureScheme,
        private_key: &Zeroizing<[u8; KEY_BYTES]>,
        digest: &[u8; KEY_BYTES],
    ) -> anyhow::Result<SignatureResult>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalSignerProvider;

impl SignerProvider for LocalSignerProvider {
    fn sign_digest(
        &self,
        scheme: SignatureScheme,
        private_key: &Zeroizing<[u8; KEY_BYTES]>,
        digest: &[u8; KEY_BYTES],
    ) -> anyhow::Result<SignatureResult> {
        match scheme {
            SignatureScheme::EcdsaSecp256k1Recoverable => {
                sign_ecdsa_recoverable(private_key, digest)
            }
            SignatureScheme::EcdsaSecp256k1Der => sign_ecdsa_der(private_key, digest),
            SignatureScheme::SchnorrSecp256k1Bip340 => sign_schnorr_random_aux(private_key, digest),
        }
    }
}

fn sign_ecdsa_recoverable(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let signing_key =
        EcdsaSigningKey::from_slice(private_key.as_ref()).map_err(|_| anyhow!("invalid key"))?;
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|_| anyhow!("signing failed"))?;
    Ok(SignatureResult {
        signature: signature.to_bytes().to_vec(),
        recovery_id: Some(recovery_id.to_byte()),
    })
}

fn sign_ecdsa_der(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let signing_key =
        EcdsaSigningKey::from_slice(private_key.as_ref()).map_err(|_| anyhow!("invalid key"))?;
    let signature: DerSignature =
        k256::ecdsa::signature::hazmat::PrehashSigner::sign_prehash(&signing_key, digest)
            .map_err(|_| anyhow!("signing failed"))?;
    Ok(SignatureResult {
        signature: signature.to_bytes().into_vec(),
        recovery_id: None,
    })
}

fn sign_schnorr_random_aux(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let mut aux_rand = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut aux_rand);
    let out = sign_schnorr_with_aux(private_key, digest, &aux_rand);
    aux_rand.zeroize();
    out
}

fn sign_schnorr_with_aux(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
    aux_rand: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let signing_key = k256::schnorr::SigningKey::from_bytes(private_key.as_ref())
        .map_err(|_| anyhow!("invalid key"))?;
    let signature = signing_key
        .sign_prehash_with_aux_rand(digest, aux_rand)
        .map_err(|_| anyhow!("signing failed"))?;
    Ok(SignatureResult {
        signature: signature.to_bytes().to_vec(),
        recovery_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: [u8; KEY_BYTES] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];
    const DIGEST: [u8; KEY_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn parses_scheme_ids() {
        assert_eq!(
            SignatureScheme::from_str(SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE).unwrap(),
            SignatureScheme::EcdsaSecp256k1Recoverable
        );
        assert_eq!(
            SignatureScheme::from_str(SIGN_SCHEME_ECDSA_SECP256K1_DER).unwrap(),
            SignatureScheme::EcdsaSecp256k1Der
        );
        assert_eq!(
            SignatureScheme::from_str(SIGN_SCHEME_SCHNORR_SECP256K1_BIP340).unwrap(),
            SignatureScheme::SchnorrSecp256k1Bip340
        );
        assert!(SignatureScheme::from_str("ed25519").is_err());
    }

    #[test]
    fn ecdsa_recoverable_signature_is_stable() {
        let key = Zeroizing::new(PRIVATE_KEY);
        let signer = LocalSignerProvider;
        let result = signer
            .sign_digest(SignatureScheme::EcdsaSecp256k1Recoverable, &key, &DIGEST)
            .unwrap();
        assert_eq!(
            hex::encode(result.signature),
            "4ca3aca3a41bc1ca96d67707e525ac6bd77ddc197a34b4c020be1ee636e29617199556ded3234058daafff2bc3153da60d402d0c71389a11a790b9f1a5862e80"
        );
        assert_eq!(result.recovery_id, Some(0));
    }

    #[test]
    fn ecdsa_der_signature_is_stable() {
        let key = Zeroizing::new(PRIVATE_KEY);
        let signer = LocalSignerProvider;
        let result = signer
            .sign_digest(SignatureScheme::EcdsaSecp256k1Der, &key, &DIGEST)
            .unwrap();
        assert_eq!(
            hex::encode(result.signature),
            "304402204ca3aca3a41bc1ca96d67707e525ac6bd77ddc197a34b4c020be1ee636e296170220199556ded3234058daafff2bc3153da60d402d0c71389a11a790b9f1a5862e80"
        );
        assert_eq!(result.recovery_id, None);
    }

    #[test]
    fn schnorr_bip340_signature_with_fixed_aux_is_stable() {
        let key = Zeroizing::new(PRIVATE_KEY);
        let result = sign_schnorr_with_aux(&key, &DIGEST, &[0u8; KEY_BYTES]).unwrap();
        assert_eq!(
            hex::encode(result.signature),
            "931a3386e9ec69fe1471ba85933640948c0296a79ce2d3801ad5a4d9353550aeb0a5e80358b68088bda70b46e6b77a640c1216826f96292e5799ba2bb7bf1342"
        );
        assert_eq!(result.recovery_id, None);
    }

    #[test]
    fn signatures_match_shared_vector_file() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json"))
                .unwrap();
        let signing = &vector["signing"];
        let private_key = hex::decode(signing["private_key_hex"].as_str().unwrap()).unwrap();
        let private_key = Zeroizing::new(private_key.try_into().unwrap());
        let digest = hex::decode(signing["digest_hex"].as_str().unwrap()).unwrap();
        let digest: [u8; KEY_BYTES] = digest.try_into().unwrap();
        let signer = LocalSignerProvider;

        for scheme in signing["schemes"].as_array().unwrap() {
            let scheme_id = scheme["scheme"].as_str().unwrap();
            let parsed = SignatureScheme::from_str(scheme_id).unwrap();
            let result = if parsed == SignatureScheme::SchnorrSecp256k1Bip340 {
                let aux = hex::decode(signing["schnorr_aux_rand_hex"].as_str().unwrap()).unwrap();
                let aux: [u8; KEY_BYTES] = aux.try_into().unwrap();
                sign_schnorr_with_aux(&private_key, &digest, &aux).unwrap()
            } else {
                signer.sign_digest(parsed, &private_key, &digest).unwrap()
            };
            assert_eq!(hex::encode(result.signature), scheme["signature_hex"]);
            assert_eq!(
                result
                    .recovery_id
                    .map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
                scheme["recovery_id"]
            );
        }
    }

    #[test]
    fn rejects_invalid_private_key() {
        let key = Zeroizing::new([0u8; KEY_BYTES]);
        let signer = LocalSignerProvider;
        assert!(signer
            .sign_digest(SignatureScheme::EcdsaSecp256k1Recoverable, &key, &DIGEST)
            .is_err());
        assert!(signer
            .sign_digest(SignatureScheme::SchnorrSecp256k1Bip340, &key, &DIGEST)
            .is_err());
    }
}
