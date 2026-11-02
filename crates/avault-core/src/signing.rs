use crate::KEY_BYTES;
use anyhow::{anyhow, bail};
use k256::ecdsa::{DerSignature, SigningKey as EcdsaSigningKey};
use k256::elliptic_curve::{
    ff::PrimeField, group::prime::PrimeCurveAffine, point::AffineCoordinates,
};
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub const SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE: &str = "ecdsa-secp256k1-recoverable";
pub const SIGN_SCHEME_ECDSA_SECP256K1_DER: &str = "ecdsa-secp256k1-der";
pub const SIGN_SCHEME_SCHNORR_SECP256K1_BIP340: &str = "schnorr-secp256k1-bip340";
pub const SIGN_SCHEME_SCHNORR_SECP256K1_BIP341_KEYPATH: &str = "schnorr-secp256k1-bip341-keypath";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256k1Recoverable,
    EcdsaSecp256k1Der,
    SchnorrSecp256k1Bip340,
    SchnorrSecp256k1Bip341Keypath,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1Recoverable => SIGN_SCHEME_ECDSA_SECP256K1_RECOVERABLE,
            Self::EcdsaSecp256k1Der => SIGN_SCHEME_ECDSA_SECP256K1_DER,
            Self::SchnorrSecp256k1Bip340 => SIGN_SCHEME_SCHNORR_SECP256K1_BIP340,
            Self::SchnorrSecp256k1Bip341Keypath => SIGN_SCHEME_SCHNORR_SECP256K1_BIP341_KEYPATH,
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
            SIGN_SCHEME_SCHNORR_SECP256K1_BIP341_KEYPATH => Ok(Self::SchnorrSecp256k1Bip341Keypath),
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
            SignatureScheme::SchnorrSecp256k1Bip341Keypath => {
                sign_schnorr_bip341_keypath_random_aux(private_key, digest)
            }
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
fn sign_schnorr_bip341_keypath_random_aux(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let mut aux_rand = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut aux_rand);
    let out = sign_schnorr_bip341_keypath_with_aux(private_key, digest, &aux_rand);
    aux_rand.zeroize();
    out
}

fn sign_schnorr_bip341_keypath_with_aux(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
    digest: &[u8; KEY_BYTES],
    aux_rand: &[u8; KEY_BYTES],
) -> anyhow::Result<SignatureResult> {
    let material = taproot_keypath_material(private_key)?;
    let result = sign_schnorr_with_aux(&material.tweaked_secret, digest, aux_rand)?;
    let verifying_key = k256::schnorr::VerifyingKey::from_bytes(&material.output_x)
        .map_err(|_| anyhow!("invalid taproot output key"))?;
    let signature = k256::schnorr::Signature::try_from(result.signature.as_slice())
        .map_err(|_| anyhow!("signing produced an invalid signature"))?;
    k256::schnorr::signature::hazmat::PrehashVerifier::verify_prehash(
        &verifying_key,
        digest,
        &signature,
    )
    .map_err(|_| anyhow!("taproot signature verification failed"))?;
    Ok(result)
}

struct TaprootKeyMaterial {
    tweaked_secret: Zeroizing<[u8; KEY_BYTES]>,
    output_x: [u8; KEY_BYTES],
}

const TAP_TWEAK_TAG: &[u8] = b"TapTweak";

/// Derive the BIP86 key-path secret and output key for an empty script tree.
///
/// This intentionally has no merkle-root parameter: the additive scheme is only for the
/// existing key-only addresses. The internal scalar is first normalized to the even-Y x-only
/// representative required by BIP340, then the raw (non-reduced) TapTweak hash is added.
fn taproot_keypath_material(
    private_key: &Zeroizing<[u8; KEY_BYTES]>,
) -> anyhow::Result<TaprootKeyMaterial> {
    let private_scalar = parse_private_scalar(private_key)?;
    let internal_point = (ProjectivePoint::GENERATOR * *private_scalar).to_affine();
    let normalized_secret = Zeroizing::new(if bool::from(internal_point.y_is_odd()) {
        -*private_scalar
    } else {
        *private_scalar
    });
    let normalized_point = (ProjectivePoint::GENERATOR * *normalized_secret).to_affine();
    let internal_x = normalized_point.x();
    let tweak_hash = tagged_hash(TAP_TWEAK_TAG, internal_x.as_ref());
    taproot_keypath_material_with_tweak(&normalized_secret, &normalized_point, &tweak_hash)
}

fn taproot_keypath_material_with_tweak(
    normalized_secret: &Zeroizing<Scalar>,
    internal_point: &k256::AffinePoint,
    tweak_bytes: &[u8; KEY_BYTES],
) -> anyhow::Result<TaprootKeyMaterial> {
    let tweak: Zeroizing<Scalar> = Zeroizing::new(
        Option::from(Scalar::from_repr((*tweak_bytes).into()))
            .ok_or_else(|| anyhow!("taproot tweak is out of range"))?,
    );
    let tweaked_secret: Zeroizing<Scalar> = Zeroizing::new(**normalized_secret + *tweak);
    if bool::from(tweaked_secret.is_zero()) {
        bail!("taproot tweaked secret is zero");
    }

    // Compute Q from the normalized public P plus the public tweak point. Keep this independent
    // from the scalar addition above so the BIP341 output-key check cannot repeat the same bug.
    let output_point = (ProjectivePoint::from(*internal_point)
        + (ProjectivePoint::GENERATOR * *tweak))
        .to_affine();
    if bool::from(output_point.is_identity()) {
        bail!("taproot output key is the point at infinity");
    }
    let mut output_x = [0u8; KEY_BYTES];
    output_x.copy_from_slice(output_point.x().as_ref());

    let encoded_secret = Zeroizing::new(tweaked_secret.to_bytes());
    let mut tweaked_secret_bytes = Zeroizing::new([0u8; KEY_BYTES]);
    tweaked_secret_bytes.copy_from_slice(encoded_secret.as_ref());
    Ok(TaprootKeyMaterial {
        tweaked_secret: tweaked_secret_bytes,
        output_x,
    })
}

fn parse_private_scalar(private_key: &[u8; KEY_BYTES]) -> anyhow::Result<Zeroizing<Scalar>> {
    let scalar: Scalar = Option::from(Scalar::from_repr((*private_key).into()))
        .ok_or_else(|| anyhow!("invalid key"))?;
    if bool::from(scalar.is_zero()) {
        bail!("invalid key");
    }
    Ok(Zeroizing::new(scalar))
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; KEY_BYTES] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
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
            SignatureScheme::from_str(SIGN_SCHEME_SCHNORR_SECP256K1_BIP341_KEYPATH).unwrap(),
            SignatureScheme::SchnorrSecp256k1Bip341Keypath
        );
        assert!(SignatureScheme::from_str("ed25519").is_err());
    }

    #[test]
    fn bip341_keypath_matches_official_empty_tree_vector() {
        // bitcoin/bips bip-0341 wallet-test-vectors.json, revision pinned by SHA-256
        // 403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f.
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/bip341_wallet_test_vectors.json"
        ))
        .unwrap();
        let mut matched = 0;
        for case in vector["keyPathSpending"].as_array().unwrap() {
            for input in case["inputSpending"].as_array().unwrap() {
                let given = &input["given"];
                if !given["merkleRoot"].is_null() {
                    continue;
                }
                let private_key: [u8; KEY_BYTES] =
                    hex::decode(given["internalPrivkey"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                let digest: [u8; KEY_BYTES] =
                    hex::decode(input["intermediary"]["sigHash"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                let key = Zeroizing::new(private_key);
                let material = taproot_keypath_material(&key).unwrap();
                assert_eq!(
                    hex::encode(material.tweaked_secret.as_ref()),
                    input["intermediary"]["tweakedPrivkey"]
                );
                let result =
                    sign_schnorr_bip341_keypath_with_aux(&key, &digest, &[0u8; KEY_BYTES]).unwrap();
                let expected = input["expected"]["witness"][0].as_str().unwrap();
                assert_eq!(hex::encode(result.signature), &expected[..128]);
                assert_eq!(result.recovery_id, None);
                matched += 1;
            }
        }
        assert_eq!(
            matched, 1,
            "the fixture must retain one BIP86 key-only spend vector"
        );
    }

    #[test]
    fn bip341_keypath_handles_internal_parity_and_rejects_invalid_tweaks() {
        let digest = [0x42u8; KEY_BYTES];
        for private_key_hex in [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000006",
        ] {
            let private_key: [u8; KEY_BYTES] =
                hex::decode(private_key_hex).unwrap().try_into().unwrap();
            let key = Zeroizing::new(private_key);
            let scalar = parse_private_scalar(&key).unwrap();
            let internal_point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
            let mut internal_x = [0u8; KEY_BYTES];
            internal_x.copy_from_slice(internal_point.x().as_ref());
            let internal_verifier = k256::schnorr::VerifyingKey::from_bytes(&internal_x).unwrap();
            let raw = sign_schnorr_with_aux(&key, &digest, &[0u8; KEY_BYTES]).unwrap();
            let raw_signature =
                k256::schnorr::Signature::try_from(raw.signature.as_slice()).unwrap();
            k256::schnorr::signature::hazmat::PrehashVerifier::verify_prehash(
                &internal_verifier,
                &digest,
                &raw_signature,
            )
            .unwrap();

            let material = taproot_keypath_material(&key).unwrap();
            let output_verifier =
                k256::schnorr::VerifyingKey::from_bytes(&material.output_x).unwrap();
            assert!(
                k256::schnorr::signature::hazmat::PrehashVerifier::verify_prehash(
                    &output_verifier,
                    &digest,
                    &raw_signature,
                )
                .is_err()
            );
            let keypath =
                sign_schnorr_bip341_keypath_with_aux(&key, &digest, &[0u8; KEY_BYTES]).unwrap();
            let keypath_signature =
                k256::schnorr::Signature::try_from(keypath.signature.as_slice()).unwrap();
            k256::schnorr::signature::hazmat::PrehashVerifier::verify_prehash(
                &output_verifier,
                &digest,
                &keypath_signature,
            )
            .unwrap();
        }

        let odd_key: [u8; KEY_BYTES] =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000006")
                .unwrap()
                .try_into()
                .unwrap();
        let odd_key = Zeroizing::new(odd_key);
        let scalar = parse_private_scalar(&odd_key).unwrap();
        let point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
        let normalized = Zeroizing::new(if bool::from(point.y_is_odd()) {
            -*scalar
        } else {
            *scalar
        });
        let normalized_point = (ProjectivePoint::GENERATOR * *normalized).to_affine();
        let zero_tweak =
            taproot_keypath_material_with_tweak(&normalized, &normalized_point, &[0u8; KEY_BYTES])
                .unwrap();
        assert_eq!(zero_tweak.output_x, normalized_point.x().as_ref());
        let expected_secret: [u8; KEY_BYTES] = normalized.to_bytes().into();
        assert_eq!(zero_tweak.tweaked_secret.as_ref(), &expected_secret);

        let order: [u8; KEY_BYTES] =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(
            taproot_keypath_material_with_tweak(&normalized, &normalized_point, &order).is_err()
        );
    }

    #[test]
    fn bip86_published_leaf_vectors_cover_all_key_parities() {
        // bitcoin/bips bip-0086.mediawiki, Account 0 published leaves. The address strings are
        // included so this signer regression also pins the exact output keys shown to users.
        let vectors = [
            (
                "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361",
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
            ),
            (
                "86c68ac0ed7df88cbdd08a847c6d639f87d1234d40503abf3ac178ef7ddc05dd",
                "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
                "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
                "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
            ),
            (
                "6ccbca4a02ac648702dde463d9c1b0d328a4df1e068ef9dc2bc788b33a4f0412",
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
                "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            ),
        ];
        let mut parity_pairs = std::collections::BTreeSet::new();
        for (private_hex, internal_hex, output_hex, address) in vectors {
            let private_key: [u8; KEY_BYTES] =
                hex::decode(private_hex).unwrap().try_into().unwrap();
            let key = Zeroizing::new(private_key);
            let scalar = parse_private_scalar(&key).unwrap();
            let point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
            let mut internal_x = [0u8; KEY_BYTES];
            internal_x.copy_from_slice(point.x().as_ref());
            assert_eq!(hex::encode(internal_x), internal_hex);
            let material = taproot_keypath_material(&key).unwrap();
            assert_eq!(hex::encode(material.output_x), output_hex);
            assert_eq!(bech32m_v1(output_hex), address);

            let normalized = Zeroizing::new(if bool::from(point.y_is_odd()) {
                -*scalar
            } else {
                *scalar
            });
            let normalized_point = (ProjectivePoint::GENERATOR * *normalized).to_affine();
            let tweak_hash = tagged_hash(TAP_TWEAK_TAG, normalized_point.x().as_ref());
            let tweak: Scalar = Option::from(Scalar::from_repr(tweak_hash.into())).unwrap();
            let output_point = (ProjectivePoint::from(normalized_point)
                + ProjectivePoint::GENERATOR * tweak)
                .to_affine();
            parity_pairs.insert((
                if bool::from(point.y_is_odd()) {
                    "odd"
                } else {
                    "even"
                },
                if bool::from(output_point.y_is_odd()) {
                    "odd"
                } else {
                    "even"
                },
            ));
        }
        assert_eq!(parity_pairs.len(), 3);
        assert!(parity_pairs.contains(&("odd", "odd")));
        assert!(parity_pairs.contains(&("even", "even")));
        assert!(parity_pairs.contains(&("even", "odd")));
    }

    fn bech32m_v1(output_hex: &str) -> String {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let program = hex::decode(output_hex).unwrap();
        let mut data = vec![1u8];
        let mut acc = 0u32;
        let mut bits = 0u8;
        for byte in program {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits != 0 {
            data.push(((acc << (5 - bits)) & 31) as u8);
        }
        fn polymod(values: &[u8]) -> u32 {
            let generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
            let mut checksum = 1u32;
            for value in values {
                let top = checksum >> 25;
                checksum = ((checksum & 0x1ffffff) << 5) ^ u32::from(*value);
                for (bit, generator) in generators.iter().enumerate() {
                    if (top >> bit) & 1 != 0 {
                        checksum ^= generator;
                    }
                }
            }
            checksum
        }
        fn hrp_expand(hrp: &str) -> Vec<u8> {
            let bytes = hrp.as_bytes();
            let mut expanded = bytes.iter().map(|byte| byte >> 5).collect::<Vec<_>>();
            expanded.push(0);
            expanded.extend(bytes.iter().map(|byte| byte & 31));
            expanded
        }
        let hrp = "bc";
        let mut values = hrp_expand(hrp);
        values.extend_from_slice(&data);
        values.extend_from_slice(&[0; 6]);
        let checksum = polymod(&values) ^ 0x2bc830a3;
        let mut output = format!("{hrp}1");
        output.extend(
            data.into_iter()
                .map(|value| CHARSET[value as usize] as char),
        );
        for shift in (0..30).step_by(5).rev() {
            output.push(CHARSET[((checksum >> shift) & 31) as usize] as char);
        }
        output
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
