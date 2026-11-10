//! Public signature verification.
//!
//! This module is keyless: every input is public (a public key, a digest, a signature) and
//! the only output is whether the signature verifies. It never takes, derives, or returns
//! private key material, so it needs no store and nothing here is zeroized.
//!
//! Design: `docs/DESIGN.md` Appendix C · Public signature verification.

use crate::KEY_BYTES;
use anyhow::{anyhow, bail};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{DerSignature, Signature, VerifyingKey};

/// Largest DER encoding of a secp256k1 ECDSA signature: a two-byte SEQUENCE header plus two
/// INTEGERs of at most 33 content bytes (32-byte scalar and a sign-padding zero) each.
const MAX_DER_SIGNATURE_BYTES: usize = 72;

const SEC1_COMPRESSED_BYTES: usize = 33;
const SEC1_UNCOMPRESSED_BYTES: usize = 65;

/// Verify a DER-encoded ECDSA secp256k1 signature (`ecdsa-secp256k1-der`) over a
/// caller-computed 32-byte digest.
///
/// - `Ok(true)`: the signature verifies for this public key and digest.
/// - `Ok(false)`: every input is well formed, but the signature does not verify. This
///   includes a high-S signature: only the low-S form is accepted, so a signature cannot
///   be rewritten into a second valid one.
/// - `Err`: an input is malformed. The public key must be a SEC1 compressed (33 bytes,
///   tag `0x02`/`0x03`) or uncompressed (65 bytes, tag `0x04`) point on the curve; the
///   signature must be strict DER with both scalars nonzero and below the group order.
///   Errors name what failed and never include input bytes.
///
/// The digest is used as given and is never hashed again. This answers only whether the
/// signature matches: whether the key is trusted, and whether the digest covers the bytes
/// the caller is about to rely on, are the caller's decisions.
pub fn verify_ecdsa_secp256k1_der(
    public_key: &[u8],
    digest: &[u8; KEY_BYTES],
    signature: &[u8],
) -> anyhow::Result<bool> {
    let verifying_key = parse_sec1_public_key(public_key)?;
    let signature = parse_der_signature(signature)?;
    // Both inputs are now valid curve values, so the only remaining failures are a high-S
    // signature and a signature that does not match: neither is a malformed request.
    Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
}

fn parse_sec1_public_key(bytes: &[u8]) -> anyhow::Result<VerifyingKey> {
    // k256 would also parse the SEC1 compact form (`0x05`), which carries only X. Accept
    // only the compressed and uncompressed forms, and match the tag to the length here, so
    // the accepted set does not depend on what else the parser understands.
    let expected_len = match bytes.first() {
        Some(0x02 | 0x03) => SEC1_COMPRESSED_BYTES,
        Some(0x04) => SEC1_UNCOMPRESSED_BYTES,
        _ => 0,
    };
    if expected_len == 0 || bytes.len() != expected_len {
        bail!(
            "public key must be a 33-byte compressed or 65-byte uncompressed SEC1 secp256k1 point"
        );
    }
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|_| anyhow!("public key is not a point on the secp256k1 curve"))
}

fn parse_der_signature(bytes: &[u8]) -> anyhow::Result<Signature> {
    if bytes.len() > MAX_DER_SIGNATURE_BYTES {
        bail!("signature exceeds the DER ECDSA secp256k1 size limit");
    }
    let der = DerSignature::from_bytes(bytes)
        .map_err(|_| anyhow!("signature is not a DER-encoded ECDSA signature"))?;
    Signature::try_from(der).map_err(|_| anyhow!("signature scalars are out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalSignerProvider, SignatureScheme, SignerProvider};
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::scalar::IsHigh;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/vectors/verify_ecdsa_secp256k1_der.json"
        ))
        .unwrap()
    }

    fn signing_vector() -> serde_json::Value {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json"))
                .unwrap();
        vector["signing"].clone()
    }

    struct Case {
        name: String,
        expect: String,
        public_key: Vec<u8>,
        digest: [u8; KEY_BYTES],
        signature: Vec<u8>,
    }

    fn cases() -> Vec<Case> {
        fixture()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                let bytes = |field: &str| hex::decode(case[field].as_str().unwrap()).unwrap();
                Case {
                    name: case["name"].as_str().unwrap().to_string(),
                    expect: case["expect"].as_str().unwrap().to_string(),
                    public_key: bytes("public_key_hex"),
                    digest: bytes("digest_hex").try_into().unwrap(),
                    signature: bytes("signature_hex"),
                }
            })
            .collect()
    }

    fn case(name: &str) -> Case {
        cases()
            .into_iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("fixture case {name} is missing"))
    }

    fn verify(case: &Case) -> anyhow::Result<bool> {
        verify_ecdsa_secp256k1_der(&case.public_key, &case.digest, &case.signature)
    }

    #[test]
    fn fixture_cases_match_their_expectations() {
        let mut seen = std::collections::BTreeMap::new();
        let mut names = std::collections::BTreeSet::new();
        for case in cases() {
            assert!(names.insert(case.name.clone()), "duplicate {}", case.name);
            let result = verify(&case);
            match case.expect.as_str() {
                "valid" => assert!(result.unwrap(), "{} must verify", case.name),
                "invalid" => assert!(!result.unwrap(), "{} must not verify", case.name),
                "error" => {
                    let message = format!("{:#}", result.expect_err(&case.name));
                    for input in [&case.public_key, &case.signature] {
                        assert!(
                            input.is_empty() || !message.contains(&hex::encode(input)),
                            "{} error echoes an input",
                            case.name
                        );
                    }
                }
                other => panic!("{} has unknown expectation {other}", case.name),
            }
            *seen.entry(case.expect).or_insert(0usize) += 1;
        }
        // The fixture must keep every class; a filtered or emptied file must not pass.
        assert_eq!(seen["valid"], 5);
        assert_eq!(seen["invalid"], 5);
        assert_eq!(seen["error"], 25);
    }

    #[test]
    fn fixture_is_the_shared_signing_vector() {
        let signing = signing_vector();
        let private_key: [u8; KEY_BYTES] =
            hex::decode(signing["private_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let der_vector = signing["schemes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scheme| scheme["scheme"] == crate::SIGN_SCHEME_ECDSA_SECP256K1_DER)
            .unwrap();
        let verifying_key = *SigningKey::from_slice(&private_key)
            .unwrap()
            .verifying_key();

        let compressed = case("shared-signing-vector-compressed-key");
        let uncompressed = case("shared-signing-vector-uncompressed-key");
        assert_eq!(
            compressed.public_key,
            verifying_key.to_encoded_point(true).as_bytes()
        );
        assert_eq!(
            uncompressed.public_key,
            verifying_key.to_encoded_point(false).as_bytes()
        );
        for case in [&compressed, &uncompressed] {
            assert_eq!(hex::encode(case.digest), signing["digest_hex"]);
            assert_eq!(hex::encode(&case.signature), der_vector["signature_hex"]);
        }
        assert_eq!(
            fixture()["scheme"],
            crate::SIGN_SCHEME_ECDSA_SECP256K1_DER,
            "the fixture is for the one scheme this helper verifies"
        );
    }

    #[test]
    fn verifies_what_the_local_signer_produces() {
        let digest: [u8; KEY_BYTES] = Sha256::digest(b"avault verify roundtrip").into();
        for private_key in [[0x11u8; KEY_BYTES], [0x7fu8; KEY_BYTES]] {
            let signed = LocalSignerProvider
                .sign_digest(
                    SignatureScheme::EcdsaSecp256k1Der,
                    &Zeroizing::new(private_key),
                    &digest,
                )
                .unwrap();
            let verifying_key = *SigningKey::from_slice(&private_key)
                .unwrap()
                .verifying_key();
            for compress in [true, false] {
                let public_key = verifying_key.to_encoded_point(compress);
                assert!(verify_ecdsa_secp256k1_der(
                    public_key.as_bytes(),
                    &digest,
                    &signed.signature
                )
                .unwrap());
            }
        }
    }

    #[test]
    fn published_rfc6979_vector_matches_the_local_signer() {
        // Private key 1 signing SHA-256("Satoshi Nakamoto") is deterministic under RFC 6979,
        // so the fixture case is reproducible by any conforming signer, not only by k256.
        let case = case("rfc6979-private-key-one");
        let digest: [u8; KEY_BYTES] = Sha256::digest(b"Satoshi Nakamoto").into();
        assert_eq!(case.digest, digest);
        let mut private_key = [0u8; KEY_BYTES];
        private_key[KEY_BYTES - 1] = 1;
        let signed = LocalSignerProvider
            .sign_digest(
                SignatureScheme::EcdsaSecp256k1Der,
                &Zeroizing::new(private_key),
                &digest,
            )
            .unwrap();
        assert_eq!(signed.signature, case.signature);
        assert!(verify(&case).unwrap());
    }

    #[test]
    fn domain_separated_digest_case_is_reproducible_from_its_preimage() {
        // How a caller is expected to use `verify`: hash a fixed domain prefix and the exact
        // payload bytes itself, then check the publisher's signature over that digest.
        let fixture = fixture();
        let raw = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "domain-separated-payload-digest")
            .unwrap();
        let preimage = &raw["digest_preimage"];
        let mut hasher = Sha256::new();
        hasher.update(preimage["domain_utf8"].as_str().unwrap());
        hasher.update(preimage["payload_utf8"].as_str().unwrap());
        let digest: [u8; KEY_BYTES] = hasher.finalize().into();

        let shared = case("shared-signing-vector-compressed-key");
        let case = case("domain-separated-payload-digest");
        assert_eq!(case.digest, digest);
        assert_eq!(case.public_key, shared.public_key);
        let private_key: [u8; KEY_BYTES] =
            hex::decode(signing_vector()["private_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let signed = LocalSignerProvider
            .sign_digest(
                SignatureScheme::EcdsaSecp256k1Der,
                &Zeroizing::new(private_key),
                &digest,
            )
            .unwrap();
        assert_eq!(signed.signature, case.signature);
        assert!(verify(&case).unwrap());
    }

    #[test]
    fn high_s_twin_of_a_valid_signature_does_not_verify() {
        let valid = case("shared-signing-vector-compressed-key");
        let signature =
            Signature::try_from(DerSignature::from_bytes(&valid.signature).unwrap()).unwrap();
        let (r, s) = signature.split_scalars();
        let high_s = Signature::from_scalars(*r, -*s).unwrap();
        assert!(bool::from(high_s.s().is_high()));

        // (r, n - s) satisfies the ECDSA equation for the same key and digest; only the
        // low-S rule rejects it.
        let fixture_case = case("high-s-signature");
        assert_eq!(fixture_case.signature, high_s.to_der().as_bytes());
        assert!(!verify(&fixture_case).unwrap());
        assert_eq!(high_s.normalize_s().unwrap(), signature);
    }

    #[test]
    fn rejects_point_encodings_k256_would_otherwise_parse() {
        let compact = case("public-key-compact-tag");
        // k256 reads the compact form as the even-Y point with this X, which here is the
        // signer's key: without the explicit tag check this signature would verify.
        assert!(VerifyingKey::from_sec1_bytes(&compact.public_key).is_ok());
        assert!(verify(&compact).is_err());
    }

    #[test]
    fn single_bit_changes_never_verify_or_panic() {
        let valid = case("shared-signing-vector-compressed-key");
        assert!(verify(&valid).unwrap());

        let flipped = |bytes: &[u8], bit: usize| {
            let mut bytes = bytes.to_vec();
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        };
        for bit in 0..valid.signature.len() * 8 {
            let signature = flipped(&valid.signature, bit);
            let result = verify_ecdsa_secp256k1_der(&valid.public_key, &valid.digest, &signature);
            assert!(!result.unwrap_or(false), "signature bit {bit}");
        }
        for bit in 0..valid.digest.len() * 8 {
            let digest: [u8; KEY_BYTES] = flipped(&valid.digest, bit).try_into().unwrap();
            let result = verify_ecdsa_secp256k1_der(&valid.public_key, &digest, &valid.signature);
            assert!(!result.unwrap(), "digest bit {bit}");
        }
        for bit in 0..valid.public_key.len() * 8 {
            let public_key = flipped(&valid.public_key, bit);
            let result = verify_ecdsa_secp256k1_der(&public_key, &valid.digest, &valid.signature);
            assert!(!result.unwrap_or(false), "public key bit {bit}");
        }
    }

    #[test]
    fn every_truncation_of_a_valid_signature_is_an_error() {
        let valid = case("shared-signing-vector-compressed-key");
        for len in 0..valid.signature.len() {
            assert!(
                verify_ecdsa_secp256k1_der(
                    &valid.public_key,
                    &valid.digest,
                    &valid.signature[..len]
                )
                .is_err(),
                "truncation to {len} bytes"
            );
        }
    }
}
