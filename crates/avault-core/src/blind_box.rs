use crate::{b64, unb64, KEY_BYTES, WRAP_META_VERSION, WRAP_SCHEME};
use anyhow::bail;
use hkdf::Hkdf;
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, Deserializable, Kem,
    OpModeR, Serializable,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HpkeKem = X25519HkdfSha256;
type HpkePrivateKey = <HpkeKem as Kem>::PrivateKey;
type HpkePublicKey = <HpkeKem as Kem>::PublicKey;
type HpkeEncappedKey = <HpkeKem as Kem>::EncappedKey;

/// Blind-box scheme identifier used on the JSON wire.
pub const BLIND_BOX_SCHEME: &str = "hpke-x25519-hkdfsha256-aes256gcm-v1";
/// HPKE `info` string for avault blind boxes.
pub const BLIND_BOX_HPKE_INFO: &[u8] = b"avault:blind-box:v1";
/// Domain separator for operation-bound blind-box AAD.
pub const BLIND_BOX_AAD_DOMAIN: &[u8] = b"avault:blind-box:aad:v1";
const CLI_DERIVED_RECEIVER_SALT: &[u8] = b"avault:blind-box:receiver-salt:v1";
const CLI_DERIVED_RECEIVER_INFO: &[u8] = b"avault:blind-box:receiver-x25519:v1";
const BLIND_BOX_PURPOSE_SEAL: &str = "seal";
const BLIND_BOX_PURPOSE_DELIVER: &str = "deliver";
const BLIND_BOX_PURPOSE_AGENT_DELIVER: &str = "agent-deliver";
const BLIND_BOX_PURPOSE_SIGN: &str = "sign";
const BLIND_BOX_PURPOSE_AGENT_SIGN: &str = "agent-sign";

/// Browser-to-avault blind box.
///
/// `enc` is the HPKE encapsulated key and `ct` is ciphertext plus AEAD tag.
/// Both byte strings are standard base64. The HPKE mode is Base with
/// DHKEM-X25519-HKDF-SHA256, HKDF-SHA256, and AES-256-GCM.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlindBox {
    pub scheme: String,
    pub enc: String,
    pub ct: String,
}

/// Operation context authenticated by a blind box.
///
/// The browser constructs the same context before HPKE sealing. avault constructs
/// it again from the approved operation before opening; a blind box from one
/// operation therefore cannot be replayed into a different name, scope, or
/// signing digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindBoxContext {
    purpose: &'static str,
    name: String,
    scope_type: Option<String>,
    scope_ref: Option<String>,
    sign_scheme: Option<String>,
    digest: Option<[u8; KEY_BYTES]>,
    approval_nonce: Option<Vec<u8>>,
    approval_expires_at_unix: Option<u64>,
    operation_hash: Option<[u8; KEY_BYTES]>,
}

impl BlindBoxContext {
    /// Context for `seal --blind-box` standard-tier creation.
    pub fn seal(name: &str) -> Self {
        Self::new(BLIND_BOX_PURPOSE_SEAL, name)
    }

    /// Context for one-shot protected delivery with a DEK blind box.
    pub fn deliver(name: &str) -> Self {
        Self::new(BLIND_BOX_PURPOSE_DELIVER, name)
    }

    /// Context for an agent grant that caches a delivery DEK under a scope.
    pub fn agent_deliver(scope_type: &str, scope_ref: &str, name: &str) -> Self {
        Self::new(BLIND_BOX_PURPOSE_AGENT_DELIVER, name).with_scope(scope_type, scope_ref)
    }

    /// Context for one-shot protected signing with a DEK blind box.
    pub fn sign(name: &str, sign_scheme: &str, digest: &[u8; KEY_BYTES]) -> Self {
        Self::new(BLIND_BOX_PURPOSE_SIGN, name).with_signing(sign_scheme, digest)
    }

    /// Context for an agent grant that caches a signing DEK for one approved digest.
    pub fn agent_sign(
        scope_type: &str,
        scope_ref: &str,
        name: &str,
        sign_scheme: &str,
        digest: &[u8; KEY_BYTES],
    ) -> Self {
        Self::new(BLIND_BOX_PURPOSE_AGENT_SIGN, name)
            .with_scope(scope_type, scope_ref)
            .with_signing(sign_scheme, digest)
    }

    fn new(purpose: &'static str, name: &str) -> Self {
        Self {
            purpose,
            name: name.to_string(),
            scope_type: None,
            scope_ref: None,
            sign_scheme: None,
            digest: None,
            approval_nonce: None,
            approval_expires_at_unix: None,
            operation_hash: None,
        }
    }

    fn with_scope(mut self, scope_type: &str, scope_ref: &str) -> Self {
        self.scope_type = Some(scope_type.to_string());
        self.scope_ref = Some(scope_ref.to_string());
        self
    }

    fn with_signing(mut self, sign_scheme: &str, digest: &[u8; KEY_BYTES]) -> Self {
        self.sign_scheme = Some(sign_scheme.to_string());
        self.digest = Some(*digest);
        self
    }

    /// Add a per-approval nonce and expiry to prevent replay of old browser releases.
    pub fn with_approval(mut self, nonce: &[u8], expires_at_unix: u64) -> Self {
        self.approval_nonce = Some(nonce.to_vec());
        self.approval_expires_at_unix = Some(expires_at_unix);
        self
    }

    /// Add a SHA-256 commitment to the approved operation details.
    pub fn with_operation_hash(mut self, operation_hash: [u8; KEY_BYTES]) -> Self {
        self.operation_hash = Some(operation_hash);
        self
    }

    /// Build a stable SHA-256 commitment from length-prefixed operation fields.
    pub fn operation_hash(fields: &[&[u8]]) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        for field in fields {
            let len = u32::try_from(field.len()).expect("operation hash field length fits u32");
            hasher.update(len.to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }

    /// Return the exact HPKE AAD bytes for this context.
    ///
    /// Encoding:
    /// `BLIND_BOX_AAD_DOMAIN || field(purpose) || field(name) ||
    /// field(WRAP_SCHEME) || field([WRAP_META_VERSION]) || field(scope_type or "")
    /// || field(scope_ref or "") || field(sign_scheme or "") || field(digest or "")
    /// || field(approval_nonce or "") || field(approval_expires_at_unix_be or "")
    /// || field(operation_hash or "")`,
    /// where `field(x) = uint32_be(len(x)) || x`.
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(BLIND_BOX_AAD_DOMAIN);
        push_aad_field(&mut out, self.purpose.as_bytes());
        push_aad_field(&mut out, self.name.as_bytes());
        push_aad_field(&mut out, WRAP_SCHEME.as_bytes());
        push_aad_field(&mut out, &[WRAP_META_VERSION]);
        push_aad_field(
            &mut out,
            self.scope_type.as_deref().unwrap_or("").as_bytes(),
        );
        push_aad_field(&mut out, self.scope_ref.as_deref().unwrap_or("").as_bytes());
        push_aad_field(
            &mut out,
            self.sign_scheme.as_deref().unwrap_or("").as_bytes(),
        );
        push_aad_field(
            &mut out,
            self.digest.as_ref().map(|d| d.as_slice()).unwrap_or(&[]),
        );
        push_aad_field(&mut out, self.approval_nonce.as_deref().unwrap_or(&[]));
        push_aad_field(
            &mut out,
            self.approval_expires_at_unix
                .map(|v| v.to_be_bytes())
                .as_ref()
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
        );
        push_aad_field(
            &mut out,
            self.operation_hash
                .as_ref()
                .map(|d| d.as_slice())
                .unwrap_or(&[]),
        );
        out
    }

    pub fn purpose(&self) -> &'static str {
        self.purpose
    }
}

fn push_aad_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("blind-box AAD field length fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

/// In-memory X25519 receiver keypair for opening blind boxes.
///
/// The private key type from `hpke` wraps `x25519-dalek::StaticSecret`, which is
/// zeroize-on-drop.
pub struct BlindBoxKeypair {
    private_key: HpkePrivateKey,
    public_key: HpkePublicKey,
}

impl BlindBoxKeypair {
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    pub fn public_key_b64(&self) -> String {
        b64(&self.public_key_bytes())
    }

    pub fn fingerprint_hex(&self) -> String {
        let digest = Sha256::digest(self.public_key_bytes());
        hex::encode(digest)
    }

    pub fn open(
        &self,
        blind_box: &BlindBox,
        context: &BlindBoxContext,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        open_blind_box_with_private_key(&self.private_key, blind_box, context)
    }
}

/// Generate a fresh in-memory blind-box receiver keypair.
pub fn generate_blind_box_keypair() -> BlindBoxKeypair {
    let mut ikm = Zeroizing::new([0u8; KEY_BYTES]);
    OsRng.fill_bytes(ikm.as_mut());
    derive_blind_box_keypair(ikm.as_ref())
}

/// Derive the one-shot CLI receiver keypair from the machine master key.
///
/// The resident agent will use a fresh in-memory keypair for its process lifetime.
/// The one-shot CLI cannot keep a random private key across `pubkey` and `seal`,
/// so it deterministically derives a receiver keypair from the already-resident
/// master key, never stores it, and drops it after the operation.
pub fn derive_blind_box_keypair_from_master(master_key: &[u8; KEY_BYTES]) -> BlindBoxKeypair {
    let hkdf = Hkdf::<Sha256>::new(Some(CLI_DERIVED_RECEIVER_SALT), master_key);
    let mut ikm = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf.expand(CLI_DERIVED_RECEIVER_INFO, ikm.as_mut())
        .expect("HKDF output length is fixed");
    derive_blind_box_keypair(ikm.as_ref())
}

fn derive_blind_box_keypair(ikm: &[u8]) -> BlindBoxKeypair {
    let (private_key, public_key) = HpkeKem::derive_keypair(ikm);
    BlindBoxKeypair {
        private_key,
        public_key,
    }
}

fn open_blind_box_with_private_key(
    private_key: &HpkePrivateKey,
    blind_box: &BlindBox,
    context: &BlindBoxContext,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if blind_box.scheme != BLIND_BOX_SCHEME {
        bail!("unsupported blind-box scheme");
    }
    let enc = unb64(&blind_box.enc, "enc")?;
    let ct = unb64(&blind_box.ct, "ct")?;
    let encapped_key =
        HpkeEncappedKey::from_bytes(&enc).map_err(|_| anyhow::anyhow!("enc has invalid length"))?;
    let plaintext = single_shot_open::<AesGcm256, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        private_key,
        &encapped_key,
        BLIND_BOX_HPKE_INFO,
        &ct,
        &context.aad_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("blind-box open failed"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
pub(crate) fn seal_blind_box_for_tests(
    public_key_b64: &str,
    plaintext: &[u8],
    rng_seed: [u8; 32],
    context: &BlindBoxContext,
) -> anyhow::Result<BlindBox> {
    use hpke::rand_core::{CryptoRng, RngCore};
    use hpke::{single_shot_seal, OpModeS};

    let public_key_bytes = unb64(public_key_b64, "public_key")?;
    let public_key = HpkePublicKey::from_bytes(&public_key_bytes)
        .map_err(|_| anyhow::anyhow!("public_key has invalid length"))?;
    struct FixedRng([u8; 32], u64);
    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut out = [0u8; 4];
            self.fill_bytes(&mut out);
            u32::from_le_bytes(out)
        }

        fn next_u64(&mut self) -> u64 {
            let mut out = [0u8; 8];
            self.fill_bytes(&mut out);
            u64::from_le_bytes(out)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut written = 0usize;
            while written < dest.len() {
                let mut block_input = [0u8; 40];
                block_input[..32].copy_from_slice(&self.0);
                block_input[32..].copy_from_slice(&self.1.to_le_bytes());
                let block = Sha256::digest(block_input);
                let to_copy = (dest.len() - written).min(block.len());
                dest[written..written + to_copy].copy_from_slice(&block[..to_copy]);
                written += to_copy;
                self.1 = self.1.wrapping_add(1);
            }
        }
    }
    impl CryptoRng for FixedRng {}

    let mut rng = FixedRng(rng_seed, 0);
    let (encapped_key, ct) = single_shot_seal::<AesGcm256, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &public_key,
        BLIND_BOX_HPKE_INFO,
        plaintext,
        &context.aad_bytes(),
        &mut rng,
    )
    .map_err(|_| anyhow::anyhow!("blind-box seal failed"))?;
    Ok(BlindBox {
        scheme: BLIND_BOX_SCHEME.to_string(),
        enc: b64(&encapped_key.to_bytes()),
        ct: b64(&ct),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_KEY: [u8; KEY_BYTES] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn derived_keypair_opens_blind_box() {
        let keypair = derive_blind_box_keypair_from_master(&MASTER_KEY);
        let context = BlindBoxContext::seal("BLIND_SECRET");
        let blind_box = seal_blind_box_for_tests(
            &keypair.public_key_b64(),
            b"blind secret",
            [0x42u8; KEY_BYTES],
            &context,
        )
        .unwrap();
        let opened = keypair.open(&blind_box, &context).unwrap();
        assert_eq!(opened.as_slice(), b"blind secret");
    }

    #[test]
    fn opens_known_answer_blind_box_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json"))
                .unwrap();
        let blind = &vector["blind_box"];
        assert_eq!(blind["scheme"], BLIND_BOX_SCHEME);
        assert_eq!(
            blind["hpke_info_utf8"],
            std::str::from_utf8(BLIND_BOX_HPKE_INFO).unwrap()
        );
        assert_eq!(blind["aad_domain_utf8"], "avault:blind-box:aad:v1");
        let master_key = hex::decode(blind["master_key_hex"].as_str().unwrap()).unwrap();
        let master_key: [u8; KEY_BYTES] = master_key.try_into().unwrap();
        let keypair = derive_blind_box_keypair_from_master(&master_key);
        assert_eq!(keypair.public_key_b64(), blind["public_key"]);
        assert_eq!(keypair.fingerprint_hex(), blind["fingerprint"]);
        let blind_box: BlindBox = serde_json::from_value(blind["box"].clone()).unwrap();
        let context = BlindBoxContext::seal(blind["context"]["name"].as_str().unwrap());
        assert_eq!(hex::encode(context.aad_bytes()), blind["aad_hex"]);
        let opened = keypair.open(&blind_box, &context).unwrap();
        assert_eq!(
            hex::encode(opened.as_slice()),
            blind["plaintext_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn blind_box_aad_examples_match_vector_file() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json"))
                .unwrap();
        let cases = vector["blind_box_aad_examples"]["cases"]
            .as_array()
            .unwrap();
        for case in cases {
            let purpose = case["purpose"].as_str().unwrap();
            let name = case["name"].as_str().unwrap();
            let scope_type = case["scope_type"].as_str().unwrap();
            let scope_ref = case["scope_ref"].as_str().unwrap();
            let sign_scheme = case["sign_scheme"].as_str().unwrap();
            let digest_hex = case["digest_hex"].as_str().unwrap();
            let mut context = match purpose {
                "seal" => BlindBoxContext::seal(name),
                "deliver" => BlindBoxContext::deliver(name),
                "sign" => {
                    let digest: [u8; KEY_BYTES] =
                        hex::decode(digest_hex).unwrap().try_into().unwrap();
                    BlindBoxContext::sign(name, sign_scheme, &digest)
                }
                "agent-deliver" => BlindBoxContext::agent_deliver(scope_type, scope_ref, name),
                "agent-sign" => {
                    let digest: [u8; KEY_BYTES] =
                        hex::decode(digest_hex).unwrap().try_into().unwrap();
                    BlindBoxContext::agent_sign(scope_type, scope_ref, name, sign_scheme, &digest)
                }
                _ => panic!("unexpected blind-box AAD vector purpose"),
            };
            if let Some(nonce_hex) = case["approval_nonce_hex"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                let nonce = hex::decode(nonce_hex).unwrap();
                let expires_at = case["approval_expires_at_unix"].as_u64().unwrap();
                context = context.with_approval(&nonce, expires_at);
            }
            if let Some(operation_hash_hex) = case["operation_hash_hex"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                let operation_hash: [u8; KEY_BYTES] =
                    hex::decode(operation_hash_hex).unwrap().try_into().unwrap();
                if let Some(fields) = case["operation_hash_fields_hex"].as_array() {
                    let decoded_fields: Vec<Vec<u8>> = fields
                        .iter()
                        .map(|field| hex::decode(field.as_str().unwrap()).unwrap())
                        .collect();
                    let field_refs: Vec<&[u8]> = decoded_fields.iter().map(Vec::as_slice).collect();
                    assert_eq!(operation_hash, BlindBoxContext::operation_hash(&field_refs));
                }
                if let Some(ttl_secs) = case["ttl_secs"].as_u64() {
                    let ttl_secs = ttl_secs.to_be_bytes();
                    let expected = match purpose {
                        "agent-deliver" => BlindBoxContext::operation_hash(&[
                            b"agent-deliver",
                            name.as_bytes(),
                            ttl_secs.as_slice(),
                        ]),
                        "agent-sign" => BlindBoxContext::operation_hash(&[
                            b"agent-sign",
                            sign_scheme.as_bytes(),
                            context.digest.as_ref().unwrap().as_slice(),
                            ttl_secs.as_slice(),
                        ]),
                        _ => panic!("ttl_secs is only valid for agent grant vectors"),
                    };
                    assert_eq!(operation_hash, expected);
                }
                context = context.with_operation_hash(operation_hash);
            }
            assert_eq!(hex::encode(context.aad_bytes()), case["aad_hex"]);
        }
    }

    #[test]
    fn rejects_wrong_blind_box_context() {
        let keypair = derive_blind_box_keypair_from_master(&MASTER_KEY);
        let context = BlindBoxContext::sign(
            "SIGNING_KEY",
            "ecdsa-secp256k1-recoverable",
            &[0x11u8; KEY_BYTES],
        );
        let blind_box = seal_blind_box_for_tests(
            &keypair.public_key_b64(),
            b"blind secret",
            [0x42u8; KEY_BYTES],
            &context,
        )
        .unwrap();
        let wrong_digest = BlindBoxContext::sign(
            "SIGNING_KEY",
            "ecdsa-secp256k1-recoverable",
            &[0x22u8; KEY_BYTES],
        );
        assert!(keypair.open(&blind_box, &wrong_digest).is_err());
        assert!(keypair
            .open(&blind_box, &BlindBoxContext::deliver("SIGNING_KEY"))
            .is_err());
    }

    #[test]
    fn rejects_wrong_blind_box_scheme() {
        let keypair = derive_blind_box_keypair_from_master(&MASTER_KEY);
        let context = BlindBoxContext::seal("BLIND_SECRET");
        let mut blind_box = seal_blind_box_for_tests(
            &keypair.public_key_b64(),
            b"blind secret",
            [0x42u8; KEY_BYTES],
            &context,
        )
        .unwrap();
        blind_box.scheme = "wrong".to_string();
        assert!(keypair.open(&blind_box, &context).is_err());
    }
}
