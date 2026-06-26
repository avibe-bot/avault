use crate::{b64, unb64, KEY_BYTES};
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
const CLI_DERIVED_RECEIVER_SALT: &[u8] = b"avault:blind-box:receiver-salt:v1";
const CLI_DERIVED_RECEIVER_INFO: &[u8] = b"avault:blind-box:receiver-x25519:v1";

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

    pub fn open(&self, blind_box: &BlindBox) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        open_blind_box_with_private_key(&self.private_key, blind_box)
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
        BLIND_BOX_SCHEME.as_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("blind-box open failed"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
pub(crate) fn seal_blind_box_for_tests(
    public_key_b64: &str,
    plaintext: &[u8],
    rng_seed: [u8; 32],
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
        BLIND_BOX_SCHEME.as_bytes(),
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
        let blind_box = seal_blind_box_for_tests(
            &keypair.public_key_b64(),
            b"blind secret",
            [0x42u8; KEY_BYTES],
        )
        .unwrap();
        let opened = keypair.open(&blind_box).unwrap();
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
        assert_eq!(blind["aad_utf8"], BLIND_BOX_SCHEME);
        let master_key = hex::decode(blind["master_key_hex"].as_str().unwrap()).unwrap();
        let master_key: [u8; KEY_BYTES] = master_key.try_into().unwrap();
        let keypair = derive_blind_box_keypair_from_master(&master_key);
        assert_eq!(keypair.public_key_b64(), blind["public_key"]);
        assert_eq!(keypair.fingerprint_hex(), blind["fingerprint"]);
        let blind_box: BlindBox = serde_json::from_value(blind["box"].clone()).unwrap();
        let opened = keypair.open(&blind_box).unwrap();
        assert_eq!(
            hex::encode(opened.as_slice()),
            blind["plaintext_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn rejects_wrong_blind_box_scheme() {
        let keypair = derive_blind_box_keypair_from_master(&MASTER_KEY);
        let mut blind_box = seal_blind_box_for_tests(
            &keypair.public_key_b64(),
            b"blind secret",
            [0x42u8; KEY_BYTES],
        )
        .unwrap();
        blind_box.scheme = "wrong".to_string();
        assert!(keypair.open(&blind_box).is_err());
    }
}
