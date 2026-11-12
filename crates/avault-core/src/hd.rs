//! Fixed-path HD derivation. Only the browser supplies a BIP39 seed: no mnemonic
//! parser, xprv/xpub API, arbitrary-path API, or secret serialization crosses the CLI.

use crate::{ed25519_public_key, SignatureScheme, KEY_BYTES};
use anyhow::{anyhow, bail};
use hmac::{Hmac, Mac};
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, Scalar, SecretKey};
use std::str::FromStr;
use zeroize::Zeroizing;

/// Fixed number of accounts prepared by import, with shared indices `0..20`.
pub const HD_ACCOUNT_COUNT: u32 = 20;
/// Length of a BIP39 seed (not a mnemonic's entropy or an Ed25519 private seed).
pub const BIP39_SEED_BYTES: usize = 64;
const HARDENED: u32 = 1 << 31;

/// The three supported chains. Each selects one fixed path and signing scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdChain {
    /// `m/44'/60'/0'/0/i`, recoverable ECDSA.
    Evm,
    /// `m/86'/0'/0'/0/i`, BIP341 key-path signing with an empty script tree.
    Bitcoin,
    /// `m/44'/501'/i'/0'`, SLIP-0010 Ed25519 exact-message signing.
    Solana,
}

impl HdChain {
    /// The only signature scheme allowed for this chain's derived key.
    pub const fn signing_scheme(self) -> SignatureScheme {
        match self {
            Self::Evm => SignatureScheme::EcdsaSecp256k1Recoverable,
            Self::Bitcoin => SignatureScheme::SchnorrSecp256k1Bip341Keypath,
            Self::Solana => SignatureScheme::Ed25519,
        }
    }
}

impl FromStr for HdChain {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "evm" => Ok(Self::Evm),
            "bitcoin" => Ok(Self::Bitcoin),
            "solana" => Ok(Self::Solana),
            _ => bail!("unsupported derivation chain"),
        }
    }
}

/// Public-only metadata for one account; never includes chain codes or extended keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdAccountPublicKeys {
    /// Shared account index.
    pub account: u32,
    /// Compressed SEC1 secp256k1 public key, 33 bytes.
    pub evm: [u8; 33],
    /// Compressed SEC1 BIP86 *internal* key, before the existing TapTweak, 33 bytes.
    pub bitcoin: [u8; 33],
    /// Raw Ed25519 public key, 32 bytes (no SLIP-0010 serialization prefix).
    pub solana: [u8; 32],
}

/// Validate the public account selector before loading or opening any key.
pub fn validate_account(account: u32) -> anyhow::Result<()> {
    if account >= HD_ACCOUNT_COUNT {
        bail!("account must be between 0 and 19");
    }
    Ok(())
}

/// Derive one private key for immediate use by the existing signing provider.
/// The caller keeps the seed and returned key in zeroizing storage.
pub fn derive_hd_private_key(
    seed: &[u8; BIP39_SEED_BYTES],
    chain: HdChain,
    account: u32,
) -> anyhow::Result<Zeroizing<[u8; KEY_BYTES]>> {
    validate_account(account)?;
    let node = match chain {
        HdChain::Evm => bip32_node(seed, &[44 | HARDENED, 60 | HARDENED, HARDENED, 0, account])?,
        HdChain::Bitcoin => bip32_node(seed, &[86 | HARDENED, HARDENED, HARDENED, 0, account])?,
        HdChain::Solana => slip10_node(
            seed,
            &[44 | HARDENED, 501 | HARDENED, account | HARDENED, HARDENED],
        )?,
    };
    Ok(node.key)
}

/// Derive public keys for one supported account. Private intermediates are wiped on drop.
pub fn derive_hd_account(
    seed: &[u8; BIP39_SEED_BYTES],
    account: u32,
) -> anyhow::Result<HdAccountPublicKeys> {
    let evm = compressed_public_key(&*derive_hd_private_key(seed, HdChain::Evm, account)?)?;
    let bitcoin = compressed_public_key(&*derive_hd_private_key(seed, HdChain::Bitcoin, account)?)?;
    let solana = ed25519_public_key(&*derive_hd_private_key(seed, HdChain::Solana, account)?);
    Ok(HdAccountPublicKeys {
        account,
        evm,
        bitcoin,
        solana,
    })
}

/// Prepare all 20 accounts for import, returning public keys only, or fail atomically.
pub fn derive_hd_accounts(
    seed: &[u8; BIP39_SEED_BYTES],
) -> anyhow::Result<Vec<HdAccountPublicKeys>> {
    (0..HD_ACCOUNT_COUNT)
        .map(|account| derive_hd_account(seed, account))
        .collect()
}

// Neither Debug nor Serialize: these contain private keys and chain codes.
struct HdNode {
    key: Zeroizing<[u8; KEY_BYTES]>,
    chain_code: Zeroizing<[u8; KEY_BYTES]>,
}

impl HdNode {
    fn from_hmac(key: &[u8], data: &[u8]) -> Self {
        let mut mac =
            Hmac::<sha2::Sha512>::new_from_slice(key).expect("HMAC accepts every key length");
        mac.update(data);
        let output = Zeroizing::new(mac.finalize().into_bytes());
        let mut node = Self {
            key: Zeroizing::new([0; KEY_BYTES]),
            chain_code: Zeroizing::new([0; KEY_BYTES]),
        };
        node.key.copy_from_slice(&output[..KEY_BYTES]);
        node.chain_code.copy_from_slice(&output[KEY_BYTES..]);
        node
    }

    fn bip32_child(&self, index: u32) -> anyhow::Result<Self> {
        let mut data = Zeroizing::new([0u8; 37]);
        if index >= HARDENED {
            data[1..33].copy_from_slice(self.key.as_ref());
        } else {
            data[..33].copy_from_slice(&compressed_public_key(&self.key)?);
        }
        data[33..].copy_from_slice(&index.to_be_bytes());
        let mut child = Self::from_hmac(self.chain_code.as_ref(), data.as_ref());
        // BIP32 permits a zero I_L tweak, but not I_L >= n or a zero child key.
        // An invalid child is undefined at this exact path: fail rather than silently
        // advance an account/coin/purpose index and label a different path as requested.
        add_bip32_tweak(&self.key, &mut child.key)?;
        Ok(child)
    }

    fn slip10_child(&self, index: u32) -> anyhow::Result<Self> {
        if index < HARDENED {
            bail!("SLIP-0010 Ed25519 requires hardened indices");
        }
        let mut data = Zeroizing::new([0u8; 37]);
        data[1..33].copy_from_slice(self.key.as_ref());
        data[33..].copy_from_slice(&index.to_be_bytes());
        Ok(Self::from_hmac(self.chain_code.as_ref(), data.as_ref()))
    }
}

fn bip32_node(seed: &[u8], path: &[u32]) -> anyhow::Result<HdNode> {
    let mut node = HdNode::from_hmac(b"Bitcoin seed", seed);
    if bool::from(scalar(&node.key)?.is_zero()) {
        bail!("invalid BIP32 master key");
    }
    for index in path {
        node = node.bip32_child(*index)?;
    }
    Ok(node)
}

fn slip10_node(seed: &[u8], path: &[u32]) -> anyhow::Result<HdNode> {
    let mut node = HdNode::from_hmac(b"ed25519 seed", seed);
    for index in path {
        node = node.slip10_child(*index)?;
    }
    Ok(node)
}

fn add_bip32_tweak(parent: &[u8; KEY_BYTES], child: &mut [u8; KEY_BYTES]) -> anyhow::Result<()> {
    let tweak = scalar(child)?;
    let parent = scalar(parent)?;
    let sum = Zeroizing::new(*tweak + *parent);
    if bool::from(sum.is_zero()) {
        bail!("invalid BIP32 child key at the requested path");
    }
    let encoded = Zeroizing::new(sum.to_bytes());
    child.copy_from_slice(encoded.as_ref());
    Ok(())
}

fn scalar(bytes: &[u8; KEY_BYTES]) -> anyhow::Result<Zeroizing<Scalar>> {
    let mut encoded = Zeroizing::new(FieldBytes::default());
    encoded.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(*encoded))
        .map(Zeroizing::new)
        .ok_or_else(|| anyhow!("invalid BIP32 scalar"))
}

fn compressed_public_key(key: &[u8; KEY_BYTES]) -> anyhow::Result<[u8; 33]> {
    let secret = SecretKey::from_slice(key).map_err(|_| anyhow!("invalid BIP32 key"))?;
    Ok(secret
        .public_key()
        .to_sec1_bytes()
        .as_ref()
        .try_into()
        .expect("compressed secp256k1 public keys are 33 bytes"))
}

#[cfg(test)]
mod tests;
