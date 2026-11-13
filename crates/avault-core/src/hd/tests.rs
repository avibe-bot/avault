use super::*;
use crate::{LocalSignerProvider, SignerProvider};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../../tests/vectors/hd_wallets.json")).unwrap()
}

fn path(text: &str) -> Vec<u32> {
    assert!(text.starts_with('m'));
    text.split('/')
        .skip(1)
        .map(|part| match part.strip_suffix('\'') {
            Some(hardened) => hardened.parse::<u32>().unwrap() | HARDENED,
            None => part.parse().unwrap(),
        })
        .collect()
}

// Only a fixture decoder, not a production extended-key import/export API.
fn extended(text: &str) -> Vec<u8> {
    let bytes = bs58::decode(text).into_vec().unwrap();
    assert_eq!(bytes.len(), 82);
    assert_eq!(
        &Sha256::digest(Sha256::digest(&bytes[..78]))[..4],
        &bytes[78..]
    );
    bytes
}

fn assert_bip32_node(node: &HdNode, expected: &Value) {
    let private = extended(expected["xprv"].as_str().unwrap());
    let public = extended(expected["xpub"].as_str().unwrap());
    assert_eq!(&private[..4], &[4, 136, 173, 228]);
    assert_eq!(&public[..4], &[4, 136, 178, 30]);
    assert_eq!(private[45], 0);
    assert_eq!(
        node.key.as_slice(),
        &private[46..78],
        "{}",
        expected["path"]
    );
    assert_eq!(node.chain_code.as_slice(), &private[13..45]);
    assert_eq!(&private[13..45], &public[13..45]);
    assert_eq!(
        compressed_public_key(&node.key).unwrap().as_slice(),
        &public[45..78]
    );
}

#[test]
fn bip32_official_vectors_one_through_four_all_nodes() {
    let fixture = fixture();
    let mut count = 0;
    for vector in fixture["bip32"].as_array().unwrap() {
        let seed = hex::decode(vector["seed"].as_str().unwrap()).unwrap();
        for expected in vector["nodes"].as_array().unwrap() {
            let node = bip32_node(&seed, &path(expected["path"].as_str().unwrap())).unwrap();
            assert_bip32_node(&node, expected);
            count += 1;
        }
    }
    assert_eq!(count, 17); // Includes both published leading-zero regressions.
}

#[test]
fn slip10_ed25519_official_vectors_one_and_two_all_nodes() {
    let fixture = fixture();
    let mut count = 0;
    for vector in fixture["slip10"].as_array().unwrap() {
        let seed = hex::decode(vector["seed"].as_str().unwrap()).unwrap();
        for expected in vector["nodes"].as_array().unwrap() {
            let node = slip10_node(&seed, &path(expected["path"].as_str().unwrap())).unwrap();
            assert_eq!(hex::encode(node.key.as_slice()), expected["private"]);
            assert_eq!(
                hex::encode(node.chain_code.as_slice()),
                expected["chain_code"]
            );
            assert_eq!(
                format!("00{}", hex::encode(ed25519_public_key(&node.key))),
                expected["public"]
            );
            count += 1;
        }
    }
    assert_eq!(count, 12);
}

#[test]
fn bip86_root_account_and_leaves_sign_under_published_output_keys() {
    let fixture = fixture();
    let seed = hex::decode(fixture["bip86_seed"].as_str().unwrap()).unwrap();
    for expected in fixture["bip86"].as_array().unwrap() {
        let node = bip32_node(&seed, &path(expected["path"].as_str().unwrap())).unwrap();
        assert_bip32_node(&node, expected);
        if let Some(output) = expected["output_key"].as_str() {
            let public = compressed_public_key(&node.key).unwrap();
            assert_eq!(hex::encode(&public[1..]), expected["internal_key"]);
            let signature = LocalSignerProvider
                .sign_digest(
                    SignatureScheme::SchnorrSecp256k1Bip341Keypath,
                    &node.key,
                    &[0x42; 32],
                )
                .unwrap();
            let signature =
                k256::schnorr::Signature::try_from(signature.signature.as_slice()).unwrap();
            let key =
                k256::schnorr::VerifyingKey::from_bytes(&hex::decode(output).unwrap()).unwrap();
            key.verify_raw(&[0x42; 32], &signature).unwrap();
            // Raw BIP340 under the internal key is not a signature for the advertised address.
            let internal = k256::schnorr::VerifyingKey::from_bytes(&public[1..]).unwrap();
            assert!(internal.verify_raw(&[0x42; 32], &signature).is_err());
        }
    }
}

#[test]
fn fixed_paths_match_the_independent_wallet_check_and_account_bounds() {
    let fixture = fixture();
    let seed: [u8; 64] = hex::decode(fixture["bip86_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let accounts = derive_hd_accounts(&seed).unwrap();
    assert_eq!(accounts.len(), 20);
    for (index, account) in accounts.iter().enumerate() {
        assert_eq!(account.account, index as u32);
        assert_eq!(*account, derive_hd_account(&seed, index as u32).unwrap());
        assert!(accounts[..index]
            .iter()
            .all(|other| other.evm != account.evm
                && other.bitcoin != account.bitcoin
                && other.solana != account.solana));
    }
    for expected in fixture["wallet_accounts"].as_array().unwrap() {
        let account = &accounts[expected["account"].as_u64().unwrap() as usize];
        assert_eq!(hex::encode(account.evm), expected["evm"]);
        assert_eq!(hex::encode(account.bitcoin), expected["bitcoin"]);
        assert_eq!(hex::encode(account.solana), expected["solana"]);
        assert_eq!(
            crate::solana_address(&account.solana),
            expected["addresses"]["solana"]
        );
    }
    for chain in [HdChain::Evm, HdChain::Bitcoin, HdChain::Solana] {
        assert!(derive_hd_private_key(&seed, chain, 19).is_ok());
        for account in [20, HARDENED, u32::MAX] {
            assert!(derive_hd_private_key(&seed, chain, account).is_err());
        }
    }
    for unsupported in ["eth", "btc", "SOLANA", "", "evm/1"] {
        assert!(HdChain::from_str(unsupported).is_err());
    }
}

#[test]
fn bitcoin_address_types_select_fixed_purposes_and_preserve_default_keys() {
    let seed: [u8; 64] = hex::decode(fixture()["bip86_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for (token, address_type, purpose, scheme) in [
        (
            "p2pkh",
            BitcoinAddressType::P2pkh,
            44,
            SignatureScheme::EcdsaSecp256k1Der,
        ),
        (
            "p2wpkh",
            BitcoinAddressType::P2wpkh,
            84,
            SignatureScheme::EcdsaSecp256k1Der,
        ),
        (
            "p2tr",
            BitcoinAddressType::P2tr,
            86,
            SignatureScheme::SchnorrSecp256k1Bip341Keypath,
        ),
    ] {
        assert_eq!(BitcoinAddressType::from_str(token).unwrap(), address_type);
        assert_eq!(
            HdChain::Bitcoin
                .signing_scheme_for(Some(address_type))
                .unwrap(),
            scheme
        );
        for account in 0..HD_ACCOUNT_COUNT {
            let key = derive_hd_private_key_with_address_type(
                &seed,
                HdChain::Bitcoin,
                account,
                Some(address_type),
            )
            .unwrap();
            let fixed =
                bip32_node(&seed, &[purpose | HARDENED, HARDENED, HARDENED, 0, account]).unwrap();
            assert_eq!(*key, *fixed.key);
            assert_eq!(
                derive_hd_bitcoin_public_key(&seed, account, address_type).unwrap(),
                compressed_public_key(&key).unwrap()
            );
            if address_type == BitcoinAddressType::P2tr {
                assert_eq!(
                    *key,
                    *derive_hd_private_key(&seed, HdChain::Bitcoin, account).unwrap()
                );
                assert_eq!(
                    derive_hd_account(&seed, account).unwrap().bitcoin,
                    compressed_public_key(&key).unwrap()
                );
            }
        }
        for chain in [HdChain::Evm, HdChain::Solana] {
            assert!(chain.signing_scheme_for(Some(address_type)).is_err());
            assert!(
                derive_hd_private_key_with_address_type(&seed, chain, 0, Some(address_type))
                    .is_err()
            );
        }
        for account in [20, HARDENED, u32::MAX] {
            assert!(derive_hd_bitcoin_public_key(&seed, account, address_type).is_err());
        }
    }
    for token in ["", "P2PKH", "p2sh", "p2wsh", "legacy", "p2tr "] {
        assert!(BitcoinAddressType::from_str(token).is_err());
    }
    for chain in [HdChain::Evm, HdChain::Bitcoin, HdChain::Solana] {
        assert_eq!(
            chain.signing_scheme_for(None).unwrap(),
            chain.signing_scheme()
        );
    }
}

#[test]
fn bip84_published_receiving_keys_are_not_bip86_reencodings() {
    // BIP84's first two receiving keys, not its change path (unsupported by this API).
    let seed: [u8; 64] = hex::decode(fixture()["bip86_seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for (account, expected) in [
        (
            0,
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        ),
        (
            1,
            "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        ),
    ] {
        let public =
            derive_hd_bitcoin_public_key(&seed, account, BitcoinAddressType::P2wpkh).unwrap();
        assert_eq!(hex::encode(public), expected);
        assert_ne!(public, derive_hd_account(&seed, account).unwrap().bitcoin);
    }
}

#[test]
fn slip132_bip44_and_bip84_published_account_keys_anchor_fixed_paths() {
    let official: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/hd_bitcoin_official.json"
    ))
    .unwrap();
    let matrix: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/hd_bitcoin_address_types.json"
    ))
    .unwrap();
    let reference = matrix["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "bip39_abandon11_about_empty")
        .unwrap();
    let seed: [u8; 64] = hex::decode(reference["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for (row, address_type, field, address) in [
        (0, BitcoinAddressType::P2pkh, "bitcoin_p2pkh", "p2pkh"),
        (1, BitcoinAddressType::P2wpkh, "bitcoin_p2wpkh", "p2wpkh"),
    ] {
        let expected = &official["slip132"][row];
        let node = bip32_node(&seed, &path(expected["account_path"].as_str().unwrap())).unwrap();
        let xpub = extended(expected["account_xpub"].as_str().unwrap());
        assert_eq!(node.chain_code.as_slice(), &xpub[13..45]);
        assert_eq!(
            compressed_public_key(&node.key).unwrap().as_slice(),
            &xpub[45..78]
        );
        assert_eq!(
            hex::encode(derive_hd_bitcoin_public_key(&seed, 0, address_type).unwrap()),
            reference["accounts"][0][field]
        );
        assert_eq!(
            reference["accounts"][0]["addresses"][address],
            expected["address"]
        );
    }
}

#[test]
fn exceptional_bip32_tweaks_fail_closed_without_advancing_the_path() {
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut zero = [0u8; 32];
    add_bip32_tweak(&one, &mut zero).unwrap();
    assert_eq!(zero, one); // A zero tweak is legal; a zero child is not.
    let order: [u8; 32] =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap()
            .try_into()
            .unwrap();
    let mut negative_one = order;
    negative_one[31] -= 1;
    assert!(add_bip32_tweak(&one, &mut negative_one).is_err());
    let mut invalid = order;
    assert!(add_bip32_tweak(&one, &mut invalid).is_err());
    assert!(add_bip32_tweak(&one, &mut [255; 32]).is_err());
    let node = slip10_node(&[42; 64], &[]).unwrap();
    assert!(node.slip10_child(0).is_err());
    assert!(node.slip10_child(HARDENED - 1).is_err());
    assert!(node.slip10_child(HARDENED).is_ok());
}
