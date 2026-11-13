//! Additive Bitcoin-HD contracts. Every seed is PUBLIC test material; never fund it.

use super::{assert_fields, hd_import, refused, success, Sandbox, NAME, SCHEME};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::Stdio;

const PROFILE: &str = "bitcoin-address-types-v1";
const TAPROOT: &str = "schnorr-secp256k1-bip341-keypath";
const PUBLIC_FIELDS: &[&str] = &[
    "account",
    "evm",
    "bitcoin",
    "solana",
    "bitcoin_p2pkh",
    "bitcoin_p2wpkh",
];

fn derive_request(envelope: &Value) -> Value {
    json!({"name": NAME, "key_envelope": envelope, "profile": PROFILE})
}

fn derive_public(sandbox: &Sandbox, envelope: &Value) -> Value {
    success(sandbox.run(
        &["keypair", "derive-public"],
        derive_request(envelope).to_string().as_bytes(),
    ))
}

fn import_extended(sandbox: &Sandbox, seed: &[u8]) -> Value {
    success(sandbox.run(
        &[
            "keypair",
            "import",
            "--name",
            NAME,
            "--type",
            "hd-seed",
            "--format",
            "raw-seed",
            "--profile",
            PROFILE,
        ],
        seed,
    ))
}

fn verify_der(digest: &[u8; 32], result: &Value, public: &str) -> Signature {
    assert_fields(result, &["signature", "recovery_id"]);
    assert_eq!(result["recovery_id"], Value::Null);
    let bytes = hex::decode(result["signature"].as_str().unwrap()).unwrap();
    let signature = Signature::from_der(&bytes).unwrap();
    // A canonical DER signature, low-S, without the transaction's sighash byte.
    assert_eq!(signature.to_der().as_bytes(), bytes);
    assert!(signature.normalize_s().is_none());
    VerifyingKey::from_sec1_bytes(&hex::decode(public).unwrap())
        .unwrap()
        .verify_prehash(digest, &signature)
        .unwrap();
    signature
}

#[test]
fn all_public_seed_cases_and_indices_sign_under_independently_derived_keys() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/hd_bitcoin_address_types.json"
    ))
    .unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 7);
    let mut count = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let sandbox = Sandbox::new();
        let imported = import_extended(
            &sandbox,
            &hex::decode(case["seed_hex"].as_str().unwrap()).unwrap(),
        );
        assert_fields(&imported, &["type", "profile", "envelope", "accounts"]);
        let derived = derive_public(&sandbox, &imported["envelope"]);
        assert_eq!(derived["accounts"], imported["accounts"]);
        assert_eq!(imported["accounts"].as_array().unwrap().len(), 20);
        for (i, expected) in case["accounts"].as_array().unwrap().iter().enumerate() {
            let account = &imported["accounts"][i];
            assert_fields(account, PUBLIC_FIELDS);
            assert_eq!(account["account"], i);
            for field in PUBLIC_FIELDS {
                assert_eq!(
                    account[*field], expected[*field],
                    "{} / {i} / {field}",
                    case["id"]
                );
            }
            let digest: [u8; 32] =
                Sha256::digest(format!("PUBLIC-HD-BTC-PARITY:{}:{i}", case["id"])).into();
            for (address_type, field, wrong_field) in [
                ("p2pkh", "bitcoin_p2pkh", "bitcoin_p2wpkh"),
                ("p2wpkh", "bitcoin_p2wpkh", "bitcoin_p2pkh"),
            ] {
                let mut request = json!({"name":NAME,"key_envelope":imported["envelope"],
                    "derivation":{"chain":"bitcoin","account":i,"address_type":address_type},
                    "digest":hex::encode(digest)});
                let signed = success(sandbox.run(&["sign"], request.to_string().as_bytes()));
                let signature = verify_der(&digest, &signed, expected[field].as_str().unwrap());
                for wrong in [
                    &expected[wrong_field],
                    &expected["bitcoin"],
                    &case["accounts"][(i + 1) % 20][field],
                ] {
                    assert!(VerifyingKey::from_sec1_bytes(
                        &hex::decode(wrong.as_str().unwrap()).unwrap()
                    )
                    .unwrap()
                    .verify_prehash(&digest, &signature)
                    .is_err());
                }
                if matches!(i, 0 | 1 | 19) {
                    request["scheme"] = json!(SCHEME);
                    assert_eq!(
                        signed,
                        success(sandbox.run(&["sign"], request.to_string().as_bytes()))
                    );
                    if i == 0 {
                        request["derivation"]
                            .as_object_mut()
                            .unwrap()
                            .remove("account");
                        assert_eq!(
                            signed,
                            success(sandbox.run(&["sign"], request.to_string().as_bytes()))
                        );
                    }
                }
            }
            // Omitted and explicit Taproot select the same tweaked output key.
            // Random auxiliary nonce means Schnorr signature bytes need not be equal.
            for explicit in [false, true] {
                let mut request = json!({"name":NAME,"key_envelope":imported["envelope"],
                    "derivation":{"chain":"bitcoin","account":i},"digest":hex::encode(digest)});
                if explicit {
                    request["derivation"]["address_type"] = json!("p2tr");
                    request["scheme"] = json!(TAPROOT);
                }
                let signed = success(sandbox.run(&["sign"], request.to_string().as_bytes()));
                assert_fields(&signed, &["signature", "recovery_id"]);
                assert_eq!(signed["recovery_id"], Value::Null);
                let signature = k256::schnorr::Signature::try_from(
                    hex::decode(signed["signature"].as_str().unwrap())
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                let key = k256::schnorr::VerifyingKey::from_bytes(
                    &hex::decode(expected["bitcoin_output_key"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                key.verify_raw(&digest, &signature).unwrap();
                let internal = hex::decode(expected["bitcoin"].as_str().unwrap()).unwrap();
                assert!(k256::schnorr::VerifyingKey::from_bytes(&internal[1..])
                    .unwrap()
                    .verify_raw(&digest, &signature)
                    .is_err());
                let wrong = &case["accounts"][(i + 1) % 20]["bitcoin_output_key"];
                assert!(k256::schnorr::VerifyingKey::from_bytes(
                    &hex::decode(wrong.as_str().unwrap()).unwrap()
                )
                .unwrap()
                .verify_raw(&digest, &signature)
                .is_err());
            }
            count += 1;
        }
    }
    assert_eq!(count, 140);
}

#[test]
fn public_derivation_preserves_old_wire_and_never_reseals_or_writes() {
    let sandbox = Sandbox::new();
    let imported = hd_import(&sandbox);
    assert_fields(&imported, &["type", "envelope", "accounts"]);
    let key_path = sandbox.0.path().join("vault/machine.key");
    let before = std::fs::read(&key_path).unwrap();
    let modified = std::fs::metadata(&key_path).unwrap().modified().unwrap();
    let envelope_bytes = serde_json::to_vec(&imported["envelope"]).unwrap();
    let public = derive_public(&sandbox, &imported["envelope"]);
    assert_fields(&public, &["type", "profile", "accounts"]);
    assert_eq!(public["type"], "hd-seed");
    assert_eq!(public["profile"], PROFILE);
    assert_eq!(public["accounts"].as_array().unwrap().len(), 20);
    for (i, account) in public["accounts"].as_array().unwrap().iter().enumerate() {
        assert_fields(account, PUBLIC_FIELDS);
        assert_fields(
            &imported["accounts"][i],
            &["account", "evm", "bitcoin", "solana"],
        );
        for field in ["account", "evm", "bitcoin", "solana"] {
            assert_eq!(account[field], imported["accounts"][i][field]);
        }
        for field in ["bitcoin_p2pkh", "bitcoin_p2wpkh"] {
            let text = account[field].as_str().unwrap();
            assert_eq!(text.len(), 66);
            assert_eq!(text, text.to_ascii_lowercase());
            assert!(matches!(hex::decode(text).unwrap()[0], 2 | 3));
            assert_ne!(account[field], account["bitcoin"]);
        }
        assert_ne!(account["bitcoin_p2pkh"], account["bitcoin_p2wpkh"]);
    }
    // Each call starts a fresh process. Repeat and overlap just two reads, not a load test.
    assert_eq!(public, derive_public(&sandbox, &imported["envelope"]));
    let request = derive_request(&imported["envelope"]).to_string();
    let children: Vec<_> = (0..2)
        .map(|_| {
            let mut child = sandbox
                .command()
                .args(["keypair", "derive-public"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(request.as_bytes())
                .unwrap();
            child
        })
        .collect();
    for child in children {
        assert_eq!(public, success(child.wait_with_output().unwrap()));
    }
    assert_eq!(before, std::fs::read(&key_path).unwrap());
    assert_eq!(
        modified,
        std::fs::metadata(&key_path).unwrap().modified().unwrap()
    );
    assert_eq!(
        std::fs::read_dir(key_path.parent().unwrap())
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        envelope_bytes,
        serde_json::to_vec(&imported["envelope"]).unwrap()
    );
    let extended = import_extended(&sandbox, &[42; 64]);
    assert_fields(&extended, &["type", "profile", "envelope", "accounts"]);
    assert_eq!(extended["accounts"], public["accounts"]);
    assert_eq!(extended["profile"], PROFILE);
    assert_ne!(extended["envelope"], imported["envelope"]); // Only import reseals.
}

#[test]
fn public_derivation_uses_existing_passphrase_store_without_rewriting_it() {
    let sandbox = Sandbox::new();
    // Test-only passphrase and seed; the last explicit store option wins.
    let prefix = b"PUBLIC-TEST-STORE-PASSPHRASE\n";
    let mut input = prefix.to_vec();
    input.extend_from_slice(&[42; 64]);
    let imported = success(sandbox.run(
        &[
            "--store",
            "file-passphrase",
            "keypair",
            "import",
            "--name",
            NAME,
            "--type",
            "hd-seed",
            "--format",
            "raw-seed",
        ],
        &input,
    ));
    let request = derive_request(&imported["envelope"]).to_string();
    let mut input = prefix.to_vec();
    input.extend_from_slice(request.as_bytes());
    let path = sandbox.0.path().join("vault/machine.passphrase.json");
    let before = std::fs::read(&path).unwrap();
    let derived = success(sandbox.run(
        &["--store", "file-passphrase", "keypair", "derive-public"],
        &input,
    ));
    assert_fields(&derived, &["type", "profile", "accounts"]);
    for i in 0..20 {
        for field in ["account", "evm", "bitcoin", "solana"] {
            assert_eq!(
                derived["accounts"][i][field],
                imported["accounts"][i][field]
            );
        }
    }
    let wrong = format!("WRONG-TEST-PASSPHRASE\n{request}");
    refused(
        sandbox.run(
            &["--store", "file-passphrase", "keypair", "derive-public"],
            wrong.as_bytes(),
        ),
        "failed to unlock",
    );
    assert_eq!(before, std::fs::read(path).unwrap());
    assert!(!sandbox.0.path().join("vault/machine.key").exists());
}

#[test]
fn public_profile_and_request_errors_fail_before_store_access() {
    let sandbox = Sandbox::new();
    let envelope = json!({"ciphertext":"invalid", "nonce":"invalid", "wrap_meta":json!({
        "v":1, "scheme":avault_core::HD_SEED_WRAP_SCHEME,
        "wrapped_dek":"invalid", "dek_nonce":"invalid"
    }).to_string()});
    let request = derive_request(&envelope);
    for profile in [
        json!(""),
        json!("bitcoin-address-types-v2"),
        json!("p2pkh"),
        json!("BITCOIN-ADDRESS-TYPES-V1"),
    ] {
        let mut bad = request.clone();
        bad["profile"] = profile;
        refused(
            sandbox.run(&["keypair", "derive-public"], bad.to_string().as_bytes()),
            "unsupported HD public profile",
        );
    }
    for profile in [Value::Null, json!(1), json!({}), json!([])] {
        let mut bad = request.clone();
        bad["profile"] = profile;
        refused(
            sandbox.run(&["keypair", "derive-public"], bad.to_string().as_bytes()),
            "derive-public JSON is invalid",
        );
    }
    for field in ["name", "key_envelope", "profile"] {
        let mut bad = request.clone();
        bad.as_object_mut().unwrap().remove(field);
        refused(
            sandbox.run(&["keypair", "derive-public"], bad.to_string().as_bytes()),
            "derive-public JSON is invalid",
        );
    }
    for field in [
        "seed",
        "mnemonic",
        "path",
        "account",
        "address_type",
        "approval",
        "dek_blindbox",
    ] {
        let mut bad = request.clone();
        bad[field] = json!("must-not-echo-this-payload");
        let result = sandbox.run(&["keypair", "derive-public"], bad.to_string().as_bytes());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("must-not-echo"));
        refused(result, "derive-public JSON is invalid");
    }
    let duplicate = format!("{{\"profile\":\"{PROFILE}\",{}", &request.to_string()[1..]);
    refused(
        sandbox.run(&["keypair", "derive-public"], duplicate.as_bytes()),
        "derive-public JSON is invalid",
    );
    refused(
        sandbox.run(&["keypair", "derive-public", "--profile", PROFILE], b""),
        "takes no options",
    );
    let mut oversized = request.to_string().into_bytes();
    oversized.resize(64 * 1024 + 1, b' ');
    refused(
        sandbox.run(&["keypair", "derive-public"], &oversized),
        "size limit",
    );
    // A valid request without a master fails instead of creating a replacement.
    refused(
        sandbox.run(
            &["keypair", "derive-public"],
            request.to_string().as_bytes(),
        ),
        "master key",
    );
    for extra in [
        vec!["--profile"],
        vec!["--profile", "wrong"],
        vec!["--profile", PROFILE, "--profile", PROFILE],
    ] {
        let mut args = vec![
            "keypair", "import", "--name", NAME, "--type", "hd-seed", "--format", "raw-seed",
        ];
        args.extend(extra);
        refused(sandbox.run(&args, &[42; 64]), "profile");
    }
    refused(
        sandbox.run(
            &[
                "keypair",
                "generate",
                "--name",
                NAME,
                "--curve",
                "secp256k1",
                "--profile",
                PROFILE,
            ],
            b"",
        ),
        "does not accept --profile",
    );
    refused(
        sandbox.run(
            &[
                "keypair",
                "import",
                "--name",
                NAME,
                "--curve",
                "ed25519",
                "--format",
                "base58-secret",
                "--profile",
                PROFILE,
            ],
            b"",
        ),
        "only valid for HD seed import",
    );
    assert!(!sandbox.0.path().join("vault").exists());
}

#[test]
fn public_derivation_rejects_legacy_protected_corrupt_and_substituted_envelopes() {
    let sandbox = Sandbox::new();
    let imported = hd_import(&sandbox);
    let legacy = sandbox.generate("secp256k1");
    refused(
        sandbox.run(
            &["keypair", "derive-public"],
            derive_request(&legacy["envelope"]).to_string().as_bytes(),
        ),
        "requires an HD seed envelope",
    );
    let mut retagged = legacy["envelope"].clone();
    let mut meta: Value = serde_json::from_str(retagged["wrap_meta"].as_str().unwrap()).unwrap();
    meta["scheme"] = json!(avault_core::HD_SEED_WRAP_SCHEME);
    retagged["wrap_meta"] = json!(meta.to_string());
    refused(
        sandbox.run(
            &["keypair", "derive-public"],
            derive_request(&retagged).to_string().as_bytes(),
        ),
        "open failed",
    );
    let mut wrong_name = derive_request(&imported["envelope"]);
    wrong_name["name"] = json!("OTHER_RECORD");
    refused(
        sandbox.run(
            &["keypair", "derive-public"],
            wrong_name.to_string().as_bytes(),
        ),
        "open failed",
    );
    for field in ["ciphertext", "nonce", "wrapped_dek", "dek_nonce"] {
        let mut bad = imported["envelope"].clone();
        let mut meta: Value = serde_json::from_str(bad["wrap_meta"].as_str().unwrap()).unwrap();
        let target = if matches!(field, "ciphertext" | "nonce") {
            &mut bad[field]
        } else {
            &mut meta[field]
        };
        let mut bytes = B64.decode(target.as_str().unwrap()).unwrap();
        bytes[0] ^= 1;
        *target = json!(B64.encode(bytes));
        bad["wrap_meta"] = json!(meta.to_string());
        let result = sandbox.run(
            &["keypair", "derive-public"],
            derive_request(&bad).to_string().as_bytes(),
        );
        assert!(!String::from_utf8_lossy(&result.stderr)
            .contains(imported["envelope"]["ciphertext"].as_str().unwrap()));
        refused(result, "open failed");
    }
    let mut bad = imported["envelope"].clone();
    let mut meta: Value = serde_json::from_str(bad["wrap_meta"].as_str().unwrap()).unwrap();
    meta["record_meta"] = json!({});
    bad["wrap_meta"] = json!(meta.to_string());
    let output = sandbox.run(
        &["keypair", "derive-public"],
        derive_request(&bad).to_string().as_bytes(),
    );
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    // A valid envelope from another machine cannot be opened under this master.
    let other = Sandbox::new();
    let other_wallet = hd_import(&other);
    refused(
        sandbox.run(
            &["keypair", "derive-public"],
            derive_request(&other_wallet["envelope"])
                .to_string()
                .as_bytes(),
        ),
        "open failed",
    );
}

#[test]
fn bitcoin_type_and_scheme_mismatches_are_rejected_before_key_use() {
    let sandbox = Sandbox::new();
    let envelope = json!({"ciphertext":"invalid", "nonce":"invalid", "wrap_meta":json!({
        "v":1, "scheme":avault_core::HD_SEED_WRAP_SCHEME,
        "wrapped_dek":"invalid", "dek_nonce":"invalid"
    }).to_string()});
    let base = json!({"name":NAME,"key_envelope":envelope,"derivation":{"chain":"bitcoin","address_type":"p2wpkh"},"digest":"00".repeat(32)});
    for address_type in [
        json!(""),
        json!("segwit"),
        json!("P2WPKH"),
        json!("p2sh"),
        json!("p2wsh"),
        json!("p2tr "),
        Value::Null,
        json!(0),
        json!(false),
        json!({}),
    ] {
        let mut bad = base.clone();
        bad["derivation"]["address_type"] = address_type.clone();
        refused(
            sandbox.run(&["sign"], bad.to_string().as_bytes()),
            if address_type.is_string() {
                "unsupported Bitcoin address type"
            } else {
                "sign JSON is invalid"
            },
        );
    }
    for chain in ["evm", "solana"] {
        for address_type in ["p2pkh", "p2wpkh", "p2tr"] {
            let mut bad = base.clone();
            bad["derivation"] = json!({"chain":chain,"address_type":address_type});
            refused(
                sandbox.run(&["sign"], bad.to_string().as_bytes()),
                "only valid for bitcoin",
            );
        }
    }
    for address_type in ["p2pkh", "p2wpkh", "p2tr"] {
        for scheme in [
            SCHEME,
            TAPROOT,
            "ecdsa-secp256k1-recoverable",
            "schnorr-secp256k1-bip340",
            "ed25519",
        ] {
            if scheme
                == if address_type == "p2tr" {
                    TAPROOT
                } else {
                    SCHEME
                }
            {
                continue;
            }
            let mut bad = base.clone();
            bad["derivation"]["address_type"] = json!(address_type);
            bad["scheme"] = json!(scheme);
            refused(
                sandbox.run(&["sign"], bad.to_string().as_bytes()),
                "does not match",
            );
        }
        for account in [
            json!(20),
            json!(4294967295u32),
            json!(-1),
            json!(0.5),
            json!("0"),
            Value::Null,
        ] {
            let mut bad = base.clone();
            bad["derivation"]["address_type"] = json!(address_type);
            bad["derivation"]["account"] = account;
            let result = sandbox.run(&["sign"], bad.to_string().as_bytes());
            assert_eq!(result.status.code(), Some(70));
            assert!(result.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&result.stderr).contains("master key"));
        }
    }
    let mut misplaced = base.clone();
    misplaced["address_type"] = json!("p2wpkh");
    refused(
        sandbox.run(&["sign"], misplaced.to_string().as_bytes()),
        "sign JSON is invalid",
    );
    assert!(!sandbox.0.path().join("vault").exists());
    // Ordinary keys may still use DER, but never accept a derivation selector.
    let ordinary = sandbox.generate("secp256k1");
    let mut bad = base;
    bad["key_envelope"] = ordinary["envelope"].clone();
    refused(
        sandbox.run(&["sign"], bad.to_string().as_bytes()),
        "legacy keypairs do not accept derivation",
    );
}

#[test]
fn bip143_published_native_witness_digest_and_der_signature() {
    // Primary BIP143 Native P2WPKH example, PUBLIC DATA.
    // https://raw.githubusercontent.com/bitcoin/bips/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0143.mediawiki
    // Source SHA256: 62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec
    // The transaction builder remains caller-owned. This pins its digest/DER
    // interface, not a new builder.
    let preimage = hex::decode(concat!(
        "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37",
        "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b",
        "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000",
        "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff",
        "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"
    ))
    .unwrap();
    let digest: [u8; 32] = Sha256::digest(Sha256::digest(preimage)).into();
    assert_eq!(
        hex::encode(digest),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    let public = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
    let expected = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee";
    let sandbox = Sandbox::new();
    let envelope = success(sandbox.run(
        &["seal", "--name", NAME],
        &hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9").unwrap(),
    ));
    let signed = success(sandbox.run(&["sign"], json!({"name":NAME,"key_envelope":envelope,"scheme":SCHEME,"digest":hex::encode(digest)}).to_string().as_bytes()));
    assert_eq!(signed["signature"], expected);
    verify_der(&digest, &signed, public);
    // BIP143 appends 01 to this DER for SIGHASH_ALL; avault must not append it.
    assert_eq!(success(sandbox.run(&["verify"], json!({"scheme":SCHEME,"public_key":public,"digest":hex::encode(digest),"signature":expected}).to_string().as_bytes())), json!({"valid":true}));
}
