//! Key generation contracts, on every platform, using only test-owned file stores.

use base64::Engine;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const NAME: &str = "TEST_CHANNEL_KEY";
const SCHEME: &str = "ecdsa-secp256k1-der";

#[path = "keypair/hd_bitcoin.rs"]
mod hd_bitcoin;

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for name in ["home", "avibe", "config", "data", "cache", "state", "tmp"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
        }
        Self(dir)
    }

    fn command(&self) -> Command {
        let root = self.0.path();
        let mut command = Command::new(env!("CARGO_BIN_EXE_avault"));
        command.args(["--store", "file"]);
        // Explicit store selection is the repository's test isolation boundary;
        // redirect every fallback too. Never select auto/Keychain/TPM in a test.
        for name in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
            command.env(name, root.join("home"));
        }
        command.env_remove("HOMEDRIVE").env_remove("HOMEPATH");
        command.env("AVAULT_STORE", "file");
        command.env("AVAULT_HOME", root.join("vault"));
        command.env("AVIBE_HOME", root.join("avibe"));
        for (name, dir) in [
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_RUNTIME_DIR", "tmp"),
            ("TMPDIR", "tmp"),
            ("TMP", "tmp"),
            ("TEMP", "tmp"),
        ] {
            command.env(name, root.join(dir));
        }
        command
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn generate(&self, curve: &str) -> Value {
        success(self.run(
            &["keypair", "generate", "--name", NAME, "--curve", curve],
            b"",
        ))
    }
}

fn success(output: Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_fields(value: &Value, expected: &[&str]) {
    let actual: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(actual, expected.iter().copied().collect());
}

fn assert_envelope(value: &Value) {
    assert_fields(value, &["ciphertext", "nonce", "wrap_meta"]);
    let decode = |value: &Value| {
        base64::engine::general_purpose::STANDARD
            .decode(value.as_str().unwrap())
            .unwrap()
    };
    // A raw 32-byte key plus GCM tag, not a serialized key or a seed/public concatenation.
    assert_eq!(decode(&value["ciphertext"]).len(), 48);
    assert_eq!(decode(&value["nonce"]).len(), 12);
    let wrap: Value = serde_json::from_str(value["wrap_meta"].as_str().unwrap()).unwrap();
    assert_fields(&wrap, &["v", "scheme", "wrapped_dek", "dek_nonce"]);
    assert_eq!(wrap["v"], 1);
    assert_eq!(wrap["scheme"], "machine-aesgcm-v1");
    assert_eq!(decode(&wrap["wrapped_dek"]).len(), 48);
    assert_eq!(decode(&wrap["dek_nonce"]).len(), 12);
}

#[test]
fn secp256k1_generate_seals_signs_and_verifies_without_a_verifier_store() {
    let signer = Sandbox::new();
    let verifier = Sandbox::new();
    let generated = signer.generate("secp256k1");
    assert_fields(&generated, &["envelope", "curve", "public_key"]);
    assert_eq!(generated["curve"], "secp256k1");
    assert_envelope(&generated["envelope"]);
    let public = generated["public_key"].as_str().unwrap();
    assert_eq!(public.len(), 66);
    assert_eq!(public, public.to_ascii_lowercase());
    assert!(matches!(hex::decode(public).unwrap()[0], 2 | 3));
    let other = signer.generate("secp256k1");
    assert_ne!(generated["public_key"], other["public_key"]);
    assert_ne!(generated["envelope"], other["envelope"]);

    // Published synthetic domain-separated payload digest. The channel computes
    // its digest outside avault; this test never opens the generated key.
    let digest = "0389b9e674c677e8f879323b379e802c991f06cd2bd69e817628faf993de9e49";
    let mut request = json!({"name": NAME, "key_envelope": generated["envelope"], "scheme": SCHEME, "digest": digest});
    let signed = success(signer.run(&["sign"], request.to_string().as_bytes()));
    assert_fields(&signed, &["signature", "recovery_id"]);
    assert_eq!(signed["recovery_id"], Value::Null);
    let mut verify = json!({"scheme": SCHEME, "public_key": public, "digest": digest, "signature": signed["signature"]});
    assert_eq!(
        success(verifier.run(&["verify"], verify.to_string().as_bytes())),
        json!({"valid": true})
    );
    verify["public_key"] = other["public_key"].clone();
    let invalid = verifier.run(&["verify"], verify.to_string().as_bytes());
    assert_eq!(invalid.status.code(), Some(1));
    assert_eq!(invalid.stdout, b"{\"valid\":false}\n");
    assert!(invalid.stderr.is_empty());
    assert!(!verifier.0.path().join("vault").exists());

    request["name"] = json!("WRONG_RECORD");
    let wrong_name = signer.run(&["sign"], request.to_string().as_bytes());
    assert_eq!(wrong_name.status.code(), Some(70));
    assert!(wrong_name.stdout.is_empty());
    let error = String::from_utf8(wrong_name.stderr).unwrap();
    assert!(error.contains("open"));
    assert!(!error.contains(public));
    assert!(!error.contains(generated["envelope"]["ciphertext"].as_str().unwrap()));
}

#[test]
fn secp256k1_invalid_options_and_import_export_fail_before_store_creation() {
    let sandbox = Sandbox::new();
    let generate = [
        "keypair",
        "generate",
        "--name",
        NAME,
        "--curve",
        "secp256k1",
    ];
    for extra in [
        vec!["--format", "raw"],
        vec!["--blind-box"],
        vec!["--seed", "not-a-production-seed"],
        vec!["--rng", "test"],
        vec!["--chain", "bitcoin"],
        vec!["--mnemonic", "test"],
        vec!["--derivation-path", "test"],
        vec!["--curve", "ed25519"],
        vec!["--name", "OTHER"],
    ] {
        let mut args = generate.to_vec();
        args.extend(extra);
        let output = sandbox.run(&args, b"");
        assert_eq!(output.status.code(), Some(70));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("not-a-production-seed"));
    }
    for args in [
        vec!["keypair", "generate", "--name", NAME, "--curve", "p256"],
        vec!["keypair", "generate", "--curve", "secp256k1"],
        vec!["keypair", "generate", "--name", NAME],
        vec!["keypair", "generate", "--name", NAME, "--curve"],
        vec![
            "keypair",
            "import",
            "--name",
            NAME,
            "--curve",
            "secp256k1",
            "--format",
            "raw",
        ],
        vec!["keypair", "export", "--name", NAME, "--curve", "secp256k1"],
    ] {
        let output = sandbox.run(&args, b"");
        assert_eq!(output.status.code(), Some(70));
        assert!(output.stdout.is_empty());
    }
    assert!(!sandbox.0.path().join("vault").exists());
}

#[test]
fn ed25519_generation_and_import_keep_the_existing_public_shape() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let sandbox = Sandbox::new();
    let seed = [7u8; 32]; // Existing synthetic Solana test fixture, never a real key.
    let public = avault_core::ed25519_public_key(&seed);
    let mut secret = Vec::from(seed);
    secret.extend_from_slice(&public);
    let mut outputs = vec![sandbox.generate("ed25519")];
    for (format, input) in [
        ("solana-cli-json", serde_json::to_vec(&secret).unwrap()),
        (
            "base58-secret",
            bs58::encode(&secret).into_string().into_bytes(),
        ),
    ] {
        let imported = success(sandbox.run(
            &[
                "keypair", "import", "--name", NAME, "--curve", "ed25519", "--format", format,
            ],
            &input,
        ));
        assert_eq!(imported["public_key"], hex::encode(public));
        outputs.push(imported);
    }
    for output in outputs {
        assert_fields(
            &output,
            &["envelope", "curve", "chain", "public_key", "address"],
        );
        assert_envelope(&output["envelope"]);
        assert_eq!(output["curve"], "ed25519");
        assert_eq!(output["chain"], "solana");
        let public: [u8; 32] = hex::decode(output["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(output["address"], bs58::encode(public).into_string());
        let message = b"keypair compatibility test";
        let signed = success(sandbox.run(&["sign"], json!({
            "name": NAME, "key_envelope": output["envelope"], "scheme": "ed25519", "message_hex": hex::encode(message),
        }).to_string().as_bytes()));
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(
                message,
                &Signature::from_slice(
                    &hex::decode(signed["signature"].as_str().unwrap()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
}
fn hd_import(sandbox: &Sandbox) -> Value {
    success(sandbox.run(
        &[
            "keypair", "import", "--name", NAME, "--type", "hd-seed", "--format", "raw-seed",
        ],
        &[42; 64],
    ))
}

fn refused(output: Output, expected: &str) {
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(expected), "{error}");
}

#[test]
fn hd_selectors_and_payload_mismatches_fail_before_any_store_access() {
    let sandbox = Sandbox::new(); // Deliberately no master key exists.
    let envelope = json!({"ciphertext":"not-ciphertext","nonce":"invalid","wrap_meta":json!({
        "v":1,"scheme":avault_core::HD_SEED_WRAP_SCHEME,"wrapped_dek":"invalid","dek_nonce":"invalid"
    }).to_string()});
    let request = json!({"name":NAME,"key_envelope":envelope,"derivation":{"chain":"evm","account":0},"digest":"00".repeat(32)});
    for (derivation, expected) in [
        (json!({"chain":"evm","account":20}), "between 0 and 19"),
        (
            json!({"chain":"evm","account":4294967295u32}),
            "between 0 and 19",
        ),
        (json!({"chain":"evm","account":-1}), "sign JSON is invalid"),
        (json!({"chain":"evm","account":0.5}), "sign JSON is invalid"),
        (json!({"chain":"evm","account":"0"}), "sign JSON is invalid"),
        (
            json!({"chain":"evm","account":null}),
            "sign JSON is invalid",
        ),
        (json!({"chain":"eth"}), "unsupported derivation chain"),
        (json!({"chain":"evm","path":"m/0"}), "sign JSON is invalid"),
        (json!({"account":0}), "sign JSON is invalid"),
    ] {
        let mut invalid = request.clone();
        invalid["derivation"] = derivation;
        refused(
            sandbox.run(&["sign"], invalid.to_string().as_bytes()),
            expected,
        );
    }
    for chain in ["evm", "bitcoin", "solana"] {
        for scheme in [
            "ecdsa-secp256k1-recoverable",
            "schnorr-secp256k1-bip341-keypath",
            "ed25519",
            "ecdsa-secp256k1-der",
            "schnorr-secp256k1-bip340",
        ] {
            if matches!(
                (chain, scheme),
                ("evm", "ecdsa-secp256k1-recoverable")
                    | ("bitcoin", "schnorr-secp256k1-bip341-keypath")
                    | ("solana", "ed25519")
            ) {
                continue;
            }
            let mut invalid = request.clone();
            invalid["derivation"]["chain"] = json!(chain);
            invalid["scheme"] = json!(scheme);
            refused(
                sandbox.run(&["sign"], invalid.to_string().as_bytes()),
                "does not match",
            );
        }
    }
    let mut invalid = request.clone();
    invalid["message_hex"] = json!("00");
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "message_hex is only valid",
    );
    invalid["derivation"]["chain"] = json!("solana");
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "digest is not valid",
    );
    invalid = request.clone();
    invalid["approval"] = json!({});
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "protected",
    );
    invalid = request.clone();
    invalid["dek_blindbox"] = json!({"scheme":"invalid","enc":"","ct":""});
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "protected",
    );
    invalid = request.clone();
    invalid["derivation"] = Value::Null;
    invalid["scheme"] = json!("ed25519");
    invalid.as_object_mut().unwrap().remove("digest");
    invalid["message_hex"] = json!("");
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "HD seed signing requires derivation",
    );
    invalid = request.clone();
    let mut meta: Value =
        serde_json::from_str(invalid["key_envelope"]["wrap_meta"].as_str().unwrap()).unwrap();
    meta["scheme"] = json!(avault_core::WRAP_SCHEME);
    invalid["key_envelope"]["wrap_meta"] = json!(meta.to_string());
    refused(
        sandbox.run(&["sign"], invalid.to_string().as_bytes()),
        "legacy keypairs do not accept derivation",
    );
    assert!(!sandbox.0.path().join("vault").exists());
}

#[test]
fn hd_import_rejects_bad_lengths_formats_and_types_without_output_or_store_creation() {
    let sandbox = Sandbox::new();
    let args = [
        "keypair", "import", "--name", NAME, "--type", "hd-seed", "--format", "raw-seed",
    ];
    for len in [0, 32, 63, 65, 128] {
        let bytes = vec![b'Q'; len];
        let output = sandbox.run(&args, &bytes);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("QQQQ"));
        refused(output, "invalid length");
    }
    for extra in [
        vec!["--type", "hd-seed"],
        vec!["--curve", "ed25519"],
        vec!["--format", "hex"],
    ] {
        let mut bad = args.to_vec();
        bad.extend(extra);
        let output = sandbox.run(&bad, &[42; 64]);
        assert_eq!(output.status.code(), Some(70));
        assert!(output.stdout.is_empty());
    }
    for format in ["hex", "seed-hex", "base64", "mnemonic"] {
        let mut bad = args;
        bad[7] = format;
        refused(
            sandbox.run(&bad, &[42; 64]),
            "unsupported HD seed import format",
        );
    }
    refused(
        sandbox.run(
            &["keypair", "generate", "--name", NAME, "--type", "hd-seed"],
            b"",
        ),
        "does not accept --type",
    );
    refused(
        sandbox.run(
            &[
                "keypair", "import", "--name", NAME, "--type", "seed", "--format", "raw-seed",
            ],
            &[42; 64],
        ),
        "unsupported keypair import type",
    );
    assert!(!sandbox.0.path().join("vault").exists());
}

#[test]
fn hd_seed_never_enters_generic_value_delivery_even_after_retagging() {
    let sandbox = Sandbox::new();
    let imported = hd_import(&sandbox);
    let mut retagged = imported["envelope"].clone();
    let mut meta: Value = serde_json::from_str(retagged["wrap_meta"].as_str().unwrap()).unwrap();
    meta["scheme"] = json!(avault_core::WRAP_SCHEME);
    retagged["wrap_meta"] = json!(meta.to_string());
    for (envelope, error) in [
        (imported["envelope"].clone(), "unsupported wrap scheme"),
        (retagged, "value decrypt failed"),
    ] {
        let secret = json!({"name":NAME,"env":NAME,"envelope":envelope});
        refused(
            sandbox.run(
                &["deliver", "run", "--", "must-not-start"],
                json!([secret]).to_string().as_bytes(),
            ),
            error,
        );
        let path = sandbox.0.path().join("must-not-write.env");
        refused(
            sandbox.run(
                &["deliver", "inject"],
                json!({"path":path,"secrets":[secret]})
                    .to_string()
                    .as_bytes(),
            ),
            error,
        );
        assert!(!path.exists());
        refused(
            sandbox.run(
                &["deliver", "fetch"],
                json!({"name":NAME,"envelope":envelope,"request":{
                    "method":"GET","url":"http://127.0.0.1:9/","allowed_hosts":["127.0.0.1"]
                }})
                .to_string()
                .as_bytes(),
            ),
            error,
        );
    }
}

#[test]
fn hd_seed_import_derives_twenty_accounts_and_signs_each_chain() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};

    let sandbox = Sandbox::new();
    let seed_hex = b"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let imported = success(sandbox.run(
        &[
            "keypair",
            "import",
            "--name",
            "HD_WALLET",
            "--type",
            "hd-seed",
            "--format",
            "raw-seed",
        ],
        &hex::decode(seed_hex).unwrap(),
    ));
    assert_fields(&imported, &["accounts", "type", "envelope"]);
    assert_eq!(imported["type"], "hd-seed");
    assert_eq!(imported["accounts"].as_array().unwrap().len(), 20);
    assert_eq!(imported["accounts"][0]["account"], 0);
    assert_eq!(
        imported["accounts"][0]["evm"],
        "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
    );
    assert_eq!(
        imported["accounts"][0]["bitcoin"],
        "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    );
    assert_eq!(
        imported["accounts"][0]["solana"],
        "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7"
    );
    let wrap: Value =
        serde_json::from_str(imported["envelope"]["wrap_meta"].as_str().unwrap()).unwrap();
    assert_eq!(wrap["scheme"], avault_core::HD_SEED_WRAP_SCHEME);
    assert_fields(&wrap, &["v", "scheme", "wrapped_dek", "dek_nonce"]);
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/vectors/hd_wallets.json")).unwrap();
    for expected in fixture["wallet_accounts"].as_array().unwrap() {
        let account = &imported["accounts"][expected["account"].as_u64().unwrap() as usize];
        assert_fields(account, &["account", "evm", "bitcoin", "solana"]);
        for chain in ["evm", "bitcoin", "solana"] {
            assert_eq!(account[chain], expected[chain]);
        }
    }
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(imported["envelope"]["ciphertext"].as_str().unwrap())
            .unwrap()
            .len(),
        80
    );

    let digest = "00".repeat(32);
    let evm_request = json!({
        "name": "HD_WALLET",
        "key_envelope": imported["envelope"],
        "derivation": {"chain": "evm", "account": 1},
        "digest": digest,
    });
    let evm_signed = success(sandbox.run(&["sign"], evm_request.to_string().as_bytes()));
    let signature = hex::decode(evm_signed["signature"].as_str().unwrap()).unwrap();
    let ecdsa_signature = EcdsaSignature::from_slice(&signature[..64]).unwrap();
    let recovery_id =
        RecoveryId::try_from(evm_signed["recovery_id"].as_u64().unwrap() as u8).unwrap();
    let recovered =
        EcdsaVerifyingKey::recover_from_prehash(&[0u8; 32], &ecdsa_signature, recovery_id).unwrap();
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        imported["accounts"][1]["evm"]
    );

    let message = b"hd seed solana signing";
    let solana_request = json!({
        "name": "HD_WALLET",
        "key_envelope": imported["envelope"],
        "derivation": {"chain": "solana", "account": 1},
        "message_hex": hex::encode(message),
    });
    let solana_signed = success(sandbox.run(&["sign"], solana_request.to_string().as_bytes()));
    let public = hex::decode(imported["accounts"][1]["solana"].as_str().unwrap()).unwrap();
    VerifyingKey::from_bytes(public.as_slice().try_into().unwrap())
        .unwrap()
        .verify(
            message,
            &Signature::from_slice(
                &hex::decode(solana_signed["signature"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

    let bitcoin_request = json!({
        "name": "HD_WALLET",
        "key_envelope": imported["envelope"],
        "derivation": {"chain": "bitcoin", "account": 1},
        "scheme": "schnorr-secp256k1-bip341-keypath",
        "digest": digest,
    });
    let bitcoin_signed = success(sandbox.run(&["sign"], bitcoin_request.to_string().as_bytes()));
    assert_eq!(bitcoin_signed["recovery_id"], Value::Null);
    let signature = k256::schnorr::Signature::try_from(
        hex::decode(bitcoin_signed["signature"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let published_output =
        hex::decode(fixture["bip86"][3]["output_key"].as_str().unwrap()).unwrap();
    k256::schnorr::VerifyingKey::from_bytes(&published_output)
        .unwrap()
        .verify_raw(&[0u8; 32], &signature)
        .unwrap();
    // Omitted account is exactly #0, explicit scheme is optional only for HD.
    let mut default = evm_request.clone();
    default["derivation"] = json!({"chain":"evm"});
    let signed_default = success(sandbox.run(&["sign"], default.to_string().as_bytes()));
    default["derivation"]["account"] = json!(0);
    default["scheme"] = json!("ecdsa-secp256k1-recoverable");
    assert_eq!(
        signed_default,
        success(sandbox.run(&["sign"], default.to_string().as_bytes()))
    );
    default["derivation"]["account"] = json!(19);
    let last = success(sandbox.run(&["sign"], default.to_string().as_bytes()));
    let signature =
        EcdsaSignature::from_slice(&hex::decode(last["signature"].as_str().unwrap()).unwrap())
            .unwrap();
    let recovered = EcdsaVerifyingKey::recover_from_prehash(
        &[0; 32],
        &signature,
        RecoveryId::try_from(last["recovery_id"].as_u64().unwrap() as u8).unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        imported["accounts"][19]["evm"]
    );
}

#[test]
fn hd_seed_type_and_derivation_mismatches_fail_without_signing() {
    let sandbox = Sandbox::new();
    let seed = [0x42u8; 64];
    let imported = success(sandbox.run(
        &[
            "keypair", "import", "--name", NAME, "--type", "hd-seed", "--format", "raw-seed",
        ],
        &seed,
    ));

    let no_derivation = sandbox.run(
        &["sign"],
        &json!({
            "name": NAME,
            "key_envelope": imported["envelope"],
            "scheme": "ecdsa-secp256k1-recoverable",
            "digest": "00".repeat(32),
        })
        .to_string()
        .into_bytes(),
    );
    assert_eq!(no_derivation.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&no_derivation.stderr)
        .contains("HD seed signing requires derivation"));

    let wrong_scheme = sandbox.run(
        &["sign"],
        &json!({
            "name": NAME,
            "key_envelope": imported["envelope"],
            "derivation": {"chain": "evm", "account": 0},
            "scheme": "ed25519",
            "message_hex": "00",
        })
        .to_string()
        .into_bytes(),
    );
    assert_eq!(wrong_scheme.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&wrong_scheme.stderr).contains("does not match"));

    let out_of_range = sandbox.run(
        &["sign"],
        &json!({
            "name": NAME,
            "key_envelope": imported["envelope"],
            "derivation": {"chain": "solana", "account": 20},
            "message_hex": "00",
        })
        .to_string()
        .into_bytes(),
    );
    assert_eq!(out_of_range.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&out_of_range.stderr).contains("between 0 and 19"));

    let legacy = sandbox.generate("ed25519");
    let legacy_with_derivation = sandbox.run(
        &["sign"],
        &json!({
            "name": NAME,
            "key_envelope": legacy["envelope"],
            "derivation": {"chain": "solana", "account": 0},
            "message_hex": "00",
        })
        .to_string()
        .into_bytes(),
    );
    assert_eq!(legacy_with_derivation.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&legacy_with_derivation.stderr)
        .contains("legacy keypairs do not accept derivation"));
}
