//! Key generation contracts, on every platform, using only test-owned file stores.

use base64::Engine;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const NAME: &str = "TEST_CHANNEL_KEY";
const SCHEME: &str = "ecdsa-secp256k1-der";

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
