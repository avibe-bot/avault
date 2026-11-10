//! `avault verify` CLI contract (docs/DESIGN.md Appendix C · Public signature verification).
//!
//! Unlike `cli.rs`, these tests run on every platform: `verify` has no store or socket.

use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

const SCHEME: &str = "ecdsa-secp256k1-der";
const VALID_STDOUT: &str = "{\"valid\":true}\n";
const INVALID_STDOUT: &str = "{\"valid\":false}\n";
/// The documented request size cap.
const MAX_REQUEST_BYTES: usize = 4096;

/// `avault` in an environment with no home directory, no `AVAULT_HOME`, and no store
/// selection: there is no machine key to find and nowhere to create one.
fn avault() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_avault"));
    for name in [
        "AVAULT_HOME",
        "AVAULT_STORE",
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
    ] {
        command.env_remove(name);
    }
    command
}

struct Outcome {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(mut command: Command, stdin: &[u8]) -> Outcome {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A request over the size cap is not read to the end, so the pipe may close early.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let output = child.wait_with_output().unwrap();
    Outcome {
        status: output.status.code(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn verify(stdin: &[u8]) -> Outcome {
    let mut command = avault();
    command.arg("verify");
    run(command, stdin)
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/vectors/verify_ecdsa_secp256k1_der.json"
    ))
    .unwrap()
}

fn fixture_case(name: &str) -> serde_json::Value {
    fixture()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("fixture case {name} is missing"))
        .clone()
}

fn request_for(case: &serde_json::Value) -> serde_json::Value {
    json!({
        "scheme": SCHEME,
        "public_key": case["public_key_hex"],
        "digest": case["digest_hex"],
        "signature": case["signature_hex"],
    })
}

fn valid_request() -> serde_json::Value {
    request_for(&fixture_case("shared-signing-vector-compressed-key"))
}

fn request_values(request: &serde_json::Value) -> Vec<String> {
    ["public_key", "digest", "signature"]
        .iter()
        .filter_map(|field| request[*field].as_str())
        .map(str::to_string)
        .collect()
}

/// A failed `verify` exits 70, prints no result, and never repeats request content.
fn assert_rejected(name: &str, outcome: &Outcome, forbidden: &[String]) {
    assert_eq!(outcome.status, Some(70), "{name}: {}", outcome.stderr);
    assert_eq!(outcome.stdout, "", "{name}");
    assert!(outcome.stderr.starts_with("avault: "), "{name}");
    let stderr = outcome.stderr.to_lowercase();
    for value in forbidden {
        // An empty field or the one-byte identity point cannot be told apart from
        // ordinary message text.
        if value.len() >= 4 {
            assert!(
                !stderr.contains(&value.to_lowercase()),
                "{name}: stderr repeats request content: {}",
                outcome.stderr
            );
        }
    }
}

#[test]
fn verify_matches_the_shared_fixture() {
    let fixture = fixture();
    assert_eq!(fixture["scheme"], SCHEME);
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "the fixture lost cases");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let request = request_for(case);
        let outcome = verify(request.to_string().as_bytes());
        match case["expect"].as_str().unwrap() {
            "valid" => {
                assert_eq!(outcome.status, Some(0), "{name}: {}", outcome.stderr);
                assert_eq!(outcome.stdout, VALID_STDOUT, "{name}");
                assert_eq!(outcome.stderr, "", "{name}");
            }
            "invalid" => {
                assert_eq!(outcome.status, Some(1), "{name}: {}", outcome.stderr);
                assert_eq!(outcome.stdout, INVALID_STDOUT, "{name}");
                assert_eq!(outcome.stderr, "", "{name}");
            }
            "error" => assert_rejected(name, &outcome, &request_values(&request)),
            other => panic!("{name} has unknown expectation {other}"),
        }
    }
}

#[test]
fn verify_rejects_malformed_requests_without_repeating_them() {
    let valid = valid_request();
    let values = request_values(&valid);
    let with = |field: &str, value: serde_json::Value| {
        let mut request = valid.clone();
        request[field] = value;
        request.to_string().into_bytes()
    };
    let without = |field: &str| {
        let mut request = valid.clone();
        request.as_object_mut().unwrap().remove(field);
        request.to_string().into_bytes()
    };
    let public_key = valid["public_key"].as_str().unwrap();
    let digest = valid["digest"].as_str().unwrap();
    let signature = valid["signature"].as_str().unwrap();
    // Stand-ins for content that must not be repeated: text and a number where serde_json
    // would otherwise quote the unexpected value or field name.
    let marker = "leak-marker-0123456789".to_string();
    const NUMERIC_MARKER: u64 = 1_234_567_890_123_456;

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty stdin", Vec::new()),
        ("not JSON", format!("{marker} is not json").into_bytes()),
        ("JSON array", format!("[\"{marker}\"]").into_bytes()),
        ("JSON string", format!("\"{marker}\"").into_bytes()),
        ("truncated JSON", {
            let mut request = valid.to_string().into_bytes();
            request.pop();
            request
        }),
        (
            "trailing content",
            format!("{valid} \"{marker}\"").into_bytes(),
        ),
        ("two requests", format!("{valid}\n{valid}").into_bytes()),
        // What a caller sends to the store-backed verbs under `--store file-passphrase`.
        (
            "store passphrase line before the request",
            format!("{marker}\n{valid}").into_bytes(),
        ),
        ("unknown field", with("name", json!(marker))),
        ("unknown field name", with(&marker, json!(1))),
        (
            "private field",
            with("key_envelope", json!({ "ciphertext": marker })),
        ),
        (
            "duplicate field",
            format!(
                "{{\"scheme\":\"{SCHEME}\",\"public_key\":\"{public_key}\",\"digest\":\"{digest}\",\
                 \"digest\":\"{digest}\",\"signature\":\"{signature}\"}}"
            )
            .into_bytes(),
        ),
        ("numeric digest", with("digest", json!(NUMERIC_MARKER))),
        ("null signature", with("signature", json!(null))),
        ("array public key", with("public_key", json!([public_key]))),
        ("object scheme", with("scheme", json!({ "id": SCHEME }))),
        ("empty digest", with("digest", json!(""))),
        ("31-byte digest", with("digest", json!(&digest[..62]))),
        (
            "33-byte digest",
            with("digest", json!(format!("{digest}00"))),
        ),
        ("odd-length digest", with("digest", json!(&digest[..63]))),
        (
            "non-hex digest",
            with("digest", json!(format!("{}zz", &digest[..62]))),
        ),
        (
            "0x-prefixed digest",
            with("digest", json!(format!("0x{}", &digest[..62]))),
        ),
        ("padded digest", with("digest", json!(format!(" {digest}")))),
        (
            "odd-length public key",
            with("public_key", json!(&public_key[..65])),
        ),
        (
            "non-hex public key",
            with("public_key", json!(format!("{}zz", &public_key[..64]))),
        ),
        (
            "0x-prefixed public key",
            with("public_key", json!(format!("0x{public_key}"))),
        ),
        (
            "odd-length signature",
            with("signature", json!(&signature[..139])),
        ),
        (
            "non-hex signature",
            with("signature", json!(format!("{}zz", &signature[..138]))),
        ),
        (
            "base64 signature",
            with(
                "signature",
                json!("MEQCIEyjrKOkG8HKltZ3B+UlrGvXfdwZejS0wCC+HuY24pYX"),
            ),
        ),
    ];
    for field in ["scheme", "public_key", "digest", "signature"] {
        cases.push((field, without(field)));
    }
    for (name, stdin) in &cases {
        let mut forbidden = values.clone();
        forbidden.extend([marker.clone(), NUMERIC_MARKER.to_string()]);
        assert_rejected(name, &verify(stdin), &forbidden);
    }

    // Only the DER ECDSA scheme is verified; the other signing schemes are not reinterpreted.
    for scheme in [
        "ecdsa-secp256k1-recoverable",
        "schnorr-secp256k1-bip340",
        "schnorr-secp256k1-bip341-keypath",
        "ECDSA-SECP256K1-DER",
        "ecdsa-secp256k1-der ",
        "ed25519",
        "",
    ] {
        let outcome = verify(&with("scheme", json!(scheme)));
        let mut forbidden = values.clone();
        forbidden.extend(["recoverable", "schnorr-", "ed25519"].map(str::to_string));
        assert_rejected(scheme, &outcome, &forbidden);
    }
}

#[test]
fn verify_takes_no_options() {
    let request = valid_request().to_string();
    for options in [
        &["--store", "file"][..],
        &["--name", "MODEL_HUB"],
        &["request.json"],
    ] {
        let mut command = avault();
        command.arg("verify").args(options);
        let outcome = run(command, request.as_bytes());
        assert_rejected(&options.join(" "), &outcome, &[]);
    }
}

#[test]
fn verify_caps_the_request_size() {
    let request = valid_request().to_string();
    // Trailing whitespace keeps the request valid JSON at any length.
    let padded = |len: usize| {
        let mut stdin = request.clone().into_bytes();
        stdin.resize(len, b' ');
        stdin
    };

    let at_cap = verify(&padded(MAX_REQUEST_BYTES));
    assert_eq!(at_cap.status, Some(0), "{}", at_cap.stderr);
    assert_eq!(at_cap.stdout, VALID_STDOUT);

    let over_cap = verify(&padded(MAX_REQUEST_BYTES + 1));
    assert_rejected("over the cap", &over_cap, &request_values(&valid_request()));
    let far_over_cap = verify(&padded(1024 * 1024));
    assert_rejected("far over the cap", &far_over_cap, &[]);
}

#[test]
fn verify_is_keyless() {
    let request = valid_request().to_string();
    let invalid_request = request_for(&fixture_case("modified-digest")).to_string();

    // Control: this environment really has no machine key and no place for one, so a
    // store-backed verb fails in it.
    let mut pubkey = avault();
    pubkey.args(["--store", "file", "pubkey"]);
    let pubkey = run(pubkey, b"");
    assert_eq!(pubkey.status, Some(70), "{}", pubkey.stderr);
    assert_eq!(pubkey.stdout, "");

    // `verify` answers in the same environment, whatever store is selected. Any store
    // access would fail here: there is no home, `keychain` and `tpm` each exist on one
    // platform only, and `file-passphrase` would read the request's first line as its
    // unlock passphrase.
    for store in ["auto", "keychain", "tpm", "file", "file-passphrase"] {
        let mut by_flag = avault();
        by_flag.args(["--store", store, "verify"]);
        let outcome = run(by_flag, request.as_bytes());
        assert_eq!(
            outcome.status,
            Some(0),
            "--store {store}: {}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, VALID_STDOUT, "--store {store}");
        assert_eq!(outcome.stderr, "", "--store {store}");

        let mut by_env = avault();
        by_env.env("AVAULT_STORE", store).arg("verify");
        let outcome = run(by_env, invalid_request.as_bytes());
        assert_eq!(
            outcome.status,
            Some(1),
            "AVAULT_STORE={store}: {}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, INVALID_STDOUT, "AVAULT_STORE={store}");
        assert_eq!(outcome.stderr, "", "AVAULT_STORE={store}");
    }

    // With a store location configured, `verify` neither creates nor reads it.
    let home = tempfile::tempdir().unwrap();
    let vault = home.path().join("vault");
    for store in ["auto", "file", "file-passphrase"] {
        let mut command = avault();
        command
            .env("AVAULT_HOME", &vault)
            .env("HOME", home.path())
            .args(["--store", store, "verify"]);
        let outcome = run(command, request.as_bytes());
        assert_eq!(
            outcome.status,
            Some(0),
            "--store {store}: {}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, VALID_STDOUT, "--store {store}");
    }
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        0,
        "verify must not create store state"
    );

    // Control: a store-backed verb with the same location does create the machine key.
    #[cfg(unix)]
    {
        let mut pubkey = avault();
        pubkey
            .env("AVAULT_HOME", &vault)
            .args(["--store", "file", "pubkey"]);
        let pubkey = run(pubkey, b"");
        assert_eq!(pubkey.status, Some(0), "{}", pubkey.stderr);
        assert!(vault.join("machine.key").exists());
    }
}

#[test]
fn help_documents_verify() {
    let mut command = avault();
    command.arg("help");
    let outcome = run(command, b"");
    assert_eq!(outcome.status, Some(0));
    for expected in ["avault verify < verify-request.json", SCHEME, "keyless"] {
        assert!(outcome.stdout.contains(expected), "help omits {expected}");
    }
}
