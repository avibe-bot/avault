use super::avault;
use serde_json::Value;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use tempfile::TempDir;

fn run_generate(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700)).unwrap();
    avault()
        .args(["generate-secret"])
        .args(args)
        .env("AVAULT_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn assert_envelope_only(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "generate-secret failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object.keys().cloned().collect::<BTreeSet<_>>(),
        ["ciphertext", "nonce", "wrap_meta"]
            .into_iter()
            .map(String::from)
            .collect()
    );
    for key in ["ciphertext", "nonce", "wrap_meta"] {
        assert!(!object[key].as_str().unwrap().is_empty());
    }
    value
}

#[test]
fn generate_secret_stdout_is_only_the_existing_envelope_and_stderr_is_empty() {
    for args in [
        vec![
            "--name",
            "GENERATED_PASSWORD",
            "--type",
            "password",
            "--length",
            "24",
        ],
        vec!["--name", "GENERATED_HEX", "--type", "hex", "--bytes", "16"],
        vec![
            "--name",
            "GENERATED_BASE64",
            "--type",
            "base64",
            "--bytes",
            "16",
        ],
    ] {
        let home = TempDir::new().unwrap();
        let envelope = assert_envelope_only(&run_generate(home.path(), &args));
        assert_eq!(envelope.as_object().unwrap().len(), 3);
    }
}

#[test]
fn generate_secret_rejects_wrong_type_flags_without_unlocking_or_sealing() {
    let home = TempDir::new().unwrap();
    let output = run_generate(
        home.path(),
        &[
            "--name",
            "INVALID_GENERATION",
            "--type",
            "hex",
            "--length",
            "16",
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("hex type does not accept --length"));
    assert!(!stderr.contains("INVALID_GENERATION"));
    assert!(!home.path().join("machine.key").exists());
}

#[test]
fn generate_secret_rejects_out_of_range_and_unknown_recipes_without_output() {
    for args in [
        vec![
            "--name",
            "BAD_LENGTH",
            "--type",
            "password",
            "--length",
            "11",
        ],
        vec!["--name", "BAD_BYTES", "--type", "base64", "--bytes", "65"],
        vec!["--name", "BAD_TYPE", "--type", "urlsafe", "--bytes", "16"],
    ] {
        let home = TempDir::new().unwrap();
        let output = run_generate(home.path(), &args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("BAD_"));
        assert!(!home.path().join("machine.key").exists());
    }
}
