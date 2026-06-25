use serde_json::json;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn avault() -> Command {
    Command::new(env!("CARGO_BIN_EXE_avault"))
}

#[test]
fn seal_and_deliver_run_roundtrip() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());
    assert!(home.path().join("machine.key").exists());
    assert!(!home.path().join("master.key").exists());
    let sealed: serde_json::Value = serde_json::from_slice(&seal_output.stdout).unwrap();
    assert!(!sealed["ciphertext"].as_str().unwrap().is_empty());
    assert!(!sealed["nonce"].as_str().unwrap().is_empty());
    let meta: serde_json::Value =
        serde_json::from_str(sealed["wrap_meta"].as_str().unwrap()).unwrap();
    assert_eq!(meta["scheme"], "machine-aesgcm-v1");
    assert_eq!(meta["v"], 1);

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$SECRET_VALUE" = "s3cr3t" && printf ok"#)
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    let deliver_output = deliver.wait_with_output().unwrap();
    assert!(deliver_output.status.success());
    assert_eq!(deliver_output.stdout, b"ok");
}

#[test]
fn deliver_run_returns_child_exit_code() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 7")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    let status = deliver.wait().unwrap();
    assert_eq!(status.code(), Some(7));
}

#[test]
fn child_exit_2_is_distinct_from_avault_internal_failure() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 2")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    assert_eq!(deliver.wait().unwrap().code(), Some(2));

    let mut failed_open = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("WRONG_NAME")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    failed_open
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    assert_eq!(failed_open.wait().unwrap().code(), Some(70));
}

#[test]
fn deliver_run_rejects_name_mismatch() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("ANTHROPIC_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(70));
}

#[test]
fn key_export_and_import_interoperate_between_stores() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", source_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    assert!(seal.wait().unwrap().success());

    let source_key = fs::read(source_home.path().join("machine.key")).unwrap();

    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", source_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    export
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct horse battery staple\n")
        .unwrap();
    let export_output = export.wait_with_output().unwrap();
    assert!(export_output.status.success());
    let blob: serde_json::Value = serde_json::from_slice(&export_output.stdout).unwrap();
    assert_eq!(blob["scheme"], "machine-key-export-v1");

    let request = json!({
        "passphrase": "correct horse battery staple",
        "blob": blob
    });
    let mut import = avault()
        .arg("key")
        .arg("import")
        .env("AVAULT_HOME", target_home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    import
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let import_output = import.wait_with_output().unwrap();
    assert!(import_output.status.success());
    assert_eq!(import_output.stdout, b"{\"ok\":true}\n");
    assert_eq!(
        fs::read(target_home.path().join("machine.key")).unwrap(),
        source_key
    );
}

#[test]
fn key_export_requires_existing_master_key() {
    let home = tempfile::tempdir().unwrap();
    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    export
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"passphrase")
        .unwrap();
    let output = export.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!home.path().join("machine.key").exists());
}

#[test]
fn refuses_group_or_world_accessible_key_file() {
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join("machine.key"), [1u8; 32]).unwrap();
    fs::set_permissions(
        home.path().join("machine.key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    export
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"passphrase")
        .unwrap();
    let output = export.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let mode = fs::metadata(home.path().join("machine.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn python_aad_reference_opens_rust_envelope_and_rust_opens_python_envelope() {
    if Command::new("python3")
        .arg("-c")
        .arg("from cryptography.hazmat.primitives.ciphers.aead import AESGCM")
        .status()
        .map(|status| !status.success())
        .unwrap_or(true)
    {
        eprintln!("python cryptography is unavailable; skipping cross-language CLI vector");
        return;
    }

    let home = tempfile::tempdir().unwrap();
    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin
        .as_mut()
        .unwrap()
        .write_all(b"rust-value")
        .unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let python_open = Command::new("python3")
        .arg("-c")
        .arg(PYTHON_AAD_REFERENCE)
        .arg("open")
        .arg(home.path().join("machine.key"))
        .arg("OPENAI_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(&seal_output.stdout)?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(python_open.status.success());
    assert_eq!(python_open.stdout, b"rust-value");

    let python_seal = Command::new("python3")
        .arg("-c")
        .arg(PYTHON_AAD_REFERENCE)
        .arg("seal")
        .arg(home.path().join("machine.key"))
        .arg("OPENAI_API_KEY")
        .arg("python-value")
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(python_seal.status.success());

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$SECRET_VALUE" = "python-value""#)
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&python_seal.stdout)
        .unwrap();
    assert!(deliver.wait().unwrap().success());
}

const PYTHON_AAD_REFERENCE: &str = r#"
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

scheme = "machine-aesgcm-v1"
version = 1

def b64(raw):
    return base64.b64encode(raw).decode("ascii")

def unb64(text):
    return base64.b64decode(text.encode("ascii"))

def aad(name):
    return name.encode() + scheme.encode() + bytes([version])

mode, key_path, name = sys.argv[1:4]
master = open(key_path, "rb").read()
if mode == "open":
    sealed = json.load(sys.stdin)
    meta = json.loads(sealed["wrap_meta"])
    dek = AESGCM(master).decrypt(unb64(meta["dek_nonce"]), unb64(meta["wrapped_dek"]), None)
    value = AESGCM(dek).decrypt(unb64(sealed["nonce"]), unb64(sealed["ciphertext"]), aad(name))
    sys.stdout.buffer.write(value)
elif mode == "seal":
    value = sys.argv[4].encode()
    dek = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, value, aad(name))
    dek_nonce = os.urandom(12)
    wrapped_dek = AESGCM(master).encrypt(dek_nonce, dek, None)
    print(json.dumps({
        "ciphertext": b64(ciphertext),
        "nonce": b64(nonce),
        "wrap_meta": json.dumps({
            "v": version,
            "scheme": scheme,
            "wrapped_dek": b64(wrapped_dek),
            "dek_nonce": b64(dek_nonce),
        }),
    }))
else:
    raise SystemExit(2)
"#;
