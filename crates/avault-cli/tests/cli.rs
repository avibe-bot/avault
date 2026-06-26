#![cfg(unix)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_seal, Deserializable,
    OpModeS, Serializable,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn avault() -> Command {
    Command::new(env!("CARGO_BIN_EXE_avault"))
}

fn seal_secret(home: &std::path::Path, name: &str, value: &[u8]) -> serde_json::Value {
    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg(name)
        .env("AVAULT_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(value).unwrap();
    let output = seal.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn write_p0_master(home: &std::path::Path) {
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        home.join("machine.key"),
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
    )
    .unwrap();
    fs::set_permissions(home.join("machine.key"), fs::Permissions::from_mode(0o600)).unwrap();
}

fn p0_no_aad_envelope() -> serde_json::Value {
    json!({
        "ciphertext": "gbSQ4CgEA//jJu56fOvXZE0hKkc9LktZoM+58v2Dsw==",
        "nonce": "MDEyMzQ1Njc4OTo7",
        "wrap_meta": json!({
            "v": 1,
            "scheme": "machine-aesgcm-v1",
            "wrapped_dek": "suj8cHJp0VSVnU1txzlNBBmnMD/TUGlEHy4kjvt+g7RlXgPlB6d7YQpDbhPKDEg7",
            "dek_nonce": "QEFCQ0RFRkdISUpL"
        }).to_string()
    })
}

struct TestBlindBoxAad<'a> {
    purpose: &'a str,
    name: &'a str,
    scope_type: &'a str,
    scope_ref: &'a str,
    scheme: &'a str,
    digest: &'a [u8],
    approval_nonce: &'a [u8],
    approval_expires_at_unix: Option<u64>,
    operation_hash: &'a [u8],
}

fn blind_box_aad(context: TestBlindBoxAad<'_>) -> Vec<u8> {
    fn push_field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"avault:blind-box:aad:v1");
    push_field(&mut out, context.purpose.as_bytes());
    push_field(&mut out, context.name.as_bytes());
    push_field(&mut out, b"machine-aesgcm-v1");
    push_field(&mut out, &[1]);
    push_field(&mut out, context.scope_type.as_bytes());
    push_field(&mut out, context.scope_ref.as_bytes());
    push_field(&mut out, context.scheme.as_bytes());
    push_field(&mut out, context.digest);
    push_field(&mut out, context.approval_nonce);
    match context.approval_expires_at_unix {
        Some(expires_at) => push_field(&mut out, &expires_at.to_be_bytes()),
        None => push_field(&mut out, &[]),
    }
    push_field(&mut out, context.operation_hash);
    out
}

fn aad_seal(name: &str) -> Vec<u8> {
    blind_box_aad(TestBlindBoxAad {
        purpose: "seal",
        name,
        scope_type: "",
        scope_ref: "",
        scheme: "",
        digest: &[],
        approval_nonce: &[],
        approval_expires_at_unix: None,
        operation_hash: &[],
    })
}

fn aad_deliver(
    name: &str,
    approval_nonce: &[u8],
    expires_at: u64,
    operation_hash: &[u8],
) -> Vec<u8> {
    blind_box_aad(TestBlindBoxAad {
        purpose: "deliver",
        name,
        scope_type: "",
        scope_ref: "",
        scheme: "",
        digest: &[],
        approval_nonce,
        approval_expires_at_unix: Some(expires_at),
        operation_hash,
    })
}

fn aad_agent_deliver(
    scope_type: &str,
    scope_ref: &str,
    name: &str,
    approval_nonce: &[u8],
    expires_at: u64,
) -> Vec<u8> {
    let operation_hash = operation_hash(&[b"agent-deliver", name.as_bytes()]);
    blind_box_aad(TestBlindBoxAad {
        purpose: "agent-deliver",
        name,
        scope_type,
        scope_ref,
        scheme: "",
        digest: &[],
        approval_nonce,
        approval_expires_at_unix: Some(expires_at),
        operation_hash: &operation_hash,
    })
}

fn aad_sign(
    name: &str,
    scheme: &str,
    digest_hex: &str,
    approval_nonce: &[u8],
    expires_at: u64,
) -> Vec<u8> {
    let digest = hex::decode(digest_hex).unwrap();
    let operation_hash = operation_hash(&[b"sign", scheme.as_bytes(), digest.as_slice()]);
    blind_box_aad(TestBlindBoxAad {
        purpose: "sign",
        name,
        scope_type: "",
        scope_ref: "",
        scheme,
        digest: &digest,
        approval_nonce,
        approval_expires_at_unix: Some(expires_at),
        operation_hash: &operation_hash,
    })
}

fn aad_agent_sign(
    scope_type: &str,
    scope_ref: &str,
    name: &str,
    scheme: &str,
    digest_hex: &str,
    approval_nonce: &[u8],
    expires_at: u64,
) -> Vec<u8> {
    let digest = hex::decode(digest_hex).unwrap();
    let operation_hash = operation_hash(&[b"agent-sign", scheme.as_bytes(), digest.as_slice()]);
    blind_box_aad(TestBlindBoxAad {
        purpose: "agent-sign",
        name,
        scope_type,
        scope_ref,
        scheme,
        digest: &digest,
        approval_nonce,
        approval_expires_at_unix: Some(expires_at),
        operation_hash: &operation_hash,
    })
}

fn operation_hash(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn approval_json(nonce: &[u8], expires_at: u64) -> serde_json::Value {
    json!({
        "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
        "expires_at_unix": expires_at
    })
}

fn future_expiry() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

fn run_operation_hash(env: &str, command: &[&str]) -> [u8; 32] {
    let mut fields = Vec::with_capacity(2 + command.len());
    fields.push(b"deliver-run".as_slice());
    fields.push(env.as_bytes());
    fields.extend(command.iter().map(|arg| arg.as_bytes()));
    operation_hash(&fields)
}

fn fetch_operation_hash(request: &serde_json::Value) -> [u8; 32] {
    let method = request["method"].as_str().unwrap_or("");
    let url = request["url"].as_str().unwrap_or("");
    let empty = Vec::new();
    let hosts = request["allowed_hosts"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|host| host.as_str().unwrap().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let hosts = hosts.join("\0");
    let headers = request["headers"]
        .as_object()
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| format!("{name}\0{}", value.as_str().unwrap()))
                .collect::<Vec<_>>()
                .join("\0")
        })
        .unwrap_or_default();
    let body = request["body"].as_str().unwrap_or("");
    let inject = match request.get("inject").and_then(|value| value.as_object()) {
        Some(inject) if inject.get("type").and_then(|v| v.as_str()) == Some("header") => {
            format!("header:{}", inject["name"].as_str().unwrap())
        }
        Some(inject) if inject.get("type").and_then(|v| v.as_str()) == Some("query") => {
            format!("query:{}", inject["name"].as_str().unwrap())
        }
        _ => "bearer".to_string(),
    };
    operation_hash(&[
        b"deliver-fetch",
        method.as_bytes(),
        url.as_bytes(),
        hosts.as_bytes(),
        headers.as_bytes(),
        body.as_bytes(),
        inject.as_bytes(),
    ])
}

fn inject_operation_hash(target_name: &str, format: &str, path: &std::path::Path) -> [u8; 32] {
    operation_hash(&[
        b"deliver-inject",
        target_name.as_bytes(),
        format.as_bytes(),
        path.to_str().unwrap().as_bytes(),
    ])
}

fn fixed_blind_box(public_key: &str, plaintext: &[u8], aad: &[u8]) -> serde_json::Value {
    struct FixedRng([u8; 32], u64);
    impl hpke::rand_core::RngCore for FixedRng {
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
            use sha2::Digest;
            let mut written = 0usize;
            while written < dest.len() {
                let mut input = [0u8; 40];
                input[..32].copy_from_slice(&self.0);
                input[32..].copy_from_slice(&self.1.to_le_bytes());
                let block = sha2::Sha256::digest(input);
                let n = (dest.len() - written).min(block.len());
                dest[written..written + n].copy_from_slice(&block[..n]);
                written += n;
                self.1 = self.1.wrapping_add(1);
            }
        }
    }
    impl hpke::rand_core::CryptoRng for FixedRng {}

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .unwrap();
    let public_key =
        <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&public_key_bytes).unwrap();
    let mut rng = FixedRng([0x42u8; 32], 0);
    let (enc, ct) = single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &public_key,
        b"avault:blind-box:v1",
        plaintext,
        aad,
        &mut rng,
    )
    .unwrap();

    json!({
        "scheme": "hpke-x25519-hkdfsha256-aes256gcm-v1",
        "enc": base64::engine::general_purpose::STANDARD.encode(enc.to_bytes()),
        "ct": base64::engine::general_purpose::STANDARD.encode(ct)
    })
}

fn p2_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../tests/vectors/p2_core_crypto.json")).unwrap()
}

fn envelope_encrypted_with_dek(name: &str, dek: &[u8; 32], value: &[u8]) -> serde_json::Value {
    let nonce = [0x11u8; 12];
    let mut aad = Vec::with_capacity(name.len() + "machine-aesgcm-v1".len() + 1);
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(b"machine-aesgcm-v1");
    aad.push(1);
    let ciphertext = Aes256Gcm::new(dek.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: value,
                aad: &aad,
            },
        )
        .unwrap();
    json!({
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext),
        "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
        "wrap_meta": json!({
            "v": 1,
            "scheme": "machine-aesgcm-v1",
            "wrapped_dek": "",
            "dek_nonce": ""
        }).to_string()
    })
}

fn connect_agent(socket: &std::path::Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                if err.kind() != std::io::ErrorKind::NotFound
                    && err.kind() != std::io::ErrorKind::ConnectionRefused
                {
                    panic!("failed to connect to agent: {err}");
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => panic!("timed out connecting to agent: {err}"),
        }
    }
}

fn agent_request(stream: &mut UnixStream, request: serde_json::Value) -> serde_json::Value {
    let bytes = serde_json::to_vec(&request).unwrap();
    let len = u32::try_from(bytes.len()).unwrap().to_be_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(&bytes).unwrap();
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let response_len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

fn spawn_agent(socket: &std::path::Path, idle_timeout_secs: u64) -> std::process::Child {
    avault()
        .arg("agent")
        .arg("--socket")
        .arg(socket)
        .arg("--idle-timeout-secs")
        .arg(idle_timeout_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_passphrase_agent(
    socket: &std::path::Path,
    idle_timeout_secs: u64,
    passphrase: &[u8],
    home: &std::path::Path,
) -> std::process::Child {
    let mut child = avault()
        .arg("agent")
        .arg("--store")
        .arg("file-passphrase")
        .arg("--unlock")
        .arg("--socket")
        .arg(socket)
        .arg("--idle-timeout-secs")
        .arg(idle_timeout_secs.to_string())
        .env("AVAULT_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(passphrase).unwrap();
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    drop(child.stdin.take());
    child
}

#[test]
fn seal_and_deliver_run_roundtrip() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());
    assert!(home.path().join("vault").join("machine.key").exists());
    assert!(!home.path().join("vault").join("master.key").exists());
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
fn passphrase_store_seal_and_deliver_roundtrip() {
    let home = tempfile::tempdir().unwrap();
    let vault_home = home.path().join("vault");

    let mut seal = avault()
        .arg("--store")
        .arg("file-passphrase")
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", &vault_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct horse battery staple\ns3cr3t")
        .unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());
    assert!(!vault_home.join("machine.key").exists());
    assert!(vault_home.join("machine.passphrase.json").exists());

    let request = json!([
        {
            "name": "OPENAI_API_KEY",
            "env": "SECRET_VALUE",
            "envelope": serde_json::from_slice::<serde_json::Value>(&seal_output.stdout).unwrap()
        }
    ]);
    let mut deliver = avault()
        .arg("--store")
        .arg("file-passphrase")
        .arg("deliver")
        .arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$SECRET_VALUE" = "s3cr3t" && printf ok"#)
        .env("AVAULT_HOME", &vault_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct horse battery staple\n")
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ok");
}

#[test]
fn passphrase_store_wrong_passphrase_fails_without_plaintext_key_file() {
    let home = tempfile::tempdir().unwrap();
    let vault_home = home.path().join("vault");
    let mut seal = avault()
        .arg("--store")
        .arg("file-passphrase")
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", &vault_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin
        .as_mut()
        .unwrap()
        .write_all(b"correct horse battery staple\ns3cr3t")
        .unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let mut deliver = avault()
        .arg("--store")
        .arg("file-passphrase")
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .env("AVAULT_HOME", &vault_home)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"wrong passphrase\n")
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&seal_output.stdout)
        .unwrap();
    let output = deliver.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(70));
    assert!(!vault_home.join("machine.key").exists());
    assert!(vault_home.join("machine.passphrase.json").exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to unlock passphrase master key"));
    assert!(!stderr.contains("s3cr3t"));
}

#[test]
fn pubkey_and_blind_box_seal_roundtrip() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));

    let output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let vector = p2_vectors();
    assert_eq!(pubkey["public_key"], vector["blind_box"]["public_key"]);
    assert_eq!(pubkey["fingerprint"], vector["blind_box"]["fingerprint"]);

    let blind_box = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        b"blind-value",
        &aad_seal("BLIND_SECRET"),
    );
    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("BLIND_SECRET")
        .arg("--blind-box")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin
        .as_mut()
        .unwrap()
        .write_all(blind_box.to_string().as_bytes())
        .unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("BLIND_SECRET")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$SECRET_VALUE" = "blind-value" && printf ok"#)
        .env("AVAULT_HOME", home.path().join("vault"))
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
fn sign_matches_shared_vectors_for_all_schemes() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let vector = p2_vectors();
    let signing = &vector["signing"];
    let private_key = hex::decode(signing["private_key_hex"].as_str().unwrap()).unwrap();
    let key_envelope = seal_secret(&home.path().join("vault"), "ETH_SIGNING_KEY", &private_key);

    for scheme in signing["schemes"].as_array().unwrap() {
        let request = json!({
            "name": "ETH_SIGNING_KEY",
            "key_envelope": key_envelope,
            "digest": signing["digest_hex"],
            "scheme": scheme["scheme"]
        });
        let mut sign = avault()
            .arg("sign")
            .env("AVAULT_HOME", home.path().join("vault"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        sign.stdin
            .as_mut()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let output = sign.wait_with_output().unwrap();
        assert!(output.status.success());
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if scheme["scheme"] == "schnorr-secp256k1-bip340" {
            assert_eq!(response["signature"].as_str().unwrap().len(), 128);
            assert_eq!(response["recovery_id"], serde_json::Value::Null);
        } else {
            assert_eq!(response["signature"], scheme["signature_hex"]);
            assert_eq!(response["recovery_id"], scheme["recovery_id"]);
        }
    }
}

#[test]
fn protected_sign_uses_dek_blindbox() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let vector = p2_vectors();
    let signing = &vector["signing"];
    let private_key = hex::decode(signing["private_key_hex"].as_str().unwrap()).unwrap();
    let dek = [0x99u8; 32];
    let approval_nonce = b"protected-sign-1";
    let approval_expires_at = future_expiry();
    let key_envelope = envelope_encrypted_with_dek("PROTECTED_KEY", &dek, &private_key);

    let output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let dek_blindbox = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        &dek,
        &aad_sign(
            "PROTECTED_KEY",
            "ecdsa-secp256k1-der",
            signing["digest_hex"].as_str().unwrap(),
            approval_nonce,
            approval_expires_at,
        ),
    );
    let expected = signing["schemes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scheme| scheme["scheme"] == "ecdsa-secp256k1-der")
        .unwrap();
    let request = json!({
        "name": "PROTECTED_KEY",
        "key_envelope": key_envelope,
        "digest": signing["digest_hex"],
        "scheme": "ecdsa-secp256k1-der",
        "dek_blindbox": dek_blindbox,
        "approval": approval_json(approval_nonce, approval_expires_at)
    });
    let mut sign = avault()
        .arg("sign")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    sign.stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = sign.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["signature"], expected["signature_hex"]);
    assert_eq!(response["recovery_id"], serde_json::Value::Null);
}

#[test]
fn protected_deliver_run_uses_dek_blindbox() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let dek = [0x7bu8; 32];
    let approval_nonce = b"protected-run-01";
    let approval_expires_at = future_expiry();
    let command = [
        "/bin/sh",
        "-c",
        r#"test "$SECRET_VALUE" = "protected-run" && printf ok"#,
    ];
    let envelope = envelope_encrypted_with_dek("PROTECTED_VALUE", &dek, b"protected-run");
    let pubkey_output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(pubkey_output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&pubkey_output.stdout).unwrap();
    let dek_blindbox = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        &dek,
        &aad_deliver(
            "PROTECTED_VALUE",
            approval_nonce,
            approval_expires_at,
            &run_operation_hash("SECRET_VALUE", &command),
        ),
    );
    let request = json!([
        {
            "name": "PROTECTED_VALUE",
            "env": "SECRET_VALUE",
            "envelope": envelope,
            "dek_blindbox": dek_blindbox,
            "approval": approval_json(approval_nonce, approval_expires_at)
        }
    ]);

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .args(command)
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ok");
}

#[test]
fn protected_deliver_rejects_replayed_blindbox_for_different_command() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let dek = [0x7cu8; 32];
    let envelope = envelope_encrypted_with_dek("PROTECTED_VALUE", &dek, b"protected-run");
    let pubkey_output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(pubkey_output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&pubkey_output.stdout).unwrap();
    let approval_nonce = b"replayed-run-001";
    let approval_expires_at = future_expiry();
    let approved_command = ["/bin/sh", "-c", "printf approved"];
    let replayed_command = ["/bin/sh", "-c", "printf replayed"];
    let dek_blindbox = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        &dek,
        &aad_deliver(
            "PROTECTED_VALUE",
            approval_nonce,
            approval_expires_at,
            &run_operation_hash("SECRET_VALUE", &approved_command),
        ),
    );
    let request = json!([
        {
            "name": "PROTECTED_VALUE",
            "env": "SECRET_VALUE",
            "envelope": envelope,
            "dek_blindbox": dek_blindbox,
            "approval": approval_json(approval_nonce, approval_expires_at)
        }
    ]);

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .args(replayed_command)
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(70));
}

#[test]
fn agent_grant_deliver_inject_release_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let inject_path = tmp.path().join("delivered.env");
    let mut agent = spawn_agent(&socket, 60);
    let mut stream = connect_agent(&socket);

    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    assert_eq!(pubkey["ok"], true);
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let dek = [0x51u8; 32];
    let approval_nonce = b"agent-deliver-01";
    let approval_expires_at = future_expiry();
    let grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "agent-test",
            "ttl_secs": 60,
            "deks": [
                {
                    "name": "API_TOKEN",
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_deliver("session", "agent-test", "API_TOKEN", approval_nonce, approval_expires_at)
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(grant["ok"], true);
    assert_eq!(grant["result"]["granted"], 1);

    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"agent-secret");
    let delivered = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "agent-test",
            "mode": "inject",
            "path": inject_path,
            "format": "dotenv",
            "secrets": [
                {"name": "API_TOKEN", "key": "API_TOKEN", "envelope": envelope}
            ]
        }),
    );
    assert_eq!(delivered["ok"], true);
    assert_eq!(
        fs::read_to_string(&inject_path).unwrap(),
        "API_TOKEN='agent-secret'\n"
    );

    let released = agent_request(
        &mut stream,
        json!({"type": "release", "scope_type": "session", "scope_ref": "agent-test"}),
    );
    assert_eq!(released["ok"], true);
    assert_eq!(released["result"]["released"], true);

    let replayed_grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "agent-test",
            "ttl_secs": 60,
            "deks": [
                {
                    "name": "API_TOKEN",
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_deliver(
                            "session",
                            "agent-test",
                            "API_TOKEN",
                            approval_nonce,
                            approval_expires_at
                        )
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(replayed_grant["ok"], false);
    assert!(replayed_grant["error"]
        .as_str()
        .unwrap()
        .contains("approval"));

    let denied = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "agent-test",
            "mode": "inject",
            "path": tmp.path().join("denied.env"),
            "format": "dotenv",
            "secrets": [
                {"name": "API_TOKEN", "key": "API_TOKEN", "envelope": envelope}
            ]
        }),
    );
    assert_eq!(denied["ok"], false);
    assert!(denied["error"].as_str().unwrap().contains("grant"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_rejects_empty_scope_and_excessive_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let mut stream = connect_agent(&socket);
    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let dek = [0x55u8; 32];
    let approval_nonce = b"agent-bad-scope";
    let approval_expires_at = future_expiry();
    let dek_input = json!({
        "name": "API_TOKEN",
        "dek_blindbox": fixed_blind_box(
            public_key,
            &dek,
            &aad_agent_deliver("session", "bad-test", "API_TOKEN", approval_nonce, approval_expires_at)
        ),
        "approval": approval_json(approval_nonce, approval_expires_at)
    });

    let empty_scope = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "",
            "scope_ref": "bad-test",
            "ttl_secs": 60,
            "deks": [dek_input.clone()]
        }),
    );
    assert_eq!(empty_scope["ok"], false);
    assert!(empty_scope["error"]
        .as_str()
        .unwrap()
        .contains("scope_type"));

    let excessive_ttl = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "bad-test",
            "ttl_secs": u64::MAX,
            "deks": [dek_input]
        }),
    );
    assert_eq!(excessive_ttl["ok"], false);
    assert!(excessive_ttl["error"].as_str().unwrap().contains("ttl"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn second_agent_refuses_live_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let _stream = connect_agent(&socket);

    let output = avault()
        .arg("agent")
        .arg("--socket")
        .arg(&socket)
        .env("AVAULT_HOME", tmp.path().join("vault-second"))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already in use"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_closes_idle_partial_frame_and_accepts_next_client() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let mut partial = connect_agent(&socket);
    partial.write_all(&10u32.to_be_bytes()).unwrap();
    drop(partial);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut stream = connect_agent(&socket);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            agent_request(&mut stream, json!({"type": "pubkey"}))
        })) {
            Ok(response) => {
                assert_eq!(response["ok"], true);
                break;
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(200)),
            Err(_) => panic!("agent did not accept a new client after partial frame timeout"),
        }
    }

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_unlocks_passphrase_store_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let vault_home = tmp.path().join("vault");
    let mut agent =
        spawn_passphrase_agent(&socket, 60, b"correct horse battery staple", &vault_home);
    let mut stream = connect_agent(&socket);

    let response = agent_request(&mut stream, json!({"type": "pubkey"}));
    assert_eq!(response["ok"], true);
    assert!(response["result"]["public_key"].as_str().unwrap().len() > 40);
    assert!(vault_home.join("machine.passphrase.json").exists());
    assert!(!vault_home.join("machine.key").exists());

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_expires_grants_by_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let mut stream = connect_agent(&socket);
    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let dek = [0x52u8; 32];
    let approval_nonce = b"agent-ttl-test01";
    let approval_expires_at = future_expiry();
    let grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "ttl-test",
            "ttl_secs": 1,
            "deks": [
                {
                    "name": "API_TOKEN",
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_deliver("session", "ttl-test", "API_TOKEN", approval_nonce, approval_expires_at)
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(grant["ok"], true);
    thread::sleep(Duration::from_millis(1200));

    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"expired");
    let denied = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "ttl-test",
            "mode": "inject",
            "path": tmp.path().join("expired.env"),
            "format": "dotenv",
            "secrets": [
                {"name": "API_TOKEN", "key": "API_TOKEN", "envelope": envelope}
            ]
        }),
    );
    assert_eq!(denied["ok"], false);
    assert!(denied["error"].as_str().unwrap().contains("grant"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_purges_grants_while_deliver_run_child_is_running() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let mut stream = connect_agent(&socket);
    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let dek = [0x56u8; 32];
    let approval_nonce = b"agent-run-purge1";
    let approval_expires_at = future_expiry();
    let grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "run-purge",
            "ttl_secs": 1,
            "deks": [
                {
                    "name": "API_TOKEN",
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_deliver("session", "run-purge", "API_TOKEN", approval_nonce, approval_expires_at)
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(grant["ok"], true);

    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"running");
    let delivered = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "run-purge",
            "mode": "run",
            "command": ["/bin/sh", "-c", "sleep 2"],
            "secrets": [
                {"name": "API_TOKEN", "env": "API_TOKEN", "envelope": envelope.clone()}
            ]
        }),
    );
    assert_eq!(delivered["ok"], true);
    assert_eq!(delivered["result"]["exit_code"], 0);

    let denied = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "run-purge",
            "mode": "inject",
            "path": tmp.path().join("purged.env"),
            "format": "dotenv",
            "secrets": [
                {"name": "API_TOKEN", "key": "API_TOKEN", "envelope": envelope}
            ]
        }),
    );
    assert_eq!(denied["ok"], false);
    assert!(denied["error"].as_str().unwrap().contains("grant"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_signs_with_cached_dek_grant() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 60);
    let mut stream = connect_agent(&socket);
    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let vector = p2_vectors();
    let signing = &vector["signing"];
    let private_key = hex::decode(signing["private_key_hex"].as_str().unwrap()).unwrap();
    let dek = [0x53u8; 32];
    let approval_nonce = b"agent-sign-test1";
    let approval_expires_at = future_expiry();
    let grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "sign-test",
            "ttl_secs": 60,
            "deks": [
                {
                    "name": "AGENT_SIGNING_KEY",
                    "purpose": "sign",
                    "scheme": "ecdsa-secp256k1-der",
                    "digest": signing["digest_hex"],
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_sign(
                            "session",
                            "sign-test",
                            "AGENT_SIGNING_KEY",
                            "ecdsa-secp256k1-der",
                            signing["digest_hex"].as_str().unwrap(),
                            approval_nonce,
                            approval_expires_at
                        )
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(grant["ok"], true);
    let key_envelope = envelope_encrypted_with_dek("AGENT_SIGNING_KEY", &dek, &private_key);
    let expected = signing["schemes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scheme| scheme["scheme"] == "ecdsa-secp256k1-der")
        .unwrap();

    let response = agent_request(
        &mut stream,
        json!({
            "type": "sign",
            "scope_type": "session",
            "scope_ref": "sign-test",
            "name": "AGENT_SIGNING_KEY",
            "key_envelope": key_envelope,
            "digest": signing["digest_hex"],
            "scheme": "ecdsa-secp256k1-der"
        }),
    );
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["signature"], expected["signature_hex"]);
    assert_eq!(response["result"]["recovery_id"], serde_json::Value::Null);

    let replayed = agent_request(
        &mut stream,
        json!({
            "type": "sign",
            "scope_type": "session",
            "scope_ref": "sign-test",
            "name": "AGENT_SIGNING_KEY",
            "key_envelope": key_envelope,
            "digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "scheme": "ecdsa-secp256k1-der"
        }),
    );
    assert_eq!(replayed["ok"], false);
    assert!(replayed["error"].as_str().unwrap().contains("grant"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn agent_idle_timeout_clears_grants() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("run").join("avault.sock");
    let mut agent = spawn_agent(&socket, 1);
    let mut stream = connect_agent(&socket);
    let pubkey = agent_request(&mut stream, json!({"type": "pubkey"}));
    let public_key = pubkey["result"]["public_key"].as_str().unwrap();
    let dek = [0x54u8; 32];
    let approval_nonce = b"agent-idle-test1";
    let approval_expires_at = future_expiry();
    let grant = agent_request(
        &mut stream,
        json!({
            "type": "grant",
            "scope_type": "session",
            "scope_ref": "idle-test",
            "ttl_secs": 60,
            "deks": [
                {
                    "name": "API_TOKEN",
                    "dek_blindbox": fixed_blind_box(
                        public_key,
                        &dek,
                        &aad_agent_deliver("session", "idle-test", "API_TOKEN", approval_nonce, approval_expires_at)
                    ),
                    "approval": approval_json(approval_nonce, approval_expires_at)
                }
            ]
        }),
    );
    assert_eq!(grant["ok"], true);
    thread::sleep(Duration::from_millis(1200));

    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"idle-cleared");
    let denied = agent_request(
        &mut stream,
        json!({
            "type": "deliver",
            "scope_type": "session",
            "scope_ref": "idle-test",
            "mode": "inject",
            "path": tmp.path().join("idle.env"),
            "format": "dotenv",
            "secrets": [
                {"name": "API_TOKEN", "key": "API_TOKEN", "envelope": envelope}
            ]
        }),
    );
    assert_eq!(denied["ok"], false);
    assert!(denied["error"].as_str().unwrap().contains("grant"));

    let _ = agent.kill();
    let _ = agent.wait();
}

#[test]
fn seal_creates_missing_relative_avault_home() {
    let workdir = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("RELATIVE_HOME_SECRET")
        .env("AVAULT_HOME", "vault")
        .current_dir(workdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"value").unwrap();
    let output = seal.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(workdir.path().join("vault").join("machine.key").exists());
}

#[test]
fn deliver_run_returns_child_exit_code() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
fn deliver_run_accepts_multiple_secrets_for_one_child() {
    let home = tempfile::tempdir().unwrap();
    let first = seal_secret(
        home.path().join("vault").as_path(),
        "FIRST_SECRET",
        b"alpha",
    );
    let second = seal_secret(
        home.path().join("vault").as_path(),
        "SECOND_SECRET",
        b"beta",
    );
    let request = json!([
        {"name": "FIRST_SECRET", "env": "FIRST_ENV", "envelope": first},
        {"name": "SECOND_SECRET", "env": "SECOND_ENV", "envelope": second}
    ]);

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$FIRST_ENV" = alpha && test "$SECOND_ENV" = beta && printf ok"#)
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ok");
}

#[test]
fn deliver_run_rejects_empty_secret_list() {
    let home = tempfile::tempdir().unwrap();
    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf should-not-run")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    deliver.stdin.as_mut().unwrap().write_all(b"[]").unwrap();
    let output = deliver.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least one secret"));
}

#[cfg(unix)]
#[test]
fn deliver_run_preserves_signal_exit_code() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "OPENAI_API_KEY",
        b"s3cr3t",
    );
    let request = json!([
        {"name": "OPENAI_API_KEY", "env": "SECRET_VALUE", "envelope": sealed}
    ]);

    let mut deliver = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("kill -TERM $$")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    deliver
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let status = deliver.wait().unwrap();
    assert_eq!(status.code(), Some(143));
}

#[test]
fn envelope_file_preserves_child_stdin() {
    let home = tempfile::tempdir().unwrap();
    let input_file = home.path().join("child-input.txt");
    let envelope_file = home.path().join("envelope.json");
    fs::write(&input_file, b"child-stdin").unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    let seal_output = seal.wait_with_output().unwrap();
    assert!(seal_output.status.success());
    fs::write(&envelope_file, &seal_output.stdout).unwrap();

    let output = avault()
        .arg("deliver")
        .arg("run")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .arg("--env")
        .arg("SECRET_VALUE")
        .arg("--envelope-file")
        .arg(&envelope_file)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"read line; test "$SECRET_VALUE" = "s3cr3t" && printf "$line""#)
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(fs::File::open(&input_file).unwrap())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"child-stdin");
}

#[test]
fn child_exit_2_is_distinct_from_avault_internal_failure() {
    let home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
fn deliver_fetch_injects_bearer_to_loopback_and_returns_response_json() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token-123\n",
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.starts_with("GET /resource HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer token-123"));
        stream
            .write_all(
                b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\naccepted",
            )
            .unwrap();
    });
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/resource", addr.port()),
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "bearer"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], 201);
    assert_eq!(response["body"], "accepted");
}

#[test]
fn deliver_fetch_redacts_verbatim_echoed_credential() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token-echo\n",
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).unwrap();
        let body = b"prefix token-echo suffix token-echo";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/resource", addr.port()),
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "bearer"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["body"],
        "prefix [avault-redacted] suffix [avault-redacted]"
    );
}

#[test]
fn deliver_fetch_redacts_verbatim_echoed_credential_header() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token-header\n",
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nX-Echo: token-header\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/resource", addr.port()),
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "bearer"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(response["headers"]
        .as_object()
        .unwrap()
        .values()
        .any(|value| value == "[avault-redacted]"));
    assert_eq!(response["body"], "ok");
}

#[test]
fn protected_deliver_fetch_redacts_echoed_credential_header() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let dek = [0x7du8; 32];
    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"protected-token\n");
    let pubkey_output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(pubkey_output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&pubkey_output.stdout).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let request_spec = json!({
        "method": "GET",
        "url": format!("http://127.0.0.1:{}/resource", addr.port()),
        "allowed_hosts": ["127.0.0.1"],
        "inject": {"type": "bearer"}
    });
    let approval_nonce = b"fetch-header-red";
    let approval_expires_at = future_expiry();
    let dek_blindbox = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        &dek,
        &aad_deliver(
            "API_TOKEN",
            approval_nonce,
            approval_expires_at,
            &fetch_operation_hash(&request_spec),
        ),
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.contains("Authorization: Bearer protected-token"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nX-Echo: protected-token\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let request = json!({
        "name": "API_TOKEN",
        "envelope": envelope,
        "dek_blindbox": dek_blindbox,
        "approval": approval_json(approval_nonce, approval_expires_at),
        "request": request_spec
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(response["headers"]
        .as_object()
        .unwrap()
        .values()
        .any(|value| value == "[avault-redacted]"));
    assert_eq!(response["body"], "ok");
}

#[test]
fn protected_deliver_inject_uses_operation_bound_dek_blindbox() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(&home.path().join("vault"));
    let output_path = home.path().join("protected.env");
    let dek = [0x7eu8; 32];
    let envelope = envelope_encrypted_with_dek("API_TOKEN", &dek, b"protected-inject");
    let pubkey_output = avault()
        .arg("pubkey")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(pubkey_output.status.success());
    let pubkey: serde_json::Value = serde_json::from_slice(&pubkey_output.stdout).unwrap();
    let approval_nonce = b"inject-protected";
    let approval_expires_at = future_expiry();
    let dek_blindbox = fixed_blind_box(
        pubkey["public_key"].as_str().unwrap(),
        &dek,
        &aad_deliver(
            "API_TOKEN",
            approval_nonce,
            approval_expires_at,
            &inject_operation_hash("API_TOKEN", "dotenv", &output_path),
        ),
    );
    let request = json!({
        "path": output_path,
        "format": "dotenv",
        "secrets": [
            {
                "name": "API_TOKEN",
                "key": "API_TOKEN",
                "envelope": envelope,
                "dek_blindbox": dek_blindbox,
                "approval": approval_json(approval_nonce, approval_expires_at)
            }
        ]
    });

    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = inject.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(&output_path).unwrap(),
        "API_TOKEN='protected-inject'\n"
    );
}

#[test]
fn deliver_fetch_rejects_plaintext_non_loopback_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "http://example.com/resource",
            "allowed_hosts": ["example.com"]
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&output.stderr).contains("plaintext HTTP"));
}

#[test]
fn deliver_fetch_requires_allowed_hosts_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://api.example.com/resource"
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("allowed_hosts is required"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_unapproved_host_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://evil.example.com/resource",
            "allowed_hosts": ["api.example.com"]
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("host is not allowed"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_injected_header_conflict_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://api.example.com/resource",
            "allowed_hosts": ["API.EXAMPLE.COM"],
            "headers": {"authorization": "Bearer placeholder"},
            "inject": {"type": "bearer"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already contains injected header"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_invalid_injected_header_name_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://api.example.com/resource",
            "allowed_hosts": ["api.example.com"],
            "inject": {"type": "header", "name": "X Api Key"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid fetch header name"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_empty_injected_header_name_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://api.example.com/resource",
            "allowed_hosts": ["api.example.com"],
            "inject": {"type": "header", "name": ""}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid fetch header name"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_injected_query_conflict_before_opening() {
    let home = tempfile::tempdir().unwrap();
    let request = json!({
        "name": "API_TOKEN",
        "envelope": {
            "ciphertext": "not-base64",
            "nonce": "not-base64",
            "wrap_meta": "{}"
        },
        "request": {
            "method": "GET",
            "url": "https://api.example.com/resource?api_key=placeholder",
            "allowed_hosts": ["api.example.com"],
            "inject": {"type": "query", "name": "api_key"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already contains injected query parameter"));
    assert!(!stderr.contains("open failed"));
}

#[test]
fn deliver_fetch_rejects_invalid_header_credential_before_request() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token\tbad",
    );
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": "http://127.0.0.1:9/resource",
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "header", "name": "X-Api-Key"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid HTTP header byte"));
    assert!(!stderr.contains("HTTP transport failed"));
    assert!(!stderr.contains("token"));
}

#[test]
fn deliver_fetch_rejects_non_ascii_header_credential_before_request() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        "tokén".as_bytes(),
    );
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": "http://127.0.0.1:9/resource",
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "header", "name": "X-Api-Key"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-ASCII byte"));
    assert!(!stderr.contains("HTTP transport failed"));
    assert!(!stderr.contains("tok"));
}

#[test]
fn deliver_fetch_sanitizes_transport_errors_after_query_injection() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token-123",
    );
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/resource", port),
            "allowed_hosts": ["127.0.0.1"],
            "inject": {"type": "query", "name": "api_key"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP transport failed"));
    assert!(!stderr.contains("token-123"));
    assert!(!stderr.contains("api_key"));
    assert!(!stderr.contains("127.0.0.1"));
    assert!(!stderr.contains("/resource"));
}

#[test]
fn deliver_fetch_rejects_oversized_response_body() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(
        home.path().join("vault").as_path(),
        "API_TOKEN",
        b"token-123",
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).unwrap();
        let body_len = 8 * 1024 * 1024 + 1;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n"
        )
        .unwrap();
        stream.write_all(&vec![b'a'; body_len]).unwrap();
    });
    let request = json!({
        "name": "API_TOKEN",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/large", addr.port()),
            "allowed_hosts": ["127.0.0.1"]
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(70));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("response body exceeds size limit"));
    assert!(!stderr.contains("token-123"));
}

#[test]
fn deliver_inject_writes_dotenv_and_json_as_0600() {
    let home = tempfile::tempdir().unwrap();
    let alpha = seal_secret(home.path().join("vault").as_path(), "A_KEY", b"alpha-1");
    let beta = seal_secret(home.path().join("vault").as_path(), "B_KEY", b"beta-2");
    let inject_dir = home.path().join("inject");
    let dotenv_path = inject_dir.join("secrets.env");
    let json_path = inject_dir.join("secrets.json");

    let dotenv = json!({
        "path": dotenv_path,
        "format": "dotenv",
        "secrets": [
            {"name": "A_KEY", "key": "A_KEY", "envelope": alpha.clone()},
            {"name": "B_KEY", "key": "B_KEY", "envelope": beta.clone()}
        ]
    });
    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(dotenv.to_string().as_bytes())
        .unwrap();
    let output = inject.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"{\"ok\":true}\n");
    assert_eq!(
        fs::metadata(&dotenv_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(&dotenv_path).unwrap(),
        "A_KEY='alpha-1'\nB_KEY='beta-2'\n"
    );

    let json_request = json!({
        "path": json_path,
        "format": "json",
        "secrets": [
            {"name": "A_KEY", "key": "A_KEY", "envelope": alpha},
            {"name": "B_KEY", "key": "B_KEY", "envelope": beta}
        ]
    });
    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(json_request.to_string().as_bytes())
        .unwrap();
    assert!(inject.wait().unwrap().success());
    assert_eq!(
        fs::metadata(&json_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(parsed, json!({"A_KEY": "alpha-1", "B_KEY": "beta-2"}));
}

#[test]
fn deliver_inject_writes_into_existing_project_directory() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(home.path().join("vault").as_path(), "A_KEY", b"alpha-1");
    let project_dir = home.path().join("project");
    fs::create_dir(&project_dir).unwrap();
    fs::set_permissions(&project_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let inject_path = project_dir.join("secrets.env");
    let request = json!({
        "path": inject_path,
        "format": "dotenv",
        "secrets": [
            {"name": "A_KEY", "key": "A_KEY", "envelope": sealed}
        ]
    });

    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = inject.wait_with_output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        fs::metadata(&project_dir).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&inject_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn deliver_inject_preserves_relative_output_path() {
    let home = tempfile::tempdir().unwrap();
    let workdir = tempfile::tempdir().unwrap();
    let sealed = seal_secret(home.path().join("vault").as_path(), "A_KEY", b"alpha-1");
    let request = json!({
        "path": "secrets.env",
        "format": "dotenv",
        "secrets": [
            {"name": "A_KEY", "key": "A_KEY", "envelope": sealed}
        ]
    });

    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .current_dir(workdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = inject.wait_with_output().unwrap();
    let inject_path = workdir.path().join("secrets.env");

    assert!(output.status.success());
    assert_eq!(
        fs::metadata(&inject_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(inject_path).unwrap(),
        "A_KEY='alpha-1'\n"
    );
}

#[test]
fn p0_no_aad_blob_opens_via_new_delivery_paths() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(home.path().join("vault").as_path());
    let sealed = p0_no_aad_envelope();

    let run_request = json!([
        {"name": "OPENAI_API_KEY", "env": "SECRET_VALUE", "envelope": sealed.clone()}
    ]);
    let mut run = avault()
        .arg("deliver")
        .arg("run")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(r#"test "$SECRET_VALUE" = "p0-python-value""#)
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    run.stdin
        .as_mut()
        .unwrap()
        .write_all(run_request.to_string().as_bytes())
        .unwrap();
    assert!(run.wait().unwrap().success());

    let inject_path = home.path().join("inject").join("p0.env");
    let inject_request = json!({
        "path": inject_path,
        "format": "dotenv",
        "secrets": [
            {"name": "OPENAI_API_KEY", "key": "OPENAI_API_KEY", "envelope": sealed.clone()}
        ]
    });
    let mut inject = avault()
        .arg("deliver")
        .arg("inject")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    inject
        .stdin
        .as_mut()
        .unwrap()
        .write_all(inject_request.to_string().as_bytes())
        .unwrap();
    assert!(inject.wait().unwrap().success());
    assert_eq!(
        fs::read_to_string(&inject_path).unwrap(),
        "OPENAI_API_KEY='p0-python-value'\n"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.contains("Authorization: Bearer p0-python-value"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
    });
    let fetch_request = json!({
        "name": "OPENAI_API_KEY",
        "envelope": sealed,
        "request": {
            "method": "GET",
            "url": format!("http://127.0.0.1:{}/p0", addr.port()),
            "allowed_hosts": ["127.0.0.1"]
        }
    });
    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    fetch
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fetch_request.to_string().as_bytes())
        .unwrap();
    let output = fetch.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["body"], "ok");
}

#[test]
fn key_export_and_import_interoperate_between_stores() {
    let source_home = tempfile::tempdir().unwrap();
    let target_home = tempfile::tempdir().unwrap();

    let mut seal = avault()
        .arg("seal")
        .arg("--name")
        .arg("OPENAI_API_KEY")
        .env("AVAULT_HOME", source_home.path().join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    seal.stdin.as_mut().unwrap().write_all(b"s3cr3t").unwrap();
    assert!(seal.wait().unwrap().success());

    let source_key = fs::read(source_home.path().join("vault").join("machine.key")).unwrap();

    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", source_home.path().join("vault"))
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
        .env("AVAULT_HOME", target_home.path().join("vault"))
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
        fs::read(target_home.path().join("vault").join("machine.key")).unwrap(),
        source_key
    );
}

#[test]
fn key_export_requires_existing_master_key() {
    let home = tempfile::tempdir().unwrap();
    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", home.path().join("vault"))
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
    assert!(!home.path().join("vault").join("machine.key").exists());
}

#[test]
fn key_import_rejects_malformed_json() {
    let home = tempfile::tempdir().unwrap();
    let mut import = avault()
        .arg("key")
        .arg("import")
        .env("AVAULT_HOME", home.path().join("vault"))
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    import
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"passphrase":"secret","#)
        .unwrap();
    let output = import.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    assert!(!home.path().join("vault").join("machine.key").exists());
}

#[test]
fn refuses_group_or_world_accessible_key_file() {
    let home = tempfile::tempdir().unwrap();
    let vault_home = home.path().join("vault");
    fs::create_dir_all(&vault_home).unwrap();
    fs::set_permissions(&vault_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(vault_home.join("machine.key"), [1u8; 32]).unwrap();
    fs::set_permissions(
        vault_home.join("machine.key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let mut export = avault()
        .arg("key")
        .arg("export")
        .env("AVAULT_HOME", &vault_home)
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
    let mode = fs::metadata(vault_home.join("machine.key"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
        .arg(home.path().join("vault").join("machine.key"))
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
        .arg(home.path().join("vault").join("machine.key"))
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
        .env("AVAULT_HOME", home.path().join("vault"))
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
