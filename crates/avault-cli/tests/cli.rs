use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread;

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
fn deliver_run_accepts_multiple_secrets_for_one_child() {
    let home = tempfile::tempdir().unwrap();
    let first = seal_secret(home.path(), "FIRST_SECRET", b"alpha");
    let second = seal_secret(home.path(), "SECOND_SECRET", b"beta");
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
        .env("AVAULT_HOME", home.path())
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

#[cfg(unix)]
#[test]
fn deliver_run_preserves_signal_exit_code() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(home.path(), "OPENAI_API_KEY", b"s3cr3t");
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
        .env("AVAULT_HOME", home.path())
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
        .env("AVAULT_HOME", home.path())
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
        .env("AVAULT_HOME", home.path())
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
fn deliver_fetch_injects_bearer_to_loopback_and_returns_response_json() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(home.path(), "API_TOKEN", b"token-123");
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
            "inject": {"type": "bearer"}
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path())
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
            "url": "http://example.com/resource"
        }
    });

    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path())
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
fn deliver_export_emits_shell_export_lines() {
    let home = tempfile::tempdir().unwrap();
    let sealed = seal_secret(home.path(), "OPENAI_API_KEY", b"sk-with space&special");
    let request = json!([
        {"name": "OPENAI_API_KEY", "export": "API_KEY", "envelope": sealed}
    ]);

    let mut export = avault()
        .arg("deliver")
        .arg("export")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    export
        .stdin
        .as_mut()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = export.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "export API_KEY='sk-with space&special'\n"
    );
}

#[test]
fn deliver_inject_writes_dotenv_and_json_as_0600() {
    let home = tempfile::tempdir().unwrap();
    let alpha = seal_secret(home.path(), "A_KEY", b"alpha-1");
    let beta = seal_secret(home.path(), "B_KEY", b"beta-2");
    let dotenv_path = home.path().join("secrets.env");
    let json_path = home.path().join("secrets.json");

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
        .env("AVAULT_HOME", home.path())
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
        .env("AVAULT_HOME", home.path())
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
fn p0_no_aad_blob_opens_via_new_delivery_paths() {
    let home = tempfile::tempdir().unwrap();
    write_p0_master(home.path());
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
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    run.stdin
        .as_mut()
        .unwrap()
        .write_all(run_request.to_string().as_bytes())
        .unwrap();
    assert!(run.wait().unwrap().success());

    let export_request = json!([
        {"name": "OPENAI_API_KEY", "export": "OPENAI_API_KEY", "envelope": sealed.clone()}
    ]);
    let mut export = avault()
        .arg("deliver")
        .arg("export")
        .env("AVAULT_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    export
        .stdin
        .as_mut()
        .unwrap()
        .write_all(export_request.to_string().as_bytes())
        .unwrap();
    let output = export.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "export OPENAI_API_KEY='p0-python-value'\n"
    );

    let inject_path = home.path().join("p0.env");
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
        .env("AVAULT_HOME", home.path())
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
            "url": format!("http://127.0.0.1:{}/p0", addr.port())
        }
    });
    let mut fetch = avault()
        .arg("deliver")
        .arg("fetch")
        .env("AVAULT_HOME", home.path())
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
fn key_import_rejects_malformed_json() {
    let home = tempfile::tempdir().unwrap();
    let mut import = avault()
        .arg("key")
        .arg("import")
        .env("AVAULT_HOME", home.path())
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
