//! `avault` — the binary. Avibe's only path to key material.
//!
//! P1 is a one-shot CLI: control via argv/JSON, bulk blobs via stdin, results via stdout.
//! P2 keeps `pubkey`, `sign`, and `agent` as stubs.

use anyhow::{bail, Context};
use avault_core::{ExportBlob, Sealed};
use avault_store::{Backend, FileStore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

const MAX_STDIN_SECRET_BYTES: usize = 1024 * 1024;
const MAX_STDIN_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const STDIN_READ_CHUNK_BYTES: usize = 8192;

const USAGE: &str = "\
avault — Avibe Vaults custody core

USAGE:
    avault seal --name NAME
    avault deliver run --name NAME --env VAR [--envelope-file PATH] -- COMMAND [ARGS...]
    avault deliver run -- COMMAND [ARGS...] < run-secrets.json
    avault deliver fetch < fetch-request.json
    avault deliver export < export-secrets.json
    avault deliver inject < inject-request.json
    avault key export
    avault key import [--force]
    avault version

P1 reads secret values, envelopes, and passphrases from stdin. Plaintext never belongs in argv.
P2 stubs: pubkey, sign, agent.
";

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("avault: {err:#}");
            ExitCode::from(70)
        }
    }
}

fn run(args: Vec<OsString>) -> anyhow::Result<u8> {
    avault_store::harden_process_memory();

    let Some(cmd) = args.first().and_then(|s| s.to_str()) else {
        print!("{USAGE}");
        return Ok(0);
    };

    match cmd {
        "version" | "--version" | "-V" => {
            println!("avault {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        "seal" => seal_cmd(&args[1..]),
        "deliver" => deliver_cmd(&args[1..]),
        "key" => key_cmd(&args[1..]),
        "pubkey" | "sign" | "agent" => {
            eprintln!("avault: '{cmd}' is a P2 stub and is not implemented in P1");
            Ok(70)
        }
        other => {
            eprintln!("avault: unknown command '{other}'\n");
            print!("{USAGE}");
            Ok(64)
        }
    }
}

fn seal_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let name = parse_required_option(args, "--name")?;
    let mut value = read_stdin_zeroizing().context("failed to read plaintext value from stdin")?;
    let master = avault_store::load_or_create_master_key(Backend::File)?;
    let sealed =
        avault_core::seal(master.as_bytes(), &name, value.as_slice()).context("seal failed")?;
    drop(master);
    value.zeroize();
    serde_json::to_writer(io::stdout(), &sealed).context("failed to write envelope JSON")?;
    println!();
    Ok(0)
}

fn deliver_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let Some(subcmd) = args.first().and_then(|s| s.to_str()) else {
        bail!("missing deliver subcommand");
    };
    match subcmd {
        "run" => deliver_run_cmd(&args[1..]),
        "fetch" => deliver_fetch_cmd(&args[1..]),
        "export" => deliver_export_cmd(&args[1..]),
        "inject" => deliver_inject_cmd(&args[1..]),
        other => bail!("unknown deliver subcommand: {other}"),
    }
}

fn deliver_run_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .context("deliver run requires -- before the command")?;
    let options = &args[..split];
    let command = &args[split + 1..];
    if command.is_empty() {
        bail!("deliver run requires a command");
    }

    if options.is_empty() {
        let input = read_json_stdin("failed to read deliver run JSON from stdin")?;
        let secrets: Vec<EnvSecretInput> =
            serde_json::from_slice(input.as_slice()).context("deliver run JSON is invalid")?;
        run_child_with_secret_env(command, secrets, true)
    } else {
        let run_options = parse_deliver_run_options(options)?;
        let envelope_stdin = run_options.envelope_file.is_none();
        let envelope = read_envelope(run_options.envelope_file.as_deref())?;
        let sealed: Sealed =
            serde_json::from_slice(envelope.as_slice()).context("envelope JSON is invalid")?;
        let secrets = vec![EnvSecretInput {
            name: run_options.name,
            env: run_options.env_name,
            envelope: sealed,
        }];
        run_child_with_secret_env(command, secrets, envelope_stdin)
    }
}

#[derive(Debug, Deserialize)]
struct EnvSecretInput {
    name: String,
    env: String,
    envelope: Sealed,
}

#[derive(Debug, Deserialize)]
struct NamedSecretInput {
    name: String,
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    export: Option<String>,
    #[serde(default)]
    key: Option<String>,
    envelope: Sealed,
}

#[derive(Debug, Deserialize)]
struct FetchInput {
    name: String,
    envelope: Sealed,
    request: FetchRequest,
}

#[derive(Debug, Deserialize)]
struct FetchRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default = "default_fetch_inject")]
    inject: FetchInject,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FetchInject {
    Bearer,
    Header { name: String },
    Query { name: String },
}

#[derive(Debug, Serialize)]
struct FetchOutput {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Debug, Deserialize)]
struct InjectInput {
    path: PathBuf,
    #[serde(default = "default_inject_format")]
    format: String,
    secrets: Vec<NamedSecretInput>,
}

struct OpenedSecret {
    name: String,
    plaintext: Zeroizing<Vec<u8>>,
}

fn default_fetch_inject() -> FetchInject {
    FetchInject::Bearer
}

fn default_inject_format() -> String {
    "dotenv".to_string()
}

fn run_child_with_secret_env(
    command: &[OsString],
    secrets: Vec<EnvSecretInput>,
    envelope_stdin: bool,
) -> anyhow::Result<u8> {
    if secrets.is_empty() {
        bail!("deliver run requires at least one secret");
    }

    let mut opened = open_env_secrets(secrets)?;
    let mut child = {
        let mut child = Command::new(&command[0]);
        child.args(&command[1..]);
        for secret in &opened {
            let env_value = std::str::from_utf8(secret.plaintext.as_slice())
                .context("secret value is not valid UTF-8 for env delivery")?;
            // Accepted standard-tier residual: `Command::env` copies this value into std's
            // process builder and then into the child's environment. Rust does not expose that
            // buffer for zeroizing; avault wipes its owned buffers immediately after spawn.
            child.env(&secret.name, env_value);
        }
        if envelope_stdin {
            child.stdin(Stdio::null());
        } else {
            child.stdin(Stdio::inherit());
        }
        child
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to run child command")?
    };
    opened.zeroize();
    drop(opened);

    let status = child.wait().context("failed to wait for child command")?;
    Ok(status_to_exit_code(status))
}

fn open_env_secrets(secrets: Vec<EnvSecretInput>) -> anyhow::Result<Vec<OpenedSecret>> {
    let master = avault_store::load_master_key(Backend::File)?;
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    for secret in secrets {
        validate_shell_name(&secret.env, "env var name")?;
        if !seen.insert(secret.env.clone()) {
            bail!("duplicate env var name");
        }
        let plaintext = avault_core::open(master.as_bytes(), &secret.name, &secret.envelope)
            .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: secret.env,
            plaintext,
        });
    }
    drop(master);
    Ok(opened)
}

impl Zeroize for OpenedSecret {
    fn zeroize(&mut self) {
        self.plaintext.zeroize();
    }
}

fn deliver_fetch_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("deliver fetch reads its JSON request from stdin and takes no options");
    }

    let input = read_json_stdin("failed to read deliver fetch JSON from stdin")?;
    let fetch: FetchInput =
        serde_json::from_slice(input.as_slice()).context("deliver fetch JSON is invalid")?;
    let url = Url::parse(&fetch.request.url).context("fetch url is invalid")?;
    let is_loopback = is_loopback_url(&url);
    validate_fetch_url(&url)?;
    validate_fetch_method(&fetch.request.method)?;
    for (name, value) in &fetch.request.headers {
        validate_header(name, value)?;
    }
    if let FetchInject::Header { name } = &fetch.request.inject {
        validate_header_name(name)?;
    }
    if let FetchInject::Query { name } = &fetch.request.inject {
        validate_query_name(name)?;
    }

    let master = avault_store::load_master_key(Backend::File)?;
    let mut secret = avault_core::open(master.as_bytes(), &fetch.name, &fetch.envelope)
        .context("open failed")?;
    drop(master);

    let mut secret_header: Option<(String, Zeroizing<String>)> = None;
    let mut target_url = Zeroizing::new(fetch.request.url.clone());
    match &fetch.request.inject {
        FetchInject::Bearer => {
            let secret_text = secret_utf8(secret.as_slice(), "fetch bearer credential")?;
            let mut bearer =
                Zeroizing::new(String::with_capacity("Bearer ".len() + secret_text.len()));
            bearer.push_str("Bearer ");
            bearer.push_str(secret_text);
            secret_header = Some(("Authorization".to_string(), bearer));
        }
        FetchInject::Header { name } => {
            let secret_text = secret_utf8(secret.as_slice(), "fetch header credential")?;
            secret_header = Some((name.clone(), Zeroizing::new(secret_text.to_string())));
        }
        FetchInject::Query { name } => {
            let secret_text = secret_utf8(secret.as_slice(), "fetch query credential")?;
            target_url = build_secret_query_url(&fetch.request.url, name, secret_text)?;
        }
    }
    secret.zeroize();
    drop(secret);

    let output = perform_fetch(
        &fetch.request.method,
        &mut target_url,
        &fetch.request.headers,
        secret_header,
        fetch.request.body,
        is_loopback,
    )
    .context("fetch request failed")?;
    let exit_code = if (200..=299).contains(&output.status) {
        0
    } else {
        1
    };
    serde_json::to_writer(io::stdout(), &output).context("failed to write fetch response JSON")?;
    println!();
    Ok(exit_code)
}

fn perform_fetch(
    method: &str,
    url: &mut Zeroizing<String>,
    headers: &BTreeMap<String, String>,
    mut secret_header: Option<(String, Zeroizing<String>)>,
    body: Option<String>,
    is_loopback: bool,
) -> anyhow::Result<FetchOutput> {
    let method = method.to_ascii_uppercase();
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .try_proxy_from_env(!is_loopback)
        .build();
    let mut request = agent.request(&method, url.as_str());
    for (name, value) in headers {
        request = request.set(name, value);
    }
    if let Some((name, value)) = secret_header.as_mut() {
        // Accepted egress residual: ureq owns an internal header copy until the
        // request is sent. avault wipes its owned copy immediately after building it.
        request = request.set(name, value.as_str());
        value.zeroize();
    }
    // For query-param injection, the request builder owns the egress URL copy now.
    url.zeroize();

    let response = match body {
        Some(body) => request.send_string(&body),
        None => request.call(),
    };
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => return Err(err).context("HTTP transport failed"),
    };

    let status = response.status();
    let mut response_headers = BTreeMap::new();
    for name in response.headers_names() {
        if let Some(value) = response.header(&name) {
            response_headers.insert(name, value.to_string());
        }
    }
    let body = response
        .into_string()
        .context("failed to read response body as UTF-8")?;
    Ok(FetchOutput {
        status,
        headers: response_headers,
        body,
    })
}

fn deliver_export_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("deliver export reads its JSON array from stdin and takes no options");
    }

    let input = read_json_stdin("failed to read deliver export JSON from stdin")?;
    let secrets: Vec<NamedSecretInput> =
        serde_json::from_slice(input.as_slice()).context("deliver export JSON is invalid")?;
    if secrets.is_empty() {
        bail!("deliver export requires at least one secret");
    }

    let mut opened = open_named_secrets(secrets, DeliveryTarget::Export)?;
    let mut out = Zeroizing::new(Vec::new());
    for secret in &opened {
        validate_shell_name(&secret.name, "export name")?;
        let value = secret_utf8(secret.plaintext.as_slice(), "export value")?;
        write!(out, "export {}=", secret.name).context("failed to render export line")?;
        write_shell_quoted(&mut out, value).context("failed to render export line")?;
        out.push(b'\n');
    }
    opened.zeroize();
    drop(opened);

    io::stdout()
        .write_all(out.as_slice())
        .context("failed to write export lines")?;
    io::stdout()
        .flush()
        .context("failed to flush export lines")?;
    out.zeroize();
    Ok(0)
}

fn deliver_inject_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("deliver inject reads its JSON request from stdin and takes no options");
    }

    let input = read_json_stdin("failed to read deliver inject JSON from stdin")?;
    let inject: InjectInput =
        serde_json::from_slice(input.as_slice()).context("deliver inject JSON is invalid")?;
    if inject.secrets.is_empty() {
        bail!("deliver inject requires at least one secret");
    }
    let format = inject.format.to_ascii_lowercase();
    if format != "dotenv" && format != "json" {
        bail!("deliver inject format is not implemented in P1.1");
    }

    let mut opened = open_named_secrets(inject.secrets, DeliveryTarget::Inject)?;
    let mut rendered = render_inject_file(&opened, &format)?;
    opened.zeroize();
    drop(opened);

    atomic_write_0600(&inject.path, rendered.as_slice()).context("failed to write inject file")?;
    rendered.zeroize();
    println!(r#"{{"ok":true}}"#);
    Ok(0)
}

enum DeliveryTarget {
    Export,
    Inject,
}

fn open_named_secrets(
    secrets: Vec<NamedSecretInput>,
    target: DeliveryTarget,
) -> anyhow::Result<Vec<OpenedSecret>> {
    let master = avault_store::load_master_key(Backend::File)?;
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    for secret in secrets {
        let target_name = match target {
            DeliveryTarget::Export => secret
                .export
                .or(secret.env)
                .unwrap_or_else(|| secret.name.clone()),
            DeliveryTarget::Inject => secret
                .key
                .or(secret.env)
                .unwrap_or_else(|| secret.name.clone()),
        };
        validate_shell_name(&target_name, "secret target name")?;
        if !seen.insert(target_name.clone()) {
            bail!("duplicate secret target name");
        }
        let plaintext = avault_core::open(master.as_bytes(), &secret.name, &secret.envelope)
            .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: target_name,
            plaintext,
        });
    }
    drop(master);
    Ok(opened)
}

fn render_inject_file(
    secrets: &[OpenedSecret],
    format: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match format {
        "dotenv" => render_dotenv(secrets),
        "json" => render_json(secrets),
        _ => bail!("deliver inject format is not implemented in P1.1"),
    }
}

fn render_dotenv(secrets: &[OpenedSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    for secret in secrets {
        let value = secret_utf8(secret.plaintext.as_slice(), "dotenv value")?;
        write!(out, "{}=", secret.name).context("failed to render dotenv")?;
        write_shell_quoted(&mut out, value).context("failed to render dotenv")?;
        out.push(b'\n');
    }
    Ok(out)
}

fn render_json(secrets: &[OpenedSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(b"{\n");
    for (index, secret) in secrets.iter().enumerate() {
        let value = secret_utf8(secret.plaintext.as_slice(), "json value")?;
        out.extend_from_slice(b"  ");
        serde_json::to_writer(&mut *out, &secret.name)?;
        out.extend_from_slice(b": ");
        write_json_string(&mut out, value)?;
        if index + 1 != secrets.len() {
            out.push(b',');
        }
        out.push(b'\n');
    }
    out.push(b'}');
    out.push(b'\n');
    Ok(out)
}

fn atomic_write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = writable_parent(path);
    fs::create_dir_all(parent).context("failed to create inject output directory")?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".avault-inject.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .context("failed to create temporary inject file")?;
    tmp.as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("failed to set temporary inject file mode")?;
    tmp.as_file_mut()
        .write_all(bytes)
        .context("failed to write temporary inject file")?;
    tmp.as_file_mut()
        .sync_all()
        .context("failed to sync temporary inject file")?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .context("failed to install inject file")?;
    File::open(parent)
        .context("failed to open inject output directory")?
        .sync_all()
        .context("failed to sync inject output directory")?;
    Ok(())
}

fn writable_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn validate_shell_name(name: &str, label: &str) -> anyhow::Result<()> {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_uppercase() || first.is_ascii_lowercase() => {
        }
        _ => bail!("invalid {label}"),
    }
    if !chars.all(|ch| {
        ch == '_' || ch.is_ascii_uppercase() || ch.is_ascii_lowercase() || ch.is_ascii_digit()
    }) {
        bail!("invalid {label}");
    }
    Ok(())
}

fn secret_utf8<'a>(bytes: &'a [u8], label: &str) -> anyhow::Result<&'a str> {
    if bytes.contains(&0) {
        bail!("{label} contains NUL byte");
    }
    std::str::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8"))
}

fn write_shell_quoted(out: &mut Vec<u8>, value: &str) -> anyhow::Result<()> {
    out.push(b'\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            write!(out, "{ch}")?;
        }
    }
    out.push(b'\'');
    Ok(())
}

fn write_json_string(out: &mut Vec<u8>, value: &str) -> anyhow::Result<()> {
    serde_json::to_writer(out, value).context("failed to render JSON string")
}

fn build_secret_query_url(url: &str, name: &str, value: &str) -> anyhow::Result<Zeroizing<String>> {
    let _ = Url::parse(url).context("fetch url is invalid")?;
    let fragment_start = url.find('#').unwrap_or(url.len());
    let (base, fragment) = url.split_at(fragment_start);
    let separator = if base.contains('?') { '&' } else { '?' };
    let mut out = Zeroizing::new(String::with_capacity(
        url.len() + 1 + name.len() + 1 + value.len(),
    ));
    out.push_str(base);
    out.push(separator);
    push_query_encoded(&mut out, name);
    out.push('=');
    push_query_encoded(&mut out, value);
    out.push_str(fragment);
    Ok(out)
}

fn push_query_encoded(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push(HEX[(other >> 4) as usize] as char);
                out.push(HEX[(other & 0x0f) as usize] as char);
            }
        }
    }
}

fn validate_fetch_method(method: &str) -> anyhow::Result<()> {
    let method = method.to_ascii_uppercase();
    if method.is_empty() || method.bytes().any(|byte| !byte.is_ascii_alphabetic()) {
        bail!("invalid fetch method");
    }
    if matches!(method.as_str(), "TRACE" | "TRACK" | "CONNECT") {
        bail!("fetch method is not allowed");
    }
    Ok(())
}

fn validate_fetch_url(url: &Url) -> anyhow::Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(url) => Ok(()),
        "http" => bail!("refusing to attach a credential over plaintext HTTP"),
        _ => bail!("fetch URL scheme must be https, or http for loopback"),
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn validate_header(name: &str, value: &str) -> anyhow::Result<()> {
    validate_header_name(name)?;
    if value.contains('\r') || value.contains('\n') {
        bail!("invalid fetch header value");
    }
    Ok(())
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty()
        || name.contains('\r')
        || name.contains('\n')
        || name.contains(':')
        || name.eq_ignore_ascii_case("host")
    {
        bail!("invalid fetch header name");
    }
    Ok(())
}

fn validate_query_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.contains('\r') || name.contains('\n') {
        bail!("invalid fetch query parameter name");
    }
    Ok(())
}

fn status_to_exit_code(status: ExitStatus) -> u8 {
    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        return (128 + signal).try_into().unwrap_or(1);
    }

    status
        .code()
        .and_then(|code| code.try_into().ok())
        .unwrap_or(1)
}

fn key_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let Some(subcmd) = args.first().and_then(|s| s.to_str()) else {
        bail!("missing key subcommand");
    };
    match subcmd {
        "export" => key_export_cmd(),
        "import" => key_import_cmd(&args[1..]),
        other => bail!("unknown key subcommand: {other}"),
    }
}

fn key_export_cmd() -> anyhow::Result<u8> {
    let mut passphrase = read_stdin_zeroizing().context("failed to read passphrase from stdin")?;
    trim_trailing_newlines(passphrase.as_mut());
    let master = avault_store::load_master_key(Backend::File)?;
    let blob = avault_core::export_master_key(master.as_bytes(), passphrase.as_slice())
        .context("key export failed")?;
    drop(master);
    passphrase.zeroize();
    serde_json::to_writer(io::stdout(), &blob).context("failed to write key export JSON")?;
    println!();
    Ok(0)
}

fn key_import_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let force = parse_flag(args, "--force")?;
    let mut input = read_stdin_zeroizing().context("failed to read key import JSON from stdin")?;
    let mut passphrase =
        import_passphrase_from_json(input.as_slice()).context("key import JSON is invalid")?;
    let blob = import_blob_from_json(input.as_slice()).context("key import JSON is invalid")?;
    input.zeroize();

    trim_trailing_newlines(passphrase.as_mut());
    let key = avault_core::import_master_key(&blob, passphrase.as_slice())
        .context("key import failed")?;
    passphrase.zeroize();

    FileStore::new(avault_store::default_master_key_path()?)
        .import(&key, force)
        .context("failed to store imported master key")?;
    drop(key);
    println!(r#"{{"ok":true}}"#);
    Ok(0)
}

fn import_blob_from_json(input: &[u8]) -> anyhow::Result<ExportBlob> {
    let value_start = find_json_field_value(input, b"blob")?;
    let value_end = json_value_end(input, value_start)?;
    serde_json::from_slice(&input[value_start..value_end]).context("key import blob is invalid")
}

fn import_passphrase_from_json(input: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let passphrase_start = find_json_field_value(input, b"passphrase")?;
    if input.get(passphrase_start) != Some(&b'"') {
        bail!("key import passphrase must be a string");
    }
    decode_json_string_bytes(&input[passphrase_start..])
}

fn find_json_field_value(input: &[u8], field: &[u8]) -> anyhow::Result<usize> {
    let mut index = skip_json_ws(input, 0);
    if input.get(index) != Some(&b'{') {
        bail!("key import JSON must be an object");
    }
    index += 1;

    loop {
        index = skip_json_ws(input, index);
        if input.get(index) == Some(&b'}') {
            bail!("key import JSON missing required field");
        }
        if input.get(index) != Some(&b'"') {
            bail!("key import JSON object key expected");
        }

        let key_start = index;
        let key = decode_json_string_bytes(&input[key_start..])?;
        let after_key = json_string_end(&input[key_start..])? + key_start;
        index = after_key;

        let colon = skip_json_ws(input, index);
        if input.get(colon) != Some(&b':') {
            bail!("key import JSON is invalid");
        }
        let value = skip_json_ws(input, colon + 1);
        if key.as_slice() == field {
            return Ok(value);
        }

        index = skip_json_ws(input, json_value_end(input, value)?);
        match input.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => bail!("key import JSON missing required field"),
            _ => bail!("key import JSON is invalid"),
        }
    }
}

fn decode_json_string_bytes(input: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if input.first() != Some(&b'"') {
        bail!("JSON string expected");
    }

    let mut out = Zeroizing::new(Vec::with_capacity(input.len().min(MAX_STDIN_SECRET_BYTES)));
    let mut index = 1;
    while index < input.len() {
        match input[index] {
            b'"' => return Ok(out),
            b'\\' => {
                index += 1;
                let escaped = *input.get(index).context("unterminated JSON escape")?;
                match escaped {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let (scalar, consumed) = decode_json_unicode_escape(input, index + 1)?;
                        let mut utf8 = [0u8; 4];
                        out.extend_from_slice(scalar.encode_utf8(&mut utf8).as_bytes());
                        index += consumed;
                    }
                    _ => bail!("invalid JSON escape"),
                }
            }
            byte if byte < 0x20 => bail!("invalid control byte in JSON string"),
            byte => out.push(byte),
        }
        if out.len() > MAX_STDIN_SECRET_BYTES {
            bail!("stdin secret input exceeds the supported size limit");
        }
        index += 1;
    }
    bail!("unterminated JSON string");
}

fn decode_json_unicode_escape(input: &[u8], start: usize) -> anyhow::Result<(char, usize)> {
    let first = decode_hex_quad(input, start)?;
    if (0xD800..=0xDBFF).contains(&first) {
        if input.get(start + 4) != Some(&b'\\') || input.get(start + 5) != Some(&b'u') {
            bail!("invalid JSON surrogate pair");
        }
        let second = decode_hex_quad(input, start + 6)?;
        if !(0xDC00..=0xDFFF).contains(&second) {
            bail!("invalid JSON surrogate pair");
        }
        let codepoint = 0x10000 + (((first - 0xD800) as u32) << 10) + (second - 0xDC00) as u32;
        Ok((
            char::from_u32(codepoint).context("invalid JSON unicode escape")?,
            10,
        ))
    } else if (0xDC00..=0xDFFF).contains(&first) {
        bail!("invalid JSON surrogate pair");
    } else {
        Ok((
            char::from_u32(first as u32).context("invalid JSON unicode escape")?,
            4,
        ))
    }
}

fn decode_hex_quad(input: &[u8], start: usize) -> anyhow::Result<u16> {
    let bytes = input
        .get(start..start + 4)
        .context("short JSON unicode escape")?;
    let mut value = 0u16;
    for byte in bytes {
        value = (value << 4) | u16::from(hex_value(*byte)?);
    }
    Ok(value)
}

fn hex_value(byte: u8) -> anyhow::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid JSON unicode escape"),
    }
}

fn json_string_end(input: &[u8]) -> anyhow::Result<usize> {
    if input.first() != Some(&b'"') {
        bail!("JSON string expected");
    }
    let mut index = 1;
    while index < input.len() {
        match input[index] {
            b'"' => return Ok(index + 1),
            b'\\' => {
                index += 1;
                if input.get(index).is_none() {
                    bail!("unterminated JSON escape");
                }
            }
            byte if byte < 0x20 => bail!("invalid control byte in JSON string"),
            _ => {}
        }
        index += 1;
    }
    bail!("unterminated JSON string");
}

fn json_value_end(input: &[u8], start: usize) -> anyhow::Result<usize> {
    match input.get(start).copied().context("missing JSON value")? {
        b'"' => Ok(start + json_string_end(&input[start..])?),
        b'{' | b'[' => json_compound_end(input, start),
        b'-' | b'0'..=b'9' => Ok(json_scalar_end(input, start)),
        b't' if input.get(start..start + 4) == Some(b"true") => Ok(start + 4),
        b'f' if input.get(start..start + 5) == Some(b"false") => Ok(start + 5),
        b'n' if input.get(start..start + 4) == Some(b"null") => Ok(start + 4),
        _ => bail!("invalid JSON value"),
    }
}

fn json_compound_end(input: &[u8], start: usize) -> anyhow::Result<usize> {
    let mut stack = vec![input[start]];
    let mut index = start + 1;
    while index < input.len() {
        match input[index] {
            b'"' => index += json_string_end(&input[index..])?,
            b'{' | b'[' => {
                stack.push(input[index]);
                index += 1;
            }
            b'}' => {
                if stack.pop() != Some(b'{') {
                    bail!("invalid JSON object");
                }
                index += 1;
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            b']' => {
                if stack.pop() != Some(b'[') {
                    bail!("invalid JSON array");
                }
                index += 1;
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => index += 1,
        }
    }
    bail!("unterminated JSON value");
}

fn json_scalar_end(input: &[u8], mut index: usize) -> usize {
    while matches!(
        input.get(index),
        Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
    ) {
        index += 1;
    }
    index
}

fn skip_json_ws(input: &[u8], mut index: usize) -> usize {
    while matches!(input.get(index), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        index += 1;
    }
    index
}

fn parse_required_option(args: &[OsString], flag: &str) -> anyhow::Result<String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            let value = args
                .get(index + 1)
                .and_then(|s| s.to_str())
                .with_context(|| format!("{flag} requires a value"))?;
            return Ok(value.to_string());
        }
        index += 1;
    }
    bail!("{flag} is required");
}

struct DeliverRunOptions {
    name: String,
    env_name: String,
    envelope_file: Option<String>,
}

fn parse_deliver_run_options(args: &[OsString]) -> anyhow::Result<DeliverRunOptions> {
    let mut name = None;
    let mut env_name = None;
    let mut envelope_file = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index]
            .to_str()
            .context("deliver run options must be valid UTF-8")?;
        let target = match flag {
            "--name" => &mut name,
            "--env" => &mut env_name,
            "--envelope-file" => &mut envelope_file,
            other => bail!("unknown deliver run option: {other}"),
        };
        if target.is_some() {
            bail!("{flag} was provided more than once");
        }
        let value = args
            .get(index + 1)
            .and_then(|s| s.to_str())
            .with_context(|| format!("{flag} requires a value"))?;
        *target = Some(value.to_string());
        index += 2;
    }

    Ok(DeliverRunOptions {
        name: name.context("--name is required")?,
        env_name: env_name.context("--env is required")?,
        envelope_file,
    })
}

fn parse_flag(args: &[OsString], flag: &str) -> anyhow::Result<bool> {
    let mut seen = false;
    for arg in args {
        if arg == flag {
            seen = true;
        } else {
            bail!("unknown option for key import");
        }
    }
    Ok(seen)
}

fn read_stdin_zeroizing() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_zeroizing_to_cap(io::stdin(), MAX_STDIN_SECRET_BYTES)
}

fn read_json_stdin(context: &'static str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_zeroizing_to_cap(io::stdin(), MAX_STDIN_ENVELOPE_BYTES).context(context)
}

fn read_zeroizing_to_cap(
    mut reader: impl Read,
    max_len: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(max_len));
    let mut scratch = Zeroizing::new([0u8; STDIN_READ_CHUNK_BYTES]);

    while out.len() < max_len {
        let remaining = max_len - out.len();
        let read_len = remaining.min(scratch.len());
        let n = reader.read(&mut scratch[..read_len])?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&scratch[..n]);
        scratch[..n].zeroize();
    }

    let mut extra = Zeroizing::new([0u8; 1]);
    match reader.read(extra.as_mut())? {
        0 => Ok(out),
        _ => bail!("stdin secret input exceeds the supported size limit"),
    }
}

fn read_envelope(path: Option<&str>) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match path {
        Some(path) => fs::read(path)
            .map(Zeroizing::new)
            .context("failed to read envelope file"),
        None => read_zeroizing_to_cap(io::stdin(), MAX_STDIN_ENVELOPE_BYTES)
            .context("failed to read envelope JSON from stdin"),
    }
}

fn trim_trailing_newlines(buf: &mut Vec<u8>) {
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_reader_accepts_exact_cap() {
        let input = vec![7u8; 16];
        let out = read_zeroizing_to_cap(input.as_slice(), 16).unwrap();

        assert_eq!(out.as_slice(), input.as_slice());
        assert!(out.capacity() >= 16);
    }

    #[test]
    fn stdin_reader_rejects_past_cap() {
        let input = vec![7u8; 17];

        assert!(read_zeroizing_to_cap(input.as_slice(), 16).is_err());
    }

    #[test]
    fn import_passphrase_decodes_json_escapes_without_root_value() {
        let input = br#"{"blob":{"passphrase":"not-this"},"passphrase":"line\n\uD83D\uDD11"}"#;
        let passphrase = import_passphrase_from_json(input).unwrap();

        assert_eq!(passphrase.as_slice(), "line\n🔑".as_bytes());
    }

    #[test]
    fn import_blob_ignores_nested_passphrase_fields() {
        let input = br#"{
            "passphrase":"secret",
            "blob":{
                "scheme":"machine-key-export-v1",
                "kdf":"scrypt",
                "n":32768,
                "r":8,
                "p":1,
                "salt":"c2FsdHlzYWx0eXNhbHQh",
                "nonce":"KCkqKywtLi8wMTIz",
                "ciphertext":"tPZK1A2HjfEGQHGTIaLP0fexWVdzlWPip9Ze0b909RrXyIjE/1sj0YZFTYnOxflB",
                "passphrase":"not-this"
            }
        }"#;
        let blob = import_blob_from_json(input).unwrap();

        assert_eq!(blob.scheme, "machine-key-export-v1");
    }
}
