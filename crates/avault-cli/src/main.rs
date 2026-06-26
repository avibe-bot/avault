//! `avault` — the binary. Avibe's only path to key material.
//!
//! One-shot CLI: control via argv/JSON, bulk blobs via stdin, results via stdout.

use anyhow::{anyhow, bail, Context};
#[cfg(unix)]
use avault_core::open_blind_box_with_seed;
use avault_core::{
    BlindBox, BlindBoxContext, ExportBlob, LocalSignerProvider, Sealed, SignatureScheme,
    SignerProvider,
};
use avault_store::{Backend, FileStore, MasterKey, PassphraseFileStore};
#[cfg(unix)]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(unix)]
use base64::Engine;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::str::FromStr;
use std::time::Duration;
#[cfg(unix)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

const MAX_STDIN_SECRET_BYTES: usize = 1024 * 1024;
const MAX_STDIN_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDIN_PASSPHRASE_BYTES: usize = 64 * 1024;
const STDIN_READ_CHUNK_BYTES: usize = 8192;
#[cfg(unix)]
const MAX_AGENT_FRAME_BYTES: usize = 2 * 1024 * 1024;
#[cfg(unix)]
const MAX_AGENT_RUN_SECRETS: usize = 1024;
#[cfg(unix)]
const MAX_AGENT_RUN_ENV_NAME_BYTES: usize = 4096;
#[cfg(unix)]
const AGENT_RUN_HELPER_MAGIC: &[u8] = b"avault-agent-run-env-v1\0";
const FETCH_CONNECT_TIMEOUT_SECS: u64 = 10;
const FETCH_TOTAL_TIMEOUT_SECS: u64 = 30;
const MAX_FETCH_BODY_BYTES: usize = 8 * 1024 * 1024;
#[cfg(unix)]
const DEFAULT_AGENT_GRANT_TTL_SECS: u64 = 300;
#[cfg(unix)]
const MAX_AGENT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
#[cfg(unix)]
const DEFAULT_AGENT_IDLE_TIMEOUT_SECS: u64 = 300;
#[cfg(unix)]
const AGENT_POLL_INTERVAL: Duration = Duration::from_millis(200);
#[cfg(unix)]
const MAX_AGENT_READ_TIMEOUTS: u8 = 30;
#[cfg(unix)]
const MIN_APPROVAL_NONCE_BYTES: usize = 16;
#[cfg(unix)]
const MAX_APPROVAL_NONCE_BYTES: usize = 128;
const FETCH_REDACTION: &str = "[avault-redacted]";

const USAGE: &str = "\
avault — Avibe Vaults custody core

USAGE:
    avault [--store file|file-passphrase] COMMAND ...
    avault seal --name NAME
    avault seal --name NAME --blind-box
    avault deliver run --name NAME --env VAR [--envelope-file PATH] -- COMMAND [ARGS...]
    avault deliver run -- COMMAND [ARGS...] < run-secrets.json
    avault deliver fetch < fetch-request.json
    avault deliver inject < inject-request.json
    avault key export
    avault key import [--force]
    avault pubkey
    avault sign < sign-request.json
    avault agent [--store file|file-passphrase] [--unlock] [--socket PATH] [--idle-timeout-secs SECS]
    avault version

P1 reads secret values, envelopes, and passphrases from stdin. Plaintext never belongs in argv.
deliver fetch requires request.allowed_hosts before attaching a credential.
file-passphrase is opt-in. Its unlock passphrase is read from the first stdin line.
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
    let (config, args) = parse_global_options(args)?;
    let mut stdin = io::stdin();

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
        "seal" => seal_cmd(&args[1..], &config, &mut stdin),
        "deliver" => deliver_cmd(&args[1..], &config, &mut stdin),
        "key" => key_cmd(&args[1..], &config, &mut stdin),
        "pubkey" => pubkey_cmd(&args[1..], &config, &mut stdin),
        "sign" => sign_cmd(&args[1..], &config, &mut stdin),
        "agent" => agent_cmd(&args[1..], &config, &mut stdin),
        #[cfg(unix)]
        "__agent-run-helper" => agent_run_helper_cmd(&args[1..], &mut stdin),
        other => {
            eprintln!("avault: unknown command '{other}'\n");
            print!("{USAGE}");
            Ok(64)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliConfig {
    store: StoreSelection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreSelection {
    File,
    FilePassphrase,
}

impl StoreSelection {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "file-passphrase" | "file+passphrase" | "passphrase" => Ok(Self::FilePassphrase),
            _ => bail!("unknown store backend"),
        }
    }
}

enum StoreUnlock {
    File,
    FilePassphrase(Zeroizing<Vec<u8>>),
}

fn parse_global_options(args: Vec<OsString>) -> anyhow::Result<(CliConfig, Vec<OsString>)> {
    let mut store = match env::var("AVAULT_STORE") {
        Ok(value) => StoreSelection::parse(&value)?,
        Err(env::VarError::NotPresent) => StoreSelection::File,
        Err(env::VarError::NotUnicode(_)) => bail!("AVAULT_STORE must be valid UTF-8"),
    };
    let mut index = 0;
    while index < args.len() {
        let Some(flag) = args[index].to_str() else {
            break;
        };
        match flag {
            "--store" => {
                let value = args
                    .get(index + 1)
                    .and_then(|s| s.to_str())
                    .context("--store requires a value")?;
                store = StoreSelection::parse(value)?;
                index += 2;
            }
            _ => break,
        }
    }
    Ok((CliConfig { store }, args[index..].to_vec()))
}

fn read_store_unlock(config: &CliConfig, input: &mut impl Read) -> anyhow::Result<StoreUnlock> {
    match config.store {
        StoreSelection::File => Ok(StoreUnlock::File),
        StoreSelection::FilePassphrase => Ok(StoreUnlock::FilePassphrase(
            read_passphrase_line(input).context("failed to read store passphrase from stdin")?,
        )),
    }
}

fn load_existing_master_from_unlock(unlock: &StoreUnlock) -> anyhow::Result<MasterKey> {
    match unlock {
        StoreUnlock::File => avault_store::load_master_key(Backend::File),
        StoreUnlock::FilePassphrase(passphrase) => {
            avault_store::load_passphrase_master_key(passphrase.as_slice())
                .context("failed to unlock passphrase master key")
        }
    }
}

fn load_or_create_master_from_unlock(unlock: &StoreUnlock) -> anyhow::Result<MasterKey> {
    match unlock {
        StoreUnlock::File => avault_store::load_or_create_master_key(Backend::File),
        StoreUnlock::FilePassphrase(passphrase) => {
            avault_store::load_or_create_passphrase_master_key(passphrase.as_slice())
                .context("failed to unlock passphrase master key")
        }
    }
}

fn import_master_with_unlock(
    unlock: &StoreUnlock,
    key: &[u8; avault_store::MASTER_KEY_BYTES],
    force: bool,
) -> anyhow::Result<()> {
    match unlock {
        StoreUnlock::File => FileStore::new(avault_store::default_master_key_path()?)
            .import(key, force)
            .context("failed to store imported master key"),
        StoreUnlock::FilePassphrase(passphrase) => {
            PassphraseFileStore::new(avault_store::default_passphrase_master_key_path()?)
                .import(key, passphrase.as_slice(), force)
                .context("failed to store imported passphrase master key")
        }
    }
}

fn seal_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    let options = parse_seal_options(args)?;
    let unlock = read_store_unlock(config, input)?;
    let (sealed, mut value) = if options.blind_box {
        let input = read_json_input(input, "failed to read blind-box JSON from stdin")?;
        let blind_box: BlindBox =
            serde_json::from_slice(input.as_slice()).context("blind-box JSON is invalid")?;
        let master = load_existing_master_from_unlock(&unlock)?;
        let keypair = avault_core::derive_blind_box_keypair_from_master(master.as_bytes());
        let value = keypair
            .open(&blind_box, &BlindBoxContext::seal(&options.name))
            .context("blind-box open failed")?;
        drop(keypair);
        let sealed = avault_core::seal(master.as_bytes(), &options.name, value.as_slice())
            .context("seal failed")?;
        drop(master);
        (sealed, value)
    } else {
        let value = read_stdin_zeroizing_from(input)
            .context("failed to read plaintext value from stdin")?;
        let master = load_or_create_master_from_unlock(&unlock)?;
        let sealed = avault_core::seal(master.as_bytes(), &options.name, value.as_slice())
            .context("seal failed")?;
        drop(master);
        (sealed, value)
    };
    value.zeroize();
    drop(unlock);
    serde_json::to_writer(io::stdout(), &sealed).context("failed to write envelope JSON")?;
    println!();
    Ok(0)
}

#[derive(Debug)]
struct SealOptions {
    name: String,
    blind_box: bool,
}

fn parse_seal_options(args: &[OsString]) -> anyhow::Result<SealOptions> {
    let mut name = None;
    let mut blind_box = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index]
            .to_str()
            .context("seal options must be valid UTF-8")?;
        match flag {
            "--name" => {
                if name.is_some() {
                    bail!("--name was provided more than once");
                }
                let value = args
                    .get(index + 1)
                    .and_then(|s| s.to_str())
                    .context("--name requires a value")?;
                name = Some(value.to_string());
                index += 2;
            }
            "--blind-box" => {
                if blind_box {
                    bail!("--blind-box was provided more than once");
                }
                blind_box = true;
                index += 1;
            }
            other => bail!("unknown seal option: {other}"),
        }
    }
    Ok(SealOptions {
        name: name.context("--name is required")?,
        blind_box,
    })
}

#[derive(Debug, Serialize)]
struct PubkeyOutput {
    public_key: String,
    fingerprint: String,
}

fn pubkey_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("pubkey takes no options");
    }
    let unlock = read_store_unlock(config, input)?;
    let master = load_or_create_master_from_unlock(&unlock)?;
    let keypair = avault_core::derive_blind_box_keypair_from_master(master.as_bytes());
    let output = PubkeyOutput {
        public_key: keypair.public_key_b64(),
        fingerprint: keypair.fingerprint_hex(),
    };
    drop(keypair);
    drop(master);
    drop(unlock);
    serde_json::to_writer(io::stdout(), &output).context("failed to write pubkey JSON")?;
    println!();
    Ok(0)
}

#[derive(Debug, Deserialize)]
struct SignInput {
    name: String,
    key_envelope: Sealed,
    digest: String,
    scheme: String,
    #[serde(default)]
    dek_blindbox: Option<BlindBox>,
    #[serde(default)]
    approval: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SignOutput {
    signature: String,
    recovery_id: Option<u8>,
}

fn sign_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("sign reads its JSON request from stdin and takes no options");
    }
    let unlock = read_store_unlock(config, input)?;
    let input = read_json_input(input, "failed to read sign JSON from stdin")?;
    let request: SignInput =
        serde_json::from_slice(input.as_slice()).context("sign JSON is invalid")?;
    let digest = decode_hex_32(&request.digest, "digest")?;
    let scheme = SignatureScheme::from_str(&request.scheme)?;

    reject_one_shot_protected_fields(request.dek_blindbox.as_ref(), request.approval.as_ref())?;
    let master = load_existing_master_from_unlock(&unlock)?;
    let key_plaintext = avault_core::open(master.as_bytes(), &request.name, &request.key_envelope)
        .context("key envelope open failed")?;
    drop(master);
    drop(unlock);
    let output = sign_digest_with_key(scheme, &digest, key_plaintext)?;
    serde_json::to_writer(io::stdout(), &output).context("failed to write signature JSON")?;
    println!();
    Ok(0)
}

fn sign_digest_with_key(
    scheme: SignatureScheme,
    digest: &[u8; 32],
    key_plaintext: Zeroizing<Vec<u8>>,
) -> anyhow::Result<SignOutput> {
    let mut private_key = zeroizing_vec_to_key32(key_plaintext, "signing key")?;
    let signer = LocalSignerProvider;
    let result = signer
        .sign_digest(scheme, &private_key, digest)
        .context("signing failed")?;
    private_key.zeroize();
    drop(private_key);
    Ok(SignOutput {
        signature: hex::encode(result.signature),
        recovery_id: result.recovery_id,
    })
}

fn decode_hex_32(text: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    if text.len() != 64 {
        bail!("{label} must be 32 bytes of hex");
    }
    let bytes = hex::decode(text).with_context(|| format!("{label} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes of hex"))
}

fn zeroizing_vec_to_key32(
    mut value: Zeroizing<Vec<u8>>,
    label: &str,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if value.len() != 32 {
        value.zeroize();
        bail!("{label} has invalid length");
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.as_mut().copy_from_slice(value.as_slice());
    value.zeroize();
    Ok(out)
}

#[cfg(unix)]
fn parse_approval_context(input: &ApprovalContextInput) -> anyhow::Result<ApprovalContext> {
    let nonce = B64
        .decode(input.nonce.as_bytes())
        .context("approval nonce is not valid base64")?;
    if nonce.len() < MIN_APPROVAL_NONCE_BYTES || nonce.len() > MAX_APPROVAL_NONCE_BYTES {
        bail!("approval nonce has invalid length");
    }
    Ok(ApprovalContext {
        nonce,
        expires_at_unix: input.expires_at_unix,
    })
}

#[cfg(unix)]
fn approval_expiry_instant(expires_at_unix: u64) -> anyhow::Result<Instant> {
    let now_unix = current_unix_secs()?;
    if expires_at_unix <= now_unix {
        bail!("approval is expired");
    }
    Instant::now()
        .checked_add(Duration::from_secs(expires_at_unix - now_unix))
        .context("approval expiration is invalid")
}

#[cfg(unix)]
fn validate_approval_not_expired(expires_at_unix: u64) -> anyhow::Result<()> {
    let now = current_unix_secs()?;
    if expires_at_unix <= now {
        bail!("approval is expired");
    }
    Ok(())
}

#[cfg(unix)]
fn current_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(unix)]
fn agent_deliver_operation_hash(name: &str, ttl_secs: u64) -> [u8; 32] {
    let ttl_secs = ttl_secs.to_be_bytes();
    BlindBoxContext::operation_hash(&[b"agent-deliver", name.as_bytes(), ttl_secs.as_slice()])
}

#[cfg(unix)]
fn agent_sign_operation_hash(scheme: &str, digest: &[u8; 32], ttl_secs: u64) -> [u8; 32] {
    let ttl_secs = ttl_secs.to_be_bytes();
    BlindBoxContext::operation_hash(&[
        b"agent-sign",
        scheme.as_bytes(),
        digest.as_slice(),
        ttl_secs.as_slice(),
    ])
}

fn deliver_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    let Some(subcmd) = args.first().and_then(|s| s.to_str()) else {
        bail!("missing deliver subcommand");
    };
    match subcmd {
        "run" => deliver_run_cmd(&args[1..], config, input),
        "fetch" => deliver_fetch_cmd(&args[1..], config, input),
        "inject" => deliver_inject_cmd(&args[1..], config, input),
        other => bail!("unknown deliver subcommand: {other}"),
    }
}

fn deliver_run_cmd(
    args: &[OsString],
    config: &CliConfig,
    input: &mut impl Read,
) -> anyhow::Result<u8> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .context("deliver run requires -- before the command")?;
    let options = &args[..split];
    let command = &args[split + 1..];
    if command.is_empty() {
        bail!("deliver run requires a command");
    }
    let unlock = read_store_unlock(config, input)?;

    if options.is_empty() {
        let input = read_json_input(input, "failed to read deliver run JSON from stdin")?;
        let secrets: Vec<EnvSecretInput> =
            serde_json::from_slice(input.as_slice()).context("deliver run JSON is invalid")?;
        if secrets.is_empty() {
            bail!("deliver run requires at least one secret");
        }
        let opened = open_env_secrets(secrets, &unlock)?;
        drop(unlock);
        run_child_with_opened_env(command, opened, true)
    } else {
        let run_options = parse_deliver_run_options(options)?;
        let envelope_stdin = run_options.envelope_file.is_none();
        let envelope = read_envelope(run_options.envelope_file.as_deref(), input)?;
        let sealed: Sealed =
            serde_json::from_slice(envelope.as_slice()).context("envelope JSON is invalid")?;
        let secrets = vec![EnvSecretInput {
            name: run_options.name,
            env: run_options.env_name,
            envelope: sealed,
            dek_blindbox: None,
            approval: None,
        }];
        let opened = open_env_secrets(secrets, &unlock)?;
        drop(unlock);
        run_child_with_opened_env(command, opened, envelope_stdin)
    }
}

#[derive(Debug, Deserialize)]
struct EnvSecretInput {
    name: String,
    env: String,
    envelope: Sealed,
    #[serde(default)]
    dek_blindbox: Option<BlindBox>,
    #[serde(default)]
    approval: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NamedSecretInput {
    name: String,
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    key: Option<String>,
    envelope: Sealed,
    #[serde(default)]
    dek_blindbox: Option<BlindBox>,
    #[serde(default)]
    approval: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FetchInput {
    name: String,
    envelope: Sealed,
    #[serde(default)]
    dek_blindbox: Option<BlindBox>,
    #[serde(default)]
    approval: Option<serde_json::Value>,
    request: FetchRequest,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct ApprovalContextInput {
    nonce: String,
    expires_at_unix: u64,
}

#[cfg(unix)]
struct ApprovalContext {
    nonce: Vec<u8>,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize)]
struct FetchRequest {
    method: String,
    url: String,
    #[serde(default)]
    allowed_hosts: Vec<String>,
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
#[serde(deny_unknown_fields)]
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

fn run_child_with_opened_env(
    command: &[OsString],
    opened: Vec<OpenedSecret>,
    envelope_stdin: bool,
) -> anyhow::Result<u8> {
    let mut child = spawn_child_with_opened_env(command, opened, envelope_stdin, true)?;
    let status = child.wait().context("failed to wait for child command")?;
    Ok(status_to_exit_code(status))
}

fn spawn_child_with_opened_env(
    command: &[OsString],
    mut opened: Vec<OpenedSecret>,
    envelope_stdin: bool,
    inherit_env: bool,
) -> anyhow::Result<std::process::Child> {
    let child = {
        let mut child = Command::new(&command[0]);
        child.args(&command[1..]);
        if !inherit_env {
            child.env_clear();
        }
        for secret in &opened {
            validate_env_value(secret.plaintext.as_slice())?;
            let env_value = std::str::from_utf8(secret.plaintext.as_slice())
                .context("secret value is not valid UTF-8 for env delivery")?;
            // Accepted one-shot standard-tier residual: `Command::env` copies this value into std's
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
    Ok(child)
}

#[cfg(unix)]
fn run_agent_child_with_opened_env(
    command: &[OsString],
    opened: Vec<OpenedSecret>,
    envelope_stdin: bool,
    state: &mut AgentState,
) -> anyhow::Result<u8> {
    let mut child = spawn_agent_run_helper(command, opened, envelope_stdin)?;
    loop {
        state.purge();
        if let Some(status) = child
            .try_wait()
            .context("failed to wait for child command")?
        {
            return Ok(status_to_exit_code(status));
        }
        std::thread::sleep(AGENT_POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn agent_run_helper_cmd(args: &[OsString], input: &mut impl Read) -> anyhow::Result<u8> {
    let mut index = 0;
    let mut stdin_null = false;
    if args.get(index).and_then(|arg| arg.to_str()) == Some("--stdin-null") {
        stdin_null = true;
        index += 1;
    }
    if args.get(index).and_then(|arg| arg.to_str()) != Some("--") {
        bail!("agent run helper requires -- before command");
    }
    let command = &args[index + 1..];
    if command.is_empty() {
        bail!("agent run helper requires a command");
    }

    let mut opened = read_agent_run_helper_frame(input)?;
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    child.env_clear();
    for secret in &opened {
        let env_value = std::str::from_utf8(secret.plaintext.as_slice())
            .context("secret value is not valid UTF-8 for env delivery")?;
        child.env(&secret.name, env_value);
    }
    if stdin_null {
        child.stdin(Stdio::null());
    } else {
        child.stdin(Stdio::inherit());
    }
    child.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let err = child.exec();
    opened.zeroize();
    drop(opened);
    Err(err).context("failed to exec child command")
}

#[cfg(unix)]
fn spawn_agent_run_helper(
    command: &[OsString],
    mut opened: Vec<OpenedSecret>,
    envelope_stdin: bool,
) -> anyhow::Result<std::process::Child> {
    if !envelope_stdin {
        bail!("agent deliver run requires closed child stdin");
    }
    let exe = env::current_exe().context("failed to locate avault helper")?;
    let mut helper = Command::new(exe);
    helper
        .arg("__agent-run-helper")
        .arg("--stdin-null")
        .arg("--")
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = helper.spawn().context("failed to spawn agent run helper")?;
    let write_result = match child.stdin.as_mut() {
        Some(stdin) => write_agent_run_helper_frame(stdin, &opened),
        None => Err(anyhow!("failed to open agent run helper stdin")),
    };
    opened.zeroize();
    drop(opened);
    drop(child.stdin.take());
    if let Err(err) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err).context("failed to send secrets to agent run helper");
    }
    Ok(child)
}

#[cfg(unix)]
fn write_agent_run_helper_frame(
    writer: &mut impl Write,
    opened: &[OpenedSecret],
) -> anyhow::Result<()> {
    if opened.is_empty() {
        bail!("agent run helper requires at least one secret");
    }
    let count: u32 = opened
        .len()
        .try_into()
        .context("too many secrets for agent run helper")?;
    writer
        .write_all(AGENT_RUN_HELPER_MAGIC)
        .context("failed to write agent run helper frame")?;
    writer
        .write_all(&count.to_be_bytes())
        .context("failed to write agent run helper frame")?;
    for secret in opened {
        validate_shell_name(&secret.name, "env var name")?;
        validate_env_value(secret.plaintext.as_slice())?;
        write_agent_run_helper_bytes(writer, secret.name.as_bytes())?;
        write_agent_run_helper_bytes(writer, secret.plaintext.as_slice())?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_agent_run_helper_bytes(writer: &mut impl Write, bytes: &[u8]) -> anyhow::Result<()> {
    let len: u32 = bytes
        .len()
        .try_into()
        .context("agent run helper field is too large")?;
    writer
        .write_all(&len.to_be_bytes())
        .context("failed to write agent run helper frame")?;
    writer
        .write_all(bytes)
        .context("failed to write agent run helper frame")
}

#[cfg(unix)]
fn read_agent_run_helper_frame(input: &mut impl Read) -> anyhow::Result<Vec<OpenedSecret>> {
    let mut magic = vec![0u8; AGENT_RUN_HELPER_MAGIC.len()];
    input
        .read_exact(&mut magic)
        .context("failed to read agent run helper frame")?;
    if magic != AGENT_RUN_HELPER_MAGIC {
        bail!("agent run helper frame is invalid");
    }
    let count = read_agent_run_helper_u32(input)? as usize;
    if count == 0 || count > MAX_AGENT_RUN_SECRETS {
        bail!("agent run helper secret count is invalid");
    }
    let mut opened = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = read_agent_run_helper_u32(input)? as usize;
        if name_len == 0 || name_len > MAX_AGENT_RUN_ENV_NAME_BYTES {
            bail!("agent run helper env name is invalid");
        }
        let mut name = vec![0u8; name_len];
        input
            .read_exact(&mut name)
            .context("failed to read agent run helper frame")?;
        let name = String::from_utf8(name).context("agent run helper env name is invalid")?;
        validate_shell_name(&name, "env var name")?;

        let value_len = read_agent_run_helper_u32(input)? as usize;
        if value_len > MAX_STDIN_SECRET_BYTES {
            bail!("agent run helper secret value is too large");
        }
        let mut plaintext = Zeroizing::new(vec![0u8; value_len]);
        input
            .read_exact(plaintext.as_mut_slice())
            .context("failed to read agent run helper frame")?;
        validate_env_value(plaintext.as_slice())?;
        opened.push(OpenedSecret { name, plaintext });
    }
    Ok(opened)
}

#[cfg(unix)]
fn read_agent_run_helper_u32(input: &mut impl Read) -> anyhow::Result<u32> {
    let mut buf = [0u8; 4];
    input
        .read_exact(&mut buf)
        .context("failed to read agent run helper frame")?;
    Ok(u32::from_be_bytes(buf))
}

fn validate_env_value(value: &[u8]) -> anyhow::Result<()> {
    std::str::from_utf8(value).context("secret value is not valid UTF-8 for env delivery")?;
    if value.contains(&0) {
        bail!("secret value contains a NUL byte and cannot be delivered as an env var");
    }
    Ok(())
}

fn open_env_secrets(
    secrets: Vec<EnvSecretInput>,
    unlock: &StoreUnlock,
) -> anyhow::Result<Vec<OpenedSecret>> {
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    let master = load_existing_master_from_unlock(unlock)?;
    for secret in secrets {
        validate_shell_name(&secret.env, "env var name")?;
        if !seen.insert(secret.env.clone()) {
            bail!("duplicate env var name");
        }
        let plaintext = open_one_shot_secret(
            &secret.name,
            &secret.envelope,
            secret.dek_blindbox.as_ref(),
            secret.approval.as_ref(),
            unlock,
            Some(&master),
        )
        .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: secret.env,
            plaintext,
        });
    }
    Ok(opened)
}

fn open_one_shot_secret(
    name: &str,
    envelope: &Sealed,
    dek_blindbox: Option<&BlindBox>,
    approval: Option<&serde_json::Value>,
    unlock: &StoreUnlock,
    loaded_master: Option<&MasterKey>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    reject_one_shot_protected_fields(dek_blindbox, approval)?;
    let master;
    let master = match loaded_master {
        Some(master) => master,
        None => {
            master = load_existing_master_from_unlock(unlock)?;
            &master
        }
    };
    let opened =
        avault_core::open(master.as_bytes(), name, envelope).context("envelope open failed")?;
    Ok(opened)
}

fn reject_one_shot_protected_fields(
    dek_blindbox: Option<&BlindBox>,
    approval: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    if dek_blindbox.is_some() || approval.is_some() {
        bail!("protected DEK blind boxes require the resident agent");
    }
    Ok(())
}

impl Zeroize for OpenedSecret {
    fn zeroize(&mut self) {
        self.plaintext.zeroize();
    }
}

fn deliver_fetch_cmd(
    args: &[OsString],
    config: &CliConfig,
    input: &mut impl Read,
) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("deliver fetch reads its JSON request from stdin and takes no options");
    }

    let unlock = read_store_unlock(config, input)?;
    let input = read_json_input(input, "failed to read deliver fetch JSON from stdin")?;
    let fetch: FetchInput =
        serde_json::from_slice(input.as_slice()).context("deliver fetch JSON is invalid")?;
    let (_url, is_loopback) = validate_fetch_input(&fetch)?;

    let mut secret = open_one_shot_secret(
        &fetch.name,
        &fetch.envelope,
        fetch.dek_blindbox.as_ref(),
        fetch.approval.as_ref(),
        &unlock,
        None,
    )
    .context("open failed")?;
    drop(unlock);
    let output = execute_fetch_request(fetch.request, &mut secret, is_loopback)
        .context("fetch request failed")?;
    secret.zeroize();
    drop(secret);

    let exit_code = fetch_output_exit_code(&output);
    serde_json::to_writer(io::stdout(), &output).context("failed to write fetch response JSON")?;
    println!();
    Ok(exit_code)
}

fn validate_fetch_input(fetch: &FetchInput) -> anyhow::Result<(Url, bool)> {
    let url = Url::parse(&fetch.request.url).context("fetch url is invalid")?;
    let is_loopback = is_loopback_url(&url);
    validate_fetch_url(&url)?;
    validate_allowed_fetch_host(&url, &fetch.request.allowed_hosts)?;
    validate_fetch_method(&fetch.request.method)?;
    for (name, value) in &fetch.request.headers {
        validate_header(name, value)?;
    }
    match &fetch.request.inject {
        FetchInject::Bearer => reject_header_conflict(&fetch.request.headers, "Authorization")?,
        FetchInject::Header { name } => {
            validate_header_name(name)?;
            reject_header_conflict(&fetch.request.headers, name)?;
        }
        FetchInject::Query { name } => {
            validate_query_name(name)?;
            reject_query_conflict(&url, name)?;
        }
    }
    Ok((url, is_loopback))
}

fn execute_fetch_request(
    request: FetchRequest,
    secret: &mut Zeroizing<Vec<u8>>,
    is_loopback: bool,
) -> anyhow::Result<FetchOutput> {
    let mut secret_header: Option<(String, Zeroizing<String>)> = None;
    let mut target_url = Zeroizing::new(request.url.clone());
    let mut redaction_needles: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    match &request.inject {
        FetchInject::Bearer => {
            let credential =
                fetch_header_credential_bytes(secret.as_slice(), "fetch bearer credential")?;
            if !credential.is_empty() {
                redaction_needles.push(Zeroizing::new(credential.to_vec()));
            }
            let secret_text = std::str::from_utf8(credential)
                .context("fetch bearer credential is not valid UTF-8")?;
            let mut bearer =
                Zeroizing::new(String::with_capacity("Bearer ".len() + secret_text.len()));
            bearer.push_str("Bearer ");
            bearer.push_str(secret_text);
            secret_header = Some(("Authorization".to_string(), bearer));
        }
        FetchInject::Header { name } => {
            let credential =
                fetch_header_credential_bytes(secret.as_slice(), "fetch header credential")?;
            if !credential.is_empty() {
                redaction_needles.push(Zeroizing::new(credential.to_vec()));
            }
            let secret_text = std::str::from_utf8(credential)
                .context("fetch header credential is not valid UTF-8")?;
            secret_header = Some((name.clone(), Zeroizing::new(secret_text.to_string())));
        }
        FetchInject::Query { name } => {
            let secret_text = secret_utf8(secret.as_slice(), "fetch query credential")?;
            if !secret.is_empty() {
                redaction_needles.push(Zeroizing::new(secret.as_slice().to_vec()));
                let mut encoded =
                    Zeroizing::new(String::with_capacity(encoded_query_len(secret_text)));
                push_query_encoded(&mut encoded, secret_text);
                redaction_needles.push(Zeroizing::new(encoded.as_bytes().to_vec()));
            }
            target_url = build_secret_query_url(&request.url, name, secret_text)?;
        }
    }
    secret.zeroize();

    let output = perform_fetch(
        &request.method,
        &mut target_url,
        &request.headers,
        secret_header,
        request.body,
        is_loopback,
        redaction_needles.as_slice(),
    )
    .context("fetch request failed")?;
    drop(redaction_needles);
    Ok(output)
}

fn fetch_output_exit_code(output: &FetchOutput) -> u8 {
    if (200..=299).contains(&output.status) {
        0
    } else {
        1
    }
}

fn perform_fetch(
    method: &str,
    url: &mut Zeroizing<String>,
    headers: &BTreeMap<String, String>,
    mut secret_header: Option<(String, Zeroizing<String>)>,
    body: Option<String>,
    is_loopback: bool,
    redaction_needles: &[Zeroizing<Vec<u8>>],
) -> anyhow::Result<FetchOutput> {
    let method = method.to_ascii_uppercase();
    let connect_timeout = Duration::from_secs(FETCH_CONNECT_TIMEOUT_SECS);
    let total_timeout = Duration::from_secs(FETCH_TOTAL_TIMEOUT_SECS);
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(connect_timeout)
        .timeout_read(total_timeout)
        .timeout_write(total_timeout)
        .timeout(total_timeout)
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
        Err(ureq::Error::Transport(err)) => {
            let kind = err.kind();
            drop(err);
            return Err(anyhow!("HTTP transport failed: {kind}"));
        }
    };

    let status = response.status();
    let mut response_headers = BTreeMap::new();
    for name in response.headers_names() {
        if let Some(value) = response.header(&name) {
            let name = redact_fetch_header_text(&name, redaction_needles)?;
            let value = redact_fetch_header_text(value, redaction_needles)?;
            response_headers.insert(name, value);
        }
    }
    let body = read_capped_fetch_body(response, redaction_needles)?;
    Ok(FetchOutput {
        status,
        headers: response_headers,
        body,
    })
}

fn read_capped_fetch_body(
    response: ureq::Response,
    redaction_needles: &[Zeroizing<Vec<u8>>],
) -> anyhow::Result<String> {
    let mut reader = response
        .into_reader()
        .take((MAX_FETCH_BODY_BYTES as u64) + 1);
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_FETCH_BODY_BYTES + 1));
    reader
        .read_to_end(&mut body)
        .map_err(|_| anyhow!("failed to read fetch response body"))?;
    if body.len() > MAX_FETCH_BODY_BYTES {
        bail!("fetch response body exceeds size limit");
    }
    redact_fetch_body(&mut body, redaction_needles)?;
    match String::from_utf8(std::mem::take(&mut *body)) {
        Ok(body) => Ok(body),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(anyhow!("fetch response body is not valid UTF-8"))
        }
    }
}

fn redact_fetch_body(
    body: &mut Vec<u8>,
    redaction_needles: &[Zeroizing<Vec<u8>>],
) -> anyhow::Result<()> {
    for needle in redaction_needles {
        redact_verbatim_bytes(body, needle.as_slice())?;
        redact_form_encoded_equivalent_bytes(body, needle.as_slice())?;
    }
    Ok(())
}

fn redact_verbatim_bytes(body: &mut Vec<u8>, needle: &[u8]) -> anyhow::Result<()> {
    const REDACTION: &[u8] = FETCH_REDACTION.as_bytes();
    if needle.is_empty() {
        return Ok(());
    }
    let mut index = 0;
    let mut matches = 0usize;
    while let Some(relative) = find_subslice(&body[index..], needle) {
        matches += 1;
        index += relative + needle.len();
    }
    if matches == 0 {
        return Ok(());
    }
    let output_len = redacted_body_len(body.len(), matches, needle.len(), REDACTION.len())?;
    if output_len > MAX_FETCH_BODY_BYTES {
        bail!("fetch response body exceeds size limit");
    }

    let mut index = 0;
    let mut redacted = Zeroizing::new(Vec::with_capacity(output_len));
    while let Some(relative) = find_subslice(&body[index..], needle) {
        let found = index + relative;
        redacted.extend_from_slice(&body[index..found]);
        redacted.extend_from_slice(REDACTION);
        index = found + needle.len();
    }
    redacted.extend_from_slice(&body[index..]);
    body.zeroize();
    body.clear();
    body.extend_from_slice(&redacted);
    Ok(())
}

fn redact_fetch_header_text(
    value: &str,
    redaction_needles: &[Zeroizing<Vec<u8>>],
) -> anyhow::Result<String> {
    let mut bytes = value.as_bytes().to_vec();
    let original_len = bytes.len();
    for needle in redaction_needles {
        redact_verbatim_bytes(&mut bytes, needle.as_slice())?;
        redact_form_encoded_equivalent_bytes(&mut bytes, needle.as_slice())?;
    }
    if bytes.len() == original_len && bytes.as_slice() == value.as_bytes() {
        return Ok(value.to_string());
    }
    match String::from_utf8(bytes) {
        Ok(value) => Ok(value),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(anyhow!(
                "fetch response header is not valid UTF-8 after redaction"
            ))
        }
    }
}

fn redact_form_encoded_equivalent_bytes(body: &mut Vec<u8>, needle: &[u8]) -> anyhow::Result<()> {
    const REDACTION: &[u8] = FETCH_REDACTION.as_bytes();
    if needle.is_empty() {
        return Ok(());
    }
    let matches = find_form_encoded_equivalent_ranges(body, needle);
    if matches.is_empty() {
        return Ok(());
    }
    let removed: usize = matches.iter().map(|(start, end)| end - start).sum();
    let output_len = body
        .len()
        .checked_sub(removed)
        .and_then(|len| len.checked_add(matches.len() * REDACTION.len()))
        .context("redacted fetch body size overflowed")?;
    if output_len > MAX_FETCH_BODY_BYTES {
        bail!("fetch response body exceeds size limit");
    }

    let mut cursor = 0usize;
    let mut redacted = Zeroizing::new(Vec::with_capacity(output_len));
    for (start, end) in matches {
        redacted.extend_from_slice(&body[cursor..start]);
        redacted.extend_from_slice(REDACTION);
        cursor = end;
    }
    redacted.extend_from_slice(&body[cursor..]);
    body.zeroize();
    body.clear();
    body.extend_from_slice(&redacted);
    Ok(())
}

fn find_form_encoded_equivalent_ranges(body: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut search_start = 0usize;
    while search_start < body.len() {
        let mut body_index = search_start;
        let mut needle_index = 0usize;
        while needle_index < needle.len() && body_index < body.len() {
            let Some((decoded, next_body_index)) = decode_form_encoded_byte(body, body_index)
            else {
                break;
            };
            if decoded != needle[needle_index] {
                break;
            }
            body_index = next_body_index;
            needle_index += 1;
        }
        if needle_index == needle.len() && body_index > search_start {
            ranges.push((search_start, body_index));
            search_start = body_index;
        } else {
            search_start += 1;
        }
    }
    ranges
}

fn decode_form_encoded_byte(input: &[u8], index: usize) -> Option<(u8, usize)> {
    match *input.get(index)? {
        b'+' => Some((b' ', index + 1)),
        b'%' => {
            let high = from_hex(*input.get(index + 1)?)?;
            let low = from_hex(*input.get(index + 2)?)?;
            Some(((high << 4) | low, index + 3))
        }
        byte => Some((byte, index + 1)),
    }
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn redacted_body_len(
    body_len: usize,
    matches: usize,
    needle_len: usize,
    redaction_len: usize,
) -> anyhow::Result<usize> {
    if redaction_len >= needle_len {
        let growth = matches
            .checked_mul(redaction_len - needle_len)
            .context("fetch response body exceeds size limit")?;
        body_len
            .checked_add(growth)
            .context("fetch response body exceeds size limit")
    } else {
        Ok(body_len - matches * (needle_len - redaction_len))
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn deliver_inject_cmd(
    args: &[OsString],
    config: &CliConfig,
    input: &mut impl Read,
) -> anyhow::Result<u8> {
    if !args.is_empty() {
        bail!("deliver inject reads its JSON request from stdin and takes no options");
    }

    let unlock = read_store_unlock(config, input)?;
    let input = read_json_input(input, "failed to read deliver inject JSON from stdin")?;
    let inject: InjectInput =
        serde_json::from_slice(input.as_slice()).context("deliver inject JSON is invalid")?;
    if inject.secrets.is_empty() {
        bail!("deliver inject requires at least one secret");
    }
    let format = inject.format.to_ascii_lowercase();
    if format != "dotenv" && format != "json" {
        bail!("deliver inject format is not implemented in P1.1");
    }

    let mut opened = open_named_secrets(inject.secrets, &unlock)?;
    drop(unlock);
    let mut rendered = render_inject_file(&opened, &format)?;
    opened.zeroize();
    drop(opened);

    avault_store::atomic_write_secret_file(&inject.path, rendered.as_slice())
        .context("failed to write inject file")?;
    rendered.zeroize();
    println!(r#"{{"ok":true}}"#);
    Ok(0)
}

fn open_named_secrets(
    secrets: Vec<NamedSecretInput>,
    unlock: &StoreUnlock,
) -> anyhow::Result<Vec<OpenedSecret>> {
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    let master = load_existing_master_from_unlock(unlock)?;
    for secret in secrets {
        let target_name = secret
            .key
            .or(secret.env)
            .unwrap_or_else(|| secret.name.clone());
        validate_shell_name(&target_name, "secret target name")?;
        if !seen.insert(target_name.clone()) {
            bail!("duplicate secret target name");
        }
        let plaintext = open_one_shot_secret(
            &secret.name,
            &secret.envelope,
            secret.dek_blindbox.as_ref(),
            secret.approval.as_ref(),
            unlock,
            Some(&master),
        )
        .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: target_name,
            plaintext,
        });
    }
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
    let capacity = secrets
        .iter()
        .map(|secret| secret.name.len() + secret.plaintext.len() + 8)
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    for secret in secrets {
        let value = secret_utf8(secret.plaintext.as_slice(), "dotenv value")?;
        write!(out, "{}=", secret.name).context("failed to render dotenv")?;
        write_shell_quoted(&mut out, value).context("failed to render dotenv")?;
        out.push(b'\n');
    }
    Ok(out)
}

fn render_json(secrets: &[OpenedSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let capacity = 4 + secrets
        .iter()
        .map(|secret| secret.name.len() + secret.plaintext.len() + 12)
        .sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
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

fn fetch_header_credential_bytes<'a>(bytes: &'a [u8], label: &str) -> anyhow::Result<&'a [u8]> {
    let trimmed = match bytes.last() {
        Some(b'\r') | Some(b'\n') => &bytes[..bytes.len() - 1],
        _ => bytes,
    };
    if !trimmed.is_ascii() {
        bail!("{label} contains non-ASCII byte");
    }
    if trimmed.iter().any(|byte| is_http_control_byte(*byte)) {
        bail!("{label} contains invalid HTTP header byte");
    }
    Ok(trimmed)
}

fn is_http_control_byte(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
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
        base.len() + 1 + encoded_query_len(name) + 1 + encoded_query_len(value) + fragment.len(),
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

fn encoded_query_len(value: &str) -> usize {
    value
        .as_bytes()
        .iter()
        .map(|byte| match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b' ' => 1,
            _ => 3,
        })
        .sum()
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

fn validate_allowed_fetch_host(url: &Url, allowed_hosts: &[String]) -> anyhow::Result<()> {
    if allowed_hosts.is_empty() {
        bail!("fetch allowed_hosts is required");
    }
    for host in allowed_hosts {
        validate_allowed_host(host)?;
    }
    let Some(host) = fetch_url_host(url) else {
        bail!("fetch url host is required");
    };
    if !allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        bail!("fetch host is not allowed");
    }
    Ok(())
}

fn validate_allowed_host(host: &str) -> anyhow::Result<()> {
    if host.trim().is_empty()
        || host.trim() != host
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('[')
        || host.contains(']')
        || host.contains('\r')
        || host.contains('\n')
        || host.contains('?')
        || host.contains('#')
    {
        bail!("invalid fetch allowed host");
    }
    if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
        bail!("invalid fetch allowed host");
    }
    Ok(())
}

fn fetch_url_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) => Some(host.to_string()),
        Host::Ipv4(addr) => Some(addr.to_string()),
        Host::Ipv6(addr) => Some(addr.to_string()),
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
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        bail!("invalid fetch header value");
    }
    Ok(())
}

fn reject_header_conflict(
    headers: &BTreeMap<String, String>,
    injected_name: &str,
) -> anyhow::Result<()> {
    if headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case(injected_name))
    {
        bail!("fetch request already contains injected header");
    }
    Ok(())
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.eq_ignore_ascii_case("host")
        || name
            .as_bytes()
            .iter()
            .any(|byte| !is_header_token_byte(*byte))
    {
        bail!("invalid fetch header name");
    }
    Ok(())
}

fn is_header_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn validate_query_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.contains('\r') || name.contains('\n') {
        bail!("invalid fetch query parameter name");
    }
    Ok(())
}

fn reject_query_conflict(url: &Url, injected_name: &str) -> anyhow::Result<()> {
    if url
        .query_pairs()
        .any(|(name, _)| name.as_ref() == injected_name)
    {
        bail!("fetch request already contains injected query parameter");
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

fn key_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    let Some(subcmd) = args.first().and_then(|s| s.to_str()) else {
        bail!("missing key subcommand");
    };
    match subcmd {
        "export" => key_export_cmd(config, input),
        "import" => key_import_cmd(&args[1..], config, input),
        other => bail!("unknown key subcommand: {other}"),
    }
}

fn key_export_cmd(config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    let unlock = read_store_unlock(config, input)?;
    let mut passphrase =
        read_stdin_zeroizing_from(input).context("failed to read passphrase from stdin")?;
    trim_trailing_newlines(passphrase.as_mut());
    let master = load_existing_master_from_unlock(&unlock)?;
    let blob = avault_core::export_master_key(master.as_bytes(), passphrase.as_slice())
        .context("key export failed")?;
    drop(master);
    drop(unlock);
    passphrase.zeroize();
    serde_json::to_writer(io::stdout(), &blob).context("failed to write key export JSON")?;
    println!();
    Ok(0)
}

fn key_import_cmd(
    args: &[OsString],
    config: &CliConfig,
    input: &mut impl Read,
) -> anyhow::Result<u8> {
    let force = parse_flag(args, "--force")?;
    let unlock = read_store_unlock(config, input)?;
    let mut input =
        read_stdin_zeroizing_from(input).context("failed to read key import JSON from stdin")?;
    let mut passphrase =
        import_passphrase_from_json(input.as_slice()).context("key import JSON is invalid")?;
    let blob = import_blob_from_json(input.as_slice()).context("key import JSON is invalid")?;
    input.zeroize();

    trim_trailing_newlines(passphrase.as_mut());
    let key = avault_core::import_master_key(&blob, passphrase.as_slice())
        .context("key import failed")?;
    passphrase.zeroize();

    import_master_with_unlock(&unlock, &key, force)?;
    drop(unlock);
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

#[derive(Debug)]
#[cfg(unix)]
struct AgentOptions {
    socket_path: PathBuf,
    idle_timeout: Duration,
    store: StoreSelection,
    unlock: bool,
}

#[cfg(unix)]
fn agent_cmd(args: &[OsString], config: &CliConfig, input: &mut impl Read) -> anyhow::Result<u8> {
    let options = parse_agent_options(args, config)?;
    run_agent(options, input)
}

#[cfg(not(unix))]
fn agent_cmd(
    _args: &[OsString],
    _config: &CliConfig,
    _input: &mut impl Read,
) -> anyhow::Result<u8> {
    bail!("avault agent is only supported on Unix platforms")
}

#[cfg(unix)]
fn parse_agent_options(args: &[OsString], config: &CliConfig) -> anyhow::Result<AgentOptions> {
    let mut socket_path = None;
    let mut idle_timeout_secs = DEFAULT_AGENT_IDLE_TIMEOUT_SECS;
    let mut store = config.store;
    let mut unlock = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index]
            .to_str()
            .context("agent options must be valid UTF-8")?;
        match flag {
            "--socket" => {
                if socket_path.is_some() {
                    bail!("--socket was provided more than once");
                }
                let value = args
                    .get(index + 1)
                    .and_then(|s| s.to_str())
                    .context("--socket requires a value")?;
                socket_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--idle-timeout-secs" => {
                let value = args
                    .get(index + 1)
                    .and_then(|s| s.to_str())
                    .context("--idle-timeout-secs requires a value")?;
                idle_timeout_secs = value
                    .parse::<u64>()
                    .context("--idle-timeout-secs must be an integer")?;
                if idle_timeout_secs == 0 {
                    bail!("--idle-timeout-secs must be positive");
                }
                index += 2;
            }
            "--store" => {
                let value = args
                    .get(index + 1)
                    .and_then(|s| s.to_str())
                    .context("--store requires a value")?;
                store = StoreSelection::parse(value)?;
                index += 2;
            }
            "--unlock" => {
                if unlock {
                    bail!("--unlock was provided more than once");
                }
                unlock = true;
                index += 1;
            }
            other => bail!("unknown agent option: {other}"),
        }
    }
    if unlock && store != StoreSelection::FilePassphrase {
        bail!("--unlock requires --store file-passphrase");
    }

    Ok(AgentOptions {
        socket_path: socket_path.unwrap_or(default_agent_socket_path()?),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
        store,
        unlock,
    })
}

#[cfg(unix)]
fn default_agent_socket_path() -> anyhow::Result<PathBuf> {
    Ok(user_home_dir()?
        .join(".avibe")
        .join("run")
        .join("avault.sock"))
}

#[cfg(unix)]
fn user_home_dir() -> anyhow::Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GrantKey {
    scope_type: String,
    scope_ref: String,
}

#[cfg(unix)]
struct GrantEntry {
    expires_at: Instant,
    deks: HashMap<AgentDekKey, MasterKey>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AgentDekKey {
    purpose: AgentDekPurpose,
    name: String,
    scheme: Option<String>,
    digest_hex: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AgentDekPurpose {
    Deliver,
    Sign,
}

#[cfg(unix)]
impl AgentDekPurpose {
    fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.unwrap_or("deliver") {
            "deliver" => Ok(Self::Deliver),
            "sign" => Ok(Self::Sign),
            _ => bail!("unsupported grant DEK purpose"),
        }
    }
}

#[cfg(unix)]
struct AgentState {
    grants: HashMap<GrantKey, GrantEntry>,
    used_grant_nonces: HashMap<Vec<u8>, Instant>,
    last_activity: Instant,
    idle_timeout: Duration,
    _master: Option<MasterKey>,
}

#[cfg(unix)]
impl AgentState {
    fn new(idle_timeout: Duration, master: Option<MasterKey>) -> Self {
        Self {
            grants: HashMap::new(),
            used_grant_nonces: HashMap::new(),
            last_activity: Instant::now(),
            idle_timeout,
            _master: master,
        }
    }

    fn record_activity(&mut self) {
        self.last_activity = Instant::now();
        self.purge();
    }

    fn purge(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_activity) >= self.idle_timeout {
            self.grants.clear();
        }
        self.grants.retain(|_, grant| grant.expires_at > now);
        self.used_grant_nonces
            .retain(|_, expires_at| *expires_at > now);
    }

    fn purge_before_blocking(&mut self, max_block: Duration) {
        self.purge();
        let now = Instant::now();
        let idle_age = now.duration_since(self.last_activity);
        if idle_age
            .checked_add(max_block)
            .map_or(true, |age| age >= self.idle_timeout)
        {
            self.grants.clear();
        }
    }

    fn get_grant(&mut self, scope: &GrantKey) -> anyhow::Result<&GrantEntry> {
        self.purge();
        self.grants
            .get(scope)
            .context("grant is missing or expired")
    }

    fn ensure_grant_nonce_unused(&mut self, nonce: &[u8]) -> anyhow::Result<()> {
        self.purge();
        if self.used_grant_nonces.contains_key(nonce) {
            bail!("grant approval was already used");
        }
        Ok(())
    }

    fn remember_grant_nonce(&mut self, nonce: Vec<u8>, expires_at: Instant) {
        self.used_grant_nonces.insert(nonce, expires_at);
    }
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AgentRequest {
    Pubkey,
    Grant(AgentGrantRequest),
    Release(AgentScopeRequest),
    Revoke(AgentScopeRequest),
    Deliver(AgentDeliverRequest),
    Sign(AgentSignRequest),
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentScopeRequest {
    scope_type: String,
    scope_ref: String,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentGrantRequest {
    scope_type: String,
    scope_ref: String,
    ttl_secs: Option<u64>,
    deks: Vec<AgentDekInput>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDekInput {
    name: String,
    dek_blindbox: BlindBox,
    approval: ApprovalContextInput,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    digest: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct AgentDeliverRequest {
    scope_type: String,
    scope_ref: String,
    #[serde(default)]
    dek_blindbox: Option<serde_json::Value>,
    #[serde(default)]
    approval: Option<serde_json::Value>,
    #[serde(flatten)]
    mode: AgentDeliverMode,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum AgentDeliverMode {
    Run(AgentRunDeliverInput),
    Fetch(AgentFetchDeliverInput),
    Inject(InjectInput),
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRunDeliverInput {
    command: Vec<String>,
    secrets: Vec<EnvSecretInput>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentFetchDeliverInput {
    name: String,
    envelope: Sealed,
    request: FetchRequest,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSignRequest {
    scope_type: String,
    scope_ref: String,
    name: String,
    key_envelope: Sealed,
    digest: String,
    scheme: String,
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct AgentResponse<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct AgentGrantOutput {
    granted: usize,
    ttl_secs: u64,
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct AgentReleaseOutput {
    released: bool,
}

#[cfg(unix)]
#[derive(Debug, Serialize)]
struct AgentRunOutput {
    exit_code: u8,
}

#[cfg(unix)]
fn run_agent(options: AgentOptions, input: &mut impl Read) -> anyhow::Result<u8> {
    avault_store::harden_process_memory();
    let master = if options.unlock {
        let mut passphrase =
            read_passphrase_line(input).context("failed to read store passphrase from stdin")?;
        let master = avault_store::load_or_create_passphrase_master_key(passphrase.as_slice())
            .context("failed to unlock passphrase master key")?;
        passphrase.zeroize();
        Some(master)
    } else {
        match options.store {
            StoreSelection::File => None,
            StoreSelection::FilePassphrase => {
                bail!("file-passphrase agent requires --unlock")
            }
        }
    };
    let seed = avault_core::generate_blind_box_keypair_seed();
    let locked_keypair_seed =
        MasterKey::from_bytes(&seed).context("failed to lock blind-box receiver key")?;
    drop(seed);
    let listener = bind_agent_socket(&options.socket_path)?;
    listener
        .set_nonblocking(true)
        .context("failed to configure agent socket")?;
    let mut state = AgentState::new(options.idle_timeout, master);

    loop {
        state.purge();
        let (mut stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(AGENT_POLL_INTERVAL);
                continue;
            }
            Err(err) => return Err(err).context("failed to accept agent connection"),
        };
        stream
            .set_nonblocking(true)
            .context("failed to configure agent connection")?;
        if let Err(err) = authorize_peer(&stream) {
            let _ = write_agent_error_frame(&mut stream, &err);
            continue;
        }
        loop {
            state.purge();
            match read_agent_frame(&mut stream, &mut state) {
                Ok(Some(frame)) => {
                    let (response, refresh_activity) =
                        handle_agent_frame(frame.as_slice(), &locked_keypair_seed, &mut state);
                    if refresh_activity {
                        state.record_activity();
                    }
                    if write_agent_json_frame(&mut stream, &response).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let _ = write_agent_error_frame(&mut stream, &err);
                    break;
                }
            }
        }
    }
}

#[cfg(unix)]
fn bind_agent_socket(path: &Path) -> anyhow::Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_agent_socket_parent(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                bail!("agent socket is already in use");
            }
            fs::remove_file(path).context("failed to remove stale agent socket")?;
        }
        Ok(_) => bail!("agent socket path already exists and is not a socket"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("failed to inspect agent socket path"),
    }

    let listener = UnixListener::bind(path).context("failed to bind agent socket")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("failed to secure agent socket")?;
    Ok(listener)
}

#[cfg(unix)]
fn ensure_agent_socket_parent(parent: &Path) -> anyhow::Result<()> {
    if !parent.exists() {
        let mut missing = Vec::new();
        let mut current = parent;
        while !current.exists() {
            missing.push(current.to_path_buf());
            current = match current.parent() {
                Some(next) if !next.as_os_str().is_empty() => next,
                _ => Path::new("."),
            };
        }
        for dir in missing.iter().rev() {
            match fs::create_dir(dir) {
                Ok(()) => secure_agent_runtime_directory(dir)?,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate_agent_runtime_directory(dir)?
                }
                Err(err) => return Err(err).context("failed to create agent runtime directory"),
            }
        }
    }
    validate_agent_runtime_directory(parent)?;
    validate_agent_socket_ancestors(parent)?;
    Ok(())
}

#[cfg(unix)]
fn secure_agent_runtime_directory(path: &Path) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("failed to secure agent runtime directory")
}

#[cfg(unix)]
fn validate_agent_runtime_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).context("failed to stat agent runtime directory")?;
    if !metadata.is_dir() {
        bail!("agent runtime path parent is not a directory");
    }
    if metadata.uid() != avault_store::effective_uid() {
        bail!("agent runtime directory is not owned by the current user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("agent runtime directory mode is too open");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_agent_socket_ancestors(parent: &Path) -> anyhow::Result<()> {
    let mut current = parent.parent();
    while let Some(path) = current {
        if path.parent().is_none() {
            break;
        }
        validate_agent_socket_ancestor(path)?;
        current = path.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn validate_agent_socket_ancestor(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).context("failed to stat agent socket ancestor")?;
    if !metadata.is_dir() {
        bail!("agent socket ancestor is not a directory");
    }
    let uid = metadata.uid();
    if uid != 0 && uid != avault_store::effective_uid() {
        bail!("agent socket ancestor is not owned by root or the current user");
    }
    let mode = metadata.permissions().mode();
    let is_sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !is_sticky {
        bail!("agent socket ancestor is writable by other users");
    }
    Ok(())
}

#[cfg(unix)]
fn handle_agent_frame(
    frame: &[u8],
    keypair_seed: &MasterKey,
    state: &mut AgentState,
) -> (serde_json::Value, bool) {
    match handle_agent_frame_inner(frame, keypair_seed, state) {
        Ok(response) => response,
        Err(err) => (
            serde_json::to_value(AgentResponse::<serde_json::Value> {
                ok: false,
                result: None,
                error: Some(err.to_string()),
            })
            .expect("agent error response serializes"),
            false,
        ),
    }
}

#[cfg(unix)]
fn handle_agent_frame_inner(
    frame: &[u8],
    keypair_seed: &MasterKey,
    state: &mut AgentState,
) -> anyhow::Result<(serde_json::Value, bool)> {
    let request: AgentRequest =
        serde_json::from_slice(frame).context("agent frame JSON is invalid")?;
    match request {
        AgentRequest::Pubkey => Ok((
            {
                let (public_key, fingerprint) =
                    avault_core::blind_box_public_key_from_seed(keypair_seed.as_bytes());
                agent_ok(PubkeyOutput {
                    public_key,
                    fingerprint,
                })?
            },
            false,
        )),
        AgentRequest::Grant(request) => {
            if request.deks.is_empty() {
                bail!("grant requires at least one DEK");
            }
            let key = grant_key_from_parts(request.scope_type, request.scope_ref)?;
            let ttl_secs = request.ttl_secs.unwrap_or(DEFAULT_AGENT_GRANT_TTL_SECS);
            if ttl_secs == 0 {
                bail!("grant ttl_secs must be positive");
            }
            if ttl_secs > MAX_AGENT_GRANT_TTL_SECS {
                bail!("grant ttl_secs exceeds maximum");
            }
            let requested_expires_at = Instant::now()
                .checked_add(Duration::from_secs(ttl_secs))
                .context("grant expiration is invalid")?;
            let mut deks = HashMap::with_capacity(request.deks.len());
            let scope_type = key.scope_type.clone();
            let scope_ref = key.scope_ref.clone();
            let mut used_nonces = Vec::with_capacity(request.deks.len());
            let mut grant_expires_at = requested_expires_at;
            for dek in request.deks {
                let approval = parse_approval_context(&dek.approval)?;
                validate_approval_not_expired(approval.expires_at_unix)?;
                let approval_expires_at = approval_expiry_instant(approval.expires_at_unix)?;
                grant_expires_at = grant_expires_at.min(approval_expires_at);
                state.ensure_grant_nonce_unused(&approval.nonce)?;
                if used_nonces.iter().any(|(nonce, _): &(Vec<u8>, Instant)| {
                    nonce.as_slice() == approval.nonce.as_slice()
                }) {
                    bail!("duplicate grant approval nonce");
                }
                let purpose = AgentDekPurpose::parse(dek.purpose.as_deref())?;
                let (context, key) = match purpose {
                    AgentDekPurpose::Deliver => {
                        if dek.scheme.is_some() || dek.digest.is_some() {
                            bail!("deliver grant DEK must not include signing fields");
                        }
                        (
                            BlindBoxContext::agent_deliver(&scope_type, &scope_ref, &dek.name)
                                .with_approval(&approval.nonce, approval.expires_at_unix)
                                .with_operation_hash(agent_deliver_operation_hash(
                                    &dek.name, ttl_secs,
                                )),
                            AgentDekKey {
                                purpose,
                                name: dek.name.clone(),
                                scheme: None,
                                digest_hex: None,
                            },
                        )
                    }
                    AgentDekPurpose::Sign => {
                        let scheme = dek.scheme.context("sign grant DEK requires scheme")?;
                        let digest_hex = dek.digest.context("sign grant DEK requires digest")?;
                        let digest = decode_hex_32(&digest_hex, "digest")?;
                        let digest_key_hex = hex::encode(digest);
                        (
                            BlindBoxContext::agent_sign(
                                &scope_type,
                                &scope_ref,
                                &dek.name,
                                &scheme,
                                &digest,
                            )
                            .with_approval(&approval.nonce, approval.expires_at_unix)
                            .with_operation_hash(
                                agent_sign_operation_hash(&scheme, &digest, ttl_secs),
                            ),
                            AgentDekKey {
                                purpose,
                                name: dek.name.clone(),
                                scheme: Some(scheme),
                                digest_hex: Some(digest_key_hex),
                            },
                        )
                    }
                };
                if deks.contains_key(&key) {
                    bail!("duplicate grant DEK name");
                }
                let opened =
                    open_blind_box_with_seed(keypair_seed.as_bytes(), &dek.dek_blindbox, &context)
                        .context("DEK blind-box open failed")?;
                let released_dek = zeroizing_vec_to_key32(opened, "released DEK")?;
                let locked =
                    MasterKey::from_bytes(&released_dek).context("failed to lock released DEK")?;
                drop(released_dek);
                deks.insert(key, locked);
                used_nonces.push((approval.nonce, approval_expires_at));
            }
            let granted = deks.len();
            for (nonce, expires_at) in used_nonces {
                state.remember_grant_nonce(nonce, expires_at);
            }
            state.grants.insert(
                key,
                GrantEntry {
                    expires_at: grant_expires_at,
                    deks,
                },
            );
            Ok((agent_ok(AgentGrantOutput { granted, ttl_secs })?, true))
        }
        AgentRequest::Release(request) | AgentRequest::Revoke(request) => {
            let key = grant_key_from_scope(request)?;
            let released = state.grants.remove(&key).is_some();
            Ok((agent_ok(AgentReleaseOutput { released })?, released))
        }
        AgentRequest::Deliver(request) => {
            reject_agent_one_shot_request_fields(
                request.dek_blindbox.as_ref(),
                request.approval.as_ref(),
            )?;
            let scope = grant_key_from_parts(request.scope_type, request.scope_ref)?;
            let grant = state.get_grant(&scope)?;
            match request.mode {
                AgentDeliverMode::Run(AgentRunDeliverInput { command, secrets }) => {
                    if command.is_empty() {
                        bail!("deliver run requires a command");
                    }
                    if secrets.is_empty() {
                        bail!("deliver run requires at least one secret");
                    }
                    let command: Vec<OsString> = command.into_iter().map(OsString::from).collect();
                    let opened = open_env_secrets_with_grant(secrets, grant)?;
                    let exit_code = run_agent_child_with_opened_env(&command, opened, true, state)?;
                    Ok((agent_ok(AgentRunOutput { exit_code })?, true))
                }
                AgentDeliverMode::Fetch(AgentFetchDeliverInput {
                    name,
                    envelope,
                    request,
                }) => {
                    let fetch = FetchInput {
                        name,
                        envelope,
                        dek_blindbox: None,
                        approval: None,
                        request,
                    };
                    let (_url, is_loopback) = validate_fetch_input(&fetch)?;
                    let mut secret = open_secret_with_grant(&fetch.name, &fetch.envelope, grant)
                        .context("open failed")?;
                    state.purge_before_blocking(Duration::from_secs(FETCH_TOTAL_TIMEOUT_SECS));
                    let output = execute_fetch_request(fetch.request, &mut secret, is_loopback)
                        .context("fetch request failed")?;
                    secret.zeroize();
                    Ok((agent_ok(output)?, true))
                }
                AgentDeliverMode::Inject(inject) => {
                    write_inject_from_opened(inject, open_named_secrets_with_grant, grant)?;
                    Ok((agent_ok(serde_json::json!({ "ok": true }))?, true))
                }
            }
        }
        AgentRequest::Sign(request) => {
            let scope = grant_key_from_parts(request.scope_type, request.scope_ref)?;
            let grant = state.get_grant(&scope)?;
            let digest = decode_hex_32(&request.digest, "digest")?;
            let scheme = SignatureScheme::from_str(&request.scheme)?;
            let key_plaintext = open_signing_key_with_grant(
                &request.name,
                &request.key_envelope,
                &request.scheme,
                &digest,
                grant,
            )?;
            let output = sign_digest_with_key(scheme, &digest, key_plaintext)?;
            Ok((agent_ok(output)?, true))
        }
    }
}

#[cfg(unix)]
fn agent_ok<T: Serialize>(result: T) -> anyhow::Result<serde_json::Value> {
    serde_json::to_value(AgentResponse {
        ok: true,
        result: Some(result),
        error: None,
    })
    .context("failed to encode agent response")
}

#[cfg(unix)]
fn grant_key_from_scope(scope: AgentScopeRequest) -> anyhow::Result<GrantKey> {
    grant_key_from_parts(scope.scope_type, scope.scope_ref)
}

#[cfg(unix)]
fn grant_key_from_parts(scope_type: String, scope_ref: String) -> anyhow::Result<GrantKey> {
    if scope_type.is_empty() || scope_ref.is_empty() {
        bail!("scope_type and scope_ref are required");
    }
    Ok(GrantKey {
        scope_type,
        scope_ref,
    })
}

#[cfg(unix)]
fn open_env_secrets_with_grant(
    secrets: Vec<EnvSecretInput>,
    grant: &GrantEntry,
) -> anyhow::Result<Vec<OpenedSecret>> {
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    for secret in secrets {
        reject_agent_one_shot_secret_fields(
            secret.dek_blindbox.as_ref(),
            secret.approval.as_ref(),
        )?;
        validate_shell_name(&secret.env, "env var name")?;
        if !seen.insert(secret.env.clone()) {
            bail!("duplicate env var name");
        }
        let plaintext = open_secret_with_grant(&secret.name, &secret.envelope, grant)
            .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: secret.env,
            plaintext,
        });
    }
    Ok(opened)
}

#[cfg(unix)]
fn open_named_secrets_with_grant(
    secrets: Vec<NamedSecretInput>,
    grant: &GrantEntry,
) -> anyhow::Result<Vec<OpenedSecret>> {
    let mut opened = Vec::with_capacity(secrets.len());
    let mut seen = BTreeSet::new();
    for secret in secrets {
        reject_agent_one_shot_secret_fields(
            secret.dek_blindbox.as_ref(),
            secret.approval.as_ref(),
        )?;
        let target_name = secret
            .key
            .or(secret.env)
            .unwrap_or_else(|| secret.name.clone());
        validate_shell_name(&target_name, "secret target name")?;
        if !seen.insert(target_name.clone()) {
            bail!("duplicate secret target name");
        }
        let plaintext = open_secret_with_grant(&secret.name, &secret.envelope, grant)
            .with_context(|| format!("open failed for {}", secret.name))?;
        opened.push(OpenedSecret {
            name: target_name,
            plaintext,
        });
    }
    Ok(opened)
}

#[cfg(unix)]
fn reject_agent_one_shot_secret_fields(
    dek_blindbox: Option<&BlindBox>,
    approval: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    if dek_blindbox.is_some() || approval.is_some() {
        bail!("agent delivery uses cached grants and rejects one-shot DEK fields");
    }
    Ok(())
}

#[cfg(unix)]
fn reject_agent_one_shot_request_fields(
    dek_blindbox: Option<&serde_json::Value>,
    approval: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    if dek_blindbox.is_some() || approval.is_some() {
        bail!("agent delivery uses cached grants and rejects one-shot DEK fields");
    }
    Ok(())
}

#[cfg(unix)]
fn open_secret_with_grant(
    name: &str,
    envelope: &Sealed,
    grant: &GrantEntry,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let dek = grant
        .deks
        .get(&AgentDekKey {
            purpose: AgentDekPurpose::Deliver,
            name: name.to_string(),
            scheme: None,
            digest_hex: None,
        })
        .context("grant does not cover secret")?;
    avault_core::open_with_dek(dek.as_bytes(), name, envelope).context("envelope open failed")
}

#[cfg(unix)]
fn open_signing_key_with_grant(
    name: &str,
    envelope: &Sealed,
    scheme: &str,
    digest: &[u8; 32],
    grant: &GrantEntry,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let dek = grant
        .deks
        .get(&AgentDekKey {
            purpose: AgentDekPurpose::Sign,
            name: name.to_string(),
            scheme: Some(scheme.to_string()),
            digest_hex: Some(hex::encode(digest)),
        })
        .context("grant does not cover signing operation")?;
    avault_core::open_with_dek(dek.as_bytes(), name, envelope).context("envelope open failed")
}

#[cfg(unix)]
fn write_inject_from_opened(
    inject: InjectInput,
    opener: fn(Vec<NamedSecretInput>, &GrantEntry) -> anyhow::Result<Vec<OpenedSecret>>,
    grant: &GrantEntry,
) -> anyhow::Result<()> {
    if inject.secrets.is_empty() {
        bail!("deliver inject requires at least one secret");
    }
    let format = inject.format.to_ascii_lowercase();
    if format != "dotenv" && format != "json" {
        bail!("deliver inject format is not implemented in P1.1");
    }
    let mut opened = opener(inject.secrets, grant)?;
    let mut rendered = render_inject_file(&opened, &format)?;
    opened.zeroize();
    drop(opened);

    avault_store::atomic_write_secret_file(&inject.path, rendered.as_slice())
        .context("failed to write inject file")?;
    rendered.zeroize();
    Ok(())
}

#[cfg(unix)]
fn read_agent_frame(
    stream: &mut UnixStream,
    state: &mut AgentState,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len_buf = [0u8; 4];
    match read_exact_agent(stream, &mut len_buf, state) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed to read agent frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_FRAME_BYTES {
        bail!("agent frame size is invalid");
    }
    let mut frame = Zeroizing::new(vec![0u8; len]);
    read_exact_agent(stream, frame.as_mut_slice(), state).context("failed to read agent frame")?;
    Ok(Some(frame))
}

#[cfg(unix)]
fn read_exact_agent(
    stream: &mut UnixStream,
    mut buf: &mut [u8],
    state: &mut AgentState,
) -> io::Result<()> {
    let read_deadline = Instant::now()
        + Duration::from_millis(
            AGENT_POLL_INTERVAL.as_millis() as u64 * u64::from(MAX_AGENT_READ_TIMEOUTS),
        );
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                state.purge();
                if Instant::now() >= read_deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(AGENT_POLL_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_agent_json_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value).context("failed to encode agent frame")?;
    write_agent_frame(stream, &bytes)
}

#[cfg(unix)]
fn write_agent_error_frame(stream: &mut UnixStream, err: &anyhow::Error) -> anyhow::Result<()> {
    write_agent_json_frame(
        stream,
        &AgentResponse::<serde_json::Value> {
            ok: false,
            result: None,
            error: Some(err.to_string()),
        },
    )
}

#[cfg(unix)]
fn write_agent_frame(stream: &mut UnixStream, bytes: &[u8]) -> anyhow::Result<()> {
    let len: u32 = bytes
        .len()
        .try_into()
        .context("agent frame exceeds supported size")?;
    write_all_agent(stream, &len.to_be_bytes()).context("failed to write agent frame length")?;
    write_all_agent(stream, bytes).context("failed to write agent frame")?;
    Ok(())
}

#[cfg(unix)]
fn write_all_agent(stream: &mut UnixStream, mut bytes: &[u8]) -> io::Result<()> {
    let write_deadline = Instant::now()
        + Duration::from_millis(
            AGENT_POLL_INTERVAL.as_millis() as u64 * u64::from(MAX_AGENT_READ_TIMEOUTS),
        );
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= write_deadline {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(AGENT_POLL_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn authorize_peer(stream: &UnixStream) -> anyhow::Result<()> {
    avault_store::authorize_same_uid_peer(stream)
}

fn read_stdin_zeroizing_from(reader: &mut impl Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_zeroizing_to_cap(reader, MAX_STDIN_SECRET_BYTES)
}

fn read_json_input(
    reader: &mut impl Read,
    context: &'static str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    read_zeroizing_to_cap(reader, MAX_STDIN_ENVELOPE_BYTES).context(context)
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

fn read_passphrase_line(reader: &mut impl Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_STDIN_PASSPHRASE_BYTES));
    let mut scratch = Zeroizing::new([0u8; 1]);
    loop {
        if out.len() >= MAX_STDIN_PASSPHRASE_BYTES {
            bail!("store passphrase exceeds the supported size limit");
        }
        let n = reader.read(scratch.as_mut())?;
        if n == 0 {
            break;
        }
        let byte = scratch[0];
        scratch[0].zeroize();
        if byte == b'\n' {
            break;
        }
        out.push(byte);
    }
    if matches!(out.last(), Some(b'\r')) {
        out.pop();
    }
    if out.is_empty() {
        bail!("a non-empty store passphrase is required");
    }
    Ok(out)
}

fn read_envelope(path: Option<&str>, reader: &mut impl Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match path {
        Some(path) => fs::read(path)
            .map(Zeroizing::new)
            .context("failed to read envelope file"),
        None => read_zeroizing_to_cap(reader, MAX_STDIN_ENVELOPE_BYTES)
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

    #[test]
    fn redacted_fetch_body_enforces_size_cap_after_growth() {
        let mut body = vec![b'b'; MAX_FETCH_BODY_BYTES];
        body[0] = b'a';
        let needles = [Zeroizing::new(b"a".to_vec())];

        assert!(redact_fetch_body(&mut body, &needles).is_err());
    }
}
