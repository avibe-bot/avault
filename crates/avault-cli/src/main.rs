//! `avault` — the binary. Avibe's only path to key material.
//!
//! P1 is a one-shot CLI: control via argv/JSON, bulk blobs via stdin, results via stdout.
//! P2 keeps `pubkey`, `sign`, and `agent` as stubs.

use anyhow::{bail, Context};
use avault_core::{ExportBlob, Sealed};
use avault_store::{Backend, FileStore};
use std::env;
use std::ffi::OsString;
use std::io::{self, Read};
use std::process::{Command, ExitCode, Stdio};
use zeroize::{Zeroize, Zeroizing};

const USAGE: &str = "\
avault — Avibe Vaults custody core

USAGE:
    avault seal --name NAME
    avault deliver run --name NAME --env VAR -- COMMAND [ARGS...]
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
        "fetch" | "inject" => bail!("deliver {subcmd} is a P2 stub and is not implemented in P1"),
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

    let name = parse_required_option(options, "--name")?;
    let env_name = parse_required_option(options, "--env")?;
    if env_name.contains('=') || env_name.is_empty() {
        bail!("invalid env var name");
    }

    let sealed: Sealed =
        serde_json::from_slice(&read_stdin_bytes()?).context("envelope JSON is invalid")?;
    let master = avault_store::load_master_key(Backend::File)?;
    let mut plaintext =
        avault_core::open(master.as_bytes(), &name, &sealed).context("open failed")?;

    let env_value = std::str::from_utf8(plaintext.as_slice())
        .context("secret value is not valid UTF-8 for env delivery")?;
    let status = Command::new(&command[0])
        .args(&command[1..])
        .env(&env_name, env_value)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to run child command")?;
    plaintext.zeroize();

    Ok(status.code().unwrap_or(1).try_into().unwrap_or(1))
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
    passphrase.zeroize();
    serde_json::to_writer(io::stdout(), &blob).context("failed to write key export JSON")?;
    println!();
    Ok(0)
}

fn key_import_cmd(args: &[OsString]) -> anyhow::Result<u8> {
    let force = parse_flag(args, "--force")?;
    let mut input = read_stdin_bytes().context("failed to read key import JSON from stdin")?;
    let request: KeyImportRequest =
        serde_json::from_slice(&input).context("key import JSON is invalid")?;
    input.zeroize();

    let mut passphrase = Zeroizing::new(request.passphrase.into_bytes());
    trim_trailing_newlines(passphrase.as_mut());
    let key = avault_core::import_master_key(&request.blob, passphrase.as_slice())
        .context("key import failed")?;
    passphrase.zeroize();

    FileStore::new(avault_store::default_master_key_path()?)
        .import(&key, force)
        .context("failed to store imported master key")?;
    println!(r#"{{"ok":true}}"#);
    Ok(0)
}

#[derive(serde::Deserialize)]
struct KeyImportRequest {
    passphrase: String,
    blob: ExportBlob,
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
    Ok(Zeroizing::new(read_stdin_bytes()?))
}

fn read_stdin_bytes() -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn trim_trailing_newlines(buf: &mut Vec<u8>) {
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
}
