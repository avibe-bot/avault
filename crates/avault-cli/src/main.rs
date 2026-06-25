//! `avault` — the binary. Avibe's only path to key material.
//!
//! P1 is a one-shot CLI: control via argv/JSON, bulk blobs via stdin, results via stdout.
//! P2 keeps `pubkey`, `sign`, and `agent` as stubs.

use anyhow::{bail, Context};
use avault_core::{ExportBlob, Sealed};
use avault_store::{Backend, FileStore};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::process::{Command, ExitCode, Stdio};
use zeroize::{Zeroize, Zeroizing};

const MAX_STDIN_SECRET_BYTES: usize = 1024 * 1024;
const MAX_STDIN_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const STDIN_READ_CHUNK_BYTES: usize = 8192;

const USAGE: &str = "\
avault — Avibe Vaults custody core

USAGE:
    avault seal --name NAME
    avault deliver run --name NAME --env VAR [--envelope-file PATH] -- COMMAND [ARGS...]
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

    let run_options = parse_deliver_run_options(options)?;
    let name = run_options.name;
    let env_name = run_options.env_name;
    let envelope_file = run_options.envelope_file;
    if env_name.contains('=') || env_name.is_empty() {
        bail!("invalid env var name");
    }

    let envelope_stdin = envelope_file.is_none();
    let envelope = read_envelope(envelope_file.as_deref())?;
    let sealed: Sealed =
        serde_json::from_slice(envelope.as_slice()).context("envelope JSON is invalid")?;
    let master = avault_store::load_master_key(Backend::File)?;
    let mut plaintext =
        avault_core::open(master.as_bytes(), &name, &sealed).context("open failed")?;
    drop(master);

    let mut child = {
        let env_value = std::str::from_utf8(plaintext.as_slice())
            .context("secret value is not valid UTF-8 for env delivery")?;
        let mut child = Command::new(&command[0]);
        // Accepted standard-tier residual: `Command::env` copies this value into std's
        // process builder and then into the child's environment. Rust does not expose that
        // buffer for zeroizing; the value is wiped from avault's owned buffer after spawn.
        child.args(&command[1..]).env(&env_name, env_value);
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
    plaintext.zeroize();
    drop(plaintext);
    let status = child.wait().context("failed to wait for child command")?;

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
