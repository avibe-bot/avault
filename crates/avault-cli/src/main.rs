//! `avault` — the binary. Avibe's only path to key material.
//!
//! Two run modes (see `docs/DESIGN.md` Appendix C):
//!   - P1: one-shot CLI — control via argv/JSON, bulk blobs via stdin, results via stdout.
//!   - P2: resident agent — unix socket, `SO_PEERCRED` / `LOCAL_PEERCRED` auth.
//!
//! Interface (deliberately narrow; there is **no** `decrypt -> plaintext` verb):
//!   pubkey · seal · deliver · sign · key export|import · agent

use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
avault — Avibe Vaults custody core (scaffold; see docs/DESIGN.md)

USAGE:
    avault <command> [..]

COMMANDS:
    pubkey               print avault's X25519 public key (+ fingerprint)
    seal                 open a blind box -> wrap under master key -> emit envelope
    deliver              decrypt an envelope and deliver (run | fetch | inject)
    sign                 sign a digest / tx (secp256k1); never returns the key
    key export|import    back up / restore the master key
    agent                run the resident agent (unix socket, peer-credential auth)
    version              print version

Plaintext only flows IN; avault returns ciphertext / results / signatures — never plaintext.
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("") {
        "version" | "--version" | "-V" => {
            println!("avault {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "" | "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        cmd @ ("pubkey" | "seal" | "deliver" | "sign" | "key" | "agent") => {
            eprintln!("avault: '{cmd}' is not implemented yet (scaffold). See docs/DESIGN.md.");
            ExitCode::from(2)
        }
        other => {
            eprintln!("avault: unknown command '{other}'\n");
            print!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
