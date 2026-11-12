#!/usr/bin/env python3
"""Optional cross-version acceptance using public fixtures and isolated file stores.

Build the old binary from the v0.1.10 tag, not the live runtime. Example:
  python3 tests/hd-compatibility.py --old /path/to/old/avault --new target/debug/avault
Add --addresses-module /path/to/avibe/storage/vault_addresses.py to check the six
public addresses through the actual consumer's public-only address implementation.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--addresses-module", type=Path)
    args = parser.parse_args()
    fixture = json.loads((Path(__file__).parent / "vectors/hd_wallets.json").read_text())
    old, new = args.old.resolve(), args.new.resolve()
    with tempfile.TemporaryDirectory(prefix="avault-hd-compat-") as directory:
        root = Path(directory)
        env = os.environ.copy()
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "AVIBE_HOME",
                    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
                    "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"):
            target = root / key.lower()
            target.mkdir()
            env[key] = str(target)
        env.pop("HOMEDRIVE", None)
        env.pop("HOMEPATH", None)
        env["AVAULT_HOME"] = str(root / "vault")
        env["AVAULT_STORE"] = "file"

        def call(binary, command, body=b"", error=None):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            result = subprocess.run([str(binary), "--store", "file", *command], input=body,
                                    capture_output=True, env=env, timeout=20, check=False)
            if error is not None:
                assert result.returncode == 70 and not result.stdout, result
                assert error in result.stderr.decode(), result.stderr
                return None
            assert result.returncode == 0 and not result.stderr, result.stderr
            return json.loads(result.stdout)

        seed = bytes.fromhex(fixture["bip86_seed"])
        command = ["keypair", "import", "--name", "HD", "--type", "hd-seed", "--format", "raw-seed"]
        call(old, command, seed, error="unknown keypair option")
        assert not (root / "vault").exists()
        imported = call(new, command, seed)
        for account in fixture["wallet_accounts"]:
            assert imported["accounts"][account["account"]] == {
                key: account[key] for key in ("account", "evm", "bitcoin", "solana")
            }
        request = {"name": "HD", "key_envelope": imported["envelope"],
                   "scheme": "ecdsa-secp256k1-recoverable", "digest": "00" * 32,
                   "derivation": {"chain": "evm", "account": 0}}
        call(old, ["sign"], request, error="unknown field")
        del request["derivation"]
        call(old, ["sign"], request, error="unsupported wrap scheme")
        for retag in (False, True):
            envelope = dict(imported["envelope"])
            if retag:
                meta = json.loads(envelope["wrap_meta"])
                meta["scheme"] = "machine-aesgcm-v1"
                envelope["wrap_meta"] = json.dumps(meta)
            error = "value decrypt failed" if retag else "unsupported wrap scheme"
            request["key_envelope"] = envelope
            call(old, ["sign"], request, error=error)
            call(old, ["deliver", "run", "--", "must-not-start"],
                 [{"name": "HD", "env": "HD", "envelope": envelope}], error=error)

        # Same legacy envelopes and deterministic signatures in both directions.
        for creator in (old, new):
            envelope = call(creator, ["seal", "--name", "LEGACY"], bytes([7]) * 32)
            for scheme in ("ecdsa-secp256k1-recoverable", "ecdsa-secp256k1-der", "ed25519"):
                request = {"name": "LEGACY", "key_envelope": envelope, "scheme": scheme}
                request.update({"message_hex": "000102ff"} if scheme == "ed25519" else {"digest": "42" * 32})
                assert call(old, ["sign"], request) == call(new, ["sign"], request)
        if args.addresses_module:
            spec = importlib.util.spec_from_file_location("public_addresses", args.addresses_module)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for expected in fixture["wallet_accounts"]:
                account = imported["accounts"][expected["account"]]
                actual = {"eth": module.derive_addresses(account["evm"])["eth"],
                          "btc_taproot": module.derive_addresses(account["bitcoin"])["btc_taproot"],
                          "solana": module.base58_encode(bytes.fromhex(account["solana"]))}
                assert actual == expected["addresses"], (actual, expected["addresses"])
            print("All six public addresses match the independent design fixture.")
        print("Old binary refuses HD import/sign/delivery, including retagging; legacy signatures match both ways.")


if __name__ == "__main__":
    main()
