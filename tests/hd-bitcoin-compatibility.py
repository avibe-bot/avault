#!/usr/bin/env python3
"""Black-box avault v0.1.11 <-> bitcoin-address-types-v1 compatibility.

Python stdlib only. Uses PUBLIC, NEVER-FUND fixtures, explicit --store file,
hermetic environments, and disposable master stores. No Keychain, network,
private-key export, decryption, source checkout changes, or wallet funding.

The group arithmetic below is a PUBLIC-ONLY test oracle, never a signer/KDF.
Taproot signatures are randomized: compare account identities and independently
verify each signature against BIP86's tweaked output key, NOT signature bytes.

Example:
  python3 hd-bitcoin-compatibility.py --old /scratch/old/avault --new /scratch/new/avault
  # --artifacts must designate a new directory; defaults to a fresh temporary directory.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

PROFILE = "bitcoin-address-types-v1"
# Deliberately public, synthetic 64-byte HD input, not mnemonic material.
PUBLIC_NEVER_FUND_HD_SEED = bytes(range(64))
# RFC 8032 test 1 seed and public key. NEVER FUND this or any derived account.
PUBLIC_NEVER_FUND_ED_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
PUBLIC_NEVER_FUND_ED_PUB = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
# Public scalar 1, for ordinary legacy secp256k1 sealed-key compatibility only.
PUBLIC_NEVER_FUND_SECP_KEY = bytes(31) + b"\x01"
DIGEST = hashlib.sha256(b"avault PUBLIC NEVER-FUND HD BTC parity compatibility v1").digest()
MESSAGE = b"avault PUBLIC NEVER-FUND Ed25519 compatibility v1"
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
OLD_FIELDS = {"account", "evm", "bitcoin", "solana"}
EXT_FIELDS = OLD_FIELDS | {"bitcoin_p2pkh", "bitcoin_p2wpkh"}
SCHEMES = {
    "evm": "ecdsa-secp256k1-recoverable",
    "bitcoin": "schnorr-secp256k1-bip341-keypath",
    "solana": "ed25519",
}


def need(value, message):
    if not value:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = ((3 * x1 * x1) * pow(2 * y1, -1, P) if a == b
             else (y2 - y1) * pow(x2 - x1, -1, P)) % P
    x = (slope * slope - x1 - x2) % P
    return x, (slope * (x1 - x) - y1) % P


def mul(k, point=G):
    out = None
    while k:
        if k & 1:
            out = add(out, point)
        point = add(point, point)
        k >>= 1
    return out


def lift_x(x):
    need(0 <= x < P, "public x out of range")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    need((y * y - x * x * x - 7) % P == 0, "public point not on curve")
    return x, y if y % 2 == 0 else P - y


def sec1(public_hex):
    raw = bytes.fromhex(public_hex)
    need(len(raw) == 33 and raw[0] in (2, 3), "not compressed secp256k1 public key")
    x, y = lift_x(int.from_bytes(raw[1:], "big"))
    return x, y if y % 2 == raw[0] % 2 else P - y


def tagged_hash(tag, msg):
    taghash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(taghash + taghash + msg).digest()


def bip86_output_x(internal_hex):
    # BIP341 first normalizes to the even-y x-only internal public key.
    internal = lift_x(sec1(internal_hex)[0])
    tweak = int.from_bytes(tagged_hash("TapTweak", internal[0].to_bytes(32, "big")), "big")
    need(tweak < N, "invalid BIP86 public tweak")
    output = add(internal, mul(tweak))
    need(output is not None, "BIP86 output infinity")
    return output[0]


def schnorr_valid(signature_hex, public_x, digest=DIGEST):
    sig = bytes.fromhex(signature_hex)
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    public = lift_x(public_x)
    challenge = int.from_bytes(tagged_hash(
        "BIP0340/challenge", sig[:32] + public_x.to_bytes(32, "big") + digest
    ), "big") % N
    neg_public = public[0], (-public[1]) % P
    point = add(mul(s), mul(challenge, neg_public))
    return point is not None and point[1] % 2 == 0 and point[0] == r


def ecdsa_valid(signature_hex, public_hex, der=False, digest=DIGEST):
    raw = bytes.fromhex(signature_hex)
    if der:
        if len(raw) < 8 or raw[0] != 0x30 or raw[1] != len(raw) - 2:
            return False
        pos = 2
        values = []
        for _ in range(2):
            if pos + 2 > len(raw) or raw[pos] != 2:
                return False
            size = raw[pos + 1]
            value = raw[pos + 2:pos + 2 + size]
            if (not value or len(value) != size or value[0] & 0x80
                    or len(value) > 1 and value[0] == 0 and value[1] < 0x80):
                return False
            values.append(int.from_bytes(value, "big"))
            pos += size + 2
        if pos != len(raw):
            return False
        r, s = values
    else:
        if len(raw) != 64:
            return False
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    inv = pow(s, -1, N)
    point = add(mul(int.from_bytes(digest, "big") * inv % N),
                mul(r * inv % N, sec1(public_hex)))
    return point is not None and point[0] % N == r


def snapshot(root):
    """Opaque hashes and metadata, never decode or report master-key bytes."""
    result = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        rel = str(path.relative_to(root))
        need(not path.is_symlink(), "unexpected symlink in isolated state")
        if path.is_file():
            result[rel] = {
                "sha256": sha(path.read_bytes()), "size": metadata.st_size,
                "mode": stat.S_IMODE(metadata.st_mode), "mtime_ns": metadata.st_mtime_ns,
                "inode": metadata.st_ino,
            }
        elif path.is_dir():
            result[rel] = {"mode": stat.S_IMODE(metadata.st_mode), "directory": True}
        else:
            raise AssertionError("unexpected special file in isolated state")
    return result


class Check:
    def __init__(self, old, new, artifacts):
        self.input_binaries = {"old": old, "new": new}
        self.binaries = {}
        self.binary_sha256 = {}
        self.artifacts = artifacts
        binary_dir = artifacts / "binaries"
        binary_dir.mkdir(mode=0o700)
        # An implementation lane may rebuild its target while this matrix runs.
        # Freeze real executable copies, never symlinks, and execute only those.
        for name, path in self.input_binaries.items():
            before = path.stat()
            data = path.read_bytes()
            after = path.stat()
            need((before.st_ino, before.st_size, before.st_mtime_ns) ==
                 (after.st_ino, after.st_size, after.st_mtime_ns),
                 f"{name} binary changed while copying; rerun against a finished build")
            target = binary_dir / ("avault-" + name)
            target.write_bytes(data)
            target.chmod(0o700)
            self.binaries[name] = target
            self.binary_sha256[name] = sha(data)
        self.responses = artifacts / "responses"
        self.responses.mkdir()
        self.state = Path(tempfile.mkdtemp(prefix="disposable-stores-", dir=artifacts))
        os.chmod(self.state, 0o700)
        self.calls = []
        self.checks = []
        self.immutable = {}
        self.verifications = {"bip86_schnorr": 0, "raw_bip340": 0, "ecdsa": 0,
                              "deterministic_pair_equality": 0}
        self.cases = {}

    def case(self, name):
        if name not in self.cases:
            root = self.state / name
            root.mkdir(mode=0o700)
            for directory in ("home", "tmp"):
                (root / directory).mkdir(mode=0o700)
            self.cases[name] = root
        return self.cases[name]

    def invoke(self, binary, case, label, argv, data=b"", creates=False, reject=None):
        root = self.case(case)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(root / "home"),
            "AVAULT_HOME": str(root / "vault"), "AVAULT_STORE": "file",
            "TMPDIR": str(root / "tmp"), "XDG_CONFIG_HOME": str(root / "home" / ".config"),
            "RUST_BACKTRACE": "0", "LC_ALL": "C",
        }
        payload = canonical(data) if isinstance(data, (dict, list)) else data
        before = snapshot(root)
        started = time.monotonic()
        process = subprocess.run(
            [str(self.binaries[binary]), "--store", "file", *argv],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, cwd=root, timeout=30, check=False,
        )
        after = snapshot(root)
        row = {
            "index": len(self.calls) + 1, "label": label, "binary": binary,
            "case": case, "argv": ["--store", "file", *argv],
            "exit": process.returncode, "stdout_bytes": len(process.stdout),
            "stdout_sha256": sha(process.stdout),
            "stderr": process.stderr.decode("utf-8", "replace"),
            "state_unchanged": before == after, "creates_allowed": creates,
            "duration_seconds": round(time.monotonic() - started, 5),
        }
        self.calls.append(row)
        if not creates:
            need(before == after, f"{label}: store/environment mutation")
        else:
            for name, prior in before.items():
                need(after.get(name) == prior, f"{label}: preexisting state changed: {name}")
            need((root / "vault" / "machine.key").is_file(), f"{label}: no isolated file store")
            need(stat.S_IMODE((root / "vault" / "machine.key").stat().st_mode) == 0o600,
                 f"{label}: master file permissions")
        if reject is not None:
            need(process.returncode == 70, f"{label}: expected refusal 70, got {process.returncode}")
            need(process.stdout == b"", f"{label}: refusal emitted output/fell back")
            if reject:
                need(reject in row["stderr"], f"{label}: missing refusal reason {reject!r}: {row['stderr']}")
            return None
        need(process.returncode == 0, f"{label}: exit {process.returncode}: {row['stderr']}")
        need(not process.stderr, f"{label}: unexpected stderr: {row['stderr']}")
        try:
            value = json.loads(process.stdout)
        except ValueError as exc:
            raise AssertionError(f"{label}: output is not JSON") from exc
        path = self.responses / f"{len(self.calls):04d}-{re.sub('[^a-zA-Z0-9_.-]', '_', label)}.json"
        path.write_bytes(process.stdout)
        row["response_file"] = str(path.relative_to(self.artifacts))
        self.immutable[path] = sha(process.stdout)
        return value

    def passed(self, text):
        self.checks.append(text)
        print("PASS", text, flush=True)

    def import_hd(self, binary, case, name, extended=False):
        args = ["keypair", "import", "--name", name, "--type", "hd-seed", "--format", "raw-seed"]
        if extended:
            args += ["--profile", PROFILE]
        result = self.invoke(binary, case, f"{case}-import", args, PUBLIC_NEVER_FUND_HD_SEED, creates=True)
        need(set(result) == ({"type", "profile", "envelope", "accounts"} if extended
                             else {"type", "envelope", "accounts"}), f"{case}: root schema drift")
        need(result["type"] == "hd-seed", f"{case}: wrong import type")
        if extended:
            need(result["profile"] == PROFILE, f"{case}: wrong profile")
        self.accounts(result["accounts"], extended)
        need(set(result["envelope"]) == {"ciphertext", "nonce", "wrap_meta"}, "envelope field drift")
        meta = json.loads(result["envelope"]["wrap_meta"])
        need(set(meta) == {"v", "scheme", "wrapped_dek", "dek_nonce"}, "wrap metadata field drift")
        need(meta["v"] == 1 and meta["scheme"] == "machine-hd-seed-aesgcm-v1", "HD wrap scheme drift")
        need(len(base64.b64decode(result["envelope"]["ciphertext"], validate=True)) == 80,
             "HD ciphertext length drift")
        return result

    @staticmethod
    def accounts(accounts, extended):
        need(isinstance(accounts, list) and len(accounts) == 20, "expected 20 accounts")
        for index, account in enumerate(accounts):
            need(set(account) == (EXT_FIELDS if extended else OLD_FIELDS), "public account field drift/leak")
            need(type(account["account"]) is int and account["account"] == index, "account index drift")
            for field in (EXT_FIELDS if extended else OLD_FIELDS) - {"account"}:
                need(isinstance(account[field], str) and re.fullmatch("[0-9a-f]+", account[field]),
                     "public key must be lowercase bare hex")
                if field == "solana":
                    need(len(account[field]) == 64, "wrong Ed25519 public key size")
                else:
                    sec1(account[field])

    def derive(self, case, name, envelope, label=None, reject=None, **overrides):
        request = {"name": name, "key_envelope": envelope, "profile": PROFILE}
        request.update(overrides)
        return self.invoke("new", case, label or f"{case}-derive-public",
                           ["keypair", "derive-public"], request, reject=reject)

    def sign(self, binary, case, name, envelope, chain, index, selector=None, reject=None,
             explicit_scheme=False, omit_account=False, label=None):
        derivation = {"chain": chain}
        if not omit_account:
            derivation["account"] = index
        if selector is not None:
            derivation["address_type"] = selector
        request = {"name": name, "key_envelope": envelope, "derivation": derivation}
        request["message_hex" if chain == "solana" else "digest"] = (
            MESSAGE.hex() if chain == "solana" else DIGEST.hex()
        )
        if explicit_scheme:
            request["scheme"] = ("ecdsa-secp256k1-der" if selector in ("p2pkh", "p2wpkh")
                                 else SCHEMES[chain])
        label = label or f"{case}-{binary}-{chain}-{index}-{selector or 'omitted'}"
        return self.invoke(binary, case, label, ["sign"], request, reject=reject)

    def signature(self, result, scheme, public_hex):
        need(set(result) == {"signature", "recovery_id"}, "signature output schema drift")
        need(isinstance(result["signature"], str) and re.fullmatch("[0-9a-f]+", result["signature"]),
             "signature not lowercase hex")
        if scheme == "ed25519":
            need(len(result["signature"]) == 128 and result["recovery_id"] is None,
                 "Ed25519 result schema")
        elif scheme.startswith("ecdsa"):
            need(ecdsa_valid(result["signature"], public_hex, der=scheme.endswith("-der")),
                 "independent ECDSA verification failed")
            need(result["recovery_id"] is None if scheme.endswith("-der") else
                 type(result["recovery_id"]) is int and 0 <= result["recovery_id"] <= 3,
                 "ECDSA recovery_id schema")
            self.verifications["ecdsa"] += 1
        else:
            output_x = (bip86_output_x(public_hex) if scheme.endswith("bip341-keypath")
                        else sec1(public_hex)[0])
            need(schnorr_valid(result["signature"], output_x), "independent Schnorr verification failed")
            need(result["recovery_id"] is None, "Schnorr recovery_id schema")
            need(not schnorr_valid(result["signature"], output_x, bytes(32)),
                 "Schnorr public oracle accepted incorrect digest")
            self.verifications["bip86_schnorr" if scheme.endswith("bip341-keypath") else "raw_bip340"] += 1

    def run(self):
        old_name = "PUBLIC-NEVER-FUND-old-HD"
        new_name = "PUBLIC-NEVER-FUND-new-HD"
        ext_name = "PUBLIC-NEVER-FUND-extended-HD"
        old = self.import_hd("old", "old-origin", old_name)
        new = self.import_hd("new", "new-origin", new_name)
        extended = self.import_hd("new", "extended-origin", ext_name, extended=True)
        need(old["accounts"] == new["accounts"], "default new import changed old identities")
        need(old["accounts"] == [{k: a[k] for k in OLD_FIELDS} for a in extended["accounts"]],
             "extended import changed old identities")
        self.passed("new default import has exact old root/account/wrap field sets; all 20 legacy identities match")
        sources = [("old-origin", old_name, old), ("new-origin", new_name, new),
                   ("extended-origin", ext_name, extended)]
        profile_accounts = None
        for case, name, imported in sources:
            before_envelope = canonical(imported["envelope"])
            derived = self.derive(case, name, imported["envelope"])
            need(set(derived) == {"type", "profile", "accounts"}, "derive-public root leaked/drifted")
            need(derived["type"] == "hd-seed" and derived["profile"] == PROFILE, "derive-public type/profile")
            self.accounts(derived["accounts"], True)
            need(old["accounts"] == [{k: a[k] for k in OLD_FIELDS} for a in derived["accounts"]],
                 "derive-public changed any old identity")
            if profile_accounts is None:
                profile_accounts = derived["accounts"]
            need(derived["accounts"] == profile_accounts == extended["accounts"],
                 "public profile differs across old/default/extended origins")
            need(canonical(imported["envelope"]) == before_envelope, "derive-public altered caller envelope")
        self.passed("new derive-public reopens old/new/extended envelopes: exact public-only profile, all20 old identities + two BTC keys")

        for case, name, imported in sources:
            envelope = imported["envelope"]
            for index, account in enumerate(old["accounts"]):
                for chain in ("evm", "bitcoin", "solana"):
                    outputs = [self.sign(binary, case, name, envelope, chain, index) for binary in ("old", "new")]
                    for result in outputs:
                        self.signature(result, SCHEMES[chain], account[chain])
                    if chain != "bitcoin":
                        need(outputs[0] == outputs[1], f"{case}: deterministic {chain} signature drift")
                        self.verifications["deterministic_pair_equality"] += 1
                    else:
                        explicit = self.sign("new", case, name, envelope, chain, index, "p2tr", explicit_scheme=True)
                        self.signature(explicit, SCHEMES[chain], account[chain])
                        # A raw, untweaked key must not verify the BIP341 signature.
                        need(not schnorr_valid(explicit["signature"], sec1(account[chain])[0]),
                             "Taproot signature erroneously verifies under untweaked key")
                for selector in ("p2pkh", "p2wpkh", "p2tr"):
                    self.sign("old", case, name, envelope, "bitcoin", index, selector,
                              reject="address_type")
                    if selector != "p2tr":
                        result = self.sign("new", case, name, envelope, "bitcoin", index, selector,
                                           explicit_scheme=True)
                        self.signature(result, "ecdsa-secp256k1-der", profile_accounts[index]["bitcoin_" + selector])
            # Default account (omitted account) remains account zero on every chain.
            for chain in ("evm", "bitcoin", "solana"):
                outputs = [self.sign(binary, case, name, envelope, chain, 0, omit_account=True,
                                     label=f"{case}-{binary}-{chain}-omitted-account") for binary in ("old", "new")]
                for result in outputs:
                    self.signature(result, SCHEMES[chain], old["accounts"][0][chain])
                if chain != "bitcoin":
                    need(outputs[0] == outputs[1], "omitted-account deterministic signature drift")
                    self.verifications["deterministic_pair_equality"] += 1
        self.passed("bidirectional old/new signing all20 x EVM/BTC/Solana; omitted Bitcoin stays BIP86 and explicit new p2tr verifies under same output keys")
        self.passed("v0.1.11 rejects all p2pkh/p2wpkh/p2tr selectors on all20 x old/new/extended envelopes, exit70 and zero stdout: no fallback")
        self.passed("extended imports cross-open in old only with omitted Bitcoin selector; new p2pkh/p2wpkh DER verifies for all20 x all origins")

        # Old parsers reject new verbs/options before creating an absent store.
        missing = "missing-master"
        self.invoke("old", missing, "old-refuses-new-derive-public", ["keypair", "derive-public"],
                    {"name": old_name, "key_envelope": old["envelope"], "profile": PROFILE},
                    reject="unknown keypair subcommand")
        self.invoke("old", missing, "old-refuses-import-profile", [
            "keypair", "import", "--name", old_name, "--type", "hd-seed", "--format", "raw-seed",
            "--profile", PROFILE], PUBLIC_NEVER_FUND_HD_SEED, reject="unknown keypair option")
        for selector in ("p2pkh", "p2wpkh", "p2tr"):
            self.sign("old", missing, old_name, old["envelope"], "bitcoin", 0, selector,
                      reject="address_type", label=f"old-missing-master-refuses-{selector}")
        self.derive(missing, old_name, old["envelope"], label="new-missing-master-derive-public", reject="")
        need(not (self.case(missing) / "vault").exists(), "missing-master operation created a store directory")
        self.passed("old new-verb/profile/selector refusals and new missing-master derive-public emit nothing and create no store")

        # Ordinary legacy keys use only known public test scalars/seeds.
        secp_pub = "02" + G[0].to_bytes(32, "big").hex()
        legacy_sources = []
        for binary in ("old", "new"):
            case = binary + "-origin"
            secp_name = "PUBLIC-NEVER-FUND-ordinary-secp-" + binary
            secp_env = self.invoke(binary, case, f"{binary}-legacy-secp-seal", ["seal", "--name", secp_name],
                                   PUBLIC_NEVER_FUND_SECP_KEY)
            for scheme in ("ecdsa-secp256k1-recoverable", "ecdsa-secp256k1-der",
                           "schnorr-secp256k1-bip340", "schnorr-secp256k1-bip341-keypath"):
                request = {"name": secp_name, "key_envelope": secp_env, "scheme": scheme, "digest": DIGEST.hex()}
                outputs = [self.invoke(target, case, f"{binary}-legacy-secp-{target}-{scheme}", ["sign"], request)
                           for target in ("old", "new")]
                for result in outputs:
                    self.signature(result, scheme, secp_pub)
                if scheme.startswith("ecdsa"):
                    need(outputs[0] == outputs[1], "ordinary secp deterministic signature drift")
                    self.verifications["deterministic_pair_equality"] += 1
            ed_name = "PUBLIC-NEVER-FUND-ordinary-ed-" + binary
            ed_result = self.invoke(binary, case, f"{binary}-legacy-ed-import", [
                "keypair", "import", "--name", ed_name, "--curve", "ed25519", "--format", "solana-cli-json"
            ], json.dumps(list(PUBLIC_NEVER_FUND_ED_SEED + bytes.fromhex(PUBLIC_NEVER_FUND_ED_PUB))).encode())
            need(set(ed_result) == {"envelope", "curve", "chain", "public_key", "address"},
                 "ordinary Ed25519 import response drift")
            need(ed_result["public_key"] == PUBLIC_NEVER_FUND_ED_PUB and ed_result["curve"] == "ed25519"
                 and ed_result["chain"] == "solana", "ordinary Ed25519 identity drift")
            request = {"name": ed_name, "key_envelope": ed_result["envelope"],
                       "scheme": "ed25519", "message_hex": MESSAGE.hex()}
            outputs = [self.invoke(target, case, f"{binary}-legacy-ed-{target}-sign", ["sign"], request)
                       for target in ("old", "new")]
            need(outputs[0] == outputs[1], "ordinary Ed25519 signature drift")
            for result in outputs:
                self.signature(result, "ed25519", PUBLIC_NEVER_FUND_ED_PUB)
            self.verifications["deterministic_pair_equality"] += 1
            legacy_sources.extend([(case, secp_name, secp_env), (case, ed_name, ed_result["envelope"])])
        self.passed("ordinary public scalar-one secp legacy envelopes and RFC8032 Ed25519 imports sign continuously in both directions")

        envelope = old["envelope"]
        self.derive("old-origin", old_name + "-wrong", envelope, label="derive-name-mismatch", reject="")
        for field in ("ciphertext", "nonce"):
            corrupt = copy.deepcopy(envelope)
            raw = bytearray(base64.b64decode(corrupt[field], validate=True))
            raw[0] ^= 1
            corrupt[field] = base64.b64encode(raw).decode()
            self.derive("old-origin", old_name, corrupt, label="derive-corrupt-" + field, reject="")
        corrupt = copy.deepcopy(envelope)
        metadata = json.loads(corrupt["wrap_meta"])
        wrapped = bytearray(base64.b64decode(metadata["wrapped_dek"], validate=True))
        wrapped[0] ^= 1
        metadata["wrapped_dek"] = base64.b64encode(wrapped).decode()
        corrupt["wrap_meta"] = json.dumps(metadata)
        self.derive("old-origin", old_name, corrupt, label="derive-corrupt-wrapped-dek", reject="")
        corrupt = copy.deepcopy(envelope)
        metadata = json.loads(corrupt["wrap_meta"])
        metadata["scheme"] = "machine-aesgcm-v1"
        corrupt["wrap_meta"] = json.dumps(metadata)
        self.derive("old-origin", old_name, corrupt, label="derive-retagged-HD", reject="")
        self.derive("new-origin", old_name, envelope, label="derive-substitute-wrong-master", reject="")
        self.derive("old-origin", old_name, new["envelope"], label="derive-substitute-other-HD-envelope", reject="")
        for case, name, substituted in legacy_sources:
            self.derive(case, name, substituted, label="derive-refuses-ordinary-" + name, reject="")
        generic = self.invoke("old", "old-origin", "old-generic64-same-name-seal", ["seal", "--name", old_name],
                              PUBLIC_NEVER_FUND_HD_SEED)
        self.derive("old-origin", old_name, generic, label="derive-substitute-generic64-same-name", reject="")
        for chain in ("evm", "solana"):
            for selector in ("p2pkh", "p2wpkh", "p2tr"):
                self.sign("new", "old-origin", old_name, envelope, chain, 0, selector, reject="")
        self.sign("new", "old-origin", old_name, envelope, "bitcoin", 20, reject="")
        self.derive("old-origin", old_name, envelope, label="derive-unknown-profile", reject="", profile="unknown-v1")
        self.derive("old-origin", old_name, envelope, label="derive-null-profile", reject="", profile=None)
        self.invoke("new", "old-origin", "derive-omitted-profile", ["keypair", "derive-public"],
                    {"name": old_name, "key_envelope": envelope}, reject="")
        self.passed("derive-public rejects wrong name, corrupt ciphertext/nonce/wrapped-DEK, retagging, wrong-master/HD/ordinary/generic substitutions")
        self.passed("new BTC selector is Bitcoin-only; account20/unknown/null/omitted public profile fail closed with zero stdout")

        # Reopen the ORIGINAL old ciphertext after every new operation/refusal.
        result = self.sign("old", "old-origin", old_name, envelope, "bitcoin", 0,
                           label="final-reopen-original-old-Taproot-in-old")
        self.signature(result, SCHEMES["bitcoin"], old["accounts"][0]["bitcoin"])
        for path, digest in self.immutable.items():
            need(sha(path.read_bytes()) == digest, "saved envelope/public response was rewritten")
        for name, path in self.binaries.items():
            need(sha(path.read_bytes()) == self.binary_sha256[name], "frozen executable was rewritten")
        self.passed("all reads/signs/refusals preserve file-store bytes+mtime+inode; saved original envelopes never mutated/re-encrypted; final old Taproot reopen verifies")

    def report(self, error=None):
        state = {name: snapshot(root) for name, root in self.cases.items()}
        return {
            "status": "PASS" if error is None else "FAIL", "error": error,
            "profile": PROFILE, "public_never_fund": True,
            "fixtures": {"hd_seed_hex": PUBLIC_NEVER_FUND_HD_SEED.hex(),
                         "ordinary_secp": "public scalar 1", "ed25519": "RFC8032 test 1"},
            "binaries": {name: {"input_path": str(self.input_binaries[name]),
                                "frozen_path": str(path),
                                "sha256": self.binary_sha256[name],
                                "frozen_sha256_after": sha(path.read_bytes())}
                         for name, path in self.binaries.items()},
            "script_sha256": sha(Path(__file__).read_bytes()),
            "checks_passed": self.checks, "verifications": self.verifications,
            "invocation_count": len(self.calls),
            "refusal_count": sum(row["exit"] != 0 for row in self.calls),
            "store_backends": ["file"], "store_snapshots_opaque": state,
            "disposable_stores_removed": False, "calls": self.calls,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old", required=True, type=Path, help="released v0.1.11 avault binary")
    parser.add_argument("--new", required=True, type=Path, help="new bitcoin-address-types-v1 avault binary")
    parser.add_argument("--artifacts", type=Path, help="new artifact directory (must not exist)")
    args = parser.parse_args()
    old, new = args.old.expanduser().resolve(strict=True), args.new.expanduser().resolve(strict=True)
    need(os.access(old, os.X_OK) and os.access(new, os.X_OK), "binary not executable")
    if args.artifacts:
        artifacts = args.artifacts.expanduser().resolve()
        artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    else:
        artifacts = Path(tempfile.mkdtemp(prefix="hd-bitcoin-compatibility-"))
    check = Check(old, new, artifacts)
    error = None
    try:
        # Public oracle sanity checks; no private derivation or signing in Python.
        need(mul(N) is None and mul(1) == G and sec1("02" + format(G[0], "064x")) == G,
             "public group oracle self-check failed")
        check.run()
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        print("FAIL", error, file=sys.stderr, flush=True)
    finally:
        report = check.report(error)
        shutil.rmtree(check.state)
        report["disposable_stores_removed"] = not check.state.exists()
        report_path = artifacts / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"REPORT {report_path}", flush=True)
        print(f"RESULT {report['status']} invocations={report['invocation_count']} refusals={report['refusal_count']}", flush=True)
    return 1 if error else 0


if __name__ == "__main__":
    sys.exit(main())
