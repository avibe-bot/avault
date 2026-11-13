#!/usr/bin/env python3
"""Independent PUBLIC / NEVER-FUND HD fixtures. Test-only; NOT production crypto.

Only stdlib + an installed OpenSSL executable. Fixed paths and outputs, no wallet
or credential APIs, no transaction/network calls. BIP39 is confined to this tool.
Initialization is explicit and exclusive; every later run is deterministic/offline.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import argparse
import hashlib
import hmac
import json
import platform
import re
import secrets
import subprocess
import unicodedata

ROOT = Path(__file__).resolve().parent
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HARD = 1 << 31
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
REFERENCE_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])
ASCII_PASSPHRASE = "PUBLIC-NEVER-FUND:ascii-2026"
UNICODE_PASSPHRASE = "PUBLIC-NEVER-FUND:caf\u00e9|\u212b|\u2460|\u334d|\u30ac\u30d0\u30f4\u30a1"


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return hashlib.new("ripemd160", sha256(data)).digest()


def hm(key, message):
    return hmac.new(key, message, hashlib.sha512).digest()


def nfkd(text):
    return unicodedata.normalize("NFKD", text)


def i32(value):
    return value.to_bytes(4, "big")


def i256(value):
    return value.to_bytes(32, "big")


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = ((3 * x1 * x1) * pow(2 * y1, -1, P) if left == right
             else (y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(scalar, point=G):
    assert 0 <= scalar < N
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


@lru_cache(maxsize=None)
def public_key(secret):
    assert 0 < secret < N
    x, y = multiply(secret)
    return bytes([2 + (y & 1)]) + i256(x)


def openssl_public(secret_bytes, curve):
    if curve == "ed25519":
        der = bytes.fromhex("302e020100300506032b657004220420") + secret_bytes
        command = ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"]
        expected_prefix = bytes.fromhex("302a300506032b6570032100")
    else:
        assert curve == "secp256k1"
        der = bytes.fromhex("302e0201010420") + secret_bytes + bytes.fromhex("a00706052b8104000a")
        command = ["openssl", "ec", "-inform", "DER", "-pubout", "-outform", "DER", "-conv_form", "compressed"]
        expected_prefix = bytes.fromhex("3036301006072a8648ce3d020106052b8104000a032200")
    process = subprocess.run(command, input=der, capture_output=True, check=True)
    assert process.stdout.startswith(expected_prefix)
    result = process.stdout[len(expected_prefix):]
    assert len(result) == (32 if curve == "ed25519" else 33)
    return result


def b58check(payload):
    raw = payload + sha256(sha256(payload))[:4]
    zeroes = len(raw) - len(raw.lstrip(b"\0"))
    value = int.from_bytes(raw, "big")
    encoded = ""
    while value:
        value, digit = divmod(value, 58)
        encoded = B58[digit] + encoded
    return "1" * zeroes + encoded


def words5(data):
    accumulator, bits, out = 0, 0, []
    for value in data:
        accumulator = (accumulator << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((accumulator >> bits) & 31)
    if bits:
        out.append((accumulator << (5 - bits)) & 31)
    return out


def polymod(values):
    chk = 1
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                chk ^= generator
    return chk


def segwit(version, program):
    assert (version == 0 and len(program) == 20) or (version == 1 and len(program) == 32)
    hrp = "bc"
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    values = [version] + words5(program)
    checksum = polymod(expanded + values + [0] * 6) ^ (1 if version == 0 else 0x2bc830a3)
    return hrp + "1" + "".join(B32[v] for v in values + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


def taproot_output(compressed_internal):
    # BIP340 lift_x: forget derived SEC1 parity and choose the even-Y point.
    x = int.from_bytes(compressed_internal[1:], "big")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    assert y * y % P == (x * x * x + 7) % P
    even = (x, y if y % 2 == 0 else P - y)
    tag = sha256(b"TapTweak")
    tweak = int.from_bytes(sha256(tag + tag + i256(x)), "big")
    assert tweak < N
    output = add(even, multiply(tweak))
    assert output is not None
    return i256(output[0])


@dataclass(frozen=True)
class Node:
    secret: int
    chain: bytes
    depth: int = 0
    fingerprint: bytes = b"\0" * 4
    index: int = 0

    @classmethod
    def master(cls, seed):
        result = hm(b"Bitcoin seed", seed)
        secret = int.from_bytes(result[:32], "big")
        assert 0 < secret < N
        return cls(secret, result[32:])

    def child(self, index):
        assert 0 <= index <= 0xffffffff
        data = b"\0" + i256(self.secret) if index >= HARD else public_key(self.secret)
        result = hm(self.chain, data + i32(index))
        tweak = int.from_bytes(result[:32], "big")
        secret = (self.secret + tweak) % N
        # Never silently change a frozen path for an invalid child.
        assert tweak < N and secret != 0
        return Node(secret, result[32:], self.depth + 1, hash160(public_key(self.secret))[:4], index)

    def derive(self, path):
        node = self
        for index in parse_path(path):
            node = node.child(index)
        return node

    def extended(self, private=False, version=None):
        if version is None:
            version = 0x0488ade4 if private else 0x0488b21e
        key = b"\0" + i256(self.secret) if private else public_key(self.secret)
        return b58check(i32(version) + bytes([self.depth]) + self.fingerprint + i32(self.index) + self.chain + key)


def parse_path(path):
    # Internal vector reader only. There is no arbitrary-path CLI/interface.
    path = path.replace("<sub>H</sub>", "'")
    assert path == "m" or path.startswith("m/")
    return [int(part.rstrip("'")) + (HARD if part.endswith("'") else 0) for part in path.split("/")[1:]]


def slip10(seed, path):
    result = hm(b"ed25519 seed", seed)
    secret, chain = result[:32], result[32:]
    for index in parse_path(path):
        assert index >= HARD
        result = hm(chain, b"\0" + secret + i32(index))
        secret, chain = result[:32], result[32:]
    return secret, chain


def mnemonic_from_entropy(entropy, wordlist):
    assert len(entropy) in (16, 20, 24, 28, 32)
    checksum_bits = len(entropy) // 4
    value = (int.from_bytes(entropy, "big") << checksum_bits) | (sha256(entropy)[0] >> (8 - checksum_bits))
    count = (len(entropy) * 8 + checksum_bits) // 11
    return " ".join(wordlist[(value >> (11 * (count - 1 - i))) & 2047] for i in range(count))


def seed_from_mnemonic(mnemonic, passphrase):
    return hashlib.pbkdf2_hmac("sha512", nfkd(mnemonic).encode("utf-8"), ("mnemonic" + nfkd(passphrase)).encode("utf-8"), 2048, 64)


def account(seed, root, index):
    paths = {"evm": f"m/44'/60'/0'/0/{index}",
             "bitcoin": f"m/86'/0'/0'/0/{index}",
             "bitcoin_p2pkh": f"m/44'/0'/0'/0/{index}",
             "bitcoin_p2wpkh": f"m/84'/0'/0'/0/{index}"}
    keys = {}
    for name, path in paths.items():
        node = root.derive(path)
        key = public_key(node.secret)
        assert key == openssl_public(i256(node.secret), "secp256k1"), (name, index)
        keys[name] = key
    solana_seed, _ = slip10(seed, f"m/44'/501'/{index}'/0'")
    solana = openssl_public(solana_seed, "ed25519")
    output = taproot_output(keys["bitcoin"])
    return {"account": index, "evm": keys["evm"].hex(), "bitcoin": keys["bitcoin"].hex(),
            "solana": solana.hex(), "bitcoin_p2pkh": keys["bitcoin_p2pkh"].hex(),
            "bitcoin_p2wpkh": keys["bitcoin_p2wpkh"].hex(),
            "addresses": {"p2pkh": b58check(b"\0" + hash160(keys["bitcoin_p2pkh"])),
                          "p2wpkh": segwit(0, hash160(keys["bitcoin_p2wpkh"])),
                          "p2tr": segwit(1, output)}, "bitcoin_output_key": output.hex()}


def source_text(relative):
    return (ROOT / "sources" / relative).read_text()


def official_checks(wordlist):
    counts = {}
    vectors = json.loads(source_text("trezor/python-mnemonic/vectors.json"))["english"]
    for entropy, mnemonic, expected_seed, expected_xprv in vectors:
        assert mnemonic_from_entropy(bytes.fromhex(entropy), wordlist) == mnemonic
        seed = seed_from_mnemonic(mnemonic, "TREZOR")
        assert seed.hex() == expected_seed
        assert Node.master(seed).extended(private=True) == expected_xprv
    counts["bip39_english_vectors"] = len(vectors)
    count = 0
    text = source_text("bitcoin/bips/bip-0032.mediawiki")
    for group in re.split(r"===Test vector \d+===", text)[1:5]:
        seed = bytes.fromhex(re.search(r"Seed \(hex\): ([0-9a-f]+)", group)[1])
        root = Node.master(seed)
        entries = re.findall(r"\* Chain ([^\n]+)\n\*\* ext pub: (\S+)\n\*\* ext prv: (\S+)", group)
        assert entries
        for path, xpub, xprv in entries:
            node = root.derive(path)
            assert node.extended() == xpub
            assert node.extended(private=True) == xprv
            count += 1
    counts["bip32_extended_key_pairs_vectors_1_to_4"] = count
    root = Node.master(seed_from_mnemonic(REFERENCE_MNEMONIC, ""))
    for purpose in (84, 86):
        text = source_text(f"bitcoin/bips/bip-00{purpose}.mediawiki").split("==Test vectors==", 1)[1]
        blocks = re.findall(r"// Account 0, (?:first receiving|second receiving|first change) address = ([^\n]+)\n(.*?)(?=\n\s*//|</pre>)", text, re.S)
        assert len(blocks) == 3
        for path, block in blocks:
            fields = dict(re.findall(r"^\s*(\w+)\s*=\s*(\S+)", block, re.M))
            node = root.derive(path.strip())
            public = public_key(node.secret)
            if purpose == 84:
                assert public.hex() == fields["pubkey"]
                assert segwit(0, hash160(public)) == fields["address"]
            else:
                output = taproot_output(public)
                assert public[1:].hex() == fields["internal_key"]
                assert output.hex() == fields["output_key"]
                assert (b"\x51\x20" + output).hex() == fields["scriptPubKey"]
                assert segwit(1, output) == fields["address"]
                assert node.extended() == fields["xpub"]
                assert node.extended(private=True) == fields["xprv"]
        counts[f"bip{purpose}_official_address_vectors"] = len(blocks)
    slip132 = source_text("satoshilabs/slips/slip-0132.md")
    for purpose, version in ((44, 0x0488b21e), (84, 0x04b24746)):
        pattern = "m/" + str(purpose) + "'/0'/0'\n"
        block = slip132.split(pattern, 1)[1]
        expected_xpub = block.splitlines()[1]
        assert root.derive(pattern.strip()).extended(version=version) == expected_xpub
        addr = block.split("address:\n", 1)[1].splitlines()[0]
        pub = public_key(root.derive(pattern.strip() + "/0/0").secret)
        assert (b58check(b"\0" + hash160(pub)) if purpose == 44 else segwit(0, hash160(pub))) == addr
    counts["slip132_bip44_and_bip84_account_xpub_and_address"] = 2
    text = source_text("satoshilabs/slips/slip-0010.md")
    for curve in ("secp256k1", "ed25519"):
        count = 0
        groups = re.findall(r"### Test vector [12] for " + curve + r"\n(.*?)(?=\n###|\Z)", text, re.S)
        assert len(groups) == 2
        for group in groups:
            seed = bytes.fromhex(re.search(r"Seed \(hex\): ([0-9a-f]+)", group)[1])
            entries = re.findall(r"\* Chain ([^\n]+)\n(.*?)(?=\n\* Chain|\Z)", group, re.S)
            assert len(entries) == 6
            for path, block in entries:
                fields = dict(re.findall(r"\* (chain code|private|public): ([0-9a-f]+)", block))
                if curve == "ed25519":
                    secret, chain = slip10(seed, path)
                    public = b"\0" + openssl_public(secret, curve)
                else:
                    node = Node.master(seed).derive(path)
                    secret, chain = i256(node.secret), node.chain
                    public = public_key(node.secret)
                    assert public == openssl_public(secret, curve)
                assert secret.hex() == fields["private"]
                assert chain.hex() == fields["chain code"]
                assert public.hex() == fields["public"]
                count += 1
        counts[f"slip10_{curve}_official_nodes"] = count
    return counts


def initialize_entropy():
    # Intentionally PUBLIC and permanently unsafe for funds. Never overwrite.
    path = ROOT / "public-entropy.json"
    with path.open("x") as output:
        value = {"warning": "PUBLIC TEST DATA - NEVER FUND - NOT A WALLET",
                 "origin": "Two fresh OS-CSPRNG entropy draws, made once; fixed forever after initialization.",
                 "mnemonics": [{"id": "random12", "words": 12, "entropy_hex": secrets.token_bytes(16).hex()},
                               {"id": "random24", "words": 24, "entropy_hex": secrets.token_bytes(32).hex()}]}
        output.write(json.dumps(value, indent=2) + "\n")
    print("Created public-entropy.json once; NEVER FUND these published test identities")


def build():
    manifest = json.loads((ROOT / "sources-manifest.json").read_text())
    for entry in manifest:
        assert hashlib.sha256((ROOT / entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
    wordlist = source_text("bitcoin/bips/bip-0039/english.txt").splitlines()
    assert len(wordlist) == 2048 and len(set(wordlist)) == 2048
    checks = official_checks(wordlist)
    entropy_input = json.loads((ROOT / "public-entropy.json").read_text())
    assert [(v["id"], v["words"]) for v in entropy_input["mnemonics"]] == [("random12", 12), ("random24", 24)]
    cases = []
    for item in entropy_input["mnemonics"]:
        entropy = bytes.fromhex(item["entropy_hex"])
        assert len(entropy) == (16 if item["words"] == 12 else 32)
        mnemonic = mnemonic_from_entropy(entropy, wordlist)
        assert len(mnemonic.split()) == item["words"]
        assert mnemonic != REFERENCE_MNEMONIC
        for label, passphrase in (("empty", ""), ("ascii", ASCII_PASSPHRASE), ("unicode_nfkd", UNICODE_PASSPHRASE)):
            seed = seed_from_mnemonic(mnemonic, passphrase)
            if label == "unicode_nfkd":
                assert passphrase != nfkd(passphrase)
                assert seed == seed_from_mnemonic(mnemonic, nfkd(passphrase))
                raw_seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048, 64)
                assert seed != raw_seed
            cases.append({"id": item["id"] + "_" + label, "mnemonic": mnemonic,
                          "passphrase": passphrase, "nfkd_passphrase": nfkd(passphrase), "seed_hex": seed.hex(),
                          "accounts": [account(seed, Node.master(seed), index) for index in range(20)]})
    seed = seed_from_mnemonic(REFERENCE_MNEMONIC, "")
    cases.append({"id": "bip39_abandon11_about_empty", "mnemonic": REFERENCE_MNEMONIC,
                  "passphrase": "", "nfkd_passphrase": "", "seed_hex": seed.hex(),
                  "accounts": [account(seed, Node.master(seed), index) for index in range(20)]})
    assert len({case["seed_hex"] for case in cases}) == 7
    odd_internal = sum(bytes.fromhex(a["bitcoin"])[0] == 3 for c in cases for a in c["accounts"])
    even_internal = 140 - odd_internal
    assert odd_internal > 0 and even_internal > 0
    checks.update({"fixture_cases": 7, "accounts_per_case": 20, "total_account_rows": 140,
                   "openssl_secp256k1_fixture_key_comparisons": 560,
                   "openssl_ed25519_fixture_public_keys": 140,
                   "fixture_addresses": 420, "taproot_odd_y_internal_keys": odd_internal,
                   "taproot_even_y_internal_keys": even_internal,
                   "unicode_nfkd_equivalence_and_raw_utf8_inequality_cases": 2})
    return {"sources": [{"url": e["url"], "sha256": e["sha256"]} for e in manifest], "cases": cases}, checks


def official_public_subset():
    """Extract only published public fields; never use Rust/project output."""
    manifest = json.loads((ROOT / "sources-manifest.json").read_text())
    def provenance(suffix):
        entry = next(e for e in manifest if e["file"].endswith(suffix))
        return {"url": entry["url"], "sha256": entry["sha256"]}
    subset = {"warning": "PUBLIC TEST DATA - NEVER FUND", "mnemonic": REFERENCE_MNEMONIC,
              "passphrase": "", "bip84": [], "bip86": [], "slip132": []}
    for purpose in (84, 86):
        name = f"bip-00{purpose}.mediawiki"
        text = source_text("bitcoin/bips/" + name).split("==Test vectors==", 1)[1]
        for path, block in re.findall(r"// Account 0, (?:first receiving|second receiving|first change) address = ([^\n]+)\n(.*?)(?=\n\s*//|</pre>)", text, re.S):
            fields = dict(re.findall(r"^\s*(\w+)\s*=\s*(\S+)", block, re.M))
            names = ("pubkey", "address") if purpose == 84 else ("xpub", "internal_key", "output_key", "scriptPubKey", "address")
            subset[f"bip{purpose}"].append({"source": provenance(name), "path": path.strip(),
                                           **{name: fields[name] for name in names}})
    text = source_text("satoshilabs/slips/slip-0132.md")
    for purpose in (44, 84):
        path = f"m/{purpose}'/0'/0'"
        block = text.split(path + "\n", 1)[1]
        subset["slip132"].append({"source": provenance("slip-0132.md"), "account_path": path,
                                   "account_xpub": block.splitlines()[1],
                                   "first_receiving_path": path + "/0/0",
                                   "address": block.split("address:\n", 1)[1].splitlines()[0]})
    return subset


def main():
    if not __debug__:
        raise RuntimeError("Run without -O/PYTHONOPTIMIZE: fixture validation requires assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--init-public-entropy", action="store_true")
    parser.add_argument("--check", action="store_true", help="recompute and require byte-identical existing JSON")
    args = parser.parse_args()
    if args.init_public_entropy:
        assert not args.check
        initialize_entropy()
        return
    fixture, checks = build()
    data = json.dumps(fixture, ensure_ascii=False, indent=2) + "\n"
    output = ROOT / "hd-public-fixtures.json"
    subset_data = (json.dumps(official_public_subset(), indent=2) + "\n").encode("utf-8")
    subset_path = ROOT / "official-public-vectors.json"
    if args.check:
        assert output.read_bytes() == data.encode("utf-8"), "fixture regeneration differed"
        if subset_path.exists():
            assert subset_path.read_bytes() == subset_data, "official public subset differed"
    else:
        output.write_bytes(data.encode("utf-8"))
        subset_path.write_bytes(subset_data)
    evidence = {"status": "PASS", "python": platform.python_version(),
                "unicode_database": unicodedata.unidata_version,
                "openssl": subprocess.check_output(["openssl", "version"], text=True).strip(),
                "fixture_sha256": hashlib.sha256(data.encode()).hexdigest(), "checks": checks}
    if not args.check:
        (ROOT / "python-verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))

if __name__ == "__main__":
    main()
