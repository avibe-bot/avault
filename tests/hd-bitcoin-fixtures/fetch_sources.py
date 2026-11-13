#!/usr/bin/env python3
"""Fetch/verify only the public source bytes in the REQUIRED frozen manifest.

No moving refs, manifest bootstrap, credentials, git, or third-party dependencies.
Run a copy in caller-owned scratch, not in the source repository.
"""
from pathlib import Path
import hashlib
import json
import urllib.request

ROOT = Path(__file__).resolve().parent


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "public-never-fund-fixture-builder"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main():
    manifest_path = ROOT / "sources-manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Copy the frozen sources-manifest.json beside this script; moving-ref bootstrap is forbidden")
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest:
        path = ROOT / entry["file"]
        data = path.read_bytes() if path.exists() else fetch(entry["url"])
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Pinned public source hash mismatch: {entry['file']}")
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f"Verified {len(manifest)} pinned public source files")


if __name__ == "__main__":
    main()
