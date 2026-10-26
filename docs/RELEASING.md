# Releasing avault

`avault` ships as manifest-pinned prebuilt binaries. The pipeline is wired
stub-first: until the custody implementation lands, the release workflow still
builds and publishes the current `avault` binary in this repository.

This matches the distribution decision in `docs/DESIGN.md` Section 16, decision
3, and the Avibe integration model in Section 12 and Appendix C.

## Release flow

1. Merge the intended release commit to `master`.
2. Confirm the release commit is on `master`.
3. Confirm the workspace package version matches the intended release version.
4. Create and push a SemVer tag prefixed with `v`, for example `v0.1.0`.
   The release workflow fails fast if the tag version does not match the
   `avault-cli` package version, because Avibe compares the manifest-pinned
   version with the installed binary's self-reported version.
   It also fails if the tagged commit is not reachable from `origin/master`.
5. GitHub Actions runs `.github/workflows/release.yml`.
6. The workflow builds, strips, packages, checksums, and uploads the supported
   platform artifacts. Release builds run with Cargo's committed lockfile via
   `--locked`. macOS binaries are Developer ID signed and notarized before they
   are packaged (see "macOS signing and notarization").
7. The workflow creates the GitHub Release for the tag and uploads
   `manifest.json`.

## Supported targets

| Manifest target | Rust target | Runner |
| --- | --- | --- |
| `macos-arm64` | `aarch64-apple-darwin` | `macos-14` |
| `macos-x64` | `x86_64-apple-darwin` | `macos-15-intel` |
| `linux-x64` | `x86_64-unknown-linux-gnu` | `ubuntu-latest` + `rust:1.86-bullseye` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` + `rust:1.86-bullseye` |
| `windows-x64` | `x86_64-pc-windows-msvc` | `windows-latest` |
| `windows-arm64` | `aarch64-pc-windows-msvc` | `windows-latest` |

Linux artifacts are GNU binaries built inside a Debian 11 / Rust 1.86 container
so Avibe does not inherit the host runner's newer glibc baseline. `windows-arm64`
is best-effort; every other target is required for a release.

## Artifact naming

Each release uploads one tarball and checksum file per supported target:

```text
avault-<version>-<target>.tar.gz
avault-<version>-<target>.tar.gz.sha256
```

The tarball contains a single executable: `avault` on Unix targets and
`avault.exe` on Windows targets.

For tag `v0.1.0`, examples are:

```text
avault-0.1.0-macos-arm64.tar.gz
avault-0.1.0-linux-x64.tar.gz
avault-0.1.0-windows-x64.tar.gz
```

## Manifest format

`manifest.json` is the contract Avibe pins and downloads. It maps each release
version to each target asset and its SHA-256 digest:

```json
{
  "schema_version": 1,
  "versions": {
    "0.1.0": {
      "linux-x64": {
        "asset": "avault-0.1.0-linux-x64.tar.gz",
        "sha256": "<hex sha256>"
      },
      "linux-arm64": {
        "asset": "avault-0.1.0-linux-arm64.tar.gz",
        "sha256": "<hex sha256>"
      },
      "macos-arm64": {
        "asset": "avault-0.1.0-macos-arm64.tar.gz",
        "sha256": "<hex sha256>"
      },
      "macos-x64": {
        "asset": "avault-0.1.0-macos-x64.tar.gz",
        "sha256": "<hex sha256>"
      },
      "windows-x64": {
        "asset": "avault-0.1.0-windows-x64.tar.gz",
        "sha256": "<hex sha256>"
      }
    }
  }
}
```

The digest is the SHA-256 of the `.tar.gz` asset, not the unpacked binary.

## macOS signing and notarization

macOS artifacts are always Developer ID signed, hardened-runtime enabled, and
notarized. There is no unsigned fallback: if any step below fails, the release
job fails and no GitHub Release is published.

The `build` job builds and strips the macOS binaries and hands them over as
`unsigned-macos-*` workflow artifacts. The `macos-artifact` job then signs each
one on a fresh runner in the `apple-signing` environment, which only `v*` tags
can deploy to:

| Target | Signing runner |
| --- | --- |
| `macos-arm64` | `macos-26` |
| `macos-x64` | `macos-26-intel` |

Both runners run macOS 26, the release the Developer ID `.p12` is exported
from. Its Security framework imports both the Keychain Access export and a
`.p12` re-encrypted by OpenSSL 3, which `macos-14` rejects with a misleading
`MAC verification failed`. One runner per architecture lets the job run the
signed binary natively.

### Secrets

The `apple-signing` environment must hold all of these secrets. The job checks
them first and fails, naming the missing ones, when any is absent:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64 of the Developer ID Application `.p12` (`base64 -i DeveloperID.p12`) |
| `APPLE_CERTIFICATE_PASSWORD` | Password of that `.p12` |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: <name> (<TEAM_ID>)` |
| `APPLE_TEAM_ID` | The 10-character Apple Team ID |
| `APPLE_API_KEY` | App Store Connect API key ID |
| `APPLE_API_ISSUER` | App Store Connect API issuer ID |
| `APPLE_API_PRIVATE_KEY` | Raw text of `AuthKey_<key id>.p8` |

Export the `.p12` from Keychain Access (the identity together with its private
key). Do not commit Apple certificates or credentials.

### What the job does

1. Imports the `.p12` into a temporary keychain and checks that it provides a
   valid code-signing identity named `APPLE_SIGNING_IDENTITY`. A wrong password
   or unreadable `.p12` fails the import with an explicit error.
2. Signs with
   `codesign --force --timestamp --options runtime --identifier bot.avibe.avault`.
   No entitlements are added. Hardened runtime has no effect on Keychain access,
   `mlock`, crash-dump hardening, child processes, HTTPS, or the agent socket;
   dyld does drop `DYLD_*` variables from avault's environment, so `deliver run`
   children on macOS do not inherit them.
3. Runs `build-support/verify-macos-codesign.sh`, which requires a strict-valid
   signature, Identifier `bot.avibe.avault`, TeamIdentifier `APPLE_TEAM_ID`, the
   hardened-runtime flag, and exactly the designated requirement below.
4. Notarizes a zip of the binary with `notarytool` and the App Store Connect API
   key, and requires status `Accepted`; otherwise it prints the notarization log
   and fails. A bare Mach-O cannot be stapled, so Gatekeeper looks the ticket up
   online.
5. Always deletes the temporary keychain, the `.p12`, and the `.p8`, even when an
   earlier step failed.
6. Runs the signed binary's `--version`, then packages it in the same
   single-member `avault-<version>-macos-<arch>.tar.gz` that Avibe consumes.

### Code identity contract

Every macOS release must carry this designated requirement (DR), with
`<TEAM_ID>` the Team ID of the signing certificate:

```text
designated => identifier "bot.avibe.avault" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = <TEAM_ID>
```

Keychain grants the standard-tier master key to this DR, so upgrades read the
key without asking the user again. **Never change the code identifier or the
Team.** Either change makes every installed Keychain approval stale and
prompts every user again. Renewing the Developer ID certificate within the same
Team keeps the DR. See `docs/DESIGN.md`, Appendix C, "macOS code identity", for
the one-time migration from ad-hoc releases and for why the `.p12` is
custody-critical.

To exercise the verification script locally against an ad-hoc build:

```sh
cargo build --locked --release --bin avault
strip target/release/avault
codesign --force --options runtime --identifier bot.avibe.avault --sign - target/release/avault
build-support/verify-macos-codesign.sh target/release/avault bot.avibe.avault ABCDE12345
```

An ad-hoc build passes the signature, identifier, and runtime checks and fails
exactly the TeamIdentifier and DR checks.

## How Avibe consumes avault

Avibe pins a compatible `avault` version, selects the matching manifest target
for the host platform, downloads the asset named by `manifest.json`, verifies
the SHA-256 digest, unpacks the `avault` executable, and makes it available on
`PATH` or through `agents.avault.cli_path`.

This is the release-side contract for the Avibe `install_avault()` TODO:
replace the placeholder installer with manifest fetch, target resolution,
checksum verification, unpack, and dependency status reporting as described in
`docs/DESIGN.md` Section 12 and Appendix C.
