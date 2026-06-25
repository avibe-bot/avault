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
   platform artifacts.
7. The workflow creates the GitHub Release for the tag and uploads
   `manifest.json`.

## Supported targets

| Manifest target | Rust target | Runner |
| --- | --- | --- |
| `macos-arm64` | `aarch64-apple-darwin` | `macos-15` |
| `linux-x64` | `x86_64-unknown-linux-musl` | `ubuntu-22.04` |

`linux-x64` is built with the musl target so Avibe can treat it as the generic
x86_64 Linux artifact without inheriting an Ubuntu glibc baseline.

## Artifact naming

Each release uploads one tarball and checksum file per supported target:

```text
avault-<version>-<target>.tar.gz
avault-<version>-<target>.tar.gz.sha256
```

The tarball contains a single executable named `avault`.

For tag `v0.1.0`, examples are:

```text
avault-0.1.0-macos-arm64.tar.gz
avault-0.1.0-linux-x64.tar.gz
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
      "macos-arm64": {
        "asset": "avault-0.1.0-macos-arm64.tar.gz",
        "sha256": "<hex sha256>"
      }
    }
  }
}
```

The digest is the SHA-256 of the `.tar.gz` asset, not the unpacked binary.

## macOS signing and notarization

The release workflow contains a disabled-by-default signing/notarization job for
`macos-arm64`. The build job first uploads an unsigned macOS artifact. A separate
fresh macOS runner downloads that artifact and only runs codesign/notarytool when
all required Apple Developer secrets are available:

- `APPLE_CODESIGN_CERTIFICATE_P12`
- `APPLE_CODESIGN_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`
- `APPLE_ID`
- `APPLE_TEAM_ID`
- `APPLE_APP_SPECIFIC_PASSWORD`

Do not commit Apple certificates or credentials. Supplying these repository
secrets is the remaining sub-task before macOS artifacts should be treated as
production-signed. When the secrets are absent, the workflow republishes the
unsigned stub-first artifact instead of blocking the release.

## How Avibe consumes avault

Avibe pins a compatible `avault` version, selects the matching manifest target
for the host platform, downloads the asset named by `manifest.json`, verifies
the SHA-256 digest, unpacks the `avault` executable, and makes it available on
`PATH` or through `agents.avault.cli_path`.

This is the release-side contract for the Avibe `install_avault()` TODO:
replace the placeholder installer with manifest fetch, target resolution,
checksum verification, unpack, and dependency status reporting as described in
`docs/DESIGN.md` Section 12 and Appendix C.
