#!/usr/bin/env bash
# Verify that a macOS binary carries avault's release code identity: a strict-valid
# Developer ID signature with hardened runtime, the given code identifier and Team ID,
# and exactly the default Developer ID designated requirement (DR) for them.
#
# Keychain approves the master-key item for a DR, so a release whose DR differs in any
# way would re-prompt every user. See docs/DESIGN.md (Appendix C, macOS code identity).
#
# Usage: verify-macos-codesign.sh BINARY IDENTIFIER TEAM_ID
# Exit status: 0 when every check passes, 1 when any check fails, 2 on bad usage.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 BINARY IDENTIFIER TEAM_ID" >&2
    exit 2
fi
binary=$1
identifier=$2
team_id=$3

if [[ ! -f "$binary" ]]; then
    echo "error: $binary is not a file" >&2
    exit 2
fi
# Both values are spliced into requirement-language text below.
if [[ ! "$identifier" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
    echo "error: identifier must be a reverse-DNS code identifier, got '$identifier'" >&2
    exit 2
fi
if [[ ! "$team_id" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "error: TEAM_ID must be a 10-character Apple Team ID, got '$team_id'" >&2
    exit 2
fi

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}
pass() {
    echo "ok: $*"
}

if codesign --verify --strict --verbose=2 "$binary"; then
    pass "codesign --verify --strict"
else
    fail "codesign --verify --strict rejected $binary"
fi

details="$(codesign --display --verbose=4 "$binary" 2>&1)" || {
    printf '%s\n' "$details" >&2
    echo "FAIL: codesign --display could not read the signature" >&2
    exit 1
}
field() {
    printf '%s\n' "$details" | sed -n "s/^$1=//p" | head -n 1
}

actual_identifier="$(field Identifier)"
if [[ "$actual_identifier" == "$identifier" ]]; then
    pass "Identifier=$actual_identifier"
else
    fail "Identifier is '$actual_identifier', expected '$identifier'"
fi

actual_team="$(field TeamIdentifier)"
if [[ "$actual_team" == "$team_id" ]]; then
    pass "TeamIdentifier=$actual_team"
else
    fail "TeamIdentifier is '$actual_team', expected '$team_id'"
fi

# CodeDirectory flag 0x10000 (CS_RUNTIME) is the hardened runtime.
flags="$(printf '%s\n' "$details" | sed -n 's/^CodeDirectory .* flags=\(0x[0-9a-fA-F]*\).*/\1/p' | head -n 1)"
if [[ -n "$flags" ]] && (( flags & 0x10000 )); then
    pass "hardened runtime (flags=$flags)"
else
    fail "hardened runtime flag is missing (flags=${flags:-none})"
fi

# Compare decompiled text with decompiled text: csreq and codesign share the decompiler,
# which quotes a Team ID that starts with a digit and leaves other Team IDs bare.
expected_dr="$(csreq -t -r "=designated => identifier \"$identifier\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = \"$team_id\"")"
if ! actual_dr="$(codesign --display --requirements - "$binary" 2>/dev/null)"; then
    actual_dr="<unreadable>"
fi
if [[ "$actual_dr" == "$expected_dr" ]]; then
    pass "$actual_dr"
else
    fail "designated requirement differs
  expected: $expected_dr
  actual:   $actual_dr"
fi

if (( failures > 0 )); then
    echo "$binary: $failures code identity check(s) failed" >&2
    exit 1
fi
echo "$binary: code identity verified"
