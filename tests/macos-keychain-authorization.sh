#!/usr/bin/env bash
# End-to-end check of the Keychain authorization contract against a real, temporary keychain:
# a binary whose code identity differs from the one that created the master-key item must fail
# without a prompt, with exit status 77 (keychain_authorization_required) and the
# `avault key authorize` hint. See docs/DESIGN.md, Appendix C, "Keychain authorization".
#
# It swaps the user's default keychain and search list for a throwaway keychain while it runs,
# so it refuses to run outside GitHub Actions. It never touches a real bot.avibe.avault item.
#
# Usage: tests/macos-keychain-authorization.sh path/to/avault
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    echo "refusing to run outside GitHub Actions: this replaces the user's default keychain" >&2
    exit 2
fi
if [[ $# -ne 1 ]]; then
    echo "usage: $0 path/to/avault" >&2
    exit 2
fi

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/avault-keychain-authorization.XXXXXX")"
keychain="$work/test.keychain-db"
unquote() { sed -e 's/^[[:space:]]*"//' -e 's/"$//'; }
original_default="$(security default-keychain -d user | unquote)"
original_search_list=()
while IFS= read -r path; do
    original_search_list+=("$path")
done < <(security list-keychains -d user | unquote)
restore() {
    security list-keychains -d user -s ${original_search_list[@]+"${original_search_list[@]}"}
    security default-keychain -d user -s "$original_default"
    security delete-keychain "$keychain" 2>/dev/null || true
    rm -rf "$work"
}
trap restore EXIT

security create-keychain -p avault-test "$keychain"
security unlock-keychain -p avault-test "$keychain"
security list-keychains -d user -s "$keychain"
security default-keychain -d user -s "$keychain"

# Two code identities: the creator owns the item, the other one was never approved.
creator="$work/avault-creator"
other="$work/avault-other"
cp "$1" "$creator"
cp "$1" "$other"
codesign --force --options runtime --identifier bot.avibe.avault.test-creator --sign - "$creator"
codesign --force --options runtime --identifier bot.avibe.avault.test-other --sign - "$other"

export AVAULT_HOME="$work/home"
envelope="$(printf 'not-a-secret' | "$creator" --store keychain seal --name PROBE)"
deliver() {
    "$1" "${@:2}" deliver run --name PROBE --env PROBE \
        --envelope-file <(printf '%s' "$envelope") -- /usr/bin/true
}
deliver "$creator" --store keychain
echo "ok: the creating binary reads the master key"

failures=0
for store in keychain auto; do
    status=0
    stderr="$(deliver "$other" --store "$store" 2>&1 >/dev/null)" || status=$?
    if [[ "$status" -eq 77 && "$stderr" == *'run `avault key authorize`'* ]]; then
        echo "ok: --store $store without authorization exits 77 with the authorize hint"
    else
        echo "FAIL: --store $store exited $status, expected 77 with the authorize hint: $stderr" >&2
        failures=$((failures + 1))
    fi
done
exit "$failures"
