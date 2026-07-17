#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
manifest=$root/tests/fixtures/crypto-fixtures-manifest-v1.json
fixture=$root/tests/fixtures/crypto-vectors-v1.json
temporary=$(mktemp "${TMPDIR:-/tmp}/olss-crypto-vectors.XXXXXX")
trap 'rm -f "$temporary"' EXIT

cd "$root"
jq -e '.schema == 1 and (.architectures | sort == ["aarch64", "x86_64"])' "$manifest" >/dev/null
while IFS=$'\t' read -r path expected; do
    actual=$(sha256sum "$root/$path" | awk '{print $1}')
    [[ $actual == "$expected" ]] || {
        printf 'crypto fixture hash drift: %s\n' "$path" >&2
        exit 1
    }
done < <(jq -r '.fixtures[] | [.path, .sha256] | @tsv' "$manifest")

cargo run --quiet --locked --example crypto_fixture_generator >"$temporary"
if [[ ${1:-} == --regenerate ]]; then
    mv "$temporary" "$fixture"
    trap - EXIT
    printf 'regenerated %s; update manifest hash only after reviewing byte drift\n' "$fixture"
    exit 0
fi
cmp "$temporary" "$fixture" || {
    printf 'crypto vector byte drift; explicit reviewed regeneration required\n' >&2
    exit 1
}

case $(uname -m) in
    x86_64) architecture=x86_64 ;;
    aarch64|arm64) architecture=aarch64 ;;
    *) printf 'unsupported crypto-vector architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
if [[ -n ${OLSS_EXPECT_ARCHITECTURE:-} && $architecture != "$OLSS_EXPECT_ARCHITECTURE" ]]; then
    printf 'crypto-vector runner architecture mismatch: expected=%s actual=%s\n' "$OLSS_EXPECT_ARCHITECTURE" "$architecture" >&2
    exit 1
fi
cargo test --quiet --locked --test crypto_fixtures
printf 'crypto vectors verified byte-identically on %s\n' "$architecture"
