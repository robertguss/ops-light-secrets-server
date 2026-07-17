#!/bin/sh
# Structural gate for U11.2 differential fixtures (pins, corpus, allowlist).
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
pin=$root/tests/fixtures/differential/reference-pin-v1.json
corpus=$root/tests/fixtures/differential/corpus-v1.json
oracle=$root/tests/fixtures/differential/openbao-oracle-v1.json
allowlist=$root/tests/fixtures/differential/allowlist-v1.json
matrix=$root/research/compat/client-matrix.json

for path in "$pin" "$corpus" "$oracle" "$allowlist" "$matrix"; do
    test -f "$path" || {
        printf 'missing differential fixture: %s\n' "$path" >&2
        exit 1
    }
done

jq -e '
    .schema == 1 and
    .reference.product == "openbao" and
    .reference.version == "2.6.0" and
    (.reference.sha256 | test("^[0-9a-f]{64}$")) and
    .reference.configuration.kv_version == 2 and
    .reference.configuration.from_scratch_per_case == true and
    .normalization.schema_version == 1
' "$pin" >/dev/null

bao_sha=$(jq -r '.clients[] | select(.product=="bao" and .version=="2.6.0") | .sha256' "$matrix")
pin_sha=$(jq -r '.reference.sha256' "$pin")
test "$bao_sha" = "$pin_sha"

jq -e '
    .schema == 1 and
    .reference_version == "openbao-2.6.0" and
    (.cases | length) >= 10 and
    all(.cases[]; (.id | length) > 0 and (.probe.method | length) > 0)
' "$corpus" >/dev/null

jq -e '
    .schema == 1 and
    .reference_version == "openbao-2.6.0" and
    (.outcomes | length) >= 10
' "$oracle" >/dev/null

jq -e '
    .schema == 1 and
    .reference_version == "openbao-2.6.0" and
    .implementation_version == "ops-light-secrets-server-0.1.0" and
    all(.entries[];
        (.case | length) > 0 and
        (.reason | length) > 0 and
        (.owner | length) > 0 and
        (.review_by | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and
        (.divergence.kind | length) > 0 and
        (.divergence.field | length) > 0
    )
' "$allowlist" >/dev/null

# Every allowlisted oracle outcome has an allowlist entry, and vice versa.
oracle_allow=$(jq -r '.outcomes | to_entries[] | select(.value.allowlisted==true) | .key' "$oracle" | sort)
list_allow=$(jq -r '.entries[].case' "$allowlist" | sort)
test "$oracle_allow" = "$list_allow"

# Corpus case ids match oracle keys exactly.
corpus_ids=$(jq -r '.cases[].id' "$corpus" | sort)
oracle_ids=$(jq -r '.outcomes | keys[]' "$oracle" | sort)
test "$corpus_ids" = "$oracle_ids"

printf 'differential fixtures: ok\n'
