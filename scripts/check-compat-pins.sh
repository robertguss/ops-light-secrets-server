#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
manifest=$root/research/compat/client-matrix.json

jq -e '
    .schema == 1 and
    .platform == "linux-amd64" and
    (.clients | length == 4) and
    ([.clients[] | select(.product == "vault" and .version == "2.0.3")] | length == 1) and
    ([.clients[] | select(.product == "bao" and .version == "2.6.0")] | length == 1) and
    ([.clients[] | select(.product == "fnox") | .version] | sort == ["1.29.0", "1.30.0"]) and
    all(.clients[];
        (.url | startswith("https://")) and
        (.provenance | startswith("https://")) and
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.archive | test("^[A-Za-z0-9._-]+$")) and
        (.binary == "vault" or .binary == "bao" or .binary == "fnox")
    )
' "$manifest" >/dev/null

duplicates=$(jq -r '.clients[].archive' "$manifest" | sort | uniq -d)
test -z "$duplicates"

printf 'compatibility client pins: ok\n'
