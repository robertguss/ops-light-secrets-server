#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-check}
if [[ "$mode" != check && "$mode" != promote ]]; then
    echo 'usage: generate-compatibility-doc.sh [check|promote]' >&2
    exit 2
fi

private=$(mktemp -d)
chmod 0700 "$private"
trap 'rm -rf -- "$private"' EXIT
candidate="$private/compatibility.md"

python3 "$root/research/compat/capture/generate_compatibility.py" \
    "$root/tests/fixtures/client-traces" "$candidate"
cargo run --quiet --manifest-path "$root/Cargo.toml" \
    --package test-support --bin compatibility_doc_gate -- \
    "$mode" "$candidate" "$root/docs/compatibility.md"
