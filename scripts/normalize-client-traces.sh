#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-check}
if [[ $mode != check && $mode != promote ]]; then
    printf 'usage: %s [check|promote]\n' "$0" >&2
    exit 64
fi

candidate=$(mktemp -d "${TMPDIR:-/tmp}/olss-client-traces.XXXXXX")
chmod 0700 "$candidate"
cleanup() {
    rm -rf -- "$candidate"
}
trap cleanup EXIT HUP INT TERM

python3 "$root/research/compat/capture/normalize.py" \
    --input "$root/research/compat/capture/observations.json" \
    --output "$candidate"
cargo run --quiet --locked --manifest-path "$root/crates/test-support/Cargo.toml" \
    --bin client_trace_fixture_gate -- \
    "$mode" "$candidate" "$root/tests/fixtures/client-traces"
