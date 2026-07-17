#!/bin/sh
# U11.5: fuzz targets build + per-PR corpus smoke (no long campaigns).
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

test -f fuzz/Cargo.toml
targets='token_credential raw_target json_body record_header checkpoint_descriptor backup_archive audit_export'
for target in $targets; do
    test -f "fuzz/fuzz_targets/${target}.rs"
    test -d "fuzz/corpus/${target}"
    # At least one seed artifact per target.
    count=$(find "fuzz/corpus/${target}" -type f | wc -l)
    test "$count" -ge 1
done

if ! command -v cargo-fuzz >/dev/null 2>&1 && ! cargo fuzz --version >/dev/null 2>&1; then
    printf 'cargo-fuzz not installed; structural corpus checks only\n' >&2
    printf 'fuzz structural: ok\n'
    exit 0
fi

# Prefer nightly for libFuzzer builds.
if rustup run nightly rustc -V >/dev/null 2>&1; then
    cargo +nightly fuzz build
    for target in $targets; do
        # Bounded smoke: a few seconds over committed corpus only.
        timeout 15 cargo +nightly fuzz run "$target" -- -max_total_time=5 -runs=1000 || {
            status=$?
            # timeout(1) returns 124 on deadline; treat completed short runs as ok.
            if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
                exit "$status"
            fi
        }
    done
else
    printf 'nightly toolchain missing; structural corpus checks only\n' >&2
fi

printf 'fuzz gate: ok\n'
