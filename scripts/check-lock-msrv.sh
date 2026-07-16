#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

git ls-files --error-unmatch Cargo.lock >/dev/null
grep -Fqx 'rust-version = "1.85"' Cargo.toml
grep -Fqx 'channel = "1.85.0"' rust-toolchain.toml
grep -Fqx 'msrv = "1.85.0"' clippy.toml

cargo metadata --locked --no-deps --format-version 1 | jq -e '
    .packages | length == 3 and
    any(.[];
        .name == "ops-light-secrets-server" and
        .rust_version == "1.85" and
        any(.targets[]; .name == "ops-light-secrets-server" and .kind == ["bin"])
    ) and
    any(.[]; .name == "test-support" and .rust_version == "1.85") and
    any(.[];
        .name == "ktd2-spike" and
        .rust_version == "1.85" and
        any(.targets[]; .name == "ktd2-spike" and .kind == ["bin"])
    )
' >/dev/null

printf 'Cargo.lock and MSRV: ok\n'
