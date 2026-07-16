#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

git ls-files --error-unmatch Cargo.lock >/dev/null
grep -Fqx 'rust-version = "1.85"' Cargo.toml
grep -Fqx 'channel = "1.85.0"' rust-toolchain.toml
grep -Fqx 'msrv = "1.85.0"' clippy.toml

cargo metadata --locked --no-deps --format-version 1 | jq -e '
    .packages | length == 1 and
    .[0].name == "ops-light-secrets-server" and
    .[0].rust_version == "1.85" and
    any(.[0].targets[]; .name == "ops-light-secrets-server" and .kind == ["bin"])
' >/dev/null

printf 'Cargo.lock and MSRV: ok\n'
