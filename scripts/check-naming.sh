#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tuple=$root/project-name.toml

require_line() {
    line=$1
    grep -Fqx -- "$line" "$tuple" || {
        printf 'naming mismatch: expected %s\n' "$line" >&2
        exit 1
    }
}

require_line 'decision = "retain"'
require_line 'display_name = "ops-light-secrets-server"'
require_line 'cargo_package = "ops-light-secrets-server"'
require_line 'binary = "ops-light-secrets-server"'
require_line 'repository_slug = "ops-light-secrets-server"'
require_line 'artifact_prefix = "ops-light-secrets-server"'
require_line 'systemd_unit = "ops-light-secrets-server.service"'

remote=$(git -C "$root" remote get-url origin)
case "$remote" in
    */ops-light-secrets-server | */ops-light-secrets-server.git) ;;
    *)
        printf 'naming mismatch: origin repository slug is not ops-light-secrets-server\n' >&2
        exit 1
        ;;
esac

if [ -f "$root/Cargo.toml" ]; then
    grep -Eq '^name = "ops-light-secrets-server"$' "$root/Cargo.toml" || {
        printf 'naming mismatch: Cargo package name\n' >&2
        exit 1
    }
fi

if [ -d "$root/systemd" ]; then
    [ -f "$root/systemd/ops-light-secrets-server.service" ] || {
        printf 'naming mismatch: systemd unit filename\n' >&2
        exit 1
    }
fi

printf 'authoritative naming tuple: ok\n'
