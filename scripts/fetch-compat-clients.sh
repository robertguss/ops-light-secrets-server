#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
manifest=$root/research/compat/client-matrix.json
output=$1
mkdir -p "$output"
chmod 0700 "$output"

jq -r '.clients[] | [.archive, .url, .sha256] | @tsv' "$manifest" |
while IFS="$(printf '\t')" read -r archive url expected; do
    destination=$output/$archive
    curl --fail --location --silent --show-error --output "$destination" "$url"
    printf '%s  %s\n' "$expected" "$destination" | sha256sum --check --status
    printf 'verified %s\n' "$archive"
done
