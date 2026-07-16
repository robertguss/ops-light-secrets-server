#!/usr/bin/env python3
"""Generate the human compatibility contract from normalized trace fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path


DIRECT = ("vault-2.0.3-direct.json", "bao-2.6.0-direct.json")
FNOX = (
    "fnox-1.30.0-vault.json",
    "fnox-1.30.0-bao.json",
    "fnox-1.29.0-vault.json",
    "fnox-1.29.0-bao.json",
)


def load(root: Path, name: str) -> dict:
    with (root / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def validate(root: Path) -> None:
    manifest = load(root, "manifest.json")
    names = {entry["path"] for entry in manifest["files"]}
    expected = set(DIRECT + FNOX)
    if names != expected or manifest["provenance"]["scanner"] != "full-artifact-v1":
        raise ValueError("fixture manifest does not match the pinned compatibility matrix")

    for name in DIRECT:
        fixture = load(root, name)
        routes = [[request["route"] for request in probe["requests"]] for probe in fixture["probes"]]
        if routes != [["seal-status", "leader"], ["health"], ["lookup-self"]]:
            raise ValueError(f"direct probe contract changed: {name}")
        if [request["route"] for request in fixture["approle"]["requests"]] != ["approle-login"]:
            raise ValueError(f"AppRole contract changed: {name}")
        if fixture["token_supply"] != "VAULT_TOKEN" or fixture["tls_root"] != "VAULT_CACERT":
            raise ValueError(f"credential plumbing changed: {name}")

    for name in FNOX:
        fixture = load(root, name)
        if fixture["token_supply"] != "VAULT_TOKEN" or fixture["tls_root"] != "VAULT_CACERT":
            raise ValueError(f"fnox credential plumbing changed: {name}")
        if not fixture["subprocess_argv"] or any(argv[:3] != ["kv", "get", "-field=value"] for argv in fixture["subprocess_argv"]):
            raise ValueError(f"fnox subprocess contract changed: {name}")
        slash_cases = {entry["case"]: len(entry["requests"]) for entry in fixture["paths"]}
        if any(slash_cases[case] != 0 for case in ("leading-slash", "trailing-slash", "double-slash")):
            raise ValueError(f"fnox slash validation changed: {name}")

    expected_fault_counts = {
        "fault-403": 1,
        "fault-404": 2,
        "fault-500": 2,
        "sealed-503": 2,
        "reset": 2,
        "timeout": 1,
    }
    for name in DIRECT + FNOX:
        fixture = load(root, name)
        actual = {entry["scenario"]: entry["request_count"] for entry in fixture["faults"]}
        if actual != expected_fault_counts:
            raise ValueError(f"fault contract changed: {name}")


DOCUMENT = """# Client compatibility

This document is generated from the normalized, synthetic traces in
`tests/fixtures/client-traces/`. It describes only the pinned Linux amd64
clients below. The fixtures, not prose memory, are the evidence. They contain
request shapes and typed metadata, never retained raw headers or response
bodies.

## Supported client matrix

| Client | Backend exercised | Prerequisite executable | Observed read endpoints | Token / TLS root |
| --- | --- | --- | --- | --- |
| Vault CLI 2.0.3 | direct | `vault` 2.0.3 | `GET /v1/sys/internal/ui/mounts/{path}`, then `GET /v1/{mount}/data/{path}` | `VAULT_TOKEN` / `VAULT_CACERT` |
| OpenBao CLI 2.6.0 | direct | `bao` 2.6.0 | same two-request read sequence | `VAULT_TOKEN` / `VAULT_CACERT` |
| fnox 1.30.0 | Vault 2.0.3 | `vault` on `PATH` | fnox runs `vault kv get -field=value {path}`; the CLI performs the two requests above | passed through as `VAULT_TOKEN` / `VAULT_CACERT` |
| fnox 1.30.0 | OpenBao 2.6.0 | Bao installed under executable name `vault` on `PATH` | same fnox subprocess and HTTP sequence | passed through as `VAULT_TOKEN` / `VAULT_CACERT` |
| fnox 1.29.0 | Vault 2.0.3 | `vault` on `PATH` | same fnox subprocess and HTTP sequence | passed through as `VAULT_TOKEN` / `VAULT_CACERT` |
| fnox 1.29.0 | OpenBao 2.6.0 | Bao installed under executable name `vault` on `PATH` | same fnox subprocess and HTTP sequence | passed through as `VAULT_TOKEN` / `VAULT_CACERT` |

The fnox versions do not speak Vault HTTP directly in these traces. The Bao
rungs succeed because fnox resolves an executable named `vault`; an unrenamed
`bao` executable alone is not sufficient.

## Captured method and endpoint contract

| Client operation | Method and path | Captured result |
| --- | --- | --- |
| KV v2 read preflight | `GET /v1/sys/internal/ui/mounts/{mount}/{path}` | required before the data read |
| KV v2 read | `GET /v1/{mount}/data/{path}` | required after a successful preflight |
| status | `GET /v1/sys/seal-status`, then `GET /v1/sys/leader` | both requests are required by Vault 2.0.3 and Bao 2.6.0 |
| health | `GET /v1/sys/health` | one request |
| token lookup | `GET /v1/auth/token/lookup-self` | one request |
| AppRole login | `PUT /v1/auth/approle/login` | one request; body shape has string `role_id` and `secret_id` fields |

These are the operations U0 captured. R1 additionally requires the KV v2
write, version, metadata, deletion, and LIST surface. Their exact response
contracts belong to later contract and differential tests; this document makes
no captured-client claim for them yet. In particular, U0 did not execute LIST,
so root LIST and trailing-empty-segment behavior is unobserved. Until a pinned
LIST capture replaces it, the router uses the narrow provisional rule: LIST is
recognized only through the explicit `LIST` method or `list=true`, and an empty
root/trailing segment is accepted only in that LIST context.

## Path behavior observed during reads

| Input class | Direct Vault / Bao | fnox before subprocess | Server compatibility decision |
| --- | --- | --- | --- |
| space, UTF-8, literal `+` | percent-encodes where needed and reads | passes through | accept canonical raw-target encoding |
| literal `%2F` or `%25` text | emits a double-encoded percent | passes through | reject ambiguous percent/double-encoding rather than aliasing a path |
| `.` or `..` segment | HTTP client normalization changes the target; read fails | subprocess runs and fails | reject |
| leading, trailing, or doubled `/` | direct CLI normalizes and reads | fnox rejects before starting its CLI | do not promise fnox equivalence; canonical server paths only |
| 1,025-byte segment | emits and reads in the capture stub | passes through | later R27 size limits remain authoritative |

## Fault behavior

All six matrix rungs made one request for a preflight `403` or timeout. They
made two requests for preflight `404`, preflight `500`, sealed `503`, and reset
scenarios. Direct CLIs exited 2; fnox exited 1. This records client divergence,
not a requirement to leak backend details or retry unsafe operations.

## Clean-host fnox onboarding (AE8)

1. Install the pinned fnox release and verify the archive digest from
   `research/compat/client-matrix.json`.
2. Install OpenBao 2.6.0 and expose that pinned binary as `vault` on the
   consumer's `PATH`. This is the preferred, MPL-2.0 prerequisite rung.
3. Configure fnox's existing Vault provider with the server address and secret
   path. No fnox source change or protocol shim is needed.
4. Supply the data-audience token through `VAULT_TOKEN` and the trusted server
   CA file through `VAULT_CACERT`. Environment custody belongs to the consumer;
   do not print, commit, or place credentials in argv.
5. Run the actual pinned fnox command and verify that it resolves the expected
   field. The acceptance subject is fnox, with its subprocess and both HTTP
   requests observed.

## Licensing and transport decision

The BUSL exit ladder stops at rung 1: both fnox versions worked with OpenBao
2.6.0 exposed as `vault`. OpenBao 2.6.0 is
[MPL-2.0](https://github.com/openbao/openbao/blob/v2.6.0/LICENSE), and fnox
1.29.0/1.30.0 are [MIT](https://github.com/jdx/fnox/blob/v1.30.0/LICENSE).
Rung 2, a direct-HTTP fnox provider, is
[welcome upstream](https://github.com/jdx/fnox/discussions/615) but is not
needed for v0.1. Rung 3 remains a functional fallback: Vault 2.0.3 is
[BUSL-1.1 with a future MPL change license](https://github.com/hashicorp/vault/blob/v2.0.3/LICENSE),
so a stack requiring it must not be described as fully OSI-licensed. A custom
shim is post-v0.1 work only if later evidence invalidates the cheaper rungs.

## Evidence maintenance

Run `./scripts/check-compat-capture.sh` locally. It replays the observations,
regenerates normalized fixtures, regenerates this document, and requires both a
typed U11.9a provenance report and a clean U11.6 `full-artifact-v1` scan before
comparison or retention. Any client upgrade must update the pinned archive,
checksum, fixtures, and this generated contract together.
"""


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_compatibility.py <fixture-root> <output>")
    validate(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(DOCUMENT, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
