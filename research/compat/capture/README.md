# Pinned-client capture harness

This directory records the observed compatibility contract for Vault 2.0.3,
OpenBao 2.6.0, and fnox 1.30.0/1.29.0. It uses only synthetic canaries and a
locally generated one-day TLS certificate. `run_capture.py` verifies the pinned
archive hashes before executing anything.

Run locally (never as an automatic CI job):

```sh
python3 run_capture.py --archives /path/to/verified/archives --output observations.json
python3 replay.py observations.json
python3 -m unittest discover -s . -p 'test_*.py' -v
```

The driver creates one mode-0700 temporary tree. Raw request records, generated
TLS private key, configs, wrapper logs, and client stdout/stderr stay there and
are removed by `TemporaryDirectory` on success or failure. Signal handlers stop
active recorder children before that removal. The normalized output retains
header names/presence and JSON value types, never header values, body values,
tokens, credentials, cookies, or TLS private material. No secure-erasure claim
is made for CoW filesystems or SSDs.

## Recorded answers

The committed observation was captured on Linux amd64 with the hashes in
`../client-matrix.json`.

1. Vault and Bao KV reads each call mount preflight then KV v2 read. Explicit
   probes call seal-status followed by leader, health, and lookup-self. AppRole calls login with
   PUT. fnox itself makes no HTTP request: both pinned versions spawn
   `vault kv get -field=value <path>`, whose selected CLI then makes the same
   preflight/read pair.
2. All rungs receive the token as `VAULT_TOKEN` and the generated CA root as
   `VAULT_CACERT`. Normalized records retain only that the token header existed.
3. Both fnox versions work without the BUSL Vault binary when OpenBao 2.6.0 is
   exposed under the executable name `vault` in a private PATH wrapper. Their
   subprocess argv and normalized HTTP requests match the Vault-backed rung.
4. Space becomes `%20`, UTF-8 becomes uppercase UTF-8 percent octets, literal
   `%2F`/`%25` are escaped again as `%252F`/`%2525`, and `+` stays literal.
   Vault/Bao remove leading/trailing/double slashes, normalize `.`/`..`, and
   emit the 1025-byte segment. fnox rejects leading/trailing/double slash
   values before spawning the CLI; its other emitted cases match directly.

For each client, 403 stops after one request; 404 reaches the second request;
500, sealed 503, and reset each produce two attempts; timeout produces one
request under the bounded client timeout. `replay.py` freezes these stable
semantics while intentionally ignoring wall-clock duration.

The canned response keys were derived by querying the pinned OpenBao 2.6.0 dev
server locally for mount preflight, seal status, health, KV v2 read, token
lookup-self, and AppRole login. Only key/type shapes were transferred; the live
server data, raw log, root token, and process tree were destroyed after the
private capture session.
