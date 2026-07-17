# ops-light-secrets-server

A single-binary, Vault KV v2–compatible secrets server for teams too small to
run Vault. It exists for **one workflow**: rotating a credential without an
outage. Every read is audited atomically so that before you revoke upstream you
can see exactly who fetched the old value and who picked up the new one —
**declared, authorized, observed, never collapsed**.

## Ops-light claim (list of refusals)

This project deliberately refuses:

- no cluster / HA consensus
- no external database
- no policy language
- no plugins
- no remote management plane
- no unseal ceremony

Management is on a **local owner-only control socket**. One operator can run
backup, restore, key rotation, and incident response alone. Unmodified `vault`
and `bao` CLIs and **fnox** work against the data plane. The whole tree is
**MIT** — nothing held back.

When you outgrow this design, the honest next step is **OpenBao** (or a full
Vault deployment). That upgrade path is a feature of the positioning, not a
failure of the product.

## Status

M2 recovery-alpha evidence is exercised via
`./scripts/e2e.sh --profile recovery-alpha` on an assembled release-profile
binary. Published-byte artifact smoke is a separate M3/release gate.

## Build and verify

```bash
cargo test --locked --all-targets
./scripts/verify.sh --self-test
./scripts/verify.sh test
```

Compatibility client pins: `./scripts/verify.sh compat-pins`.

Differential corpus (R1): `cargo test --locked --test differential`.

## License

MIT. See [LICENSE](LICENSE).
