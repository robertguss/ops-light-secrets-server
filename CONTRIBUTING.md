# Contributing

## Ground rules

- Follow `AGENTS.md` and keep changes surgical.
- No secret values in logs, commits, tests, or fixtures (use canaries and
  synthetic tokens only).
- Issue tracking is via `br` / `bv` in `.beads/` — do not hand-edit JSONL as the
  primary write path.
- Do not push or open PRs unless the maintainer asks; local commits on `main`
  are the default for agent work.

## Development checks

Run the same gates operators and CI rely on:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
./scripts/verify.sh --self-test
./scripts/verify.sh fmt
./scripts/verify.sh clippy
./scripts/verify.sh test
```

When `cargo-deny` is installed:

```bash
cargo deny check
```

## Code style

- Rust edition and MSRV are pinned in `Cargo.toml` / `rust-toolchain.toml`.
- Prefer existing modules over new abstractions.
- Tests that claim product behavior must drive real shipped code paths (no
  hard-coded “theater” expectations that pass while the program is broken).

## Compatibility and crypto

- Client pins live in `research/compat/client-matrix.json`.
- Frozen crypto vectors are under `tests/fixtures/` and gated by
  `./scripts/verify.sh crypto-vectors`.

## fnox-aligned contributor discipline

This project applies the spirit of fnox’s CONTRIBUTING checks: keep the tree
buildable with `--locked`, avoid silent dependency drift, document
security-sensitive changes, and refuse to land work that weakens authentication,
audit, or secret-handling guarantees.
