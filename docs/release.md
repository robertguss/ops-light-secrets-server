# Release pipeline (U12.5 / R38)

1. Build release: `cargo build --locked --release`
2. Record `sha256sum target/release/ops-light-secrets-server`
3. Run `./scripts/release/smoke-artifact.sh <binary>`
4. Artifact-smoke E2E: `OLSS_E2E_BINARY=<binary> ./scripts/e2e.sh --profile artifact-smoke --binary <binary>`
5. Publish signed checksums with the release notes; SBOM/provenance optional appetite tier.

Attestations: checksum file is required; SBOM/provenance recommended for secrets servers.
