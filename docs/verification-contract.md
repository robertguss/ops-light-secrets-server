# Verification Contract (U11.8)

Required local/CI gates (from `scripts/verify-checks.json`):

| Check id | Purpose |
| --- | --- |
| compat-pins | Client pin matrix |
| compat-capture | Capture/normalize fixtures |
| differential | OpenBao differential suite |
| deny | Packaging + cargo-deny |
| fuzz | Decoder fuzz smoke |
| compatibility-doc | Generated docs/compatibility.md drift |
| fmt / clippy / test / doc | Standard Rust gates |
| crypto-vectors / lock-msrv / msrv-* | Crypto + MSRV |
| harness-* / canary-gate | Observability + R25 |

Epic closes require the fullest practical local subset. Leaf closes use targeted tests.
