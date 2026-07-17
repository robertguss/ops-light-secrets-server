# Performance baseline (U11.7)

## Named reference host

| Field | Value |
| --- | --- |
| Host name | `local-smoke` (CI/dev substitute) |
| Architecture | `x86_64` / `aarch64` as recorded by the runner |
| Durability | process-local `KvService` audited write path (token/grant not composed; full server path is source-full E2E) |
| Peak intent | tens of concurrent clients, low hundreds of req/s (design envelope) |

## How to record

```bash
cargo bench --bench audited_kv
OLSS_BENCH_ITERS=1000 OLSS_BENCH_HOST=my-host cargo bench --bench audited_kv
```

Commit refreshed JSON lines under `benches/baseline/` when a named-host campaign
runs. Material regressions of audited write p95 require explicit review — the
durable-write-per-read ceiling is accepted product cost (R26), not a bug.

## Smoke (CI)

`cargo bench --bench audited_kv` with default low iteration count is a
correctness/smoke gate, not a baselining campaign.
