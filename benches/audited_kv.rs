//! U11.7: audited KV read/write latency smoke + baseline recorder.
//!
//! Full named-host baselining is documented in benches/BASELINE.md.
//! This binary is the reproducible micro-harness for local/CI smoke.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ops_light_secrets_server::identity::{Capability, GrantRecord, GrantScope};
use ops_light_secrets_server::kv::{KvCatalog, KvService};
use ops_light_secrets_server::raw_target::parse_raw_target;
use serde_json::{Map, json};

const IDENTITY: [u8; 16] = [9; 16];

fn percentile(sorted_ns: &[u128], p: f64) -> u128 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let idx = ((sorted_ns.len() as f64 - 1.0) * p).round() as usize;
    sorted_ns[idx.min(sorted_ns.len() - 1)]
}

fn main() {
    let iterations: usize = std::env::var("OLSS_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let mut catalog = KvCatalog::new(false, 1_800_000_000_000);
    catalog.replace_grants(vec![GrantRecord::new(
        [1; 16],
        IDENTITY,
        "secret".into(),
        GrantScope::Subtree,
        Vec::new(),
        [
            Capability::SecretWrite,
            Capability::SecretReadCurrent,
            Capability::SecretReadHistory,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
    )
    .unwrap()]);
    let service = KvService::new(catalog);
    let write_ep = parse_raw_target(&axum::http::Method::POST, "/v1/secret/data/bench/key").unwrap();
    let read_ep = parse_raw_target(&axum::http::Method::GET, "/v1/secret/data/bench/key").unwrap();
    let mut data = Map::new();
    data.insert("value".into(), json!("bench"));

    service
        .write(IDENTITY, &write_ep, data.clone(), Some(0))
        .unwrap();

    let mut write_ns = Vec::with_capacity(iterations);
    let mut read_ns = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let mut next = Map::new();
        next.insert("value".into(), json!(i));
        let started = Instant::now();
        let _ = service
            .write(IDENTITY, &write_ep, next, Some(i as u64 + 1))
            .unwrap();
        write_ns.push(started.elapsed().as_nanos());
        let started = Instant::now();
        let _ = service.read(IDENTITY, &read_ep).unwrap();
        read_ns.push(started.elapsed().as_nanos());
    }
    write_ns.sort_unstable();
    read_ns.sort_unstable();
    let host = std::env::var("OLSS_BENCH_HOST").unwrap_or_else(|_| "local-smoke".into());
    println!(
        "{}",
        serde_json::json!({
            "schema": 1,
            "host": host,
            "iterations": iterations,
            "write_ns": {
                "p50": percentile(&write_ns, 0.50),
                "p95": percentile(&write_ns, 0.95),
                "p99": percentile(&write_ns, 0.99),
            },
            "read_ns": {
                "p50": percentile(&read_ns, 0.50),
                "p95": percentile(&read_ns, 0.95),
                "p99": percentile(&read_ns, 0.99),
            },
            "notes": "audited in-process KV path; named-host baseline in benches/BASELINE.md"
        })
    );
    let _ = Duration::from_nanos(1);
}
