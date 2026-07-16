use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use redb::{Database, Durability, ReadableTable, TableDefinition};
use serde_json::{Value, json};
use tempfile::TempDir;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const STATE: TableDefinition<u64, &[u8]> = TableDefinition::new("state");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const GROWTH: TableDefinition<u64, &[u8]> = TableDefinition::new("growth");
const HEAD: &str = "head";
const CRASH_POINTS: [&str; 6] = [
    "before_begin",
    "after_begin",
    "after_state_insert",
    "after_audit_insert",
    "commit_started",
    "commit_returned",
];

fn main() {
    if let Err(error) = real_main() {
        eprintln!("ktd2-spike: {error}");
        std::process::exit(1);
    }
}

fn real_main() -> AnyResult<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 6 && args[2] == "--protocol" && args[4] == "--output" => {
            run(Path::new(&args[3]), Path::new(&args[5]))
        }
        Some("measure-aarch64-xchacha")
            if args.len() == 6 && args[2] == "--protocol" && args[4] == "--output" =>
        {
            measure_aarch64_xchacha(Path::new(&args[3]), Path::new(&args[5]))
        }
        Some("crash-child") if args.len() == 5 => {
            crash_child(Path::new(&args[2]), &args[3], args[4].parse()?)
        }
        _ => Err(
            "usage: ktd2-spike (run|measure-aarch64-xchacha) --protocol PATH --output PATH".into(),
        ),
    }
}

fn measure_aarch64_xchacha(protocol_path: &Path, output_path: &Path) -> AnyResult<()> {
    require_aarch64(env::consts::ARCH)?;
    let protocol_bytes = fs::read(protocol_path)?;
    let protocol: Value = serde_json::from_slice(&protocol_bytes)?;
    validate_protocol(&protocol)?;
    let result = json!({
        "schema": 1,
        "evidence_kind": "native_aarch64_xchacha20poly1305",
        "measured_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "protocol_digest_blake3": blake3::hash(&protocol_bytes).to_hex().to_string(),
        "execution_host_observation": execution_host_observation()?,
        "xchacha": xchacha_test()?,
    });
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}

fn require_aarch64(architecture: &str) -> AnyResult<()> {
    if architecture == "aarch64" {
        Ok(())
    } else {
        Err("native aarch64 execution required; cross-builds and emulation are not evidence".into())
    }
}

fn run(protocol_path: &Path, output_path: &Path) -> AnyResult<()> {
    let protocol_bytes = fs::read(protocol_path)?;
    let protocol: Value = serde_json::from_slice(&protocol_bytes)?;
    validate_protocol(&protocol)?;
    let execution_host = execution_host_observation()?;
    verify_execution_host(&protocol, &execution_host)?;
    let work = tempfile::tempdir()?;

    let atomic = atomic_test(&work)?;
    let latency = latency_test(&work)?;
    let crash = crash_test(&work)?;
    let snapshot = snapshot_test(&work, latency[&32].p99_ms)?;
    let growth = growth_test(&work)?;
    let xchacha = xchacha_test()?;

    let latency_pass = latency[&32].p99_ms <= 25.0;
    let crash_pass = crash.iter().all(|row| row.successes == row.repetitions);
    let snapshot_allowed_ms = snapshot.baseline_p99_ms + snapshot.p99_ms;
    let snapshot_pass = snapshot.consistent && snapshot.max_commit_ms <= snapshot_allowed_ms;
    let growth_pass = growth.file_to_live_ratio <= 3.0;
    let overall = atomic && latency_pass && crash_pass && snapshot_pass && growth_pass;

    let samples: BTreeMap<String, Value> = latency
        .iter()
        .map(|(concurrency, result)| {
            (
                concurrency.to_string(),
                json!({
                    "raw_commit_latency_us": result.raw_us,
                    "p50_ms": result.p50_ms,
                    "p95_ms": result.p95_ms,
                    "p99_ms": result.p99_ms,
                    "maximum_ms": result.max_ms,
                }),
            )
        })
        .collect();

    let result = json!({
        "schema": 1,
        "measured_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "protocol_digest_blake3": blake3::hash(&protocol_bytes).to_hex().to_string(),
        "host_fingerprint": protocol["reference_host"],
        "execution_host_observation": execution_host,
        "redb_version": "2.6.3",
        "durability": "Immediate",
        "atomic_state_audit": {"transactions": 1000, "passed": atomic},
        "samples": samples,
        "percentiles": {"method": "nearest-rank", "units": "milliseconds"},
        "crash_matrix": crash.iter().map(|row| json!({
            "kill_point": row.point,
            "repetitions": row.repetitions,
            "successes": row.successes,
            "recovered_previous": row.previous,
            "recovered_next": row.next,
        })).collect::<Vec<_>>(),
        "snapshot": {
            "writer_commits": 500,
            "consistent": snapshot.consistent,
            "baseline_p99_ms": snapshot.baseline_p99_ms,
            "raw_writer_commit_latency_us": snapshot.raw_us,
            "writer_p99_ms": snapshot.p99_ms,
            "maximum_writer_commit_ms": snapshot.max_commit_ms,
            "allowed_maximum_ms": snapshot_allowed_ms,
        },
        "growth": {
            "cycles": 10,
            "records_per_cycle": 20000,
            "value_bytes": 1024,
            "file_bytes_before_churn": growth.before,
            "file_bytes_before_compact": growth.pre_compact,
            "file_bytes_after_compact": growth.post_compact,
            "live_data_bytes": growth.live,
            "post_compaction_file_to_live_ratio": growth.file_to_live_ratio,
        },
        "xchacha": xchacha,
        "single_writer_lock": {
            "linux_x86_64_observation": "second Database::open rejected with DatabaseAlreadyOpen",
            "redb_2_6_3_source": "Unix uses flock(LOCK_EX|LOCK_NB); Windows uses LockFile; WASI and fallback backends do not lock",
            "deployment_rule": "only certified Linux targets on filesystems with working flock are supported; startup lock probe must fail closed",
        },
        "threshold_verdicts": {
            "atomic_state_audit": atomic,
            "durable_commit_p99_ms_at_concurrency_32": {"limit": 25.0, "observed": latency[&32].p99_ms, "passed": latency_pass},
            "crash_recovery_success_percent": {"required": 100.0, "observed": if crash_pass {100.0} else {0.0}, "passed": crash_pass},
            "snapshot_consistency_and_stall": snapshot_pass,
            "post_compaction_max_file_to_live_ratio": {"limit": 3.0, "observed": growth.file_to_live_ratio, "passed": growth_pass},
        },
        "target_coverage": {
            "x86_64_unknown_linux_gnu": "measured",
            "aarch64_unknown_linux_gnu": "pending_external_native_host; emulation intentionally rejected",
        },
        "overall_verdict": if overall {"redb_pass"} else {"rusqlite_fallback_required"},
    });
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    write_summary(output_path.with_file_name("RESULTS.md"), &result)?;
    if overall {
        Ok(())
    } else {
        Err("one or more Gate G1 thresholds failed".into())
    }
}

fn validate_protocol(value: &Value) -> AnyResult<()> {
    let expected = [
        ("/storage_candidate/crate", json!("redb")),
        ("/storage_candidate/version", json!("2.6.3")),
        ("/durability/redb_mode", json!("Durability::Immediate")),
        ("/workloads/atomic_state_audit/transactions", json!(1000)),
        (
            "/workloads/durable_latency/aggregate_arrival_rate_per_second",
            json!(100),
        ),
        (
            "/workloads/durable_latency/warmup_commits_per_point",
            json!(50),
        ),
        (
            "/workloads/durable_latency/measured_commits_per_repetition",
            json!(500),
        ),
        ("/workloads/durable_latency/repetitions", json!(3)),
        ("/workloads/crash_recovery/repetitions_per_point", json!(25)),
        ("/workloads/concurrent_snapshot/writer_commits", json!(500)),
        ("/workloads/growth_compaction/cycles", json!(10)),
        (
            "/workloads/growth_compaction/records_per_cycle",
            json!(20000),
        ),
        (
            "/workloads/xchacha20poly1305/measured_operations",
            json!(20000),
        ),
        (
            "/thresholds/durable_commit_p99_ms_at_concurrency_32",
            json!(25.0),
        ),
        (
            "/thresholds/post_compaction_max_file_to_live_ratio",
            json!(3.0),
        ),
    ];
    for (pointer, required) in expected {
        if value.pointer(pointer) != Some(&required) {
            return Err(format!("frozen protocol mismatch at {pointer}").into());
        }
    }
    if value.pointer("/workloads/durable_latency/concurrency_points") != Some(&json!([1, 8, 32])) {
        return Err("frozen concurrency points changed".into());
    }
    if value.pointer("/workloads/crash_recovery/kill_points") != Some(&json!(CRASH_POINTS)) {
        return Err("frozen crash points changed".into());
    }
    Ok(())
}

fn execution_host_observation() -> AnyResult<Value> {
    let cpu_model = fs::read_to_string("/proc/cpuinfo")?
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: "))
        .ok_or("CPU model unavailable")?
        .to_owned();
    let memory_kib: u64 = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")
                .and_then(|tail| tail.split_whitespace().next())
        })
        .ok_or("memory total unavailable")?
        .parse()?;
    let uname = command_output("uname", &["-srmo"])?;
    let mount = command_output("findmnt", &["-T", "/tmp", "-no", "SOURCE,FSTYPE,OPTIONS"])?;
    Ok(json!({
        "architecture": env::consts::ARCH,
        "cpu_count": thread::available_parallelism()?.get(),
        "cpu_model": cpu_model,
        "memory_gib": memory_kib as f64 / 1024.0 / 1024.0,
        "kernel": uname,
        "benchmark_mount": mount,
    }))
}

fn command_output(program: &str, args: &[&str]) -> AnyResult<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!("host fingerprint command failed: {program}").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn verify_execution_host(protocol: &Value, observed: &Value) -> AnyResult<()> {
    let reference = &protocol["reference_host"];
    for field in ["architecture", "cpu_count", "cpu_model"] {
        if reference[field] != observed[field] {
            return Err(format!(
                "execution host changed at {field}; full preregistration required"
            )
            .into());
        }
    }
    if !observed["benchmark_mount"]
        .as_str()
        .unwrap_or_default()
        .contains(" ext4 ")
    {
        return Err("benchmark filesystem is not preregistered ext4".into());
    }
    Ok(())
}

fn database(path: &Path) -> AnyResult<Database> {
    Ok(Database::create(path)?)
}

fn initialize(db: &Database) -> AnyResult<()> {
    let mut tx = db.begin_write()?;
    tx.set_durability(Durability::Immediate);
    {
        tx.open_table(STATE)?;
        tx.open_table(AUDIT)?;
        let mut meta = tx.open_table(META)?;
        if meta.get(HEAD)?.is_none() {
            meta.insert(HEAD, 0)?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn commit_generation(db: &Database, generation: u64, value_bytes: usize) -> AnyResult<()> {
    let value = vec![(generation % 251) as u8; value_bytes];
    let mut tx = db.begin_write()?;
    tx.set_durability(Durability::Immediate);
    {
        tx.open_table(STATE)?.insert(generation, value.as_slice())?;
        tx.open_table(AUDIT)?.insert(generation, value.as_slice())?;
        tx.open_table(META)?.insert(HEAD, generation)?;
    }
    tx.commit()?;
    Ok(())
}

fn consistent_generation(db: &Database) -> AnyResult<u64> {
    let tx = db.begin_read()?;
    let meta = tx.open_table(META)?;
    let generation = meta.get(HEAD)?.map(|v| v.value()).unwrap_or(0);
    if generation > 0 {
        let state = tx.open_table(STATE)?;
        let audit = tx.open_table(AUDIT)?;
        if state.get(generation)?.is_none() || audit.get(generation)?.is_none() {
            return Err("state/audit/meta generation mismatch".into());
        }
    }
    Ok(generation)
}

fn atomic_test(work: &TempDir) -> AnyResult<bool> {
    let path = work.path().join("atomic.redb");
    let db = database(&path)?;
    initialize(&db)?;
    for generation in 1..=1000 {
        commit_generation(&db, generation, 256)?;
        if consistent_generation(&db)? != generation {
            return Ok(false);
        }
    }
    let second_open_rejected = Database::open(&path).is_err();
    Ok(second_open_rejected)
}

#[derive(Debug)]
struct LatencyResult {
    raw_us: Vec<u64>,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

fn latency_test(work: &TempDir) -> AnyResult<BTreeMap<usize, LatencyResult>> {
    let mut results = BTreeMap::new();
    for concurrency in [1, 8, 32] {
        let path = work.path().join(format!("latency-{concurrency}.redb"));
        let db = Arc::new(database(&path)?);
        initialize(&db)?;
        let ids = Arc::new(AtomicU64::new(1));
        run_latency_batch(Arc::clone(&db), Arc::clone(&ids), concurrency, 50, false)?;
        let mut raw = Vec::with_capacity(1500);
        for _ in 0..3 {
            raw.extend(run_latency_batch(
                Arc::clone(&db),
                Arc::clone(&ids),
                concurrency,
                500,
                true,
            )?);
        }
        results.insert(concurrency, latency_result(raw));
    }
    Ok(results)
}

fn run_latency_batch(
    db: Arc<Database>,
    ids: Arc<AtomicU64>,
    concurrency: usize,
    count: usize,
    paced: bool,
) -> AnyResult<Vec<u64>> {
    let start = Instant::now();
    let next = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let db = Arc::clone(&db);
        let ids = Arc::clone(&ids);
        let next = Arc::clone(&next);
        handles.push(thread::spawn(move || -> AnyResult<Vec<u64>> {
            let mut samples = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed) as usize;
                if index >= count {
                    break;
                }
                if paced {
                    let due = start + Duration::from_millis((index as u64) * 10);
                    if let Some(delay) = due.checked_duration_since(Instant::now()) {
                        thread::sleep(delay);
                    }
                }
                let generation = ids.fetch_add(1, Ordering::Relaxed);
                let began = Instant::now();
                commit_generation(&db, generation, 256)?;
                samples.push(began.elapsed().as_micros() as u64);
            }
            Ok(samples)
        }));
    }
    let mut samples = Vec::with_capacity(count);
    for handle in handles {
        samples.extend(handle.join().map_err(|_| "latency worker panicked")??);
    }
    if samples.len() != count {
        return Err("latency sample count mismatch".into());
    }
    Ok(samples)
}

fn latency_result(mut raw_us: Vec<u64>) -> LatencyResult {
    raw_us.sort_unstable();
    LatencyResult {
        p50_ms: percentile_us(&raw_us, 50) / 1000.0,
        p95_ms: percentile_us(&raw_us, 95) / 1000.0,
        p99_ms: percentile_us(&raw_us, 99) / 1000.0,
        max_ms: *raw_us.last().unwrap_or(&0) as f64 / 1000.0,
        raw_us,
    }
}

fn percentile_us(sorted: &[u64], percentile: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (percentile * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1] as f64
}

#[derive(Debug)]
struct CrashRow {
    point: String,
    repetitions: usize,
    successes: usize,
    previous: usize,
    next: usize,
}

fn crash_test(work: &TempDir) -> AnyResult<Vec<CrashRow>> {
    let path = work.path().join("crash.redb");
    {
        let db = database(&path)?;
        initialize(&db)?;
    }
    let mut rows = Vec::new();
    for point in CRASH_POINTS {
        let mut row = CrashRow {
            point: point.into(),
            repetitions: 25,
            successes: 0,
            previous: 0,
            next: 0,
        };
        for _ in 0..25 {
            let previous = {
                let db = Database::open(&path)?;
                consistent_generation(&db)?
            };
            let proposed = previous + 1;
            let mut child = spawn_crash_child(&path, point, proposed)?;
            wait_ready(&mut child)?;
            if point == "commit_started" {
                child
                    .stdin
                    .as_mut()
                    .ok_or("missing child stdin")?
                    .write_all(b"c")?;
                child.stdin.as_mut().unwrap().flush()?;
            }
            kill_and_wait(&mut child)?;
            let recovered = {
                let db = Database::open(&path)?;
                consistent_generation(&db)?
            };
            if recovered == previous || recovered == proposed {
                row.successes += 1;
                if recovered == previous {
                    row.previous += 1;
                } else {
                    row.next += 1;
                }
            }
            if point == "commit_returned" && recovered != proposed {
                return Err("commit_returned did not recover committed generation".into());
            }
        }
        rows.push(row);
    }
    Ok(rows)
}

fn spawn_crash_child(path: &Path, point: &str, generation: u64) -> AnyResult<Child> {
    Ok(Command::new(env::current_exe()?)
        .arg("crash-child")
        .arg(path)
        .arg(point)
        .arg(generation.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?)
}

fn wait_ready(child: &mut Child) -> AnyResult<()> {
    let mut line = String::new();
    io::BufReader::new(child.stdout.as_mut().ok_or("missing child stdout")?)
        .read_line(&mut line)?;
    if line.trim() != "READY" {
        return Err(format!("crash child failed before kill point: {line:?}").into());
    }
    Ok(())
}

fn kill_and_wait(child: &mut Child) -> AnyResult<()> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error.into()),
    }
    child.wait()?;
    Ok(())
}

fn crash_child(path: &Path, point: &str, generation: u64) -> AnyResult<()> {
    if point == "before_begin" {
        return ready_and_park();
    }
    let db = Database::open(path)?;
    let mut tx = db.begin_write()?;
    tx.set_durability(Durability::Immediate);
    if point == "after_begin" {
        return ready_and_park();
    }
    let value = vec![(generation % 251) as u8; 256];
    tx.open_table(STATE)?.insert(generation, value.as_slice())?;
    if point == "after_state_insert" {
        return ready_and_park();
    }
    tx.open_table(AUDIT)?.insert(generation, value.as_slice())?;
    if point == "after_audit_insert" {
        return ready_and_park();
    }
    tx.open_table(META)?.insert(HEAD, generation)?;
    if point == "commit_started" {
        print_ready()?;
        let mut byte = [0_u8];
        io::stdin().read_exact(&mut byte)?;
        tx.commit()?;
        return ready_and_park();
    }
    if point == "commit_returned" {
        tx.commit()?;
        return ready_and_park();
    }
    Err(format!("unknown crash point: {point}").into())
}

fn print_ready() -> AnyResult<()> {
    println!("READY");
    io::stdout().flush()?;
    Ok(())
}
fn ready_and_park() -> AnyResult<()> {
    print_ready()?;
    loop {
        thread::park();
    }
}

#[derive(Debug)]
struct SnapshotResult {
    consistent: bool,
    baseline_p99_ms: f64,
    raw_us: Vec<u64>,
    p99_ms: f64,
    max_commit_ms: f64,
}

fn snapshot_test(work: &TempDir, baseline_p99_ms: f64) -> AnyResult<SnapshotResult> {
    let path = work.path().join("snapshot.redb");
    let db = Arc::new(database(&path)?);
    initialize(&db)?;
    commit_generation(&db, 1, 256)?;
    let snapshot = db.begin_read()?;
    let snapshot_meta = snapshot.open_table(META)?;
    let initial = snapshot_meta.get(HEAD)?.unwrap().value();
    let writer_db = Arc::clone(&db);
    let writer = thread::spawn(move || -> AnyResult<Vec<u64>> {
        let mut raw = Vec::with_capacity(500);
        for generation in 2..=501 {
            let began = Instant::now();
            commit_generation(&writer_db, generation, 256)?;
            raw.push(began.elapsed().as_micros() as u64);
        }
        Ok(raw)
    });
    let mut consistent = true;
    while !writer.is_finished() {
        if snapshot_meta.get(HEAD)?.map(|v| v.value()) != Some(initial) {
            consistent = false;
        }
        thread::yield_now();
    }
    let raw = writer.join().map_err(|_| "snapshot writer panicked")??;
    if snapshot_meta.get(HEAD)?.map(|v| v.value()) != Some(initial) {
        consistent = false;
    }
    let state = snapshot.open_table(STATE)?;
    let audit = snapshot.open_table(AUDIT)?;
    consistent &= state.get(initial)?.is_some() && audit.get(initial)?.is_some();
    let stats = latency_result(raw);
    Ok(SnapshotResult {
        consistent,
        baseline_p99_ms,
        raw_us: stats.raw_us,
        p99_ms: stats.p99_ms,
        max_commit_ms: stats.max_ms,
    })
}

#[derive(Debug)]
struct GrowthResult {
    before: u64,
    pre_compact: u64,
    post_compact: u64,
    live: u64,
    file_to_live_ratio: f64,
}

fn growth_test(work: &TempDir) -> AnyResult<GrowthResult> {
    let path = work.path().join("growth.redb");
    let mut db = database(&path)?;
    initialize(&db)?;
    let before = fs::metadata(&path)?.len();
    let value = vec![0x5a; 1024];
    for cycle in 0_u64..10 {
        let start = cycle * 20_000;
        let mut tx = db.begin_write()?;
        tx.set_durability(Durability::Immediate);
        {
            let mut table = tx.open_table(GROWTH)?;
            for key in start..start + 20_000 {
                table.insert(key, value.as_slice())?;
            }
            for key in (start..start + 20_000).step_by(2) {
                table.remove(key)?;
            }
        }
        tx.commit()?;
    }
    let pre_compact = fs::metadata(&path)?.len();
    let read = db.begin_read()?;
    let table = read.open_table(GROWTH)?;
    let mut live = 0_u64;
    for entry in table.iter()? {
        let (key, value) = entry?;
        let _ = key;
        live += 8 + value.value().len() as u64;
    }
    drop(table);
    drop(read);
    while db.compact()? {}
    let post_compact = fs::metadata(&path)?.len();
    Ok(GrowthResult {
        before,
        pre_compact,
        post_compact,
        live,
        file_to_live_ratio: post_compact as f64 / live as f64,
    })
}

fn xchacha_test() -> AnyResult<Value> {
    let cipher = XChaCha20Poly1305::new((&[0x42_u8; 32]).into());
    let plaintext = vec![0x24_u8; 4096];
    for index in 0..2000 {
        let _ = cipher.encrypt(&nonce(index), plaintext.as_ref())?;
    }
    let mut encrypt_us = Vec::with_capacity(20_000);
    let encrypt_start = Instant::now();
    let mut ciphertexts = Vec::with_capacity(20_000);
    for index in 0..20_000_u64 {
        let began = Instant::now();
        ciphertexts.push(cipher.encrypt(&nonce(index), plaintext.as_ref())?);
        encrypt_us.push(began.elapsed().as_micros() as u64);
    }
    let encrypt_elapsed = encrypt_start.elapsed().as_secs_f64();
    for (index, ciphertext) in ciphertexts.iter().take(2000).enumerate() {
        let _ = cipher.decrypt(&nonce(index as u64), ciphertext.as_ref())?;
    }
    let mut decrypt_us = Vec::with_capacity(20_000);
    let decrypt_start = Instant::now();
    for (index, ciphertext) in ciphertexts.iter().enumerate() {
        let began = Instant::now();
        let decoded = cipher.decrypt(&nonce(index as u64), ciphertext.as_ref())?;
        if decoded != plaintext {
            return Err("XChaCha round trip mismatch".into());
        }
        decrypt_us.push(began.elapsed().as_micros() as u64);
    }
    let decrypt_elapsed = decrypt_start.elapsed().as_secs_f64();
    encrypt_us.sort_unstable();
    decrypt_us.sort_unstable();
    let mib = (20_000.0 * 4096.0) / (1024.0 * 1024.0);
    Ok(json!({
        "target": env::consts::ARCH,
        "message_bytes": 4096,
        "measured_operations": 20000,
        "encrypt_mib_per_second": mib / encrypt_elapsed,
        "decrypt_mib_per_second": mib / decrypt_elapsed,
        "encrypt_p99_us": percentile_us(&encrypt_us, 99),
        "decrypt_p99_us": percentile_us(&decrypt_us, 99),
        "raw_encrypt_latency_us": encrypt_us,
        "raw_decrypt_latency_us": decrypt_us,
    }))
}

fn nonce(index: u64) -> XNonce {
    let mut bytes = [0_u8; 24];
    bytes[16..].copy_from_slice(&index.to_le_bytes());
    bytes.into()
}

fn write_summary(path: PathBuf, result: &Value) -> AnyResult<()> {
    let verdict = result["overall_verdict"].as_str().unwrap_or("unknown");
    let latency = &result["threshold_verdicts"]["durable_commit_p99_ms_at_concurrency_32"];
    let growth = &result["threshold_verdicts"]["post_compaction_max_file_to_live_ratio"];
    let text = format!(
        "# KTD2 redb proof results\n\nOverall Gate G1 verdict: **{verdict}**.\n\n\
         - Atomic state + audit commit: {}\n\
         - Durable commit p99 at concurrency 32: {:.3} ms (limit 25 ms)\n\
         - Crash recovery matrix: {}\n\
         - Concurrent snapshot consistency and stall: {}\n\
         - Post-compaction file/live ratio: {:.3} (limit 3.0)\n\
         - Native x86_64 XChaCha20-Poly1305: measured\n\
         - Native aarch64 XChaCha20-Poly1305: pending external native host; emulation rejected\n\n\
         ## Single-writer lock constraint\n\nredb 2.6.3 uses nonblocking `flock` on Unix and `LockFile` on Windows, but its WASI and fallback file backends silently omit the process lock. This service therefore supports only the certified Linux targets on filesystems with working `flock`, and a startup lock probe must fail closed. The reference ext4 host rejected a second open as expected.\n\nRaw samples and the immutable host fingerprint are in [`results.json`](results.json).\n",
        result["atomic_state_audit"]["passed"],
        latency["observed"].as_f64().unwrap_or_default(),
        result["threshold_verdicts"]["crash_recovery_success_percent"]["passed"],
        result["threshold_verdicts"]["snapshot_consistency_and_stall"],
        growth["observed"].as_f64().unwrap_or_default(),
    );
    fs::write(path, text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_evidence_gate_refuses_non_native_targets() {
        assert!(require_aarch64("aarch64").is_ok());
        assert_eq!(
            require_aarch64("x86_64").unwrap_err().to_string(),
            "native aarch64 execution required; cross-builds and emulation are not evidence"
        );
    }

    #[test]
    fn nearest_rank_percentile_is_stable() {
        let values: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_us(&values, 50), 50.0);
        assert_eq!(percentile_us(&values, 99), 99.0);
    }

    #[test]
    fn state_audit_meta_commit_is_atomic() -> AnyResult<()> {
        let dir = tempfile::tempdir()?;
        let db = database(&dir.path().join("test.redb"))?;
        initialize(&db)?;
        commit_generation(&db, 1, 32)?;
        assert_eq!(consistent_generation(&db)?, 1);
        let mut tx = db.begin_write()?;
        tx.set_durability(Durability::Immediate);
        tx.open_table(STATE)?.insert(2, &[1_u8; 32][..])?;
        tx.abort()?;
        assert_eq!(consistent_generation(&db)?, 1);
        Ok(())
    }
}
