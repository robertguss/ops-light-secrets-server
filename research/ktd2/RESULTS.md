# KTD2 redb proof results

Overall Gate G1 verdict: **redb_pass**.

- Atomic state + audit commit: true
- Durable commit p99 at concurrency 32: 4.633 ms (limit 25 ms)
- Crash recovery matrix: true
- Concurrent snapshot consistency and stall: true
- Post-compaction file/live ratio: 2.616 (limit 3.0)
- Native x86_64 XChaCha20-Poly1305: measured
- Native aarch64 XChaCha20-Poly1305: pending external native host; emulation rejected

The user explicitly waived the pending native aarch64 performance observation
on 2026-07-16 to allow Gate G1 to proceed. No ARM performance result is claimed;
this remains a documented residual capacity risk.

## Single-writer lock constraint

redb 2.6.3 uses nonblocking `flock` on Unix and `LockFile` on Windows, but its WASI and fallback file backends silently omit the process lock. This service therefore supports only the certified Linux targets on filesystems with working `flock`, and a startup lock probe must fail closed. The reference ext4 host rejected a second open as expected.

Raw samples and the immutable host fingerprint are in [`results.json`](results.json).
