# KTD2 redb proof spike

[`protocol.json`](protocol.json) is the immutable preregistration for Gate G1.
It was committed before spike code executed or measurements were collected.
Thresholds, workload shape, percentile method, crash points, durability mode,
and host fingerprint may not be changed after execution begins. A changed host
requires a full rerun.

Hetzner metadata identifies the provider, region, and `ash-dc1` zone but does
not expose the commercial instance SKU. The preregistered surrogate therefore
uses the exact observable machine class: Hetzner vServer, KVM, two AMD
EPYC-Milan vCPUs, 7.6 GiB RAM, non-rotational QEMU disk, and ext4. This
resolution is recorded on bead `olss-charter-qul.3.1` for user review.

The certified runtime matrix also includes native aarch64 Linux. This host is
x86_64 and has no native aarch64 execution facility. Emulation is not accepted
as performance evidence. The spike records x86_64 XChaCha20-Poly1305
performance and leaves the native aarch64 measurement explicitly pending until
an authorized host exists.

On an authorized native aarch64 Linux host, produce the remaining evidence with:

```text
cargo run --release --locked --manifest-path research/ktd2/spike/Cargo.toml -- measure-aarch64-xchacha --protocol research/ktd2/protocol.json --output aarch64-xchacha-results.json
```

The command refuses every non-aarch64 runtime, including this x86_64 host. It
records the frozen protocol digest, native host fingerprint, aggregate rates,
percentiles, and raw samples. Return that JSON artifact for review and committed
integration; do not replace the reference-host `results.json` with it.

Verify the returned artifact locally before review:

```text
cargo run --release --locked --manifest-path research/ktd2/spike/Cargo.toml -- verify-aarch64-xchacha --protocol research/ktd2/protocol.json --evidence aarch64-xchacha-results.json
```

The verifier requires an exact evidence schema, matching frozen-protocol
digest, native aarch64 kernel and build fingerprints, the registered 4 KiB ×
20,000-operation workload, complete sorted raw samples, and summaries that
recompute from the raw timings. It rejects missing, extra, altered, cross-host,
or non-finite fields.

The frozen run completed with a `redb_pass` verdict. See
[`RESULTS.md`](RESULTS.md) for the threshold summary and
[`results.json`](results.json) for the raw samples and execution-host
observation. Reproduce it locally with the `redacted_command` frozen in the
protocol. No automatic CI job runs this host-sensitive benchmark.

On 2026-07-16 the user explicitly waived the still-pending native aarch64
XChaCha performance observation so Gate G1 could proceed. This waiver does not
convert the x86_64 number into ARM evidence and makes no ARM performance claim.
Native aarch64 remains in the intended runtime matrix, with its software-cipher
capacity an explicit residual risk until the command above is run on native
hardware. All storage correctness, recovery, snapshot, compaction, durability,
and x86_64 performance gates remain measured and passed without waiver.
