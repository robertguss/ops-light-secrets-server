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

The frozen run completed with a `redb_pass` verdict. See
[`RESULTS.md`](RESULTS.md) for the threshold summary and
[`results.json`](results.json) for the raw samples and execution-host
observation. Reproduce it locally with the `redacted_command` frozen in the
protocol. No automatic CI job runs this host-sensitive benchmark.
