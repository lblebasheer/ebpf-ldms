# nerscfslat

An eBPF-based filesystem latency monitor for Linux, built with the
[Aya](https://aya-rs.dev/) Rust framework. It instruments VFS kernel functions
to measure the latency of write-path filesystem operations, aggregates the
results per filesystem path prefix, and publishes them into a shared BPF ring
buffer for downstream consumption by the
[nersc-ebpf-streamer](https://gitlab.nersc.gov/ebasheer/ebpf-ldms-streamer)
daemon.

## Motivation

NERSC provides several large-scale shared filesystems to its users — GPFS-based
community storage (`/global/cfs`) and multiple Lustre scratch filesystems
(`/pscratch`, `/mscratch`, `/ascratch`). These filesystems are critical to the
interactive experience of users working on login and compute nodes. When a
filesystem becomes slow or unresponsive, users feel it immediately, but
historically it has been hard to make direct, continuous, per-filesystem
measurements of that latency from the perspective of user processes.

`nerscfslat` was created to fill that gap. It runs as a system daemon on NERSC
nodes, using eBPF to observe actual VFS call latencies with nanosecond
precision, broken down by filesystem — without modifying any application code
and with negligible overhead.

## How It Works

### eBPF Probes

Four kernel functions are instrumented using `fentry`/`fexit` tracepoints:

| Kernel function    | Operation                     |
|--------------------|-------------------------------|
| `vfs_write`        | Single-buffer write           |
| `vfs_writev`       | Vectored (scatter-gather) write |
| `vfs_fsync_range`  | fsync / data flush            |
| `filp_close`       | File close                    |

On `fentry`, the current kernel timestamp and the first few path components of
the file being operated on are captured and stored in a per-CPU hash map keyed
by the file pointer.

On `fexit`, the elapsed time is calculated and matched against the configured
path prefix table. If the file's path starts with one of the configured
prefixes, the latency sample is added to the running statistics for that prefix.

### Path Prefix Filtering

Up to **8 path prefixes** (each up to **16 characters**) can be configured.
Latency statistics are tracked independently for each prefix, so every
configured filesystem gets its own set of metrics. At NERSC, all external
shared filesystems can be uniquely identified within the 16-character prefix
limit:

| Prefix        | Filesystem                              |
|---------------|-----------------------------------------|
| `/global/cfs` | Community File System (GPFS)            |
| `/global/u1`  | GPFS user home directories              |
| `/global/u2`  | GPFS user home directories              |
| `/pscratch`   | Perlmutter scratch (Lustre)             |
| `/mscratch`   | Muller scratch (Lustre)                 |
| `/ascratch`   | Additional scratch (Lustre)             |

Prefixes are loaded at startup via `bpftool` using the
`nerscfslat_load_prefixes.sh` helper script (see [Configuration](#configuration)).

### Aggregation and the Ring Buffer

Within each 500 ms aggregation window, per-prefix statistics are accumulated
in a BPF array map (`WRITESTATS`) entirely in the kernel:

- **min latency** (ns)
- **max latency** (ns)
- **total latency** (ns)
- **sample count**

At the end of each window, a summary record is serialized as a
**CBOR-encoded map** and written into a **pinned BPF ring buffer** named
`LDMS_SHARED_STREAM`. The ring buffer is pinned in the BPF filesystem, making
it accessible to other user-space processes on the same node.

### Message Format

Each record written to the ring buffer is a CBOR map with the following fields:

| Field                 | Type   | Description                                      |
|-----------------------|--------|--------------------------------------------------|
| `id`                  | string | Always `"fslat"`                                 |
| `version`             | string | Schema version, currently `"v1"`                 |
| `timestamp_monotonic` | u64    | Kernel monotonic timestamp at publish time (ns)  |
| `opname`              | string | Kernel function name (e.g. `"vfs_write"`)        |
| `sequence`            | u64    | Monotonically increasing sequence number         |
| `min_latency`         | u64    | Minimum observed latency in the window (ns)      |
| `max_latency`         | u64    | Maximum observed latency in the window (ns)      |
| `total_latency`       | u64    | Sum of all latencies in the window (ns)          |
| `count_samples`       | u64    | Number of operations observed in the window      |
| `interval`            | u64    | Aggregation window length (ns); nominally 500 ms |
| `unit`                | string | Always `"ns"`                                    |
| `path_prefix`         | string | The matched path prefix                          |

## Integration with nersc-ebpf-streamer

[nersc-ebpf-streamer](https://gitlab.nersc.gov/ebasheer/ebpf-ldms-streamer) is
a companion daemon that runs alongside `nerscfslat`. It reads CBOR records from
the `LDMS_SHARED_STREAM` ring buffer and forwards them into
[LDMS](https://ovis-hpc.readthedocs.io/en/latest/ldms/ldms-quickstart.html)
(Lightweight Distributed Metric Service) as JSON stream messages. LDMS then
aggregates and stores the data across the NERSC fleet for analysis and alerting.

The systemd service for `nerscfslat` is ordered to start **after**
`nersc-ebpf-streamer.service` and is configured as `PartOf` that service, so
both start and stop together.

## Configuration

Path prefixes are specified via the `PREFIXES` environment variable in the
systemd service unit (space-separated). The default configuration in
`deploy/nersc-ebpf-nerscfslat.service` is:

```
PREFIXES=/global/u1 /global/u2 /global/cfs /pscratch /mscratch /ascratch
```

After `nerscfslat` starts and its eBPF maps are loaded, the
`nerscfslat_load_prefixes.sh` script uses `bpftool` to write the prefix list
into the `WRITESTATS` BPF array map of each active probe. Up to **8 prefixes**
are supported; each prefix must be at most **16 characters** long.

## Deployment

The project produces an RPM via
[`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm).
The RPM installs a systemd service (`nersc-ebpf-nerscfslat.service`) that
starts `nerscfslat` automatically as part of `nersc-ready.target`. The
`PREFIXES` environment variable in the unit file controls which path prefixes
are monitored.

## Building from Source

### Prerequisites

1. Stable Rust toolchain: `rustup toolchain install stable`
2. Nightly Rust toolchain: `rustup toolchain install nightly --component rust-src`
3. BPF linker: `cargo install bpf-linker`

### Build & Run

```shell
cargo build --release
cargo run --release
```

Cargo build scripts compile the eBPF programs automatically and embed them in
the userspace binary.

## Crate Structure

| Crate                      | Description                                              |
|----------------------------|----------------------------------------------------------|
| `nerscfslat`               | Userspace driver: loads and attaches eBPF programs       |
| `nerscfslat-common`        | Shared eBPF logic: path resolution, stats, ring buffer writes |
| `nerscfslat-ebpf-close`    | eBPF probe for `filp_close`                              |
| `nerscfslat-ebpf-fsync`    | eBPF probe for `vfs_fsync_range`                         |
| `nerscfslat-ebpf-write`    | eBPF probe for `vfs_write`                               |
| `nerscfslat-ebpf-writev`   | eBPF probe for `vfs_writev`                              |

## License

With the exception of eBPF code, nerscfslat is distributed under the terms
of either the [MIT license](LICENSE-MIT) or the [Apache License](LICENSE-APACHE)
(version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2](LICENSE-GPL2) or the [MIT license](LICENSE-MIT),
at your option.
