# vfslatency

An eBPF-based filesystem latency monitor for Linux, built with the
[Aya](https://aya-rs.dev/) Rust framework. It instruments VFS kernel functions
to measure the latency of read/write-path filesystem operations, aggregates the
results per filesystem path prefix, and publishes them into a shared BPF ring
buffer for downstream consumption by the
[ebpf-ldms](../../README.md)
daemon.

## Motivation

NERSC provides several large-scale shared filesystems to its users — GPFS-based
community storage (`/global/cfs`) and multiple Lustre scratch filesystems
(`/pscratch`, `/mscratch`, `/ascratch`). These filesystems are critical to the
interactive experience of users working on login and compute nodes. When a
filesystem becomes slow or unresponsive, users feel it immediately, but
historically it has been hard to make direct, continuous, per-filesystem
measurements of that latency from the perspective of user processes.

`vfslatency` was created to fill that gap. It runs as a system daemon on NERSC
nodes, using eBPF to observe actual VFS call latencies with nanosecond
precision, broken down by filesystem — without modifying any application code.

## How It Works

### eBPF Probes

Six kernel functions are instrumented using `fentry`/`fexit` tracepoints:

| Kernel function    | Operation                     |
|--------------------|-------------------------------|
| `vfs_write`        | Single-buffer write           |
| `vfs_writev`       | Vectored (scatter-gather) write |
| `vfs_read`         | Single-buffer read            |
| `vfs_readv`        | Vectored (scatter-gather) read |
| `vfs_fsync_range`  | fsync / data flush            |
| `filp_close`       | File close                    |

On `fentry`, the current kernel timestamp and the first few path components of
the file being operated on are captured and stored in a per-CPU hash map keyed
by the pid/thread-id of the process in whose context the operation is being executed.

On `fexit`, the elapsed time is calculated and matched against the configured
path prefix table. If the file's path starts with one of the configured
prefixes, the latency sample is added to the running statistics for that prefix.

### Path Prefix Filtering

Up to **8 path prefixes** (each up to **32 characters**) can be configured.
Latency statistics are tracked independently for each prefix, so every
configured filesystem gets its own set of metrics. At NERSC, all external
shared filesystems can be uniquely identified within the 32-character prefix
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
`vfslatency_load_prefixes.sh` helper script (see [Configuration](#configuration)).

### Aggregation and the Ring Buffer

Within each 1s aggregation window, per-prefix statistics are accumulated in a
BPF array map for each of the traced functions. This happens entirely in the
kernel. Stats collected are.

- **min latency** (ns)
- **max latency** (ns)
- **total latency** (ns)
- **total bytes** (bytes)
- **sample count**

At the end of each window, a stats record is serialized as a **CBOR-encoded
map** and written into a **pinned BPF ring buffer** named `LDMS_SHARED_STREAM`.
The ring buffer is pinned in the BPF filesystem, making it accessible to
the ebpf_ldms daemon.

### Message Format

Each record written to the ring buffer is a CBOR map. Example:

```json
{
  "hostname": "opensuse15",
  "id": "fslat/v2",
  "metrics": {
    "count_samples": 32,
    "max_latency": 468941,
    "min_latency": 235853,
    "total_bytes": 4568,
    "total_latency": 11649610
  },
  "opname": "vfs_read",
  "path_prefix": "/vagrant",
  "sequence": 20,
  "timestamp": 1773966858.1229975,
  "unit": "ns"
}
```


## Integration with ebpf-ldms

[ebpf-ldms](https://github.com/lblebasheer/ebpf-ldms) is
a companion daemon that runs alongside `vfslatency`. It reads CBOR records from
the `LDMS_SHARED_STREAM` ring buffer and forwards them into
[LDMS](https://ovis-hpc.readthedocs.io/en/latest/ldms/ldms-quickstart.html)
(Lightweight Distributed Metric Service) as JSON stream messages.

## Configuration

Path prefixes are specified via the `PREFIXES` environment variable in the
systemd service unit (space-separated). The default configuration in
`deploy/vfslatency.service` is:

```
PREFIXES=/global/u1 /global/u2 /global/cfs /pscratch /mscratch /ascratch
```

After `vfslatency` starts and its eBPF maps are loaded, the
`vfslatency_load_prefixes.sh` script uses `bpftool` to write the prefix list
into the per-vfs-function BPF array map of each active probe. Up to **8
prefixes** are supported; each prefix must be at most **32 characters** long.

## Deployment

The project produces an RPM via
[`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm).
The RPM installs a systemd service (`vfslatency.service`).

## Building from Source

### Prerequisites

1. Stable Rust toolchain: `rustup toolchain install stable`
2. Nightly Rust toolchain: `rustup toolchain install nightly --component rust-src`
3. BPF linker: `cargo install bpf-linker`

### Build & Run

From the root of the repository

```shell
cargo build --release -p vfslatency
```

Cargo build scripts compile the eBPF programs automatically and embed them in
the userspace binary.

### Build RPM

```shell
cargo generate-rpm -p producer/fslatency/vfslatency
```

## Crate Structure

All six eBPF probes live in a single `vfslatency-ebpf` crate. A macro generates
the `fentry`/`fexit` pair for each instrumented kernel function:

| Crate                      | Description                                              |
|----------------------------|----------------------------------------------------------|
| `vfslatency`               | Userspace driver: loads and attaches eBPF programs       |
| `vfslatency-common`        | Shared eBPF logic: path resolution, stats, ring buffer writes |
| `vfslatency-ebpf`          | Single eBPF crate containing probes for: `filp_close`, `vfs_fsync_range`, `vfs_write`, `vfs_writev`, `vfs_read`, `vfs_readv` |

## License

Unless otherwise noted, this project is distributed under the terms of the
[Modified BSD License](../../LICENSE.md).
