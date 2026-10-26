## 1. Workspace Topology, Crate DAG, Dependencies & Config Schema

### 1.1 Strict Acyclic Crate Dependency Graph (DAG)
The workspace contains 13 crates under `crates/` (`default-members = ["crates/cli"]`), `wit/tantry.wit`, `config.toml`, `.cargo/config.toml`, and `tests/`. Dependencies flow strictly top-down with zero circularity:

| # | Crate Path | Crate Name | Type | Direct Internal Workspace Dependencies |
| :- | :--- | :--- | :--- | :--- |
| 1 | `crates/base` | `base` | `lib` | *None* (Zero I/O, pure AST, `VfsTree`, `DeltaChannel`, `StateExtensionMap`, config & tool metadata) |
| 2 | `crates/iam` | `iam` | `lib` | `base` |
| 3 | `crates/permissions` | `permissions` | `lib` | `base`, `iam` |
| 4 | `crates/data` | `data` | `lib` | `base`, `iam` |
| 5 | `crates/repo` | `repo` | `lib` | `base`, `data` |
| 6 | `crates/backends` | `backends` | `lib` | `base`, `iam`, `permissions`, `data`, `repo` |
| 7 | `crates/cognitive` | `cognitive` | `lib` | `base`, `iam`, `data` |
| 8 | `crates/transport` | `transport` | `lib` | `base`, `iam`, `permissions` |
| 9 | `crates/runtime` | `runtime` | `lib` | `base`, `iam`, `permissions`, `data`, `backends`, `cognitive`, `transport` |
| 10| `crates/profiles` | `profiles` | `lib` | `base`, `iam`, `permissions`, `backends`, `runtime` |
| 11| `crates/middleware` | `middleware` | `lib` | `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles` |
| 12| `crates/tantry` | `tantry` | `lib` | `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles`, `middleware` |
| 13| `crates/cli` | `cli` | `bin` (`tantry`) | `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles`, `middleware`, `tantry` |

### 1.2 Workspace External Dependencies (`[workspace.dependencies]`)

| Category | Crate | Version | Mandatory Features & Configuration |
| :--- | :--- | :--- | :--- |
| **Async & Concurrency** | `tokio` | `1.43` | `["full"]` |
| | `tokio-stream`, `tokio-util` | `0.1`, `0.7` | `tokio-stream`: `["sync"]`; `tokio-util`: `["codec", "rt"]` |
| | `async-trait`, `futures` | `0.1`, `0.3` | Default |
| | `parking_lot`, `dashmap`, `rayon` | `0.12`, `6.1`, `1.10` | Default |
| **Serialization & CoW** | `serde`, `serde_json` | `1.0`, `1.0` | `serde`: `["derive", "rc"]`; `serde_json`: `["preserve_order"]` |
| | `serde_yml`, `toml`, `rmp-serde` | `0.0.12`, `0.8`, `1.3` | Default |
| | `rkyv` | `0.8.18` | `["bytecheck", "alloc", "std"]` |
| | `zstd` | `0.13` | `default-features = false` |
| | `bytes`, `rpds` | `1.9`, `1.1` | `["serde"]` (`rpds` replaces unmaintained `im`) |
| | `smallvec` | `1.13` | `["serde", "union", "const_generics"]` |
| | `schemars` | `0.8` | `["uuid1", "chrono"]` |
| **Crypto, IAM & Storage** | `blake3` | `1.6` | `["rayon", "mmap", "zeroize"]` |
| | `chacha20poly1305` | `0.10` | `["std", "rand_core"]` |
| | `aes-gcm-siv` | `0.11` | `["std"]` (Note: `aes-gcm` is forbidden; use `aes-gcm-siv` or `chacha20poly1305`) |
| | `ml-dsa` | `0.1.0-rc.2` | Default (FIPS 204 ML-DSA-65 PQ signatures) |
| | `ed25519-dalek` | `2.1` | `["rand_core", "pkcs8", "pem", "zeroize"]` |
| | `hkdf`, `sha2`, `zeroize` | `0.12`, `0.10`, `1.8` | `zeroize`: `["derive"]` |
| | `rcgen` | `0.13` | `["x509-parser", "pem"]` |
| | `rustls` | `0.23` | `default-features = false`, `["ring", "std", "tls12"]` |
| | `rusqlite` | `0.38` | `["bundled", "functions", "vtab", "blob", "backup", "serde_json"]` |
| | `sqlite-vec` | `0.1.6` | Default |
| **Repo & Diffing** | `tree-sitter` | `0.25` | Plus grammar crates (`tree-sitter-rust`, `python`, `typescript`, `go`, `c`, `cpp`) |
| | `imara-diff`, `globset`, `ignore`| `0.2`, `0.4`, `0.4` | Default |
| | `grep-searcher`, `grep-regex`, `grep-matcher` | `0.1` | Default |
| **Sandboxing & OS** | `wasmtime`, `wasmtime-wasi` | `43.0.2` | `wasmtime`: `["component-model", "async", "cranelift", "epoch-interruption"]` |
| | `wasmparser` | `0.224` | Default |
| | `cap-std`, `landlock` | `4.0.3`, `0.4.7` | Default |
| | `nix` | `0.29` | `["process", "signal", "fs", "socket", "sched", "uio", "ptrace"]` |
| **Transport** | `zenoh` | `1.10.1` | `default-features = false`, `["transport_tls", "transport_quic", "transport_tcp", "transport_unixsock-stream", "unstable"]` |
| | `quinn`, `quinn-proto` | `0.11.12`, `>=0.11.18`| `quinn`: `default-features = false`, `["runtime-tokio", "rustls", "ring"]` |
| | `h3`, `h3-quinn`, `h2` | `0.0.6`, `0.0.7`, `0.4` | Default |
| | `reqwest`, `eventsource-stream` | `0.12`, `0.2` | `reqwest`: `default-features = false`, `["rustls-tls", "json", "stream", "http2"]` |
| **Observability, CLI, Test**| `opentelemetry`, `opentelemetry_sdk`| `0.33.1` | `opentelemetry`: `["trace", "metrics", "logs"]`; `sdk`: `["rt-tokio"]` |
| | `tracing-opentelemetry`, `prometheus`| `0.34`, `0.13` | Default |
| | `tracing`, `tracing-subscriber` | `0.1`, `0.3` | `tracing-subscriber`: `["env-filter", "json"]` |
| | `clap`, `ratatui`, `crossterm` | `4.5`, `0.29`, `0.28` | `clap`: `["derive", "env"]` |
| | `uuid`, `chrono`, `thiserror`, `proptest` | `1.12`, `0.4`, `2.0`, `1.6` | `uuid`: `["v7", "serde"]`; `chrono`: `["serde"]` |

### 1.3 Compiler Profiles & Linker Governance (`.cargo/config.toml`)
* **`[profile.dev]`**: `opt-level = 1`, `debug = "line-tables-only"`, `split-debuginfo = "unpacked"`.
* **`[profile.release]`**: `opt-level = 3`, `lto = "thin"`, `codegen-units = 4`, `strip = "symbols"`, `panic = "abort"`.
* **`[target.aarch64-linux-android]`**: `linker = "clang"`, `rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=-Wl,--threads=4,--no-keep-memory", "-C", "target-cpu=generic", "-C", "target-feature=+neon,+crc,+crypto,+dotprod"]`.
* **`[target.x86_64-unknown-linux-gnu]`**: `linker = "clang"`, `rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "target-feature=+avx2,+fma,+aes,+sse4.2"]`.
* **`[target.aarch64-unknown-linux-gnu]`**: `linker = "clang"`, `rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "target-feature=+neon,+crc,+crypto,+dotprod"]`.

### 1.4 Declarative System Configuration Schema (`config.toml`)

| Section & Key | Type | Default Value | Validation Invariant / Constraint |
| :--- | :--- | :--- | :--- |
| `system.trust_domain` | `String` | `"tantry.internal"` | Non-empty RFC 3986 host string; no `'/'` or whitespace |
| `system.spire_socket_path` | `String` | `"${PREFIX:-}/run/spire/sockets/agent.sock"` | Interpolated and normalized POSIX path |
| `system.enable_embedded_sovereign_ca_fallback` | `bool` | `true` | Enables local Ed25519 + ML-DSA-65 CA when SPIRE socket is absent |
| `system.require_pq_hybrid_signatures` | `bool` | `true` | Requires dual Ed25519 + ML-DSA-65 verification on envelopes & SVIDs |
| `system.data_dir` | `String` | `"${PREFIX:-}/var/lib/tantry/data"` | Writable directory; created with `0700` permissions if missing |
| `system.cache_dir` | `String` | `"${PREFIX:-}/var/lib/tantry/cache"` | Writable directory |
| `system.verify_sigstore_bundles` | `bool` | `true` | Enforces Fulcio/Rekor verification on skills & OCI profiles |
| `system.strict_posix_paths` | `bool` | `false` | Disables automatic Termux `${PREFIX}` path rebasing when `true` |
| `cognitive.default_provider` | `String` | `"google_genai"` | Non-empty provider identifier |
| `cognitive.semantic_cache_similarity_threshold`| `f32` | `0.94` | Must satisfy $\theta \in [0.50, 1.00]$ |
| `cognitive.semantic_cache_max_entries` | `usize` | `50000` | Must be $> 0$ |
| `cognitive.enable_linucb_bandit_routing` | `bool` | `true` | Serde alias `"enable_ucb1_bandit_routing"`; enables 12D LinUCB + Thompson router |
| `cognitive.tiers.frontier_deep` | `String` | `"google_genai:gemini-4-argon"` | Must contain `':'` via `split_once(':')` |
| `cognitive.tiers.reasoning_pro` | `String` | `"google_genai:gemini-3.1-pro"` | Must contain `':'` via `split_once(':')` |
| `cognitive.tiers.fast_execution` | `String` | `"google_genai:gemini-3.8-flash"` | Must contain `':'` via `split_once(':')` |
| `cognitive.tiers.compact_lite` | `String` | `"google_genai:gemini-3.5-flash-lite"` | Must contain `':'` via `split_once(':')` |
| `billing.webhook_url` | `String` | `"https://billing.internal/v1/tantry-budget-alert"`| Valid `http://` or `https://` URL |
| `billing.soft_warning_ratio` | `f64` | `0.90` | Must satisfy $0.0 < \text{soft\_warning\_ratio} < \text{hard\_stop\_ratio} \le 1.0$ |
| `billing.hard_stop_ratio` | `f64` | `1.00` | Must satisfy $\le 1.00$ |
| `billing.webhook_timeout_ms` | `u64` | `2500` | Must be $\in [100, 30000]$ |
| `sandboxes.preferred_isolation_mode` | `String` | `"auto"` | Enum: `"auto"` \| `"firecracker"` \| `"termux_proot"` \| `"wasm_only"` |
| `sandboxes.max_workers` | `usize` | `8` | Must be $> 0$; clamped to $\min(\text{max\_workers}, 8)$ on Termux |
| `sandboxes.wasm.max_memory_bytes` | `usize` | `67108864` (64 MiB) | Multiple of $65,536$ (64 KiB WASM page) and $\ge 16,777,216$ (16 MiB) |
| `sandboxes.wasm.fuel_budget` | `u64` | `50000000` | Must be $> 0$ |
| `sandboxes.wasm.epoch_tick_ms` | `u64` | `10` | Must be $\in [1, 1000]$ |
| `sandboxes.wasm.wall_clock_timeout_ms` | `u64` | `10000` | Must be $\ge \text{epoch\_tick\_ms}$ |
| `sandboxes.firecracker.jailer_binary` | `String` | `"${PREFIX:-/usr}/bin/jailer"` | Normalized path |
| `sandboxes.firecracker.firecracker_binary` | `String` | `"${PREFIX:-/usr}/bin/firecracker"` | Normalized path |
| `sandboxes.firecracker.kernel_image` | `String` | `"${PREFIX:-}/var/lib/tantry/cache/vmlinux-virtio.bin"` | Normalized path |
| `sandboxes.firecracker.warm_snapshot_pool_size`| `usize` | `8` | Pre-warmed `userfaultfd` microVM pool size |
| `sandboxes.firecracker.restore_latency_target_ms`| `u64` | `125` | Target warm snapshot restore SLA |
| `sandboxes.firecracker.egress_proxy_listen_addr`| `String` | `"127.0.0.1:18443"` | Valid `SocketAddr` |
| `sandboxes.firecracker.allowlisted_mirrors` | `Vec<String>`| `["static.crates.io", "index.crates.io", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com"]` | Hostnames permitted through TLS SNI egress proxy |
| `sandboxes.termux_proot.proot_binary` | `String` | `"${PREFIX:-/data/data/com.termux/files/usr}/bin/proot"` | Normalized path |
| `sandboxes.termux_proot.rootfs_dir` | `String` | `"${PREFIX:-/data/data/com.termux/files/usr}/var/lib/tantry/rootfs"` | Normalized path |
| `sandboxes.termux_proot.uds_control_socket_dir`| `String` | `"${PREFIX:-/data/data/com.termux/files/usr}/var/run/tantry/sandboxes"` | Directory for multiplexed `AF_UNIX` control sockets |
| `sandboxes.termux_proot.enable_seccomp_bpf` | `bool` | `true` | Enables Seccomp-BPF + `SECCOMP_RET_USER_NOTIF` filter |
| `transport.zenoh_listen_endpoints` | `Vec<String>`| `["tls/0.0.0.0:7447"]` | Non-empty Zenoh 1.10.1 locator strings |
| `transport.quic_mcp_listen_addr` | `String` | `"0.0.0.0:8443"` | Valid `SocketAddr` |
| `transport.quic_handshake_fallback_timeout_ms` | `u64` | `250` | Must be $\in [50, 5000]$ |
| `transport.mcp_protocol_version` | `String` | `"2026-07-28"` | Must equal `"2026-07-28"` |

---
