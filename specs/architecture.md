## 0. Global Architectural Mandates, CVE Baseline & Build Governance

**Tantry** is a single-binary, capability-isolated, zero-trust, Rust-native **Agentic Operating System and Cognitive Harness**. Every crate, module, state machine, and wire protocol MUST obey these non-negotiable invariants:

1. **Compiler & Toolchain Baseline**:
   * Rust `edition = "2024"`, Cargo `resolver = "3"`, `rust-version = "1.85"` (compatible through `rustc 1.97+`).
   * Zero compiler or Clippy warnings permitted across all targets (`RUSTFLAGS="-D warnings"`).
2. **Foundational Crate Naming Invariant (`core` $\rightarrow$ `base`)**:
   * Crate 1 MUST be named `base` (`crates/base`).
   * **Strict Prohibition**: No crate in the workspace may be named `core`. All internal crate imports MUST reference `base::*` to prevent namespace collisions with Rust's built-in `::core` (`::core::fmt`, `::core::result`, `::core::option`) inside procedural macro expansions (`serde`, `thiserror`, `rkyv`, `proptest`).
3. **First-Class Dual-Target Execution (Linux Server & Android Termux)**:
   * Compiles and executes natively on standard Linux servers (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`) and unprivileged **Termux on Android (`aarch64-linux-android`, Bionic libc, Android GKI Linux 5.15/6.1/6.6+)**.
   * **Zero CMake/BoringSSL Build Blockers**: Uses pure-Rust `quinn` + `h3` + `rustls` (`ring`), `rusqlite` (`bundled`), pure-Rust AEAD (`chacha20poly1305` / `aes-gcm-siv`), and `zstd` (`default-features = false`).
   * **Android Phantom Process Killer (`SIGKILL` / Signal 9) Immunity**: Caps LLD linker threads at 4 during build, clamps Rayon thread pools to $\min(\text{num\_cpus}, 4)$ on Termux, and bounds the runtime Zygote Sandbox Worker Pool to $\min(\text{max\_workers}, 8)$ processes, keeping total child OS processes $\le 12$ (strictly below Android 12–16 `max_phantom_processes = 32`).
4. **October 2026 Vulnerability Remediation Baseline**:
   * **RUSTSEC-2026-0248 & RUSTSEC-2026-0292 (`im` / `imbl-sized-chunks` UAF/double-free)**: Completely replaces `im::OrdMap` with `rpds 1.1` and a content-addressable persistent `MerkleRadixVfsTree` in `crates/base`.
   * **RUSTSEC-2026-0338 (`quinn-proto` zero-length STREAM frame DoS panic)**: Enforces `quinn = "0.11.12"` and `quinn-proto = ">=0.11.18"`, and forbids `read_unordered` on unauthenticated peer streams.
   * **RUSTSEC-2026-0358 (`wasmtime` component `start` function yield panic)**: Enforces `wasmtime = "43.0.2"` / `wasmtime-wasi = "43.0.2"` and runs a pre-instantiation `wasmparser = "0.224"` validation pass rejecting any guest component containing a core or component `start` section that can invoke async-yielding host imports.
5. **MCP `2026-07-28` & OAuth 2.1 + DPoP Compliance**:
   * Full implementation of **MCP `2026-07-28`**: stateless Streamable HTTP, `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name` (SEP-2243), `_meta` capability/version envelopes, `server/discover`, Multi Round-Trip `InputRequiredResult` (SEP-2322), W3C TraceContext in `_meta` (SEP-414), resource caching `ttlMs`/`cacheScope` (SEP-2549), bidirectional `sampling/createMessage` and `elicitation/create`, and OAuth 2.1 Protected Resource Metadata (RFC 9728) with RFC 9449 DPoP sender-constrained tokens and strict anti-token-passthrough guards.

---
