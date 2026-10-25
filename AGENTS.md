# AGENTS.md — Tantry Autonomous Engineering Mandate

**Tantry** is a single-binary, capability-isolated, zero-trust, Rust-native **Agentic Operating System and Cognitive Harness**. It is engineered for standard Linux servers and unprivileged **Android Termux** environments.

## 1. Build, Check & Test Commands
Always verify your changes incrementally at the crate level before running workspace-wide checks. Zero warnings are strictly enforced:

### 1. Fast type and import check for a specific crate
RUSTFLAGS="-D warnings" cargo check -p <crate_name>

### 2. Run unit tests for a specific crate
RUSTFLAGS="-D warnings" cargo test -p <crate_name>

### 3. Full workspace verification gate (MUST pass cleanly)
RUSTFLAGS="-D warnings" cargo test --workspace

## 2. Strict 13-Crate Acyclic Dependency Graph (DAG)
Dependencies flow strictly top-down with zero circularity. Never add a dependency from an upstream crate to a downstream crate:
| # | Crate Name | Primary Responsibility & Boundary Rules |
|---|---|---|
| 1 | base | Zero I/O domain AST, MerkleRadixVfsTree, TantryConfig. |
| 2 | iam | Post-Quantum hybrid SVIDs (Ed25519 + ML-DSA-65), RFC 9449 DPoP. |
| 3 | permissions | 4D join-semilattice policy engine (Fs, Net, Env, Mcp). |
| 4 | data | Writer-first SQLite WAL pools, AEAD ledgers, RaBitQ index. |
| 5 | repo | 3-pass Scope-Graph, Katz centrality blast radius, RepoMap. |
| 6 | backends | Capability VFS, WASI 0.3 sandboxes, Termux Zygote pool. |
| 7 | cognitive | 12D LinUCB + Thompson router, atomic credit leases. |
| 8 | transport | Zenoh 1.10.1 mesh, Quinn QUIC/H3 MCP 2026-07-28. |
| 9 | runtime | 5-phase turn engine, Bernstein DAG scheduler, time-travel. |
| 10 | profiles | Hierarchical split_once(':') registry, Sigstore verifier. |
| 11 | middleware | 17-slot onion pipeline, 22 built-in tools. |
| 12 | tantry | Compile-time typestate TantryBuilder, 10-stage compilation. |
| 13 | cli | clap 4.5 CLI & 60fps responsive ratatui TUI. |

Every crate has a spec file named by crate (e.g., `base.md`, `iam.md`) located in the `specs/` directory.

## 3. Non-Negotiable Coding Rules
 * Never Name a Crate core: Crate 1 is crates/base. Never create or import a workspace crate named core, as it collides with Rust's built-in ::core.
 * Production-grade/ready code & implementations: No mocks, "hacks", TODO comments, or structural simplifications are permitted in code intended for the final compilation gate.
 * Zero Panic Placeholders: Never commit panic-inducing macros or empty structures; all temporary scaffolding, todo!(), and unimplemented!() hooks must be fully implemented before staging.
 * Strict Error Propagation: Forbid the use of .unwrap() or .expect() on Option and Result types; every potential failure path must be explicitly mapped to a custom domain error type via idiomatic Result propagation.
 * Exhaustive Match Handling: Avoid wildcard match arms (_) when matching on local or internal domain enums; compile-time exhaustiveness checks must be strictly leveraged to catch unhandled states and edge cases.
 * No Mocked String-Matching or Fallbacks: Never use hardcoded strings like "Success" or mocked pattern-matching for dynamic tool execution. Dispatch tools dynamically through middleware hooks or backend interfaces.
 * No Large Multiline Regex Edits: Do not run multiline regex scripts to rewrite large blocks, as this corrupts syntax. Make targeted edits and verify immediately via cargo check.
 * Verify Workspace Exports: Before refactoring cross-crate calls, manually inspect the upstream crate's src/lib.rs to ensure the symbols actually exist and are public.

## 4. Critical Security, Concurrency & Data Invariants
 * Android Phantom Process Killer Immunity: Clamp Rayon thread pools in execute_subagents to min(num_cpus, 4) on Termux targets. In crates/runtime, sequentially pre-fork state (fork_for_subagent) before entering parallel iteration to avoid mutable reference contention.
 * October 2026 CVE Remediations:
   * RUSTSEC-2026-0248/0292: Strictly forbid im crate; use rpds and MerkleRadixVfsTree.
   * RUSTSEC-2026-0338: Enforce quinn = "0.11.12" and forbid unordered stream reads.
   * RUSTSEC-2026-0358: Run validate_component_no_start_yield prior to WASM instantiation to block async-yielding start functions.
 * SQLite Time-Travel & WAL Invariants:
   * DbHandle must always initialize the writer connection and execute DDL/Checkpoints before opening the reader pool.
   * commit_checkpoint must use plain INSERT INTO (never INSERT OR REPLACE).
   * When hydrating state in reconstruct_state_at_checkpoint, capture the step index from the head of the walk, reverse the chain, and decrypt cross-thread forks using the target row's own thread_id and key_epoch.
   
