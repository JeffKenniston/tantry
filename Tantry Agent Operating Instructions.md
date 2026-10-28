# AGENTS.md — Tantry Autonomous Engineering Mandate

**Tantry** is a single-binary, capability-isolated, zero-trust, Rust-native Agentic Operating System (`edition = "2024"`, `resolver = "3"`, `rust-version = "1.85"`). Every plan, edit, and verification command must obey the rules below.

---

## 1. Dynamic Scope Lock & Phased Execution Protocol

You must dynamically lock your working scope to the exact crate(s) and files required by the user prompt.

1. **Phase 0 — Scope Lock & Upstream Symbol Inspection**:

   * Identify the target `<crate>` and read ONLY `specs/<crate>.md` and the target source files in `crates/<crate>/`.

   * Do NOT scan, analyze, format, or lint unrelated crates or directories.

   * Before calling any upstream trait, struct, function, or `StateSlot`, inspect the upstream crate's `crates/<dep>/src/lib.rs` to verify exact exported symbol names, parameter order, and return types. Never guess or hallucinate upstream signatures.

2. **Phase 1 — Stepped Implementation Plan**:

   * Formulate a concise, deterministic, step-by-step plan mapped strictly to the phases and module boundaries in `specs/<crate>.md`.

   * State the exact files to be created or modified and the verification command for each step.

3. **Phase 2 — Incremental Execution & Targeted Verification**:

   * Execute one step at a time using targeted, incremental file edits.

   * Verify compilation after each step using package-scoped `cargo check`:
     `RUSTFLAGS="-D warnings" cargo check -p <crate>`

   * Do NOT waste turns running `cargo fmt`, `cargo clippy --workspace`, or workspace-wide test suites while iterating on a single crate.

4. **Phase 3 — Crate Completion Gate**:

   * Run package-scoped unit and integration tests only after code changes for the active phase compile cleanly:
     `RUSTFLAGS="-D warnings" cargo test -p <crate>`

   * Run `RUSTFLAGS="-D warnings" cargo clippy -p <crate> --all-targets` once before finalizing the task.

---

## 2. Strict 13-Crate Acyclic DAG & Canonical Specs

Dependencies flow strictly top-down with zero circularity. Never add an internal dependency to `Cargo.toml` that violates this table:

| # | Crate Path | Crate Name | Allowed Internal Workspace Dependencies | Canonical Spec |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `crates/base` | `base` | *None* (Zero OS, FS, or network I/O dependencies) | `specs/base.md` |
| 2 | `crates/iam` | `iam` | `base` | `specs/iam.md` |
| 3 | `crates/permissions` | `permissions` | `base`, `iam` | `specs/permissions.md` |
| 4 | `crates/data` | `data` | `base`, `iam` | `specs/data.md` |
| 5 | `crates/repo` | `repo` | `base`, `data` | `specs/repo.md` |
| 6 | `crates/backends` | `backends` | `base`, `iam`, `permissions`, `data`, `repo` | `specs/backends.md` |
| 7 | `crates/cognitive` | `cognitive` | `base`, `iam`, `data` | `specs/cognitive.md` |
| 8 | `crates/transport` | `transport` | `base`, `iam`, `permissions` | `specs/transport.md` |
| 9 | `crates/runtime` | `runtime` | `base`, `iam`, `permissions`, `data`, `backends`, `cognitive`, `transport` | `specs/runtime.md` |
| 10 | `crates/profiles` | `profiles` | `base`, `iam`, `permissions`, `backends`, `runtime` | `specs/profiles.md` |
| 11 | `crates/middleware` | `middleware` | `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles` | `specs/middleware.md` |
| 12 | `crates/tantry` | `tantry` | `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles`, `middleware` | `specs/tantry.md` |
| 13 | `crates/cli` | `cli` (`tantry` bin) | All 12 library crates | `specs/cli.md` |

* **Shared Polymorphic Contracts**: Traits required by both upstream and downstream crates reside in the lowest common upstream crate (e.g., `AgentMiddleware`, `NextModelCall`, and `TurnExecutionContext` are defined in `crates/runtime` and re-exported/implemented in `crates/middleware`).

---

## 3. Production Code Quality & Zero-Mock Mandate

All code must be 100% production-grade, complete, and spec-compliant on the first pass.

* **Zero Mocks, Stubs, or Hardcoded Fallbacks**: Never use `todo!()`, `unimplemented!()`, empty match arms (`_ => {}`), or hardcoded return strings such as `"executed"`, `"Success"`, or `"Executed tool '{other}'"`.

* **No Ignored Parameters**: Never silence unused parameter warnings by prefixing required inputs with underscores (e.g., `_ctx`, `_fork_delta`, `_decisions`). Wire every parameter into its functional logic.

* **Real Upstream Dispatch**:
  * Phase 3 tool execution in `crates/runtime` must dispatch dynamically to `ctx.backend` (`VfsBackend`), `ctx.iam` (`IdentityManager`), `ctx.data_stores` (`DataStoreManager`), and active `AgentMiddleware` hooks.
  * Multi-branch VFS reconciliation in `crates/runtime` and `crates/middleware` must invoke `backends::merge::merge_subagent_trees(base: &VfsTree, branches: Vec<(String, VfsTree)>, now: DateTime<Utc>) -> VfsMergeReport` using a deterministic `Vec<(String, VfsTree)>`, never a `HashMap` or non-existent merger function.
  * Offloaded tool outputs (`base::tools_meta::maybe_offload_tool_output` writing `/offloaded_tool_results/{tool_use_id}.txt`) must be preserved across parallel wave merges by checking `new_child_state.files.root_hash() != base_vfs.root_hash()`.

* **Known Trapdoors to Avoid**:
  * **Never call `Arc::get_mut` on shared context handles**: `ctx.publisher` (`Option<Arc<CreditControlledPublisher>>`) has `strong_count >= 2`; invoke interior-mutable methods (`&self`) directly on the `Arc`.
  * **Never double-serialize checkpoint payloads**: Serialize `state.extensions.serialize_all()?`, `message_delta`, `file_deltas`, `todos`, and `async_tasks` exactly once in the format expected by `InteractionChainStore::reconstruct_state_at_checkpoint`.
  * **Head-Step Query Invariant**: Before committing any checkpoint in `crates/runtime`, query `InteractionChainStore::get_latest_checkpoint_for_thread(&state.thread_id)` so `next_step_index = head_step_index + 1` never resets to `1` on a continuing thread.
  * **Deterministic Collections**: Use `BTreeMap` and `BTreeSet` (never `HashMap` or `HashSet`) for any data structure affecting Merkle hashes, prompt block ordering, tool schema ordering, or VFS merges.

---

## 4. Non-Negotiable Architectural & Security Invariants

* **Foundational Crate Naming (`base`, never `core`)**: Crate 1 is `base`. Never name any crate or module `core` to prevent namespace collisions with `::core` inside `serde`, `thiserror`, `rkyv`, and `proptest` macros.

* **Dual-Target Linux & Android Termux Execution**:
  * Clamp Rayon thread pools to `std::cmp::min(num_cpus, 4)` when `RuntimePlatform::AndroidTermux` is active.
  * Clamp `TermuxZygotePool` workers to `std::cmp::min(max_workers, 8)` so total child OS processes remain `<= 12` (Android Phantom Process Killer immunity).
  * Spawn sandboxed child processes in dedicated process groups (`nix::unistd::setsid()`) and reap timed-out/cancelled groups via `nix::sys::signal::kill(Pid::from_raw(-pgid), Signal::SIGKILL)`.

* **October 2026 Vulnerability Remediation Baseline**:
  * **Forbidden Crates**: Never add `im`, `imbl-sized-chunks` (`RUSTSEC-2026-0248` / `0292`), or `aes-gcm`. Use `rpds = "1.1"`, `base::vfs_tree::VfsTree`, and `chacha20poly1305` / `aes-gcm-siv`.
  * **QUIC DoS Guard (`RUSTSEC-2026-0338`)**: Enforce `quinn = "0.11.12"` and `quinn-proto = ">=0.11.18"`. Never call `read_unordered` on QUIC streams.
  * **Wasmtime Guard (`RUSTSEC-2026-0358`)**: Enforce `wasmtime = "43.0.2"` and run `wasmparser = "0.224"` (`validate_component_no_start_yield`) before instantiation to reject any WASM component containing `Payload::StartSection` or `Payload::ComponentStartSection`.

---

## 5. Forbidden Workspace Actions

* **NEVER** run large multiline regex, `sed`, `awk`, or ad-hoc Python scripts to bulk-rewrite Rust source files.
* **NEVER** commit temporary `.sh`, `.py`, or scratch files into the repository.
* **NEVER** create nested `Cargo.lock` files inside `crates/*`; only the root `Cargo.lock` is permitted.
* **NEVER** modify `Cargo.toml` workspace dependencies or edit files outside your active task scope unless explicitly instructed.