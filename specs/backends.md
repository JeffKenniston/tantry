## 7. Crate 6: `crates/backends` (Capability VFS, 4-Stage Mergiraf PCS-Triple Merger, WASI 0.3 & Sandboxes)

### Crate `backends`: Phase 1 — `VfsBackend` Trait, `StateBackend`, `LocalFsBackend` (`cap-std`) & `CompositeBackend`
1. **`src/traits.rs` (`VfsBackend` & `BackendCapabilities`)**:
   * `BackendCapabilities`: `supports_delete: bool`, `supports_execute: bool`, `is_persistent_host_fs: bool`.
   * `VfsBackend` trait (`Send + Sync`): `capabilities(&self) -> BackendCapabilities`, `ls(&self, state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError>`, `read_file(&self, state: &TantryState, path: &str, offset_line: Option<usize>, limit_lines: Option<usize>) -> Result<String, BackendError>`, `write_file(&self, state: &mut TantryState, path: &str, content: &str) -> Result<WriteReceipt, BackendError>`, `edit_file(&self, state: &mut TantryState, path: &str, old_string: &str, new_string: &str, replace_all: bool) -> Result<EditReceipt, BackendError>`, `delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError>`, `glob(&self, state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError>`, `grep(&self, state: &TantryState, pattern: &str, path_glob: Option<&str>) -> Result<Vec<GrepMatch>, BackendError>`, and `execute(&self, req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError>`.
2. **`src/state_backend.rs`, `src/local_fs.rs` & `src/composite.rs`**:
   * `StateBackend`: Operates purely on `state.files` (`VfsTree`). `edit_file` counts exact occurrences of `old_string`: if $0$, returns `BackendError::OldStringNotFound`; if $> 1$ and `!replace_all`, returns `BackendError::OccurrenceMismatch { count }`.
   * `LocalFsBackend`: Opens `workspace_root` using `cap_std::fs::Dir::open_ambient_dir` (enforcing Linux `openat2` `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`), strips leading `'/'` from normalized `PosixPath`, and executes all file operations relative to the capability `Dir` handle (blocking all symlink/hardlink escapes outside `workspace_root` at the kernel level). Synchronizes read/written files into `state.files` (`VfsTree`).
   * `CompositeBackend`: Routes operations by longest normalized prefix mount (e.g., `/memories` $\rightarrow$ persistent store, `/offloaded_tool_results` $\rightarrow$ `StateBackend`, `/` $\rightarrow$ `LocalFsBackend`).

### Crate `backends`: Phase 2 — 4-Stage Mergiraf PCS-Triple 3-Way VFS Merger (`src/merge.rs`)
`pub fn merge_subagent_trees(base: &VfsTree, branches: Vec<(String, VfsTree)>, now: DateTime<Utc>) -> VfsMergeReport` reconciles $K$ parallel subagent or tool-wave VFS trees against base tree $T_0$ via iterative left-fold:
1. **Stage 0 (Merkle Fast-Forward & Delete/Modify Detection)**:
   * Uses `base.diff(&branch)` to skip unchanged subtrees in $O(1)$.
   * If only one branch modified path $P$, or multiple branches produced the exact same `blake3_hash` for $P$, fast-forwards $P$ and increments `stage0_fast_forwards`.
   * If Branch A modified $P$ while Branch B deleted $P$, records `VfsMergeConflict::ModifyDeleteConflict { path, modified_by, deleted_by }`.
2. **Stage 1 (`imara-diff 0.2` Histogram 3-Way Line Merge)**:
   * For UTF-8 files modified with distinct hashes by $\ge 2$ branches, tokenizes lines with `imara_diff::InternedInput` and computes diffs $(T_0 \rightarrow T_A)$ and $(T_0 \rightarrow T_B)$ using `imara_diff::Algorithm::Histogram`.
   * If changed line ranges $[s_A, e_A]$ and $[s_B, e_B]$ do not overlap (and are not adjacent insertions at the exact same line offset), applies both hunk sets cleanly and increments `stage1_line_merges`.
3. **Stage 2 (GumTree + Parent-Child-Successor PCS-Triple CST Merge)**:
   * Invoked when Stage 1 hunks overlap in a supported `tree-sitter 0.25` language (`.rs`, `.py`, `.ts`, `.tsx`, `.go`, `.c`, `.h`, `.cpp`, `.hpp`):
   * **Phase 2a (Top-Down Isomorphic Subtree Matching)**: Computes structural `blake3` hashes for all CST nodes in $T_0, T_A, T_B$ and greedily matches identical subtrees of height $\ge 2$.
   * **Phase 2b (Bottom-Up Container Matching)**: Matches unmatched interior CST nodes $(u, v)$ of identical grammar `kind()` whose matched descendant Dice similarity satisfies:
     $$\text{Dice}(u, v) = \frac{2 \cdot |\text{Descendants}(u) \cap \text{Descendants}(v)|}{|\text{Descendants}(u)| + |\text{Descendants}(v)|} \ge 0.50$$
   * **Phase 2c (PCS-Triple Set Resolution)**: Encodes ordered CST containers as Parent-Child-Successor triples $(p, c, s)$ between start sentinel $\dashv$ and end sentinel $\vdash$, and computes the 3-way merged triple set:
     $$\mathcal{T}_{\text{merged}} = \left(\mathcal{T}_0 \setminus \left((\mathcal{T}_0 \setminus \mathcal{T}_A) \cup (\mathcal{T}_0 \setminus \mathcal{T}_B)\right)\right) \cup (\mathcal{T}_A \setminus \mathcal{T}_0) \cup (\mathcal{T}_B \setminus \mathcal{T}_0)$$
     Resolves concurrent non-overlapping intra-line parameter edits (e.g., Branch A mutating parameter 1 and Branch B mutating parameter 2 of the same function signature) when their child `parameter` CST nodes are distinct.
   * **Phase 2d (`CommutativeParent` & Duplicate `signature_blake3` Guard)**: For commutative AST parent kinds (`use_declaration` blocks, `import_statement` blocks, `field_declaration_list`, `enum_variant_list`, module-level item lists, and `declaration_list` inside `impl`/class blocks), relaxes successor ordering constraints $(p, c, s)$, takes the set union of inserted/retained child declarations formatted with `CommutativeChildSeparator`, and computes `signature_blake3` for every child declaration. **If two distinct child declarations in the same container share the exact same `signature_blake3` (e.g., two functions with the same name and parameter signature but different bodies), aborts Stage 2 and escalates to Stage 3**.
   * **Phase 2e (Syntax Verification)**: Reparses the reconstructed source with `tree-sitter 0.25`; if `!merged_tree.root_node().has_error()`, commits the merged file and increments `stage2_cst_merges`.
4. **Stage 3 (Conflict Surfacing)**:
   * Emits `VfsMergeConflict::WriteWriteConflict { path, branch_a, branch_b }`, increments `stage3_conflicts`, and writes standard Git conflict markers (`<<<<<<< {branch_a}`, `=======`, `>>>>>>> {branch_b}`) into the merged `VfsTree`.

### Crate `backends`: Phase 3 — WASI 0.3 (`wasmtime 43.0.2`), Adaptive OS Sandboxes & TLS SNI Egress Proxy
1. **`src/wasm.rs` (WASI 0.3 Component Sandbox & `RUSTSEC-2026-0358` Guard)**:
   * Implements the WIT world `eval-sandbox` (`wit/tantry.wit`, package `tantry:runtime@0.3.0`) with async host imports `fs` (`read-file`, `write-file`, `list-dir`), `graph` (`query-symbols`, `blast-radius`), and `tunnel` (`request-scoped-token`), and guest export `eval: async func(code: string) -> result<string, string>`.
   * **Pre-Instantiation Validator (`pub fn validate_component_no_start_yield(wasm_bytes: &[u8]) -> Result<(), BackendError>`)**: Walks all sections using `wasmparser::Parser::new(0)`. Rejects any binary containing `Payload::StartSection` or `Payload::ComponentStartSection` (or any core module that imports host functions alongside a start function) with `BackendError::UnsafeWasmStartSection` prior to `wasmtime::component::Component::new`, completely neutralizing `RUSTSEC-2026-0358`.
   * Enforces `consume_fuel(true)` (`fuel_budget`), `epoch_interruption(true)` (`epoch_tick_ms` background ticker + `wall_clock_timeout_ms`), `StoreLimitsBuilder::new().memory_size(max_memory_bytes)`, and routes all `fs`/`tunnel` host imports through `validate_and_normalize_path` and `PermissionLattice`.
2. **`src/sandbox.rs` & `src/termux_supervisor.rs` (Adaptive 3-Tier OS Sandbox & Zygote Pool)**:
   * `HostCapabilityProbe::detect(config: &SandboxesConfig, platform: &RuntimePlatform) -> IsolationTier`:
     * **Tier 1 (`FirecrackerKvm`)**: Selected when `/dev/kvm` is accessible (`R_OK | W_OK`) and `firecracker`/`jailer` binaries exist. Maintains a `warm_snapshot_pool_size` pool of `userfaultfd`-restorable microVMs ($< 125\text{ms}$ restore SLA), communicates over `AF_VSOCK`, and restricts the host VMM process via Linux `landlock 0.4.7` (`ABI::V5`).
     * **Tier 2 (`TermuxProotUds`)**: Selected on `AndroidTermux` or when `proot_binary` exists. Managed by `TermuxZygotePool` (`termux_supervisor.rs`) which spawns at most $\min(\text{max\_workers}, 8)$ persistent worker processes (keeping total OS child processes $\le 12$), binds `-b ${PREFIX}/tmp:/tmp` with `PROOT_TMP_DIR=${PREFIX}/tmp`, installs a Seccomp-BPF + `SECCOMP_RET_USER_NOTIF` filter blocking non-loopback `connect()` and `ptrace`, and communicates over multiplexed `AF_UNIX` sockets.
     * **Tier 3 (`Wasi03AndSanitizedProcessGroup`)**: Fallback using `EnvCapability::scrub_host_env`.
   * **Process-Group Reaping Invariant**: Every command execution spawns its child process in a dedicated session/process group via `nix::unistd::setsid()`. On wall-clock timeout or cancellation, the supervisor sends `nix::sys::signal::kill(Pid::from_raw(-pgid), Signal::SIGKILL)` to reap the entire descendant process tree without leaking orphan processes.
3. **`src/egress_proxy.rs` (Transparent TLS SNI & HTTP `CONNECT` Egress Proxy)**:
   * Listens on `egress_proxy_listen_addr` (`127.0.0.1:18443`).
   * Inspects the first bytes of each inbound TCP stream without terminating TLS: extracts the target hostname from either an HTTP `CONNECT host:port` header or a TLS 1.3 `ClientHello` Server Name Indication (SNI) extension (type `0x0000`).
   * Permits bidirectional TCP splicing if and only if the normalized hostname matches `allowlisted_mirrors` or `ScopedTunnelRegistry::is_service_active(hostname, now_ms) == true`. Otherwise, closes the socket immediately and appends an `EGRESS_BLOCKED` entry to `audit_log.sqlite`.

---
