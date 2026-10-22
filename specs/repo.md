## 6. Crate 5: `crates/repo` (Scope-Graph Resolver, Katz Centrality Blast Radius & `RepoEngine`)

### Crate `repo`: Phase 1 — Merkle Workspace Indexer, Incremental `tree-sitter 0.25` Parser & CST Linter
1. **`src/indexer.rs` (Workspace `blake3` Merkle Indexer)**:
   * Persists `merkle_nodes(vfs_path TEXT PRIMARY KEY, is_dir INTEGER, blake3_hash BLOB, mtime_ns INTEGER, symbol_count INTEGER)` in `repo_index.sqlite`.
   * Computes $O(\log N)$ dirty file sets by comparing `VfsTree` directory `subtree_blake3` hashes against stored `merkle_nodes` and detects external concurrent Git modifications on disk prior to subagent VFS merges.
2. **`src/parser.rs` (Incremental `tree-sitter 0.25` + `rayon` CST Parser)**:
   * Supports 6 language grammars: Rust (`.rs`), Python (`.py`), TypeScript/TSX (`.ts`, `.tsx`), Go (`.go`), C (`.c`, `.h`), and C++ (`.cpp`, `.hpp`, `.cc`).
   * Maintains an LRU cache `DashMap<(PosixPath, [u8; 32]), tree_sitter::Tree>`.
   * On byte-range edits (`edit_file`), computes `tree_sitter::InputEdit` (`start_byte`, `old_end_byte`, `new_end_byte`, `start_position`, `old_end_position`, `new_end_position`), calls `old_tree.edit(&input_edit)`, and reparses incrementally in $< 1\text{ms}$.
3. **`src/linting_hooks.rs` ($< 2\text{ms}$ Synchronous CST Diagnostic Extractor)**:
   * `pub fn check_cst_diagnostics(path: &str, tree: &tree_sitter::Tree, source: &str) -> Vec<CstDiagnostic>`: Walks `tree.root_node()` using `TreeCursor`; whenever `node.is_error()` or `node.is_missing()`, records 1-based `(start_line, start_col, end_line, end_col, snippet)` and formats an inline compiler-style diagnostic string appended to `write_file`/`edit_file` tool results.

### Crate `repo`: Phase 2 — 3-Pass Lexical Scope-Graph, Katz Centrality Blast Radius & Skeleton `RepoMap`
1. **`src/scope_graph.rs` (3-Pass Lexical Scope-Graph Cross-File Symbol Resolver)**:
   * Constructs directed Scope Graph $G = (V_{\text{scope}}, E_{\text{parent}}, E_{\text{import}}, D_{\text{def}}, R_{\text{ref}})$:
     * **Pass 1 (Local Scope & Definition Extraction)**: Extracts scopes (module, struct/class, `impl`/interface, function, block) and definitions $d \in D_{\text{def}}$. Computes:
       * `symbol_id = hex(BLAKE3(file_path || "::" || scope_qualified_name || "::" || kind))`
       * `signature_blake3: [u8; 32]`: BLAKE3 digest of normalized visibility, symbol name, generic parameters, parameter types, return type, and `where`/trait bounds (ignoring whitespace and comments).
       * `body_blake3: [u8; 32]`: BLAKE3 digest of the normalized function/method body block.
     * **Pass 2 (Import & Export Edge Wiring)**: Resolves `use`/`import`/`#include` statements into cross-file $E_{\text{import}}$ edges.
     * **Pass 3 (Priority-Shadowed Reference Resolution)**: Resolves every reference $r \in R_{\text{ref}}$ via shortest path in $G$ obeying the strict lexical shadowing priority ladder:
       $$\text{Inner Local Block} > \text{Receiver } \texttt{impl} \text{ / Class Scope} > \text{Explicit Named Import} > \text{Same-Module Definition} > \text{Wildcard Import} > \text{Prelude}$$
2. **`src/graph.rs` (Damped Katz Centrality Blast Radius & Hybrid FTS5 + RaBitQ RRF Search)**:
   * **Transitive Reverse-Dependency Recursive CTE**: Traverses `symbol_edges(caller_id, callee_id, call_kind)` up to depth $16$ to collect distinct `(caller_id, file_path, min_distance)`.
   * **Damped Katz Centrality**: With attenuation $\alpha = 0.15$ and base weight $\beta = 1.0$ (iterated to convergence $\epsilon < 10^{-5}$ or max 30 iterations):
     $$C_{\text{Katz}}(u) = \beta + \alpha \sum_{v \in \text{Callers}(u)} C_{\text{Katz}}(v)$$
   * **Signature-Aware Blast Radius Risk Score**: Given previous and new symbol definitions, sets $\sigma_{\text{mut}} = 1.0$ if `old.signature_blake3 != new.signature_blake3` (or symbol was deleted), and $\sigma_{\text{mut}} = 0.35$ if only `body_blake3` changed:
     $$\text{risk\_score}(u) = \text{clamp}\left(1.0 - \exp\left(-\frac{\sigma_{\text{mut}} \cdot \left(0.20 \cdot C_{\text{Katz}}(u) + 0.40 \cdot |\text{affected\_files}| + 0.50 \cdot |\text{public\_trait\_impls}|\right)}{10.0}\right),\; 0.0,\; 1.0\right)$$
     Returns `base::ast::BlastRadiusReport`.
   * **Hybrid Symbol Search (`search_symbols_hybrid`)**: Combines SQLite FTS5 `bm25(symbols_fts)` and `crates/data` `MatryoshkaVectorStore` similarity rankings via Reciprocal Rank Fusion ($k = 60$):
     $$\text{RRF}(d) = \frac{1}{60 + \text{rank}_{\text{BM25}}(d)} + \frac{1}{60 + \text{rank}_{\text{Vec}}(d)}$$
3. **`src/repomap.rs` (Token-Budgeted Skeletonized `RepoMap` & `SkeletonRepoMapSlot`)**:
   * Ranks workspace files and symbols by personalized PageRank / Katz centrality (boosting symbols in files mentioned in the latest user prompt by $3.0\times$), elides function implementation bodies into `{ ... }`, and packs declarations in descending rank order until reaching `max_tokens` (default $2,500$ tokens, estimated as $\lceil \text{bytes} / 4 \rceil$).
   * Defines `SkeletonRepoMapSlot` (`WIRE_KEY = "tantry.repo.skeleton_map"`, `VISIBILITY = SlotVisibility::Shared`, `CODEC_TAG = CodecTag::MessagePackNamed`).

### Crate `repo`: Phase 3 — `RepoEngine` Transactional Orchestrator (`src/lib.rs`)
1. **`RepoEngineConfig` & Termux Thread-Pool Governance**:
   * Builds a dedicated `rayon::ThreadPool` capped at $\min(\text{num\_cpus}, 4)$ on `AndroidTermux` and $\text{num\_cpus}$ on `LinuxStandard`.
2. **Two-Phase Transactional `sync_workspace(&self, vfs: &VfsTree)` & `on_file_mutated(...)`**:
   * **Phase A (Lock-Free Parallel CPU Pass)**: Uses the bounded Rayon pool to parse dirty files with `tree-sitter 0.25`, extract local Scope-Graph definitions/references, compute `signature_blake3` and `body_blake3`, and run `check_cst_diagnostics`.
   * **Phase B (Single `BEGIN IMMEDIATE` SQLite Transaction)**: Batch-upserts `merkle_nodes`, `symbols`, `symbol_edges`, and `symbols_fts`, resolves cross-file `E_import` and `R_ref` edges, recomputes damped Katz centrality $C_{\text{Katz}}$, and returns `FileMutationAnalysis { diagnostics: Vec<CstDiagnostic>, blast_radius: Vec<BlastRadiusReport>, max_risk_score: f32, cyclomatic_complexity: u32 }`.

---
