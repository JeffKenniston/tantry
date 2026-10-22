## 2. Crate 1: `crates/base` (Zero-I/O Domain AST, `VfsTree`, `DeltaChannel` & `StateExtensionMap`)

`crates/base` MUST have **zero OS, network, or filesystem I/O dependencies**.

### Crate `base`: Phase 1 — Error Taxonomy, `PosixPath`, Platform Rebasing & Config Validator
1. **`src/error.rs`**:
   * `PathValidationError`: `EmptyPath`, `NullByteOrControlChar`, `BackslashForbidden`, `TraversalAttempt`.
   * `StateReducerError`: `MessageIdNotFound(Uuid)`, `EmptyCompactionRange`, `InvalidToolUsePatch(String)`.
   * `ExtensionError`: `UnknownWireKey(String)`, `CodecTagMismatch { expected: u8, actual: u8 }`, `SerializationFailed(String)`, `DeserializationFailed(String)`.
   * `ConfigValidationError`: `InvalidTrustDomain(String)`, `InvalidSimilarityThreshold(f32)`, `InvalidBudgetRatios { soft: f64, hard: f64 }`, `InvalidWasmMemoryBytes(usize)`, `InvalidModelTierFormat(String)`, `InvalidMcpProtocolVersion(String)`, `InvalidSocketAddr(String)`, `PathError(#[from] PathValidationError)`.
   * `BaseError`: Top-level `thiserror::Error` enum wrapping all four error types above.
2. **`src/path.rs` (`PosixPath` Normalization)**:
   * `pub type PosixPath = String;`
   * `pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError>`:
     * Rejects empty strings (`EmptyPath`), null bytes or ASCII control chars `0x00..=0x1F` or `0x7F` (`NullByteOrControlChar`), and backslashes `\` (`BackslashForbidden`).
     * Splits on `'/'`; immediately returns `Err(PathValidationError::TraversalAttempt)` if any segment equals `"."` or `".."` (never silently resolves `..`).
     * Collapses consecutive slashes (`//` $\rightarrow$ `/`), strips trailing slashes (except root `"/"`), and prepends `'/'` if missing.
3. **`src/platform.rs` (Pure Shell Interpolation & Termux Path Rebasing)**:
   * `pub fn interpolate_env_vars<F: Fn(&str) -> Option<String>>(input: &str, env_lookup: F) -> String`: Expands `${VAR:-default}` and `${VAR}` patterns in a single pass without regex dependencies.
   * `RuntimePlatform`: Enum `LinuxStandard` | `AndroidTermux { prefix: PosixPath }`.
   * `RuntimePlatform::detect_from_env<F>(env_lookup: F, is_android_target: bool) -> Self`: Detects Termux if `is_android_target` is true, `TERMUX_VERSION` is non-empty, or `PREFIX` starts with `"/data/data/com.termux"`. Default Termux prefix is `"/data/data/com.termux/files/usr"`.
   * `RuntimePlatform::rebase_path(&self, path: &str, strict_posix_paths: bool) -> Result<PosixPath, PathValidationError>`: First normalizes `path`. If `Self::AndroidTermux { prefix }` and `!strict_posix_paths`:
     * Any path starting with `"/var/lib/tantry"` (and not already under `prefix`) is rebased to `"{prefix}/var/lib/tantry..."`.
     * Any path starting with `"/run/spire"` is rebased to `"{prefix}/var/run/spire..."`.
     * Any path starting with `"/var/run/tantry"` is rebased to `"{prefix}/var/run/tantry..."`.
   * `RuntimePlatform::effective_max_workers(&self, configured: usize) -> usize`: Returns $\min(\max(\text{configured}, 1), 8)$ on `AndroidTermux`, or $\max(\text{configured}, 1)$ on `LinuxStandard`.
4. **`src/config.rs` (`TantryConfig` AST & Pre-Boot Validator)**:
   * Defines `TantryConfig` and sub-structs (`SystemConfig`, `CognitiveConfig`, `ModelTiersConfig`, `BillingConfig`, `SandboxesConfig`, `WasmSandboxConfig`, `FirecrackerSandboxConfig`, `TermuxProotSandboxConfig`, `TransportConfig`) matching Section 1.4.
   * `TantryConfig::parse_and_validate<F>(toml_str: &str, env_lookup: F, is_android_target: bool) -> Result<Self, BaseError>`: Interpolates env vars across all path strings, applies `RuntimePlatform::rebase_path`, clamps `sandboxes.max_workers`, and validates all numeric, URL, socket address, WASM page alignment, and protocol version invariants.

### Crate `base`: Phase 2 — Domain AST, `MerkleRadixVfsTree` & `DeltaChannel` Reducers
1. **`src/ast.rs` (Canonical Domain AST)**:
   * Type aliases: `pub type MessageId = Uuid;` (UUIDv7 via `Uuid::now_v7()`), `pub type ToolCallId = String;`, `pub type TaskId = String;`.
   * `Role`: `System`, `User`, `Assistant`, `Tool`.
   * `MediaKind`: `Image`, `Video`, `Audio`, `Document` with `MediaKind::from_extension(ext: &str) -> Option<Self>` and `MediaKind::from_mime(mime: &str) -> Option<Self>` covering all supported extensions in Section 0.
   * `CacheControl`: `Ephemeral`, `Persistent { ttl_seconds: u32 }`.
   * `ExecuteArtifact`: `exit_code: i32`, `timed_out: bool`, `duration_ms: u64`, `peak_rss_bytes: Option<u64>`, `sandbox_id: String`, `isolation_tier: String` (`"firecracker_kvm"` | `"termux_proot"` | `"wasi_0_3"`).
   * `BlastRadiusReport`: `target_symbol: String`, `affected_files: Vec<PosixPath>`, `reverse_dependency_count: usize`, `max_depth_reached: usize`, `katz_centrality: f32`, `signature_mutated: bool`, `risk_score: f32`.
   * `ToolArtifact`: `Execute(ExecuteArtifact)`, `BlastRadius(BlastRadiusReport)`, `McpUiResource { uri: String, mime_type: String }`, `Custom(serde_json::Value)`.
   * `ContentBlock`:
     * `Text { text: String, cache_control: Option<CacheControl> }`
     * `Reasoning { thought_summary: String, opaque_signature: Option<Bytes> }`
     * `Media { kind: MediaKind, mime_type: String, data: Bytes, source_path: Option<PosixPath> }`
     * `ToolUse { id: ToolCallId, name: String, input: serde_json::Value }`
     * `ToolResult { tool_use_id: ToolCallId, is_error: bool, content: Vec<ContentBlock>, artifact: Option<ToolArtifact> }`
   * `Message`: `id: MessageId`, `role: Role`, `content: Vec<ContentBlock>`, `created_at: DateTime<Utc>`, `metadata: BTreeMap<String, serde_json::Value>`. Constructors `Message::user(text)`, `Message::system(text, cache_control)`, `Message::assistant(content)`, `Message::tool_result(tool_use_id, is_error, text, artifact)`, and helper `Message::assistant_text(&self) -> Option<String>` joining non-empty `ContentBlock::Text` blocks with `'\n'`.
   * `TodoStatus` (`Pending`, `InProgress`, `Completed`, `Cancelled`), `TodoItem` (`id`, `content`, `status`).
   * `FileData`: `content: Bytes`, `blake3_hash: [u8; 32]`, `is_utf8: bool`, `mime_type: Option<String>`, `created_at: DateTime<Utc>`, `modified_at: DateTime<Utc>`. Constructors `new_utf8(text: String, now: DateTime<Utc>)`, `new_binary(bytes: Bytes, mime_type: Option<String>, now: DateTime<Utc>)`, and `as_str(&self) -> Option<&str>`.
   * `SkillFrontmatter`: `name: String`, `description: String`, `vfs_path: PosixPath`, `tags: Vec<String>`, `sigstore_verified: bool`, `blake3_digest: [u8; 32]`.
   * `AsyncTaskStatus` (`Pending`, `Running`, `InputRequired { prompt: String }`, `Succeeded`, `Failed { error: String }`, `Cancelled`), `AsyncTaskHandle` (`task_id`, `subagent_name`, `transport_scheme`, `endpoint`, `thread_id`, `run_id`, `child_svid_spiffe_id`, `status`).
   * `RubricOutcome` (`Satisfied`, `Failed { feedback: String }`, `MaxIterationsReached { iterations: u32 }`, `GraderError { reason: String }`), `SubagentMode` (`Isolated`, `Fork`).
2. **`src/vfs_tree.rs` (Content-Addressable Persistent `MerkleRadixVfsTree`)**:
   * `MerkleDirNode`: `segment: String`, `subtree_blake3: [u8; 32]`, `file_count: usize`, `subdirs: BTreeMap<String, Arc<MerkleDirNode>>`, `files: BTreeMap<String, Arc<FileData>>`.
   * `MerkleDirNode::recompute_hash(&mut self)`: Initializes `blake3::Hasher`, updates with `b"tantry:merkle_dir:v3:"` and `self.segment.as_bytes()`. Iterates in lexicographical `BTreeMap` order over `self.files` feeding `b"/F:" || fname.as_bytes() || &fdata.blake3_hash`, then iterates over `self.subdirs` feeding `b"/D:" || dname.as_bytes() || &dnode.subtree_blake3`. Sets `self.file_count = self.files.len() + self.subdirs.values().map(|d| d.file_count).sum::<usize>()`.
   * `VfsTree`: Wraps `root: Arc<MerkleDirNode>`.
     * `new() -> Self`, `root_hash(&self) -> [u8; 32]` ($O(1)$), `len(&self) -> usize` ($O(1)$), `is_empty(&self) -> bool`.
     * `get(&self, normalized_path: &str) -> Option<&Arc<FileData>>` ($O(D \log B)$).
     * `insert(&mut self, normalized_path: PosixPath, data: Arc<FileData>) -> Result<Option<Arc<FileData>>, PathValidationError>`: Path-copying mutation via `Arc::make_mut` down the segment chain, updating `modified_at` (preserving `created_at` if replacing existing file), and running `recompute_hash()` bottom-up.
     * `remove(&mut self, normalized_path: &str) -> Option<Arc<FileData>>`: Removes target entry via `Arc::make_mut`, prunes any child directory where `child_arc.file_count == 0`, and runs `recompute_hash()` bottom-up.
     * `diff_with_stats(&self, after: &Self) -> (Vec<FileDelta>, usize)` and `diff(&self, after: &Self) -> Vec<FileDelta>`: Recursively compares `(before, after)` directory nodes while counting visited directory nodes. Whenever `b.subtree_blake3 == a.subtree_blake3`, returns immediately in $O(1)$ time without inspecting children. Emits `FileDelta::Upsert` for added or hash-modified files and `FileDelta::Delete` for removed files/subtrees in deterministic lexicographical path order.
3. **`src/delta.rs` (`DeltaChannel` Algebraic Reducers)**:
   * `MessageDelta`: `Append(Vec<Message>)`, `PatchById { target_id: MessageId, replacement: Message }`, `CompactRange { up_to_id_inclusive: MessageId, summary_message: Message }`.
   * `MessageDelta::apply(messages: &mut Vec<Message>, delta: MessageDelta) -> Result<Vec<Message>, StateReducerError>`:
     * `Append(new_msgs)`: Appends messages (deduplicating if `id` already exists in tail) and returns `Ok(vec![])`.
     * `PatchById { target_id, replacement }`: Finds `target_id` index, replaces message in-place, and returns `Ok(vec![evicted_original])` (or `Err(StateReducerError::MessageIdNotFound(target_id))`).
     * `CompactRange { up_to_id_inclusive, summary_message }`: Finds index `idx` of `up_to_id_inclusive`, drains `0..=idx` into `evicted: Vec<Message>`, inserts `summary_message` at index `0`, and returns `Ok(evicted)`.
   * `FileDelta`: `Upsert { path: PosixPath, data: Arc<FileData> }`, `Delete { path: PosixPath }`.
   * `FileDelta::apply_batch(tree: &mut VfsTree, deltas: &[FileDelta]) -> Result<(), PathValidationError>` and `FileDelta::diff_trees(before: &VfsTree, after: &VfsTree) -> Vec<FileDelta>`.

### Crate `base`: Phase 3 — `StateExtensionMap`, `TantryState`, 22-Tool Metadata & Execution Primitives
1. **`src/typemap.rs` (Dual-Codec Zero-Cost `StateExtensionMap`)**:
   * `TypeIdHasher`: Identity `write_u64(&mut self, id: u64)` (`self.0 = id`) and FNV-1a `write(&mut self, bytes: &[u8])`.
   * `FastTypeMap<V> = HashMap<TypeId, V, BuildHasherDefault<TypeIdHasher>>`.
   * `SlotVisibility`: `Private` (stripped on subagent spawn) | `Shared` ($O(1)$ `Arc` clone into child subagent).
   * `CodecTag`: `RkyvAligned = 0x01` (`rkyv 0.8.18` with `bytecheck`) | `MessagePackNamed = 0x02` (`rmp_serde::to_vec_named` / `from_slice`).
   * `StateSlot` trait: `Any + Send + Sync + Clone + 'static` with `const WIRE_KEY: &'static str`, `const VISIBILITY: SlotVisibility`, `const CODEC_TAG: CodecTag`, `fn encode_payload(&self) -> Result<Vec<u8>, ExtensionError>`, and `fn decode_payload(bytes: &[u8]) -> Result<Self, ExtensionError>`.
   * `StateExtensionMap`: Stores `FastTypeMap<Box<dyn ErasedSlot>>` where `SlotHolder<T>` wraps `Arc<T>`. Methods: `get<T: StateSlot>(&self) -> Option<&T>`, `get_mut<T: StateSlot>(&mut self) -> Option<&mut T>` (via `Arc::make_mut`), `insert<T: StateSlot>(&mut self, val: T)`, `remove<T: StateSlot>(&mut self)`, `fork_shared_only(&self) -> Self` ($O(1)$ `Arc` clone of `SlotVisibility::Shared` entries only), `serialize_all(&self) -> Result<BTreeMap<String, Vec<u8>>, ExtensionError>` (prefixes each value with 1-byte `[T::CODEC_TAG as u8]`), and `hydrate_all(&mut self, raw: &BTreeMap<String, Vec<u8>>, registry: &StateExtensionRegistry) -> Result<(), ExtensionError>`.
2. **`src/state.rs` (`TantryState` & Subagent Forking Hygiene)**:
   * `TantryState`: `thread_id: String`, `step_index: u64`, `last_checkpoint_id: Option<String>`, `messages: Vec<Message>`, `files: VfsTree`, `todos: Vec<TodoItem>`, `skills_metadata: Vec<SkillFrontmatter>`, `memory_contents: BTreeMap<PosixPath, String>`, `async_tasks: BTreeMap<TaskId, AsyncTaskHandle>`, `rubric_input: Option<String>`, `rubric_status: Option<RubricOutcome>`, `structured_response: Option<serde_json::Value>`, `extensions: StateExtensionMap`.
   * `fork_for_subagent(&self, mode: SubagentMode, child_thread_id: String, task_prompt: Message) -> Self`:
     * `SubagentMode::Isolated`: `messages = vec![task_prompt]`.
     * `SubagentMode::Fork`: Clones `self.messages` and appends `task_prompt`.
     * Sets `thread_id = child_thread_id`, `step_index = 0`, `last_checkpoint_id = None`, resets `todos`, `skills_metadata`, `memory_contents`, `async_tasks`, `rubric_input`, `rubric_status`, `structured_response` to empty/`None`, clones `self.files` ($O(1)$), and sets `extensions = self.extensions.fork_shared_only()`.
   * `build_tool_use_edit_delta(&self, tool_use_id: &str, modified_arguments: serde_json::Value) -> Result<MessageDelta, StateReducerError>`: Scans `self.messages` in reverse for the `Message` containing `ContentBlock::ToolUse { id == tool_use_id }`, clones that `Message` with `input = modified_arguments`, and returns `MessageDelta::PatchById { target_id: msg.id, replacement }`.
3. **`src/tools_meta.rs` (Canonical 22-Tool Catalog, Bernstein Footprints & Smart Offloader)**:
   * Defines constants and metadata for all 22 built-in tools:
     * Slot 2: `write_todos`, `read_todos`
     * Slot 3: `ls`, `read_file`, `write_file`, `edit_file`, `delete`, `glob`, `grep`, `execute`
     * Slot 4: `ast_blast_radius`, `repo_map`
     * Slot 5: `eval`, `browser`, `computer`, `ephemeral_tunnel`
     * Slot 7: `task`
     * Slot 8: `launch_async_task`, `check_async_task`, `update_async_task`, `cancel_async_task`, `list_async_tasks`
     * Slot 14: `update_memory` (Note: `read_todos` + `write_todos` count as the `todos` pair; total 23 callable tool schemas across the 22 functional tool families).
   * `ToolAccessFootprint`: `reads: Vec<PosixPath>`, `writes: Vec<PosixPath>`, `is_global_barrier: bool`, `is_mutating_for_semantic_cache: bool`.
   * Virtual Metadata Namespaces for Bernstein DAG Scheduling:
     * `write_todos`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/todos"}\}, \mathcal{W} = \{\text{"/\_\_meta\_\_/todos"}\}$; `read_todos`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/todos"}\}, \mathcal{W} = \emptyset$.
     * `update_memory`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/memory"}\}, \mathcal{W} = \{\text{"/\_\_meta\_\_/memory"}\}$.
     * `launch_async_task`, `update_async_task`, `cancel_async_task`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/async\_tasks"}\}, \mathcal{W} = \{\text{"/\_\_meta\_\_/async\_tasks"}\}$; `check_async_task`, `list_async_tasks`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/async\_tasks"}\}, \mathcal{W} = \emptyset$.
     * `ephemeral_tunnel`: $\mathcal{R} = \{\text{"/\_\_meta\_\_/tunnel"}\}, \mathcal{W} = \{\text{"/\_\_meta\_\_/tunnel"}\}$.
     * `read_file(p)`, `ls(p)`: $\mathcal{R} = \{p\}, \mathcal{W} = \emptyset$; `glob`, `grep`, `ast_blast_radius`, `repo_map`: $\mathcal{R} = \{\text{"/**"}\}, \mathcal{W} = \emptyset$.
     * `write_file(p)`, `edit_file(p)`, `delete(p)`: $\mathcal{R} = \{p\}, \mathcal{W} = \{p\}$ (`is_mutating_for_semantic_cache = true`).
     * `execute`, `eval`, `browser`, `computer`, `task`: $\mathcal{R} = \{\text{"/**"}\}, \mathcal{W} = \{\text{"/**"}\}, \text{is\_global\_barrier} = \text{true}$ (`is_mutating_for_semantic_cache = true`).
   * `pub fn maybe_offload_tool_output(tool_use_id: &str, raw_output: &str, vfs: &mut VfsTree, now: DateTime<Utc>) -> String`: If `raw_output.len() <= 20_000 && raw_output.lines().count() <= 500`, returns `raw_output.to_string()`. Otherwise, writes full output to `/offloaded_tool_results/{tool_use_id}.txt` in `vfs` and returns a summary containing the offloaded VFS path, total char/line count, the first 15 lines, the last 15 lines, and up to 10 highest-priority diagnostic lines matching `["error[E", "error:", "FAILED", "panicked at", "Traceback", "SyntaxError", "Exception"]` with their 1-based line numbers.
4. **`src/execution.rs` (Cross-Crate Execution & Prompt AST Primitives)**:
   * `ModelTier`: `FrontierDeep`, `ReasoningPro`, `FastExecution`, `CompactLite` (`as_str`, `from_str`).
   * `TokenUsage`: `input_tokens: u64`, `cached_tokens: u64`, `output_tokens: u64`.
   * `ToolDefinition`: `name: String`, `description: String`, `input_schema: serde_json::Value`.
   * `ApprovalDecision`: `Approve { tool_use_id: ToolCallId }`, `Edit { tool_use_id: ToolCallId, modified_arguments: serde_json::Value }`, `Reject { tool_use_id: ToolCallId, feedback: String }`.
   * `LoopDirective`: `ContinueTurn`, `FinishTurn`.
   * `StreamEvent`: `ModelDelta { text_delta: String, reasoning_delta: Option<String> }`, `ToolCallStart { tool_use_id: ToolCallId, name: String }`, `ToolCallEnd { tool_use_id: ToolCallId, is_error: bool }`, `Interrupted { thread_id: String, checkpoint_id: String, pending_tools: Vec<ToolCallId> }`, `TurnComplete { step_index: u64, usage: TokenUsage }`. Includes `StreamEvent::coalesce_in_place(&mut self, next: StreamEvent) -> Result<(), StreamEvent>` which merges two consecutive `ModelDelta` events when backpressure credits $= 0$ and refuses to coalesce lifecycle events.
   * `PromptBlock`: `Block1StaticSystem(String)`, `Block2StaticTools { tools_json: String, cache_control: CacheControl }`, `Block3SemiStaticSkillsAndRepoMap { skills_catalog: String, repo_map: String }`, `Block4SemiStaticMemory { memory_text: String, cache_control: CacheControl }`, `Block5DynamicTurnState { todos_text: String, async_tasks_text: String }`.

---
