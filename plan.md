# Phased Architectural Remediation & Implementation Plan


## Phase 1: Workspace Hygiene, Linker Governance & Crates 1–8 Upstream Integration Fixes


**Step 1: Remove Spurious Lockfile & Configure `.cargo/config.toml` and Root `Cargo.toml`**

* Delete the stray `crates/data/Cargo.lock` file so the workspace uses a single authoritative root `Cargo.lock`.

* Create `.cargo/config.toml` at the repository root with `[profile.dev]` (`opt-level = 1`, `debug = "line-tables-only"`, `split-debuginfo = "unpacked"`), `[profile.release]` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 4`, `strip = "symbols"`, `panic = "abort"`), and target rules for `aarch64-linux-android` (`linker = "clang"`, `rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=-Wl,--threads=4,--no-keep-memory", "-C", "target-cpu=generic", "-C", "target-feature=+neon,+crc,+crypto,+dotprod"]`), `x86_64-unknown-linux-gnu` (`+avx2,+fma,+aes,+sse4.2`), and `aarch64-unknown-linux-gnu` (`+neon,+crc,+crypto,+dotprod`).

* Create the default root `config.toml` matching `specs/architecture.md` and `base::config::TantryConfig`.

* Inspect root `Cargo.toml` to verify `edition = "2024"`, `resolver = "3"`, `rust-version = "1.85"`, `im` / `imbl-sized-chunks` and `aes-gcm` are absent, and `rpds = "1.1"`, `quinn = "0.11.12"`, `quinn-proto = ">=0.11.18"`, `wasmtime = "43.0.2"`, and `wasmparser = "0.224"` are pinned in `[workspace.dependencies]`.


**Step 2: Complete & Align `crates/iam` (`src/key_hierarchy.rs`, `src/ca.rs`, `src/spire.rs`, `src/lib.rs`)**

* In `crates/iam/src/key_hierarchy.rs`, implement the full 3-tier HKDF-SHA256 key hierarchy (`pub const HKDF_DEK_DOMAIN_INFO: &[u8] = b"tantry-sqlite-aead-dek-v3";`) wrapping `kek_root: Zeroizing<[u8; 32]>`, `cached_thread_deks: DashMap<(String, u32), Zeroizing<[u8; 32]>>`, and `shredded_threads: DashSet<String>`.

* Implement `derive_epoch_dek(&self, epoch_id: u32, epoch_salt: &[u8; 32]) -> Zeroizing<[u8; 32]>` using `Hkdf::<Sha256>::new(Some(epoch_salt), &*self.kek_root)` expanding info `"tantry:dek:epoch:v3:" || epoch_id.to_be_bytes()`.

* Implement `derive_thread_dek(&self, thread_id: &str, epoch_id: u32, epoch_salt: &[u8; 32], thread_salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, IamError>`: check `self.shredded_threads.contains(thread_id)` first (returning `Err(IamError::KeyEpochShredded { thread_id, epoch: epoch_id })` if shredded), check `cached_thread_deks`, otherwise derive from `DEK_epoch` with info `HKDF_DEK_DOMAIN_INFO || b":" || thread_id.as_bytes()`, cache, and return.

* Implement `crypto_shred_thread(&self, thread_id: &str)` to insert `thread_id` into `shredded_threads` and remove/zeroize all entries matching `thread_id` from `cached_thread_deks` in `O(1)`.

* Verify `AuditSthSignature`, `SpireSocketIdentityManager`, `SovereignCaIdentityManager`, `DualModeIdentityProvider`, and `WorkloadIdentitySlot` (`WIRE_KEY = "tantry.iam.workload_identity"`) are exported from `crates/iam/src/lib.rs`.


**Step 3: Complete & Align `crates/permissions` (`src/attenuation.rs`, `src/capabilities.rs`, `src/zenoh_guard.rs`)**

* In `crates/permissions/src/attenuation.rs`, implement `PermissionLattice::narrow_for_subagent(&self, child: &PermissionLattice) -> PermissionLattice` so that for every input `x` across `FsCapability`, `NetCapability`, `EnvCapability`, and `McpCapability`, evaluating the narrowed lattice yields `self.evaluate(x).join(child.evaluate(x))` (`Allow = 0 < Interrupt = 1 < Deny = 2`), and `effective_max_spend_micros = self.mcp.effective_max_spend_micros.min(child.mcp.effective_max_spend_micros)`.

* In `crates/permissions/src/zenoh_guard.rs`, implement `evaluate_zenoh_topic(svid: &SpiffeId, action: ZenohAction, topic: &str) -> PermissionMode` to enforce that any subagent SVID (`svid.uri().contains("/subagent/")`) can only `Publish` to its own `/events` and `/state` suffixes and `Subscribe` to its own `/cmd` suffix, returning `PermissionMode::Deny` on any cross-agent or parent `/cmd` topic access.


**Step 4: Verify Upstream Wiring in `crates/data`, `crates/repo`, `crates/backends`, `crates/cognitive`, and `crates/transport`**

* In `crates/repo/src/lib.rs`, verify `RepoEngine`, `RepoEngineConfig`, `FileMutationAnalysis`, `CstDiagnostic`, and `SkeletonRepoMapSlot` (`WIRE_KEY = "tantry.repo.skeleton_map"`) are publicly exported.

* In `crates/backends/src/merge.rs`, ensure Stage 2d (`CommutativeParent`) computes `signature_blake3` per child declaration and aborts Stage 2 (escalating to Stage 3 conflict markers) when two distinct declarations in the same container have the exact same `signature_blake3`.

* In `crates/backends/src/sandbox.rs`, `src/termux_supervisor.rs`, and `src/egress_proxy.rs`, ensure `TermuxZygotePool` enforces `min(max_workers, 8)`, process execution uses `nix::unistd::setsid()` and reaps timeouts via `kill(Pid::from_raw(-pgid), Signal::SIGKILL)`, and `egress_proxy.rs` checks `iam::ScopedTunnelRegistry::is_service_active` and logs `EGRESS_BLOCKED` to `data::AuditMmrStore`.

* In `crates/cognitive/src/lib.rs`, ensure `RoutingSignalsSlot` (`WIRE_KEY = "tantry.cognitive.routing_signals"`, `SlotVisibility::Private`, `CodecTag::RkyvAligned`) and `PendingBanditFeedbackSlot` (`WIRE_KEY = "tantry.cognitive.bandit_feedback"`, `SlotVisibility::Private`, `CodecTag::RkyvAligned`) are publicly exported alongside `LlmProvider`, `ModelRequest`, `ModelResponse`, `CognitiveRouter`, `SemanticCache`, `CreditLeaseEnforcer`, `BudgetLeaseGuard`, and `execute_mcp_sampling_request`.

* Run `RUSTFLAGS="-D warnings" cargo test -p base -p iam -p permissions -p data -p repo -p backends -p cognitive -p transport` and confirm zero warnings and 100% test pass rate.


---


## Phase 2: Complete `crates/runtime` (Crate 9 — Phases 2, 3 & 4)


**Step 1: Inspect `crates/runtime` Phase 1 Exports & Upstream Signatures**

* Inspect `crates/runtime/src/slots.rs`, `src/error.rs`, `src/middleware.rs`, `src/observability.rs`, and `src/lib.rs`, as well as `crates/cognitive/src/lib.rs` and `crates/backends/src/traits.rs`.

* Verify `TurnExecutionContext` in `crates/runtime/src/middleware.rs` holds: `task_id: String`, `tenant_id: String`, `iam: Arc<dyn IdentityManager>`, `permission_lattice: Arc<PermissionLattice>`, `data_stores: Arc<DataStoreManager>`, `backend: Arc<dyn VfsBackend>`, `llm_provider: Arc<dyn LlmProvider>`, `publisher: Option<Arc<CreditControlledPublisher>>`, `metrics: Arc<RuntimeMetrics>`, and `active_tools: Vec<ToolDefinition>`.


**Step 2: Implement 22-Tool Bernstein Dependency-DAG Scheduler (`crates/runtime/src/tool_scheduler.rs`)**

* Implement `ToolAccessClassifier::classify(tool_name: &str, input: &serde_json::Value) -> ToolAccessFootprint` delegating to `base::tools_meta::classify_tool_footprint(tool_name, input)` to extract `(R_i, W_i, is_global_barrier, is_mutating_for_semantic_cache)` including virtual namespaces `/__meta__/todos`, `/__meta__/memory`, `/__meta__/async_tasks`, `/__meta__/tunnel`, and global barrier `/**`.

* Implement `paths_intersect(p1: &str, p2: &str) -> bool`: returns `true` if `p1 == "/**"` or `p2 == "/**"` or `p1 == p2` or `p1` is a directory prefix of `p2` (e.g., `p2.starts_with(&format!("{}/", p1.trim_end_matches('/')))`) or `p2` is a directory prefix of `p1`.

* Implement `BernsteinToolScheduler::partition_into_waves(calls: &[ToolUseCall]) -> Vec<Vec<usize>>`:
  * For every pair `(i, j)` with `0 <= i < j < calls.len()`, add a directed dependency edge `i -> j` if `calls[i].footprint.is_global_barrier || calls[j].footprint.is_global_barrier` or if any path in `W_i` intersects `W_j`, any path in `R_i` intersects `W_j`, or any path in `W_i` intersects `R_j`.
  * Partition nodes into topological waves using Kahn's level-order algorithm (collecting all nodes with `in_degree == 0` into the current wave, decrementing successor in-degrees after the wave, and repeating until all `M` calls are scheduled).

* Implement wave execution and VFS reconciliation:
  * For a wave with 1 tool call, execute directly against `&mut state`.
  * For a wave with `K > 1` concurrent tool calls, clone `let base_vfs = state.files.clone();` (`O(1)` `Arc` clone), execute each tool call concurrently via `futures::future::join_all` against its own isolated `TantryState` fork containing `base_vfs.clone()`, collect `(branch_name, child_state.files)` for tools that mutated files, reconcile via `backends::merge::merge_subagent_trees(&base_vfs, branches, Utc::now())`, update `metrics.vfs_merge_conflicts_total` labels (`"fast_path"`, `"line_diff"`, `"cst_ast"`, `"unresolved_conflict"`), apply non-VFS metadata mutations (`todos`, `memory_contents`, `async_tasks`), and return `Vec<Message>` tool results in exact original `0..M` call order.


**Step 3: Implement 5-Phase Durable Turn Lifecycle, Dynamic Tool Dispatch, HITL & Time-Travel (`crates/runtime/src/engine.rs`)**

* Implement dynamic tool execution (`execute_single_tool`) in `crates/runtime/src/engine.rs` with zero mocked fallbacks:
  * Dispatch `ls`, `read_file`, `write_file`, `edit_file`, `delete`, `glob`, `grep`, and `execute` directly to `ctx.backend` (`VfsBackend` methods), running `base::tools_meta::maybe_offload_tool_output` on the formatted output string and attaching `ToolArtifact::Execute` for `execute`.
  * Dispatch `write_todos` and `read_todos` against `state.todos`.
  * Dispatch `update_memory` against `state.memory_contents` and `ctx.backend.write_file(state, "/memories/AGENTS.md", ...)`.
  * Dispatch `ephemeral_tunnel` to `ctx.iam.request_scoped_tunnel_token(service_name, ttl_secs)`.
  * Dispatch `launch_async_task`, `check_async_task`, `update_async_task`, `cancel_async_task`, and `list_async_tasks` against `state.async_tasks`.
  * Allow middleware-provided custom tool handlers (or `RepoIntelligenceMiddleware` / `InterpreterAndSandboxMiddleware` / `SubAgentMiddleware` callbacks) to execute `ast_blast_radius`, `repo_map`, `eval`, `browser`, `computer`, and `task`.

* Implement `RuntimeEngine::execute_turn(&self, mut state: TantryState, ctx: &TurnExecutionContext) -> Result<TurnExecutionOutcome, RuntimeError>`:
  * **Phase 1 (`before_agent`)**: Ensure `TurnDeltaBufferSlot` is initialized (empty) in `state.extensions`. Execute `mw.before_agent(&mut state, ctx).await?` in forward order `0..middlewares.len()`.
  * **Phase 2 (`wrap_model_call` Onion & Streaming)**: Fold `self.middlewares` from the innermost `ctx.llm_provider` call outward (`rev()`) into `NextModelCall<'a>`. Inside the innermost closure, if `ctx.publisher` is `Some(pub_handle)`, stream chunks via `ctx.llm_provider.stream_complete` and publish `StreamEvent::ModelDelta` events through `pub_handle.publish(event)`; record `tantry_kv_cache_hit_ratio` and `tantry_token_spend_micros_total`. Append `response.assistant_message` to `state.messages` and push `MessageDelta::Append(vec![response.assistant_message.clone()])` to `TurnDeltaBufferSlot`.
  * **Phase 3 (Bernstein Parallel Tool Wave Dispatch)**: Extract all `ContentBlock::ToolUse` blocks from the assistant message. For each tool call, evaluate permissions across `ctx.permission_lattice` and `mw.evaluate_tool_permission(&state, &id, &name, &input, ctx).await?`, bypassing `PermissionMode::Interrupt` if `id` is present in `HitlBypassSlot`. If any tool returns `PermissionMode::Deny`, generate an error `Message::tool_result(id, true, "Permission denied by policy lattice", None)`. If any tool returns `PermissionMode::Interrupt`, skip execution of interrupted tools and transition immediately to Phase 4 (`TurnStatus::Interrupted`). Otherwise emit `StreamEvent::ToolCallStart`, execute waves via `BernsteinToolScheduler`, emit `StreamEvent::ToolCallEnd`, append tool result messages to `state.messages` (and `TurnDeltaBufferSlot`), and clear `HitlBypassSlot`.
  * **Phase 4 (Head-Aware Checkpoint Commit)**:
    * Query `ctx.data_stores.interaction_chain.get_latest_checkpoint_for_thread(&state.thread_id)?` to obtain `head: Option<(String, u64)>`.
    * Compute `let next_step_index = head.as_ref().map_or(1, |(_, s)| s + 1);` and `let prev_cp_id = head.map(|(id, _)| id).or_else(|| state.last_checkpoint_id.clone());`.
    * Synchronize `state.step_index = next_step_index;`.
    * Drain `TurnDeltaBufferSlot` and commit the checkpoint (`commit_checkpoint`) with `FileDelta::diff_trees(&prev_vfs, &state.files)` and `state.extensions.serialize_all()?`.
    * Update `state.last_checkpoint_id = Some(checkpoint_id.clone());`.
    * If interrupted in Phase 3, emit `StreamEvent::Interrupted { thread_id, checkpoint_id, pending_tools }` and return `TurnExecutionOutcome::Interrupted`.
    * If tool calls were executed in Phase 3 and none were interrupted, loop back to Phase 2 for the next model step within the turn (bounded by `max_steps_per_turn`).
  * **Phase 5 (`after_agent` Self-Grading Loop)**: When the assistant emits no `ToolUse` blocks, execute `mw.after_agent(&mut state, ctx).await?` in reverse order (`17 -> 1`). If any middleware returns `LoopDirective::ContinueTurn`, loop back to Phase 2; otherwise emit `StreamEvent::TurnComplete { step_index: state.step_index, usage }` and return `TurnExecutionOutcome::Completed(state)`.

* Implement `execute_subagents`, `resume_interrupted_thread` (`ApprovalDecision::Approve`, `Edit` via `state.build_tool_use_edit_delta`, and `Reject`), `fork_thread_at_checkpoint` (reconstructing state at `source_checkpoint_id`, setting `state.thread_id = new_thread_id`, applying optional `fork_delta`, and committing the first branch checkpoint at `reconstructed.step_index + 1` with `previous_checkpoint_id = Some(source_checkpoint_id)`), and `hydrate_thread_state`.

* Export `tool_scheduler` and `engine` symbols from `crates/runtime/src/lib.rs` and write unit tests in `crates/runtime/tests/` verifying all Phase 2–4 requirements. Run `RUSTFLAGS="-D warnings" cargo test -p runtime`.


---


## Phase 3: Implement `crates/profiles` (Crate 10)


**Step 1: Scaffold `crates/profiles` & Implement Schema, First-Colon Registry & Algebraic Merge (`src/schema.rs`, `src/registry.rs`)**

* Create `crates/profiles/Cargo.toml` depending strictly on `base`, `iam`, `permissions`, `backends`, and `runtime` (plus `serde`, `serde_json`, `thiserror`, `blake3`, `ed25519-dalek`, `ml-dsa`, `sha2`, `x509-parser`, `chrono`). Add `"crates/profiles"` to root `Cargo.toml` `[workspace] members`.

* In `src/schema.rs`, define `HarnessProfile` and `HarnessProfileOverride` containing: `profile_key: String`, `system_prompt_prefix: Option<String>`, `system_prompt_suffix: Option<String>`, `excluded_tools: BTreeSet<String>`, `excluded_middleware: BTreeSet<String>`, `tool_description_overrides: BTreeMap<String, String>`, `extra_middleware: Vec<Arc<dyn runtime::AgentMiddleware>>`, `supported_media_kinds: Option<Vec<base::ast::MediaKind>>`, `init_kwargs: BTreeMap<String, serde_json::Value>`, `context_window_tokens: usize`, and `general_purpose_subagent: Option<Box<HarnessProfileOverride>>`.

* Implement `parse_profile_key(key: &str) -> (&str, Option<&str>)` splitting strictly on the first colon via `key.split_once(':')` so `"google_genai:gemini-3.1-pro:preview"` yields `("google_genai", Some("gemini-3.1-pro:preview"))`.

* Implement `HarnessProfile::apply_override(&mut self, ovr: &HarnessProfileOverride)` obeying the exact algebraic laws:
  * `excluded_tools` and `excluded_middleware`: Set Union (`extend`).
  * `tool_description_overrides` and `init_kwargs`: Key-wise map merge (`insert` overwriting matching keys while preserving unmentioned base keys).
  * `extra_middleware`: In-place replacement by `.name()` (if `existing.iter().position(|m| m.name() == new_mw.name())` is `Some(idx)`, replace `existing[idx] = new_mw.clone()`; else `push(new_mw.clone())`).
  * `system_prompt_prefix`, `system_prompt_suffix`, `supported_media_kinds`: `Some(v)` replaces base value; `None` preserves base value.
  * `general_purpose_subagent`: Recursive field-wise merge.

* In `src/registry.rs`, implement `ProfileRegistry` with built-in provider defaults (`anthropic`, `google_genai`, `openai`, `local_vllm`) and two-level resolution (`resolve("provider:model")` clones base `"provider"` and applies `"provider:model"` override).


**Step 2: Implement 5-Block Token-Budget Allocator & Sigstore Bundle Verifier (`src/budget_allocator.rs`, `src/sigstore.rs`, `src/lib.rs`)**

* In `src/budget_allocator.rs`, implement `PromptTokenBudgetAllocator::allocate(context_window_tokens: usize) -> PromptBlockBudgets` capping total 5-block system prompt overhead at `<= 25%` of `context_window_tokens` (`max_total = context_window_tokens / 4`), with `block3_repomap_max_tokens = 2500` and `block4_memory_max_tokens = 4000` (scaled down proportionally on small context windows).

* In `src/sigstore.rs`, implement `SigstoreVerifier::verify_bundle(artifact_bytes: &[u8], bundle_json: &str, require_pq: bool) -> Result<SigstoreVerificationReport, ProfileError>` verifying: (1) artifact BLAKE3/SHA-256 digest match, (2) Fulcio certificate chain and OIDC SAN, (3) certificate validity timestamp within Rekor `integratedTime`, (4) RFC 6962 Rekor Merkle inclusion proof (`0x00` leaf, `0x01` interior node), and (5) optional ML-DSA-65 PQ signature when `require_pq == true`.

* Export all types in `crates/profiles/src/lib.rs` and run `RUSTFLAGS="-D warnings" cargo test -p profiles`.


---


## Phase 4: Implement `crates/middleware` (Crate 11)


**Step 1: Scaffold `crates/middleware` & Implement 17-Slot Onion Compiler (`src/compiler.rs`)**

* Create `crates/middleware/Cargo.toml` depending on `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, and `profiles`. Add `"crates/middleware"` to root `Cargo.toml` `[workspace] members`.

* Re-export `runtime::{AgentMiddleware, NextModelCall, TurnExecutionContext}` in `crates/middleware/src/lib.rs`.

* In `src/compiler.rs`, implement `MiddlewarePipelineCompiler::compile(canonical_slots: Vec<Arc<dyn AgentMiddleware>>, custom_middlewares: Vec<Arc<dyn AgentMiddleware>>, excluded_middleware: &BTreeSet<String>) -> Result<Vec<Arc<dyn AgentMiddleware>>, RuntimeError>`:
  * Reject exclusion of `"FilesystemMiddleware"` with `RuntimeError::MiddlewareError`.
  * Place canonical slots 1..=10 in Zone 1 and 12..=17 in Zone 3.
  * For each middleware in `custom_middlewares`: if its `.name()` matches any canonical slot in Zone 1 or Zone 3, replace that slot in-place at its exact canonical position; otherwise append it into Zone 2 (Slot 11) in registration order.
  * Filter out any slot whose `.name()` is in `excluded_middleware`.


**Step 2: Implement Zone 1 Middlewares — Slots 1 to 10 (`src/slots_zone1.rs`)**

* **Slot 1 (`IdentityAndBudgetMiddleware`)**: In `before_agent`, attests/rotates `WorkloadSvid` via `ctx.iam`, populates `WorkloadIdentitySlot` in `state.extensions` with W3C `traceparent`, and in `wrap_model_call` acquires a pre-flight `BudgetLeaseGuard` via `cognitive::CreditLeaseEnforcer`.

* **Slot 2 (`TodoListMiddleware`)**: Contributes `write_todos` and `read_todos` tool definitions.

* **Slot 3 (`FilesystemMiddleware` — MANDATORY)**: Contributes `ls`, `read_file`, `write_file`, `edit_file`, `delete`, `glob`, `grep`, and `execute` tool definitions and enforces `base::tools_meta::maybe_offload_tool_output`.

* **Slot 4 (`RepoIntelligenceMiddleware`)**: Contributes `ast_blast_radius` and `repo_map` tools. Automatically invokes `RepoEngine::on_file_mutated` after `write_file`/`edit_file` to append `< 2ms` CST syntax diagnostics to the tool result, updates `SkeletonRepoMapSlot` in `state.extensions`, and updates `blast_radius_risk` and `cyclomatic_complexity` in `cognitive::RoutingSignalsSlot`.

* **Slot 5 (`InterpreterAndSandboxMiddleware`)**: Contributes `eval` (executing in `backends::wasm::WasiSandbox`), `browser`, `computer`, and `ephemeral_tunnel` (`ctx.iam.request_scoped_tunnel_token`).

* **Slot 6 (`SkillsMiddleware`)**: In `before_agent`, scans `/skills/**/SKILL.md` in `state.files`, verifies `.sigstore.json` bundles via `profiles::SigstoreVerifier` when `verify_sigstore_bundles == true`, parses YAML frontmatter (`name`, `description`, `tags`), and populates `state.skills_metadata: Vec<SkillFrontmatter>` (progressive disclosure without loading full skill bodies into prompt).

* **Slot 7 (`SubAgentMiddleware`)**: Contributes synchronous `task` tool supporting single or parallel subagent fan-out in `SubagentMode::Isolated` or `SubagentMode::Fork`. Tracks recursion depth in `SubagentDepthSlot` (`WIRE_KEY = "tantry.middleware.subagent_depth"`, `SlotVisibility::Shared`, `CodecTag::RkyvAligned`), rejecting depth `> 3` with `RuntimeError::SubagentRecursionLimitExceeded(depth)`, and delegates to `RuntimeEngine::execute_subagents`.

* **Slot 8 (`AsyncSubAgentMiddleware`)**: Contributes `launch_async_task`, `check_async_task`, `update_async_task`, `cancel_async_task`, and `list_async_tasks` over `zenoh`, `quic-mcp`, or `http-ap`.

* **Slot 9 (`SummarizationMiddleware`)**: In `wrap_model_call`:
  * **Stage A**: Truncates `write_file` / `edit_file` `ContentBlock::ToolUse` input payloads `> 2,000` chars in messages older than `K = 6` turns.
  * **Stage B**: When estimated token utilization exceeds `85%` of context window, computes `cut_idx` at `60%` of `state.messages.len()`. While `cut_idx > 0` and (`state.messages[cut_idx]` contains `ContentBlock::ToolUse` OR `state.messages.get(cut_idx + 1)` has `role == Role::Tool` or `ContentBlock::ToolResult`), decrements `cut_idx -= 1` so a `ToolUse` is NEVER separated from its `ToolResult`. Summarizes `0..=cut_idx` using `ModelTier::CompactLite` into the 4-section Markdown schema (`## Completed Objectives`, `## Mutated Files & Symbols`, `## Active Constraints & Errors`, `## Next Immediate Step`), applies `MessageDelta::CompactRange`, archives evicted messages to `ctx.data_stores.interaction_chain`, and pushes the `CompactRange` delta into `TurnDeltaBufferSlot`.

* **Slot 10 (`PatchToolCallsMiddleware`)**: In `before_agent` / `wrap_model_call`, scans `state.messages` for any `Message` containing `ContentBlock::ToolUse { id, name, .. }` where the subsequent message does not contain a matching `ContentBlock::ToolResult { tool_use_id == id }`. Injects a synthetic recovery `Message::tool_result(id, true, "Tool call was interrupted or cancelled before completion.", None)` and records `MessageDelta::Append` in `TurnDeltaBufferSlot`.


**Step 3: Implement Zone 3 Middlewares — Slots 12 to 17 & 5-Block Prompt Compiler (`src/slots_zone3.rs`, `src/prompt_cache.rs`)**

* **Slot 12 (`CognitiveRouterMiddleware`)**: Pre-call commits any `PendingBanditFeedbackSlot` reward into `linucb_bandit_arms`, checks `SemanticCache` (obeying the Mutation Bypass Invariant), builds the 12D context vector `x_t` from `RoutingSignalsSlot` and `TantryState`, selects `ModelTier` via `CognitiveRouter` (obeying Safety Guardrails 1–4), and stores the new `PendingBanditFeedbackSlot`. Post-call settles the `BudgetLeaseGuard`.

* **Slot 13 (`ProfileFilterMiddleware`)**: Filters active `ToolDefinition` schemas against `profile.excluded_tools`, applies `profile.tool_description_overrides`, and attaches `system_prompt_prefix` / `system_prompt_suffix`.

* **Slot 14 (`MemoryMiddleware`)**: In `before_agent`, loads `/memories/AGENTS.md` and `/AGENTS.md` from `state.files` into `state.memory_contents` and contributes the `update_memory` tool.

* **Slot 15 (`RubricMiddleware`)**: Defines `RubricIterationSlot` (`WIRE_KEY = "tantry.middleware.rubric_iteration"`, `SlotVisibility::Private`, `CodecTag::RkyvAligned`). In `after_agent`, when `state.rubric_input` is `Some(rubric)`:
  * **Step 1 (`< 1ms` Deterministic Pre-Check)**: Scans modified files in `state.files` for `<<<<<<<` merge conflict markers or `tree-sitter` syntax errors (`has_error()`). If found, sets `state.rubric_status = Some(RubricOutcome::Failed { feedback })`, appends feedback message, and returns `Ok(LoopDirective::ContinueTurn)` without invoking the LLM.
  * **Step 2 (`CompactLite` LLM Grader)**: Checks `RubricIterationSlot` (max 3 iterations). Grades output via `ModelTier::CompactLite` (`is_utility_call = true`). Returns `FinishTurn` when satisfied or when `iterations >= 3` (`RubricOutcome::MaxIterationsReached { iterations: 3 }`), or injects feedback and returns `ContinueTurn`.

* **Slot 16 (`HumanInTheLoopAndAuditMiddleware`)**: Implements `evaluate_tool_permission` evaluating the 4D `PermissionLattice` (returning `Allow` if `tool_use_id` is in `HitlBypassSlot`) and appends a signed `blake3` + RFC 6962 MMR entry to `ctx.data_stores.audit_mmr` for every tool call and security event.

* **Slot 17 (`PromptCachingAndModalityMiddleware` & `src/prompt_cache.rs`)**: Compiles the 5-Block Prefix-Stable Prompt Hierarchy:
  * `Block1StaticSystem`: Base system prompt + profile prefix/suffix.
  * `Block2StaticTools`: Lexicographically sorted `ToolDefinition` JSON schemas with `CacheControl::Ephemeral` (Breakpoint #1 — never includes `RepoMap`).
  * `Block3SemiStaticSkillsAndRepoMap`: Lexicographically sorted `state.skills_metadata` frontmatter + `SkeletonRepoMapSlot`.
  * `Block4SemiStaticMemory`: Lexicographically sorted `state.memory_contents` (`AGENTS.md`) with `CacheControl::Ephemeral` (Breakpoint #2).
  * `Block5DynamicTurnState`: Active `state.todos` + `state.async_tasks`.
  * Filters unsupported `ContentBlock::Media` blocks per `profile.supported_media_kinds`.

* Run `RUSTFLAGS="-D warnings" cargo test -p middleware`.


---


## Phase 5: Implement `crates/tantry` (Crate 12 — Typestate Builder & 10-Stage Compiler)


**Step 1: Implement `TantryBuilder<B, I>` & 10-Stage Compilation Pipeline (`crates/tantry/src/builder.rs`, `src/lib.rs`)**

* Create `crates/tantry/Cargo.toml` depending on `base`, `iam`, `permissions`, `data`, `repo`, `backends`, `cognitive`, `transport`, `runtime`, `profiles`, and `middleware`. Add `"crates/tantry"` to root `Cargo.toml` `[workspace] members`.

* Define compile-time typestate structs `MissingBackend`, `BackendProvided(pub Arc<dyn VfsBackend>)`, `MissingIdentity`, and `IdentityProvided(pub Arc<dyn IdentityManager>)`.

* Implement `TantryBuilder<MissingBackend, MissingIdentity>::new(config: TantryConfig)` and transitions `.with_backend(backend)` and `.with_identity(identity)`.

* Implement `.build(self) -> Result<CompiledTantryAgent, BuildError>` exclusively on `TantryBuilder<BackendProvided, IdentityProvided>` executing all 10 deterministic stages:
  * **Stage 1**: Validate `TantryConfig` and apply `RuntimePlatform` path rebasing and worker clamping.
  * **Stage 2**: Resolve `HarnessProfile` via `ProfileRegistry::resolve` and apply caller `HarnessProfileOverride`.
  * **Stage 3 (Mandatory Scaffolding Guard)**: If `"FilesystemMiddleware"` is in `effective_profile.excluded_middleware`, return `Err(BuildError::RequiredScaffoldingExcluded("FilesystemMiddleware"))`.
  * **Stage 4 (Mandatory `read_file` Guard)**: If `"read_file"` is in `effective_profile.excluded_tools`, return `Err(BuildError::MissingMandatoryReadFileTool)`.
  * **Stage 5 (Capability-Driven Tool Pruning)**: Inspect `backend.capabilities()`. If `!capabilities.supports_delete`, insert `"delete"` into `effective_profile.excluded_tools`. If `!capabilities.supports_execute`, insert `"execute"` into `effective_profile.excluded_tools`.
  * **Stage 6 (17-Slot Onion Compilation)**: Compile the 17 middleware slots via `MiddlewarePipelineCompiler::compile`.
  * **Stage 7 (Lexicographical Tool Schema Compilation)**: Collect all tools from active middlewares, remove `effective_profile.excluded_tools`, apply `tool_description_overrides`, and sort lexicographically by `tool.name`.
  * **Stage 8 (`StateExtensionRegistry` Wiring)**: Register hydrators for all 9 built-in `StateSlot` types (`WorkloadIdentitySlot`, `SkeletonRepoMapSlot`, `PendingBanditFeedbackSlot`, `RoutingSignalsSlot`, `RubricIterationSlot`, `SubagentDepthSlot`, `HitlBypassSlot`, `TurnDeltaBufferSlot`, `McpSamplingDepthSlot`) plus any caller-registered custom slots.
  * **Stage 9 (Subagent Factory Wiring)**: Compile the recursive `general_purpose_subagent` profile and bind the subagent runner into `RuntimeEngine`.
  * **Stage 10 (`CompiledTantryAgent` Assembly)**: Return `CompiledTantryAgent` exposing `run_turn`, `stream_turn`, `resume`, `fork_thread_at_checkpoint`, `hydrate_thread_state`, and `verify_audit_integrity`.

* Run `RUSTFLAGS="-D warnings" cargo test -p tantry`.


---


## Phase 6: Implement `crates/cli` (Crate 13 — `tantry` Binary & 60fps `ratatui` TUI)


**Step 1: Implement `clap 4.5` Subcommands (`crates/cli/src/args.rs`, `src/commands.rs`, `src/main.rs`)**

* Create `crates/cli/Cargo.toml` (`[[bin]] name = "tantry"`) depending on all 12 workspace library crates plus `clap`, `ratatui`, `crossterm`, `tokio`, `tracing`, and `tracing-subscriber`. Add `"crates/cli"` and `default-members = ["crates/cli"]` to root `Cargo.toml`.

* Implement global flags `--config <PATH>` (default `"config.toml"`) and `--log-format <pretty|json>`, and all 6 subcommands in `src/commands.rs`:
  * `tantry boot [--daemon]`: Parses/validates `config.toml`, probes `HostCapabilityProbe::detect`, initializes `DualModeIdentityProvider` and `DataStoreManager`, starts `ZenohBusTransport`, `QuicMcpTransport`, and `EgressProxyServer` (`127.0.0.1:18443`), warms the sandbox pool, and awaits `SIGINT`/`SIGTERM`.
  * `tantry run <PROMPT> [-m <MODEL>] [-t <THREAD_ID>] [--rubric <RUBRIC>]`: Compiles `CompiledTantryAgent` and streams ANSI-formatted events to `stdout`.
  * `tantry repl [-w <WORKSPACE>] [-t <THREAD_ID>]`: Launches the 60fps `ratatui` TUI.
  * `tantry resume --thread-id <ID> --decision <approve|reject|edit> --tool-use-id <TOOL_ID> [--payload <JSON_OR_TEXT>]`: Invokes `agent.resume(thread_id, vec![decision])` and streams to completion.
  * `tantry branch --from-thread <ID> --step <N> [--new-thread <NEW_ID>] [--prompt <TEXT>]`: Resolves checkpoint at step `N` via `get_checkpoint_id_by_step`, constructs optional `MessageDelta::Append`, calls `fork_thread_at_checkpoint`, and executes/prints the branched timeline.
  * `tantry audit --verify-chain`: Calls `DataStoreManager::verify_all_integrity(&iam)`, exiting with code `0` on full integrity or code `1` with the exact corrupted `seq_no` or `checkpoint_id`.


**Step 2: Implement 60fps Adaptive Desktop & Termux Mobile TUI (`crates/cli/src/tui.rs`)**

* Implement the 16.6ms (60Hz) `tokio::time::interval` render loop paired with `crossterm::event::EventStream`. On every frame that drains `drained_count > 0` buffered `StreamEvent` items, send `CreditGrant { stream_id, additional_credits: drained_count }` back to `CreditControlledPublisher`.

* Implement responsive layout switching based on `frame.area().width`:
  * **Desktop Split View (`width >= 80`)**: 2x2 Quadrant Grid — Top-Left (60% width, 70% height: Live Chat, Reasoning Accordion & Streaming Tool Output), Top-Right (40% width, 70% height: Live VFS Merkle Diff Tree, CST Diagnostics & Blast Radius Risk Gauge), Bottom-Left (60% width, 30% height: Active TodoList, Subagent Execution DAG & Async Tasks), Bottom-Right (40% width, 30% height: SVID TTL Countdown, LinUCB Selected `ModelTier`, KV-Cache Hit Ratio & Credit-Lease Budget Gauge).
  * **Termux Mobile Portrait View (`width < 80`)**: Full-screen 4-Tab Bar navigated via keys `1`–`4` or `Tab` (`Tab 1 [Chat & Stream]`, `Tab 2 [Subagent DAG]`, `Tab 3 [VFS Diff & AST]`, `Tab 4 [HITL & Budget]`).

* Implement the centered HITL Approval Modal triggered on `StreamEvent::Interrupted` with hotkeys `[A]pprove`, `[R]eject`, and `[E]dit JSON`.


---


## Phase 7: Consolidate Master Verification Suites & Full Workspace Gate


**Step 1: Deduplicate Test Files & Implement `tdd_runtime_dag_scheduler_and_time_travel.rs`**

* Consolidate the 8 master verification suites so each test suite runs cleanly under `cargo test --workspace`:
  1. `tdd_base_merkle_vfs_and_deltas.rs`
  2. `tdd_iam_pq_svid_and_permissions_lattice.rs`
  3. `tdd_data_aead_mmr_and_quantized_vec.rs`
  4. `tdd_repo_scope_graph_and_mergiraf_cst.rs`
  5. `tdd_backends_cap_std_and_wasm_guard.rs`
  6. `tdd_cognitive_linucb_and_credit_leases.rs`
  7. `tdd_transport_quic_fallback_and_mcp_2026.rs`
  8. `tdd_runtime_dag_scheduler_and_time_travel.rs`

* In `tdd_runtime_dag_scheduler_and_time_travel.rs`, implement and verify:
  * Bernstein 22-tool dependency-DAG wave scheduling (concurrent execution on disjoint files, strict serialization on overlapping files, virtual metadata paths `/__meta__/*`, and global barriers `/**`).
  * Canonical 17-slot middleware compilation, `FilesystemMiddleware` smart diagnostic offloading at `> 20,000` chars, `SummarizationMiddleware` atomic `ToolUse`/`ToolResult` boundary preservation, `PatchToolCallsMiddleware` dangling tool call healing, and `TantryBuilder` guardrails (`RequiredScaffoldingExcluded("FilesystemMiddleware")`, `MissingMandatoryReadFileTool`, and capability-driven `delete`/`execute` pruning).
  * `test_counterfactual_time_travel_fork_from_checkpoint`: commit steps `1 -> 2 -> 3` on `main_thread`, call `fork_thread_at_checkpoint` from step `2` onto `branch_thread` (committing branch step `3`), commit step `4` on `main_thread`, and assert `hydrate_thread_state("main_thread").step_index == 4`, `hydrate_thread_state("branch_thread").step_index == 3`, and both timelines preserve their exact divergent `vfs_root_blake3` hashes and decrypted message histories across the cross-thread fork boundary.


**Action:** Execute Phases 1 through 7 in order, running `RUSTFLAGS="-D warnings" cargo test --workspace` and `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` after each phase until all 13 crates and all 8 master test suites pass with zero warnings.
