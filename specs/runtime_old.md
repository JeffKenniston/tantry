## 10. Crate 9: `crates/runtime` (Durable Cyclical Graph, Bernstein DAG Scheduler & Time-Travel Engine)

### Crate `runtime`: Phase 1 — Runtime `StateSlot`s, Error Taxonomy & OpenTelemetry/Prometheus Metrics
1. **`src/slots.rs` (Built-In Runtime `StateSlot` Extensions)**:
   * `HitlBypassSlot`: `approved_tool_use_ids: BTreeSet<ToolCallId>` (`WIRE_KEY = "tantry.runtime.hitl_bypass"`, `VISIBILITY = SlotVisibility::Private`, `CODEC_TAG = CodecTag::MessagePackNamed`). Populated by `agent.resume` so Slot 16 does not re-interrupt an approved tool call.
   * `TurnDeltaBufferSlot`: `message_deltas: Vec<MessageDelta>` (`WIRE_KEY = "tantry.runtime.turn_delta_buffer"`, `VISIBILITY = SlotVisibility::Private`, `CODEC_TAG = CodecTag::MessagePackNamed`). Used by Slot 9 (`SummarizationMiddleware`) and Slot 10 (`PatchToolCallsMiddleware`) to record in-turn message compactions/patches so Phase 4 persists them accurately to `interaction_chain.sqlite`.
   * `McpSamplingDepthSlot`: `depth: u8` (`WIRE_KEY = "tantry.runtime.mcp_sampling_depth"`, `VISIBILITY = SlotVisibility::Shared`, `CODEC_TAG = CodecTag::RkyvAligned`).
2. **`src/observability.rs` (OpenTelemetry 0.33.1 & 5 Prometheus HPA Metrics)**:
   * Registers and updates all 5 mandatory Prometheus metrics in a `prometheus::Registry`:
     1. `tantry_microvm_snapshot_pool_available` (`Gauge`)
     2. `tantry_zenoh_task_queue_depth` (`Gauge`)
     3. `tantry_token_spend_micros_total` (`IntCounterVec` labels: `["tenant_id", "model_tier"]`)
     4. `tantry_kv_cache_hit_ratio` (`HistogramVec` labels: `["provider", "model_tier"]`)
     5. `tantry_vfs_merge_conflicts_total` (`IntCounterVec` labels: `["resolution_stage"]` $\in \{\text{"fast\_path"}, \text{"line\_diff"}, \text{"cst\_ast"}, \text{"unresolved\_conflict"}\}$)
   * Every spawned `tokio::spawn` task MUST propagate the current tracing span via `.instrument(tracing::Span::current())`.

### Crate `runtime`: Phase 2 — Bernstein Dependency-DAG Tool Scheduler & 5-Phase Turn Engine
1. **`src/tool_scheduler.rs` (22-Tool `ToolAccessClassifier`, Bernstein Conflict DAG & Wave Merger)**:
   * For a batch of `ContentBlock::ToolUse` calls $1 \dots M$, extracts $(\mathcal{R}_i, \mathcal{W}_i)$ using `base::tools_meta::ToolAccessFootprint` (including virtual metadata paths `/__meta__/todos`, `/__meta__/memory`, `/__meta__/async_tasks`, `/__meta__/tunnel` and global barrier `/**`).
   * Adds a directed edge $i \rightarrow j$ ($1 \le i < j \le M$) if and only if Bernstein's conflict condition holds:
     $$(\mathcal{W}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{R}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{W}_i \cap \mathcal{R}_j \neq \emptyset)$$
     where path intersection checks exact equality or prefix containment (e.g., `/**` intersects every path; `/src` intersects `/src/lib.rs`).
   * Partitions tools into topological waves by in-degree $= 0$ (Kahn's level-order algorithm).
   * Executes all tools in a single wave concurrently (`futures::future::join_all`) on isolated $O(1)$ CoW clones of `state.files` (`VfsTree`), reconciles their file mutations via `backends::merge::merge_subagent_trees`, updates `tantry_vfs_merge_conflicts_total` per stage, and preserves the original `1..=M` `ToolResult` ordering.
2. **`src/engine.rs` (5-Phase Durable Turn Lifecycle & Synchronous Subagent Runner)**:
   * **Phase 1 (`before_agent`)**: Runs middleware slots $1 \rightarrow 17$ `before_agent(&mut state, &ctx)`.
   * **Phase 2 (`wrap_model_call`)**: Runs middleware slots $1 \rightarrow 17$ `wrap_model_call`, streaming `StreamEvent::ModelDelta` via `CreditControlledPublisher`.
   * **Phase 3 (Bernstein Parallel Tool Wave Dispatch)**: Evaluates `PermissionLattice` via Slot 16 (`HumanInTheLoopAndAuditMiddleware`, respecting `HitlBypassSlot`). Executes permitted tool waves via `BernsteinToolScheduler`.
   * **Phase 4 (HITL Interrupt & Head-Aware Checkpoint Commit)**:
     * **Head-Step Query Invariant**: Before committing any checkpoint for `thread_id`, queries `InteractionChainStore::get_latest_checkpoint_for_thread(thread_id)` to obtain `(head_cp_id, head_step_index)` and sets `next_step_index = head_step_index.map_or(1, |s| s + 1)` and `previous_checkpoint_id = head_cp_id` (ensuring `step_index` never resets to `1` on a continuing thread).
     * Drains `TurnDeltaBufferSlot` + the turn's new messages and `before_vfs.diff(&state.files)` into `InteractionChainStore::commit_checkpoint`.
     * If any tool returned `PermissionMode::Interrupt`, sets `task_ledger.status = 'INTERRUPTED'`, emits `StreamEvent::Interrupted`, and returns `RunOutcome::Interrupted`.
     * If `ToolUse` calls were executed without interrupt, loops back to Phase 2.
   * **Phase 5 (`after_agent` Self-Grading Loop)**: When the model emits no `ToolUse` blocks, executes middleware slots $17 \rightarrow 1$ `after_agent(&mut state, &ctx)`. If Slot 15 (`RubricMiddleware`) returns `LoopDirective::ContinueTurn`, re-enters Phase 2; otherwise sets `task_ledger.status = 'SUCCEEDED'` and returns `RunOutcome::Completed`.
   * **`execute_subagents` (Synchronous Subagent Fan-Out Orchestrator)**: For each `SubagentSpawnSpec`, mints a narrowed child SVID (`iam.mint_subagent_svid`), narrows the policy (`lattice.narrow_for_subagent`), forks state (`state.fork_for_subagent`), runs child turn loops in parallel, and merges all child `VfsTree`s into the parent `VfsTree` via `merge_subagent_trees`.

### Crate `runtime`: Phase 3 — HITL `agent.resume` & Counterfactual Time-Travel (`src/hitl.rs`, `src/time_travel.rs`)
1. **`src/hitl.rs` (`resume_interrupted_thread`)**:
   * Rehydrates the interrupted thread via `hydrate_thread_state(thread_id)` and verifies `checkpoint_blake3`.
   * Processes each `ApprovalDecision`:
     * `Approve { tool_use_id }`: Appends `HITL_APPROVED` to `audit_log` and inserts `tool_use_id` into `HitlBypassSlot`.
     * `Edit { tool_use_id, modified_arguments }`: Calls `state.build_tool_use_edit_delta(tool_use_id, modified_arguments)`, applies `MessageDelta::PatchById` to `state.messages`, pushes the delta to `TurnDeltaBufferSlot` (archiving the original unedited `ToolUse` message in `archived_messages`), appends `HITL_EDITED` to `audit_log`, and inserts `tool_use_id` into `HitlBypassSlot`.
     * `Reject { tool_use_id, feedback }`: Appends `HITL_REJECTED` to `audit_log` and appends `ContentBlock::ToolResult { tool_use_id, is_error: true, content: vec![ContentBlock::Text { text: feedback, cache_control: None }], artifact: None }`.
   * Resumes `execute_turn` from Phase 3.
2. **`src/time_travel.rs` (`hydrate_thread_state` & `fork_thread_at_checkpoint`)**:
   * `hydrate_thread_state(thread_id) -> Result<HydratedThreadState, RuntimeError>`: Looks up the latest `checkpoint_id` for `thread_id`, calls `InteractionChainStore::reconstruct_state_at_checkpoint`, and returns `HydratedThreadState { step_index, vfs_root_blake3, checkpoint_id, state }`.
   * `fork_thread_at_checkpoint(source_thread_id, target_checkpoint_id, new_thread_id, state_patch: Option<MessageDelta>) -> Result<HydratedThreadState, RuntimeError>`:
     1. Calls `reconstruct_state_at_checkpoint(target_checkpoint_id)` to reconstruct `target` (`target.step_index == k`).
     2. Initializes a new `key_epochs` entry for `(new_thread_id, key_epoch = 1)`.
     3. If `state_patch` is `Some(delta)`, applies `MessageDelta::apply(&mut target.state.messages, delta.clone())`.
     4. Commits the first checkpoint on `new_thread_id` with:
        * `thread_id = new_thread_id`
        * `previous_checkpoint_id = Some(target_checkpoint_id.to_string())` (zero duplication of historical rows $1 \dots k$)
        * `step_index = target.step_index + 1` ($k + 1$)
        * `message_delta = state_patch.unwrap_or_else(|| MessageDelta::Append(vec![]))`
        * `file_deltas = vec![]`
     5. Leaves `source_thread_id` completely untouched so subsequent commits on `source_thread_id` advance from `source_thread_id`'s own head step (`step_main == 4`), while `hydrate_thread_state(new_thread_id)` walks `cp_fork (step k+1) -> cp_k -> ... -> cp_1` decrypting each row with its own `(row.thread_id, row.key_epoch)`.

---
