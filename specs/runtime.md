# Crate 9: `crates/runtime` — Durable Cyclical Graph, Bernstein DAG Scheduler & Time-Travel Engine

## 0. Crate DAG Position & Architectural Boundaries

In the Tantry 13-crate acyclic dependency graph (DAG), **`crates/runtime` is Crate 9**:

* **Direct Internal Workspace Dependencies**: `base`, `iam`, `permissions`, `data`, `backends`, `cognitive`, `transport`.
* **Direct Downstream Dependents**: `crates/profiles` (Crate 10), `crates/middleware` (Crate 11), `crates/tantry` (Crate 12), and `crates/cli` (Crate 13).

### Architectural Boundary Invariant (Zero Circular Dependencies)
Because dependencies flow strictly top-down with zero circularity:
1. **`crates/runtime` (Crate 9)** defines the polymorphic **`AgentMiddleware`** trait, the **`NextModelCall<'a>`** onion continuation type, and **`TurnExecutionContext`**, and executes them polymorphically across Phases 1, 2, 3, and 5 of `RuntimeEngine::execute_turn`.
2. **`crates/profiles` (Crate 10)** imports `runtime::AgentMiddleware` so `HarnessProfile` and `HarnessProfileOverride` can store `extra_middleware: Vec<Arc<dyn AgentMiddleware>>` and perform in-place replacement by `.name()` without depending on `crates/middleware`.
3. **`crates/middleware` (Crate 11)** depends on both `runtime` and `profiles`, re-exports `pub use runtime::{AgentMiddleware, NextModelCall, TurnExecutionContext};`, implements the concrete built-in middlewares (`Slots 1..=17`, including `SummarizationMiddleware` at Slot 9, `PatchToolCallsMiddleware` at Slot 10, `RubricMiddleware` at Slot 15, `HumanInTheLoopAndAuditMiddleware` at Slot 16, and `PromptCachingAndModalityMiddleware` at Slot 17), and compiles the canonical 17-slot pipeline in `crates/middleware/src/compiler.rs`.

---

## 1. Phase 1 — Error Taxonomy, Runtime `StateSlot`s, Polymorphic `AgentMiddleware` Contract & Observability

### 1.1 `src/error.rs` (`RuntimeError` Taxonomy)
Defines the top-level `thiserror::Error` enum for all turn execution, tool scheduling, HITL, and time-travel operations:
* `Base(#[from] base::error::BaseError)`
* `PathValidation(#[from] base::error::PathValidationError)`
* `StateReducer(#[from] base::error::StateReducerError)`
* `Extension(#[from] base::error::ExtensionError)`
* `Iam(#[from] iam::error::IamError)`
* `Data(#[from] data::error::DataError)`
* `Backend(#[from] backends::error::BackendError)`
* `Cognitive(String)` (wraps `cognitive::CognitiveError`)
* `Transport(String)` (wraps `transport::TransportError`)
* `CheckpointNotFound(String)`
* `StateHashMismatch { expected: [u8; 32], actual: [u8; 32] }`
* `SubagentRecursionLimitExceeded(u8)`
* `ToolExecutionFailed { tool_name: String, reason: String }`
* `MiddlewareError { slot_name: String, reason: String }`
* `InvalidHitlDecision(String)`

### 1.2 `src/slots.rs` (Built-In Runtime `StateSlot` Extensions)
Implements `base::typemap::StateSlot` for runtime state coordination across turns, subagents, and checkpoints:

1. **`HitlBypassSlot`**:
   * **Fields**: `pub approved_tool_use_ids: BTreeSet<ToolCallId>`
   * **Constants**: `WIRE_KEY = "tantry.runtime.hitl_bypass"`, `VISIBILITY = SlotVisibility::Private`, `CODEC_TAG = CodecTag::MessagePackNamed`.
   * **Role**: Populated by `resume_interrupted_thread` (`agent.resume`) when a human operator approves or edits a pending tool call so Phase 3 and Slot 16 (`HumanInTheLoopAndAuditMiddleware`) do not re-interrupt the already-approved `tool_use_id`.
2. **`TurnDeltaBufferSlot`**:
   * **Fields**: `pub message_deltas: Vec<MessageDelta>`
   * **Constants**: `WIRE_KEY = "tantry.runtime.turn_delta_buffer"`, `VISIBILITY = SlotVisibility::Private`, `CODEC_TAG = CodecTag::MessagePackNamed`.
   * **Role**: Initialized at the start of a turn and used by Slot 9 (`SummarizationMiddleware` pushing `MessageDelta::CompactRange`), Slot 10 (`PatchToolCallsMiddleware` pushing `MessageDelta::Append`), and HITL `ApprovalDecision::Edit` (pushing `MessageDelta::PatchById`) to record in-turn message mutations so Phase 4 drains and persists them accurately to `interaction_chain.sqlite` (including archiving evicted/original messages in `archived_messages`).
3. **`McpSamplingDepthSlot`**:
   * **Fields**: `pub depth: u8`
   * **Constants**: `WIRE_KEY = "tantry.runtime.mcp_sampling_depth"`, `VISIBILITY = SlotVisibility::Shared`, `CODEC_TAG = CodecTag::RkyvAligned`.
   * **Role**: Shared across subagent forks (`$O(1)$` `Arc` clone) so `cognitive::execute_mcp_sampling_request` enforces the strict MCP `sampling/createMessage` recursion limit ($\text{depth} < 2$, rejecting $\text{depth} \ge 2$).
4. **`SubagentDepthSlot`**:
   * **Fields**: `pub depth: u8`
   * **Constants**: `WIRE_KEY = "tantry.runtime.subagent_depth"`, `VISIBILITY = SlotVisibility::Shared`, `CODEC_TAG = CodecTag::RkyvAligned`.
   * **Role**: Shared across subagent spawns to enforce synchronous subagent recursion depth $\le 3$ and prevent fork bombs.

### 1.3 `src/middleware.rs` (Polymorphic `AgentMiddleware` Trait & Onion Continuation)
Defines the middleware execution contract invoked by `RuntimeEngine` and implemented by `crates/middleware`:

```rust
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use base::ast::ToolCallId;
use base::execution::{LoopDirective, ToolDefinition};
use base::state::TantryState;
use backends::traits::VfsBackend;
use cognitive::{LlmProvider, ModelRequest, ModelResponse};
use data::DataStoreManager;
use iam::IdentityManager;
use permissions::{PermissionLattice, PermissionMode};
use transport::backpressure::CreditControlledPublisher;

use crate::error::RuntimeError;

/// Boxed async continuation representing the inner layers of the Phase 2 `wrap_model_call` onion.
pub type NextModelCall<'a> = Box<
    dyn FnOnce(&'a mut TantryState, ModelRequest) -> Pin<
            Box<dyn Future<Output = Result<ModelResponse, RuntimeError>> + Send + 'a>,
        > + Send
        + 'a,
>;

/// Shared runtime services passed to every middleware hook during a turn.
#[derive(Clone)]
pub struct TurnExecutionContext {
    pub task_id: String,
    pub tenant_id: String,
    pub iam: Arc<dyn IdentityManager>,
    pub permission_lattice: Arc<PermissionLattice>,
    pub data_stores: Arc<DataStoreManager>,
    pub backend: Arc<dyn VfsBackend>,
    pub llm_provider: Arc<dyn LlmProvider>,
    pub publisher: Option<Arc<CreditControlledPublisher>>,
    pub active_tools: Vec<ToolDefinition>,
}

#[async_trait]
pub trait AgentMiddleware: Send + Sync {
    /// Canonical middleware name (e.g., "FilesystemMiddleware", "SummarizationMiddleware").
    fn name(&self) -> &'static str;

    /// Canonical slot number (1..=17) for built-in middlewares; `None` for custom Zone 2 middlewares.
    fn canonical_slot(&self) -> Option<u8> {
        None
    }

    /// Tool schemas contributed by this middleware slot.
    fn tools(&self) -> Vec<ToolDefinition> {
        Vec::new()
    }

    /// Phase 1: Executed in forward slot order (1 -> 17) at the start of a turn.
    async fn before_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    /// Phase 2: Executed as a nested onion (1 -> 17 -> LlmProvider -> 17 -> 1).
    async fn wrap_model_call<'a>(
        &'a self,
        state: &'a mut TantryState,
        req: ModelRequest,
        ctx: &'a TurnExecutionContext,
        next: NextModelCall<'a>,
    ) -> Result<ModelResponse, RuntimeError> {
        next(state, req).await
    }

    /// Phase 3 Hook (Slot 16 `HumanInTheLoopAndAuditMiddleware`):
    /// Evaluates a tool call against the 4D `PermissionLattice` (respecting `HitlBypassSlot`)
    /// and appends an immutable blake3 + MMR entry to `audit_log.sqlite`.
    async fn evaluate_tool_permission(
        &self,
        _state: &TantryState,
        _tool_use_id: &ToolCallId,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _ctx: &TurnExecutionContext,
    ) -> Result<Option<PermissionMode>, RuntimeError> {
        Ok(None)
    }

    /// Phase 5: Executed in reverse slot order (17 -> 1) when the assistant emits no `ToolUse` blocks.
    async fn after_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<LoopDirective, RuntimeError> {
        Ok(LoopDirective::FinishTurn)
    }
}
```

### 1.4 `src/observability.rs` (OpenTelemetry 0.33.1 & 5 Mandatory Prometheus HPA Metrics)
* Registers and updates all 5 mandatory Prometheus metrics in a `prometheus::Registry`:
  1. `tantry_microvm_snapshot_pool_available` (`Gauge`)
  2. `tantry_zenoh_task_queue_depth` (`Gauge`)
  3. `tantry_token_spend_micros_total` (`IntCounterVec` with labels `["tenant_id", "model_tier"]`)
  4. `tantry_kv_cache_hit_ratio` (`HistogramVec` with labels `["provider", "model_tier"]`)
  5. `tantry_vfs_merge_conflicts_total` (`IntCounterVec` with labels `["resolution_stage"]` $\in \{\text{"fast\_path"}, \text{"line\_diff"}, \text{"cst\_ast"}, \text{"unresolved\_conflict"}\}$)
* **Async Span Propagation Invariant**: Every spawned `tokio::spawn` task across `crates/runtime` MUST propagate the active tracing span via `tracing::Instrument::instrument(future, tracing::Span::current())`.

---

## 2. Phase 2 — Bernstein Dependency-DAG Tool Scheduler & 5-Phase Turn Engine

### 2.1 `src/tool_scheduler.rs` (22-Tool `ToolAccessClassifier`, Bernstein Conflict DAG & Wave Merger)
1. **Footprint Extraction**:
   * For a batch of `ContentBlock::ToolUse` calls $1 \dots M$, extracts $(\mathcal{R}_i, \mathcal{W}_i)$ using `base::tools_meta::ToolAccessFootprint` (including virtual metadata namespaces `/__meta__/todos`, `/__meta__/memory`, `/__meta__/async_tasks`, `/__meta__/tunnel` and global barrier `/**`).
2. **Bernstein Conflict Graph Construction**:
   * Adds a directed dependency edge $i \rightarrow j$ ($1 \le i < j \le M$) if and only if Bernstein's conflict condition holds:
     $$(\mathcal{W}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{R}_i \cap \mathcal{W}_j \neq \emptyset) \lor (\mathcal{W}_i \cap \mathcal{R}_j \neq \emptyset)$$
     where path intersection checks exact equality, global wildcard `"/**"`, or normalized directory prefix containment (e.g., `"/src"` intersects `"/src/lib.rs"`).
3. **Kahn's Level-Order Topological Wave Partitioning**:
   * Iteratively extracts all unscheduled nodes with $\text{in\_degree} = 0$ into wave $W_k$, removes their outgoing edges, and repeats until all $M$ tool calls are partitioned into ordered execution waves $W_1, W_2, \dots, W_L$.
4. **Concurrent CoW Wave Execution & 4-Stage Mergiraf Reconciliation**:
   * Executes all tools within a single wave $W_k$ concurrently (`futures::future::join_all`, instrumented with `tracing::Span::current()`) on isolated $O(1)$ CoW clones of `state.files` (`VfsTree`).
   * Applies `base::tools_meta::maybe_offload_tool_output` to any tool output exceeding $20,000$ characters or $500$ lines.
   * Reconciles all wave branch `VfsTree` mutations against the pre-wave base `VfsTree` via `backends::merge::merge_subagent_trees(&base_vfs, wave_branches, Utc::now())`.
   * Increments `tantry_vfs_merge_conflicts_total` by stage (`"fast_path"`, `"line_diff"`, `"cst_ast"`, `"unresolved_conflict"`) from `VfsMergeReport`.
   * Preserves the original $1 \dots M$ `ContentBlock::ToolResult` ordering regardless of wave completion order.

### 2.2 `src/engine.rs` (5-Phase Durable Turn Lifecycle & Parallel Subagent Runner)

#### A. 5-Phase Durable Turn Lifecycle (`RuntimeEngine::execute_turn`)
1. **Phase 1 (`before_agent` $1 \rightarrow 17$)**:
   * Ensures `TurnDeltaBufferSlot` is initialized in `state.extensions`.
   * Propagates `spiffe_id` from `ctx.iam.current_svid()` into `WorkloadIdentitySlot` in `state.extensions` if not already populated.
   * Iterates forward ($1 \rightarrow 17$) over `self.middlewares`, invoking `mw.before_agent(&mut state, &ctx).await?`.
2. **Phase 2 (`wrap_model_call` Onion $1 \rightarrow 17 \rightarrow \text{LlmProvider} \rightarrow 17 \rightarrow 1$)**:
   * Folds `self.middlewares` right-to-left around the innermost `LlmProvider` call via `invoke_model_with_middleware_onion(&mut state, req, &ctx)`:
     * When `ctx.publisher` (`Some(Arc<CreditControlledPublisher>)`) is present, opens `ctx.llm_provider.stream_complete(req)` and publishes each incoming `StreamEvent::ModelDelta` through `publisher.publish(event)` (which flushes immediately when receiver credits $> 0$ or coalesces consecutive `ModelDelta` chunks in-place via `StreamEvent::coalesce_in_place` when credits $= 0$, while never dropping or coalescing lifecycle events).
     * Obtains the completed `ModelResponse` (including `assistant_message`, `usage: TokenUsage`, `model_tier`, and `provider`).
     * Computes KV-cache hit ratio:
       $$\text{hit\_ratio} = \frac{\text{usage.cached\_tokens}}{\max(\text{usage.input\_tokens}, 1)}$$
       and records `tantry_kv_cache_hit_ratio` and `tantry_token_spend_micros_total`.
   * Appends `response.assistant_message` to `state.messages` and records it in the turn's pending message list.
3. **Phase 3 (Bernstein Parallel Tool Wave Dispatch)**:
   * Extracts all `ContentBlock::ToolUse { id, name, input }` blocks from the assistant message.
   * For each tool call:
     * Checks `HitlBypassSlot` in `state.extensions`. If `approved_tool_use_ids.contains(&id)`, removes `id` from `HitlBypassSlot` and marks the tool `PermissionMode::Allow`.
     * Otherwise queries `mw.evaluate_tool_permission(&state, &id, &name, &input, &ctx)` across `self.middlewares` (Slot 16) and joins ($\sqcup$) with `ctx.permission_lattice` evaluation.
     * If `PermissionMode::Deny`, synthesizes an immediate error `Message::tool_result(id, true, "Permission denied by policy lattice.", None)` and logs `TOOL_DENIED` to `audit_log.sqlite`.
     * If `PermissionMode::Interrupt`, adds `id` to `pending_interrupt_tools: Vec<ToolCallId>`.
   * If `pending_interrupt_tools` is empty and permitted tools exist:
     * Publishes `StreamEvent::ToolCallStart` via `CreditControlledPublisher`, executes all permitted tool waves via `BernsteinToolScheduler`, publishes `StreamEvent::ToolCallEnd`, and appends the resulting `ToolResult` messages to `state.messages`.
4. **Phase 4 (HITL Interrupt & Head-Aware Checkpoint Commit)**:
   * **Head-Step Query Invariant**: Before committing any checkpoint for `state.thread_id`, queries `InteractionChainStore::get_latest_checkpoint_for_thread(&state.thread_id)` to obtain `(head_cp_id, head_step_index)` and computes:
     $$\text{next\_step\_index} = \begin{cases} h + 1 & \text{if } \text{head\_step\_index} = \text{Some}(h) \\ 1 & \text{if } \text{head\_step\_index} = \text{None} \end{cases}$$
     and sets `previous_checkpoint_id = head_cp_id`. This guarantees `step_index` never resets to $1$ on a continuing thread and never triggers a `UNIQUE(thread_id, step_index)` collision under `InteractionChainStore::commit_checkpoint`'s strict plain `INSERT INTO` invariant.
   * Drains all `MessageDelta` entries buffered in `TurnDeltaBufferSlot` (from Slot 9 `SummarizationMiddleware`, Slot 10 `PatchToolCallsMiddleware`, or HITL `Edit`) alongside the turn's newly appended messages and `before_vfs.diff(&state.files)`, and commits the checkpoint to `interaction_chain.sqlite`.
   * Synchronizes `state.step_index = next_step_index` and `state.last_checkpoint_id = Some(committed_checkpoint_id.clone())`.
   * If `pending_interrupt_tools` is non-empty:
     * Updates `task_ledger.status = 'INTERRUPTED'`.
     * Publishes `StreamEvent::Interrupted { thread_id: state.thread_id.clone(), checkpoint_id: committed_checkpoint_id, pending_tools: pending_interrupt_tools }` via `CreditControlledPublisher`.
     * Returns `Ok(RunOutcome::Interrupted { checkpoint_id, pending_tools, state })`.
   * If tool calls were executed in Phase 3 without interrupt, loops back to **Phase 2**.
5. **Phase 5 (`after_agent` $17 \rightarrow 1$ Self-Grading Loop)**:
   * Reached only when the assistant message contains zero `ContentBlock::ToolUse` blocks.
   * Iterates in reverse slot order ($17 \rightarrow 1$) over `self.middlewares`, calling `mw.after_agent(&mut state, &ctx).await?`.
   * If any middleware (such as Slot 15 `RubricMiddleware`) returns `LoopDirective::ContinueTurn`, commits any feedback message delta and re-enters **Phase 2**.
   * Otherwise, updates `task_ledger.status = 'SUCCEEDED'`, publishes `StreamEvent::TurnComplete { step_index: state.step_index, usage }`, and returns `Ok(RunOutcome::Completed { checkpoint_id, state })`.

#### B. Synchronous Parallel Subagent Runner (`RuntimeEngine::execute_subagents`)
1. **Recursion Depth Guard**:
   * Reads `SubagentDepthSlot` from `parent_state.extensions` (defaulting to $0$). If `depth >= 3`, returns `Err(RuntimeError::SubagentRecursionLimitExceeded(depth))`.
2. **Sequential Pre-Forking (Borrow-Checker & Thread-Safety Hygiene)**:
   * Prior to entering the Rayon parallel iterator, sequentially constructs an owned `PreparedSubagentTask` vector for each `SubagentSpawnSpec`:
     * Mints a narrowed child SVID via `ctx.iam.mint_subagent_svid(&parent_svid, &spec.subagent_name, &spec.child_task_id, spec.requested_ttl)?`.
     * Attenuates the permission lattice via `ctx.permission_lattice.narrow_for_subagent(&spec.requested_permissions)` (enforcing $\text{Effective}(x) = \mathcal{P}_{\text{parent}}(x) \sqcup \mathcal{C}_{\text{child}}(x) \sqsupseteq \mathcal{P}_{\text{parent}}(x)$).
     * Forks state via `let mut child_state = parent_state.fork_for_subagent(spec.mode, spec.child_thread_id.clone(), Message::user(&spec.task_prompt));` (which strips `SlotVisibility::Private` slots, $O(1)$ clones `SlotVisibility::Shared` slots and `parent_state.files`, and resets `step_index = 0` and `last_checkpoint_id = None`).
     * Inserts `SubagentDepthSlot { depth: depth + 1 }` and the child's `WorkloadIdentitySlot` (`child_svid.spiffe_id.uri()`) into `child_state.extensions`.
3. **Bounded Rayon Parallel Execution (Termux Phantom Process Killer Immunity)**:
   * Builds or reuses a bounded `rayon::ThreadPool` capped at $\min(\text{num\_cpus}, 4)$ on `RuntimePlatform::AndroidTermux` and $\text{num\_cpus}$ on `RuntimePlatform::LinuxStandard`.
   * Executes the owned `PreparedSubagentTask` items in parallel via `thread_pool.install(|| prepared_tasks.into_par_iter().map(|task| ...).collect())`, bridging async turn execution per worker without sharing mutable references to `parent_state`.
4. **4-Stage Mergiraf VFS Reconciliation**:
   * Collects `(child_id, child_state.files)` from all completed subagents in deterministic spawn order and invokes `backends::merge::merge_subagent_trees(&parent_state.files, child_branches, Utc::now())`.
   * Updates `parent_state.files = merge_report.merged_tree`, increments `tantry_vfs_merge_conflicts_total` per resolution stage, and returns the ordered `Vec<SubagentRunResult>` and `VfsMergeReport`.

---

## 3. Phase 3 — HITL `agent.resume` & Counterfactual Time-Travel (`src/hitl.rs`, `src/time_travel.rs`)

### 3.1 `src/hitl.rs` (`resume_interrupted_thread`)
1. **Rehydration & Digest Verification**:
   * Calls `self.hydrate_thread_state(thread_id)` to reconstruct the interrupted thread at its latest checkpoint and verifies `checkpoint_blake3`.
2. **Decision Processing**:
   * Ensures `HitlBypassSlot` and `TurnDeltaBufferSlot` are present in `hydrated.state.extensions`.
   * For each `ApprovalDecision`:
     * **`ApprovalDecision::Approve { tool_use_id }`**:
       * Appends `HITL_APPROVED` entry to `audit_log.sqlite` (`AuditMmrStore`).
       * Inserts `tool_use_id` into `HitlBypassSlot::approved_tool_use_ids`.
     * **`ApprovalDecision::Edit { tool_use_id, modified_arguments }`**:
       * Calls `hydrated.state.build_tool_use_edit_delta(&tool_use_id, modified_arguments)?` to obtain `MessageDelta::PatchById { target_id, replacement }`.
       * Applies `MessageDelta::apply(&mut hydrated.state.messages, delta.clone())?` in-memory.
       * Pushes `delta` into `TurnDeltaBufferSlot::message_deltas` so Phase 4 persists the patch and archives the original unedited `ToolUse` message into `archived_messages`.
       * Appends `HITL_EDITED` entry to `audit_log.sqlite` and inserts `tool_use_id` into `HitlBypassSlot::approved_tool_use_ids`.
     * **`ApprovalDecision::Reject { tool_use_id, feedback }`**:
       * Appends `HITL_REJECTED` entry to `audit_log.sqlite`.
       * Appends `Message::tool_result(tool_use_id, true, feedback, None)` to `hydrated.state.messages` and pushes `MessageDelta::Append` to `TurnDeltaBufferSlot`.
3. **Phase 3 Resume**:
   * Updates `task_ledger.status = 'RUNNING'` and resumes `RuntimeEngine` execution directly from **Phase 3** (executing any approved/edited tool calls and committing the next head-aware checkpoint at `step_index = hydrated.step_index + 1`).

### 3.2 `src/time_travel.rs` (`hydrate_thread_state` & `fork_thread_at_checkpoint`)

#### Shared Store Handle Invariant
`RuntimeEngine` and `TimeTravelEngine` MUST share the exact same `Arc<InteractionChainStore>` and `Arc<StateExtensionRegistry>` instances (never opening a separate SQLite connection to `:memory:` or an unshared database handle).

#### 1. `hydrate_thread_state(thread_id: &str) -> Result<HydratedThreadState, RuntimeError>`
* Queries `InteractionChainStore::get_latest_checkpoint_for_thread(thread_id)?` to obtain `(latest_checkpoint_id, _head_step)`. If `None`, returns `Err(RuntimeError::CheckpointNotFound(thread_id.to_string()))`.
* Calls `InteractionChainStore::reconstruct_state_at_checkpoint(&latest_checkpoint_id, &self.extension_registry)?`, which enforces:
  1. **Backward Ancestor Walk**: Walks backward from `latest_checkpoint_id` to genesis via `previous_checkpoint_id`.
  2. **Pre-Reverse Step-Index Capture**: Captures `target_step_index = chain.first().map(|r| r.step_index).unwrap_or(0)` and `target_thread_id` from the head of the walk **before** calling `chain.reverse()`.
  3. **Cross-Thread Fork Decryption**: Replays `chain` oldest-to-newest, decrypting each ancestor row's `message_delta_aead`, `file_deltas_aead`, and `extension_slots_aead` using **that row's own `(&row.thread_id, row.key_epoch)` and `row.checkpoint_id` AAD** (never the caller's `thread_id`), so hydration seamlessly traverses across `fork_thread_at_checkpoint` boundaries.
  4. **Explicit State Synchronization**: Explicitly sets `state.step_index = target_step_index`, `state.thread_id = target_thread_id`, and `state.last_checkpoint_id = Some(latest_checkpoint_id.clone())`.
* Returns `HydratedThreadState { step_index: reconstructed.step_index, vfs_root_blake3: reconstructed.vfs_root_blake3, checkpoint_id: latest_checkpoint_id, state: reconstructed.state }`.

#### 2. `fork_thread_at_checkpoint(source_thread_id: &str, target_checkpoint_id: &str, new_thread_id: &str, state_patch: Option<MessageDelta>) -> Result<HydratedThreadState, RuntimeError>`
1. Calls `reconstruct_state_at_checkpoint(target_checkpoint_id, &self.extension_registry)?` to reconstruct the target state at step $k$ (`target.step_index == k`).
2. Initializes a fresh `key_epochs` entry for `(new_thread_id, key_epoch = 1)`.
3. Sets `target.state.thread_id = new_thread_id.to_string()`.
4. If `state_patch` is `Some(delta)`, applies `MessageDelta::apply(&mut target.state.messages, delta.clone())?`.
5. Commits the first checkpoint on `new_thread_id` via `InteractionChainStore::commit_checkpoint` with:
   * `thread_id = new_thread_id`
   * `previous_checkpoint_id = Some(target_checkpoint_id.to_string())` (zero duplication of historical rows $1 \dots k$)
   * `step_index = target.step_index + 1` ($k + 1$)
   * `message_delta = state_patch.unwrap_or_else(|| MessageDelta::Append(vec![]))`
   * `file_deltas = vec![]`
6. Synchronizes `target.state.step_index = target.step_index + 1` and `target.state.last_checkpoint_id = Some(fork_cp_id.clone())`.
7. Leaves `source_thread_id` completely untouched so subsequent commits on `source_thread_id` advance from `source_thread_id`'s own head step (e.g., `step_main == 4`), while `hydrate_thread_state(new_thread_id)` walks `cp_fork (step k+1) -> cp_k -> ... -> cp_1` and returns `step_branch == k + 1`.

---

## 4. Phase 4 — TDD Verification Matrix (`tests/tdd_runtime_dag_scheduler_and_time_travel.rs`)

All unit tests in `crates/runtime` and the workspace integration suite `tests/tdd_runtime_dag_scheduler_and_time_travel.rs` MUST pass under `cargo test --workspace` with `RUSTFLAGS="-D warnings"`:

| Test Name | Verified Invariants & Assertions |
| :--- | :--- |
| `test_bernstein_dag_scheduler_disjoint_vs_conflicting_waves` | Verifies that mutating tool calls on disjoint files (`/src/a.rs`, `/src/b.rs`) execute concurrently in Wave 1, whereas calls with write-write, read-write, or write-read overlap on the same file, prefix (`/src`), virtual metadata namespace (`/__meta__/todos`, `/__meta__/memory`, `/__meta__/async_tasks`, `/__meta__/tunnel`), or global barrier (`/**` for `execute`, `eval`, `browser`, `computer`, `task`) are serialized into subsequent topological waves while preserving $1 \dots M$ `ToolResult` ordering. |
| `test_middleware_onion_order_and_credit_backpressure_streaming` | Verifies `before_agent` runs $1 \rightarrow 17$, `wrap_model_call` enters $1 \rightarrow 17 \rightarrow \text{LlmProvider}$ and unwinds $17 \rightarrow 1$, `after_agent` runs $17 \rightarrow 1$ (looping back to Phase 2 on `LoopDirective::ContinueTurn`), and `CreditControlledPublisher` coalesces consecutive `StreamEvent::ModelDelta` chunks when credits $= 0$ without dropping `ToolCallStart`, `ToolCallEnd`, `Interrupted`, or `TurnComplete`. |
| `test_subagent_parallel_rayon_fanout_and_mergiraf_reconciliation` | Verifies `execute_subagents` pre-forks state (`SlotVisibility::Private` stripped, `SlotVisibility::Shared` preserved), narrows SVID TTLs and 4D `PermissionLattice` rules ($\mathcal{P} \sqcup \mathcal{C} \sqsupseteq \mathcal{P}$), clamps Rayon threads to $\le 4$ on `AndroidTermux`, enforces recursion depth $\le 3$, and merges concurrent child `VfsTree` edits via `merge_subagent_trees`. |
| `test_hitl_interrupt_and_resume_approve_edit_reject` | Verifies a tool matching `PermissionMode::Interrupt` halts at Phase 4 with `RunOutcome::Interrupted`, and `resume_interrupted_thread` handles `Approve` (via `HitlBypassSlot`), `Edit` (applying `MessageDelta::PatchById`, archiving the original `ToolUse` in `archived_messages`, and bypassing re-interrupt), and `Reject` (injecting an error `ToolResult`). |
| `test_counterfactual_time_travel_fork_from_checkpoint` | Commits steps $1 \rightarrow 2 \rightarrow 3$ on `main_thread`, calls `fork_thread_at_checkpoint("main_thread", &cp2_id, "branch_thread", Some(patch))` to create step $3$ on `branch_thread`, commits step $4$ on `main_thread`, and proves `hydrate_thread_state("main_thread")` returns `step_index == 4` while `hydrate_thread_state("branch_thread")` returns `step_index == 3` with exact divergent `vfs_root_blake3` hashes and zero row duplication. |
