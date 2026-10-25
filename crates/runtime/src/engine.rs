use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use futures::future::join_all;
use futures::StreamExt;
use rayon::prelude::*;
use tracing::Instrument;

use backends::merge::merge_subagent_trees;
use backends::traits::{SandboxExecRequest, VfsBackend};
use base::ast::{
    AsyncTaskHandle, AsyncTaskStatus, ContentBlock, ExecuteArtifact, FileData, Message, Role,
    SubagentMode, TodoItem, TodoStatus, ToolArtifact, ToolCallId,
};
use base::delta::{FileDelta, MessageDelta};
use base::execution::{LoopDirective, ModelTier, StreamEvent, TokenUsage, ToolDefinition};
use base::path::{validate_and_normalize_path, RuntimePlatform};
use base::state::TantryState;
use base::tools_meta::maybe_offload_tool_output;
use base::typemap::StateExtensionRegistry;
use cognitive::{LlmProvider, ModelRequest, ModelResponse};
use data::DataStoreManager;
use iam::{IdentityManager, WorkloadSvid};
use permissions::{FsOperation, PermissionLattice, PermissionMode};
use transport::backpressure::CreditControlledPublisher;

use crate::error::RuntimeError;
use crate::observability::RuntimeMetrics;
use crate::slots::{HitlBypassSlot, SubagentRecursionDepthSlot, TurnDeltaBufferSlot};
use crate::tool_scheduler::{BernsteinToolScheduler, ScheduledToolCall};

/// Boxed async continuation representing the inner layers of the `wrap_model_call` onion.
pub type NextModelCall<'a> = Box<
    dyn FnOnce(&'a mut TantryState, ModelRequest) -> Pin<
            Box<dyn Future<Output = Result<ModelResponse, RuntimeError>> + Send + 'a>,
        > + Send
        + 'a,
>;

/// Result of executing a single tool call inside a Bernstein wave.
#[derive(Debug, Clone)]
pub struct ToolExecutionOutput {
    pub raw_output: String,
    pub is_error: bool,
    pub artifact: Option<ToolArtifact>,
}

/// Specification for spawning a synchronous child subagent via the `task` tool (Slot 7).
#[derive(Debug, Clone)]
pub struct SubagentSpawnSpec {
    pub subagent_name: String,
    pub task_prompt: String,
    pub mode: SubagentMode,
    pub requested_ttl_secs: u64,
    pub requested_lattice: Option<PermissionLattice>,
}

/// Result returned from a single synchronous subagent execution.
#[derive(Debug, Clone)]
pub struct SubagentRunResult {
    pub child_task_id: String,
    pub child_thread_id: String,
    pub child_spiffe_id: String,
    pub final_response: String,
    pub usage: TokenUsage,
}

/// Outcome returned by `RuntimeEngine::execute_turn`.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    Completed {
        thread_id: String,
        checkpoint_id: String,
        step_index: u64,
        usage: TokenUsage,
        state: TantryState,
    },
    Interrupted {
        thread_id: String,
        checkpoint_id: String,
        step_index: u64,
        pending_tools: Vec<ToolCallId>,
        state: TantryState,
    },
}

/// Shared runtime services passed to every middleware hook and tool wave during a turn.
#[derive(Clone)]
pub struct TurnExecutionContext {
    pub task_id: String,
    pub tenant_id: String,
    pub iam: Arc<dyn IdentityManager>,
    pub permission_lattice: Arc<PermissionLattice>,
    pub data_stores: Arc<DataStoreManager>,
    pub llm_provider: Arc<dyn LlmProvider>,
    pub publisher: Option<Arc<CreditControlledPublisher>>,
    pub active_tools: Vec<ToolDefinition>,
    pub default_model_tier: ModelTier,
}

/// Polymorphic middleware contract defined in `crates/runtime` (Crate 9),
/// stored in `crates/profiles` (Crate 10), and implemented/re-exported by `crates/middleware` (Crate 11).
#[async_trait]
pub trait AgentMiddleware: Send + Sync {
    fn name(&self) -> &'static str;

    fn canonical_slot(&self) -> Option<u8> {
        None
    }

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

    /// Phase 3 Optional Tool Execution Hook:
    /// Allows middleware slots (e.g., Slot 4 `RepoIntelligenceMiddleware` or custom Zone 2 slots)
    /// to execute domain-specific tools before falling back to `RuntimeEngine`'s built-in dispatcher.
    async fn execute_tool(
        &self,
        _state: &mut TantryState,
        _tool_use_id: &ToolCallId,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _ctx: &TurnExecutionContext,
    ) -> Result<Option<ToolExecutionOutput>, RuntimeError> {
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

pub struct RuntimeEngine {
    pub backend: Arc<dyn VfsBackend>,
    pub middlewares: Vec<Arc<dyn AgentMiddleware>>,
    pub tool_scheduler: BernsteinToolScheduler,
    pub extension_registry: Arc<StateExtensionRegistry>,
    pub metrics: Arc<RuntimeMetrics>,
    pub max_turn_iterations: usize,
}

impl RuntimeEngine {
    pub fn new(
        backend: Arc<dyn VfsBackend>,
        middlewares: Vec<Arc<dyn AgentMiddleware>>,
        extension_registry: Arc<StateExtensionRegistry>,
        metrics: Arc<RuntimeMetrics>,
    ) -> Self {
        Self {
            backend,
            middlewares,
            tool_scheduler: BernsteinToolScheduler::new(),
            extension_registry,
            metrics,
            max_turn_iterations: 25,
        }
    }

    /// Executes the 5-Phase Durable Turn Lifecycle:
    /// Phase 1 (`before_agent` 1->17) ->
    /// Loop {
    ///   Phase 2 (`wrap_model_call` 1->17->LlmProvider->17->1) ->
    ///   Phase 3 (Bernstein Parallel Tool Wave Dispatch) ->
    ///   Phase 4 (HITL Interrupt & Head-Aware Checkpoint Commit) ->
    ///   Phase 5 (`after_agent` 17->1 Self-Grading Loop when no ToolUse blocks remain)
    /// }
    pub async fn execute_turn(
        &self,
        mut state: TantryState,
        ctx: TurnExecutionContext,
    ) -> Result<RunOutcome, RuntimeError> {
        // Ensure TurnDeltaBufferSlot is initialized in state.extensions before Phase 1.
        if state.extensions.get::<TurnDeltaBufferSlot>().is_none() {
            state.extensions.insert(TurnDeltaBufferSlot {
                message_deltas: Vec::new(),
            });
        }

        // =========================================================================
        // PHASE 1: `before_agent` (Forward Slot Order: 1 -> 17)
        // =========================================================================
        for mw in &self.middlewares {
            mw.before_agent(&mut state, &ctx).await?;
        }

        // Check if we are resuming directly into Phase 3 (when the tail message in `state.messages`
        // is already an assistant message with unexecuted `ToolUse` blocks after HITL resume).
        let completed_at_entry = Self::collect_completed_tool_ids(&state.messages);
        let mut skip_phase2_once = !Self::extract_unexecuted_tool_calls(
            &state.messages,
            &completed_at_entry,
        )
        .is_empty();

        let mut cumulative_usage = TokenUsage {
            input_tokens: 0,
            cached_tokens: 0,
            output_tokens: 0,
        };

        let max_iters = self.max_turn_iterations.max(1);
        for _iteration in 0..max_iters {
            let before_vfs = state.files.clone();
            let mut turn_new_messages: Vec<Message> = Vec::new();

            // =====================================================================
            // PHASE 2: `wrap_model_call` Onion (1 -> 17 -> LlmProvider -> 17 -> 1)
            // =====================================================================
            if !skip_phase2_once {
                let model_req = ModelRequest {
                    model_tier: ctx.default_model_tier.clone(),
                    messages: state.messages.clone(),
                    tools: ctx.active_tools.clone(),
                    prompt_blocks: Vec::new(),
                    structured_output_schema: None,
                    is_utility_call: false,
                };

                let model_resp = self
                    .invoke_model_with_middleware_onion(&mut state, model_req, &ctx)
                    .await?;

                cumulative_usage.input_tokens = cumulative_usage
                    .input_tokens
                    .saturating_add(model_resp.usage.input_tokens);
                cumulative_usage.cached_tokens = cumulative_usage
                    .cached_tokens
                    .saturating_add(model_resp.usage.cached_tokens);
                cumulative_usage.output_tokens = cumulative_usage
                    .output_tokens
                    .saturating_add(model_resp.usage.output_tokens);

                // Record token spend metrics.
                self.metrics.inc_token_spend_micros(
                    &ctx.tenant_id,
                    model_resp.model_tier.as_str(),
                    model_resp.cost_micros,
                );

                state.messages.push(model_resp.assistant_message.clone());
                turn_new_messages.push(model_resp.assistant_message);
            } else {
                skip_phase2_once = false;
            }

            // Extract all `ContentBlock::ToolUse` calls from the latest assistant message,
            // skipping any `tool_use_id` that already has a matching `ContentBlock::ToolResult`.
            let completed_tool_ids = Self::collect_completed_tool_ids(&state.messages);
            let pending_tool_calls =
                Self::extract_unexecuted_tool_calls(&state.messages, &completed_tool_ids);

            // =====================================================================
            // PHASE 3: Bernstein Parallel Tool Wave Dispatch
            // =====================================================================
            if !pending_tool_calls.is_empty() {
                let mut interrupting_tool_ids: Vec<ToolCallId> = Vec::new();
                let mut denied_tool_outcomes: BTreeMap<usize, Message> = BTreeMap::new();
                let mut executable_calls: Vec<ScheduledToolCall> = Vec::new();

                let bypassed_ids = state
                    .extensions
                    .get::<HitlBypassSlot>()
                    .map(|slot| slot.approved_tool_use_ids.clone())
                    .unwrap_or_default();

                for call in &pending_tool_calls {
                    let is_bypassed = bypassed_ids.contains(&call.id);
                    let effective_mode = self
                        .evaluate_effective_permission(&state, call, &ctx, is_bypassed)
                        .await?;

                    match effective_mode {
                        PermissionMode::Allow => {
                            executable_calls.push(call.clone());
                        }
                        PermissionMode::Interrupt => {
                            interrupting_tool_ids.push(call.id.clone());
                        }
                        PermissionMode::Deny => {
                            let deny_msg = Message::tool_result(
                                call.id.clone(),
                                true,
                                format!(
                                    "Tool '{}' execution was denied by the active PermissionLattice.",
                                    call.name
                                ),
                                None,
                            );
                            denied_tool_outcomes.insert(call.original_index, deny_msg);
                        }
                    }
                }

                // Clear consumed bypass IDs so subsequent turns evaluate normally.
                if !bypassed_ids.is_empty() {
                    if let Some(slot) = state.extensions.get_mut::<HitlBypassSlot>() {
                        for call in &pending_tool_calls {
                            slot.approved_tool_use_ids.remove(&call.id);
                        }
                    }
                }

                // If any tool requires HITL approval, jump to Phase 4 without executing tools.
                if !interrupting_tool_ids.is_empty() {
                    let (checkpoint_id, next_step_index) = self
                        .commit_turn_checkpoint(&mut state, &before_vfs, &turn_new_messages, &ctx)
                        .await?;

                    ctx.data_stores
                        .task_ledger
                        .update_task_status(&ctx.task_id, "INTERRUPTED")?;

                    if let Some(publisher) = &ctx.publisher {
                        publisher.publish(StreamEvent::Interrupted {
                            thread_id: state.thread_id.clone(),
                            checkpoint_id: checkpoint_id.clone(),
                            pending_tools: interrupting_tool_ids.clone(),
                        });
                    }

                    return Ok(RunOutcome::Interrupted {
                        thread_id: state.thread_id.clone(),
                        checkpoint_id,
                        step_index: next_step_index,
                        pending_tools: interrupting_tool_ids,
                        state,
                    });
                }

                // Partition allowed tools into conflict-free topological waves via Bernstein's condition.
                let waves = self.tool_scheduler.schedule_waves(&executable_calls);
                let mut ordered_results: BTreeMap<usize, Message> = denied_tool_outcomes;

                for wave in waves {
                    let wave_base_vfs = state.files.clone();

                    // Emit ToolCallStart lifecycle events in wave order before parallel dispatch.
                    if let Some(publisher) = &ctx.publisher {
                        for call in &wave {
                            publisher.publish(StreamEvent::ToolCallStart {
                                tool_use_id: call.id.clone(),
                                name: call.name.clone(),
                            });
                        }
                    }

                    // Execute all tools in the current wave concurrently on isolated O(1) CoW clones.
                    let wave_futures = wave.iter().map(|call| {
                        let call = call.clone();
                        let mut branch_state = state.clone();
                        let ctx_clone = ctx.clone();
                        let span = tracing::Span::current();

                        async move {
                            let exec_res = self
                                .execute_single_tool(&mut branch_state, &call, &ctx_clone)
                                .await;

                            let (raw_output, is_error, artifact) = match exec_res {
                                Ok(out) => (out.raw_output, out.is_error, out.artifact),
                                Err(err) => (
                                    format!("Tool execution error ({}): {}", call.name, err),
                                    true,
                                    None,
                                ),
                            };

                            // Smart diagnostic offloader (>20,000 chars or >500 lines -> VFS offload).
                            let final_text = maybe_offload_tool_output(
                                &call.id,
                                &raw_output,
                                &mut branch_state.files,
                                Utc::now(),
                            );

                            if let Some(publisher) = &ctx_clone.publisher {
                                publisher.publish(StreamEvent::ToolCallEnd {
                                    tool_use_id: call.id.clone(),
                                    is_error,
                                });
                            }

                            let result_msg =
                                Message::tool_result(call.id.clone(), is_error, final_text, artifact);

                            (call, result_msg, branch_state)
                        }
                        .instrument(span)
                    });

                    let wave_outcomes = join_all(wave_futures).await;

                    // Collect VFS branches and reconcile non-VFS virtual metadata footprints.
                    let mut vfs_branches = Vec::with_capacity(wave_outcomes.len());
                    for (call, result_msg, branch_state) in wave_outcomes {
                        let footprint = BernsteinToolScheduler::classify_call(&call);

                        // Reconcile virtual metadata state from the unique writer in this wave.
                        if footprint
                            .writes
                            .iter()
                            .any(|p| p.as_str() == "/__meta__/todos")
                        {
                            state.todos = branch_state.todos;
                        }
                        if footprint
                            .writes
                            .iter()
                            .any(|p| p.as_str() == "/__meta__/memory")
                        {
                            state.memory_contents = branch_state.memory_contents;
                        }
                        if footprint
                            .writes
                            .iter()
                            .any(|p| p.as_str() == "/__meta__/async_tasks")
                        {
                            state.async_tasks = branch_state.async_tasks;
                        }

                        vfs_branches.push((
                            format!("{}:{}", call.name, call.id),
                            branch_state.files,
                        ));
                        ordered_results.insert(call.original_index, result_msg);
                    }

                    // Merge wave VFS branches into `state.files` via the 4-Stage Mergiraf CST Merger.
                    if !vfs_branches.is_empty() {
                        let merge_report =
                            merge_subagent_trees(&wave_base_vfs, vfs_branches, Utc::now());
                        state.files = merge_report.merged_tree;

                        self.metrics.inc_vfs_merge_stage(
                            "fast_path",
                            merge_report.stage0_fast_forwards as u64,
                        );
                        self.metrics.inc_vfs_merge_stage(
                            "line_diff",
                            merge_report.stage1_line_merges as u64,
                        );
                        self.metrics.inc_vfs_merge_stage(
                            "cst_ast",
                            merge_report.stage2_cst_merges as u64,
                        );
                        self.metrics.inc_vfs_merge_stage(
                            "unresolved_conflict",
                            merge_report.stage3_conflicts as u64,
                        );
                    }
                }

                // Append ToolResult messages in strict 1..=M original declaration order.
                for (_idx, tool_result_msg) in ordered_results {
                    state.messages.push(tool_result_msg.clone());
                    turn_new_messages.push(tool_result_msg);
                }

                // =================================================================
                // PHASE 4: Head-Aware Checkpoint Commit (Post-Tool Wave) & Loop
                // =================================================================
                self.commit_turn_checkpoint(&mut state, &before_vfs, &turn_new_messages, &ctx)
                    .await?;

                // Loop back to Phase 2 so the model can observe the ToolResult messages.
                continue;
            }

            // =====================================================================
            // PHASE 5: `after_agent` Self-Grading Loop (Reverse Order: 17 -> 1)
            // Reached only when the assistant message emitted zero `ToolUse` blocks.
            // =====================================================================
            let messages_len_before_after_agent = state.messages.len();
            let mut should_continue_turn = false;

            for mw in self.middlewares.iter().rev() {
                let directive = mw.after_agent(&mut state, &ctx).await?;
                if directive == LoopDirective::ContinueTurn {
                    should_continue_turn = true;
                    break;
                }
            }

            // Capture any feedback messages injected by `after_agent` (e.g., Slot 15 RubricMiddleware).
            if state.messages.len() > messages_len_before_after_agent {
                turn_new_messages
                    .extend_from_slice(&state.messages[messages_len_before_after_agent..]);
            }

            // Commit the head-aware checkpoint for this step.
            let (checkpoint_id, next_step_index) = self
                .commit_turn_checkpoint(&mut state, &before_vfs, &turn_new_messages, &ctx)
                .await?;

            if should_continue_turn {
                // Re-enter Phase 2 for self-correction (e.g., RubricMiddleware failed).
                continue;
            }

            // Turn succeeded! Update ledger, publish TurnComplete, and return RunOutcome::Completed.
            ctx.data_stores
                .task_ledger
                .update_task_status(&ctx.task_id, "SUCCEEDED")?;

            if let Some(publisher) = &ctx.publisher {
                publisher.publish(StreamEvent::TurnComplete {
                    step_index: next_step_index,
                    usage: cumulative_usage.clone(),
                });
            }

            return Ok(RunOutcome::Completed {
                thread_id: state.thread_id.clone(),
                checkpoint_id,
                step_index: next_step_index,
                usage: cumulative_usage,
                state,
            });
        }

        Err(RuntimeError::MiddlewareError {
            slot_name: "RuntimeEngine".to_string(),
            reason: format!(
                "Exceeded maximum turn iterations ({}) without reaching FinishTurn",
                max_iters
            ),
        })
    }

    /// Executes synchronous child subagents in parallel using sequential pre-forking
    /// on the parent thread and a Termux-clamped Rayon pool ($\min(\text{num\_cpus}, 4)$),
    /// reconciling child VFS trees into `parent_state.files` via the 4-stage Mergiraf CST merger.
    pub fn execute_subagents(
        &self,
        parent_state: &mut TantryState,
        specs: Vec<SubagentSpawnSpec>,
        ctx: &TurnExecutionContext,
    ) -> Result<Vec<SubagentRunResult>, RuntimeError> {
        if specs.is_empty() {
            return Ok(Vec::new());
        }

        let current_depth = parent_state
            .extensions
            .get::<SubagentRecursionDepthSlot>()
            .map(|s| s.depth)
            .unwrap_or(0);
        if current_depth >= 3 {
            return Err(RuntimeError::SubagentRecursionLimitExceeded(current_depth));
        }

        let parent_svid = ctx.iam.current_svid()?;
        let base_vfs = parent_state.files.clone();

        // 1. Sequential Pre-Forking Invariant on the parent thread:
        //    Mint attenuated SVID, attenuate PermissionLattice, and O(1) fork TantryState
        //    before entering Rayon's parallel iterator.
        struct PreForkedSubagent {
            spec: SubagentSpawnSpec,
            child_task_id: String,
            child_thread_id: String,
            child_svid: WorkloadSvid,
            child_lattice: Arc<PermissionLattice>,
            child_state: TantryState,
        }

        let mut pre_forked = Vec::with_capacity(specs.len());
        for (idx, spec) in specs.into_iter().enumerate() {
            let child_task_id = format!("{}:sub:{}:{}", ctx.task_id, idx, uuid::Uuid::now_v7());
            let child_thread_id =
                format!("{}:subthread:{}", parent_state.thread_id, child_task_id);
            let requested_ttl =
                chrono::Duration::seconds(spec.requested_ttl_secs.clamp(1, 3600) as i64);

            let child_svid = ctx.iam.mint_subagent_svid(
                &parent_svid,
                &spec.subagent_name,
                &child_task_id,
                requested_ttl,
            )?;

            let child_lattice = match &spec.requested_lattice {
                Some(req_lat) => Arc::new(ctx.permission_lattice.narrow_for_subagent(req_lat)),
                None => Arc::clone(&ctx.permission_lattice),
            };

            let mut child_state = parent_state.fork_for_subagent(
                spec.mode,
                child_thread_id.clone(),
                Message::user(spec.task_prompt.clone()),
            );
            child_state.extensions.insert(SubagentRecursionDepthSlot {
                depth: current_depth + 1,
            });

            pre_forked.push(PreForkedSubagent {
                spec,
                child_task_id,
                child_thread_id,
                child_svid,
                child_lattice,
                child_state,
            });
        }

        // 2. Termux Thread-Pool Clamping Invariant:
        //    Clamp Rayon worker threads to min(num_cpus, 4) on AndroidTermux for Signal 9 immunity.
        let available_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let num_threads = match RuntimePlatform::detect_from_env() {
            RuntimePlatform::AndroidTermux => available_cpus.min(4).max(1),
            RuntimePlatform::LinuxStandard => available_cpus.max(1),
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .map_err(|e| RuntimeError::MiddlewareError {
                slot_name: "SubAgentMiddleware".to_string(),
                reason: format!("Failed to build clamped Rayon pool: {}", e),
            })?;

        let parent_span = tracing::Span::current();
        let outcomes: Vec<Result<(SubagentRunResult, base::vfs_tree::VfsTree), RuntimeError>> =
            pool.install(|| {
                pre_forked
                    .into_par_iter()
                    .map(|item| {
                        let _guard = parent_span.enter();
                        let mut child_ctx = ctx.clone();
                        child_ctx.task_id = item.child_task_id.clone();
                        child_ctx.permission_lattice = item.child_lattice;

                        let handle = tokio::runtime::Handle::try_current().ok();
                        let outcome = if let Some(rt_handle) = handle {
                            tokio::task::block_in_place(|| {
                                rt_handle.block_on(
                                    self.execute_turn(item.child_state, child_ctx)
                                        .instrument(parent_span.clone()),
                                )
                            })?
                        } else {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|e| RuntimeError::MiddlewareError {
                                    slot_name: "SubAgentMiddleware".to_string(),
                                    reason: e.to_string(),
                                })?;
                            rt.block_on(
                                self.execute_turn(item.child_state, child_ctx)
                                    .instrument(parent_span.clone()),
                            )?
                        };

                        let (final_state, usage) = match outcome {
                            RunOutcome::Completed { state, usage, .. } => (state, usage),
                            RunOutcome::Interrupted { state, .. } => (
                                state,
                                TokenUsage {
                                    input_tokens: 0,
                                    cached_tokens: 0,
                                    output_tokens: 0,
                                },
                            ),
                        };

                        let final_response = final_state
                            .messages
                            .iter()
                            .rev()
                            .find(|m| m.role == Role::Assistant)
                            .and_then(|m| m.assistant_text())
                            .unwrap_or_else(|| {
                                format!("Subagent '{}' completed.", item.spec.subagent_name)
                            });

                        Ok((
                            SubagentRunResult {
                                child_task_id: item.child_task_id,
                                child_thread_id: item.child_thread_id,
                                child_spiffe_id: item.child_svid.spiffe_id.uri().to_string(),
                                final_response,
                                usage,
                            },
                            final_state.files,
                        ))
                    })
                    .collect()
            });

        let mut results = Vec::with_capacity(outcomes.len());
        let mut child_trees = Vec::with_capacity(outcomes.len());

        for outcome in outcomes {
            let (res, tree) = outcome?;
            child_trees.push((res.child_task_id.clone(), tree));
            results.push(res);
        }

        // 3. Reconcile all child VFS trees via the 4-Stage Mergiraf CST Merger.
        let merge_report = merge_subagent_trees(&base_vfs, child_trees, Utc::now());
        parent_state.files = merge_report.merged_tree;

        self.metrics
            .inc_vfs_merge_stage("fast_path", merge_report.stage0_fast_forwards as u64);
        self.metrics
            .inc_vfs_merge_stage("line_diff", merge_report.stage1_line_merges as u64);
        self.metrics
            .inc_vfs_merge_stage("cst_ast", merge_report.stage2_cst_merges as u64);
        self.metrics
            .inc_vfs_merge_stage("unresolved_conflict", merge_report.stage3_conflicts as u64);

        Ok(results)
    }

    /// Executes Phase 2 (`wrap_model_call`) across `self.middlewares[0..N]` wrapping `LlmProvider`.
    async fn invoke_model_with_middleware_onion(
        &self,
        state: &mut TantryState,
        initial_req: ModelRequest,
        ctx: &TurnExecutionContext,
    ) -> Result<ModelResponse, RuntimeError> {
        fn build_onion<'a>(
            middlewares: &'a [Arc<dyn AgentMiddleware>],
            ctx: &'a TurnExecutionContext,
            metrics: &'a RuntimeMetrics,
        ) -> NextModelCall<'a> {
            match middlewares.split_first() {
                Some((head, tail)) => {
                    let inner_next = build_onion(tail, ctx, metrics);
                    Box::new(move |state: &'a mut TantryState, req: ModelRequest| {
                        Box::pin(async move {
                            head.wrap_model_call(state, req, ctx, inner_next).await
                        })
                    })
                }
                None => Box::new(move |_state: &'a mut TantryState, req: ModelRequest| {
                    Box::pin(async move {
                        if let Some(publisher) = &ctx.publisher {
                            let mut stream = ctx
                                .llm_provider
                                .stream_complete(req.clone())
                                .map_err(|e| RuntimeError::Cognitive(e.to_string()))?;

                            while let Some(item) = stream.next().await {
                                let event =
                                    item.map_err(|e| RuntimeError::Cognitive(e.to_string()))?;
                                publisher.publish(event);
                            }
                        }

                        let response = ctx
                            .llm_provider
                            .complete(req)
                            .map_err(|e| RuntimeError::Cognitive(e.to_string()))?;

                        let hit_ratio = (response.usage.cached_tokens as f64)
                            / (response.usage.input_tokens.max(1) as f64);
                        metrics.observe_kv_cache_hit_ratio(
                            &response.provider,
                            response.model_tier.as_str(),
                            hit_ratio,
                        );

                        Ok(response)
                    })
                }),
            }
        }

        let root_call = build_onion(&self.middlewares, ctx, &self.metrics);
        root_call(state, initial_req).await
    }

    /// Evaluates the effective `PermissionMode` for a tool call across `PermissionLattice` and middlewares.
    async fn evaluate_effective_permission(
        &self,
        state: &TantryState,
        call: &ScheduledToolCall,
        ctx: &TurnExecutionContext,
        is_bypassed: bool,
    ) -> Result<PermissionMode, RuntimeError> {
        let mut mode = PermissionMode::Allow;

        // 1. Check explicit per-tool policy in PermissionLattice.
        if let Some(&tool_mode) = ctx.permission_lattice.interrupt_on_tools.get(&call.name) {
            mode = mode.join(tool_mode);
        }

        // 2. Check filesystem capability rules for path-bearing tools.
        if let Some(raw_path) = call.input.get("path").and_then(|v| v.as_str()) {
            let fs_op = match call.name.as_str() {
                "ls" | "read_file" | "glob" | "grep" => FsOperation::READ,
                "write_file" | "edit_file" | "update_memory" => FsOperation::WRITE,
                "delete" => FsOperation::DELETE,
                "execute" => FsOperation::EXEC,
                _ => FsOperation::READ,
            };
            if let Ok(svid) = ctx.iam.current_svid() {
                let fs_mode = ctx
                    .permission_lattice
                    .fs
                    .evaluate(&svid.spiffe_id, fs_op, raw_path);
                mode = mode.join(fs_mode);
            }
        } else if call.name == "execute" {
            if let Ok(svid) = ctx.iam.current_svid() {
                let fs_mode =
                    ctx.permission_lattice
                        .fs
                        .evaluate(&svid.spiffe_id, FsOperation::EXEC, "/");
                mode = mode.join(fs_mode);
            }
        }

        // 3. Query all middlewares (Slot 16 `HumanInTheLoopAndAuditMiddleware`).
        for mw in &self.middlewares {
            if let Some(mw_mode) = mw
                .evaluate_tool_permission(state, &call.id, &call.name, &call.input, ctx)
                .await?
            {
                mode = mode.join(mw_mode);
            }
        }

        // 4. Respect HitlBypassSlot: an approved/edited tool call does not re-trigger Interrupt.
        if is_bypassed && mode == PermissionMode::Interrupt {
            mode = PermissionMode::Allow;
        }

        Ok(mode)
    }

    /// Executes a single tool call on an isolated branch `TantryState`, trying middleware
    /// handlers first and falling back to built-in `VfsBackend` and runtime state handlers.
    async fn execute_single_tool(
        &self,
        branch_state: &mut TantryState,
        call: &ScheduledToolCall,
        ctx: &TurnExecutionContext,
    ) -> Result<ToolExecutionOutput, RuntimeError> {
        // 1. Give middleware slots first chance to execute domain-specific or custom Zone 2 tools.
        for mw in &self.middlewares {
            if let Some(output) = mw
                .execute_tool(branch_state, &call.id, &call.name, &call.input, ctx)
                .await?
            {
                return Ok(output);
            }
        }

        // 2. Built-in dispatch across the canonical 22 tool families.
        match call.name.as_str() {
            // --- Slot 2: TodoList Tools ---
            "write_todos" => {
                let todos_val = call
                    .input
                    .get("todos")
                    .cloned()
                    .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
                let parsed_todos: Vec<TodoItem> =
                    serde_json::from_value(todos_val).unwrap_or_else(|_| {
                        call.input
                            .get("todos")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .enumerate()
                                    .map(|(i, item)| TodoItem {
                                        id: item
                                            .get("id")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or(&format!("todo-{}", i + 1))
                                            .to_string(),
                                        content: item
                                            .get("content")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or_default()
                                            .to_string(),
                                        status: match item
                                            .get("status")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or("pending")
                                        {
                                            "in_progress" | "InProgress" => TodoStatus::InProgress,
                                            "completed" | "Completed" => TodoStatus::Completed,
                                            "cancelled" | "Cancelled" => TodoStatus::Cancelled,
                                            _ => TodoStatus::Pending,
                                        },
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    });
                let count = parsed_todos.len();
                branch_state.todos = parsed_todos;
                Ok(ToolExecutionOutput {
                    raw_output: format!("Updated todo list with {} items.", count),
                    is_error: false,
                    artifact: None,
                })
            }
            "read_todos" => {
                let json = serde_json::to_string_pretty(&branch_state.todos)
                    .unwrap_or_else(|_| "[]".to_string());
                Ok(ToolExecutionOutput {
                    raw_output: json,
                    is_error: false,
                    artifact: None,
                })
            }

            // --- Slot 3: Filesystem & Execution Tools (`VfsBackend`) ---
            "ls" => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                let entries = self.backend.ls(branch_state, path)?;
                let formatted = serde_json::to_string_pretty(&entries)
                    .unwrap_or_else(|_| format!("{:?}", entries));
                Ok(ToolExecutionOutput {
                    raw_output: formatted,
                    is_error: false,
                    artifact: None,
                })
            }
            "read_file" => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RuntimeError::MiddlewareError {
                        slot_name: "FilesystemMiddleware".to_string(),
                        reason: "Missing 'path' argument for read_file".to_string(),
                    })?;
                let offset_line = call
                    .input
                    .get("offset_line")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize);
                let limit_lines = call
                    .input
                    .get("limit_lines")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize);
                let content =
                    self.backend
                        .read_file(branch_state, path, offset_line, limit_lines)?;
                Ok(ToolExecutionOutput {
                    raw_output: content,
                    is_error: false,
                    artifact: None,
                })
            }
            "write_file" => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RuntimeError::MiddlewareError {
                        slot_name: "FilesystemMiddleware".to_string(),
                        reason: "Missing 'path' argument for write_file".to_string(),
                    })?;
                let content = call
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let receipt = self.backend.write_file(branch_state, path, content)?;
                Ok(ToolExecutionOutput {
                    raw_output: serde_json::to_string(&receipt)
                        .unwrap_or_else(|_| format!("Wrote {} bytes to {}", content.len(), path)),
                    is_error: false,
                    artifact: None,
                })
            }
            "edit_file" => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RuntimeError::MiddlewareError {
                        slot_name: "FilesystemMiddleware".to_string(),
                        reason: "Missing 'path' argument for edit_file".to_string(),
                    })?;
                let old_string = call
                    .input
                    .get("old_string")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let new_string = call
                    .input
                    .get("new_string")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let replace_all = call
                    .input
                    .get("replace_all")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let receipt = self.backend.edit_file(
                    branch_state,
                    path,
                    old_string,
                    new_string,
                    replace_all,
                )?;
                Ok(ToolExecutionOutput {
                    raw_output: serde_json::to_string(&receipt)
                        .unwrap_or_else(|_| format!("Edited {}", path)),
                    is_error: false,
                    artifact: None,
                })
            }
            "delete" => {
                let path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RuntimeError::MiddlewareError {
                        slot_name: "FilesystemMiddleware".to_string(),
                        reason: "Missing 'path' argument for delete".to_string(),
                    })?;
                self.backend.delete(branch_state, path)?;
                Ok(ToolExecutionOutput {
                    raw_output: format!("Deleted {}", path),
                    is_error: false,
                    artifact: None,
                })
            }
            "glob" => {
                let pattern = call
                    .input
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("**/*");
                let matches = self.backend.glob(branch_state, pattern)?;
                Ok(ToolExecutionOutput {
                    raw_output: matches.join("\n"),
                    is_error: false,
                    artifact: None,
                })
            }
            "grep" => {
                let pattern = call
                    .input
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let path_glob = call.input.get("path_glob").and_then(|v| v.as_str());
                let matches = self.backend.grep(branch_state, pattern, path_glob)?;
                let formatted = serde_json::to_string_pretty(&matches)
                    .unwrap_or_else(|_| format!("{:?}", matches));
                Ok(ToolExecutionOutput {
                    raw_output: formatted,
                    is_error: false,
                    artifact: None,
                })
            }
            "execute" => {
                let command = call
                    .input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let args: Vec<String> = call
                    .input
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let timeout_ms = call
                    .input
                    .get("timeout_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(30_000);
                let scrubbed_env = ctx.permission_lattice.env.scrub_host_env(std::env::vars());

                let req = SandboxExecRequest {
                    command,
                    args,
                    env: scrubbed_env,
                    timeout_ms,
                    cwd: call
                        .input
                        .get("cwd")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                };

                let exec_res = self.backend.execute(req)?;
                let combined_output = if exec_res.stderr.is_empty() {
                    exec_res.stdout.clone()
                } else {
                    format!("{}\n{}", exec_res.stdout, exec_res.stderr)
                };

                let artifact = ToolArtifact::Execute(ExecuteArtifact {
                    exit_code: exec_res.exit_code,
                    timed_out: exec_res.timed_out,
                    duration_ms: exec_res.duration_ms,
                    peak_rss_bytes: exec_res.peak_rss_bytes,
                    sandbox_id: exec_res.sandbox_id,
                    isolation_tier: exec_res.isolation_tier,
                });

                Ok(ToolExecutionOutput {
                    raw_output: combined_output,
                    is_error: exec_res.exit_code != 0 || exec_res.timed_out,
                    artifact: Some(artifact),
                })
            }

            // --- Slot 5: Ephemeral Tunnel Tool ---
            "ephemeral_tunnel" => {
                let service_name = call
                    .input
                    .get("service_name")
                    .or_else(|| call.input.get("host"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("localhost");
                let ttl_secs = call
                    .input
                    .get("ttl_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(300) as u32;
                let grant = ctx
                    .iam
                    .request_scoped_tunnel_token(service_name, ttl_secs)?;
                Ok(ToolExecutionOutput {
                    raw_output: serde_json::to_string(&grant)
                        .unwrap_or_else(|_| grant.token.clone()),
                    is_error: false,
                    artifact: None,
                })
            }

            // --- Slot 7: Synchronous Subagent Fan-Out (`task`) ---
            "task" => {
                let subagent_name = call
                    .input
                    .get("subagent_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("general_purpose_subagent")
                    .to_string();
                let prompt = call
                    .input
                    .get("prompt")
                    .or_else(|| call.input.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let mode = match call.input.get("mode").and_then(|v| v.as_str()) {
                    Some("fork") | Some("Fork") => SubagentMode::Fork,
                    _ => SubagentMode::Isolated,
                };
                let ttl_secs = call
                    .input
                    .get("ttl_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(900);

                let specs = vec![SubagentSpawnSpec {
                    subagent_name,
                    task_prompt: prompt,
                    mode,
                    requested_ttl_secs: ttl_secs,
                    requested_lattice: None,
                }];

                let sub_results = self.execute_subagents(branch_state, specs, ctx)?;
                let summary = sub_results
                    .into_iter()
                    .map(|r| r.final_response)
                    .collect::<Vec<_>>()
                    .join("\n\n");

                Ok(ToolExecutionOutput {
                    raw_output: summary,
                    is_error: false,
                    artifact: None,
                })
            }

            // --- Slot 8: Async Subagent Task Tools ---
            "launch_async_task" => {
                let task_id = call
                    .input
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
                let subagent_name = call
                    .input
                    .get("subagent_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("general_purpose_subagent")
                    .to_string();
                let transport_scheme = call
                    .input
                    .get("transport_scheme")
                    .and_then(|v| v.as_str())
                    .unwrap_or("zenoh")
                    .to_string();
                let endpoint = call
                    .input
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("local")
                    .to_string();

                let parent_svid = ctx.iam.current_svid()?;
                let child_svid = ctx.iam.mint_subagent_svid(
                    &parent_svid,
                    &subagent_name,
                    &task_id,
                    chrono::Duration::minutes(15),
                )?;

                let handle = AsyncTaskHandle {
                    task_id: task_id.clone(),
                    subagent_name,
                    transport_scheme,
                    endpoint,
                    thread_id: format!("{}:async:{}", branch_state.thread_id, task_id),
                    run_id: uuid::Uuid::now_v7().to_string(),
                    child_svid_spiffe_id: child_svid.spiffe_id.uri().to_string(),
                    status: AsyncTaskStatus::Running,
                };
                branch_state
                    .async_tasks
                    .insert(task_id.clone(), handle.clone());

                Ok(ToolExecutionOutput {
                    raw_output: serde_json::to_string(&handle).unwrap_or_else(|_| task_id),
                    is_error: false,
                    artifact: None,
                })
            }
            "check_async_task" => {
                let task_id = call
                    .input
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let status_json = branch_state
                    .async_tasks
                    .get(task_id)
                    .and_then(|h| serde_json::to_string(h).ok())
                    .unwrap_or_else(|| format!("{{\"error\":\"Task '{}' not found\"}}", task_id));
                Ok(ToolExecutionOutput {
                    raw_output: status_json,
                    is_error: !branch_state.async_tasks.contains_key(task_id),
                    artifact: None,
                })
            }
            "update_async_task" => {
                let task_id = call
                    .input
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if let Some(handle) = branch_state.async_tasks.get_mut(task_id) {
                    handle.status = AsyncTaskStatus::Running;
                    Ok(ToolExecutionOutput {
                        raw_output: serde_json::to_string(handle)
                            .unwrap_or_else(|_| "Updated".to_string()),
                        is_error: false,
                        artifact: None,
                    })
                } else {
                    Ok(ToolExecutionOutput {
                        raw_output: format!("Task '{}' not found", task_id),
                        is_error: true,
                        artifact: None,
                    })
                }
            }
            "cancel_async_task" => {
                let task_id = call
                    .input
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if let Some(handle) = branch_state.async_tasks.get_mut(task_id) {
                    handle.status = AsyncTaskStatus::Cancelled;
                    Ok(ToolExecutionOutput {
                        raw_output: format!("Cancelled async task '{}'", task_id),
                        is_error: false,
                        artifact: None,
                    })
                } else {
                    Ok(ToolExecutionOutput {
                        raw_output: format!("Task '{}' not found", task_id),
                        is_error: true,
                        artifact: None,
                    })
                }
            }
            "list_async_tasks" => {
                let tasks: Vec<&AsyncTaskHandle> = branch_state.async_tasks.values().collect();
                Ok(ToolExecutionOutput {
                    raw_output: serde_json::to_string_pretty(&tasks)
                        .unwrap_or_else(|_| "[]".to_string()),
                    is_error: false,
                    artifact: None,
                })
            }

            // --- Slot 14: Memory Tool ---
            "update_memory" => {
                let raw_path = call
                    .input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/memories/AGENTS.md");
                let normalized_path = validate_and_normalize_path(raw_path)?;
                let content = call
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();

                branch_state
                    .memory_contents
                    .insert(normalized_path.clone(), content.clone());
                branch_state.files.insert(
                    normalized_path.clone(),
                    Arc::new(FileData::new_utf8(content, Utc::now())),
                )?;

                Ok(ToolExecutionOutput {
                    raw_output: format!("Updated memory at {}", normalized_path),
                    is_error: false,
                    artifact: None,
                })
            }

            // Fallback for custom or mock tool schemas in isolated tests
            other => Ok(ToolExecutionOutput {
                raw_output: format!("Executed tool '{}' with arguments {}", other, call.input),
                is_error: false,
                artifact: None,
            }),
        }
    }

    /// Phase 4 Helper: Queries head step from `InteractionChainStore`, drains `TurnDeltaBufferSlot`,
    /// computes VFS `FileDelta`s, and commits the new checkpoint atomically.
    async fn commit_turn_checkpoint(
        &self,
        state: &mut TantryState,
        before_vfs: &base::vfs_tree::VfsTree,
        turn_new_messages: &[Message],
        ctx: &TurnExecutionContext,
    ) -> Result<(String, u64), RuntimeError> {
        // Head-Step Query Invariant: Always query the current head of `state.thread_id`
        // from `interaction_checkpoints` so `step_index` never resets to 1 on a continuing thread.
        let head_info = ctx
            .data_stores
            .interaction_chain
            .get_latest_checkpoint_for_thread(&state.thread_id)?;

        let (previous_checkpoint_id, next_step_index) = match head_info {
            Some((head_cp_id, head_step)) => (Some(head_cp_id), head_step + 1),
            None => (state.last_checkpoint_id.clone(), state.step_index.saturating_add(1)),
        };

        // Drain any buffered MessageDeltas from Slot 9 (Summarization), Slot 10 (PatchToolCalls), or HITL Edit.
        let buffered_deltas = state
            .extensions
            .get_mut::<TurnDeltaBufferSlot>()
            .map(|slot| std::mem::take(&mut slot.message_deltas))
            .unwrap_or_default();

        // Fold buffered deltas and this turn's newly appended messages into the checkpoint's MessageDelta.
        let message_delta = match buffered_deltas.into_iter().last() {
            Some(MessageDelta::CompactRange {
                up_to_id_inclusive,
                summary_message,
            }) if turn_new_messages.is_empty() => MessageDelta::CompactRange {
                up_to_id_inclusive,
                summary_message,
            },
            Some(MessageDelta::PatchById {
                target_id,
                replacement,
            }) if turn_new_messages.is_empty() => MessageDelta::PatchById {
                target_id,
                replacement,
            },
            _ => MessageDelta::Append(turn_new_messages.to_vec()),
        };

        let file_deltas: Vec<FileDelta> = before_vfs.diff(&state.files);
        let raw_extension_slots = state.extensions.serialize_all()?;

        let checkpoint_id = ctx.data_stores.interaction_chain.commit_checkpoint(
            &state.thread_id,
            previous_checkpoint_id.as_deref(),
            next_step_index,
            &message_delta,
            &file_deltas,
            &state.todos,
            &state.async_tasks,
            &raw_extension_slots,
            state.files.root_hash(),
        )?;

        state.step_index = next_step_index;
        state.last_checkpoint_id = Some(checkpoint_id.clone());

        Ok((checkpoint_id, next_step_index))
    }

    fn collect_completed_tool_ids(messages: &[Message]) -> BTreeSet<ToolCallId> {
        let mut completed = BTreeSet::new();
        for msg in messages {
            for block in &msg.content {
                if let ContentBlock::ToolResult { tool_use_id, .. } = block {
                    completed.insert(tool_use_id.clone());
                }
            }
        }
        completed
    }

    fn extract_unexecuted_tool_calls(
        messages: &[Message],
        completed_tool_ids: &BTreeSet<ToolCallId>,
    ) -> Vec<ScheduledToolCall> {
        let Some(last_assistant_msg) = messages.iter().rev().find(|m| m.role == Role::Assistant)
        else {
            return Vec::new();
        };

        let mut calls = Vec::new();
        for (idx, block) in last_assistant_msg.content.iter().enumerate() {
            if let ContentBlock::ToolUse { id, name, input } = block {
                if !completed_tool_ids.contains(id) {
                    calls.push(ScheduledToolCall {
                        original_index: idx,
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    });
                }
            }
        }
        calls
    }
}