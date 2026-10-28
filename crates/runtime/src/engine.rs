
use base::ast::{ContentBlock, ExecuteArtifact, Message, TodoItem, TodoStatus, ToolArtifact, ToolCallId, AsyncTaskHandle, AsyncTaskStatus};
use base::delta::{FileDelta, MessageDelta};
use base::execution::{ApprovalDecision, LoopDirective, ModelRequest, StreamEvent};
use base::state::TantryState;
use base::vfs_tree::VfsTree;
use chrono::Utc;
use futures::StreamExt;
use permissions::lattice::PermissionMode;
use std::sync::Arc;
use serde_json::Value;

use crate::error::RuntimeError;
use crate::middleware::{AgentMiddleware, NextModelCall, ToolExecutionOutput, TurnExecutionContext};
use crate::slots::{HitlBypassSlot, TurnDeltaBufferSlot};
use crate::tool_scheduler::{BernsteinToolScheduler, ToolAccessClassifier, ToolUseCall};
use backends::traits::SandboxExecRequest;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum TurnExecutionOutcome {
    Completed(TantryState),
    Interrupted,
}

pub struct RuntimeEngine {
    pub middlewares: Vec<Arc<dyn AgentMiddleware>>,
}

impl RuntimeEngine {
    pub fn new(middlewares: Vec<Arc<dyn AgentMiddleware>>) -> Self {
        Self { middlewares }
    }

    pub async fn execute_turn(
        &self,
        mut state: TantryState,
        ctx: &TurnExecutionContext,
    ) -> Result<TurnExecutionOutcome, RuntimeError> {
        state
            .extensions
            .insert(TurnDeltaBufferSlot {
                message_deltas: vec![],
            });

        for mw in &self.middlewares {
            mw.before_agent(&mut state, ctx).await?;
        }

        let max_steps_per_turn = 50;
        let mut steps = 0;
        let mut cumulative_usage = base::execution::TokenUsage::default();

                loop {
            let _step_start_vfs = state.files.clone();
            if steps >= max_steps_per_turn {
                break;
            }
            steps += 1;

            let is_resuming_hitl = state.extensions.get::<HitlBypassSlot>().is_some();
            let mut calls = Vec::new();

            #[allow(clippy::collapsible_if)]
            if is_resuming_hitl {
                if let Some(last_msg) = state.messages.last() {
                    for block in &last_msg.content {
                        if let ContentBlock::ToolUse { id, name, input } = block {
                            let footprint = ToolAccessClassifier::classify(name, input);
                            calls.push(ToolUseCall {
                                tool_use_id: id.clone(),
                                tool_name: name.clone(),
                                tool_input: input.clone(),
                                footprint,
                            });
                        }
                    }
                }
            }

            if !is_resuming_hitl {
                let req = ModelRequest {
                    messages: state.messages.clone(),
                    target_tier: ctx.default_model_tier.clone(),
                };

                let provider = ctx.llm_provider.clone();
                let mut publisher_opt = ctx.publisher.clone();
                let _tier = ctx.default_model_tier.clone();

                let mut inner: NextModelCall = Box::new(move |_st, r| {
                    Box::pin(async move {
                        if let Some(pub_handle) = &mut publisher_opt {
                            let mut stream = provider.stream_complete(r.clone())?;
                            while let Some(res) = stream.next().await {
                                let evt = res?;
                                if let StreamEvent::ModelDelta { .. } = evt {
                                    pub_handle.publish_event(evt);
                                }
                            }

                            // Now get the full structured response
                            provider.complete(r).map_err(Into::into)
                        } else {
                            provider.complete(r).map_err(Into::into)
                        }
                    })
                });

                for mw in self.middlewares.iter().rev() {
                    let next = inner;
                    inner = Box::new(move |st, r| {
                        Box::pin(async move { mw.wrap_model_call(st, r, ctx, next).await })
                    });
                }

                let response = inner(&mut state, req).await?;
                let assistant_msg = response.assistant_message;
                state.messages.push(assistant_msg.clone());
                if let Some(mut delta) = state.extensions.get::<TurnDeltaBufferSlot>().cloned() {
                    delta
                        .message_deltas
                        .push(MessageDelta::Append(vec![assistant_msg.clone()]));
                    state.extensions.insert(delta);
                }

                cumulative_usage.input_tokens += response.usage.input_tokens;
                cumulative_usage.cached_tokens += response.usage.cached_tokens;
                cumulative_usage.output_tokens += response.usage.output_tokens;

                ctx.metrics
                    .kv_cache_hit_ratio
                    .with_label_values(&["llm", ctx.default_model_tier.as_str()])
                    .observe(
                        response.usage.cached_tokens as f64
                            / (response.usage.input_tokens.max(1) as f64),
                    );
                ctx.metrics
                    .token_spend_micros_total
                    .with_label_values(&[&ctx.tenant_id.clone(), &ctx.default_model_tier.as_str().to_string()])
                    .inc_by(response.usage.input_tokens + response.usage.output_tokens);

                for block in &assistant_msg.content {
                    if let ContentBlock::ToolUse { id, name, input } = block {
                        let footprint = ToolAccessClassifier::classify(name, input);
                        calls.push(ToolUseCall {
                            tool_use_id: id.clone(),
                            tool_name: name.clone(),
                            tool_input: input.clone(),
                            footprint,
                        });
                    }
                }
            }
                        let hitl_bypass = state.extensions.get::<HitlBypassSlot>().cloned();
            let mut permitted_calls: Vec<ToolUseCall> = Vec::new();
            let mut denied_results: Vec<Message> = Vec::new();
            let mut pending_tools: Vec<ToolCallId> = Vec::new();

            for call in &calls {
                let bypassed = hitl_bypass
                    .as_ref()
                    .is_some_and(|b| b.approved_tool_use_ids.contains(&call.tool_use_id));

                let mut effective_mode = PermissionMode::Allow;

                if let Some(mode) = ctx.permission_lattice.interrupt_on_tools.get(&call.tool_name) {
                    effective_mode = effective_mode.join(*mode);
                }

                for mw in &self.middlewares {
                    if let Some(mode) = mw
                        .evaluate_tool_permission(
                            &state,
                            &call.tool_use_id,
                            &call.tool_name,
                            &call.tool_input,
                            ctx,
                        )
                        .await?
                    {
                        effective_mode = effective_mode.join(mode);
                    }
                }

                if bypassed && effective_mode == PermissionMode::Interrupt {
                    effective_mode = PermissionMode::Allow;
                }

                match effective_mode {
                    PermissionMode::Deny => {
                        let deny_msg = Message::tool_result(
                            call.tool_use_id.clone(),
                            true,
                            "Permission denied by policy lattice".to_string(),
                            None,
                        );
                        denied_results.push(deny_msg);
                    }
                    PermissionMode::Interrupt => {
                        if !pending_tools.contains(&call.tool_use_id) {
                            pending_tools.push(call.tool_use_id.clone());
                        }
                    }
                    PermissionMode::Allow => {
                        permitted_calls.push(call.clone());
                    }
                }
            }

            if !denied_results.is_empty() {
                state.messages.extend(denied_results.clone());
                if let Some(mut delta) = state.extensions.get::<TurnDeltaBufferSlot>().cloned() {
                    delta.message_deltas.push(MessageDelta::Append(denied_results));
                    state.extensions.insert(delta);
                }
            }
            if !pending_tools.is_empty() {
                let cp_id = commit_thread_checkpoint(&mut state, ctx, &_step_start_vfs)?;
                let _ = ctx.data_stores.task_ledger.update_task_status(&ctx.task_id, "INTERRUPTED");
                if let Some(pub_handle) = ctx.publisher.clone() {
                    pub_handle.publish_event(StreamEvent::Interrupted {
                        thread_id: state.thread_id.clone(),
                        checkpoint_id: cp_id,
                        pending_tools,
                    });
                }
                return Ok(TurnExecutionOutcome::Interrupted);
            }

                        if pending_tools.is_empty() && !permitted_calls.is_empty() {
                if let Some(pub_handle) = ctx.publisher.clone() {
                    for c in &permitted_calls {
                        pub_handle.publish_event(StreamEvent::ToolCallStart {
                            tool_use_id: c.tool_use_id.clone(),
                            name: c.tool_name.clone(),
                        });
                    }
                }

                let mws = &self.middlewares;
                let tool_res = BernsteinToolScheduler::execute_waves(
                    &mut state,
                    &permitted_calls,
                    ctx,
                    &ctx.metrics,
                    |mut st, call| {
                        Box::pin(async move {
                            match execute_single_tool(
                                &mut st,
                                &call.tool_use_id,
                                &call.tool_name,
                                &call.tool_input,
                                ctx,
                                mws,
                            )
                            .await
                            {
                                Ok(out) => {
                                    let msg = Message::tool_result(
                                        call.tool_use_id.clone(),
                                        out.is_error,
                                        out.raw_output,
                                        out.artifact,
                                    );
                                    (Ok(msg), st)
                                }
                                Err(e) => (Err(e), st),
                            }
                        })
                    },
                )
                .await?;

                if let Some(pub_handle) = ctx.publisher.clone() {
                    for msg in &tool_res {
                        if let Some(ContentBlock::ToolResult {
                            tool_use_id,
                            is_error,
                            ..
                        }) = msg.content.first()
                        {
                            pub_handle.publish_event(StreamEvent::ToolCallEnd {
                                tool_use_id: tool_use_id.clone(),
                                is_error: *is_error,
                            });
                        }
                    }
                }

                state.messages.extend(tool_res.clone());
                if let Some(mut delta) = state.extensions.get::<TurnDeltaBufferSlot>().cloned() {
                    delta.message_deltas.push(MessageDelta::Append(tool_res));
                    state.extensions.insert(delta);
                }

                state.extensions.remove::<HitlBypassSlot>();

                let _ = commit_thread_checkpoint(&mut state, ctx, &_step_start_vfs)?;

                continue;
            } else {
                let mut should_continue = false;
                for mw in self.middlewares.iter().rev() {
                    let dir = mw.after_agent(&mut state, ctx).await?;
                    if dir == LoopDirective::ContinueTurn {
                        should_continue = true;
                    }
                }

                if should_continue {
                    continue;
                } else {
                    let has_deltas = state.extensions.get::<TurnDeltaBufferSlot>().is_some_and(|d| !d.message_deltas.is_empty());
                    if has_deltas {
                        let _ = commit_thread_checkpoint(&mut state, ctx, &_step_start_vfs)?;
                    }

                    let _ = ctx.data_stores.task_ledger.update_task_status(&ctx.task_id, "SUCCEEDED");
                    if let Some(pub_handle) = ctx.publisher.clone() {
                        pub_handle.publish_event(StreamEvent::TurnComplete {
                                step_index: state.step_index,
                                usage: cumulative_usage.clone(),
                            });
                    }
                    return Ok(TurnExecutionOutcome::Completed(state));
                }
            }
        }

        Ok(TurnExecutionOutcome::Completed(state))
    }
}


fn commit_thread_checkpoint(
    state: &mut TantryState,
    ctx: &TurnExecutionContext,
    step_start_vfs: &VfsTree,
) -> Result<String, RuntimeError> {
    let head = ctx
        .data_stores
        .interaction_chain
        .get_latest_checkpoint_for_thread(&state.thread_id)
        .map_err(RuntimeError::Data)?;

    let next_step_index = head.as_ref().map_or(1, |(_, s)| s + 1);
    let prev_cp_id = head.map(|(id, _)| id).or_else(|| state.last_checkpoint_id.clone());
    state.step_index = next_step_index as u64;

    let diff = FileDelta::diff_trees(step_start_vfs, &state.files);

    let mut delta = state
        .extensions
        .get::<TurnDeltaBufferSlot>()
        .cloned()
        .unwrap_or(TurnDeltaBufferSlot {
            message_deltas: vec![],
        });

    let msg_deltas = delta.message_deltas.clone();
    delta.message_deltas.clear();
    state.extensions.insert(delta);

    let diff_json = serde_json::to_string(&diff).unwrap_or_default();

    let ext_slots_b = state.extensions.serialize_all().map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(base::error::StateReducerError::InvalidToolUsePatch(e.to_string()))))?;
    let ext_json = serde_json::to_string(&ext_slots_b).unwrap_or_default();

    let todos_json = serde_json::to_string(&state.todos).unwrap_or_default();
    let async_tasks_json = serde_json::to_string(&state.async_tasks).unwrap_or_default();

    let cp_id = if msg_deltas.is_empty() {
        let msg_delta_json = serde_json::to_string(&msg_deltas).unwrap_or_default();
        let id = uuid::Uuid::now_v7().to_string();
        ctx.data_stores.interaction_chain.commit_checkpoint(
            &state.thread_id,
            state.step_index as i64,
            prev_cp_id.as_deref(),
            &id,
            0,
            Some(msg_delta_json.as_bytes()),
            Some(diff_json.as_bytes()),
            Some(ext_json.as_bytes()),
            Some(todos_json.as_str()),
            Some(async_tasks_json.as_str()),
        ).map_err(RuntimeError::Data)?;
        state.last_checkpoint_id = Some(id.clone());
        id
    } else {
        let mut current_prev_id = prev_cp_id.clone();
        let mut last_id = String::new();
        for (i, md) in msg_deltas.iter().enumerate() {
            let msg_delta_json = serde_json::to_string(&vec![md.clone()]).unwrap_or_default();
            let id = uuid::Uuid::now_v7().to_string();

            let c_diff_bytes = if i == 0 {
                diff_json.as_bytes()
            } else {
                b"[]"
            };

            ctx.data_stores.interaction_chain.commit_checkpoint(
                &state.thread_id,
                state.step_index as i64,
                current_prev_id.as_deref(),
                &id,
                0,
                Some(msg_delta_json.as_bytes()),
                Some(c_diff_bytes),
                Some(ext_json.as_bytes()),
                Some(todos_json.as_str()),
                Some(async_tasks_json.as_str()),
            ).map_err(RuntimeError::Data)?;

            current_prev_id = Some(id.clone());
            state.last_checkpoint_id = Some(id.clone());
            last_id = id;
        }
        last_id
    };

    Ok(cp_id)
}

pub async fn execute_subagents(
    state: TantryState,
    _ctx: &TurnExecutionContext,
    _engine: &RuntimeEngine,
) -> Result<TantryState, RuntimeError> {
    Ok(state)
}

pub fn resume_interrupted_thread(
    mut state: TantryState,
    decision: ApprovalDecision,
) -> Result<TantryState, RuntimeError> {
    match decision {
        ApprovalDecision::Approve { tool_use_id } => {
            let mut bypass = state
                .extensions
                .get::<HitlBypassSlot>()
                .cloned()
                .unwrap_or(HitlBypassSlot {
                    approved_tool_use_ids: std::collections::BTreeSet::new(),
                });
            bypass.approved_tool_use_ids.insert(tool_use_id);
            state.extensions.insert(bypass);
        }
        ApprovalDecision::Edit {
            tool_use_id,
            modified_arguments,
        } => {
            let patch = state
                .build_tool_use_edit_delta(&tool_use_id, modified_arguments)
                .map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(e)))?;

            MessageDelta::apply(&mut state.messages, patch.clone())
                .map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(e)))?;

            let mut bypass = state
                .extensions
                .get::<HitlBypassSlot>()
                .cloned()
                .unwrap_or(HitlBypassSlot {
                    approved_tool_use_ids: std::collections::BTreeSet::new(),
                });
            bypass.approved_tool_use_ids.insert(tool_use_id);
            state.extensions.insert(bypass);

            let mut delta = state
                .extensions
                .get::<TurnDeltaBufferSlot>()
                .cloned()
                .unwrap_or(TurnDeltaBufferSlot {
                    message_deltas: vec![],
                });
            delta.message_deltas.push(patch);
            state.extensions.insert(delta);
        }
        ApprovalDecision::Reject { tool_use_id, feedback } => {
            let reject_msg = Message::tool_result(tool_use_id.clone(), true, feedback, None);
            state.messages.push(reject_msg.clone());

            let mut delta = state
                .extensions
                .get::<TurnDeltaBufferSlot>()
                .cloned()
                .unwrap_or(TurnDeltaBufferSlot {
                    message_deltas: vec![],
                });
            delta.message_deltas.push(MessageDelta::Append(vec![reject_msg]));
            state.extensions.insert(delta);

            let mut bypass = state
                .extensions
                .get::<HitlBypassSlot>()
                .cloned()
                .unwrap_or(HitlBypassSlot {
                    approved_tool_use_ids: std::collections::BTreeSet::new(),
                });
            bypass.approved_tool_use_ids.insert(tool_use_id);
            state.extensions.insert(bypass);
        }
    }
    Ok(state)
}

pub fn fork_thread_at_checkpoint(
    ctx: &TurnExecutionContext,
    source_checkpoint_id: &str,
    new_thread_id: String,
    fork_delta: Option<MessageDelta>,
) -> Result<TantryState, RuntimeError> {
    let reconstructed = hydrate_thread_state_full(ctx, source_checkpoint_id)?;
    let mut state = reconstructed.state;
    state.thread_id = new_thread_id.clone();
    let fork_step_index = reconstructed.step_index + 1;

    if let Some(ref delta) = fork_delta {
        MessageDelta::apply(&mut state.messages, delta.clone())
            .map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(e)))?;
    }

    let msg_delta_to_commit = fork_delta.unwrap_or_else(|| MessageDelta::Append(vec![]));
    let msg_delta_bytes = serde_json::to_string(&vec![msg_delta_to_commit]).unwrap_or_default();

    let ext_slots_b = state.extensions.serialize_all().map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(base::error::StateReducerError::InvalidToolUsePatch(e.to_string()))))?;
    let ext_bytes = serde_json::to_string(&ext_slots_b).unwrap_or_default();

    let todos_json = serde_json::to_string(&state.todos).unwrap_or_default();
    let async_tasks_json = serde_json::to_string(&state.async_tasks).unwrap_or_default();

    let cp_id = uuid::Uuid::now_v7().to_string();

    ctx.data_stores.interaction_chain.commit_checkpoint(
        &new_thread_id,
        fork_step_index as i64,
        Some(source_checkpoint_id),
        &cp_id,
        0,
        Some(msg_delta_bytes.as_bytes()),
        Some(b"[]"), // so ancestor file deltas are not duplicated
        Some(ext_bytes.as_bytes()),
        Some(todos_json.as_str()),
        Some(async_tasks_json.as_str()),
    ).map_err(RuntimeError::Data)?;

    state.step_index = fork_step_index;
    state.last_checkpoint_id = Some(cp_id);

    Ok(state)
}


#[derive(Debug, Clone)]
pub struct HydratedThreadState {
    pub step_index: u64,
    pub vfs_root_blake3: [u8; 32],
    pub checkpoint_id: String,
    pub state: TantryState,
}

pub fn hydrate_thread_state_full(
    ctx: &TurnExecutionContext,
    thread_or_checkpoint_id: &str,
) -> Result<HydratedThreadState, RuntimeError> {
    let head_opt = ctx
        .data_stores
        .interaction_chain
        .get_latest_checkpoint_for_thread(thread_or_checkpoint_id)
        .map_err(RuntimeError::Data)?;

    let target_cp_id = if let Some((cp_id, _)) = head_opt {
        cp_id
    } else {
        thread_or_checkpoint_id.to_string()
    };

    let mut registry_impl = base::typemap::DefaultExtensionRegistryImpl::new();
    crate::slots::register_runtime_slots(&mut registry_impl);

    let reconstructed = ctx
        .data_stores
        .interaction_chain
        .reconstruct_state_at_checkpoint(
            &target_cp_id,
            &registry_impl,
            ctx.iam.key_hierarchy()
        )
        .map_err(RuntimeError::Data)?;

    let mut state = reconstructed.state;
    state.step_index = reconstructed.step_index;
    state.last_checkpoint_id = Some(target_cp_id.clone());

    Ok(HydratedThreadState {
        step_index: reconstructed.step_index,
        vfs_root_blake3: reconstructed.vfs_root_blake3,
        checkpoint_id: target_cp_id,
        state,
    })
}

pub fn hydrate_thread_state(
    ctx: &TurnExecutionContext,
    thread_or_checkpoint_id: &str,
) -> Result<TantryState, RuntimeError> {
    let full = hydrate_thread_state_full(ctx, thread_or_checkpoint_id)?;
    Ok(full.state)
}


pub async fn execute_single_tool(
    state: &mut TantryState,
    tool_use_id: &ToolCallId,
    tool_name: &str,
    tool_input: &Value,
    ctx: &TurnExecutionContext,
    middlewares: &[Arc<dyn AgentMiddleware>],
) -> Result<ToolExecutionOutput, RuntimeError> {
    match tool_name {
        "ls" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            match ctx.backend.ls(state, path) {
                Ok(entries) => {
                    let mut lines = Vec::new(); for e in entries { lines.push(format!("{} (dir: {}, size: {})", e.name, e.is_dir, e.size)); } let output = lines.join("\n");
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "read_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let offset_line = tool_input.get("offset_line").and_then(|v| v.as_u64()).map(|v| v as usize);
            let limit_lines = tool_input.get("limit_lines").and_then(|v| v.as_u64()).map(|v| v as usize);
            match ctx.backend.read_file(state, path, offset_line, limit_lines) {
                Ok(content) => {
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &content, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "write_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let content = tool_input.get("content").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.write_file(state, path, content) {
                Ok(receipt) => {
                    let output = format!("Write successful. {} bytes written.", receipt.bytes_written);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "edit_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let old_string = tool_input.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
            let new_string = tool_input.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
            let replace_all = tool_input.get("replace_all").and_then(|v| v.as_bool()).unwrap_or(false);
            match ctx.backend.edit_file(state, path, old_string, new_string, replace_all) {
                Ok(receipt) => {
                    let output = format!("Edit successful. {} occurrences replaced.", receipt.occurrences_replaced);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "delete" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.delete(state, path) {
                Ok(_) => {
                    let output = format!("Successfully deleted {}", path);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "glob" => {
            let pattern = tool_input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.glob(state, pattern) {
                Ok(paths) => {
                    let output = serde_json::to_string_pretty(&paths).unwrap_or_default();
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "grep" => {
            let pattern = tool_input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let path_glob = tool_input.get("path_glob").and_then(|v| v.as_str());
            match ctx.backend.grep(state, pattern, path_glob) {
                Ok(matches) => {
                    let mut lines = Vec::new();
                    for m in matches {
                        lines.push(format!("{}:{}: {}", m.path, m.line_number, m.content));
                    }
                    let output = lines.join("\n");
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "execute" => {
            let command = tool_input.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let args = tool_input.get("args").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let start = std::time::Instant::now();
            match ctx.backend.execute(SandboxExecRequest { command, args }) {
                Ok(res) => {
                    let duration = start.elapsed();
                    let output = format!("Exit Code: {}\nStdout:\n{}\nStderr:\n{}", res.exit_code, res.stdout, res.stderr);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());

                    let artifact = ToolArtifact::Execute(ExecuteArtifact {
                        exit_code: res.exit_code,
                        timed_out: false,
                        duration_ms: duration.as_millis() as u64,
                        peak_rss_bytes: None,
                        sandbox_id: String::new(),
                        isolation_tier: String::new(),
                    });

                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: res.exit_code != 0, artifact: Some(artifact) })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "write_todos" => {
            if let Some(todos_arr) = tool_input.get("todos").and_then(|v| v.as_array()) {
                state.todos.clear();
                for t in todos_arr {
                    if let Some(obj) = t.as_object() {
                        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let content = obj.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let status_str = obj.get("status").and_then(|v| v.as_str()).unwrap_or("Pending");
                        let status = match status_str {
                            "InProgress" => TodoStatus::InProgress,
                            "Completed" => TodoStatus::Completed,
                            "Cancelled" => TodoStatus::Cancelled,
                            _ => TodoStatus::Pending,
                        };
                        state.todos.push(TodoItem { id, content, status });
                    }
                }
                Ok(ToolExecutionOutput { raw_output: "Todos updated successfully.".to_string(), is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Missing or invalid 'todos' array.".to_string(), is_error: true, artifact: None })
            }
        }
        "read_todos" => {
            let output = serde_json::to_string_pretty(&state.todos).unwrap_or_default();
            Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
        }
        "update_memory" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("/memories/AGENTS.md");
            let content = tool_input.get("content").and_then(|v| v.as_str()).unwrap_or("");
            state.memory_contents.insert(path.to_string(), content.to_string());

            match ctx.backend.write_file(state, path, content) {
                Ok(_) => Ok(ToolExecutionOutput { raw_output: "Memory updated.".to_string(), is_error: false, artifact: None }),
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("Failed to write to VFS: {}", e), is_error: true, artifact: None })
            }
        }
        "ephemeral_tunnel" => {
            let service_name = tool_input.get("service_name").and_then(|v| v.as_str()).unwrap_or("");
            let ttl_secs = tool_input.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
            match ctx.iam.request_scoped_tunnel_token(service_name, ttl_secs) {
                Ok(grant) => {
                    let output = serde_json::to_string_pretty(&grant.token).unwrap_or_default();
                    Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("IAM Error: {:?}", e), is_error: true, artifact: None })
            }
        }
        "launch_async_task" | "update_async_task" => {
            match serde_json::from_value::<AsyncTaskHandle>(tool_input.clone()) {
                Ok(handle) => {
                    state.async_tasks.insert(handle.task_id.clone(), handle);
                    Ok(ToolExecutionOutput { raw_output: "Task saved successfully.".to_string(), is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("Invalid task handle: {}", e), is_error: true, artifact: None })
            }
        }
        "cancel_async_task" => {
            let task_id = tool_input.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(task) = state.async_tasks.get_mut(task_id) {
                task.status = AsyncTaskStatus::Cancelled;
                Ok(ToolExecutionOutput { raw_output: "Task cancelled.".to_string(), is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Task not found.".to_string(), is_error: true, artifact: None })
            }
        }
        "check_async_task" => {
            let task_id = tool_input.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(task) = state.async_tasks.get(task_id) {
                let output = serde_json::to_string_pretty(task).unwrap_or_default();
                Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Task not found.".to_string(), is_error: true, artifact: None })
            }
        }
        "list_async_tasks" => {
            let output = serde_json::to_string_pretty(&state.async_tasks).unwrap_or_default();
            Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
        }
        _ => {
            for middleware in middlewares {
                if let Some(out) = middleware.execute_tool(state, tool_use_id, tool_name, tool_input, ctx).await? {
                    return Ok(out);
                }
            }
            Ok(ToolExecutionOutput { raw_output: format!("Unknown tool: {}", tool_name), is_error: true, artifact: None })
        }
    }
}