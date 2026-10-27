
use base::ast::{ContentBlock, ExecuteArtifact, Message, TodoItem, TodoStatus, ToolArtifact, ToolCallId, AsyncTaskHandle, AsyncTaskStatus};
use base::delta::{FileDelta, MessageDelta};
use base::execution::{ApprovalDecision, LoopDirective, ModelRequest, ModelResponse, StreamEvent};
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

        loop {
            if steps >= max_steps_per_turn {
                break;
            }
            steps += 1;

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
                        let mut stream = provider.stream_complete(r)?;
                        let mut content_buffer = String::new();
                        while let Some(res) = stream.next().await {
                            let evt = res?;
                            if let StreamEvent::ModelDelta { ref text_delta, .. } = evt {
                                content_buffer.push_str(text_delta);
                            }
                            if let Some(arc_mut) = Arc::get_mut(pub_handle) {
                                arc_mut.publish_event(evt);
                            }
                        }

                        Ok(ModelResponse {
                            content: content_buffer.clone(),
                            assistant_message: Message::assistant(vec![ContentBlock::Text {
                                text: content_buffer,
                                cache_control: None,
                            }]),
                            usage: base::execution::TokenUsage::default(),
                        })
                    } else {
                        provider.complete(r).map_err(Into::into)
                    }
                })
            });



            // We need a way to reference self.middlewares over lifetime 'a. But execute_turn takes `&self`.
            // We can't use self.middlewares safely if the future is Send + 'static. But it's Send + 'a!
            // Wait! NextModelCall<'a> is tied to 'a. The closure can capture `mw: &'a Arc<dyn AgentMiddleware>`.
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

            let mut calls = Vec::new();
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

            let hitl_bypass = state.extensions.get::<HitlBypassSlot>().cloned();
            let mut interrupted = false;
            let mut pending_tools = Vec::new();

            for call in &calls {
                let bypassed = hitl_bypass
                    .as_ref()
                    .map_or(false, |b| b.approved_tool_use_ids.contains(&call.tool_use_id));

                if !bypassed {
                    if let Some(mode) = ctx.permission_lattice.interrupt_on_tools.get(&call.tool_name) {
                        let mode = mode.clone();
                        if mode == PermissionMode::Deny {
                            state.messages.push(Message::tool_result(
                                call.tool_use_id.clone(),
                                true,
                                "Permission denied by policy lattice".to_string(),
                                None,
                            ));
                            continue;
                        }
                        if mode == PermissionMode::Interrupt {
                            interrupted = true;
                            pending_tools.push(call.tool_use_id.clone());
                        }
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
                            if mode == PermissionMode::Deny {
                                state.messages.push(Message::tool_result(
                                    call.tool_use_id.clone(),
                                    true,
                                    "Permission denied by policy lattice".to_string(),
                                    None,
                                ));
                                break;
                            }
                            if mode == PermissionMode::Interrupt {
                                interrupted = true;
                                pending_tools.push(call.tool_use_id.clone());
                                break;
                            }
                        }
                    }
                }
            }

            if interrupted {
                let head = ctx
                    .data_stores
                    .interaction_chain
                    .get_latest_checkpoint_for_thread(&state.thread_id)
                    .unwrap_or(None);
                let next_step_index = head.as_ref().map_or(1, |(_, s)| s + 1);
                let prev_cp_id = head
                    .map(|(id, _)| id)
                    .or_else(|| state.last_checkpoint_id.clone());
                state.step_index = next_step_index as u64;

                let prev_vfs = VfsTree::new();
                let diff = FileDelta::diff_trees(&prev_vfs, &state.files);

                let mut delta = state
                    .extensions
                    .get::<TurnDeltaBufferSlot>()
                    .cloned()
                    .unwrap_or(TurnDeltaBufferSlot {
                        message_deltas: vec![],
                    });
                let msg_delta_str = serde_json::to_string(&delta.message_deltas).unwrap_or_default();
                delta.message_deltas.clear();
                state.extensions.insert(delta);

                let ext_slots_b = state.extensions.serialize_all().map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(base::error::StateReducerError::InvalidToolUsePatch(e.to_string()))))?;
    let ext_slots = serde_json::to_string(&ext_slots_b).unwrap_or_default();
                let serialized = serde_json::to_string(&ext_slots).unwrap_or_default();
                let cp_id = uuid::Uuid::now_v7().to_string();

                ctx.data_stores.interaction_chain.commit_checkpoint(
                    &state.thread_id,
                    state.step_index as i64,
                    prev_cp_id.as_deref(),
                    &cp_id,
                    0,
                    Some(msg_delta_str.as_bytes()),
                    Some(serde_json::to_string(&diff).unwrap_or_default().as_bytes()),
                    Some(serialized.as_bytes()),
                    None,
                    None,
                ).map_err(|e| RuntimeError::Data(e))?;
                state.last_checkpoint_id = Some(cp_id.clone());

                if let Some(mut pub_handle) = ctx.publisher.clone() {
                    if let Some(arc_mut) = Arc::get_mut(&mut pub_handle) {
                        arc_mut.publish_event(StreamEvent::Interrupted {
                            thread_id: state.thread_id.clone(),
                            checkpoint_id: cp_id,
                            pending_tools,
                        });
                    }
                }

                return Ok(TurnExecutionOutcome::Interrupted);
            }

            if !calls.is_empty() {
                if let Some(mut pub_handle) = ctx.publisher.clone() {
                    if let Some(arc_mut) = Arc::get_mut(&mut pub_handle) {
                        arc_mut.publish_event(StreamEvent::ToolCallStart {
                            tool_use_id: calls[0].tool_use_id.clone(),
                            name: calls[0].tool_name.clone(),
                        });
                    }
                }

                let _mws_clone = self.middlewares.clone();
                let tool_res = BernsteinToolScheduler::execute_waves(
                    &mut state,
                    &calls,
                    ctx,
                    &ctx.metrics,
                    |st, call| {
                        let tool_use_id = call.tool_use_id.clone();
                        Box::pin(async move {
                            let msg = Message::tool_result(
                                tool_use_id.clone(),
                                false,
                                "executed".to_string(),
                                None,
                            );
                            (Ok(msg), st)
                        })
                    },
                )
                .await?;

                if let Some(mut pub_handle) = ctx.publisher.clone() {
                    if let Some(arc_mut) = Arc::get_mut(&mut pub_handle) {
                        if let ContentBlock::ToolResult {
                            tool_use_id,
                            is_error,
                            ..
                        } = &tool_res[0].content[0]
                        {
                            arc_mut.publish_event(StreamEvent::ToolCallEnd {
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

                let head = ctx
                    .data_stores
                    .interaction_chain
                    .get_latest_checkpoint_for_thread(&state.thread_id)
                    .unwrap_or(None);
                let next_step_index = head.as_ref().map_or(1, |(_, s)| s + 1);
                let prev_cp_id = head
                    .map(|(id, _)| id)
                    .or_else(|| state.last_checkpoint_id.clone());
                state.step_index = next_step_index as u64;

                let prev_vfs = VfsTree::new();
                let diff = FileDelta::diff_trees(&prev_vfs, &state.files);

                let mut delta = state
                    .extensions
                    .get::<TurnDeltaBufferSlot>()
                    .cloned()
                    .unwrap_or(TurnDeltaBufferSlot {
                        message_deltas: vec![],
                    });
                let msg_delta_str = serde_json::to_string(&delta.message_deltas).unwrap_or_default();
                delta.message_deltas.clear();
                state.extensions.insert(delta);

                let ext_slots_b = state.extensions.serialize_all().map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(base::error::StateReducerError::InvalidToolUsePatch(e.to_string()))))?;
    let ext_slots = serde_json::to_string(&ext_slots_b).unwrap_or_default();
                let serialized = serde_json::to_string(&ext_slots).unwrap_or_default();
                let cp_id = uuid::Uuid::now_v7().to_string();

                ctx.data_stores.interaction_chain.commit_checkpoint(
                    &state.thread_id,
                    state.step_index as i64,
                    prev_cp_id.as_deref(),
                    &cp_id,
                    0,
                    Some(msg_delta_str.as_bytes()),
                    Some(serde_json::to_string(&diff).unwrap_or_default().as_bytes()),
                    Some(serialized.as_bytes()),
                    None,
                    None,
                ).map_err(|e| RuntimeError::Data(e))?;
                state.last_checkpoint_id = Some(cp_id);

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
                    if let Some(mut pub_handle) = ctx.publisher.clone() {
                        if let Some(arc_mut) = Arc::get_mut(&mut pub_handle) {
                            arc_mut.publish_event(StreamEvent::TurnComplete {
                                step_index: state.step_index,
                                usage: base::execution::TokenUsage::default(),
                            });
                        }
                    }
                    return Ok(TurnExecutionOutcome::Completed(state));
                }
            }
        }

        Ok(TurnExecutionOutcome::Completed(state))
    }
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
        ApprovalDecision::Reject { .. } => {}
    }
    Ok(state)
}

pub fn fork_thread_at_checkpoint(
    ctx: &TurnExecutionContext,
    source_checkpoint_id: &str,
    new_thread_id: String,
    _fork_delta: Option<MessageDelta>,
) -> Result<TantryState, RuntimeError> {
    let mut state = hydrate_thread_state(ctx, source_checkpoint_id)?;
    state.thread_id = new_thread_id;

    let cp_id = uuid::Uuid::now_v7().to_string();

    let prev_vfs = VfsTree::new();
    let diff = FileDelta::diff_trees(&prev_vfs, &state.files);
    let diff_json = serde_json::to_string(&diff).unwrap_or_default();
    let ext_slots_b = state.extensions.serialize_all().map_err(|e| RuntimeError::Base(base::error::BaseError::StateReducer(base::error::StateReducerError::InvalidToolUsePatch(e.to_string()))))?;
    let ext_slots = serde_json::to_string(&ext_slots_b).unwrap_or_default();

    ctx.data_stores.interaction_chain.commit_checkpoint(
        &state.thread_id,
        (state.step_index + 1) as i64,
        Some(source_checkpoint_id),
        &cp_id,
        0,
        Some(b"[]"),
        Some(diff_json.as_bytes()),
        Some(ext_slots.as_bytes()),
        None,
        None,
    ).map_err(|e| RuntimeError::Data(e))?;
    state.last_checkpoint_id = Some(cp_id);

    Ok(state)
}

pub fn hydrate_thread_state(
    _ctx: &TurnExecutionContext,
    checkpoint_id: &str,
) -> Result<TantryState, RuntimeError> {
    Ok(TantryState {
        thread_id: "hydrated".into(),
        step_index: 0,
        last_checkpoint_id: Some(checkpoint_id.into()),
        messages: vec![],
        files: VfsTree::new(),
        todos: vec![],
        skills_metadata: vec![],
        memory_contents: std::collections::BTreeMap::new(),
        async_tasks: std::collections::BTreeMap::new(),
        rubric_input: None,
        rubric_status: None,
        structured_response: None,
        extensions: base::typemap::StateExtensionMap::new(),
    })
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

            match ctx.backend.write_file(state, "/memories/AGENTS.md", content) {
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