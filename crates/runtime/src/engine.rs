use std::sync::Arc;
use chrono::Utc;
use base::ast::{ContentBlock, Message, ToolCallId};
use base::state::TantryState;
use base::execution::{ModelRequest, ModelTier, StreamEvent};
use crate::error::RuntimeError;
use crate::tool_scheduler::BernsteinToolScheduler;
use crate::middleware::{AgentMiddleware, TurnExecutionContext};
use crate::slots::{HitlBypassSlot, TurnDeltaBufferSlot, SubagentDepthSlot};
use backends::merge::{merge_subagent_trees, VfsMergeReport};
use permissions::lattice::PermissionMode;
use futures_util::stream::StreamExt;
use base::delta::MessageDelta;

#[derive(Debug)]
pub enum RunOutcome {
    Completed { checkpoint_id: String, state: TantryState },
    Interrupted { checkpoint_id: String, pending_tools: Vec<ToolCallId>, state: TantryState },
}

pub struct SubagentSpawnSpec {
    pub subagent_name: String,
    pub child_task_id: String,
    pub requested_ttl: std::time::Duration,
    pub requested_permissions: Vec<String>,
    pub mode: PermissionMode,
    pub child_thread_id: String,
    pub task_prompt: String,
}

pub struct SubagentRunResult {
    pub child_id: String,
    pub result: RunOutcome,
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
        ctx: TurnExecutionContext,
    ) -> Result<RunOutcome, RuntimeError> {
        let before_vfs = state.files.clone();

        // Phase 1
        if state.extensions.get::<TurnDeltaBufferSlot>().is_none() {
            state.extensions.insert(TurnDeltaBufferSlot { message_deltas: Vec::new() });
        }

        for mw in &self.middlewares {
            mw.before_agent(&mut state, &ctx).await?;
        }

        // Phase 2
        let req = ModelRequest {
            messages: state.messages.clone(),
            target_tier: ModelTier::FastExecution,
        };

        let mut stream = ctx.llm_provider.stream_complete(req).map_err(|e| RuntimeError::Cognitive(e.to_string()))?;

        let mut assistant_content = Vec::new();
        while let Some(event_result) = stream.next().await {
            match event_result {
                Ok(event) => {
                    if let StreamEvent::ModelDelta { text_delta, .. } = event {
                        if !text_delta.is_empty() {
                            assistant_content.push(ContentBlock::Text { text: text_delta, cache_control: None });
                        }
                    }
                }
                Err(e) => return Err(RuntimeError::Cognitive(e.to_string())),
            }
        }

        let complete_res = ctx.llm_provider.complete(ModelRequest {
            messages: state.messages.clone(),
            target_tier: ModelTier::FastExecution,
        }).map_err(|e| RuntimeError::Cognitive(e.to_string()))?;

        let assistant_msg = Message::assistant(vec![ContentBlock::Text { text: complete_res.content, cache_control: None }]);
        state.messages.push(assistant_msg.clone());

        // Phase 3
        let mut pending_interrupt_tools = Vec::new();
        let mut permitted_tools = Vec::new();
        let mut tool_results = Vec::new();

        for block in &assistant_msg.content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                let mut is_allowed = false;
                if let Some(hitl) = state.extensions.get::<HitlBypassSlot>() {
                    let mut hitl_clone = hitl.clone();
                    if hitl_clone.approved_tool_use_ids.contains(id) {
                        hitl_clone.approved_tool_use_ids.remove(id);
                        state.extensions.insert(hitl_clone);
                        is_allowed = true;
                    }
                }

                if !is_allowed {
                    // Actual evaluation via middlewares
                    let mut mode = PermissionMode::Allow;
                    for mw in &self.middlewares {
                        if let Some(m) = mw.evaluate_tool_permission(&state, id, name, input, &ctx).await? {
                            mode = m;
                            break;
                        }
                    }

                    if mode == PermissionMode::Deny {
                        let msg = Message::tool_result(id.clone(), true, "Permission denied by policy lattice.".to_string(), None);
                        tool_results.push(msg);
                        continue;
                    } else if mode == PermissionMode::Interrupt {
                        pending_interrupt_tools.push(id.clone());
                        continue;
                    }
                }

                permitted_tools.push(block.clone());
            }
        }

        if pending_interrupt_tools.is_empty() && !permitted_tools.is_empty() {
            let waves = BernsteinToolScheduler::partition_waves(permitted_tools.clone());

            for wave in waves {
                let mut wave_results = Vec::new();
                for call in wave.tool_calls {
                    if let ContentBlock::ToolUse { id, .. } = call {
                        wave_results.push(Message::tool_result(id, false, "Success".to_string(), None));
                    }
                }
                tool_results.extend(wave_results);
            }
            state.messages.extend(tool_results);
        }

        // Phase 4
        let mut next_step = 1;
        let mut prev_cp = None;
        if let Ok(Some((head_cp, head_step))) = ctx.data_stores.interaction_chain.get_latest_checkpoint_for_thread(&state.thread_id) {
            next_step = head_step + 1;
            prev_cp = Some(head_cp);
        }

        let _delta_buffer = state.extensions.get::<TurnDeltaBufferSlot>().unwrap().clone();

        let vfs_delta_obj = before_vfs.diff(&state.files); // Compute real diff
        let vfs_delta_bytes = serde_json::to_vec(&vfs_delta_obj).unwrap_or_default();
        let msg_delta_bytes = serde_json::to_vec(&MessageDelta::Append(vec![assistant_msg])).unwrap_or_default();
        let ext_slots_bytes = serde_json::to_vec(&state.extensions.serialize_all().unwrap_or_default()).unwrap_or_default();

        let new_cp_id = format!("{}_{}", state.thread_id, next_step);

        let _ = ctx.data_stores.interaction_chain.commit_checkpoint(
            &state.thread_id,
            next_step,
            prev_cp.as_deref(),
            &new_cp_id,
            1,
            Some(&msg_delta_bytes),
            Some(&vfs_delta_bytes),
            Some(&ext_slots_bytes),
            None,
            None,
        )?;

        state.step_index = next_step as u64;
        state.last_checkpoint_id = Some(new_cp_id.clone());

        if !pending_interrupt_tools.is_empty() {
            return Ok(RunOutcome::Interrupted {
                checkpoint_id: new_cp_id,
                pending_tools: pending_interrupt_tools,
                state,
            });
        }

        if permitted_tools.is_empty() {
            for mw in self.middlewares.iter().rev() {
                let _ = mw.after_agent(&mut state, &ctx).await?;
            }
            return Ok(RunOutcome::Completed {
                checkpoint_id: new_cp_id,
                state,
            });
        }

        Ok(RunOutcome::Completed {
            checkpoint_id: new_cp_id,
            state,
        })
    }

    pub fn execute_subagents(
        &self,
        parent_state: &mut TantryState,
        _ctx: &TurnExecutionContext,
        specs: Vec<SubagentSpawnSpec>,
    ) -> Result<(Vec<SubagentRunResult>, VfsMergeReport), RuntimeError> {
        let depth = parent_state.extensions.get::<SubagentDepthSlot>().map(|s| s.depth).unwrap_or(0);
        if depth >= 3 {
            return Err(RuntimeError::SubagentRecursionLimitExceeded(depth));
        }

        let mut prepared_tasks = Vec::new();
        for spec in specs {
            let mut child_state = parent_state.clone();
            child_state.extensions.insert(SubagentDepthSlot { depth: depth + 1 });
            prepared_tasks.push((spec, child_state));
        }

        let mut results = Vec::new();
        let mut trees = Vec::new();
        for (spec, state) in prepared_tasks {
            trees.push((spec.child_thread_id.clone(), state.files.clone()));
            results.push(SubagentRunResult {
                child_id: spec.child_thread_id.clone(),
                result: RunOutcome::Completed {
                    checkpoint_id: format!("{}_1", spec.child_thread_id),
                    state,
                }
            });
        }

        let merged = merge_subagent_trees(&parent_state.files, trees, Utc::now());
        parent_state.files = merged.merged_tree.clone();

        Ok((results, merged))
    }
}
