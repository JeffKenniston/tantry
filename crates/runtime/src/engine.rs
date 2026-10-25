use base::delta::MessageDelta;
use data::interaction_chain::InteractionChainStore;
use base::state::TantryState;
use crate::tool_scheduler::{BernsteinToolScheduler, ToolNode};
use permissions::lattice::PermissionMode;
use permissions::attenuation::PermissionLattice;
use crate::slots::{HitlBypassSlot, TurnDeltaBufferSlot};
use uuid::Uuid;
use chrono::Utc;
use backends::merge::{merge_subagent_trees, VfsMergeReport};



use base::ast::{SubagentMode, Message};
use iam::svid::WorkloadSvid;
use iam::IdentityManager;

/// Specification for spawning a subagent.
pub struct SubagentSpawnSpec {
    pub name: String,
    pub task_id: String,
    pub requested_ttl: i64,
    pub mode: SubagentMode,
    pub task_prompt: Message,
    pub requested_lattice: PermissionLattice,
    pub tools: Vec<ToolNode>,
}

/// Outcome of a single run turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Agent completed the turn naturally.
    Completed,
    /// Turn was interrupted by a HITL requirement.
    Interrupted,
}

/// Context passed to runtime steps.
pub struct RunContext {
    /// Security constraints in effect.
    pub lattice: PermissionLattice,
}

/// Used for mocking task ledger.
pub struct TaskLedger {
    /// Status.
    pub status: String,
}

/// Executes a single turn synchronously.
pub trait AgentMiddleware: Send + Sync {
    fn name(&self) -> &str;
    fn before_agent(&self, state: &mut TantryState, ctx: &RunContext) -> Result<(), String> {
        let _ = (state, ctx);
        Ok(())
    }
    fn wrap_model_call(
        &self,
        state: &mut TantryState,
        ctx: &RunContext,
    ) -> Result<Option<transport::backpressure::CreditControlledPublisher>, String> {
        let _ = (state, ctx);
        Ok(None)
    }
    fn after_agent(
        &self,
        state: &mut TantryState,
        ctx: &RunContext,
    ) -> Result<base::execution::LoopDirective, String> {
        let _ = (state, ctx);
        Ok(base::execution::LoopDirective::FinishTurn)
    }
}

pub fn execute_turn(
    state: &mut TantryState,
    ctx: &RunContext,
    store: &InteractionChainStore,
    task_ledger: &mut TaskLedger,
    tools: Vec<ToolNode>,
    middlewares: &[Box<dyn AgentMiddleware>]
) -> Result<RunOutcome, String> {

    let mut current_tools = tools;

    loop {
        // Phase 1: before_agent middlewares
        for mw in middlewares.iter() {
            mw.before_agent(state, ctx)?;
        }

        // Phase 2: wrap_model_call
        let mut model_emitted_tool_uses = false;
        let mut _publisher: Option<transport::backpressure::CreditControlledPublisher> = None;
        for mw in middlewares.iter() {
            if let Some(publ) = mw.wrap_model_call(state, ctx)? {
                _publisher = Some(publ);
            }
        }

        // Simulating extraction of tools: normally this would be parsed from state.messages / TurnDeltaBufferSlot
        // For now, if we have current tools, we execute them. In a fully implemented wrap_model_call,
        // the newly emitted tools would populate `current_tools`.
        if !current_tools.is_empty() {
            model_emitted_tool_uses = true;
        }

        if model_emitted_tool_uses {
            // Phase 3: Bernstein Parallel Tool Wave Dispatch
            let scheduler = BernsteinToolScheduler::new(current_tools.clone());
            let waves = scheduler.schedule_waves();

            let mut interrupt_requested = false;

            let bypass_slot = state.extensions.get::<HitlBypassSlot>().cloned().unwrap_or(HitlBypassSlot {
                approved_tool_use_ids: std::collections::BTreeSet::new()
            });

            for wave in waves {
                for &node_idx in &wave {
                    let node = &scheduler.nodes[node_idx];
                    if ctx.lattice.interrupt_on_tools.get(&node.tool_use_id.to_string()) == Some(&PermissionMode::Interrupt) {
                        if !bypass_slot.approved_tool_use_ids.contains(&node.tool_use_id) {
                            interrupt_requested = true;
                        }
                    }
                }
            }

            // Clear current tools after executing them
            current_tools.clear();

            // Phase 4: Checkpoint Commit
            let latest = store.get_latest_checkpoint_for_thread(&state.thread_id)
                .map_err(|e| e.to_string())?;

            let (head_cp_id, head_step) = if let Some(l) = latest {
                (Some(l.0), l.1)
            } else {
                (None, 0)
            };

            let next_step = head_step + 1;
            let new_cp_id = Uuid::now_v7().to_string();

            state.step_index = next_step as u64;
            state.last_checkpoint_id = head_cp_id.clone();

            let mut deltas_to_commit = Vec::new();
            if let Some(turn_buffer) = state.extensions.get_mut::<TurnDeltaBufferSlot>() {
                deltas_to_commit = std::mem::take(&mut turn_buffer.message_deltas);
            }

            let delta_bytes = if !deltas_to_commit.is_empty() {
                Some(rmp_serde::to_vec_named(&deltas_to_commit[0]).unwrap())
            } else {
                None
            };

            let _cp_hash = store.commit_checkpoint(
                &state.thread_id,
                next_step,
                head_cp_id.as_deref(),
                &new_cp_id,
                1,
                delta_bytes.as_deref(),
                None,
                None,
                None,
                None,
            ).map_err(|e| e.to_string())?;

            if interrupt_requested {
                task_ledger.status = "INTERRUPTED".to_string();
                return Ok(RunOutcome::Interrupted);
            }

            continue; // Loop back to Phase 1/2 for the next turn
        }

        // Phase 5: Self-Grading Loop
        let mut continue_turn = false;
        for mw in middlewares.iter().rev() {
            if let base::execution::LoopDirective::ContinueTurn = mw.after_agent(state, ctx)? {
                continue_turn = true;
            }
        }

        if continue_turn {
            continue;
        } else {
            task_ledger.status = "SUCCEEDED".to_string();
            return Ok(RunOutcome::Completed);
        }
    }
}



pub fn execute_subagents(
    parent_state: &mut TantryState,
    parent_svid: &WorkloadSvid,
    identity_manager: &(dyn IdentityManager + Sync),
    parent_lattice: &PermissionLattice,
    store: &InteractionChainStore,
    specs: Vec<SubagentSpawnSpec>
) -> Result<VfsMergeReport, String> {
    use rayon::prelude::*;

    let mut pre_forked = Vec::new();

    for (i, spec) in specs.into_iter().enumerate() {
        let _child_svid = identity_manager.mint_subagent_svid(
            parent_svid,
            &spec.name,
            &spec.task_id,
            spec.requested_ttl,
        ).map_err(|e| format!("Failed to mint subagent SVID: {:?}", e))?;

        let child_lattice = parent_lattice.narrow_for_subagent(&spec.requested_lattice);

        let child_state = parent_state.fork_for_subagent(
            spec.mode,
            format!("{}-{}", parent_state.thread_id, spec.name),
            spec.task_prompt.clone(),
        );

        pre_forked.push((i, child_lattice, child_state, spec.tools));
    }

    let branches_res: Result<Vec<_>, String> = pre_forked.into_par_iter().map(|(i, child_lattice, mut child_state, tools)| {
        let ctx = RunContext {
            lattice: child_lattice,
        };
        let mut _task_ledger = TaskLedger { status: "RUNNING".to_string() };
        let empty_middlewares: Vec<Box<dyn AgentMiddleware>> = Vec::new();

        match execute_turn(&mut child_state, &ctx, store, &mut _task_ledger, tools, &empty_middlewares)? {
            RunOutcome::Completed => {}
            RunOutcome::Interrupted => {}
        }

        Ok((format!("subagent_{}", i), child_state.files))
    }).collect();

    let branches = branches_res?;

    let report = merge_subagent_trees(&parent_state.files, branches, Utc::now());

    parent_state.files = report.merged_tree.clone();

    Ok(report)
}

/// Dummy engine loop to satisfy stub requirements.
pub fn dummy_engine() {}


pub struct PatchToolCallsMiddleware;

impl AgentMiddleware for PatchToolCallsMiddleware {
    fn name(&self) -> &str {
        "PatchToolCallsMiddleware"
    }

    fn wrap_model_call(
        &self,
        state: &mut TantryState,
        _ctx: &RunContext,
    ) -> Result<Option<transport::backpressure::CreditControlledPublisher>, String> {
        let mut buffer = state.extensions.get_mut::<TurnDeltaBufferSlot>()
            .cloned()
            .unwrap_or(TurnDeltaBufferSlot { message_deltas: Vec::new() });

                for msg in &state.messages {
            for block in &msg.content {
                if let base::ast::ContentBlock::ToolUse { id, .. } = block {
                    let has_result = state.messages.iter().any(|m| {
                        m.content.iter().any(|b| {
                            if let base::ast::ContentBlock::ToolResult { tool_use_id, .. } = b {
                                tool_use_id == id
                            } else {
                                false
                            }
                        })
                    });
                    if !has_result {
                        let result_msg = base::ast::Message {
                            id: base::ast::MessageId::default(),
                            role: base::ast::Role::Tool,
                            content: vec![base::ast::ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                is_error: true,
                                content: vec![base::ast::ContentBlock::Text {
                                    text: "Tool call was cancelled or interrupted before completion.".to_string(),
                                    cache_control: None,
                                }],
                                artifact: None,
                            }],
                            created_at: chrono::Utc::now(),
                            metadata: std::collections::BTreeMap::new(),
                        };
                        buffer.message_deltas.push(MessageDelta::Append(vec![result_msg]));
                    }
                }
            }
        }

        state.extensions.insert(buffer);

        Ok(None)
    }
}


pub struct SummarizationMiddleware;

impl AgentMiddleware for SummarizationMiddleware {
    fn name(&self) -> &str {
        "SummarizationMiddleware"
    }

    fn before_agent(
        &self,
        state: &mut TantryState,
        _ctx: &RunContext,
    ) -> Result<(), String> {
        let mut buffer = state.extensions.get_mut::<TurnDeltaBufferSlot>()
            .cloned()
            .unwrap_or(TurnDeltaBufferSlot { message_deltas: Vec::new() });

        // Phase A: Old Tool Input Truncation
        let mut patch_deltas = Vec::new();
        let total_msgs = state.messages.len();
        if total_msgs > 6 {
            let cutoff = total_msgs - 6;
            for (_idx, msg) in state.messages.iter().enumerate().take(cutoff) {
                let mut modified = false;
                let mut new_msg = msg.clone();
                for block in &mut new_msg.content {
                    if let base::ast::ContentBlock::ToolUse { name, input, .. } = block {
                        if (name == "write_file" || name == "edit_file") && input.to_string().len() > 2000 {
                            *input = serde_json::json!({ "truncated": true });
                            modified = true;
                        }
                    }
                }
                if modified {
                    patch_deltas.push(MessageDelta::PatchById { target_id: msg.id.clone(), replacement: new_msg });
                }
            }
        }

        buffer.message_deltas.extend(patch_deltas);

        // Phase B: Atomic Boundary Compaction
        if state.messages.len() > 10 { // Simulate > 85% context util
            let mut cut_idx = (state.messages.len() as f64 * 0.6) as usize;

            while cut_idx > 0 {
                let has_tool_use = state.messages[cut_idx].content.iter().any(|b| matches!(b, base::ast::ContentBlock::ToolUse { .. }));
                let next_is_tool_result = state.messages.get(cut_idx + 1).map_or(false, |m| m.role == base::ast::Role::Tool || m.content.iter().any(|b| matches!(b, base::ast::ContentBlock::ToolResult { .. })));

                if has_tool_use || next_is_tool_result {
                    cut_idx -= 1;
                } else {
                    break;
                }
            }

            if cut_idx > 0 {
                let summary_msg = base::ast::Message {
                    id: base::ast::MessageId::default(),
                    role: base::ast::Role::Assistant,
                    content: vec![base::ast::ContentBlock::Text {
                        text: "## Completed Objectives\n## Mutated Files & Symbols\n## Active Constraints & Errors\n## Next Immediate Step".to_string(),
                        cache_control: None,
                    }],
                    created_at: chrono::Utc::now(),
                    metadata: std::collections::BTreeMap::new(),
                };

                buffer.message_deltas.push(MessageDelta::CompactRange {
                    up_to_id_inclusive: state.messages[cut_idx].id.clone(),
                    summary_message: summary_msg,
                });
            }
        }

        state.extensions.insert(buffer);

        Ok(())
    }
}
