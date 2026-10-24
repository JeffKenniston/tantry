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
pub fn execute_turn(
    state: &mut TantryState,
    ctx: &RunContext,
    store: &InteractionChainStore,
    task_ledger: &mut TaskLedger,
    tools: Vec<ToolNode>
) -> Result<RunOutcome, String> {

    // Phase 1: before_agent middlewares (stubbed)

    // Phase 2: wrap_model_call (stubbed)

    // Phase 3: Bernstein Parallel Tool Wave Dispatch
    let scheduler = BernsteinToolScheduler::new(tools);
    let waves = scheduler.schedule_waves();

    let mut interrupt_requested = false;

    let bypass_slot = state.extensions.get::<HitlBypassSlot>().cloned().unwrap_or(HitlBypassSlot {
        approved_tool_use_ids: std::collections::BTreeSet::new()
    });

    for wave in waves {
        // Parallel execution simulation logic would go here
        for &node_idx in &wave {
            let node = &scheduler.nodes[node_idx];
            if ctx.lattice.interrupt_on_tools.get(&node.tool_use_id.to_string()) == Some(&PermissionMode::Interrupt) {
                if !bypass_slot.approved_tool_use_ids.contains(&node.tool_use_id) {
                    interrupt_requested = true;
                }
            }
        }
    }

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

    // Drain TurnDeltaBufferSlot
    let mut deltas_to_commit = Vec::new();
    if let Some(turn_buffer) = state.extensions.get_mut::<TurnDeltaBufferSlot>() {
        deltas_to_commit = std::mem::take(&mut turn_buffer.message_deltas);
    }

    let delta_bytes = if !deltas_to_commit.is_empty() {
        // Just take the first one for the stub logic
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
        None, // file_deltas
        None, // extensions
        None, // todos
        None, // async tasks
    ).map_err(|e| e.to_string())?;

    if interrupt_requested {
        task_ledger.status = "INTERRUPTED".to_string();
        return Ok(RunOutcome::Interrupted);
    }

    // Phase 5: Self-Grading Loop (stubbed)
    task_ledger.status = "SUCCEEDED".to_string();
    Ok(RunOutcome::Completed)
}



/// Synchronous Subagent Fan-Out Orchestrator
pub fn execute_subagents(
    parent_state: &mut TantryState,
    parent_svid: &WorkloadSvid,
    identity_manager: &dyn IdentityManager,
    parent_lattice: &PermissionLattice,
    store: &InteractionChainStore,
    specs: Vec<SubagentSpawnSpec>
) -> Result<VfsMergeReport, String> {
    let mut branches = Vec::new();

    // In a real implementation this would use futures::future::join_all or rayon
    for (i, spec) in specs.into_iter().enumerate() {
        // 1. Mint narrowed SVID
        let _child_svid = identity_manager.mint_subagent_svid(
            parent_svid,
            &spec.name,
            &spec.task_id,
            spec.requested_ttl,
        ).map_err(|e| format!("Failed to mint subagent SVID: {:?}", e))?;

        // 2. Narrow policy
        let child_lattice = parent_lattice.narrow_for_subagent(&spec.requested_lattice);

        // 3. Fork state
        let mut child_state = parent_state.fork_for_subagent(
            spec.mode,
            format!("{}-{}", parent_state.thread_id, spec.name),
            spec.task_prompt,
        );

        let ctx = RunContext {
            lattice: child_lattice,
        };
        let mut task_ledger = TaskLedger { status: "RUNNING".to_string() };

        // 4. Run child turn loops
        // Note: For simplicity, we just execute one turn for the subagent here.
        execute_turn(&mut child_state, &ctx, store, &mut task_ledger, spec.tools)?;

        branches.push((format!("subagent_{}", i), child_state.files));
    }

    let report = merge_subagent_trees(&parent_state.files, branches, Utc::now());

    // Merge back into parent state
    parent_state.files = report.merged_tree.clone();

    Ok(report)
}

/// Dummy engine loop to satisfy stub requirements.
pub fn dummy_engine() {}
