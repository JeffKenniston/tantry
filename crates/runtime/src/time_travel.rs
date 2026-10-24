use base::state::TantryState;
use base::delta::MessageDelta;
use data::interaction_chain::InteractionChainStore;
use iam::key_hierarchy::KeyHierarchy;
use base::typemap::StateExtensionRegistry;

#[derive(Debug)]
pub enum RuntimeError {
    Database(String),
}

impl From<data::error::DataError> for RuntimeError {
    fn from(e: data::error::DataError) -> Self {
        RuntimeError::Database(e.to_string())
    }
}

pub struct HydratedThreadState {
    pub step_index: u64,
    pub vfs_root_blake3: [u8; 32],
    pub checkpoint_id: [u8; 32],
    pub state: TantryState,
}

pub fn hydrate_thread_state(
    store: &InteractionChainStore,
    registry: &dyn StateExtensionRegistry,
    keys: &KeyHierarchy,
    thread_id: &str,
) -> Result<HydratedThreadState, RuntimeError> {
    let latest = store.get_latest_checkpoint_for_thread(thread_id)?;
    if let Some((cp_id, _)) = latest {
        let reconstructed = store.reconstruct_state_at_checkpoint(&cp_id, registry, keys)?;
        Ok(HydratedThreadState {
            step_index: reconstructed.step_index,
            vfs_root_blake3: reconstructed.vfs_root_blake3,
            checkpoint_id: reconstructed.checkpoint_blake3,
            state: reconstructed.state,
        })
    } else {
        Err(RuntimeError::Database(format!("No checkpoint found for thread {}", thread_id)))
    }
}

pub fn fork_thread_at_checkpoint(
    store: &InteractionChainStore,
    registry: &dyn StateExtensionRegistry,
    keys: &KeyHierarchy,
    _source_thread_id: &str,
    target_checkpoint_id: &str,
    new_thread_id: &str,
    state_patch: Option<MessageDelta>,
) -> Result<HydratedThreadState, RuntimeError> {

    // 1. Reconstruct state at target checkpoint
    let mut reconstructed = store.reconstruct_state_at_checkpoint(target_checkpoint_id, registry, keys)?;

    // 3. Apply state patch if provided
    let msg_delta_bytes = if let Some(delta) = state_patch {
        MessageDelta::apply(&mut reconstructed.state.messages, delta.clone())
            .map_err(|e| RuntimeError::Database(format!("Delta apply error: {:?}", e)))?;
        Some(rmp_serde::to_vec_named(&delta).unwrap())
    } else {
        None
    };

    // 4. Commit new checkpoint
    let new_step = reconstructed.step_index + 1;
    let new_cp_id = uuid::Uuid::now_v7().to_string();

    let cp_hash = store.commit_checkpoint(
        new_thread_id,
        new_step as i64,
        Some(target_checkpoint_id),
        &new_cp_id,
        1, // key_epoch
        msg_delta_bytes.as_deref(),
        None, // file deltas
        None, // extensions
        None, // todos
        None, // async tasks
    ).map_err(|e| RuntimeError::Database(e.to_string()))?;

    // 5. Source thread untouched
    reconstructed.state.thread_id = new_thread_id.to_string();
    reconstructed.state.step_index = new_step;

    Ok(HydratedThreadState {
        step_index: new_step,
        vfs_root_blake3: reconstructed.vfs_root_blake3,
        checkpoint_id: cp_hash,
        state: reconstructed.state,
    })
}
