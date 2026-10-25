use std::sync::Arc;
use crate::error::RuntimeError;
use base::state::TantryState;
use data::interaction_chain::InteractionChainStore;
use base::typemap::StateExtensionRegistry;
use base::delta::MessageDelta;
use iam::key_hierarchy::KeyHierarchy;

#[derive(Debug)]
pub struct HydratedThreadState {
    pub step_index: i64,
    pub vfs_root_blake3: [u8; 32],
    pub checkpoint_id: String,
    pub state: TantryState,
}

pub struct TimeTravelEngine {
    pub interaction_chain_store: Arc<InteractionChainStore>,
    pub extension_registry: Arc<dyn StateExtensionRegistry>,
    pub key_hierarchy: Arc<KeyHierarchy>,
}

impl TimeTravelEngine {
    pub fn new(
        interaction_chain_store: Arc<InteractionChainStore>,
        extension_registry: Arc<dyn StateExtensionRegistry>,
        key_hierarchy: Arc<KeyHierarchy>
    ) -> Self {
        Self {
            interaction_chain_store,
            extension_registry,
            key_hierarchy,
        }
    }

    pub fn hydrate_thread_state(&self, thread_id: &str) -> Result<HydratedThreadState, RuntimeError> {
        let (latest_checkpoint_id, _head_step) = self.interaction_chain_store.get_latest_checkpoint_for_thread(thread_id)?
            .ok_or_else(|| RuntimeError::CheckpointNotFound(thread_id.to_string()))?;

        let reconstructed = self.interaction_chain_store.reconstruct_state_at_checkpoint(
            &latest_checkpoint_id,
            self.extension_registry.as_ref(),
            &self.key_hierarchy,
        )?;

        Ok(HydratedThreadState {
            step_index: reconstructed.step_index as i64,
            vfs_root_blake3: reconstructed.vfs_root_blake3,
            checkpoint_id: latest_checkpoint_id,
            state: reconstructed.state,
        })
    }

    pub fn fork_thread_at_checkpoint(
        &self,
        _source_thread_id: &str,
        target_checkpoint_id: &str,
        new_thread_id: &str,
        state_patch: Option<MessageDelta>,
    ) -> Result<HydratedThreadState, RuntimeError> {
        let mut target = self.interaction_chain_store.reconstruct_state_at_checkpoint(
            target_checkpoint_id,
            self.extension_registry.as_ref(),
            &self.key_hierarchy,
        )?;

        target.state.thread_id = new_thread_id.to_string();

        let message_delta = if let Some(delta) = state_patch {
            MessageDelta::apply(&mut target.state.messages, delta.clone())?;
            delta
        } else {
            MessageDelta::Append(vec![])
        };

        let message_delta_bytes = serde_json::to_vec(&message_delta).unwrap_or_default();
        let serialized_ext = target.state.extensions.serialize_all().unwrap_or_default();
        let ext_slots_bytes = serde_json::to_vec(&serialized_ext).unwrap_or_default();

        let new_cp_id = format!("{}_{}", new_thread_id, target.step_index + 1);

        let _fork_cp_id_bytes = self.interaction_chain_store.commit_checkpoint(
            new_thread_id,
            (target.step_index + 1) as i64,
            Some(target_checkpoint_id),
            &new_cp_id,
            1, // key_epoch
            Some(&message_delta_bytes),
            None,
            Some(&ext_slots_bytes),
            None,
            None,
        )?;

        target.state.step_index = target.step_index + 1;
        target.state.last_checkpoint_id = Some(new_cp_id.clone());

        Ok(HydratedThreadState {
            step_index: target.state.step_index as i64,
            vfs_root_blake3: target.vfs_root_blake3,
            checkpoint_id: new_cp_id,
            state: target.state,
        })
    }
}
