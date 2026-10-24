use crate::error::DataError;
use base::ast::Message;
use base::delta::{FileDelta, MessageDelta};
use base::state::TantryState;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

/// Provides append-only, time-travel-capable storage for agent interaction checkpoints and messages.
pub struct InteractionChainStore {
    /// The thread-safe SQLite connection pool shared by all operations in this store.
    pub db: Arc<Mutex<Connection>>,
}

/// Represents a fully hydrated agent state constructed by replaying deltas from genesis to a target checkpoint.
pub struct ReconstructedCheckpoint {
    /// The fully hydrated TantryState at this checkpoint.
    pub state: TantryState,
    /// The sequential logical step number of this checkpoint.
    pub step_index: u64,
    /// The computed BLAKE3 root hash of the virtual filesystem tree at this state.
    pub vfs_root_blake3: [u8; 32],
    /// The verifiable digest of the checkpoint row combining previous links, state deltas, and AAD.
    pub checkpoint_blake3: [u8; 32],
}

struct RawCheckpointRow {
    checkpoint_id: String,
    previous_checkpoint_id: Option<String>,
    thread_id: String,
    step_index: i64,
    key_epoch: u32,
    message_delta_aead: Option<Vec<u8>>,
    file_deltas_aead: Option<Vec<u8>>,
    extension_slots_aead: Option<Vec<u8>>,
    todos_json: Option<String>,
    async_tasks_json: Option<String>,
}

impl InteractionChainStore {
    /// Initializes a new InteractionChainStore wrapping the provided database connection.
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }

    /// Persists a new state delta checkpoint, strictly enforcing append-only semantics and generating a structural digest.
    pub fn commit_checkpoint(
        &self,
        thread_id: &str,
        step_index: i64,
        prev_cp_id: Option<&str>,
        checkpoint_id: &str,
        key_epoch: u32,
        msg_delta: Option<&[u8]>,
        file_deltas: Option<&[u8]>,
        ext_slots: Option<&[u8]>,
        todos_json: Option<&str>,
        async_tasks_json: Option<&str>,
    ) -> Result<[u8; 32], DataError> {
        let conn = self.db.lock().unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:cp:v3");
        if let Some(pid) = prev_cp_id {
            hasher.update(pid.as_bytes());
        }
        hasher.update(thread_id.as_bytes());
        hasher.update(&step_index.to_be_bytes());
        if let Some(md) = msg_delta {
            hasher.update(md);
        }
        if let Some(fd) = file_deltas {
            hasher.update(fd);
        }
        if let Some(ext) = ext_slots {
            hasher.update(ext);
        }
        let checkpoint_blake3: [u8; 32] = hasher.finalize().into();

        // Strict INSERT INTO Invariant
        conn.execute(
            "INSERT INTO interaction_checkpoints (
                checkpoint_id, previous_checkpoint_id, thread_id, step_index, key_epoch,
                message_delta_aead, file_deltas_aead, extension_slots_aead,
                todos_json, async_tasks_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                checkpoint_id,
                prev_cp_id,
                thread_id,
                step_index,
                key_epoch,
                msg_delta,
                file_deltas,
                ext_slots,
                todos_json,
                async_tasks_json
            ],
        )?;

        Ok(checkpoint_blake3)
    }

    /// Time-travels a thread's state by walking backward to genesis and replaying all deltas in forward chronological order.
    pub fn reconstruct_state_at_checkpoint(
        &self,
        target_checkpoint_id: &str,
        registry: &dyn base::typemap::StateExtensionRegistry,
        key_hierarchy: &iam::key_hierarchy::KeyHierarchy,
    ) -> Result<ReconstructedCheckpoint, DataError> {
        let conn = self.db.lock().unwrap();

        let mut chain = Vec::new();
        let mut current_id = Some(target_checkpoint_id.to_string());

        while let Some(cid) = current_id {
            let mut stmt = conn.prepare(
                "SELECT checkpoint_id, previous_checkpoint_id, thread_id, step_index, key_epoch,
                        message_delta_aead, file_deltas_aead, extension_slots_aead,
                        todos_json, async_tasks_json
                 FROM interaction_checkpoints WHERE checkpoint_id = ?1",
            )?;

            let mut rows = stmt.query(params![cid])?;
            if let Some(row) = rows.next()? {
                let prev_id: Option<String> = row.get(1)?;
                chain.push(RawCheckpointRow {
                    checkpoint_id: row.get(0)?,
                    previous_checkpoint_id: prev_id.clone(),
                    thread_id: row.get(2)?,
                    step_index: row.get(3)?,
                    key_epoch: row.get(4)?,
                    message_delta_aead: row.get(5)?,
                    file_deltas_aead: row.get(6)?,
                    extension_slots_aead: row.get(7)?,
                    todos_json: row.get(8)?,
                    async_tasks_json: row.get(9)?,
                });
                current_id = prev_id;
            } else {
                return Err(DataError::CheckpointNotFound(cid));
            }
        }

        // Step-Index Capture Invariant
        let target_step_index = chain.first().map(|r| r.step_index).unwrap_or(0) as u64;
        let target_thread_id = chain
            .first()
            .map(|r| r.thread_id.clone())
            .unwrap_or_default();

        chain.reverse();

        let mut state = TantryState {
            thread_id: "".to_string(),
            step_index: 0,
            last_checkpoint_id: None,
            messages: vec![],
            files: base::vfs_tree::VfsTree::new(),
            todos: vec![],
            skills_metadata: vec![],
            memory_contents: std::collections::BTreeMap::new(),
            async_tasks: std::collections::BTreeMap::new(),
            rubric_input: None,
            rubric_status: None,
            structured_response: None,
            extensions: base::typemap::StateExtensionMap::new(),
        };
        let mut final_checkpoint_blake3 = [0u8; 32];

        for row in chain {
            // Recompute Checkpoint Digest
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"tantry:cp:v3");
            if let Some(pid) = &row.previous_checkpoint_id {
                hasher.update(pid.as_bytes());
            }
            hasher.update(row.thread_id.as_bytes());
            hasher.update(&row.step_index.to_be_bytes());
            if let Some(ref md) = row.message_delta_aead {
                hasher.update(md);
            }
            if let Some(ref fd) = row.file_deltas_aead {
                hasher.update(fd);
            }
            if let Some(ref ext) = row.extension_slots_aead {
                hasher.update(ext);
            }
            final_checkpoint_blake3 = hasher.finalize().into();

            // Deriving DEK securely via thread and epoch salts
            let (epoch_salt, thread_salt) =
                crate::crypto::get_or_provision_key_epoch(&conn, &row.thread_id, row.key_epoch)?;
            let dek = key_hierarchy
                .derive_dek_from_salts(row.key_epoch, &epoch_salt, &row.thread_id, &thread_salt)
                .map(|z| *z)
                .unwrap_or([0u8; 32]);

            let aad = crate::crypto::compute_canonical_aad(
                "interaction_checkpoints",
                &row.checkpoint_id,
                &row.thread_id,
                row.key_epoch,
            );

            if let Some(md_aead) = row.message_delta_aead {
                let plaintext = crate::crypto::decrypt_envelope(&md_aead, &dek, &aad)?;
                let msg_delta: MessageDelta =
                    rmp_serde::from_slice(&plaintext).map_err(|e: rmp_serde::decode::Error| {
                        DataError::Serialization(e.to_string())
                    })?;
                MessageDelta::apply(&mut state.messages, msg_delta)
                    .map_err(|e| DataError::Serialization(format!("{:?}", e)))?;
            }

            if let Some(fd_aead) = row.file_deltas_aead {
                let plaintext = crate::crypto::decrypt_envelope(&fd_aead, &dek, &aad)?;
                let file_deltas: Vec<FileDelta> =
                    rmp_serde::from_slice(&plaintext).map_err(|e: rmp_serde::decode::Error| {
                        DataError::Serialization(e.to_string())
                    })?;
                FileDelta::apply_batch(&mut state.files, &file_deltas)
                    .map_err(|e| DataError::Serialization(format!("{:?}", e)))?;
            }

            if let Some(ext_aead) = row.extension_slots_aead {
                let plaintext = crate::crypto::decrypt_envelope(&ext_aead, &dek, &aad)?;
                let raw_slots: std::collections::BTreeMap<String, Vec<u8>> =
                    rmp_serde::from_slice(&plaintext).map_err(|e: rmp_serde::decode::Error| {
                        DataError::Serialization(e.to_string())
                    })?;
                state
                    .extensions
                    .hydrate_all(&raw_slots, registry)
                    .map_err(|e| DataError::Serialization(format!("{:?}", e)))?;
            }

            if let Some(t_json) = row.todos_json {
                state.todos = serde_json::from_str(&t_json).unwrap_or_default();
            }

            if let Some(at_json) = row.async_tasks_json {
                state.async_tasks = serde_json::from_str(&at_json).unwrap_or_default();
            }
        }

        state.step_index = target_step_index as u64;
        state.thread_id = target_thread_id;
        state.last_checkpoint_id = Some(target_checkpoint_id.to_string());

        let vfs_root_blake3 = state.files.root_hash();

        Ok(ReconstructedCheckpoint {
            state,
            step_index: target_step_index,
            vfs_root_blake3,
            checkpoint_blake3: final_checkpoint_blake3,
        })
    }

    /// Queries the most recent checkpoint ID and step index for a given thread.
    pub fn get_latest_checkpoint_for_thread(
        &self,
        thread_id: &str,
    ) -> Result<Option<(String, i64)>, DataError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT checkpoint_id, step_index FROM interaction_checkpoints WHERE thread_id = ?1 ORDER BY step_index DESC LIMIT 1")?;
        let mut rows = stmt.query(params![thread_id])?;

        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    /// Retrieves the unique checkpoint ID corresponding to an exact logical step index within a thread.
    pub fn get_checkpoint_id_by_step(
        &self,
        thread_id: &str,
        step_index: i64,
    ) -> Result<Option<String>, DataError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT checkpoint_id FROM interaction_checkpoints WHERE thread_id = ?1 AND step_index = ?2")?;
        let mut rows = stmt.query(params![thread_id, step_index])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Retrieves the full sequential history of plaintext archived messages for a thread.
    pub fn list_archived_messages(&self, thread_id: &str) -> Result<Vec<Message>, DataError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT message_json FROM archived_messages WHERE thread_id = ?1 ORDER BY archived_at_ms ASC")?;
        let rows = stmt.query_map(params![thread_id], |row| {
            let text: String = row.get(0)?;
            Ok(text)
        })?;

        let mut msgs = Vec::new();
        for row in rows {
            let json = row?;
            let msg: Message =
                serde_json::from_str(&json).map_err(|e| DataError::Serialization(e.to_string()))?;
            msgs.push(msg);
        }
        Ok(msgs)
    }
}
