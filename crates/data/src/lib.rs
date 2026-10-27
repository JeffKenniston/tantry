#![allow(clippy::all)]
pub mod audit_mmr;
pub mod crypto;
pub mod db;
pub mod error;
pub mod interaction_chain;
pub mod task_ledger;
pub mod vector_index;

use crate::error::DataError;
use iam::IdentityManager;
use std::sync::Arc;

/// The boolean result of a full cryptographic consistency verification across all ledgers.
pub struct IntegrityReport {
    /// True if all hashes, signatures, and AEAD tags verified successfully.
    pub is_valid: bool,
}

/// A high-level facade providing unified access to the task ledger, interaction chain, audit MMR, and vector store.
pub struct DataStoreManager {
    /// The underlying store managing budgets and bandit matrices.
    pub task_ledger: Arc<task_ledger::TaskLedgerStore>,
    /// The underlying store managing time-travel agent states.
    pub interaction_chain: Arc<interaction_chain::InteractionChainStore>,
    /// The underlying store managing the tamper-evident RFC 6962 audit log.
    pub audit_mmr: Arc<audit_mmr::AuditMmrStore>,
    /// The underlying store managing quantized Matryoshka embeddings.
    pub vector_index: Arc<vector_index::MatryoshkaVectorStore>,
}

impl DataStoreManager {
    pub fn new(task_ledger_path: &str, interaction_chain_path: &str, audit_mmr_path: &str, vector_index_path: &str) -> Result<Self, DataError> {
        Ok(Self {
            task_ledger: Arc::new(task_ledger::TaskLedgerStore::new(task_ledger_path)?),
            interaction_chain: Arc::new(interaction_chain::InteractionChainStore::new(interaction_chain_path)?),
            audit_mmr: Arc::new(audit_mmr::AuditMmrStore::new(audit_mmr_path)?),
            vector_index: Arc::new(vector_index::MatryoshkaVectorStore::new(vector_index_path)?),
        })
    }
    /// Validates the full cryptosystem: verifying the audit MMR and decrypting all valid (unshredded) checkpoints and messages to prove AEAD authenticity.
    pub fn verify_all_integrity(
        &self,
        iam: &dyn IdentityManager,
    ) -> Result<IntegrityReport, DataError> {
        self.audit_mmr
            .verify_all_chain_and_sths(iam)
            .map_err(DataError::TamperedAuditEntry)?;

        let conn = self.interaction_chain.db.lock().unwrap();
        let mut stmt = conn.prepare("
            SELECT i.thread_id, i.checkpoint_id, i.key_epoch, i.message_delta_aead, i.file_deltas_aead, i.extension_slots_aead
            FROM interaction_checkpoints i
            LEFT JOIN key_epochs k ON i.thread_id = k.thread_id AND i.key_epoch = k.key_epoch
            WHERE k.shredded = 0
        ")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let thread_id: String = row.get(0)?;
            let checkpoint_id: String = row.get(1)?;
            let key_epoch: u32 = row.get(2)?;
            let md_aead: Option<Vec<u8>> = row.get(3)?;
            let fd_aead: Option<Vec<u8>> = row.get(4)?;
            let ext_aead: Option<Vec<u8>> = row.get(5)?;

            let (epoch_salt, thread_salt) =
                crate::crypto::get_or_provision_key_epoch(&conn, &thread_id, key_epoch)?;
            let dek = iam
                .key_hierarchy()
                .derive_thread_dek(&thread_id, key_epoch, &epoch_salt, &thread_salt)
                .map(|z| *z)
                .unwrap_or([0u8; 32]);
            let aad = crate::crypto::compute_canonical_aad(
                "interaction_checkpoints",
                &checkpoint_id,
                &thread_id,
                key_epoch,
            );

            if let Some(wire) = md_aead {
                let _ = crate::crypto::decrypt_envelope(&wire, &dek, &aad)?;
            }
            if let Some(wire) = fd_aead {
                let _ = crate::crypto::decrypt_envelope(&wire, &dek, &aad)?;
            }
            if let Some(wire) = ext_aead {
                let _ = crate::crypto::decrypt_envelope(&wire, &dek, &aad)?;
            }
        }

        let mut stmt = conn.prepare(
            "
            SELECT a.thread_id, a.message_id, a.key_epoch, a.message_aead
            FROM archived_messages a
            LEFT JOIN key_epochs k ON a.thread_id = k.thread_id AND a.key_epoch = k.key_epoch
            WHERE k.shredded = 0
        ",
        )?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let thread_id: String = row.get(0)?;
            let message_id: String = row.get(1)?;
            let key_epoch: u32 = row.get(2)?;
            let aead: Vec<u8> = row.get(3)?;

            let (epoch_salt, thread_salt) =
                crate::crypto::get_or_provision_key_epoch(&conn, &thread_id, key_epoch)?;
            let dek = iam
                .key_hierarchy()
                .derive_thread_dek(&thread_id, key_epoch, &epoch_salt, &thread_salt)
                .map(|z| *z)
                .unwrap_or([0u8; 32]);
            let aad = crate::crypto::compute_canonical_aad(
                "archived_messages",
                &message_id,
                &thread_id,
                key_epoch,
            );

            let _ = crate::crypto::decrypt_envelope(&aead, &dek, &aad)?;
        }

        Ok(IntegrityReport { is_valid: true })
    }
}
