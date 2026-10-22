pub mod error;
pub mod db;
pub mod crypto;
pub mod task_ledger;
pub mod interaction_chain;
pub mod audit_mmr;
pub mod vector_index;

use std::sync::Arc;
use crate::error::DataError;
use iam::IdentityManager;

pub struct IntegrityReport {
    pub is_valid: bool,
}

pub struct DataStoreManager {
    pub task_ledger: Arc<task_ledger::TaskLedgerStore>,
    pub interaction_chain: Arc<interaction_chain::InteractionChainStore>,
    pub audit_mmr: Arc<audit_mmr::AuditMmrStore>,
    pub vector_index: Arc<vector_index::MatryoshkaVectorStore>,
}

impl DataStoreManager {
    pub fn verify_all_integrity(&self, iam: &dyn IdentityManager) -> Result<IntegrityReport, DataError> {
        self.audit_mmr.verify_all_chain_and_sths(iam).map_err(|e| DataError::TamperedAuditEntry(e))?;

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

            let (epoch_salt, thread_salt) = crate::crypto::get_or_provision_key_epoch(&conn, &thread_id, key_epoch)?;
            let dek = iam.key_hierarchy().derive_dek(&epoch_salt, &thread_salt);
            let aad = crate::crypto::compute_canonical_aad("interaction_checkpoints", &checkpoint_id, &thread_id, key_epoch);

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

        let mut stmt = conn.prepare("
            SELECT a.thread_id, a.message_id, a.key_epoch, a.message_aead
            FROM archived_messages a
            LEFT JOIN key_epochs k ON a.thread_id = k.thread_id AND a.key_epoch = k.key_epoch
            WHERE k.shredded = 0
        ")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let thread_id: String = row.get(0)?;
            let message_id: String = row.get(1)?;
            let key_epoch: u32 = row.get(2)?;
            let aead: Vec<u8> = row.get(3)?;

            let (epoch_salt, thread_salt) = crate::crypto::get_or_provision_key_epoch(&conn, &thread_id, key_epoch)?;
            let dek = iam.key_hierarchy().derive_dek(&epoch_salt, &thread_salt);
            let aad = crate::crypto::compute_canonical_aad("archived_messages", &message_id, &thread_id, key_epoch);

            let _ = crate::crypto::decrypt_envelope(&aead, &dek, &aad)?;
        }

        Ok(IntegrityReport { is_valid: true })
    }
}
