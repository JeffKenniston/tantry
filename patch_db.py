with open("crates/data/src/db.rs", "r") as f:
    content = f.read()
impl_str = """
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use crate::error::DataError;
use rusqlite::{Connection, OpenFlags};
use iam::IdentityManager;

/// A high-level facade providing unified access to the task ledger, interaction chain, audit MMR, and vector store.
pub struct DataStoreManager {
    /// The underlying store managing budgets and bandit matrices.
    pub task_ledger: Arc<crate::task_ledger::TaskLedgerStore>,
    /// The underlying store managing time-travel agent states.
    pub interaction_chain: Arc<crate::interaction_chain::InteractionChainStore>,
    /// The underlying store managing the tamper-evident RFC 6962 audit log.
    pub audit_mmr: Arc<crate::audit_mmr::AuditMmrStore>,
    /// The underlying store managing quantized Matryoshka embeddings.
    pub vector_store: Arc<crate::vector_index::MatryoshkaVectorStore>,
}

impl DataStoreManager {
    pub fn open(
        data_dir: impl AsRef<Path>,
        _cipher_suite: crate::crypto::AeadCipherSuite,
        _platform: &base::platform::RuntimePlatform,
    ) -> Result<Self, DataError> {
        let dir = data_dir.as_ref();
        let task_ledger = Arc::new(crate::task_ledger::TaskLedgerStore::new(dir.join("task_ledger.sqlite").to_str().unwrap())?);
        let vector_store = Arc::new(crate::vector_index::MatryoshkaVectorStore::from_handle(task_ledger.db.clone()));
        let interaction_chain = Arc::new(crate::interaction_chain::InteractionChainStore::new(dir.join("interaction_chain.sqlite").to_str().unwrap())?);
        let audit_mmr = Arc::new(crate::audit_mmr::AuditMmrStore::new(dir.join("audit_log.sqlite").to_str().unwrap())?);

        Ok(Self {
            task_ledger,
            vector_store,
            interaction_chain,
            audit_mmr,
        })
    }

    /// Validates the full cryptosystem: verifying the audit MMR and decrypting all valid (unshredded) checkpoints and messages to prove AEAD authenticity.
    pub fn verify_all_integrity(
        &self,
        iam: &dyn IdentityManager,
    ) -> Result<(), DataError> {
        self.audit_mmr
            .verify_all_chain_and_sths(iam)
            .map_err(|seq_no| DataError::CorruptedAuditChain { seq_no, reason: "Tampered".to_string() })?;

        let conn = self.interaction_chain.db.lock();
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

        Ok(())
    }
}
"""
import re
content = re.sub(r'use crate::error::DataError;\nuse rusqlite::\{Connection, OpenFlags\};\nuse std::path::\{Path, PathBuf\};\nuse std::sync::atomic::\{AtomicUsize, Ordering\};\nuse std::sync::Arc;\n', '', content)
with open("crates/data/src/db.rs", "w") as f:
    f.write(impl_str + "\n" + content)
