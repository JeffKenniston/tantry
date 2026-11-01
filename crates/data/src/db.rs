
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
    /// The underlying store managing encryption key epochs.
    pub key_epochs: Arc<crate::crypto::KeyEpochStore>,
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
        let conn = interaction_chain.db.lock();
        conn.execute_batch(crate::crypto::KEY_EPOCH_DDL)?;
        drop(conn);
        let key_epochs = Arc::new(crate::crypto::KeyEpochStore::new(interaction_chain.db.clone()));
        let audit_mmr = Arc::new(crate::audit_mmr::AuditMmrStore::new(dir.join("audit_log.sqlite").to_str().unwrap())?);

        Ok(Self {
            task_ledger,
            vector_store,
            interaction_chain,
            audit_mmr,
            key_epochs,
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
            SELECT i.thread_id, i.checkpoint_id, i.epoch_id, i.message_delta_aead, i.file_deltas_aead, i.extension_slots_aead
            FROM interaction_checkpoints i
            LEFT JOIN key_epochs k ON i.thread_id = k.thread_id AND i.epoch_id = k.epoch_id
            WHERE k.shredded = 0
        ")?;
        let mut rows = stmt.query([])?;

        let mut checkpoints_to_check = Vec::new();
        while let Some(row) = rows.next()? {
            let thread_id: String = row.get(0)?;
            let checkpoint_id: String = row.get(1)?;
            let epoch_id: u32 = row.get(2)?;
            let md_aead: Option<Vec<u8>> = row.get(3)?;
            let fd_aead: Option<Vec<u8>> = row.get(4)?;
            let ext_aead: Option<Vec<u8>> = row.get(5)?;
            checkpoints_to_check.push((thread_id, checkpoint_id, epoch_id, md_aead, fd_aead, ext_aead));
        }

        drop(rows);
        drop(stmt);
        drop(conn);

        for (thread_id, checkpoint_id, epoch_id, md_aead, fd_aead, ext_aead) in checkpoints_to_check {
            let key_epoch_store = crate::crypto::KeyEpochStore::new(self.interaction_chain.db.clone());
            let dek = key_epoch_store
                .resolve_or_init_thread_dek(iam.key_hierarchy(), &thread_id, epoch_id)
                .map(|z| *z)
                .unwrap_or([0u8; 32]);
            let aad = crate::crypto::compute_canonical_aad(
                "interaction_checkpoints",
                &checkpoint_id,
                &thread_id,
                epoch_id,
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

        let conn = self.interaction_chain.db.lock();
        let mut stmt = conn.prepare(
            "
            SELECT a.thread_id, a.message_id, a.epoch_id, a.message_aead
            FROM archived_messages a
            LEFT JOIN key_epochs k ON a.thread_id = k.thread_id AND a.epoch_id = k.epoch_id
            WHERE k.shredded = 0
        ",
        )?;
        let mut rows = stmt.query([])?;

        let mut messages_to_check = Vec::new();
        while let Some(row) = rows.next()? {
            let thread_id: String = row.get(0)?;
            let message_id: String = row.get(1)?;
            let epoch_id: u32 = row.get(2)?;
            let aead: Vec<u8> = row.get(3)?;
            messages_to_check.push((thread_id, message_id, epoch_id, aead));
        }

        drop(rows);
        drop(stmt);
        drop(conn);

        for (thread_id, message_id, epoch_id, aead) in messages_to_check {
            let key_epoch_store = crate::crypto::KeyEpochStore::new(self.interaction_chain.db.clone());
            let dek = key_epoch_store
                .resolve_or_init_thread_dek(iam.key_hierarchy(), &thread_id, epoch_id)
                .map(|z| *z)
                .unwrap_or([0u8; 32]);
            let aad = crate::crypto::compute_canonical_aad(
                "archived_messages",
                &message_id,
                &thread_id,
                epoch_id,
            );

            let _ = crate::crypto::decrypt_envelope(&aead, &dek, &aad)?;
        }

        Ok(())
    }
}


/// A thread-safe, writer-first initialization handle for SQLite databases ensuring WAL mode and initial schemas are set before readers are allowed.
pub struct DbHandle {
    pub db_path: PathBuf,
    pub writer: Arc<parking_lot::Mutex<Connection>>,
    pub readers: Vec<parking_lot::Mutex<Connection>>,
    pub reader_cursor: AtomicUsize,
}

impl DbHandle {
    /// Opens a new DbHandle, opening the writer connection first, applying PRAGMAs, executing DDL, and checkpointing.
    pub fn open<F>(
        db_path: impl AsRef<Path>,
        read_pool_size: usize,
        platform: &base::platform::RuntimePlatform,
        init_ddl: F,
    ) -> Result<Self, DataError>
    where
        F: FnOnce(&Connection) -> Result<(), DataError>,
    {
        let path = db_path.as_ref();

        // Create parent directories if db_path is not `:memory:`.
        if path.to_string_lossy() != ":memory:" {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        DataError::Base(base::error::BaseError::Config(
                            base::error::ConfigValidationError::InvalidToml(e.to_string()),
                        )) // Just a temporary workaround for lack of explicit fs error type in DataError
                    })?;
                }
            }
        }

        let writer_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;

        let writer_conn = Connection::open_with_flags(path, writer_flags)?;

        writer_conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;
            ",
        )?;

        init_ddl(&writer_conn)?;
        let _ = writer_conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");

        let effective_readers = match platform {
            base::platform::RuntimePlatform::AndroidTermux { .. } => read_pool_size.clamp(1, 4),
            base::platform::RuntimePlatform::LinuxStandard => read_pool_size.max(1),
        };

        let mut readers = Vec::with_capacity(effective_readers);
        let path_str = path.to_string_lossy();

        // We use string manipulation to check if it's an in-memory shared URI.
        let is_memory_shared = path_str.starts_with("file:") && path_str.contains("mode=memory") && path_str.contains("cache=shared");

        for _ in 0..effective_readers {
            let reader_flags = if is_memory_shared {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_MEMORY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI
            };

            let reader_conn = Connection::open_with_flags(path, reader_flags)?;

            reader_conn.execute_batch(
                "
                PRAGMA busy_timeout = 5000;
                PRAGMA query_only = ON;
                ",
            )?;

            readers.push(parking_lot::Mutex::new(reader_conn));
        }

        Ok(Self {
            db_path: path.to_path_buf(),
            writer: Arc::new(parking_lot::Mutex::new(writer_conn)),
            readers,
            reader_cursor: AtomicUsize::new(0),
        })
    }

    pub fn with_writer<T, F>(&self, f: F) -> Result<T, DataError>
    where
        F: FnOnce(&mut Connection) -> Result<T, DataError>,
    {
        let mut conn = self.writer.lock();
        f(&mut conn)
    }

    pub fn with_reader<T, F>(&self, f: F) -> Result<T, DataError>
    where
        F: FnOnce(&Connection) -> Result<T, DataError>,
    {
        if self.readers.is_empty() {
            // Should not happen since we clamped/maxed to at least 1, but just in case
            let conn = self.writer.lock();
            f(&conn)
        } else {
            let idx = self.reader_cursor.fetch_add(1, Ordering::Relaxed) % self.readers.len();
            let conn = self.readers[idx].lock();
            f(&conn)
        }
    }
}
