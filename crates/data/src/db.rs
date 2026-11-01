use crate::error::DataError;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
