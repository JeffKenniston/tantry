use std::sync::{Arc, Mutex};
use rusqlite::{Connection, OpenFlags};
use crate::error::DataError;

pub struct DbHandle {
    pub writer: Arc<Mutex<Connection>>,
    path: String,
}

impl DbHandle {
    pub fn new(path: &str, ddl: &str) -> Result<Self, DataError> {
        let writer = Connection::open(path)?;

        writer.pragma_update(None, "journal_mode", "WAL")?;
        writer.pragma_update(None, "synchronous", "NORMAL")?;
        writer.pragma_update(None, "foreign_keys", "ON")?;
        writer.pragma_update(None, "busy_timeout", 5000)?;

        writer.execute_batch(ddl)?;
        writer.pragma_update(None, "wal_checkpoint", "PASSIVE")?;

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            path: path.to_string(),
        })
    }

    pub fn get_reader(&self) -> Result<Connection, DataError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&self.path, flags)?;
        Ok(conn)
    }
}
