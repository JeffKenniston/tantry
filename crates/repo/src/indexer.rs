use base::vfs_tree::VfsTree;
use rusqlite::{Connection, Result};
use std::collections::HashSet;

/// Workspace indexer for checking dirty files against SQLite state.
pub struct Indexer {
    conn: Connection,
}

impl Indexer {
    /// Creates a new `Indexer` connected to the given database path.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS merkle_nodes (
                vfs_path TEXT PRIMARY KEY,
                is_dir INTEGER,
                blake3_hash BLOB,
                mtime_ns INTEGER,
                symbol_count INTEGER
            )",
            [],
        )?;
        Ok(Self { conn })
    }

    /// Gets a set of paths corresponding to dirty files by comparing the given `VfsTree`
    /// to the stored Merkle tree.
    pub fn get_dirty_files(&self, vfs: &VfsTree) -> Result<HashSet<String>> {
        let mut dirty_files = HashSet::new();
        let mut stmt = self.conn.prepare("SELECT vfs_path, blake3_hash FROM merkle_nodes WHERE is_dir = 1")?;
        let rows = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            Ok((path, hash))
        })?;

        let mut db_dirs = std::collections::HashMap::new();
        for row in rows {
            if let Ok((path, hash)) = row {
                db_dirs.insert(path, hash);
            }
        }

        let mut file_stmt = self.conn.prepare("SELECT vfs_path, blake3_hash FROM merkle_nodes WHERE is_dir = 0")?;
        let file_rows = file_stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let hash: Vec<u8> = row.get(1)?;
            Ok((path, hash))
        })?;

        let mut db_files = std::collections::HashMap::new();
        for row in file_rows {
            if let Ok((path, hash)) = row {
                db_files.insert(path, hash);
            }
        }

        let mut queue = vec![(String::from(""), &vfs.root)];
        while let Some((path, node)) = queue.pop() {
            let hash = node.subtree_blake3.to_vec();
            if let Some(db_hash) = db_dirs.get(&path) {
                if db_hash == &hash {
                    // Tree hasn't changed, prune search
                    continue;
                }
            }

            for (file_name, file_data) in &node.files {
                let file_path = if path.is_empty() {
                    file_name.clone()
                } else {
                    format!("{}/{}", path, file_name)
                };
                let file_hash = file_data.blake3_hash.to_vec();
                if let Some(db_file_hash) = db_files.get(&file_path) {
                    if db_file_hash != &file_hash {
                        dirty_files.insert(file_path);
                    }
                } else {
                    dirty_files.insert(file_path);
                }
            }

            for (subdir_name, subdir_node) in &node.subdirs {
                let subdir_path = if path.is_empty() {
                    subdir_name.clone()
                } else {
                    format!("{}/{}", path, subdir_name)
                };
                queue.push((subdir_path, subdir_node));
            }
        }

        Ok(dirty_files)
    }

    /// Persists the given `VfsTree` nodes into the SQLite `merkle_nodes` table.
    pub fn persist(&mut self, vfs: &VfsTree) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO merkle_nodes (vfs_path, is_dir, blake3_hash, mtime_ns, symbol_count)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(vfs_path) DO UPDATE SET
                    is_dir = excluded.is_dir,
                    blake3_hash = excluded.blake3_hash,
                    mtime_ns = excluded.mtime_ns,
                    symbol_count = excluded.symbol_count",
            )?;

            let mut queue = vec![(String::from(""), &vfs.root)];
            while let Some((path, node)) = queue.pop() {
                stmt.execute((
                    &path,
                    1,
                    node.subtree_blake3.as_slice(),
                    0_i64, // Directory mtime
                    0_i64, // Directory symbol_count
                ))?;

                for (file_name, file_data) in &node.files {
                    let file_path = if path.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{}/{}", path, file_name)
                    };
                    stmt.execute((
                        &file_path,
                        0,
                        file_data.blake3_hash.as_slice(),
                        file_data.modified_at.timestamp_nanos_opt().unwrap_or(0),
                        0_i64, // File symbol_count
                    ))?;
                }

                for (subdir_name, subdir_node) in &node.subdirs {
                    let subdir_path = if path.is_empty() {
                        subdir_name.clone()
                    } else {
                        format!("{}/{}", path, subdir_name)
                    };
                    queue.push((subdir_path, subdir_node));
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
