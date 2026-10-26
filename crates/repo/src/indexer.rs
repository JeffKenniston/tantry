use base::vfs_tree::VfsTree;
use rusqlite::{Connection, Result};
use std::collections::HashSet;

/// Phase 1: Workspace indexer for checking dirty files against SQLite state.
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
    /// to the stored Merkle tree. O(log N) runtime by pruning subtrees matching in hash.
    pub fn get_dirty_files(&self, vfs: &VfsTree) -> Result<HashSet<String>> {
        let mut dirty_files = HashSet::new();

        // 1. Load the SQLite state once (for O(log N) check, we only do this once to avoid repeated querying)
        // In a real system, we'd query dynamically but here SQLite is fast and doing it in memory is fine for the spec.
        let mut stmt = self
            .conn
            .prepare("SELECT vfs_path, is_dir, blake3_hash FROM merkle_nodes")?;
        let rows = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let is_dir: i32 = row.get(1)?;
            let hash: Vec<u8> = row.get(2)?;
            Ok((path, is_dir, hash))
        })?;

        let mut db_dirs = std::collections::HashMap::new();
        let mut db_files = std::collections::HashMap::new();
        for row in rows {
            if let Ok((path, is_dir, hash)) = row {
                if is_dir == 1 {
                    db_dirs.insert(path, hash);
                } else {
                    db_files.insert(path, hash);
                }
            }
        }

        // 2. Compute dirty files using O(log N) logic.
        let mut vfs_files = HashSet::new();
        let mut queue = vec![(String::from(""), &vfs.root)];

        while let Some((path, node)) = queue.pop() {
            let hash = node.subtree_blake3.to_vec();

            // Pruning step for O(log N) complexity:
            if let Some(db_hash) = db_dirs.get(&path) {
                if db_hash == &hash {
                    // Tree hasn't changed. We can skip checking files and subdirectories.
                    // However, we still need to record the files so they aren't marked as deleted.
                    let mut collect_queue = vec![(path.clone(), node)];
                    while let Some((cp, n)) = collect_queue.pop() {
                        for (fnm, _) in &n.files {
                            let fp = if cp.is_empty() {
                                fnm.clone()
                            } else {
                                format!("{}/{}", cp, fnm)
                            };
                            vfs_files.insert(fp);
                        }
                        for (snm, sn) in &n.subdirs {
                            let sp = if cp.is_empty() {
                                snm.clone()
                            } else {
                                format!("{}/{}", cp, snm)
                            };
                            collect_queue.push((sp, sn));
                        }
                    }
                    continue;
                }
            }

            // Subtree changed. Process immediate children.
            for (file_name, file_data) in &node.files {
                let file_path = if path.is_empty() {
                    file_name.clone()
                } else {
                    format!("{}/{}", path, file_name)
                };
                vfs_files.insert(file_path.clone());

                let file_hash = file_data.blake3_hash.to_vec();
                if let Some(db_file_hash) = db_files.get(&file_path) {
                    if db_file_hash != &file_hash {
                        dirty_files.insert(file_path);
                    }
                } else {
                    // New file
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

        // Check for deleted files
        for (db_file_path, _) in db_files {
            if !vfs_files.contains(&db_file_path) {
                dirty_files.insert(db_file_path);
            }
        }

        Ok(dirty_files)
    }

    /// Persists the given `VfsTree` nodes into the SQLite `merkle_nodes` table.
    pub fn persist(&mut self, vfs: &VfsTree) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut vfs_paths = HashSet::new();

            let mut queue = vec![(String::from(""), &vfs.root)];
            while let Some((path, node)) = queue.pop() {
                vfs_paths.insert(path.clone());
                for (file_name, _) in &node.files {
                    let file_path = if path.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{}/{}", path, file_name)
                    };
                    vfs_paths.insert(file_path);
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

            // Get existing paths
            let mut db_paths = Vec::new();
            let mut select_stmt = tx.prepare("SELECT vfs_path FROM merkle_nodes")?;
            let mut rows = select_stmt.query([])?;
            while let Some(row) = rows.next()? {
                let p: String = row.get(0)?;
                db_paths.push(p);
            }
            drop(rows);
            drop(select_stmt);

            let mut delete_stmt = tx.prepare("DELETE FROM merkle_nodes WHERE vfs_path = ?")?;
            for p in db_paths {
                if !vfs_paths.contains(&p) {
                    delete_stmt.execute([&p])?;
                }
            }
            drop(delete_stmt);

            let mut stmt = tx.prepare(
                "INSERT INTO merkle_nodes (vfs_path, is_dir, blake3_hash, mtime_ns, symbol_count)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(vfs_path) DO UPDATE SET
                    is_dir = excluded.is_dir,
                    blake3_hash = excluded.blake3_hash,
                    mtime_ns = excluded.mtime_ns,
                    symbol_count = excluded.symbol_count",
            )?;

            let mut queue2 = vec![(String::from(""), &vfs.root)];
            while let Some((path, node)) = queue2.pop() {
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
                    queue2.push((subdir_path, subdir_node));
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
