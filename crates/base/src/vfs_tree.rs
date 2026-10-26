use std::collections::BTreeMap;
use std::sync::Arc;
use crate::ast::FileData;

#[derive(Debug, Clone, PartialEq)]
pub struct MerkleDirNode {
    pub segment: String,
    pub subtree_blake3: [u8; 32],
    pub file_count: usize,
    pub subdirs: BTreeMap<String, Arc<MerkleDirNode>>,
    pub files: BTreeMap<String, FileData>,
}

impl MerkleDirNode {
    pub fn new(segment: String) -> Self {
        let mut node = Self {
            segment,
            subtree_blake3: [0; 32],
            file_count: 0,
            subdirs: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        node.recompute_hash();
        node
    }

    pub fn recompute_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:merkle_dir:v3:");

        self.file_count = self.files.len();

        for (name, child) in &self.subdirs {
            hasher.update(name.as_bytes());
            hasher.update(&child.subtree_blake3);
            self.file_count += child.file_count;
        }

        for (name, file) in &self.files {
            hasher.update(name.as_bytes());
            hasher.update(&file.blake3_hash);
        }

        self.subtree_blake3 = *hasher.finalize().as_bytes();
    }
}

#[derive(Debug, Clone)]
pub struct VfsTree {
    pub root: Arc<MerkleDirNode>,
}

impl VfsTree {
    pub fn new() -> Self {
        Self {
            root: Arc::new(MerkleDirNode::new("".to_string())),
        }
    }

    pub fn root_hash(&self) -> [u8; 32] {
        self.root.subtree_blake3
    }

    pub fn len(&self) -> usize {
        self.root.file_count
    }

    pub fn get(&self, path: &str) -> Option<&FileData> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }

        let mut current = &self.root;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                return current.files.get(*part);
            } else {
                current = current.subdirs.get(*part)?;
            }
        }
        None
    }

    pub fn insert(&mut self, path: &str, mut file_data: FileData) {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return;
        }

        fn insert_recursive(
            node: &mut MerkleDirNode,
            parts: &[&str],
            file_data: &mut FileData,
        ) {
            let part = parts[0];
            if parts.len() == 1 {
                if let Some(existing) = node.files.get(part) {
                    file_data.created_at = existing.created_at;
                }
                node.files.insert(part.to_string(), file_data.clone());
            } else {
                let child_node = node
                    .subdirs
                    .entry(part.to_string())
                    .or_insert_with(|| Arc::new(MerkleDirNode::new(part.to_string())));

                let mut child_mut = Arc::make_mut(child_node);
                insert_recursive(&mut child_mut, &parts[1..], file_data);
            }
            node.recompute_hash();
        }

        let mut root_mut = Arc::make_mut(&mut self.root);
        insert_recursive(&mut root_mut, &parts, &mut file_data);
    }

    pub fn remove(&mut self, path: &str) -> Option<FileData> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }

        fn remove_recursive(
            node: &mut MerkleDirNode,
            parts: &[&str],
        ) -> Option<FileData> {
            let part = parts[0];
            let removed;
            if parts.len() == 1 {
                removed = node.files.remove(part);
            } else {
                if let Some(child_node) = node.subdirs.get_mut(part) {
                    let mut child_mut = Arc::make_mut(child_node);
                    removed = remove_recursive(&mut child_mut, &parts[1..]);
                    if child_mut.files.is_empty() && child_mut.subdirs.is_empty() {
                        node.subdirs.remove(part);
                    }
                } else {
                    return None;
                }
            }
            if removed.is_some() {
                node.recompute_hash();
            }
            removed
        }

        let mut root_mut = Arc::make_mut(&mut self.root);
        remove_recursive(&mut root_mut, &parts)
    }
}

use crate::delta::FileDelta;

impl VfsTree {
    pub fn diff(&self, target: &VfsTree) -> Vec<FileDelta> {
        self.diff_with_stats(target).0
    }

    pub fn diff_with_stats(&self, target: &VfsTree) -> (Vec<FileDelta>, usize) {
        let mut deltas = Vec::new();
        let mut nodes_visited = 0;

        fn diff_recursive(
            a: &Arc<MerkleDirNode>,
            b: &Arc<MerkleDirNode>,
            path_prefix: String,
            deltas: &mut Vec<FileDelta>,
            nodes_visited: &mut usize,
        ) {
            *nodes_visited += 1;

            if a.subtree_blake3 == b.subtree_blake3 {
                return;
            }

            // Compare files
            let mut a_files = a.files.iter();
            let mut b_files = b.files.iter();

            let mut next_a = a_files.next();
            let mut next_b = b_files.next();

            while let (Some((a_name, a_file)), Some((b_name, b_file))) = (next_a, next_b) {
                if a_name < b_name {
                    let full_path = if path_prefix.is_empty() { a_name.clone() } else { format!("{}/{}", path_prefix, a_name) };
                    deltas.push(FileDelta::Delete { path: full_path });
                    next_a = a_files.next();
                } else if a_name > b_name {
                    let full_path = if path_prefix.is_empty() { b_name.clone() } else { format!("{}/{}", path_prefix, b_name) };
                    deltas.push(FileDelta::Upsert { path: full_path, file: b_file.clone() });
                    next_b = b_files.next();
                } else {
                    if a_file.blake3_hash != b_file.blake3_hash {
                        let full_path = if path_prefix.is_empty() { b_name.clone() } else { format!("{}/{}", path_prefix, b_name) };
                        deltas.push(FileDelta::Upsert { path: full_path, file: b_file.clone() });
                    }
                    next_a = a_files.next();
                    next_b = b_files.next();
                }
            }

            while let Some((a_name, _)) = next_a {
                let full_path = if path_prefix.is_empty() { a_name.clone() } else { format!("{}/{}", path_prefix, a_name) };
                deltas.push(FileDelta::Delete { path: full_path });
                next_a = a_files.next();
            }

            while let Some((b_name, b_file)) = next_b {
                let full_path = if path_prefix.is_empty() { b_name.clone() } else { format!("{}/{}", path_prefix, b_name) };
                deltas.push(FileDelta::Upsert { path: full_path, file: b_file.clone() });
                next_b = b_files.next();
            }

            // Compare subdirs
            let mut a_subdirs = a.subdirs.iter();
            let mut b_subdirs = b.subdirs.iter();

            let mut next_a_dir = a_subdirs.next();
            let mut next_b_dir = b_subdirs.next();

            while let (Some((a_name, a_dir)), Some((b_name, b_dir))) = (next_a_dir, next_b_dir) {
                if a_name < b_name {
                    let full_path = if path_prefix.is_empty() { a_name.clone() } else { format!("{}/{}", path_prefix, a_name) };
                    // Recursively delete all files in a_dir
                    fn emit_deletes(dir: &Arc<MerkleDirNode>, prefix: &str, deltas: &mut Vec<FileDelta>) {
                        for (name, _) in &dir.files {
                            deltas.push(FileDelta::Delete { path: format!("{}/{}", prefix, name) });
                        }
                        for (name, subdir) in &dir.subdirs {
                            emit_deletes(subdir, &format!("{}/{}", prefix, name), deltas);
                        }
                    }
                    emit_deletes(a_dir, &full_path, deltas);
                    next_a_dir = a_subdirs.next();
                } else if a_name > b_name {
                    let full_path = if path_prefix.is_empty() { b_name.clone() } else { format!("{}/{}", path_prefix, b_name) };
                    // Recursively upsert all files in b_dir
                    fn emit_upserts(dir: &Arc<MerkleDirNode>, prefix: &str, deltas: &mut Vec<FileDelta>) {
                        for (name, file) in &dir.files {
                            deltas.push(FileDelta::Upsert { path: format!("{}/{}", prefix, name), file: file.clone() });
                        }
                        for (name, subdir) in &dir.subdirs {
                            emit_upserts(subdir, &format!("{}/{}", prefix, name), deltas);
                        }
                    }
                    emit_upserts(b_dir, &full_path, deltas);
                    next_b_dir = b_subdirs.next();
                } else {
                    let full_path = if path_prefix.is_empty() { a_name.clone() } else { format!("{}/{}", path_prefix, a_name) };
                    diff_recursive(a_dir, b_dir, full_path, deltas, nodes_visited);
                    next_a_dir = a_subdirs.next();
                    next_b_dir = b_subdirs.next();
                }
            }

            while let Some((a_name, a_dir)) = next_a_dir {
                let full_path = if path_prefix.is_empty() { a_name.clone() } else { format!("{}/{}", path_prefix, a_name) };
                fn emit_deletes(dir: &Arc<MerkleDirNode>, prefix: &str, deltas: &mut Vec<FileDelta>) {
                    for (name, _) in &dir.files {
                        deltas.push(FileDelta::Delete { path: format!("{}/{}", prefix, name) });
                    }
                    for (name, subdir) in &dir.subdirs {
                        emit_deletes(subdir, &format!("{}/{}", prefix, name), deltas);
                    }
                }
                emit_deletes(a_dir, &full_path, deltas);
                next_a_dir = a_subdirs.next();
            }

            while let Some((b_name, b_dir)) = next_b_dir {
                let full_path = if path_prefix.is_empty() { b_name.clone() } else { format!("{}/{}", path_prefix, b_name) };
                fn emit_upserts(dir: &Arc<MerkleDirNode>, prefix: &str, deltas: &mut Vec<FileDelta>) {
                    for (name, file) in &dir.files {
                        deltas.push(FileDelta::Upsert { path: format!("{}/{}", prefix, name), file: file.clone() });
                    }
                    for (name, subdir) in &dir.subdirs {
                        emit_upserts(subdir, &format!("{}/{}", prefix, name), deltas);
                    }
                }
                emit_upserts(b_dir, &full_path, deltas);
                next_b_dir = b_subdirs.next();
            }
        }

        diff_recursive(&self.root, &target.root, "".to_string(), &mut deltas, &mut nodes_visited);
        (deltas, nodes_visited)
    }
}
