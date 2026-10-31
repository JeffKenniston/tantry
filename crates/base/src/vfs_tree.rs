use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ast::FileData;
use crate::error::PathValidationError;
use crate::path::PosixPath;
use crate::delta::FileDelta;

#[derive(Debug, Clone)]
pub struct MerkleDirNode {
    pub segment: String,
    pub subtree_blake3: [u8; 32],
    pub file_count: usize,
    pub subdirs: BTreeMap<String, Arc<MerkleDirNode>>,
    pub files: BTreeMap<String, Arc<FileData>>,
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
        hasher.update(self.segment.as_bytes());

        for (fname, fdata) in &self.files {
            hasher.update(b"/F:");
            hasher.update(fname.as_bytes());
            hasher.update(&fdata.blake3_hash);
        }

        for (dname, dnode) in &self.subdirs {
            hasher.update(b"/D:");
            hasher.update(dname.as_bytes());
            hasher.update(&dnode.subtree_blake3);
        }

        self.subtree_blake3 = hasher.finalize().into();
        self.file_count = self.files.len() + self.subdirs.values().map(|d| d.file_count).sum::<usize>();
    }
}

#[derive(Debug, Clone)]
pub struct VfsTree {
    pub root: Arc<MerkleDirNode>,
}

impl Default for VfsTree {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, normalized_path: &str) -> Option<&Arc<FileData>> {
        let mut current = &self.root;
        let mut segments = normalized_path.split('/').filter(|s| !s.is_empty()).peekable();

        while let Some(segment) = segments.next() {
            if segments.peek().is_none() {
                return current.files.get(segment);
            } else if let Some(child) = current.subdirs.get(segment) {
                current = child;
            } else {
                return None;
            }
        }
        None
    }

    pub fn insert(&mut self, normalized_path: PosixPath, mut data: Arc<FileData>) -> Result<Option<Arc<FileData>>, PathValidationError> {
        if normalized_path.is_empty() || normalized_path == "/" {
            return Err(PathValidationError::EmptyPath);
        }

        let segments: Vec<&str> = normalized_path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(PathValidationError::EmptyPath);
        }

        let mut path_stack = vec![(Arc::clone(&self.root), "".to_string())];
        let mut current = Arc::clone(&self.root);

        for &segment in &segments[..segments.len() - 1] {
            let child = {
                if let Some(c) = current.subdirs.get(segment) {
                    Arc::clone(c)
                } else {
                    Arc::new(MerkleDirNode::new(segment.to_string()))
                }
            };
            path_stack.push((Arc::clone(&child), segment.to_string()));
            current = child;
        }

        let filename = segments.last().unwrap().to_string();

        let mut old_data = None;
        if let Some(existing) = current.files.get(&filename) {
            old_data = Some(Arc::clone(existing));
            let mut new_data = (*data).clone();
            new_data.created_at = existing.created_at;
            data = Arc::new(new_data);
        }

        let mut new_current = (*current).clone();
        new_current.files.insert(filename, Arc::clone(&data));
        new_current.recompute_hash();

        let mut child_node = Arc::new(new_current);

        while let Some((parent, segment_name)) = path_stack.pop() {
            if segment_name.is_empty() {
                self.root = child_node;
                break;
            }

            let mut new_parent = (*parent).clone();
            new_parent.subdirs.insert(segment_name, Arc::clone(&child_node));
            new_parent.recompute_hash();
            child_node = Arc::new(new_parent);
        }

        Ok(old_data)
    }

    pub fn remove(&mut self, normalized_path: &str) -> Option<Arc<FileData>> {
        let segments: Vec<&str> = normalized_path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }

        let mut path_stack = vec![(Arc::clone(&self.root), "".to_string())];
        let mut current = Arc::clone(&self.root);

        for &segment in &segments[..segments.len() - 1] {
            if let Some(child) = current.subdirs.get(segment) {
                path_stack.push((Arc::clone(child), segment.to_string()));
                current = Arc::clone(child);
            } else {
                return None;
            }
        }

        let filename = segments.last().unwrap().to_string();

        let mut new_current = (*current).clone();
        let old_data = new_current.files.remove(&filename)?;
        new_current.recompute_hash();

        let mut child_node = Arc::new(new_current);

        while let Some((parent, segment_name)) = path_stack.pop() {
            if segment_name.is_empty() {
                self.root = child_node;
                break;
            }

            let mut new_parent = (*parent).clone();
            if child_node.file_count == 0 {
                new_parent.subdirs.remove(&segment_name);
            } else {
                new_parent.subdirs.insert(segment_name, Arc::clone(&child_node));
            }
            new_parent.recompute_hash();
            child_node = Arc::new(new_parent);
        }

        Some(old_data)
    }

    pub fn diff(&self, after: &Self) -> Vec<FileDelta> {
        let (deltas, _) = self.diff_with_stats(after);
        deltas
    }

    pub fn diff_with_stats(&self, after: &Self) -> (Vec<FileDelta>, usize) {
        let mut deltas = Vec::new();
        let mut visited = 0;
        Self::compare_nodes(&self.root, &after.root, "".to_string(), &mut deltas, &mut visited);
        (deltas, visited)
    }

    fn compare_nodes(
        b: &Arc<MerkleDirNode>,
        a: &Arc<MerkleDirNode>,
        path_prefix: String,
        deltas: &mut Vec<FileDelta>,
        visited: &mut usize,
    ) {
        *visited += 1;
        if b.subtree_blake3 == a.subtree_blake3 {
            return;
        }

        // Deletions
        for (name, b_file) in &b.files {
            let path = format!("{}/{}", path_prefix, name);
            if !a.files.contains_key(name) {
                deltas.push(FileDelta::Delete { path });
            } else {
                let a_file = a.files.get(name).unwrap();
                if b_file.blake3_hash != a_file.blake3_hash {
                    deltas.push(FileDelta::Upsert { path, data: Arc::clone(a_file) });
                }
            }
        }

        for (name, b_dir) in &b.subdirs {
            let path = format!("{}/{}", path_prefix, name);
            if !a.subdirs.contains_key(name) {
                Self::collect_deletes(b_dir, path, deltas);
            }
        }

        // Additions
        for (name, a_file) in &a.files {
            let path = format!("{}/{}", path_prefix, name);
            if !b.files.contains_key(name) {
                deltas.push(FileDelta::Upsert { path, data: Arc::clone(a_file) });
            }
        }

        // Modifications
        for (name, a_dir) in &a.subdirs {
            let path = format!("{}/{}", path_prefix, name);
            if let Some(b_dir) = b.subdirs.get(name) {
                Self::compare_nodes(b_dir, a_dir, path, deltas, visited);
            } else {
                Self::collect_upserts(a_dir, path, deltas);
            }
        }
    }

    fn collect_deletes(node: &Arc<MerkleDirNode>, path_prefix: String, deltas: &mut Vec<FileDelta>) {
        for (name, _) in &node.files {
            deltas.push(FileDelta::Delete { path: format!("{}/{}", path_prefix, name) });
        }
        for (name, child) in &node.subdirs {
            Self::collect_deletes(child, format!("{}/{}", path_prefix, name), deltas);
        }
    }

    fn collect_upserts(node: &Arc<MerkleDirNode>, path_prefix: String, deltas: &mut Vec<FileDelta>) {
        for (name, data) in &node.files {
            deltas.push(FileDelta::Upsert { path: format!("{}/{}", path_prefix, name), data: Arc::clone(data) });
        }
        for (name, child) in &node.subdirs {
            Self::collect_upserts(child, format!("{}/{}", path_prefix, name), deltas);
        }
    }
}
