use crate::ast::FileData;
use crate::delta::FileDelta;
use crate::error::PathValidationError;
use crate::path::PosixPath;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum MerkleNode {
    File(Arc<FileData>),
    Directory(Arc<MerkleDirNode>),
}

impl MerkleNode {
    pub fn blake3_hash(&self) -> [u8; 32] {
        match self {
            MerkleNode::File(f) => f.blake3_hash,
            MerkleNode::Directory(d) => d.subtree_blake3,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MerkleDirNode {
    pub children: BTreeMap<String, MerkleNode>,
    pub subtree_blake3: [u8; 32],
    pub file_count: usize,
}

impl Default for MerkleDirNode {
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            subtree_blake3: blake3::hash(b"").into(),
            file_count: 0,
        }
    }
}

impl MerkleDirNode {
    pub fn recompute_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        let mut count = 0;

        for (name, node) in &self.children {
            let hash = node.blake3_hash();
            hasher.update(name.as_bytes());
            hasher.update(&hash);

            match node {
                MerkleNode::File(_) => count += 1,
                MerkleNode::Directory(d) => count += d.file_count,
            }
        }

        self.subtree_blake3 = hasher.finalize().into();
        self.file_count = count;
    }
}

#[derive(Debug, Clone, PartialEq)]
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
            root: Arc::new(MerkleDirNode::default()),
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
        let path = normalized_path.strip_prefix('/').unwrap_or(normalized_path);
        if path.is_empty() {
            return None;
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_dir = &*self.root;

        for (i, &segment) in segments.iter().enumerate() {
            let is_last = i == segments.len() - 1;
            if let Some(node) = current_dir.children.get(segment) {
                match node {
                    MerkleNode::File(f) => {
                        if is_last {
                            return Some(f);
                        } else {
                            return None;
                        }
                    }
                    MerkleNode::Directory(d) => {
                        if is_last {
                            return None;
                        }
                        current_dir = d;
                    }
                }
            } else {
                return None;
            }
        }

        None
    }

    pub fn insert(
        &mut self,
        normalized_path: PosixPath,
        data: Arc<FileData>,
    ) -> Result<Option<Arc<FileData>>, PathValidationError> {
        let path = normalized_path
            .strip_prefix('/')
            .unwrap_or(&normalized_path);
        if path.is_empty() {
            return Err(PathValidationError::EmptyPath);
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(PathValidationError::EmptyPath);
        }

        let (replaced, new_root) = Self::insert_recursive(&self.root, &segments, 0, data)?;
        self.root = new_root;
        Ok(replaced)
    }

    fn insert_recursive(
        dir: &Arc<MerkleDirNode>,
        segments: &[&str],
        depth: usize,
        data: Arc<FileData>,
    ) -> Result<(Option<Arc<FileData>>, Arc<MerkleDirNode>), PathValidationError> {
        let mut new_dir = (**dir).clone();
        let segment = segments[depth];
        let is_last = depth == segments.len() - 1;

        let mut replaced = None;

        if is_last {
            if let Some(old) = new_dir
                .children
                .insert(segment.to_string(), MerkleNode::File(data))
            {
                if let MerkleNode::File(f) = old {
                    replaced = Some(f);
                }
            }
        } else {
            let child_node = new_dir.children.get(segment);
            let next_dir = match child_node {
                Some(MerkleNode::Directory(d)) => d.clone(),
                Some(MerkleNode::File(_)) => {
                    // Overwriting file with dir path, let's treat it as a new dir
                    Arc::new(MerkleDirNode::default())
                }
                None => Arc::new(MerkleDirNode::default()),
            };

            let (child_replaced, next_dir) =
                Self::insert_recursive(&next_dir, segments, depth + 1, data)?;
            replaced = child_replaced;
            new_dir
                .children
                .insert(segment.to_string(), MerkleNode::Directory(next_dir));
        }

        new_dir.recompute_hash();
        Ok((replaced, Arc::new(new_dir)))
    }

    pub fn remove(&mut self, normalized_path: &str) -> Option<Arc<FileData>> {
        let path = normalized_path.strip_prefix('/').unwrap_or(normalized_path);
        if path.is_empty() {
            return None;
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }

        let (removed, new_root) = Self::remove_recursive(&self.root, &segments, 0);
        if removed.is_some() {
            self.root = new_root;
        }
        removed
    }

    fn remove_recursive(
        dir: &Arc<MerkleDirNode>,
        segments: &[&str],
        depth: usize,
    ) -> (Option<Arc<FileData>>, Arc<MerkleDirNode>) {
        let segment = segments[depth];
        let is_last = depth == segments.len() - 1;

        if !dir.children.contains_key(segment) {
            return (None, dir.clone());
        }

        let mut new_dir = (**dir).clone();
        let mut removed = None;

        if is_last {
            if let Some(MerkleNode::File(f)) = new_dir.children.remove(segment) {
                removed = Some(f);
            }
        } else {
            if let Some(MerkleNode::Directory(child_dir)) = new_dir.children.get(segment) {
                let (child_removed, new_child_dir) =
                    Self::remove_recursive(child_dir, segments, depth + 1);
                removed = child_removed;

                if new_child_dir.file_count == 0 {
                    new_dir.children.remove(segment);
                } else {
                    new_dir
                        .children
                        .insert(segment.to_string(), MerkleNode::Directory(new_child_dir));
                }
            }
        }

        if removed.is_some() {
            new_dir.recompute_hash();
        }

        (removed, Arc::new(new_dir))
    }

    pub fn diff(&self, after: &Self) -> Vec<FileDelta> {
        let (deltas, _) = self.diff_with_stats(after);
        deltas
    }

    pub fn diff_with_stats(&self, after: &Self) -> (Vec<FileDelta>, usize) {
        let mut deltas = Vec::new();
        let mut visited = 0;
        Self::diff_recursive(
            &self.root,
            &after.root,
            String::new(),
            &mut deltas,
            &mut visited,
        );
        (deltas, visited)
    }

    fn diff_recursive(
        before: &MerkleDirNode,
        after: &MerkleDirNode,
        path_prefix: String,
        deltas: &mut Vec<FileDelta>,
        visited: &mut usize,
    ) {
        *visited += 1;
        if before.subtree_blake3 == after.subtree_blake3 {
            return;
        }

        let mut before_keys: Vec<_> = before.children.keys().collect();
        let mut after_keys: Vec<_> = after.children.keys().collect();
        before_keys.sort();
        after_keys.sort();

        let mut b_iter = before_keys.into_iter().peekable();
        let mut a_iter = after_keys.into_iter().peekable();

        while let (Some(&b_key_str), Some(&a_key_str)) = (b_iter.peek(), a_iter.peek()) {
            let b_key = b_key_str.as_str();
            let a_key = a_key_str.as_str();

            if b_key == a_key {
                let current_path = format!("{}/{}", path_prefix, b_key);
                let b_node = before.children.get(b_key).unwrap();
                let a_node = after.children.get(a_key).unwrap();

                if b_node.blake3_hash() != a_node.blake3_hash() {
                    match (b_node, a_node) {
                        (MerkleNode::File(_), MerkleNode::File(a_f)) => {
                            deltas.push(FileDelta::Upsert {
                                path: current_path,
                                data: a_f.clone(),
                            });
                        }
                        (MerkleNode::Directory(b_d), MerkleNode::Directory(a_d)) => {
                            Self::diff_recursive(b_d, a_d, current_path, deltas, visited);
                        }
                        (MerkleNode::File(_), MerkleNode::Directory(a_d)) => {
                            deltas.push(FileDelta::Delete {
                                path: current_path.clone(),
                            });
                            Self::collect_upserts(a_d, current_path, deltas, visited);
                        }
                        (MerkleNode::Directory(b_d), MerkleNode::File(a_f)) => {
                            Self::collect_deletes(b_d, current_path.clone(), deltas, visited);
                            deltas.push(FileDelta::Upsert {
                                path: current_path,
                                data: a_f.clone(),
                            });
                        }
                    }
                }

                b_iter.next();
                a_iter.next();
            } else if b_key < a_key {
                let current_path = format!("{}/{}", path_prefix, b_key);
                match before.children.get(b_key).unwrap() {
                    MerkleNode::File(_) => {
                        deltas.push(FileDelta::Delete { path: current_path });
                    }
                    MerkleNode::Directory(d) => {
                        Self::collect_deletes(d, current_path, deltas, visited);
                    }
                }
                b_iter.next();
            } else {
                let current_path = format!("{}/{}", path_prefix, a_key);
                match after.children.get(a_key).unwrap() {
                    MerkleNode::File(f) => {
                        deltas.push(FileDelta::Upsert {
                            path: current_path,
                            data: f.clone(),
                        });
                    }
                    MerkleNode::Directory(d) => {
                        Self::collect_upserts(d, current_path, deltas, visited);
                    }
                }
                a_iter.next();
            }
        }

        while let Some(b_key_str) = b_iter.next() {
            let b_key = b_key_str.as_str();
            let current_path = format!("{}/{}", path_prefix, b_key);
            match before.children.get(b_key).unwrap() {
                MerkleNode::File(_) => {
                    deltas.push(FileDelta::Delete { path: current_path });
                }
                MerkleNode::Directory(d) => {
                    Self::collect_deletes(d, current_path, deltas, visited);
                }
            }
        }

        while let Some(a_key_str) = a_iter.next() {
            let a_key = a_key_str.as_str();
            let current_path = format!("{}/{}", path_prefix, a_key);
            match after.children.get(a_key).unwrap() {
                MerkleNode::File(f) => {
                    deltas.push(FileDelta::Upsert {
                        path: current_path,
                        data: f.clone(),
                    });
                }
                MerkleNode::Directory(d) => {
                    Self::collect_upserts(d, current_path, deltas, visited);
                }
            }
        }
    }

    fn collect_upserts(
        dir: &MerkleDirNode,
        path_prefix: String,
        deltas: &mut Vec<FileDelta>,
        visited: &mut usize,
    ) {
        *visited += 1;
        let mut keys: Vec<_> = dir.children.keys().collect();
        keys.sort();

        for key in keys {
            let current_path = format!("{}/{}", path_prefix, key);
            match dir.children.get(key).unwrap() {
                MerkleNode::File(f) => deltas.push(FileDelta::Upsert {
                    path: current_path,
                    data: f.clone(),
                }),
                MerkleNode::Directory(d) => Self::collect_upserts(d, current_path, deltas, visited),
            }
        }
    }

    fn collect_deletes(
        dir: &MerkleDirNode,
        path_prefix: String,
        deltas: &mut Vec<FileDelta>,
        visited: &mut usize,
    ) {
        *visited += 1;
        let mut keys: Vec<_> = dir.children.keys().collect();
        keys.sort();

        for key in keys {
            let current_path = format!("{}/{}", path_prefix, key);
            match dir.children.get(key).unwrap() {
                MerkleNode::File(_) => deltas.push(FileDelta::Delete { path: current_path }),
                MerkleNode::Directory(d) => Self::collect_deletes(d, current_path, deltas, visited),
            }
        }
    }
}
