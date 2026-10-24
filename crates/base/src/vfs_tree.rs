use crate::ast::FileData;
use crate::delta::FileDelta;
use crate::error::PathValidationError;
use crate::path::PosixPath;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
/// MerkleDirNode struct
pub struct MerkleDirNode {
    pub segment: String,
    pub subtree_blake3: [u8; 32],
    pub file_count: usize,
    pub subdirs: BTreeMap<String, Arc<MerkleDirNode>>,
    pub files: BTreeMap<String, Arc<FileData>>,
}

impl Default for MerkleDirNode {
    fn default() -> Self {
        Self {
            segment: String::new(),
            subtree_blake3: blake3::hash(b"").into(),
            file_count: 0,
            subdirs: BTreeMap::new(),
            files: BTreeMap::new(),
        }
    }
}

impl MerkleDirNode {
    /// new fn
    pub fn new(segment: String) -> Self {
        let mut node = Self {
            segment,
            ..Default::default()
        };
        node.recompute_hash();
        node
    }

    /// recompute_hash fn
    pub fn recompute_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tantry:merkle_dir:v3:");
        hasher.update(self.segment.as_bytes());

        let mut count = self.files.len();

        for (name, file) in &self.files {
            hasher.update(b"/F:");
            hasher.update(name.as_bytes());
            hasher.update(&file.blake3_hash);
        }

        for (name, dir) in &self.subdirs {
            hasher.update(b"/D:");
            hasher.update(name.as_bytes());
            hasher.update(&dir.subtree_blake3);
            count += dir.file_count;
        }

        self.subtree_blake3 = hasher.finalize().into();
        self.file_count = count;
    }
}

#[derive(Debug, Clone, PartialEq)]
/// VfsTree struct
pub struct VfsTree {
    pub root: Arc<MerkleDirNode>,
}

impl Default for VfsTree {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsTree {
    /// new fn
    pub fn new() -> Self {
        let mut root = MerkleDirNode::new("".to_string());
        root.recompute_hash();
        Self {
            root: Arc::new(root),
        }
    }

    /// root_hash fn
    pub fn root_hash(&self) -> [u8; 32] {
        self.root.subtree_blake3
    }

    /// len fn
    pub fn len(&self) -> usize {
        self.root.file_count
    }

    /// is_empty fn
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// get fn
    pub fn get(&self, normalized_path: &str) -> Option<&Arc<FileData>> {
        let path = normalized_path.strip_prefix('/').unwrap_or(normalized_path);
        if path.is_empty() {
            return None;
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }

        let mut current_dir = &self.root;
        for (i, segment) in segments.iter().enumerate() {
            if i == segments.len() - 1 {
                return current_dir.files.get(*segment);
            } else {
                current_dir = current_dir.subdirs.get(*segment)?;
            }
        }
        None
    }
    /// insert fn
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

        let replaced = Self::insert_recursive(&mut self.root, &segments, 0, data)?;
        Ok(replaced)
    }

    fn insert_recursive(
        dir: &mut Arc<MerkleDirNode>,
        segments: &[&str],
        depth: usize,
        mut data: Arc<FileData>,
    ) -> Result<Option<Arc<FileData>>, PathValidationError> {
        let segment = segments[depth];
        let is_last = depth == segments.len() - 1;

        let replaced;

        let new_dir = Arc::make_mut(dir);

        if is_last {
            new_dir.subdirs.remove(segment);
            if let Some(existing) = new_dir.files.get(segment) {
                let mut new_data = (*data).clone();
                new_data.created_at = existing.created_at;
                data = Arc::new(new_data);
            }
            replaced = new_dir.files.insert(segment.to_string(), data);
        } else {
            new_dir.files.remove(segment);
            if !new_dir.subdirs.contains_key(segment) {
                new_dir.subdirs.insert(
                    segment.to_string(),
                    Arc::new(MerkleDirNode::new(segment.to_string())),
                );
            }
            let child_dir = new_dir.subdirs.get_mut(segment).unwrap();

            replaced = Self::insert_recursive(child_dir, segments, depth + 1, data)?;
        }

        new_dir.recompute_hash();
        Ok(replaced)
    }

    /// remove fn
    pub fn remove(&mut self, normalized_path: &str) -> Option<Arc<FileData>> {
        let path = normalized_path.strip_prefix('/').unwrap_or(normalized_path);
        if path.is_empty() {
            return None;
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return None;
        }

        Self::remove_recursive(&mut self.root, &segments, 0)
    }

    fn remove_recursive(
        dir: &mut Arc<MerkleDirNode>,
        segments: &[&str],
        depth: usize,
    ) -> Option<Arc<FileData>> {
        let segment = segments[depth];
        let is_last = depth == segments.len() - 1;

        let mut remove_child = false;
        let removed;

        {
            let new_dir = Arc::make_mut(dir);

            if is_last {
                removed = new_dir.files.remove(segment);
            } else {
                if let Some(child_dir) = new_dir.subdirs.get_mut(segment) {
                    removed = Self::remove_recursive(child_dir, segments, depth + 1);
                    if child_dir.file_count == 0 {
                        remove_child = true;
                    }
                } else {
                    removed = None;
                }
            }

            if remove_child {
                new_dir.subdirs.remove(segment);
            }

            if removed.is_some() {
                new_dir.recompute_hash();
            }
        }

        removed
    }

    /// diff fn
    pub fn diff(&self, after: &Self) -> Vec<FileDelta> {
        let (deltas, _) = self.diff_with_stats(after);
        deltas
    }

    /// diff_with_stats fn
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

        let b_keys: std::collections::BTreeSet<&String> =
            before.files.keys().chain(before.subdirs.keys()).collect();
        let a_keys: std::collections::BTreeSet<&String> =
            after.files.keys().chain(after.subdirs.keys()).collect();

        let all_keys: std::collections::BTreeSet<&String> =
            b_keys.union(&a_keys).cloned().collect();

        for key in all_keys {
            let current_path = format!("{}/{}", path_prefix, key);

            let b_file = before.files.get(key);
            let b_dir = before.subdirs.get(key);
            let a_file = after.files.get(key);
            let a_dir = after.subdirs.get(key);

            if let (Some(bf), Some(af)) = (b_file, a_file) {
                if bf.blake3_hash != af.blake3_hash {
                    deltas.push(FileDelta::Upsert {
                        path: current_path,
                        data: af.clone(),
                    });
                }
            } else if let (Some(bd), Some(ad)) = (b_dir, a_dir) {
                Self::diff_recursive(bd, ad, current_path, deltas, visited);
            } else {
                if let Some(d) = b_dir {
                    Self::collect_deletes(d, current_path.clone(), deltas, visited);
                } else if b_file.is_some() {
                    deltas.push(FileDelta::Delete {
                        path: current_path.clone(),
                    });
                }

                if let Some(d) = a_dir {
                    Self::collect_upserts(d, current_path, deltas, visited);
                } else if let Some(f) = a_file {
                    deltas.push(FileDelta::Upsert {
                        path: current_path,
                        data: f.clone(),
                    });
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

        let keys: std::collections::BTreeSet<&String> =
            dir.files.keys().chain(dir.subdirs.keys()).collect();

        for key in keys {
            let current_path = format!("{}/{}", path_prefix, key);
            if let Some(f) = dir.files.get(key) {
                deltas.push(FileDelta::Upsert {
                    path: current_path,
                    data: f.clone(),
                });
            } else if let Some(d) = dir.subdirs.get(key) {
                Self::collect_upserts(d, current_path, deltas, visited);
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

        let keys: std::collections::BTreeSet<&String> =
            dir.files.keys().chain(dir.subdirs.keys()).collect();

        for key in keys {
            let current_path = format!("{}/{}", path_prefix, key);
            if dir.files.contains_key(key) {
                deltas.push(FileDelta::Delete { path: current_path });
            } else if let Some(d) = dir.subdirs.get(key) {
                Self::collect_deletes(d, current_path, deltas, visited);
            }
        }
    }
}
