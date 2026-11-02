use crate::error::BackendError;
use crate::traits::{
    BackendCapabilities, DirEntryInfo, EditReceipt, GrepMatch, SandboxExecRequest,
    SandboxExecResult, VfsBackend, WriteReceipt,
};
use base::ast::FileData;
use base::path::PosixPath;
use base::state::TantryState;
use chrono::Utc;
use std::sync::Arc;

use base::vfs_tree::MerkleDirNode;

/// StateBackend struct
pub struct StateBackend;

impl StateBackend {
    fn walk_dir(
        &self,
        node: &MerkleDirNode,
        matches: &mut Vec<PosixPath>,
        current_path: &str,
        matcher: &glob::Pattern,
    ) {
        for (name, child_dir) in &node.subdirs {
            let new_path = if current_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", current_path, name)
            };
            let mut final_path = String::from("/");
            final_path.push_str(&new_path);

            if matcher.matches(&final_path) {
                matches.push(base::path::validate_and_normalize_path(&final_path).unwrap_or_else(|_| PosixPath::default()));
            }
            self.walk_dir(child_dir, matches, &new_path, matcher);
        }

        for name in node.files.keys() {
            let new_path = if current_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", current_path, name)
            };
            let mut final_path = String::from("/");
            final_path.push_str(&new_path);

            if matcher.matches(&final_path) {
                matches.push(base::path::validate_and_normalize_path(&final_path).unwrap_or_else(|_| PosixPath::default()));
            }
        }
    }
}

impl VfsBackend for StateBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_delete: true,
            supports_execute: false,
            is_persistent_host_fs: false,
        }
    }

    fn ls(&self, state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError> {
        let path_strip = path.strip_prefix('/').unwrap_or(path);
        let mut current_dir = &state.files.root;

        if !path_strip.is_empty() {
            let segments: Vec<&str> = path_strip.split('/').filter(|s| !s.is_empty()).collect();
            for segment in segments {
                if let Some(dir) = current_dir.subdirs.get(segment) {
                    current_dir = dir;
                } else {
                    return Err(BackendError::Path(format!("Directory not found: {}", path_strip)));
                }
            }
        }

        let mut entries = Vec::new();
        for name in current_dir.subdirs.keys() {
            let path_str = if path_strip.is_empty() { format!("/{}", name) } else { format!("/{}/{}", path_strip, name) };
            let posix_path = base::path::validate_and_normalize_path(&path_str).unwrap_or_else(|_| PosixPath::default());
            entries.push(DirEntryInfo {
                path: posix_path,
                name: name.clone(),
                is_dir: true,
                size_bytes: 0,
                blake3_hash: None,
            });
        }
        for (name, file) in &current_dir.files {
            let path_str = if path_strip.is_empty() { format!("/{}", name) } else { format!("/{}/{}", path_strip, name) };
            let posix_path = base::path::validate_and_normalize_path(&path_str).unwrap_or_else(|_| PosixPath::default());
            entries.push(DirEntryInfo {
                path: posix_path,
                name: name.clone(),
                is_dir: false,
                size_bytes: file.content.len() as u64,
                blake3_hash: None,
            });
        }
        Ok(entries)
    }

    fn read_file(
        &self,
        state: &TantryState,
        path: &str,
        offset_line: Option<usize>,
        limit_lines: Option<usize>,
    ) -> Result<String, BackendError> {
        let file = state
            .files
            .get(path)
            .ok_or_else(|| BackendError::Path(format!("File not found: {}", path)))?;
        let content = file
            .as_str()
            .ok_or_else(|| BackendError::InvalidOperation("File is not valid UTF-8".to_string()))?;

        let lines: Vec<&str> = content.lines().collect();
        let start = offset_line.unwrap_or(0);
        if start >= lines.len() && !lines.is_empty() {
            return Ok(String::new());
        }

        let end = match limit_lines {
            Some(limit) => std::cmp::min(start + limit, lines.len()),
            None => lines.len(),
        };

        Ok(lines[start..end].join("\n"))
    }

    fn write_file(
        &self,
        state: &mut TantryState,
        path: &str,
        content: &str,
    ) -> Result<WriteReceipt, BackendError> {
        let normalized = base::path::validate_and_normalize_path(path)
            .map_err(|e| BackendError::Path(e.to_string()))?;
        let file_data = Arc::new(FileData::new_utf8(content.to_string(), Utc::now()));
        let _ = state
            .files
            .insert(normalized.clone(), file_data);

        let mut cst_diagnostics = vec![];
        let parser = repo::parser::Parser::new();
        if let Some(tree) = parser.parse(&normalized.to_string(), content, [0; 32]) {
            cst_diagnostics = repo::linting_hooks::check_cst_diagnostics(&normalized.to_string(), &tree, content);
        }

        let new_blake3_hash = *blake3::hash(content.as_bytes()).as_bytes();
        Ok(WriteReceipt {
            path: normalized,
            bytes_written: content.len(),
            new_blake3_hash,
            cst_diagnostics,
        })
    }

    fn edit_file(
        &self,
        state: &mut TantryState,
        path: &str,
        old_string: &str,
        new_string: &str,
        replace_all: bool,
    ) -> Result<EditReceipt, BackendError> {
        let file = state
            .files
            .get(path)
            .ok_or_else(|| BackendError::Path(format!("File not found: {}", path)))?;
        let content = file
            .as_str()
            .ok_or_else(|| BackendError::InvalidOperation("File is not valid UTF-8".to_string()))?;

        let occurrences = content.matches(old_string).count();
        if occurrences == 0 {
            let norm_path = base::path::validate_and_normalize_path(path).unwrap_or_default();
            return Err(BackendError::OldStringNotFound { path: norm_path });
        }
        if occurrences > 1 && !replace_all {
            let norm_path = base::path::validate_and_normalize_path(path).unwrap_or_default();
            return Err(BackendError::OccurrenceMismatch { path: norm_path, count: occurrences });
        }

        let new_content = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };

        let receipt = self.write_file(state, path, &new_content)?;

        Ok(EditReceipt {
            path: receipt.path,
            replacements_made: occurrences,
            new_blake3_hash: receipt.new_blake3_hash,
            cst_diagnostics: receipt.cst_diagnostics,
        })
    }

    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError> {
        state.files.remove(path);
        Ok(())
    }

    fn glob(&self, state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError> {
        let matcher = glob::Pattern::new(pattern)
            .map_err(|e| BackendError::InvalidOperation(e.to_string()))?;
        let mut matches = Vec::new();
        self.walk_dir(&state.files.root, &mut matches, "", &matcher);
        Ok(matches)
    }

    fn grep(
        &self,
        state: &TantryState,
        pattern: &str,
        path_glob: Option<&str>,
    ) -> Result<Vec<GrepMatch>, BackendError> {
        let paths = if let Some(g) = path_glob {
            self.glob(state, g)?
        } else {
            let mut all_paths = Vec::new();
            let catch_all = glob::Pattern::new("**/*")
                .map_err(|e| BackendError::InvalidOperation(e.to_string()))?;
            self.walk_dir(&state.files.root, &mut all_paths, "", &catch_all);
            all_paths
        };

        let mut grep_matches = Vec::new();
        for path in paths {
            #[allow(clippy::collapsible_if)]
            if let Some(file_data) = state.files.get(&path.to_string()) {
                if let Ok(content_str) = std::str::from_utf8(&file_data.content) {
                    for (i, line) in content_str.lines().enumerate() {
                        if line.contains(pattern) {
                            grep_matches.push(GrepMatch {
                                path: path.clone(),
                                line_number: i + 1,
                                line_text: line.to_string(),
                            });
                        }
                    }
                }
            }
        }
        Ok(grep_matches)
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        Err(BackendError::CapabilityNotSupported)
    }
}
