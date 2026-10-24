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
                matches.push(final_path.clone());
            }
            self.walk_dir(child_dir, matches, &new_path, matcher);
        }

        for (name, _) in &node.files {
            let new_path = if current_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", current_path, name)
            };
            let mut final_path = String::from("/");
            final_path.push_str(&new_path);

            if matcher.matches(&final_path) {
                matches.push(final_path);
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
        let path = path.strip_prefix('/').unwrap_or(path);
        let mut current_dir = &state.files.root;

        if !path.is_empty() {
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            for segment in segments {
                if let Some(dir) = current_dir.subdirs.get(segment) {
                    current_dir = dir;
                } else {
                    return Err(BackendError::Path(format!("Directory not found: {}", path)));
                }
            }
        }

        let mut entries = Vec::new();
        for (name, _) in &current_dir.subdirs {
            entries.push(DirEntryInfo {
                name: name.clone(),
                is_dir: true,
                size: 0,
            });
        }
        for (name, file) in &current_dir.files {
            entries.push(DirEntryInfo {
                name: name.clone(),
                is_dir: false,
                size: file.content.len() as u64,
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
        state
            .files
            .insert(normalized, file_data)
            .map_err(|e| BackendError::Path(e.to_string()))?;
        Ok(WriteReceipt {
            bytes_written: content.len() as u64,
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
            return Err(BackendError::OldStringNotFound);
        }
        if occurrences > 1 && !replace_all {
            return Err(BackendError::OccurrenceMismatch { count: occurrences });
        }

        let new_content = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };

        let normalized = base::path::validate_and_normalize_path(path)
            .map_err(|e| BackendError::Path(e.to_string()))?;
        let file_data = Arc::new(FileData::new_utf8(new_content, Utc::now()));
        state
            .files
            .insert(normalized, file_data)
            .map_err(|e| BackendError::Path(e.to_string()))?;

        Ok(EditReceipt {
            occurrences_replaced: occurrences,
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
            if let Some(file_data) = state.files.get(&path) {
                if let Ok(content_str) = std::str::from_utf8(&file_data.content) {
                    for (i, line) in content_str.lines().enumerate() {
                        if line.contains(pattern) {
                            grep_matches.push(GrepMatch {
                                path: path.clone(),
                                line_number: i + 1,
                                content: line.to_string(),
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
