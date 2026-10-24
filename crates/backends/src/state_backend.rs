use crate::traits::{BackendCapabilities, DirEntryInfo, EditReceipt, GrepMatch, SandboxExecRequest, SandboxExecResult, VfsBackend, WriteReceipt};
use crate::error::BackendError;
use base::state::TantryState;
use base::path::PosixPath;
use base::ast::FileData;
use chrono::Utc;
use std::sync::Arc;

/// StateBackend struct
pub struct StateBackend;

impl VfsBackend for StateBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_delete: true,
            supports_execute: false,
            is_persistent_host_fs: false,
        }
    }

    fn ls(&self, _state: &TantryState, _path: &str) -> Result<Vec<DirEntryInfo>, BackendError> {
        // ... to be implemented properly, for now just satisfying trait
        Ok(vec![])
    }

    fn read_file(&self, state: &TantryState, path: &str, offset_line: Option<usize>, limit_lines: Option<usize>) -> Result<String, BackendError> {
        let file = state.files.get(path).ok_or_else(|| BackendError::Path(format!("File not found: {}", path)))?;
        let content = file.as_str().ok_or_else(|| BackendError::InvalidOperation("File is not valid UTF-8".to_string()))?;

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

    fn write_file(&self, state: &mut TantryState, path: &str, content: &str) -> Result<WriteReceipt, BackendError> {
        let normalized = base::path::validate_and_normalize_path(path).map_err(|e| BackendError::Path(e.to_string()))?;
        let file_data = Arc::new(FileData::new_utf8(content.to_string(), Utc::now()));
        state.files.insert(normalized, file_data).map_err(|e| BackendError::Path(e.to_string()))?;
        Ok(WriteReceipt { bytes_written: content.len() as u64 })
    }

    fn edit_file(&self, state: &mut TantryState, path: &str, old_string: &str, new_string: &str, replace_all: bool) -> Result<EditReceipt, BackendError> {
        let file = state.files.get(path).ok_or_else(|| BackendError::Path(format!("File not found: {}", path)))?;
        let content = file.as_str().ok_or_else(|| BackendError::InvalidOperation("File is not valid UTF-8".to_string()))?;

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

        let normalized = base::path::validate_and_normalize_path(path).map_err(|e| BackendError::Path(e.to_string()))?;
        let file_data = Arc::new(FileData::new_utf8(new_content, Utc::now()));
        state.files.insert(normalized, file_data).map_err(|e| BackendError::Path(e.to_string()))?;

        Ok(EditReceipt { occurrences_replaced: occurrences })
    }

    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError> {
        state.files.remove(path);
        Ok(())
    }

    fn glob(&self, _state: &TantryState, _pattern: &str) -> Result<Vec<PosixPath>, BackendError> {
        Ok(vec![])
    }

    fn grep(&self, _state: &TantryState, _pattern: &str, _path_glob: Option<&str>) -> Result<Vec<GrepMatch>, BackendError> {
        Ok(vec![])
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        Err(BackendError::CapabilityNotSupported)
    }
}
