use crate::traits::{BackendCapabilities, DirEntryInfo, EditReceipt, GrepMatch, SandboxExecRequest, SandboxExecResult, VfsBackend, WriteReceipt};
use crate::error::BackendError;
use base::state::TantryState;
use base::path::PosixPath;
use base::ast::FileData;
use chrono::Utc;
use std::sync::Arc;
use std::io::{Read, Write};
use cap_std::fs::Dir;

/// LocalFsBackend struct
pub struct LocalFsBackend {
    dir: Dir,
}

impl LocalFsBackend {
    /// new method
    pub fn new(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        Ok(Self { dir })
    }

    fn normalize_local_path<'a>(&self, path: &'a str) -> &'a str {
        path.strip_prefix('/').unwrap_or(path)
    }
}

impl VfsBackend for LocalFsBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_delete: true,
            supports_execute: false,
            is_persistent_host_fs: true,
        }
    }

    fn ls(&self, _state: &TantryState, _path: &str) -> Result<Vec<DirEntryInfo>, BackendError> {
        Ok(vec![])
    }

    fn read_file(&self, _state: &TantryState, path: &str, offset_line: Option<usize>, limit_lines: Option<usize>) -> Result<String, BackendError> {
        let local_path = self.normalize_local_path(path);
        let mut file = self.dir.open(local_path).map_err(|e| BackendError::Io(e.to_string()))?;
        let mut content = String::new();
        file.read_to_string(&mut content).map_err(|e| BackendError::Io(e.to_string()))?;

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
        let local_path = self.normalize_local_path(path);
        let mut file = self.dir.create(local_path).map_err(|e| BackendError::Io(e.to_string()))?;
        file.write_all(content.as_bytes()).map_err(|e| BackendError::Io(e.to_string()))?;

        let normalized = base::path::validate_and_normalize_path(path).map_err(|e| BackendError::Path(e.to_string()))?;
        let file_data = Arc::new(FileData::new_utf8(content.to_string(), Utc::now()));
        state.files.insert(normalized, file_data).map_err(|e| BackendError::Path(e.to_string()))?;

        Ok(WriteReceipt { bytes_written: content.len() as u64 })
    }

    fn edit_file(&self, state: &mut TantryState, path: &str, old_string: &str, new_string: &str, replace_all: bool) -> Result<EditReceipt, BackendError> {
        let content = self.read_file(state, path, None, None)?;

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

        self.write_file(state, path, &new_content)?;

        Ok(EditReceipt { occurrences_replaced: occurrences })
    }

    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError> {
        let local_path = self.normalize_local_path(path);
        self.dir.remove_file(local_path).map_err(|e| BackendError::Io(e.to_string()))?;
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
