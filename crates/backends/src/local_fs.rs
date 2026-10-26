use crate::error::BackendError;
use crate::traits::{
    BackendCapabilities, DirEntryInfo, EditReceipt, GrepMatch, SandboxExecRequest,
    SandboxExecResult, VfsBackend, WriteReceipt,
};
use base::ast::FileData;
use base::path::PosixPath;
use base::state::TantryState;
use cap_std::fs::Dir;
use chrono::Utc;
use std::io::{Read, Write};
use std::sync::Arc;

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

    fn walk_dir(
        &self,
        matches: &mut Vec<PosixPath>,
        current_path: &str,
        matcher: &glob::Pattern,
    ) -> Result<(), BackendError> {
        let read_dir = if current_path.is_empty() {
            self.dir.entries()
        } else {
            self.dir.read_dir(current_path)
        };

        if let Ok(entries) = read_dir {
            #[allow(clippy::manual_flatten)]
        for entry_res in entries {
                if let Ok(entry) = entry_res {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    let new_path = if current_path.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{}/{}", current_path, file_name)
                    };

                    if let Ok(metadata) = entry.metadata() {
                        let mut final_path = String::from("/");
                        final_path.push_str(&new_path);

                        if matcher.matches(&final_path) {
                            matches.push(final_path.clone());
                        }

                        if metadata.is_dir() {
                            self.walk_dir(matches, &new_path, matcher)?;
                        }
                    }
                }
            }
        }
        Ok(())
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

    fn ls(&self, _state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError> {
        let local_path = self.normalize_local_path(path);
        let mut entries = Vec::new();

        let dir_entries = if local_path.is_empty() {
            self.dir
                .entries()
                .map_err(|e| BackendError::Io(e.to_string()))?
        } else {
            self.dir
                .read_dir(local_path)
                .map_err(|e| BackendError::Io(e.to_string()))?
        };

        for entry in dir_entries {
            let entry = entry.map_err(|e| BackendError::Io(e.to_string()))?;
            let metadata = entry
                .metadata()
                .map_err(|e| BackendError::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            entries.push(DirEntryInfo {
                name,
                is_dir: metadata.is_dir(),
                size: metadata.len(),
            });
        }
        Ok(entries)
    }

    fn read_file(
        &self,
        _state: &TantryState,
        path: &str,
        offset_line: Option<usize>,
        limit_lines: Option<usize>,
    ) -> Result<String, BackendError> {
        let local_path = self.normalize_local_path(path);
        let mut file = self
            .dir
            .open(local_path)
            .map_err(|e| BackendError::Io(e.to_string()))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| BackendError::Io(e.to_string()))?;

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
        let local_path = self.normalize_local_path(path);
        let mut file = self
            .dir
            .create(local_path)
            .map_err(|e| BackendError::Io(e.to_string()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| BackendError::Io(e.to_string()))?;

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

        Ok(EditReceipt {
            occurrences_replaced: occurrences,
        })
    }

    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError> {
        let local_path = self.normalize_local_path(path);
        self.dir
            .remove_file(local_path)
            .map_err(|e| BackendError::Io(e.to_string()))?;
        state.files.remove(path);
        Ok(())
    }

    fn glob(&self, _state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError> {
        let matcher = glob::Pattern::new(pattern)
            .map_err(|e| BackendError::InvalidOperation(e.to_string()))?;
        let mut matches = Vec::new();
        self.walk_dir(&mut matches, "", &matcher)?;
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
            self.walk_dir(&mut all_paths, "", &catch_all)?;
            all_paths
        };

        let mut grep_matches = Vec::new();
        for path in paths {
            if let Ok(content) = self.read_file(state, &path, None, None) {
                for (i, line) in content.lines().enumerate() {
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
        Ok(grep_matches)
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        Err(BackendError::CapabilityNotSupported)
    }
}
