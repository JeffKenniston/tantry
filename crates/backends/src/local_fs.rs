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
                            matches.push(base::path::validate_and_normalize_path(&final_path).unwrap_or_else(|_| PosixPath::default()));
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

    fn map_io_error(err: std::io::Error, path: &str) -> BackendError {
        let raw = err.raw_os_error();
        let msg = err.to_string();
        if raw == Some(nix::libc::ELOOP) || raw == Some(nix::libc::EXDEV) || raw == Some(nix::libc::EACCES) || raw == Some(nix::libc::EPERM) || msg.contains("symlink") || msg.contains("escape") {
            let norm_path = base::path::validate_and_normalize_path(path).unwrap_or_else(|_| PosixPath::default());
            BackendError::CapabilityEscapeBlocked { path: norm_path, reason: msg }
        } else {
            BackendError::Io(msg)
        }
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
                .map_err(|e| Self::map_io_error(e, path))?
        } else {
            self.dir
                .read_dir(local_path)
                .map_err(|e| Self::map_io_error(e, path))?
        };

        for entry in dir_entries {
            let entry = entry.map_err(|e| Self::map_io_error(e, path))?;
            let metadata = entry
                .metadata()
                .map_err(|e| Self::map_io_error(e, path))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let path_str = if local_path.is_empty() { name.clone() } else { format!("{}/{}", local_path, name) };
            let posix_path = base::path::validate_and_normalize_path(&path_str).unwrap_or_else(|_| PosixPath::default());
            entries.push(DirEntryInfo {
                path: posix_path,
                name,
                is_dir: metadata.is_dir(),
                size_bytes: metadata.len(),
                blake3_hash: None,
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
            .map_err(|e| Self::map_io_error(e, path))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| Self::map_io_error(e, path))?;

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
            .map_err(|e| Self::map_io_error(e, path))?;
        file.write_all(content.as_bytes())
            .map_err(|e| Self::map_io_error(e, path))?;

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
        let content = self.read_file(state, path, None, None)?;

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
        let local_path = self.normalize_local_path(path);
        self.dir
            .remove_file(local_path)
            .map_err(|e| Self::map_io_error(e, path))?;
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
            if let Ok(content) = self.read_file(state, &path.to_string(), None, None) {
                for (i, line) in content.lines().enumerate() {
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
        Ok(grep_matches)
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        Err(BackendError::CapabilityNotSupported)
    }
}
