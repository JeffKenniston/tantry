use crate::traits::{BackendCapabilities, DirEntryInfo, EditReceipt, GrepMatch, SandboxExecRequest, SandboxExecResult, VfsBackend, WriteReceipt};
use crate::error::BackendError;
use base::state::TantryState;
use base::path::PosixPath;
use std::collections::BTreeMap;
use std::sync::Arc;

/// CompositeBackend struct
pub struct CompositeBackend {
    /// mounts field
    pub mounts: BTreeMap<String, Arc<dyn VfsBackend>>,
}

impl CompositeBackend {
    /// new method
    pub fn new() -> Self {
        Self { mounts: BTreeMap::new() }
    }

    /// mount method
    pub fn mount(&mut self, prefix: String, backend: Arc<dyn VfsBackend>) {
        self.mounts.insert(prefix, backend);
    }

    fn get_backend<'a>(&'a self, path: &str) -> Result<(&'a Arc<dyn VfsBackend>, String), BackendError> {
        let normalized = base::path::validate_and_normalize_path(path).map_err(|e| BackendError::Path(e.to_string()))?;

        // Find longest matching prefix
        let mut best_match = "";
        let mut best_backend = None;

        for (prefix, backend) in self.mounts.iter() {
            if normalized.starts_with(prefix) && prefix.len() >= best_match.len() {
                // Ensure it matches a full segment, not just a string prefix
                if prefix == "/" || prefix == &normalized || normalized[prefix.len()..].starts_with('/') {
                    best_match = prefix;
                    best_backend = Some(backend);
                }
            }
        }

        if let Some(backend) = best_backend {
            let remaining = if best_match == "/" {
                normalized.clone()
            } else {
                normalized[best_match.len()..].to_string()
            };
            let remaining = if remaining.is_empty() { "/".to_string() } else { remaining };
            Ok((backend, remaining))
        } else {
            Err(BackendError::Path(format!("No backend mounted for path: {}", path)))
        }
    }
}

impl Default for CompositeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsBackend for CompositeBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_delete: true,
            supports_execute: true,
            is_persistent_host_fs: true,
        }
    }

    fn ls(&self, state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError> {
        let (backend, rel_path) = self.get_backend(path)?;
        backend.ls(state, &rel_path)
    }

    fn read_file(&self, state: &TantryState, path: &str, offset_line: Option<usize>, limit_lines: Option<usize>) -> Result<String, BackendError> {
        let (backend, rel_path) = self.get_backend(path)?;
        backend.read_file(state, &rel_path, offset_line, limit_lines)
    }

    fn write_file(&self, state: &mut TantryState, path: &str, content: &str) -> Result<WriteReceipt, BackendError> {
        let (backend, rel_path) = self.get_backend(path)?;
        backend.write_file(state, &rel_path, content)
    }

    fn edit_file(&self, state: &mut TantryState, path: &str, old_string: &str, new_string: &str, replace_all: bool) -> Result<EditReceipt, BackendError> {
        let (backend, rel_path) = self.get_backend(path)?;
        backend.edit_file(state, &rel_path, old_string, new_string, replace_all)
    }

    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError> {
        let (backend, rel_path) = self.get_backend(path)?;
        backend.delete(state, &rel_path)
    }

    fn glob(&self, state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError> {
        let mut results = Vec::new();

        let normalized_pattern = base::path::validate_and_normalize_path(pattern).unwrap_or(pattern.to_string());
        let matcher = glob::Pattern::new(pattern).ok();

        for (prefix, backend) in &self.mounts {
            let mut pattern_for_backend = pattern.to_string();

            if prefix != "/" {
                if normalized_pattern.starts_with(prefix) {
                    let mut stripped = normalized_pattern[prefix.len()..].to_string();
                    if stripped.is_empty() {
                        stripped = "/".to_string();
                    } else if !stripped.starts_with('/') {
                        stripped = format!("/{}", stripped);
                    }
                    pattern_for_backend = stripped;
                } else if normalized_pattern.contains('*') || normalized_pattern.contains('?') {
                     pattern_for_backend = "**/*".to_string(); // Incomplete implementation for cross boundary globs
                } else {
                    continue; // Path doesn't match this prefix
                }
            }

            if let Ok(backend_matches) = backend.glob(state, &pattern_for_backend) {
                for mut match_path in backend_matches {
                    if prefix != "/" {
                        let formatted_path = if match_path.starts_with('/') {
                            match_path.clone()
                        } else {
                            format!("/{}", match_path)
                        };
                        match_path = format!("{}{}", prefix, formatted_path);
                    }

                    if let Some(ref m) = matcher {
                       if m.matches(&match_path) {
                          results.push(match_path);
                       }
                    } else {
                        results.push(match_path);
                    }
                }
            }
        }
        Ok(results)
    }

    fn grep(&self, state: &TantryState, pattern: &str, path_glob: Option<&str>) -> Result<Vec<GrepMatch>, BackendError> {
        let mut results = Vec::new();

        let normalized_pattern = path_glob.map(|p| base::path::validate_and_normalize_path(p).unwrap_or(p.to_string()));
        let matcher = path_glob.and_then(|p| glob::Pattern::new(p).ok());

        for (prefix, backend) in &self.mounts {
            let mut pattern_for_backend = None;

            if let Some(ref np) = normalized_pattern {
                if prefix != "/" {
                    if np.starts_with(prefix) {
                        let mut stripped = np[prefix.len()..].to_string();
                        if stripped.is_empty() {
                            stripped = "/".to_string();
                        } else if !stripped.starts_with('/') {
                            stripped = format!("/{}", stripped);
                        }
                        pattern_for_backend = Some(stripped);
                    } else if np.contains('*') || np.contains('?') {
                         pattern_for_backend = Some("**/*".to_string());
                    } else {
                        continue;
                    }
                } else {
                    pattern_for_backend = Some(np.clone());
                }
            }

            let backend_glob_ref = pattern_for_backend.as_deref();

            if let Ok(backend_matches) = backend.grep(state, pattern, backend_glob_ref) {
                for mut grep_match in backend_matches {
                    if prefix != "/" {
                        let formatted_path = if grep_match.path.starts_with('/') {
                            grep_match.path.clone()
                        } else {
                            format!("/{}", grep_match.path)
                        };
                        grep_match.path = format!("{}{}", prefix, formatted_path);
                    }

                    if let Some(ref m) = matcher {
                        if m.matches(&grep_match.path) {
                            results.push(grep_match);
                        }
                    } else {
                        results.push(grep_match);
                    }
                }
            }
        }
        Ok(results)
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        // Would typically route to a specific backend that supports execution
        Err(BackendError::CapabilityNotSupported)
    }
}
