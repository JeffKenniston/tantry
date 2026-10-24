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

    fn glob(&self, _state: &TantryState, _pattern: &str) -> Result<Vec<PosixPath>, BackendError> {
        // Correct implementation would query across backends or specific backend
        Ok(vec![])
    }

    fn grep(&self, _state: &TantryState, _pattern: &str, _path_glob: Option<&str>) -> Result<Vec<GrepMatch>, BackendError> {
        Ok(vec![])
    }

    fn execute(&self, _req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError> {
        // Would typically route to a specific backend that supports execution
        Err(BackendError::CapabilityNotSupported)
    }
}
