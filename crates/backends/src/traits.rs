use crate::error::BackendError;
use base::path::PosixPath;
use base::state::TantryState;

/// BackendCapabilities struct
pub struct BackendCapabilities {
    /// supports_delete field
    pub supports_delete: bool,
    /// supports_execute field
    pub supports_execute: bool,
    /// is_persistent_host_fs field
    pub is_persistent_host_fs: bool,
}

/// DirEntryInfo struct
pub struct DirEntryInfo {
    /// name field
    pub name: String,
    /// is_dir field
    pub is_dir: bool,
    /// size field
    pub size: u64,
}

/// WriteReceipt struct
pub struct WriteReceipt {
    /// bytes_written field
    pub bytes_written: u64,
}

/// EditReceipt struct
pub struct EditReceipt {
    /// occurrences_replaced field
    pub occurrences_replaced: usize,
}

/// GrepMatch struct
pub struct GrepMatch {
    /// path field
    pub path: PosixPath,
    /// line_number field
    pub line_number: usize,
    /// content field
    pub content: String,
}

/// SandboxExecRequest struct
pub struct SandboxExecRequest {
    /// command field
    pub command: String,
    /// args field
    pub args: Vec<String>,
}

/// SandboxExecResult struct
pub struct SandboxExecResult {
    /// exit_code field
    pub exit_code: i32,
    /// stdout field
    pub stdout: String,
    /// stderr field
    pub stderr: String,
}

/// VfsBackend trait
pub trait VfsBackend: Send + Sync {
    /// capabilities method
    fn capabilities(&self) -> BackendCapabilities;
    /// ls method
    fn ls(&self, state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError>;
    /// read_file method
    fn read_file(
        &self,
        state: &TantryState,
        path: &str,
        offset_line: Option<usize>,
        limit_lines: Option<usize>,
    ) -> Result<String, BackendError>;
    /// write_file method
    fn write_file(
        &self,
        state: &mut TantryState,
        path: &str,
        content: &str,
    ) -> Result<WriteReceipt, BackendError>;
    /// edit_file method
    fn edit_file(
        &self,
        state: &mut TantryState,
        path: &str,
        old_string: &str,
        new_string: &str,
        replace_all: bool,
    ) -> Result<EditReceipt, BackendError>;
    /// delete method
    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError>;
    /// glob method
    fn glob(&self, state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError>;
    /// grep method
    fn grep(
        &self,
        state: &TantryState,
        pattern: &str,
        path_glob: Option<&str>,
    ) -> Result<Vec<GrepMatch>, BackendError>;
    /// execute method
    fn execute(&self, req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError>;
}
