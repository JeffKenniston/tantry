use crate::error::BackendError;
use base::path::PosixPath;
use base::state::TantryState;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    pub supports_delete: bool,
    pub supports_execute: bool,
    pub is_persistent_host_fs: bool,
}

#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub path: PosixPath,
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub blake3_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct WriteReceipt {
    pub path: PosixPath,
    pub bytes_written: usize,
    pub new_blake3_hash: [u8; 32],
    pub cst_diagnostics: Vec<repo::CstDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct EditReceipt {
    pub path: PosixPath,
    pub replacements_made: usize,
    pub new_blake3_hash: [u8; 32],
    pub cst_diagnostics: Vec<repo::CstDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct GrepMatch {
    pub path: PosixPath,
    pub line_number: usize,
    pub line_text: String,
}

#[derive(Debug, Clone)]
pub struct SandboxExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PosixPath,
    pub env_overrides: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub svid: Option<iam::spiffe::SpiffeId>,
}

#[derive(Debug, Clone)]
pub struct SandboxExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub isolation_tier: String,
}

pub trait VfsBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    fn ls(&self, state: &TantryState, path: &str) -> Result<Vec<DirEntryInfo>, BackendError>;
    fn read_file(
        &self,
        state: &TantryState,
        path: &str,
        offset_line: Option<usize>,
        limit_lines: Option<usize>,
    ) -> Result<String, BackendError>;
    fn write_file(
        &self,
        state: &mut TantryState,
        path: &str,
        content: &str,
    ) -> Result<WriteReceipt, BackendError>;
    fn edit_file(
        &self,
        state: &mut TantryState,
        path: &str,
        old_string: &str,
        new_string: &str,
        replace_all: bool,
    ) -> Result<EditReceipt, BackendError>;
    fn delete(&self, state: &mut TantryState, path: &str) -> Result<(), BackendError>;
    fn glob(&self, state: &TantryState, pattern: &str) -> Result<Vec<PosixPath>, BackendError>;
    fn grep(
        &self,
        state: &TantryState,
        pattern: &str,
        path_glob: Option<&str>,
    ) -> Result<Vec<GrepMatch>, BackendError>;
    fn execute(&self, req: SandboxExecRequest) -> Result<SandboxExecResult, BackendError>;
}
