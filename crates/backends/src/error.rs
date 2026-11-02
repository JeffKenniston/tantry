use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq)]
/// BackendError enum
pub enum BackendError {
    #[error("Old string not found in {path}")]
    OldStringNotFound { path: base::path::PosixPath },
    #[error("Occurrence mismatch in {path}: found {count}")]
    OccurrenceMismatch { path: base::path::PosixPath, count: usize },
    #[error("IO error: {0}")]
    Io(String),
    #[error("Path error: {0}")]
    Path(String),
    #[error("Capability not supported")]
    CapabilityNotSupported,
    #[error("Execution error: {0}")]
    Execution(String),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Unsafe WASM Start Section")]
    UnsafeWasmStartSection,
    #[error("Capability escape blocked: {path} - {reason}")]
    CapabilityEscapeBlocked { path: base::path::PosixPath, reason: String },
}

impl From<std::io::Error> for BackendError {
    fn from(err: std::io::Error) -> Self {
        BackendError::Io(err.to_string())
    }
}
