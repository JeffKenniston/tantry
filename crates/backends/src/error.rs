use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
/// BackendError enum
pub enum BackendError {
    #[error("Old string not found")]
    OldStringNotFound,
    #[error("Occurrence mismatch: found {count}")]
    OccurrenceMismatch { count: usize },
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
}

impl From<std::io::Error> for BackendError {
    fn from(err: std::io::Error) -> Self {
        BackendError::Io(err.to_string())
    }
}
