use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PathValidationError {
    #[error("Path cannot be empty")]
    EmptyPath,
    #[error("Path contains null bytes or ASCII control characters")]
    NullByteOrControlChar,
    #[error("Path contains forbidden backslash characters")]
    BackslashForbidden,
    #[error("Path contains directory traversal attempt ('.' or '..')")]
    TraversalAttempt,
}

#[derive(Debug, Error)]
pub enum StateReducerError {
    #[error("Message ID not found: {0}")]
    MessageIdNotFound(Uuid),
    #[error("Compaction range is empty")]
    EmptyCompactionRange,
    #[error("Invalid tool use patch: {0}")]
    InvalidToolUsePatch(String),
}

#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error("Unknown wire key: {0}")]
    UnknownWireKey(String),
    #[error("Codec tag mismatch: expected {expected}, actual {actual}")]
    CodecTagMismatch { expected: u8, actual: u8 },
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}

#[derive(Debug, Error)]
pub enum ConfigValidationError {
    #[error("Invalid trust domain: {0}")]
    InvalidTrustDomain(String),
    #[error("Similarity threshold out of range (must be 0.0 to 1.0)")]
    InvalidSimilarityThreshold,
    #[error("Budget ratio out of range")]
    InvalidBudgetRatio,
    #[error("Invalid WASM memory configuration")]
    InvalidWasmMemory,
    #[error("Invalid model tier format")]
    InvalidModelTierFormat,
    #[error("Invalid MCP protocol version: {0}")]
    InvalidMcpProtocolVersion(String),
    #[error("Invalid socket address: {0}")]
    InvalidSocketAddress(String),
    #[error("Path validation error: {0}")]
    PathError(#[from] PathValidationError),
}

#[derive(Debug, Error)]
pub enum BaseError {
    #[error(transparent)]
    Path(#[from] PathValidationError),
    #[error(transparent)]
    StateReducer(#[from] StateReducerError),
    #[error(transparent)]
    Extension(#[from] ExtensionError),
    #[error(transparent)]
    Config(#[from] ConfigValidationError),
}
