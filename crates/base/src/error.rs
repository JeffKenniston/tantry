use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug, PartialEq)]
pub enum PathValidationError {
    #[error("Path cannot be empty")]
    EmptyPath,
    #[error("Path contains null byte or control character")]
    NullByteOrControlChar,
    #[error("Path cannot contain backslashes")]
    BackslashForbidden,
    #[error("Path traversal attempt ('.' or '..')")]
    TraversalAttempt,
}

#[derive(Error, Debug)]
pub enum StateReducerError {
    #[error("Message ID not found: {0}")]
    MessageIdNotFound(Uuid),
    #[error("Compaction range is empty")]
    EmptyCompactionRange,
    #[error("Invalid tool use patch: {0}")]
    InvalidToolUsePatch(String),
}

#[derive(Error, Debug)]
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

#[derive(Error, Debug)]
pub enum ConfigValidationError {
    #[error("Invalid trust domain: {0}")]
    InvalidTrustDomain(String),
    #[error("Invalid similarity threshold: {0}")]
    InvalidSimilarityThreshold(f32),
    #[error("Invalid budget ratios: soft={soft}, hard={hard}")]
    InvalidBudgetRatios { soft: f64, hard: f64 },
    #[error("Invalid WASM memory bytes: {0}")]
    InvalidWasmMemoryBytes(usize),
    #[error("Invalid model tier format: {0}")]
    InvalidModelTierFormat(String),
    #[error("Invalid MCP protocol version: {0}")]
    InvalidMcpProtocolVersion(String),
    #[error("Invalid socket address: {0}")]
    InvalidSocketAddr(String),
    #[error(transparent)]
    PathError(#[from] PathValidationError),
}

#[derive(Error, Debug)]
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
