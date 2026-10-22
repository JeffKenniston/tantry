use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PathValidationError {
    #[error("Path is empty")]
    EmptyPath,
    #[error("Path contains null byte or control character")]
    NullByteOrControlChar,
    #[error("Path contains forbidden backslash")]
    BackslashForbidden,
    #[error("Path attempts directory traversal")]
    TraversalAttempt,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StateReducerError {
    #[error("Message ID not found: {0}")]
    MessageIdNotFound(Uuid),
    #[error("Empty compaction range")]
    EmptyCompactionRange,
    #[error("Invalid tool use patch: {0}")]
    InvalidToolUsePatch(String),
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
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

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ConfigValidationError {
    #[error("Invalid trust domain: {0}")]
    InvalidTrustDomain(String),
    #[error("Invalid similarity threshold: {0}")]
    InvalidSimilarityThreshold(f32),
    #[error("Invalid budget ratios: soft {soft}, hard {hard}")]
    InvalidBudgetRatios { soft: f64, hard: f64 },
    #[error("Invalid WASM memory bytes: {0}")]
    InvalidWasmMemoryBytes(usize),
    #[error("Invalid model tier format: {0}")]
    InvalidModelTierFormat(String),
    #[error("Invalid MCP protocol version: {0}")]
    InvalidMcpProtocolVersion(String),
    #[error("Invalid socket address: {0}")]
    InvalidSocketAddr(String),
    #[error("Path validation error: {0}")]
    PathError(#[from] PathValidationError),
    #[error("Invalid provider: {0}")]
    InvalidProvider(String),
    #[error("Invalid semantic cache entries: {0}")]
    InvalidSemanticCacheEntries(usize),
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Invalid webhook timeout: {0}")]
    InvalidWebhookTimeout(u64),
    #[error("Invalid sandbox mode: {0}")]
    InvalidSandboxMode(String),
    #[error("Invalid worker count: {0}")]
    InvalidWorkerCount(usize),
    #[error("Invalid WASM budget: {0}")]
    InvalidWasmBudget(u64),
    #[error("Invalid epoch tick: {0}")]
    InvalidEpochTick(u64),
    #[error("Invalid wall clock timeout: {0}")]
    InvalidWallClockTimeout(u64),
    #[error("Invalid endpoints")]
    InvalidEndpoints,
    #[error("Invalid QUIC timeout: {0}")]
    InvalidQuicTimeout(u64),
}

#[derive(Error, Debug)]
pub enum BaseError {
    #[error("Path validation error: {0}")]
    Path(#[from] PathValidationError),
    #[error("State reducer error: {0}")]
    StateReducer(#[from] StateReducerError),
    #[error("Extension error: {0}")]
    Extension(#[from] ExtensionError),
    #[error("Config validation error: {0}")]
    Config(#[from] ConfigValidationError),
}
