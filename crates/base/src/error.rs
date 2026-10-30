use uuid::Uuid;

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
/// PathValidationError enum
pub enum PathValidationError {
    #[error("path is empty")]
    EmptyPath,
    #[error("path contains null byte or control character")]
    NullByteOrControlChar,
    #[error("path contains forbidden backslash")]
    BackslashForbidden,
    #[error("path contains traversal attempt ('.' or '..')")]
    TraversalAttempt,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
/// StateReducerError enum
pub enum StateReducerError {
    #[error("message ID not found: {0}")]
    MessageIdNotFound(Uuid),
    #[error("empty compaction range")]
    EmptyCompactionRange,
    #[error("invalid tool use patch: {0}")]
    InvalidToolUsePatch(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
/// ExtensionError enum
pub enum ExtensionError {
    #[error("unknown wire key: {0}")]
    UnknownWireKey(String),
    #[error("codec tag mismatch: expected {expected}, actual {actual}")]
    CodecTagMismatch { expected: u8, actual: u8 },
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
/// ConfigValidationError enum
pub enum ConfigValidationError {
    #[error("invalid trust domain: {0}")]
    InvalidTrustDomain(String),
    #[error("invalid similarity threshold: {0}")]
    InvalidSimilarityThreshold(f32),
    #[error("invalid budget ratios: soft={soft}, hard={hard}")]
    InvalidBudgetRatios { soft: f64, hard: f64 },
    #[error("invalid wasm memory bytes: {0}")]
    InvalidWasmMemoryBytes(usize),
    #[error("invalid model tier format: {0}")]
    InvalidModelTierFormat(String),
    #[error("invalid MCP protocol version: {0}")]
    InvalidMcpProtocolVersion(String),
    #[error("invalid socket address: {0}")]
    InvalidSocketAddr(String),
    #[error("path error: {0}")]
    PathError(#[from] PathValidationError),
    #[error("invalid TOML format: {0}")]
    InvalidToml(String),
    #[error("invalid cognitive provider: {0}")]
    InvalidCognitiveProvider(String),
    #[error("invalid semantic cache max entries: {0}")]
    InvalidSemanticCacheMaxEntries(usize),
    #[error("invalid webhook URL: {0}")]
    InvalidWebhookUrl(String),
    #[error("invalid webhook timeout ms: {0}")]
    InvalidWebhookTimeoutMs(u64),
    #[error("invalid isolation mode: {0}")]
    InvalidIsolationMode(String),
    #[error("invalid max workers: {0}")]
    InvalidMaxWorkers(usize),
    #[error("invalid wasm fuel budget: {0}")]
    InvalidWasmFuelBudget(u64),
    #[error("invalid wasm epoch tick ms: {0}")]
    InvalidWasmEpochTickMs(u64),
    #[error("invalid wasm wall clock timeout ms: {0}")]
    InvalidWasmWallClockTimeoutMs(u64),
    #[error("invalid zenoh listen endpoints")]
    InvalidZenohListenEndpoints,
    #[error("invalid quic handshake fallback timeout ms: {0}")]
    InvalidQuicHandshakeFallbackTimeoutMs(u64),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
/// BaseError enum
pub enum BaseError {
    #[error("path validation error: {0}")]
    Path(#[from] PathValidationError),
    #[error("state reducer error: {0}")]
    StateReducer(#[from] StateReducerError),
    #[error("extension error: {0}")]
    Extension(#[from] ExtensionError),
    #[error("config validation error: {0}")]
    Config(#[from] ConfigValidationError),
}
