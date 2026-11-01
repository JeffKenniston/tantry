use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataError {
    #[error(transparent)]
    Base(#[from] base::error::BaseError),
    #[error(transparent)]
    Iam(#[from] iam::error::IamError),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("AEAD encryption failed")]
    AeadEncryptionFailed,
    #[error("AEAD decryption failed: {context}")]
    AeadDecryptionFailed { context: String },
    #[error("Key epoch shredded: thread_id={thread_id}, epoch={epoch}")]
    KeyEpochShredded { thread_id: String, epoch: u32 },
    #[error("Checkpoint not found: {0}")]
    CheckpointNotFound(String),
    #[error("Thread head not found: {0}")]
    ThreadHeadNotFound(String),
    #[error("Corrupted audit chain: seq_no={seq_no}, reason={reason}")]
    CorruptedAuditChain { seq_no: u64, reason: String },
    #[error("Corrupted MMR peak: seq_no={seq_no}")]
    CorruptedMmrPeak { seq_no: u64 },
    #[error("Invalid audit STH signature for tree_size={tree_size}")]
    InvalidAuditSthSignature { tree_size: u64 },
    #[error("Budget exhausted: task_id={task_id}, requested_micros={requested_micros}, remaining_micros={remaining_micros}")]
    BudgetExhausted { task_id: String, requested_micros: u64, remaining_micros: u64 },
    #[error("Lease not found: {0}")]
    LeaseNotFound(String),
    #[error("Vector dimension mismatch: expected={expected}, actual={actual}")]
    VectorDimensionMismatch { expected: usize, actual: usize },
}
