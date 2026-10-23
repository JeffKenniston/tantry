use thiserror::Error;

#[derive(Error, Debug)]
/// Standard error enumeration for all persistence, cryptographic, and serialization failures in the data crate.
pub enum DataError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("AEAD error: {0}")]
    AeadError(String),
    #[error("AAD Mismatch")]
    AadMismatch,
    #[error("Zstd error: {0}")]
    ZstdError(String),
    #[error("Crypto shredded: {0}")]
    CryptoShredded(String),
    #[error("Checkpoint not found: {0}")]
    CheckpointNotFound(String),
    #[error("Tampered audit entry: {0}")]
    TamperedAuditEntry(u64),
    #[error("MMR proof invalid")]
    MmrProofInvalid,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Budget exhausted: {0}")]
    BudgetExhausted(String),
}
