use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("Unknown provider profile key: {0}")]
    UnknownProvider(String),

    #[error("Invalid profile key '{0}': provider segment cannot be empty")]
    InvalidProfileKey(String),

    #[error("Context window tokens ({0}) must be >= 64")]
    InvalidBudgetWindow(usize),

    #[error("Failed to parse Sigstore bundle JSON: {0}")]
    SigstoreBundleParseError(String),

    #[error("Sigstore artifact digest mismatch: expected {expected}, got {actual}")]
    SigstoreDigestMismatch { expected: String, actual: String },

    #[error("Fulcio certificate or SAN verification failed: {0}")]
    SigstoreCertificateInvalid(String),

    #[error(
        "Rekor integrated_time {integrated_time} outside certificate validity [{not_before}, {not_after}]"
    )]
    SigstoreTimestampOutOfRange {
        integrated_time: i64,
        not_before: i64,
        not_after: i64,
    },

    #[error("RFC 6962 Rekor Merkle inclusion proof invalid: {0}")]
    SigstoreMerkleProofInvalid(String),

    #[error("Classical Ed25519 signature verification failed: {0}")]
    SigstoreSignatureInvalid(String),

    #[error("Post-quantum ML-DSA-65 signature required by policy but absent from bundle")]
    SigstoreMissingPqSignature,

    #[error("Post-quantum ML-DSA-65 signature verification failed: {0}")]
    SigstorePqSignatureInvalid(String),

    #[error(transparent)]
    Base(#[from] base::error::BaseError),

    #[error(transparent)]
    Iam(#[from] iam::IamError),
}
