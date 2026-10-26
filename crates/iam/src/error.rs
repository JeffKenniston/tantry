use thiserror::Error;

#[derive(Error, Debug)]
pub enum IamError {
    #[error("Invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    #[error("Hierarchy violation: child {child} cannot be derived from parent {parent}")]
    HierarchyViolation { parent: String, child: String },

    #[error("TTL escalation attempt detected")]
    TtlEscalation,

    #[error("Certificate generation error: {0}")]
    CertificateGenerationError(String),

    #[error("PQ signature verification failed")]
    PqSignatureVerificationFailed,

    #[error("Ed25519 signature verification failed")]
    Ed25519VerificationFailed,

    #[error("DPoP validation failed: {0}")]
    DpopValidationFailed(String),

    #[error("DPoP replay detected: {0}")]
    DpopReplayDetected(String),

    #[error("Master key unavailable")]
    MasterKeyUnavailable,

    #[error("Key epoch shredded for thread {thread_id} at epoch {epoch}")]
    KeyEpochShredded { thread_id: String, epoch: u32 },

    #[error("Tunnel grant expired or invalid: {0}")]
    TunnelGrantExpiredOrInvalid(String),

    #[error("SPIRE socket unavailable: {0}")]
    SpireSocketUnavailable(String),
}
