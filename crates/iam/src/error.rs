use thiserror::Error;

#[derive(Error, Debug)]
pub enum IamError {
    #[error("Invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),
    #[error("Hierarchy violation: {parent} cannot spawn {child}")]
    HierarchyViolation { parent: String, child: String },
    #[error("TTL escalation")]
    TtlEscalation,
    #[error("Certificate generation error: {0}")]
    CertificateGenerationError(String),
    #[error("PQ signature verification failed")]
    PqSignatureVerificationFailed,
    #[error("Ed25519 verification failed")]
    Ed25519VerificationFailed,
    #[error("DPoP validation failed: {0}")]
    DpopValidationFailed(String),
    #[error("DPoP replay detected: {0}")]
    DpopReplayDetected(String),
    #[error("Master key unavailable")]
    MasterKeyUnavailable,
    #[error("Key epoch shredded: thread {thread_id}, epoch {epoch}")]
    KeyEpochShredded { thread_id: String, epoch: u32 },
    #[error("Tunnel grant expired or invalid: {0}")]
    TunnelGrantExpiredOrInvalid(String),
    #[error("SPIRE socket unavailable: {0}")]
    SpireSocketUnavailable(String),
    #[error("Not implemented")]
    NotImplemented,
}
