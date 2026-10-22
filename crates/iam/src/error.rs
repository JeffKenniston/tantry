use thiserror::Error;

#[derive(Error, Debug)]
pub enum IamError {
    #[error("Invalid SpiffeId: {0}")]
    InvalidSpiffeId(String),
    #[error("Hierarchy Violation: parent {parent}, child {child}")]
    HierarchyViolation { parent: String, child: String },
    #[error("TTL Escalation detected")]
    TtlEscalation,
    #[error("Certificate Generation Error: {0}")]
    CertificateGenerationError(String),
    #[error("PQ Signature Verification Failed")]
    PqSignatureVerificationFailed,
    #[error("Ed25519 Verification Failed")]
    Ed25519VerificationFailed,
    #[error("DPoP Validation Failed: {0}")]
    DpopValidationFailed(String),
    #[error("DPoP Replay Detected: {0}")]
    DpopReplayDetected(String),
    #[error("Master Key Unavailable")]
    MasterKeyUnavailable,
    #[error("Key Epoch Shredded: thread {thread_id}, epoch {epoch}")]
    KeyEpochShredded { thread_id: String, epoch: u32 },
    #[error("Tunnel Grant Expired Or Invalid: {0}")]
    TunnelGrantExpiredOrInvalid(String),
    #[error("Spire Socket Unavailable: {0}")]
    SpireSocketUnavailable(String),
}
