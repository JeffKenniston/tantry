use thiserror::Error;

/// IamError enumerates all errors produced by the iam crate.
#[derive(Error, Debug)]
pub enum IamError {
    /// Indicates that the parsed SpiffeId is invalid.
    #[error("Invalid SpiffeId: {0}")]
    InvalidSpiffeId(String),

    /// Indicates that a requested subagent does not correctly descend from the parent SpiffeId.
    #[error("Hierarchy Violation: parent {parent}, child {child}")]
    HierarchyViolation {
        /// The parent SpiffeId URI.
        parent: String,
        /// The child SpiffeId URI.
        child: String,
    },

    /// Indicates an attempt to escalate a requested TTL beyond the parent's boundaries.
    #[error("TTL Escalation detected")]
    TtlEscalation,

    /// General certificate generation error.
    #[error("Certificate Generation Error: {0}")]
    CertificateGenerationError(String),

    /// Indicates ML-DSA-65 PQ Signature verification failed.
    #[error("PQ Signature Verification Failed")]
    PqSignatureVerificationFailed,

    /// Indicates Ed25519 outer signature verification failed.
    #[error("Ed25519 Verification Failed")]
    Ed25519VerificationFailed,

    /// Indicates RFC 9449 DPoP proof validation failed.
    #[error("DPoP Validation Failed: {0}")]
    DpopValidationFailed(String),

    /// Indicates a replayed DPoP token was detected.
    #[error("DPoP Replay Detected: {0}")]
    DpopReplayDetected(String),

    /// Indicates the root Master Key was unavailable.
    #[error("Master Key Unavailable")]
    MasterKeyUnavailable,

    /// Indicates the key epoch for a given thread has been completely zeroized/shredded.
    #[error("Key Epoch Shredded: thread {thread_id}, epoch {epoch}")]
    KeyEpochShredded {
        /// The shredded thread id.
        thread_id: String,
        /// The shredded epoch.
        epoch: u32,
    },

    /// Indicates a tunnel grant token was invalid or expired.
    #[error("Tunnel Grant Expired Or Invalid: {0}")]
    TunnelGrantExpiredOrInvalid(String),

    /// Indicates the SPIRE agent Unix socket could not be connected to.
    #[error("Spire Socket Unavailable: {0}")]
    SpireSocketUnavailable(String),

    /// Placeholder for unimplemented logic.
    #[error("Not implemented")]
    NotImplemented,
}
