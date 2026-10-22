use thiserror::Error;

#[derive(Error, Debug)]
pub enum IamError {
    #[error("Key epoch shredded: thread_id={thread_id}, epoch={epoch}")]
    KeyEpochShredded { thread_id: String, epoch: u32 },
    #[error("Not implemented")]
    NotImplemented,
    #[error("Master key unavailable")]
    MasterKeyUnavailable,
    #[error("Certificate generation error: {0}")]
    CertificateGenerationError(String),
    #[error("Ed25519 verification failed")]
    Ed25519VerificationFailed,
    #[error("PQ signature verification failed")]
    PqSignatureVerificationFailed,
    #[error("SPIRE socket unavailable: {0}")]
    SpireSocketUnavailable(String),
}
