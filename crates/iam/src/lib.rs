pub mod error;
pub mod key_hierarchy;

pub struct AuditSthSignature {
    pub tree_size: u64,
    pub timestamp_ms: i64,
    pub mmr_root_blake3: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    pub mldsa65_sig: Vec<u8>,
}

pub trait IdentityManager: Send + Sync {
    fn key_hierarchy(&self) -> &key_hierarchy::KeyHierarchy;
    fn sign_audit_sth(&self, tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> Result<AuditSthSignature, error::IamError>;
    fn verify_audit_sth(&self, sth: &AuditSthSignature) -> Result<(), error::IamError>;
}
