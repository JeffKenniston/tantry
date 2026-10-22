use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

// A stub for SpiffeId which needs to exist. We'll use a string alias.
pub type SpiffeId = String;

#[derive(Clone, Debug)]
pub struct WorkloadSvid {
    pub spiffe_id: SpiffeId,
    pub cert_der_chain: Vec<Vec<u8>>,
    pub ed25519_pkcs8_der: Zeroizing<Vec<u8>>,
    pub ed25519_public_key: [u8; 32],
    pub mldsa65_signing_key_bytes: Zeroizing<Vec<u8>>,
    pub mldsa65_verifying_key_bytes: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
