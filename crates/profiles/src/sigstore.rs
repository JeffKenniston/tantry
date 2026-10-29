use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash_hex: String,
    pub hashes_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorTransparencyLogEntry {
    pub integrated_time: i64,
    pub canonicalized_body_b64: String,
    pub inclusion_proof: RekorInclusionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulcioCertificateDescriptor {
    pub leaf_cert_der_b64: Option<String>,
    pub subject_public_key_ed25519_hex: String,
    pub issuer_signature_ed25519_hex: String,
    pub oidc_issuer: String,
    pub san_uri: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    pub media_type: String,
    pub artifact_blake3_hex: String,
    pub artifact_sha256_hex: String,
    pub signature_ed25519_hex: String,
    pub fulcio_cert: FulcioCertificateDescriptor,
    pub rekor_entry: RekorTransparencyLogEntry,
    pub pq_public_key_mldsa65_b64: Option<String>,
    pub pq_signature_mldsa65_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigstoreVerificationReport {
    pub artifact_blake3: [u8; 32],
    pub artifact_sha256: [u8; 32],
    pub oidc_issuer: String,
    pub san_uri: String,
    pub rekor_log_index: u64,
    pub integrated_time: i64,
    pub pq_verified: bool,
}

pub fn build_fulcio_leaf_transcript(
    subject_public_key_ed25519_bytes: &[u8; 32],
    oidc_issuer: &str,
    san_uri: &str,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"tantry:fulcio:leaf:v3:");
    transcript.extend_from_slice(subject_public_key_ed25519_bytes);
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(oidc_issuer.as_bytes());
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(san_uri.as_bytes());
    transcript.extend_from_slice(b":");
    transcript.extend_from_slice(&not_before.to_be_bytes());
    transcript.extend_from_slice(&not_after.to_be_bytes());
    transcript
}

pub fn build_hybrid_pq_signing_transcript(
    artifact_blake3_32: &[u8; 32],
    artifact_sha256_32: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"tantry:sigstore:pq:v3:");
    transcript.extend_from_slice(artifact_blake3_32);
    transcript.extend_from_slice(artifact_sha256_32);
    transcript
}
