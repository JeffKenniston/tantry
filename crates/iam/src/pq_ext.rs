use serde::{Deserialize, Serialize};
use blake3::Hasher;
use rcgen::{CertificateParams, CustomExtension};
use crate::error::IamError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PqExtensionPayload {
    pub subject_mldsa65_pk: Vec<u8>, // 1952 bytes
    pub issuer_mldsa65_sig: Vec<u8>, // 3309 bytes
    pub pre_tbs_blake3: [u8; 32],
}

pub fn compute_pre_tbs_pq_digest(
    serial_be: &[u8],
    issuer_dn: &[u8],
    subject_san_uri: &[u8],
    not_before_s_be64: [u8; 8],
    not_after_s_be64: [u8; 8],
    is_ca_u8: u8,
    ed25519_pk: &[u8; 32],
    mldsa65_pk: &[u8], // 1952 bytes
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"tantry:x509-pq-tbs:v3");
    hasher.update(serial_be);
    hasher.update(issuer_dn);
    hasher.update(subject_san_uri);
    hasher.update(&not_before_s_be64);
    hasher.update(&not_after_s_be64);
    hasher.update(&[is_ca_u8]);
    hasher.update(ed25519_pk);
    hasher.update(mldsa65_pk);
    *hasher.finalize().as_bytes()
}

pub fn attach_pq_extension(
    params: &mut CertificateParams,
    payload: &PqExtensionPayload,
) -> Result<(), IamError> {
    let encoded = rmp_serde::to_vec(payload)
        .map_err(|e| IamError::CertificateGenerationError(format!("Failed to encode PQ payload: {}", e)))?;

    let mut ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1, 204], encoded);
    ext.set_criticality(false);

    params.custom_extensions.push(ext);

    Ok(())
}
