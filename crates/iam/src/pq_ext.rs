use crate::error::IamError;
use rcgen::CustomExtension;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PqExtensionPayload {
    pub subject_mldsa65_pk: Vec<u8>,
    pub issuer_mldsa65_sig: Vec<u8>,
    pub pre_tbs_blake3: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn compute_pre_tbs_pq_digest(
    serial_be: &[u8],
    issuer_dn: &[u8],
    subject_san_uri: &[u8],
    not_before_s_be64: &[u8; 8],
    not_after_s_be64: &[u8; 8],
    is_ca_u8: u8,
    ed25519_pk: &[u8; 32],
    mldsa65_pk: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:x509-pq-tbs:v3");
    hasher.update(serial_be);
    hasher.update(issuer_dn);
    hasher.update(subject_san_uri);
    hasher.update(not_before_s_be64);
    hasher.update(not_after_s_be64);
    hasher.update(&[is_ca_u8]);
    hasher.update(ed25519_pk);
    hasher.update(mldsa65_pk);
    hasher.finalize().into()
}

pub fn generate_pq_extension(
    subject_mldsa65_pk: Vec<u8>,
    issuer_mldsa65_signing_key_bytes: &[u8],
    digest: [u8; 32],
) -> Result<CustomExtension, IamError> {
    use ml_dsa::MlDsa65;
    use ml_dsa::SignatureEncoding;
    use ml_dsa::pkcs8::DecodePrivateKey;
    use ml_dsa::signature::Signer as _;

    let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(issuer_mldsa65_signing_key_bytes)
        .map_err(|_| {
            IamError::CertificateGenerationError("Invalid ML-DSA-65 secret key".to_string())
        })?;

    let sig = ml_sk.sign(&digest).to_bytes().to_vec();

    let payload = PqExtensionPayload {
        subject_mldsa65_pk,
        issuer_mldsa65_sig: sig,
        pre_tbs_blake3: digest,
    };

    let encoded_payload = rmp_serde::to_vec(&payload).map_err(|e| {
        IamError::CertificateGenerationError(format!("Failed to encode payload: {}", e))
    })?;

    let oid = vec![1, 3, 6, 1, 4, 1, 99999, 1, 204];

    let mut ext = CustomExtension::from_oid_content(&oid, encoded_payload);
    ext.set_criticality(false);
    Ok(ext)
}
