use crate::error::IamError;
use rcgen::CustomExtension;
use serde::{Deserialize, Serialize};

pub const PQ_MDSA65_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 204];

#[derive(Serialize, Deserialize)]
pub struct PqExtensionPayload {
    pub subject_mldsa65_pk: Vec<u8>,
    pub issuer_mldsa65_sig: Vec<u8>,
    pub pre_tbs_blake3: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn compute_pre_tbs_pq_digest(
    serial_be: &[u8],
    issuer_dn: &str,
    subject_san_uri: &str,
    not_before_s: i64,
    not_after_s: i64,
    is_ca: bool,
    subject_ed25519_pk: &[u8; 32],
    subject_mldsa65_pk: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tantry:x509-pq-tbs:v3");
    hasher.update(serial_be);
    hasher.update(issuer_dn.as_bytes());
    hasher.update(subject_san_uri.as_bytes());
    hasher.update(&not_before_s.to_be_bytes());
    hasher.update(&not_after_s.to_be_bytes());
    hasher.update(&[u8::from(is_ca)]);
    hasher.update(subject_ed25519_pk);
    hasher.update(subject_mldsa65_pk);
    hasher.finalize().into()
}

pub fn build_pq_custom_extension(
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

    let mut ext = CustomExtension::from_oid_content(PQ_MDSA65_EXT_OID, encoded_payload);
    ext.set_criticality(false);
    Ok(ext)
}

pub fn verify_pq_custom_extension(
    encoded_payload: &[u8],
    expected_pre_tbs_digest: &[u8; 32],
    issuer_mldsa65_pk: &[u8],
) -> Result<PqExtensionPayload, IamError> {
    use ml_dsa::MlDsa65;
    use ml_dsa::signature::Verifier;

    let payload: PqExtensionPayload = rmp_serde::from_slice(encoded_payload).map_err(|_| {
        IamError::PqSignatureVerificationFailed
    })?;

    if payload.subject_mldsa65_pk.len() != 1952 {
        return Err(IamError::PqSignatureVerificationFailed);
    }

    if payload.issuer_mldsa65_sig.len() != 3309 {
        return Err(IamError::PqSignatureVerificationFailed);
    }

    if payload.pre_tbs_blake3 != *expected_pre_tbs_digest {
        return Err(IamError::PqSignatureVerificationFailed);
    }

    let mut pk_arr = [0u8; 1952];
    if issuer_mldsa65_pk.len() != 1952 {
        return Err(IamError::PqSignatureVerificationFailed);
    }
    pk_arr.copy_from_slice(issuer_mldsa65_pk);
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode((&pk_arr).into());

    let mut sig_arr = [0u8; 3309];
    sig_arr.copy_from_slice(&payload.issuer_mldsa65_sig);
    let sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_arr).into()).ok_or(IamError::PqSignatureVerificationFailed)?;

    vk.verify(expected_pre_tbs_digest, &sig).map_err(|_| IamError::PqSignatureVerificationFailed)?;

    Ok(payload)
}
