use crate::error::IamError;
use blake3::Hasher;
use ml_dsa::MlDsa65;
use ml_dsa::signature::{Signer, Verifier};
use ed25519_dalek::{VerifyingKey, Signature as EdSignature};
use pkcs8::DecodePrivateKey;
use crate::svid::WorkloadSvid;
use std::convert::TryInto;
use ml_dsa::SignatureEncoding;

pub struct AuditSthSignature {
    pub tree_size: u64,
    pub timestamp_ms: i64,
    pub mmr_root_blake3: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    pub mldsa65_sig: Vec<u8>,
}

pub fn calculate_sth_digest(tree_size: u64, timestamp_ms: i64, mmr_root_blake3: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"tantry:audit:sth:v3");
    hasher.update(&tree_size.to_be_bytes());
    hasher.update(&timestamp_ms.to_be_bytes());
    hasher.update(mmr_root_blake3);
    *hasher.finalize().as_bytes()
}

pub fn sign_audit_sth(
    svid: &WorkloadSvid,
    tree_size: u64,
    timestamp_ms: i64,
    mmr_root_blake3: &[u8; 32]
) -> Result<AuditSthSignature, IamError> {
    let digest = calculate_sth_digest(tree_size, timestamp_ms, mmr_root_blake3);

    let ed25519_sk = ed25519_dalek::SigningKey::from_pkcs8_der(&svid.ed25519_pkcs8_der)
        .map_err(|_| IamError::CertificateGenerationError("Invalid Ed25519 PKCS8 key".to_string()))?;

    let ed_sig = ed25519_sk.sign(&digest).to_bytes().to_vec();

    let mldsa_signing_key_array: [u8; 4032] = svid.mldsa65_signing_key_bytes[..]
        .try_into()
        .map_err(|_| IamError::CertificateGenerationError("Invalid ML-DSA-65 signing key length".to_string()))?;

    let enc = ml_dsa::ExpandedSigningKeyBytes::<MlDsa65>::from(mldsa_signing_key_array);
    #[allow(deprecated)]
    let mldsa_signing_key = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(&enc);
    let pq_sig = mldsa_signing_key.sign(&digest).to_vec();

    Ok(AuditSthSignature {
        tree_size,
        timestamp_ms,
        mmr_root_blake3: *mmr_root_blake3,
        ed25519_sig: ed_sig,
        mldsa65_sig: pq_sig,
    })
}

pub fn verify_audit_sth(
    sth: &AuditSthSignature,
    ed25519_pk: &[u8; 32],
    mldsa65_pk: &[u8],
) -> Result<(), IamError> {
    let digest = calculate_sth_digest(sth.tree_size, sth.timestamp_ms, &sth.mmr_root_blake3);

    let ed_sig = EdSignature::from_slice(&sth.ed25519_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let vk = VerifyingKey::from_bytes(ed25519_pk)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    vk.verify(&digest, &ed_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    let mldsa_pk_array: [u8; 1952] = mldsa65_pk
        .try_into()
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;
    let enc: ml_dsa::EncodedVerifyingKey<MlDsa65> = mldsa_pk_array.into();
    let mldsa_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);

    let pq_sig = ml_dsa::Signature::<MlDsa65>::try_from(sth.mldsa65_sig.as_slice())
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;

    mldsa_vk.verify(&digest, &pq_sig)
        .map_err(|_| IamError::PqSignatureVerificationFailed)?;

    Ok(())
}
