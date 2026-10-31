use crate::error::IamError;
use crate::pq_ext::PqExtensionPayload;
use crate::spiffe::SpiffeId;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct WorkloadSvid {
    pub spiffe_id: SpiffeId,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub ed25519_pk: [u8; 32],
    pub mldsa65_pk: Vec<u8>,
    pub pq_extension: PqExtensionPayload,
    pub ed25519_seed: Zeroizing<[u8; 32]>,
    pub mldsa65_sk_bytes: Zeroizing<Vec<u8>>,
}

pub fn verify_svid_chain(
    svid: &WorkloadSvid,
    issuer_ed25519_pk: &[u8; 32],
    issuer_mldsa65_pk: &[u8],
    now_ms: i64,
) -> Result<(), IamError> {
    if now_ms < svid.issued_at_ms || now_ms > svid.expires_at_ms {
        return Err(IamError::TtlEscalation);
    }

    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(&svid.cert_der)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let ed_vk = VerifyingKey::from_bytes(issuer_ed25519_pk)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_sig = Signature::from_slice(cert.signature_value.as_ref())
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    ed_vk
        .verify(cert.tbs_certificate.as_ref(), &ed_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    // We already have pq_extension parsed inside the svid for easy access but let's recompute the pre_tbs digest
    let serial_be = cert.tbs_certificate.raw_serial();
    let issuer_dn = cert.tbs_certificate.issuer.to_string();
    let subject_san_uri = svid.spiffe_id.uri();

    let not_before_s = cert.tbs_certificate.validity.not_before.timestamp();
    let not_after_s = cert.tbs_certificate.validity.not_after.timestamp();

    let is_ca = cert
        .tbs_certificate
        .basic_constraints()
        .map(|bc| bc.unwrap().value.ca)
        .unwrap_or(false);

    let expected_digest = crate::pq_ext::compute_pre_tbs_pq_digest(
        serial_be,
        &issuer_dn,
        subject_san_uri,
        not_before_s,
        not_after_s,
        is_ca,
        &svid.ed25519_pk,
        &svid.mldsa65_pk,
    );

    // Get the pq extension bytes from cert
    let mut pq_ext = None;
    for ext in cert.tbs_certificate.extensions() {
        if ext.oid
            == x509_parser::oid_registry::Oid::from(crate::pq_ext::PQ_MDSA65_EXT_OID).unwrap()
        {
            pq_ext = Some(ext);
        }
    }
    let ext = pq_ext.ok_or(IamError::PqSignatureVerificationFailed)?;

    crate::pq_ext::verify_pq_custom_extension(ext.value, &expected_digest, issuer_mldsa65_pk)?;

    Ok(())
}

pub fn verify_subagent_svid_attenuation(
    parent: &WorkloadSvid,
    child: &WorkloadSvid,
    parent_ed25519_pk: &[u8; 32],
    parent_mldsa65_pk: &[u8],
    now_ms: i64,
) -> Result<(), IamError> {
    parent.spiffe_id.verify_attenuation(&child.spiffe_id)?;
    if child.expires_at_ms > parent.expires_at_ms {
        return Err(IamError::TtlEscalation);
    }
    verify_svid_chain(child, parent_ed25519_pk, parent_mldsa65_pk, now_ms)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtSvidClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub pq_pk_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub htm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub htu: Option<String>,
}

use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use ml_dsa::MlDsa65;
use ml_dsa::SignatureEncoding;
use serde_json::json;

pub fn mint_hybrid_jwt_svid(
    svid: &WorkloadSvid,
    claims: &JwtSvidClaims,
) -> Result<String, IamError> {
    let mut kid_hasher = blake3::Hasher::new();
    kid_hasher.update(&svid.ed25519_pk);
    kid_hasher.update(&svid.mldsa65_pk);
    let kid_hash = kid_hasher.finalize();
    let kid = hex::encode(&kid_hash.as_bytes()[0..16]);

    let claims_json = serde_json::to_string(claims)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let claims_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let mut pq_hasher = blake3::Hasher::new();
    pq_hasher.update(b"tantry:jwt-pq-sig:v3");
    pq_hasher.update(claims_json.as_bytes());
    let claims_digest = pq_hasher.finalize();

    let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(svid.mldsa65_sk_bytes.as_ref())
        .map_err(|_| {
            IamError::CertificateGenerationError("invalid mldsa65 secret key".to_string())
        })?;

    let pq_sig = ml_sk.sign(claims_digest.as_bytes());
    let pq_sig_bytes = pq_sig.to_bytes();
    let pq_sig_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pq_sig_bytes.as_ref() as &[u8]);

    let is_dpop = claims.htm.is_some() && claims.htu.is_some();
    let typ = if is_dpop { "dpop+jwt" } else { "JWT" };

    let header = json!({
        "alg": "EdDSA",
        "typ": typ,
        "kid": kid,
        "pq_alg": "ML-DSA-65",
        "pq_sig": pq_sig_b64
    });

    let header_json = serde_json::to_string(&header)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let message = format!("{}.{}", header_b64, claims_b64);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(svid.ed25519_seed.as_ref());
    let ed_sk = SigningKey::from_bytes(&seed);

    let ed_sig = ed_sk.sign(message.as_bytes());
    let ed_sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ed_sig.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, claims_b64, ed_sig_b64))
}

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ml_dsa::pkcs8::DecodePublicKey;

pub fn verify_hybrid_jwt_svid(
    token: &str,
    expected_audience: &str,
    ed25519_public_key: &[u8; 32],
    mldsa65_verifying_key_bytes: &[u8],
    require_pq_hybrid_signatures: bool,
) -> Result<JwtSvidClaims, IamError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IamError::PqSignatureVerificationFailed);
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let ed_sig_b64 = parts[2];

    let message = format!("{}.{}", header_b64, claims_b64);

    let ed_sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ed_sig_b64)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_sig =
        Signature::from_slice(&ed_sig_bytes).map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_vk = VerifyingKey::from_bytes(ed25519_public_key)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    ed_vk
        .verify(message.as_bytes(), &ed_sig)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    let claims_json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;
    let claims: JwtSvidClaims = serde_json::from_slice(&claims_json_bytes)
        .map_err(|_| IamError::Ed25519VerificationFailed)?;

    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(IamError::TunnelGrantExpiredOrInvalid(
            "Token expired".to_string(),
        ));
    }

    if !claims.aud.contains(&expected_audience.to_string()) {
        return Err(IamError::TunnelGrantExpiredOrInvalid(
            "Invalid audience".to_string(),
        ));
    }

    if require_pq_hybrid_signatures {
        let header_json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;
        let header: serde_json::Value = serde_json::from_slice(&header_json_bytes)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        let pq_sig_b64 = header
            .get("pq_sig")
            .and_then(|v| v.as_str())
            .ok_or(IamError::PqSignatureVerificationFailed)?;

        let mut pq_hasher = blake3::Hasher::new();
        pq_hasher.update(b"tantry:jwt-pq-sig:v3");
        pq_hasher.update(&claims_json_bytes);
        let claims_digest = pq_hasher.finalize();

        let pq_sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pq_sig_b64)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        if pq_sig_bytes.len() != 3309 {
            return Err(IamError::PqSignatureVerificationFailed);
        }
        let mut sig_array = [0u8; 3309];
        sig_array.copy_from_slice(&pq_sig_bytes);

        let ml_vk =
            ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(mldsa65_verifying_key_bytes)
                .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        let pq_sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_array).into())
            .ok_or(IamError::PqSignatureVerificationFailed)?;

        ml_vk
            .verify(claims_digest.as_bytes(), &pq_sig)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;
    }

    Ok(claims)
}
