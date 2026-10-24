use crate::error::IamError;
use crate::spiffe::SpiffeId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtSvidClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub pq_pk_b64: String,
}

use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePrivateKey as EdDecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use ml_dsa::MlDsa65;
use ml_dsa::SignatureEncoding;
use serde_json::json;

pub fn mint_hybrid_jwt_svid(
    svid: &WorkloadSvid,
    claims: &JwtSvidClaims,
) -> Result<String, IamError> {
    let mut kid_hasher = blake3::Hasher::new();
    kid_hasher.update(&svid.ed25519_public_key);
    kid_hasher.update(&svid.mldsa65_verifying_key_bytes);
    let kid_hash = kid_hasher.finalize();
    let kid = hex::encode(&kid_hash.as_bytes()[0..16]);

    let claims_json = serde_json::to_string(claims)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json);

    let mut pq_hasher = blake3::Hasher::new();
    pq_hasher.update(b"tantry:jwt-svid:pq:v3:");
    pq_hasher.update(kid.as_bytes());
    pq_hasher.update(b".");
    pq_hasher.update(claims_b64.as_bytes());
    let pq_digest = pq_hasher.finalize();

    let ml_sk =
        ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(svid.mldsa65_signing_key_bytes.as_ref())
            .map_err(|_| {
                IamError::CertificateGenerationError("invalid mldsa65 secret key".to_string())
            })?;

    let pq_sig = ml_sk.sign(pq_digest.as_bytes());
    let pq_sig_bytes = pq_sig.to_bytes();
    let pq_sig_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pq_sig_bytes.as_ref() as &[u8]);

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": kid,
        "pq_alg": "ML-DSA-65",
        "pq_sig": pq_sig_b64
    });

    let header_json = serde_json::to_string(&header)
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);

    let message = format!("{}.{}", header_b64, claims_b64);

    let ed_sk = SigningKey::from_pkcs8_der(svid.ed25519_pkcs8_der.as_ref())
        .map_err(|e| IamError::CertificateGenerationError(e.to_string()))?;

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
        return Err(IamError::PqSignatureVerificationFailed); // Or some other verification error
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

        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or(IamError::PqSignatureVerificationFailed)?;
        let pq_sig_b64 = header
            .get("pq_sig")
            .and_then(|v| v.as_str())
            .ok_or(IamError::PqSignatureVerificationFailed)?;

        let mut pq_hasher = blake3::Hasher::new();
        pq_hasher.update(b"tantry:jwt-svid:pq:v3:");
        pq_hasher.update(kid.as_bytes());
        pq_hasher.update(b".");
        pq_hasher.update(claims_b64.as_bytes());
        let pq_digest = pq_hasher.finalize();

        let pq_sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pq_sig_b64)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        let mut sig_array = [0u8; 3309];
        if pq_sig_bytes.len() != 3309 {
            return Err(IamError::PqSignatureVerificationFailed);
        }
        sig_array.copy_from_slice(&pq_sig_bytes);

        let ml_vk =
            ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(mldsa65_verifying_key_bytes)
                .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        let pq_sig = ml_dsa::Signature::<MlDsa65>::decode((&sig_array).into())
            .ok_or(IamError::PqSignatureVerificationFailed)?;

        ml_vk
            .verify(pq_digest.as_bytes(), &pq_sig)
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;
    }

    Ok(claims)
}
