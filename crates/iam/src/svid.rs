use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use crate::spiffe::SpiffeId;
use crate::error::IamError;
use blake3::Hasher;
use ml_dsa::MlDsa65;
use ml_dsa::SignatureEncoding;
use ml_dsa::signature::{Signer, Verifier};
use ed25519_dalek::{VerifyingKey, Signature as EdSignature};
use pkcs8::DecodePrivateKey;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use std::convert::TryInto;

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

#[derive(Serialize, Deserialize)]
pub struct JwtSvidClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub pq_pk_b64: String,
}

#[derive(Serialize, Deserialize)]
struct JwsProtectedHeader {
    alg: String,
    typ: String,
    kid: String,
    pq_alg: String,
    pq_sig: String,
}

pub fn mint_hybrid_jwt_svid(svid: &WorkloadSvid, aud: Vec<String>) -> Result<String, IamError> {
    let mut hasher = Hasher::new();
    hasher.update(&svid.ed25519_public_key);
    hasher.update(&svid.mldsa65_verifying_key_bytes);
    let kid = hex::encode(&hasher.finalize().as_bytes()[0..16]);

    let claims = JwtSvidClaims {
        iss: svid.spiffe_id.to_string(),
        sub: svid.spiffe_id.to_string(),
        aud,
        exp: svid.expires_at.timestamp(),
        iat: svid.issued_at.timestamp(),
        jti: Uuid::now_v7().to_string(),
        pq_pk_b64: b64.encode(&svid.mldsa65_verifying_key_bytes),
    };

    let claims_b64 = b64.encode(serde_json::to_string(&claims).unwrap());

    let mut pq_hasher = Hasher::new();
    pq_hasher.update(b"tantry:jwt-svid:pq:v3:");
    pq_hasher.update(kid.as_bytes());
    pq_hasher.update(b".");
    pq_hasher.update(claims_b64.as_bytes());
    let pq_digest = pq_hasher.finalize();

    let mldsa_signing_key_array: [u8; 4032] = svid.mldsa65_signing_key_bytes[..]
        .try_into()
        .map_err(|_| IamError::CertificateGenerationError("Invalid ML-DSA-65 signing key length".to_string()))?;

    let mut mldsa_signing_key_slice = [0u8; 4032];
    mldsa_signing_key_slice.copy_from_slice(&mldsa_signing_key_array);
    let enc = ml_dsa::ExpandedSigningKeyBytes::<MlDsa65>::from(mldsa_signing_key_array);
    #[allow(deprecated)]
    let mldsa_signing_key = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(&enc);
    let pq_sig = mldsa_signing_key.sign(pq_digest.as_bytes());
    let pq_sig_b64 = b64.encode(pq_sig.to_bytes());

    let header = JwsProtectedHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
        kid,
        pq_alg: "ML-DSA-65".to_string(),
        pq_sig: pq_sig_b64,
    };

    let header_b64 = b64.encode(serde_json::to_string(&header).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let ed25519_sk = ed25519_dalek::SigningKey::from_pkcs8_der(&svid.ed25519_pkcs8_der)
        .map_err(|_| IamError::CertificateGenerationError("Invalid Ed25519 PKCS8 key".to_string()))?;

    let ed_sig = ed25519_sk.sign(signing_input.as_bytes());
    let ed_sig_b64 = b64.encode(ed_sig.to_bytes());

    Ok(format!("{}.{}", signing_input, ed_sig_b64))
}


pub fn verify_hybrid_jwt_svid(
    token: &str,
    ed25519_pk: &[u8; 32],
    mldsa65_pk: &[u8],
    expected_aud: &str,
    require_pq_hybrid_signatures: bool
) -> Result<JwtSvidClaims, IamError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IamError::Ed25519VerificationFailed);
    }

    let header_bytes = b64.decode(parts[0]).map_err(|_| IamError::Ed25519VerificationFailed)?;
    let _header: JwsProtectedHeader = serde_json::from_slice(&header_bytes).map_err(|_| IamError::Ed25519VerificationFailed)?;

    let claims_bytes = b64.decode(parts[1]).map_err(|_| IamError::Ed25519VerificationFailed)?;
    let claims: JwtSvidClaims = serde_json::from_slice(&claims_bytes).map_err(|_| IamError::Ed25519VerificationFailed)?;

    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(IamError::Ed25519VerificationFailed);
    }

    if !claims.aud.contains(&expected_aud.to_string()) {
        return Err(IamError::Ed25519VerificationFailed);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let ed_sig_bytes = b64.decode(parts[2]).map_err(|_| IamError::Ed25519VerificationFailed)?;
    let ed_sig = EdSignature::from_slice(&ed_sig_bytes).map_err(|_| IamError::Ed25519VerificationFailed)?;

    let vk = VerifyingKey::from_bytes(ed25519_pk).map_err(|_| IamError::Ed25519VerificationFailed)?;
    vk.verify(signing_input.as_bytes(), &ed_sig).map_err(|_| IamError::Ed25519VerificationFailed)?;

    if require_pq_hybrid_signatures {
        let mut pq_hasher = Hasher::new();
        pq_hasher.update(b"tantry:jwt-svid:pq:v3:");
        pq_hasher.update(_header.kid.as_bytes());
        pq_hasher.update(b".");
        pq_hasher.update(parts[1].as_bytes());
        let pq_digest = pq_hasher.finalize();

        let pq_sig_bytes = b64.decode(&_header.pq_sig).map_err(|_| IamError::PqSignatureVerificationFailed)?;

        let mldsa_pk_array: [u8; 1952] = mldsa65_pk
            .try_into()
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;
        let enc: ml_dsa::EncodedVerifyingKey<MlDsa65> = mldsa_pk_array.into();
        let mldsa_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);

        let pq_sig = ml_dsa::Signature::<MlDsa65>::try_from(pq_sig_bytes.as_slice())
            .map_err(|_| IamError::PqSignatureVerificationFailed)?;

        mldsa_vk.verify(pq_digest.as_bytes(), &pq_sig).map_err(|_| IamError::PqSignatureVerificationFailed)?;
    }

    Ok(claims)
}
