use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::error::IamError;
use crate::svid::WorkloadSvid;
use ed25519_dalek::{VerifyingKey, Signature as EdSignature};
use pkcs8::DecodePrivateKey;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use ml_dsa::signature::{Signer, Verifier};
use dashmap::DashMap;

use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize)]
struct DpopProtectedHeader {
    typ: String,
    alg: String,
    jwk: Jwk,
}

#[derive(Serialize, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Serialize, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

pub fn mint_dpop_proof(svid: &WorkloadSvid, htm: &str, htu: &str, access_token: Option<&str>) -> Result<String, IamError> {
    let mut normalized_htu = htu.to_string();
    if let Some(pos) = normalized_htu.find('?') {
        normalized_htu.truncate(pos);
    }
    if let Some(pos) = normalized_htu.find('#') {
        normalized_htu.truncate(pos);
    }

    let header = DpopProtectedHeader {
        typ: "dpop+jwt".to_string(),
        alg: "EdDSA".to_string(),
        jwk: Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: b64.encode(&svid.ed25519_public_key),
        },
    };

    let ath = access_token.map(|t| {
        let mut hasher = Sha256::new();
        hasher.update(t.as_bytes());
        b64.encode(hasher.finalize())
    });

    let claims = DpopClaims {
        jti: Uuid::now_v7().to_string(),
        htm: htm.to_uppercase(),
        htu: normalized_htu,
        iat: Utc::now().timestamp(),
        ath,
    };

    let header_b64 = b64.encode(serde_json::to_string(&header).unwrap());
    let claims_b64 = b64.encode(serde_json::to_string(&claims).unwrap());

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let ed25519_sk = ed25519_dalek::SigningKey::from_pkcs8_der(&svid.ed25519_pkcs8_der)
        .map_err(|_| IamError::CertificateGenerationError("Invalid Ed25519 PKCS8 key".to_string()))?;

    let ed_sig = ed25519_sk.sign(signing_input.as_bytes());
    let ed_sig_b64 = b64.encode(ed_sig.to_bytes());

    Ok(format!("{}.{}", signing_input, ed_sig_b64))
}

pub fn verify_dpop_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    cache: &DashMap<String, i64>
) -> Result<(), IamError> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(IamError::DpopValidationFailed("Invalid DPoP token format".to_string()));
    }

    let header_bytes = b64.decode(parts[0]).map_err(|_| IamError::DpopValidationFailed("Invalid header base64".to_string()))?;
    let header: DpopProtectedHeader = serde_json::from_slice(&header_bytes).map_err(|_| IamError::DpopValidationFailed("Invalid header JSON".to_string()))?;

    if header.typ != "dpop+jwt" {
        return Err(IamError::DpopValidationFailed("Invalid typ".to_string()));
    }

    if header.jwk.kty != "OKP" || header.jwk.crv != "Ed25519" {
        return Err(IamError::DpopValidationFailed("Invalid JWK".to_string()));
    }

    let pk_bytes = b64.decode(&header.jwk.x).map_err(|_| IamError::DpopValidationFailed("Invalid JWK x".to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(IamError::DpopValidationFailed("Invalid JWK x length".to_string()));
    }

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);

    let claims_bytes = b64.decode(parts[1]).map_err(|_| IamError::DpopValidationFailed("Invalid claims base64".to_string()))?;
    let claims: DpopClaims = serde_json::from_slice(&claims_bytes).map_err(|_| IamError::DpopValidationFailed("Invalid claims JSON".to_string()))?;

    let now = Utc::now().timestamp();
    if (now - claims.iat).abs() > 60 {
        return Err(IamError::DpopValidationFailed("DPoP proof expired or from future".to_string()));
    }

    if claims.htm != htm.to_uppercase() {
        return Err(IamError::DpopValidationFailed("HTTP method mismatch".to_string()));
    }

    let mut normalized_htu = htu.to_string();
    if let Some(pos) = normalized_htu.find('?') {
        normalized_htu.truncate(pos);
    }
    if let Some(pos) = normalized_htu.find('#') {
        normalized_htu.truncate(pos);
    }

    if claims.htu != normalized_htu {
        return Err(IamError::DpopValidationFailed("HTTP URI mismatch".to_string()));
    }

    if let Some(at) = access_token {
        let mut hasher = Sha256::new();
        hasher.update(at.as_bytes());
        let expected_ath = b64.encode(hasher.finalize());
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(IamError::DpopValidationFailed("Access token hash mismatch".to_string()));
        }
    } else if claims.ath.is_some() {
        return Err(IamError::DpopValidationFailed("Unexpected ath claim".to_string()));
    }

    if cache.insert(claims.jti.clone(), claims.iat).is_some() {
        return Err(IamError::DpopReplayDetected(claims.jti));
    }
    if cache.len() > 1000 {
        let mut to_remove = Vec::new();
        for entry in cache.iter() {
            if (now - *entry.value()).abs() > 60 {
                to_remove.push(entry.key().clone());
            }
        }
        for k in to_remove {
            cache.remove(&k);
        }
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let ed_sig_bytes = b64.decode(parts[2]).map_err(|_| IamError::DpopValidationFailed("Invalid signature base64".to_string()))?;
    let ed_sig = EdSignature::from_slice(&ed_sig_bytes).map_err(|_| IamError::DpopValidationFailed("Invalid signature bytes".to_string()))?;

    let vk = VerifyingKey::from_bytes(&pk_array).map_err(|_| IamError::DpopValidationFailed("Invalid public key".to_string()))?;
    vk.verify(signing_input.as_bytes(), &ed_sig).map_err(|_| IamError::DpopValidationFailed("Signature verification failed".to_string()))?;

    Ok(())
}
